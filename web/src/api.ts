// REST + WebSocket client for mx-server. URLs are relative so Vite's dev proxy forwards
// them same-origin to the backend (see vite.config.ts).

// How an account was created — selects the matching login input + server identifier field.
export type RegisterMethod = "email" | "phone" | "name";

export interface Identity {
  userId: string;
  deviceId: string;
  token: string;
  username: string;
  method?: RegisterMethod; // how the account was created
  contact?: string; // the email/phone entered (shown in the profile header)
}

// Wire shape of an envelope, matching mx_transport::wire_envelope (externally-tagged
// recipient, ciphertext as a byte array).
export interface WireEnvelope {
  id: string;
  from: string;
  to: { direct: string } | { group: string };
  kind: "chat" | "control" | "group_handshake";
  ciphertext: number[];
  ts: number;
}

function randomBytes(n: number): number[] {
  return Array.from(crypto.getRandomValues(new Uint8Array(n)));
}

// The placeholder device identity key. The real long-term key is published separately via the
// prekey bundle; this field just satisfies the registration contract.
function deviceKey(): Record<string, unknown> {
  return { algo: "x25519", bytes: randomBytes(32) };
}

function identityFrom(
  j: { user_id: string; device_id: string; token: string; must_change?: boolean },
  value: string,
  method: RegisterMethod,
): Identity & { mustChange?: boolean } {
  return {
    userId: j.user_id,
    deviceId: j.device_id,
    token: j.token,
    username: value,
    method,
    contact: method === "name" ? undefined : value,
    mustChange: j.must_change,
  };
}

// Register a new account + first device and obtain a session token. Email/phone registration
// requires a password (enforced server-side too); the "name" demo path stays passwordless.
export async function register(
  value: string,
  method: RegisterMethod = "name",
  password?: string,
): Promise<Identity> {
  const body: Record<string, unknown> = { identity_key: deviceKey() };
  if (method === "email") body.email = value;
  else if (method === "phone") body.phone = value;
  else body.username = value;
  if (password) body.password = password;

  const res = await fetch("/v1/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await errText(res, "register"));
  const j = (await res.json()) as { user_id: string; device_id: string; token: string };
  return identityFrom(j, value, method);
}

// Log into an existing account by identifier + password; opens a fresh device session. The
// returned identity carries `mustChange` when the password was a server-issued temporary one.
export async function login(
  value: string,
  method: RegisterMethod,
  password: string,
): Promise<Identity & { mustChange?: boolean }> {
  const body: Record<string, unknown> = { identity_key: deviceKey(), password };
  if (method === "email") body.email = value;
  else if (method === "phone") body.phone = value;
  else body.username = value;

  const res = await fetch("/v1/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.status === 401) throw new Error("Неверный логин или пароль");
  if (!res.ok) throw new Error(await errText(res, "login"));
  const j = (await res.json()) as {
    user_id: string;
    device_id: string;
    token: string;
    must_change?: boolean;
  };
  return identityFrom(j, value, method);
}

// Start a password reset. Email → returns a one-time reset token (demo: shown in the UI).
// Phone → returns a generated temporary password (demo: shown in the UI).
export async function forgotPassword(
  value: string,
  method: "email" | "phone",
): Promise<{ channel: string; reset_token?: string; temp_password?: string }> {
  const body: Record<string, unknown> = { method };
  if (method === "email") body.email = value;
  else body.phone = value;
  const res = await fetch("/v1/auth/forgot", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await errText(res, "forgot"));
  return (await res.json()) as { channel: string; reset_token?: string; temp_password?: string };
}

// Complete an email reset with the token + a new (policy-compliant) password.
export async function resetPassword(token: string, password: string): Promise<void> {
  const res = await fetch("/v1/auth/reset", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, password }),
  });
  if (!res.ok) throw new Error(await errText(res, "reset"));
}

// Set a new password for the authenticated session (forced change after an SMS temp password).
export async function changePassword(token: string, password: string): Promise<void> {
  const res = await fetch("/v1/auth/change", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) throw new Error(await errText(res, "change"));
}

// The server-stored, cross-device profile (display name, status, avatar data URL).
export interface RemoteProfile {
  name?: string;
  status?: string;
  avatar?: string;
}

// Fetch the authenticated user's profile (synced across their devices).
export async function getProfile(token: string): Promise<RemoteProfile> {
  const res = await fetch("/v1/profile", { headers: { authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(await errText(res, "profile"));
  return (await res.json()) as RemoteProfile;
}

// Replace the authenticated user's profile on the server.
export async function putProfile(token: string, p: RemoteProfile): Promise<void> {
  const res = await fetch("/v1/profile", {
    method: "PUT",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify(p),
  });
  if (!res.ok) throw new Error(await errText(res, "profile"));
}

// Pull the server's `{"error": "..."}` message out of a failed response for a friendlier alert.
async function errText(res: Response, what: string): Promise<string> {
  try {
    const j = (await res.json()) as { error?: string };
    if (j.error) return j.error;
  } catch {
    /* non-JSON body */
  }
  return `${what} failed: ${res.status}`;
}

// Admin REST helper: attaches the x-admin-token header and normalizes 401 / 204.
export async function adminFetch<T>(
  path: string,
  adminToken: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "content-type": "application/json",
      "x-admin-token": adminToken,
      ...(init?.headers ?? {}),
    },
  });
  if (res.status === 401) throw new Error("unauthorized");
  if (!res.ok) throw new Error(`admin ${path} failed: ${res.status} ${await res.text()}`);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// Publish a device's pre-key bundle (JSON string from the wasm crypto layer) so peers can
// run a PQXDH handshake against it.
export async function publishPrekeys(bundleJson: string): Promise<void> {
  const res = await fetch("/v1/prekeys", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ bundle: JSON.parse(bundleJson) }),
  });
  if (!res.ok) throw new Error(`publish prekeys failed: ${res.status} ${await res.text()}`);
}

type IncomingHandler = (env: WireEnvelope) => void;
type StatusHandler = (status: "connecting" | "online" | "offline") => void;
type AckHandler = (messageId: string) => void;

// A thin wrapper over the mx-server WebSocket gateway. Speaks the mx_transport
// ClientMessage/ServerMessage framing ({"t":..,"d":..}).
export class MxSocket {
  private ws: WebSocket | null = null;
  private reconnect = true;

  constructor(
    private token: string,
    private onIncoming: IncomingHandler,
    private onStatus: StatusHandler,
    private onAck: AckHandler = () => {},
  ) {}

  connect(): void {
    this.onStatus("connecting");
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/v1/ws`);
    // The server sends binary frames; receive them as ArrayBuffer so we can decode to text.
    ws.binaryType = "arraybuffer";
    this.ws = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ t: "hello", d: { token: this.token } }));
      this.onStatus("online");
    };

    ws.onmessage = (ev) => {
      const raw =
        typeof ev.data === "string" ? ev.data : new TextDecoder().decode(ev.data as ArrayBuffer);
      let msg: { t: string; d: unknown };
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }
      if (msg.t === "incoming") {
        const env = msg.d as WireEnvelope;
        this.onIncoming(env);
        // Transport-level delivery receipt to the server.
        ws.send(JSON.stringify({ t: "ack", d: env.id }));
      } else if (msg.t === "ack") {
        // Server accepted one of our sent messages → mark it "sent" (single check).
        this.onAck(msg.d as string);
      } else if (msg.t === "error") {
        console.warn("server error frame:", msg.d);
      }
    };

    ws.onclose = () => {
      this.onStatus("offline");
      if (this.reconnect) setTimeout(() => this.connect(), 1500);
    };
    ws.onerror = () => ws.close();
  }

  send(env: WireEnvelope): void {
    this.ws?.send(JSON.stringify({ t: "send", d: env }));
  }

  close(): void {
    this.reconnect = false;
    this.ws?.close();
  }
}
