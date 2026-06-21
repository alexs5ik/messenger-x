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

// Register a new account + first device and obtain a session token. The chosen identifier
// (email / phone / name) is sent in its matching field; the server requires >=1 of them.
export async function register(
  value: string,
  method: RegisterMethod = "name",
): Promise<Identity> {
  const body: Record<string, unknown> = {
    // Placeholder identity key — the real client publishes its mx-crypto public key here.
    identity_key: { algo: "x25519", bytes: randomBytes(32) },
  };
  if (method === "email") body.email = value;
  else if (method === "phone") body.phone = value;
  else body.username = value;

  const res = await fetch("/v1/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  const j = (await res.json()) as { user_id: string; device_id: string; token: string };
  // Display handle = whatever the user typed (email/phone/name) — that's what they recognize.
  return {
    userId: j.user_id,
    deviceId: j.device_id,
    token: j.token,
    username: value,
    method,
    contact: method === "name" ? undefined : value,
  };
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
