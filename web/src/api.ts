// REST + WebSocket client for mx-server. URLs are relative so Vite's dev proxy forwards
// them same-origin to the backend (see vite.config.ts).

export interface Identity {
  userId: string;
  deviceId: string;
  token: string;
  username: string;
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

// Register a new account + first device and obtain a session token.
export async function register(username: string): Promise<Identity> {
  const res = await fetch("/v1/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      username,
      // Placeholder identity key — the real client publishes its mx-crypto public key here.
      identity_key: { algo: "x25519", bytes: randomBytes(32) },
    }),
  });
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  const j = (await res.json()) as { user_id: string; device_id: string; token: string };
  return { userId: j.user_id, deviceId: j.device_id, token: j.token, username };
}

type IncomingHandler = (env: WireEnvelope) => void;
type StatusHandler = (status: "connecting" | "online" | "offline") => void;

// A thin wrapper over the mx-server WebSocket gateway. Speaks the mx_transport
// ClientMessage/ServerMessage framing ({"t":..,"d":..}).
export class MxSocket {
  private ws: WebSocket | null = null;
  private reconnect = true;

  constructor(
    private token: string,
    private onIncoming: IncomingHandler,
    private onStatus: StatusHandler,
  ) {}

  connect(): void {
    this.onStatus("connecting");
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/v1/ws`);
    this.ws = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ t: "hello", d: { token: this.token } }));
      this.onStatus("online");
    };

    ws.onmessage = (ev) => {
      let msg: { t: string; d: unknown };
      try {
        msg = JSON.parse(ev.data as string);
      } catch {
        return;
      }
      if (msg.t === "incoming") {
        const env = msg.d as WireEnvelope;
        this.onIncoming(env);
        // Transport-level delivery receipt.
        ws.send(JSON.stringify({ t: "ack", d: env.id }));
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
