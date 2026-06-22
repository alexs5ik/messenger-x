// Client-side cryptography for Messenger X — real PQXDH + Double Ratchet, via mx-crypto (wasm).
//
// On registration the device creates an account and publishes its public bundle. To message a
// peer we fetch their bundle and run a hybrid PQXDH handshake (X25519 + ML-KEM-768) that seeds
// a Double Ratchet; every message then advances the ratchet, deriving a fresh one-time key
// (per-message forward secrecy). The server only ever sees opaque ciphertext.
//
// Each direction is its own one-way ratchet (sender = initiator against the recipient's
// bundle), which avoids handshake glare. Ratchet state is persisted so a live session survives
// page reloads. Delivery must be in order per direction (the WS FIFO guarantees this); the
// simplified ratchet does not store skipped-message keys (design doc §7).

import init, {
  account_create,
  session_initiator,
  session_responder,
  ratchet_encrypt,
  ratchet_decrypt,
  pqxdh_selftest,
} from "./mxwasm/mx_crypto_wasm.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

let ready: Promise<void> | null = null;
function ensureReady(): Promise<void> {
  if (!ready) ready = init().then(() => undefined);
  return ready;
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s);
}
function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Long-lived identity material persists across sessions (localStorage): the device's secret blob
// and its published bundle, so a returning user can re-announce itself without re-registering.
const SECRETS_KEY = "mx.secrets";
const BUNDLE_KEY = "mx.bundle";
// Double-Ratchet session state is deliberately EPHEMERAL (sessionStorage): it resets when the tab
// closes, so the next session re-runs the PQXDH handshake against the peer's current bundle. This
// self-heals after a peer re-registers or the server loses its prekey state — persisting it caused
// the sender to keep a stale ratchet and silently fail to deliver.
const OUT_KEY = "mx.sessions.out";
const IN_KEY = "mx.sessions.in";

function loadSecrets(): Uint8Array {
  const b = localStorage.getItem(SECRETS_KEY);
  if (!b) throw new Error("device not provisioned (no secrets)");
  return unb64(b);
}

type OutSession = { ratchet: string; init: string; sentInit: boolean };
type InSession = { ratchet: string };
const loadMap = <T>(key: string): Record<string, T> =>
  JSON.parse(sessionStorage.getItem(key) ?? "{}") as Record<string, T>;
const saveMap = (key: string, m: unknown): void => sessionStorage.setItem(key, JSON.stringify(m));

/// Provision this device: create an account, store the secret blob + bundle, return the bundle
/// JSON to publish. Call once per registration; the stored bundle lets us re-announce on reload.
export async function provisionAccount(deviceId: string): Promise<string> {
  await ensureReady();
  const acc = account_create(deviceId);
  localStorage.setItem(SECRETS_KEY, b64(acc.secrets));
  localStorage.setItem(BUNDLE_KEY, acc.bundle_json);
  return acc.bundle_json;
}

/// The bundle published at provision time, if any — used to re-publish on startup so a server that
/// lost its prekey directory (restart/redeploy) re-learns this device. Null if never provisioned.
export function storedBundle(): string | null {
  return localStorage.getItem(BUNDLE_KEY);
}

async function fetchBundle(peer: string): Promise<string> {
  const r = await fetch(`/v1/users/${peer}/prekey`);
  if (!r.ok) throw new Error(`prekey directory ${r.status} for ${peer}`);
  return r.text();
}

// Encrypt `text` from `me` to `peer`, advancing the outbound ratchet. The init message rides on
// the first message only (the ratchet carries everything afterwards).
export async function encrypt(me: string, peer: string, text: string): Promise<Uint8Array> {
  await ensureReady();
  const out = loadMap<OutSession>(OUT_KEY);
  let sess = out[peer];
  if (!sess) {
    const bundle = await fetchBundle(peer);
    const established = session_initiator(loadSecrets(), bundle);
    sess = { ratchet: b64(established.ratchet), init: established.init_json, sentInit: false };
    out[peer] = sess;
  }
  const step = ratchet_encrypt(unb64(sess.ratchet), enc.encode(text));
  sess.ratchet = b64(step.state);
  const includeInit = !sess.sentInit;
  sess.sentInit = true;
  saveMap(OUT_KEY, out);
  const env: Record<string, unknown> = { v: 4, from: me, f: b64(step.data) };
  if (includeInit) env.init = sess.init;
  return enc.encode(JSON.stringify(env));
}

export interface Decrypted {
  from: string;
  text: string;
}

// Decrypt a payload addressed to us, advancing the inbound ratchet. The first message from a
// peer carries its init, used to seed our responder ratchet. Throws on tamper/out-of-order.
export async function decrypt(payload: Uint8Array): Promise<Decrypted> {
  await ensureReady();
  const obj = JSON.parse(dec.decode(payload)) as { from: string; f: string; init?: string };
  const inMap = loadMap<InSession>(IN_KEY);
  let sess = inMap[obj.from];
  if (!sess) {
    if (!obj.init) throw new Error("no inbound session and no init message");
    sess = { ratchet: b64(session_responder(loadSecrets(), obj.init)) };
    inMap[obj.from] = sess;
  }
  const step = ratchet_decrypt(unb64(sess.ratchet), unb64(obj.f));
  sess.ratchet = b64(step.state);
  saveMap(IN_KEY, inMap);
  return { from: obj.from, text: dec.decode(step.data) };
}

export interface PqStatus {
  ok: boolean;
  secretMatch?: boolean;
  ratchetOk?: boolean;
  kem?: string;
  error?: string;
}

// Run the real PQXDH + ratchet self-test in wasm and return its result (for a UI badge).
export async function pqStatus(): Promise<PqStatus> {
  await ensureReady();
  try {
    return JSON.parse(pqxdh_selftest()) as PqStatus;
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}
