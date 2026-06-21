// Client-side cryptography for Messenger X — real PQXDH, backed by mx-crypto compiled to wasm.
//
// On registration the device creates an account (identity + pre-keys) and publishes its public
// bundle; the secret blob is kept locally. To message a peer we fetch their bundle from the
// server's prekey directory and run a real hybrid PQXDH handshake (X25519 + ML-KEM-768) to
// derive a per-conversation secret, then seal each message with ChaCha20-Poly1305. The server
// only ever sees opaque ciphertext. Each direction is its own X3DH/PQXDH session (sender =
// initiator against the recipient's bundle), which avoids handshake glare.

import init, {
  account_create,
  session_initiator,
  session_responder,
  seal,
  open,
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

const SECRETS_KEY = "mx.secrets";
const OUT_KEY = "mx.sessions.out";

function loadSecrets(): Uint8Array {
  const b = sessionStorage.getItem(SECRETS_KEY);
  if (!b) throw new Error("device not provisioned (no secrets)");
  return unb64(b);
}

// Outbound sessions (we are the initiator): peer -> { secret, init }. Persisted so the init we
// advertise — and thus the secret the peer derived — stays stable across page reloads.
type OutSession = { secret: string; init: string };
function loadOut(): Record<string, OutSession> {
  return JSON.parse(sessionStorage.getItem(OUT_KEY) ?? "{}") as Record<string, OutSession>;
}
function saveOut(map: Record<string, OutSession>): void {
  sessionStorage.setItem(OUT_KEY, JSON.stringify(map));
}

// Inbound sessions (we are the responder): from -> { init, secret }. In-memory; the sender
// includes its init on every message, so this is just an optimisation and is re-derived if the
// peer's init changes (e.g. after the peer re-registers).
const inbound = new Map<string, { init: string; secret: Uint8Array }>();

/// Provision this device: create an account, store the secret blob, return the bundle JSON to
/// publish. Call once per registration; on reload the existing secrets are reused.
export async function provisionAccount(deviceId: string): Promise<string> {
  await ensureReady();
  const acc = account_create(deviceId);
  sessionStorage.setItem(SECRETS_KEY, b64(acc.secrets));
  return acc.bundle_json;
}

async function fetchBundle(peer: string): Promise<string> {
  const r = await fetch(`/v1/users/${peer}/prekey`);
  if (!r.ok) throw new Error(`prekey directory ${r.status} for ${peer}`);
  return r.text();
}

// Encrypt `text` from `me` to `peer` using a real PQXDH-derived secret. The init message is
// carried on every message so the recipient can derive the same secret.
export async function encrypt(me: string, peer: string, text: string): Promise<Uint8Array> {
  await ensureReady();
  const out = loadOut();
  let sess = out[peer];
  if (!sess) {
    const bundle = await fetchBundle(peer);
    const established = session_initiator(loadSecrets(), bundle);
    sess = { secret: b64(established.secret), init: established.init_json };
    out[peer] = sess;
    saveOut(out);
  }
  const sealed = seal(unb64(sess.secret), enc.encode(text));
  return enc.encode(JSON.stringify({ v: 3, from: me, c: b64(sealed), init: sess.init }));
}

export interface Decrypted {
  from: string;
  text: string;
}

// Decrypt a payload addressed to us. Derives (or reuses) the responder secret from the sender's
// init. Throws on tamper/wrong key (AEAD authentication).
export async function decrypt(payload: Uint8Array): Promise<Decrypted> {
  await ensureReady();
  const obj = JSON.parse(dec.decode(payload)) as { from: string; c: string; init?: string };
  let cached = inbound.get(obj.from);
  if (!cached || cached.init !== obj.init) {
    if (!obj.init) throw new Error("no session and no init message");
    cached = { init: obj.init, secret: session_responder(loadSecrets(), obj.init) };
    inbound.set(obj.from, cached);
  }
  const pt = open(cached.secret, unb64(obj.c));
  return { from: obj.from, text: dec.decode(pt) };
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
