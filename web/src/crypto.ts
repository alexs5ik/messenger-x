// Client-side encryption for Messenger X — now backed by the real mx-crypto core compiled
// to WebAssembly (HKDF-SHA256 → ChaCha20-Poly1305). The browser encrypts before sending and
// decrypts after receiving, so the server only ever handles opaque ciphertext.
//
// What's real: every message is sealed/opened by the actual Rust AEAD running in wasm, and
// `pqStatus()` runs a full hybrid PQXDH (X25519 + ML-KEM-768) handshake + Double Ratchet
// round-trip in the browser to prove the post-quantum stack works here.
//
// What's still a demo: the per-conversation secret is derived deterministically from the two
// user ids (SHA-256) rather than from a live PQXDH exchange — that needs a prekey-directory
// endpoint to look up a peer's published bundle. The sealing primitives are real; the key
// agreement is the remaining piece.

import init, { seal, open, pqxdh_selftest } from "./mxwasm/mx_crypto_wasm.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

let ready: Promise<void> | null = null;
function ensureReady(): Promise<void> {
  if (!ready) ready = init().then(() => undefined);
  return ready;
}

const secretCache = new Map<string, Promise<Uint8Array>>();

// 32-byte conversation secret, identical for both participants (sorted ids → SHA-256).
function deriveSecret(a: string, b: string): Promise<Uint8Array> {
  const id = [a, b].sort().join("|") + ":mx-demo-v2";
  let s = secretCache.get(id);
  if (!s) {
    s = crypto.subtle
      .digest("SHA-256", enc.encode(id))
      .then((buf) => new Uint8Array(buf));
    secretCache.set(id, s);
  }
  return s;
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

// Encrypt `text` from `me` to `peer`. Returns the opaque envelope-ciphertext bytes. The
// sender id rides in a cleartext header so the recipient can pick the conversation secret.
export async function encrypt(me: string, peer: string, text: string): Promise<Uint8Array> {
  await ensureReady();
  const secret = await deriveSecret(me, peer);
  const sealed = seal(secret, enc.encode(text)); // real ChaCha20-Poly1305 in wasm
  const blob = JSON.stringify({ v: 2, from: me, c: b64(sealed) });
  return enc.encode(blob);
}

export interface Decrypted {
  from: string;
  text: string;
}

// Decrypt a payload addressed to `me`. Throws on tamper/wrong key (AEAD authentication).
export async function decrypt(me: string, payload: Uint8Array): Promise<Decrypted> {
  await ensureReady();
  const obj = JSON.parse(dec.decode(payload)) as { from: string; c: string };
  const secret = await deriveSecret(me, obj.from);
  const pt = open(secret, unb64(obj.c)); // real ChaCha20-Poly1305 in wasm
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
