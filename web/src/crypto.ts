// Client-side encryption for Messenger X.
//
// The contract this module upholds is the one that matters for the architecture: the
// browser encrypts before sending and decrypts after receiving, so the server only ever
// handles opaque ciphertext (the "ciphertext-only" invariant of mx-server).
//
// Key agreement here is a DEMO stand-in: a conversation key is derived deterministically
// from the two participants' user ids via PBKDF2, so two browser tabs agree on the same
// key with zero friction. The real build replaces this whole module with the WASM build of
// `mx-crypto` (hybrid PQXDH X25519 + ML-KEM-768 → Double Ratchet). The public API below is
// intentionally the seam where that swap happens — nothing else in the client changes.

const enc = new TextEncoder();
const dec = new TextDecoder();

// WebCrypto wants a `BufferSource` backed by a plain `ArrayBuffer`. TS 5.7's stricter
// typed-array generics reject `Uint8Array<ArrayBufferLike>`, so copy into a fresh buffer.
function ab(u: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(u.byteLength);
  new Uint8Array(b).set(u);
  return b;
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function pairId(a: string, b: string): string {
  return [a, b].sort().join("|");
}

function deriveKey(a: string, b: string): Promise<CryptoKey> {
  const id = pairId(a, b);
  let k = keyCache.get(id);
  if (!k) {
    k = (async () => {
      const base = await crypto.subtle.importKey(
        "raw",
        ab(enc.encode(id + ":mx-demo-v1")),
        "PBKDF2",
        false,
        ["deriveKey"],
      );
      return crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: ab(enc.encode("messenger-x-demo-salt")),
          iterations: 100_000,
          hash: "SHA-256",
        },
        base,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
    })();
    keyCache.set(id, k);
  }
  return k;
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Encrypt `text` from `me` to `peer`. Returns the opaque payload bytes that become the
// envelope ciphertext. The sender's user id rides in a cleartext header so the recipient
// (who only learns the sending *device* from routing) can pick the conversation key — in a
// real build this is handled by the session/sealed-sender, not the payload.
export async function encrypt(
  me: string,
  peer: string,
  text: string,
): Promise<Uint8Array> {
  const key = await deriveKey(me, peer);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: ab(iv) }, key, ab(enc.encode(text))),
  );
  const blob = JSON.stringify({ v: 1, from: me, iv: b64(iv), ct: b64(ct) });
  return enc.encode(blob);
}

export interface Decrypted {
  from: string;
  text: string;
}

// Decrypt a payload addressed to `me`. Reads the cleartext sender header, derives the
// conversation key, and authenticates+decrypts the body. Throws on tamper (AES-GCM).
export async function decrypt(me: string, payload: Uint8Array): Promise<Decrypted> {
  const obj = JSON.parse(dec.decode(payload)) as {
    from: string;
    iv: string;
    ct: string;
  };
  const key = await deriveKey(me, obj.from);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ab(unb64(obj.iv)) },
    key,
    ab(unb64(obj.ct)),
  );
  return { from: obj.from, text: dec.decode(pt) };
}
