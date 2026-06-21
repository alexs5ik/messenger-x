// End-to-end test of the real client crypto path: replicate crypto.ts (SHA-256 pair-secret
// + wasm seal/open + JSON envelope) across two WebSocket clients through the live server.
// Proves: browser-equivalent encrypt -> server (ciphertext-only) -> browser-equivalent decrypt.
import init, { seal, open } from "../web/src/mxwasm/mx_crypto_wasm.js";
import { readFileSync } from "node:fs";

const BASE = process.env.MX_BASE ?? "http://127.0.0.1:9990";
const WS = BASE.replace(/^http/, "ws") + "/v1/ws";
await init({ module_or_path: readFileSync(new URL("../web/src/mxwasm/mx_crypto_wasm_bg.wasm", import.meta.url)) });

const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (u) => Buffer.from(u).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

async function deriveSecret(a, b) {
  const id = [a, b].sort().join("|") + ":mx-demo-v2";
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(id)));
}
async function encrypt(me, peer, text) {
  const secret = await deriveSecret(me, peer);
  const sealed = seal(secret, enc.encode(text));
  return enc.encode(JSON.stringify({ v: 2, from: me, c: b64(sealed) }));
}
async function decrypt(me, payloadBytes) {
  const obj = JSON.parse(dec.decode(payloadBytes));
  const secret = await deriveSecret(me, obj.from);
  return { from: obj.from, text: dec.decode(open(secret, unb64(obj.c))) };
}

const reg = async (n) => (await (await fetch(BASE + "/v1/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: n, identity_key: { algo: "x25519", bytes: [1] } }) })).json());
const hello = (ws, token) => new Promise((res) => { ws.addEventListener("open", () => { ws.send(JSON.stringify({ t: "hello", d: { token } })); setTimeout(res, 250); }); });

const u = Math.floor(Math.random() * 1e9);
const alice = await reg("alice-" + u), bob = await reg("bob-" + u);

const aliceWs = new WebSocket(WS); aliceWs.binaryType = "arraybuffer";
const toText = async (d) => (typeof d === "string" ? d : d instanceof ArrayBuffer ? dec.decode(d) : dec.decode(await d.arrayBuffer()));
const received = new Promise((res) => aliceWs.addEventListener("message", async (ev) => {
  const m = JSON.parse(await toText(ev.data));
  if (m.t === "incoming") res(await decrypt(alice.user_id, Uint8Array.from(m.d.ciphertext)));
}));
await hello(aliceWs, alice.token);

const bobWs = new WebSocket(WS); await hello(bobWs, bob.token);
const plaintext = "Настоящий ML-KEM/ChaCha20 из WASM через сервер 🔐";
const payload = await encrypt(bob.user_id, alice.user_id, plaintext);
bobWs.send(JSON.stringify({ t: "send", d: { id: crypto.randomUUID(), from: bob.device_id, to: { direct: alice.user_id }, kind: "chat", ciphertext: Array.from(payload), ts: Date.now() } }));

const got = await Promise.race([received, new Promise((_, rej) => setTimeout(() => rej(new Error("no delivery")), 3000))]);
const ok = got.text === plaintext && got.from === bob.user_id;
console.log(JSON.stringify({ ok, decryptedMatches: got.text === plaintext, serverSawCiphertextBytes: payload.length, sample: got.text }, null, 2));
process.exit(ok ? 0 : 1);
