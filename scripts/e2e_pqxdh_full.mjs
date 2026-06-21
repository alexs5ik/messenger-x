// Authoritative E2E of the real-PQXDH client flow through the live server, mirroring
// crypto.ts exactly: provision accounts -> publish bundles -> directory fetch -> PQXDH
// handshake -> seal -> send over WS -> receive -> responder handshake -> open. Bidirectional.
import init, { account_create, session_initiator, session_responder, seal, open } from "../web/src/mxwasm/mx_crypto_wasm.js";
import { readFileSync } from "node:fs";

const BASE = process.env.MX_BASE ?? "http://127.0.0.1:9990";
const WS = BASE.replace(/^http/, "ws") + "/v1/ws";
await init({ module_or_path: readFileSync(new URL("../web/src/mxwasm/mx_crypto_wasm_bg.wasm", import.meta.url)) });
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (u) => Buffer.from(u).toString("base64"), unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

const reg = async (n) => (await (await fetch(BASE + "/v1/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: n, identity_key: { algo: "x25519", bytes: [1] } }) })).json());
const publish = async (j) => { const r = await fetch(BASE + "/v1/prekeys", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ bundle: JSON.parse(j) }) }); if (!r.ok) throw new Error("publish " + r.status); };
const hello = (ws, token) => new Promise((res) => { ws.addEventListener("open", () => { ws.send(JSON.stringify({ t: "hello", d: { token } })); setTimeout(res, 250); }); });
const toText = async (d) => (typeof d === "string" ? d : d instanceof ArrayBuffer ? dec.decode(d) : dec.decode(await d.arrayBuffer()));

// per-party crypto state (mirrors crypto.ts)
const mk = (secrets) => ({ secrets, out: new Map(), in: new Map() });
async function encryptFrom(p, me, peer, text) {
  let s = p.out.get(peer);
  if (!s) { const bundle = await (await fetch(BASE + "/v1/users/" + peer + "/prekey")).text(); const e = session_initiator(p.secrets, bundle); s = { secret: e.secret, init: e.init_json }; p.out.set(peer, s); }
  return enc.encode(JSON.stringify({ from: me, c: b64(seal(s.secret, enc.encode(text))), init: s.init }));
}
function decryptTo(p, payloadBytes) {
  const o = JSON.parse(dec.decode(payloadBytes));
  let c = p.in.get(o.from);
  if (!c || c.init !== o.init) { c = { init: o.init, secret: session_responder(p.secrets, o.init) }; p.in.set(o.from, c); }
  return { from: o.from, text: dec.decode(open(c.secret, unb64(o.c))) };
}

const u = Math.floor(Math.random() * 1e9);
const alice = await reg("alice-" + u), bob = await reg("bob-" + u);
const aliceAcc = account_create(alice.device_id), bobAcc = account_create(bob.device_id);
await publish(aliceAcc.bundle_json); await publish(bobAcc.bundle_json);
const A = mk(aliceAcc.secrets), B = mk(bobAcc.secrets);

const sendVia = (ws, fromDev, toUser, payload) => ws.send(JSON.stringify({ t: "send", d: { id: crypto.randomUUID(), from: fromDev, to: { direct: toUser }, kind: "chat", ciphertext: Array.from(payload), ts: Date.now() } }));

const aliceWs = new WebSocket(WS); aliceWs.binaryType = "arraybuffer";
const bobWs = new WebSocket(WS); bobWs.binaryType = "arraybuffer";
const bobGot = new Promise((res) => bobWs.addEventListener("message", async (ev) => { const m = JSON.parse(await toText(ev.data)); if (m.t === "incoming") res(decryptTo(B, Uint8Array.from(m.d.ciphertext))); }));
const aliceGot = new Promise((res) => aliceWs.addEventListener("message", async (ev) => { const m = JSON.parse(await toText(ev.data)); if (m.t === "incoming") res(decryptTo(A, Uint8Array.from(m.d.ciphertext))); }));
await hello(aliceWs, alice.token); await hello(bobWs, bob.token);

sendVia(aliceWs, alice.device_id, bob.user_id, await encryptFrom(A, alice.user_id, bob.user_id, "Привет, Боб — настоящий PQXDH"));
const r1 = await Promise.race([bobGot, new Promise((_, j) => setTimeout(() => j(new Error("bob timeout")), 3000))]);
sendVia(bobWs, bob.device_id, alice.user_id, await encryptFrom(B, bob.user_id, alice.user_id, "Привет, Алиса — и в обратную сторону"));
const r2 = await Promise.race([aliceGot, new Promise((_, j) => setTimeout(() => j(new Error("alice timeout")), 3000))]);

const ok = r1.text === "Привет, Боб — настоящий PQXDH" && r2.text === "Привет, Алиса — и в обратную сторону";
console.log(JSON.stringify({ ok, bobReceived: r1.text, aliceReceived: r2.text }, null, 2));
process.exit(ok ? 0 : 1);
