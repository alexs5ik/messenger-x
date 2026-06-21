// Verify real per-conversation PQXDH end to end: create accounts (wasm), publish bundles,
// resolve the peer via the prekey directory, run the initiator/responder handshake, and
// confirm both sides derive the SAME secret and can seal/open with it.
import init, { account_create, session_initiator, session_responder, seal, open } from "../web/src/mxwasm/mx_crypto_wasm.js";
import { readFileSync } from "node:fs";

const BASE = process.env.MX_BASE ?? "http://127.0.0.1:9990";
await init({ module_or_path: readFileSync(new URL("../web/src/mxwasm/mx_crypto_wasm_bg.wasm", import.meta.url)) });

const reg = async (n) => (await (await fetch(BASE + "/v1/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: n, identity_key: { algo: "x25519", bytes: [1] } }) })).json());
const publish = async (bundleJson) => {
  const r = await fetch(BASE + "/v1/prekeys", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ bundle: JSON.parse(bundleJson) }) });
  if (!r.ok) throw new Error("publish " + r.status + " " + (await r.text()));
};

const u = Math.floor(Math.random() * 1e9);
const alice = await reg("alice-" + u);
const bob = await reg("bob-" + u);
const aliceAcc = account_create(alice.device_id);
const bobAcc = account_create(bob.device_id);
await publish(aliceAcc.bundle_json);
await publish(bobAcc.bundle_json);

// Alice fetches Bob from the directory (by user id) and runs the initiator handshake.
const bobBundle = await (await fetch(BASE + "/v1/users/" + bob.user_id + "/prekey")).text();
const sess = session_initiator(aliceAcc.secrets, bobBundle);
// Bob derives the same secret from Alice's init message using his stored secrets.
const bobSecret = session_responder(bobAcc.secrets, sess.init_json);

const secretsMatch = Buffer.from(sess.secret).equals(Buffer.from(bobSecret));
const msg = "real PQXDH per-conversation 🔐";
const ct = seal(sess.secret, new TextEncoder().encode(msg));
const sealOpen = new TextDecoder().decode(open(bobSecret, ct)) === msg;

console.log(JSON.stringify({ secretsMatch, sealOpen, secretLen: sess.secret.length, initBytes: sess.init_json.length }, null, 2));
process.exit(secretsMatch && sealOpen ? 0 : 1);
