// Verify the per-message Double Ratchet over a real PQXDH-seeded session (pure crypto, no
// server): establish, then exchange several messages, confirming each decrypts and the state
// (and thus the per-message key) advances every message.
import init, { account_create, session_initiator, session_responder, ratchet_encrypt, ratchet_decrypt } from "../web/src/mxwasm/mx_crypto_wasm.js";
import { readFileSync } from "node:fs";
await init({ module_or_path: readFileSync(new URL("../web/src/mxwasm/mx_crypto_wasm_bg.wasm", import.meta.url)) });

const enc = new TextEncoder(), dec = new TextDecoder();
const hex = (u) => Buffer.from(u).toString("hex");

const aliceAcc = account_create(crypto.randomUUID());
const bobAcc = account_create(crypto.randomUUID());

// Alice initiates against Bob's published bundle; Bob seeds the matching ratchet from the init.
const sess = session_initiator(aliceAcc.secrets, bobAcc.bundle_json);
let aliceRt = sess.ratchet;
let bobRt = session_responder(bobAcc.secrets, sess.init_json);

const msgs = ["сообщение 1", "сообщение 2 (цепочка двигается)", "сообщение 3"];
const results = [];
const frameSamples = [];
for (const m of msgs) {
  const e = ratchet_encrypt(aliceRt, enc.encode(m));
  aliceRt = e.state;
  frameSamples.push(hex(e.data).slice(0, 24));
  const d = ratchet_decrypt(bobRt, e.data);
  bobRt = d.state;
  results.push(dec.decode(d.data) === m);
}

// Forward-secrecy sanity: encrypting identical content twice yields different frames (the
// per-message key advanced). Decrypt both in order to confirm they still open.
const e1 = ratchet_encrypt(aliceRt, enc.encode("same"));
aliceRt = e1.state;
const e2 = ratchet_encrypt(aliceRt, enc.encode("same"));
aliceRt = e2.state;
const framesDiffer = hex(e1.data) !== hex(e2.data);
const d1 = ratchet_decrypt(bobRt, e1.data); bobRt = d1.state;
const d2 = ratchet_decrypt(bobRt, e2.data); bobRt = d2.state;
const sameOpens = dec.decode(d1.data) === "same" && dec.decode(d2.data) === "same";

console.log(JSON.stringify({
  sameOpens,
  allDecrypted: results.every(Boolean),
  count: results.length,
  framesDifferForSameText: framesDiffer,
  firstFramePrefixes: frameSamples,
}, null, 2));
process.exit(results.every(Boolean) && framesDiffer && sameOpens ? 0 : 1);
