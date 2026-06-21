// Verify the wasm crypto core runs: load the web-target wasm with explicit bytes (Node has
// no fetch for file URLs), run the PQXDH self-test, and a seal/open round-trip + tamper check.
import init, { pqxdh_selftest, seal, open } from "../web/src/mxwasm/mx_crypto_wasm.js";
import { readFileSync } from "node:fs";

const wasmBytes = readFileSync(new URL("../web/src/mxwasm/mx_crypto_wasm_bg.wasm", import.meta.url));
await init({ module_or_path: wasmBytes });

const selftest = JSON.parse(pqxdh_selftest());

const secret = new Uint8Array(32).fill(7);
const msg = "hello from real wasm crypto 🔐";
const ct = seal(secret, new TextEncoder().encode(msg));
const pt = new TextDecoder().decode(open(secret, ct));
const roundtrip = pt === msg;

let tamperRejected = false;
try {
  const bad = Uint8Array.from(ct);
  bad[bad.length - 1] ^= 0xff;
  open(secret, bad);
} catch {
  tamperRejected = true;
}

console.log(JSON.stringify({ selftest, sealOpenRoundtrip: roundtrip, ciphertextBytes: ct.length, tamperRejected }, null, 2));
process.exit(selftest.ok && roundtrip && tamperRejected ? 0 : 1);
