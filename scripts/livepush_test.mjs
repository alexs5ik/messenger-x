// Deterministic test of the server's real-time WS push (no browser, no polling).
// Two WebSocket clients connect; Bob sends to Alice while Alice is already connected and
// idle. If Alice's socket receives the envelope promptly, live push works.
const BASE = process.env.MX_BASE ?? "http://127.0.0.1:9990";
const WS = BASE.replace(/^http/, "ws") + "/v1/ws";

const reg = async (name) => {
  const r = await fetch(BASE + "/v1/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: name, identity_key: { algo: "x25519", bytes: [1, 2, 3] } }),
  });
  if (!r.ok) throw new Error("register " + name + ": " + r.status + " " + (await r.text()));
  return r.json();
};

const hello = (ws, token) =>
  new Promise((res, rej) => {
    ws.addEventListener("open", () => ws.send(JSON.stringify({ t: "hello", d: { token } })));
    ws.addEventListener("error", () => rej(new Error("ws error")));
    setTimeout(res, 300); // give hello a moment to be processed
  });

const main = async () => {
  const u = Math.floor(Math.random() * 1e9);
  const alice = await reg("alice-" + u);
  const bob = await reg("bob-" + u);

  const aliceWs = new WebSocket(WS);
  aliceWs.binaryType = "arraybuffer";
  const dec = new TextDecoder();
  const toText = async (data) =>
    typeof data === "string"
      ? data
      : data instanceof ArrayBuffer
        ? dec.decode(data)
        : dec.decode(await data.arrayBuffer());
  const got = new Promise((res) => {
    aliceWs.addEventListener("message", async (ev) => {
      const m = JSON.parse(await toText(ev.data));
      if (m.t === "incoming") res({ from: m.d.from, ct: m.d.ciphertext });
    });
  });
  await hello(aliceWs, alice.token);

  const bobWs = new WebSocket(WS);
  await hello(bobWs, bob.token);

  // Alice is connected and idle. Bob sends now — this exercises LIVE push (the connect
  // flush already ran and was empty).
  const marker = [77, 88, 0, 1, 2, 3]; // opaque bytes; push test doesn't need real crypto
  const t0 = performance.now();
  bobWs.send(
    JSON.stringify({
      t: "send",
      d: {
        id: crypto.randomUUID(),
        from: bob.device_id,
        to: { direct: alice.user_id },
        kind: "chat",
        ciphertext: marker,
        ts: Date.now(),
      },
    }),
  );

  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("NO PUSH within 2s")), 2000));
  const recv = await Promise.race([got, timeout]);
  const latency = Math.round(performance.now() - t0);

  const ok = recv.from === bob.device_id && JSON.stringify(recv.ct) === JSON.stringify(marker);
  console.log(JSON.stringify({ livePush: ok, latencyMs: latency, fromMatches: recv.from === bob.device_id }, null, 2));
  process.exit(ok ? 0 : 1);
};

main().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
