/**
 * Smoke test — boots the service exactly as configured and checks the wire
 * shape a buyer sees. No payment is made; this proves the 402 challenge is
 * byte-correct against the facilitator's own asset table.
 *
 * Asserts:
 *  1. GET /health -> 200, network eip155:42220
 *  2. GET /       -> 200, names ERC-8004 agentId 9966 and the payTo wallet
 *  3. POST /v1/check/verify without payment -> 402 whose accepts[] carry:
 *     x402Version 2, scheme "exact", network "eip155:42220",
 *     payTo 0xD004278bC57FE4B9F743ABf17d713ed4169A88E9,
 *     USA₮ 0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771 amount "1000"
 *       with EIP-712 domain { name: "Tether America USD", version: "1" },
 *     USDC 0xcebA9300f2b948710d2653dD7B07f33A8B32118C amount "1000"
 *       with EIP-712 domain { name: "USDC", version: "2" }.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const EXPECT_PAYTO = "0xD004278bC57FE4B9F743ABf17d713ed4169A88E9";

let failures = 0;
function check(label, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

const child = spawn("node", ["src/server.js"], {
  env: { ...process.env, PORT: String(PORT), CELO_NETWORK: "mainnet" },
  stdio: ["ignore", "pipe", "pipe"],
});
let bootLog = "";
child.stdout.on("data", (d) => (bootLog += d));
child.stderr.on("data", (d) => (bootLog += d));

try {
  let up = false;
  for (let i = 0; i < 40 && !up; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      up = r.ok;
    } catch {
      await sleep(500);
    }
  }
  if (!up) {
    console.log("SERVER BOOT LOG:\n" + bootLog);
    throw new Error("server did not come up");
  }

  const health = await (await fetch(`${BASE}/health`)).json();
  check("health network is Celo mainnet", health.network === "eip155:42220", health.network);
  check("health agent_id is 9966", health.agent_id === 9966);
  check("health pay_to exact", health.pay_to === EXPECT_PAYTO);

  const card = await (await fetch(`${BASE}/`)).json();
  check("service card names ERC-8004", card.agent_identity?.standard === "ERC-8004");
  check("service card agent_id 9966", card.agent_identity?.agent_id === 9966);

  const resp = await fetch(`${BASE}/v1/check/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.com/" }),
  });
  check("unpaid call returns 402", resp.status === 402, `status ${resp.status}`);
  const body = await resp.json();
  const hdrChallenge = resp.headers.get("payment-required");
  check("PAYMENT-REQUIRED header present", Boolean(hdrChallenge));
  if (hdrChallenge) {
    const decoded = JSON.parse(Buffer.from(hdrChallenge, "base64").toString("utf8"));
    check("header challenge matches body challenge", JSON.stringify(decoded) === JSON.stringify(body));
  }
  check("challenge x402Version is 2", body.x402Version === 2, `got ${body.x402Version}`);
  const accepts = body.accepts || [];
  check("two accepts offered (USA₮ + USDC)", accepts.length === 2, `got ${accepts.length}`);

  const byAsset = Object.fromEntries(accepts.map((a) => [a.asset, a]));
  const usat = byAsset["0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771"];
  const usdc = byAsset["0xcebA9300f2b948710d2653dD7B07f33A8B32118C"];
  check("USA₮ accept present", Boolean(usat));
  check("USDC accept present", Boolean(usdc));
  for (const [label, a] of [["USA₮", usat], ["USDC", usdc]]) {
    if (!a) continue;
    check(`${label} scheme exact`, a.scheme === "exact");
    check(`${label} network`, a.network === "eip155:42220", a.network);
    check(`${label} payTo exact`, a.payTo === EXPECT_PAYTO, a.payTo);
    check(`${label} amount 1000 (0.001)`, a.amount === "1000", a.amount);
  }
  if (usat) check("USA₮ EIP-712 domain", usat.extra?.name === "Tether America USD" && usat.extra?.version === "1", JSON.stringify(usat.extra));
  if (usdc) check("USDC EIP-712 domain", usdc.extra?.name === "USDC" && usdc.extra?.version === "2", JSON.stringify(usdc.extra));
} finally {
  child.kill("SIGTERM");
}

console.log(failures === 0 ? "\nSMOKE: ALL PASS" : `\nSMOKE: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
