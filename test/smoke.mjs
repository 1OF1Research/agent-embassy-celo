/**
 * Smoke test — boots the service exactly as configured and checks the wire
 * shape a buyer sees on EVERY paid route. No payment is made; this proves
 * each 402 challenge is byte-correct against the facilitator's own asset
 * table.
 *
 * Asserts, per paid route:
 *  1. GET /health -> 200, network eip155:42220
 *  2. GET /       -> 200, presents no agent identity (none is
 *     configured in this boot) and names the payTo wallet; /health
 *     reports the agent gate open
 *  3. POST <route> without payment -> 402 whose accepts[] carry:
 *     x402Version 2, scheme "exact", network "eip155:42220",
 *     payTo 0xD004278bC57FE4B9F743ABf17d713ed4169A88E9,
 *     USA₮ 0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771 amount "1000"
 *       with EIP-712 domain { name: "Tether America USD", version: "1" },
 *     USDC 0xcebA9300f2b948710d2653dD7B07f33A8B32118C amount "1000"
 *       with EIP-712 domain { name: "USDC", version: "2" }.
 *     The body challenge is byte-identical to the PAYMENT-REQUIRED header
 *     challenge (the Gate 1 assertion, hunted on every route).
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const EXPECT_PAYTO = "0xD004278bC57FE4B9F743ABf17d713ed4169A88E9";
const PAID_ROUTES = [
  { path: "/v1/check/verify", body: { url: "https://example.com/" } },
  { path: "/v1/check/ping", body: { url: "https://example.com/", expect_status: 200 } },
  {
    path: "/v1/check/changes",
    body: { url: "https://example.com/", known_sha256: "0".repeat(64) },
  },
];

let failures = 0;
function check(label, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

const bootEnv = { ...process.env, PORT: String(PORT), CELO_NETWORK: "mainnet" };
/* The identity and the gate are settings; this boot pins the clean
 * out-of-the-box state no matter what the operator's shell carries. */
for (const k of ["AGENT_ID", "AGENT_CARD_URL", "REQUIRE_AGENT_ID", "CELO_RPC_URL"]) delete bootEnv[k];
const child = spawn("node", ["src/server.js"], {
  env: bootEnv,
  stdio: ["ignore", "pipe", "pipe"],
});
let bootLog = "";
child.stdout.on("data", (d) => (bootLog += d));
child.stderr.on("data", (d) => (bootLog += d));

async function checkRoute({ path, body }) {
  const resp = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  check(`${path} unpaid call returns 402`, resp.status === 402, `status ${resp.status}`);
  const respBody = await resp.json();
  const hdrChallenge = resp.headers.get("payment-required");
  check(`${path} PAYMENT-REQUIRED header present`, Boolean(hdrChallenge));
  if (hdrChallenge) {
    const decoded = JSON.parse(Buffer.from(hdrChallenge, "base64").toString("utf8"));
    check(`${path} header challenge matches body challenge`, JSON.stringify(decoded) === JSON.stringify(respBody));
  }
  check(`${path} challenge x402Version is 2`, respBody.x402Version === 2, `got ${respBody.x402Version}`);
  const accepts = respBody.accepts || [];
  check(`${path} two accepts offered (USA₮ + USDC)`, accepts.length === 2, `got ${accepts.length}`);

  const byAsset = Object.fromEntries(accepts.map((a) => [a.asset, a]));
  const usat = byAsset["0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771"];
  const usdc = byAsset["0xcebA9300f2b948710d2653dD7B07f33A8B32118C"];
  check(`${path} USA₮ accept present`, Boolean(usat));
  check(`${path} USDC accept present`, Boolean(usdc));
  for (const [label, a] of [["USA₮", usat], ["USDC", usdc]]) {
    if (!a) continue;
    check(`${path} ${label} scheme exact`, a.scheme === "exact");
    check(`${path} ${label} network`, a.network === "eip155:42220", a.network);
    check(`${path} ${label} payTo exact`, a.payTo === EXPECT_PAYTO, a.payTo);
    check(`${path} ${label} amount 1000 (0.001)`, a.amount === "1000", a.amount);
  }
  if (usat) check(`${path} USA₮ EIP-712 domain`, usat.extra?.name === "Tether America USD" && usat.extra?.version === "1", JSON.stringify(usat.extra));
  if (usdc) check(`${path} USDC EIP-712 domain`, usdc.extra?.name === "USDC" && usdc.extra?.version === "2", JSON.stringify(usdc.extra));
}

try {
  let up = false;
  // Boot includes a live fetch of the facilitator's /supported table;
  // on a slow network that can take well over 20s, so the window is 80s.
  for (let i = 0; i < 160 && !up; i++) {
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
  check("health agent_id null (no identity configured)", health.agent_id === null);
  check("health gate open (require_agent_id false)", health.require_agent_id === false);
  check("health pay_to exact", health.pay_to === EXPECT_PAYTO);

  const card = await (await fetch(`${BASE}/`)).json();
  check("service card presents no agent identity", card.agent_identity === null);

  for (const route of PAID_ROUTES) await checkRoute(route);
} finally {
  child.kill("SIGTERM");
}

console.log(failures === 0 ? "\nSMOKE: ALL PASS" : `\nSMOKE: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
