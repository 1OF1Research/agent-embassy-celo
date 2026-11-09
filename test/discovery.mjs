/**
 * Discovery test — the shelf an outside agent reads before it ever
 * calls: x402.json, the OpenAPI document, the agent card, llms.txt,
 * and the service card. The documents are generated from one route
 * table; this suite proves the consequence a stranger relies on —
 * every document names exactly the same paid shelf, every named
 * route answers, and nothing live is left unadvertised.
 *
 * No payment is made.
 */

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const PORT = 18789;
const BASE = `http://127.0.0.1:${PORT}`;
const EXPECTED_ROUTES = ["/v1/check/verify", "/v1/check/ping", "/v1/check/changes"];
const EXPECT_PAYTO = "0xD004278bC57FE4B9F743ABf17d713ed4169A88E9";
const USAT = "0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771";
const USDC = "0xcebA9300f2b948710d2653dD7B07f33A8B32118C";

let failures = 0;
function check(label, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}
const sameSet = (xs, ys) => xs.length === ys.length && xs.every((x) => ys.includes(x));

const child = spawn("node", ["src/server.js"], {
  env: { ...process.env, PORT: String(PORT), CELO_NETWORK: "mainnet" },
  stdio: ["ignore", "pipe", "pipe"],
});
let bootLog = "";
child.stdout.on("data", (d) => (bootLog += d));
child.stderr.on("data", (d) => (bootLog += d));

try {
  let up = false;
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

  /* x402 discovery document */
  const x402 = await (await fetch(`${BASE}/.well-known/x402.json`)).json();
  check("x402.json is version 2", x402.x402Version === 2);
  const x402Paths = (x402.resources || []).map((r) => new URL(r.resource).pathname);
  check("x402.json names the whole shelf", sameSet(x402Paths, EXPECTED_ROUTES), x402Paths.join(", "));
  for (const resource of x402.resources || []) {
    const assets = (resource.accepts || []).map((a) => a.asset);
    check(
      `x402.json ${new URL(resource.resource).pathname} offers both assets at 1000 to the exact payTo`,
      sameSet(assets, [USAT, USDC]) &&
        resource.accepts.every((a) => a.amount === "1000" && a.payTo === EXPECT_PAYTO && a.network === "eip155:42220"),
    );
  }

  /* OpenAPI document */
  const openapi = await (await fetch(`${BASE}/openapi.json`)).json();
  const openapiPaid = Object.keys(openapi.paths || {}).filter((p) => p.startsWith("/v1/check/"));
  check("openapi names the whole shelf", sameSet(openapiPaid, EXPECTED_ROUTES), openapiPaid.join(", "));
  check(
    "openapi documents the ladder",
    ["/v1/receipts", "/v1/receipts/{receiptId}", "/v1/receipts/{receiptId}/verify", "/.well-known/embassy-signer.json"].every(
      (p) => p in (openapi.paths || {}),
    ),
  );

  /* Agent card */
  const card = await (await fetch(`${BASE}/.well-known/agent.json`)).json();
  const cardX402 = (card.services || []).filter((s) => s.name === "x402").map((s) => new URL(s.endpoint).pathname);
  check("agent card names the whole shelf", sameSet(cardX402, EXPECTED_ROUTES), cardX402.join(", "));
  check("agent card keeps registration 9966", card.registrations?.[0]?.agentId === 9966);
  check("agent card declares x402 support", card.x402Support === true);

  /* llms.txt */
  const llmsResp = await fetch(`${BASE}/llms.txt`);
  const llms = await llmsResp.text();
  check("llms.txt serves as text", llmsResp.ok && (llmsResp.headers.get("content-type") || "").includes("text/plain"));
  check("llms.txt names the whole shelf", EXPECTED_ROUTES.every((p) => llms.includes(p)));

  /* Service card */
  const svc = await (await fetch(`${BASE}/`)).json();
  const svcPaths = (svc.endpoints || []).map((e) => e.path);
  check("service card names the whole shelf", sameSet(svcPaths, EXPECTED_ROUTES), svcPaths.join(", "));
  check("service card links the proof ladder", typeof svc.proof?.verify === "string" && svc.proof.verify.includes("/v1/receipts/"));
  check("service card links the discovery shelf", typeof svc.discovery?.x402 === "string" && svc.discovery.x402.endsWith("/.well-known/x402.json"));

  /* Every advertised public route answers */
  for (const p of ["/health", "/", "/.well-known/agent.json", "/.well-known/embassy-signer.json", "/.well-known/x402.json", "/openapi.json", "/llms.txt", "/v1/receipts", "/proof"]) {
    const r = await fetch(`${BASE}${p}`);
    check(`advertised route answers: GET ${p}`, r.ok, `status ${r.status}`);
  }
} finally {
  child.kill("SIGTERM");
}

console.log(failures === 0 ? "\nDISCOVERY: ALL PASS" : `\nDISCOVERY: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
