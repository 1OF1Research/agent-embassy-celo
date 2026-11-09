/**
 * Agent-gate test — the operator-side acceptance policy (REQUIRE_AGENT_ID)
 * and the configured identity (AGENT_ID), proven at the wire.
 *
 * The scenario, in the owner's words: an operator sets the box to
 * agentid-only, and from then on only customers who present an agent
 * number they actually own can pay; everyone else is turned away before
 * any money moves.
 *
 * The chain boundary this service reads is the Celo JSON-RPC endpoint
 * (CELO_RPC_URL). These tests stub exactly that boundary: a local stub
 * RPC answers ownerOf(agentId) from a two-row table — agent 12345 belongs
 * to the test payer, every other number belongs to someone else. The
 * stub is named here so nobody mistakes it for a chain read: every
 * ownership verdict in this file comes from the stub. Live-chain refusal
 * behavior is proven separately against a real network instance.
 *
 * Asserts:
 *  Gate ON  (boot A): the 402 challenge and x402.json advertise
 *    agentIdRequired; a paid call with no agentId is refused
 *    (agent_id_required) with no receipt written; a paid call naming an
 *    agentId the payer does not own is refused (agent_id_not_owned),
 *    again with no receipt; a paid call naming the payer's own agentId
 *    passes the gate into the payment flow (the facilitator's own
 *    verdict on the fabricated authorization is downstream and is NOT
 *    asserted — only that the refusal is not the gate's).
 *  Gate OFF (boot B): accepts carry exactly today's bare extras, health
 *    reports the gate open and no identity, the agent card carries no
 *    registration, descriptions name no agent number.
 *  Identity (boot C): with AGENT_ID=12345 (a placeholder, nobody's real
 *    number), health, the agent card, the service card, and every
 *    description present that number; accepts stay bare (gate off).
 *
 * No real payment is made and no real key is used: the payer is a
 * throwaway key with no funds, so no authorization in this file can
 * settle.
 */

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
const USDC = "0xcebA9300f2b948710d2653dD7B07f33A8B32118C";
const OWNED_ID = 12345; // placeholder fixture number — the stub makes the payer own it
const FOREIGN_ID = 999; // the stub gives this one to someone else

const payerAccount = privateKeyToAccount(generatePrivateKey());
const PAYER = payerAccount.address;
const OTHER = "0x000000000000000000000000000000000000dEaD";

let failures = 0;
function check(label, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

/* ------------------------------------------------------------------ */
/* The stub chain boundary: a local JSON-RPC server answering eth_call */
/* ownerOf(agentId) from the fixture table above.                      */
/* ------------------------------------------------------------------ */
const stubRpc = createServer((req, res) => {
  let raw = "";
  req.on("data", (d) => (raw += d));
  req.on("end", () => {
    let out = { jsonrpc: "2.0", id: 1, result: "0x" };
    try {
      const call = JSON.parse(raw);
      const data = call.params?.[0]?.data || "";
      if (call.method === "eth_call" && data.startsWith("0x6352211e")) {
        const id = Number(BigInt("0x" + data.slice(-64)));
        const owner = id === OWNED_ID ? PAYER : OTHER;
        out.result = "0x" + owner.slice(2).toLowerCase().padStart(64, "0");
      }
    } catch { /* the stub answers empty to anything it does not model */ }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(out));
  });
});
await new Promise((r) => stubRpc.listen(18793, "127.0.0.1", r));
const STUB_RPC_URL = "http://127.0.0.1:18793";

/* ------------------------------------------------------------------ */
/* Boot helper — env is built explicitly so an operator shell that     */
/* happens to carry these variables can never leak into a boot.        */
/* ------------------------------------------------------------------ */
async function boot(port, extraEnv) {
  const env = { ...process.env, PORT: String(port), CELO_NETWORK: "mainnet", DATA_DIR: mkdtempSync(join(tmpdir(), "celo-gate-")) };
  for (const k of ["AGENT_ID", "AGENT_CARD_URL", "REQUIRE_AGENT_ID", "CELO_RPC_URL", "X402_CELO_API_KEY", "EMBASSY_SIGNING_KEY"]) delete env[k];
  Object.assign(env, extraEnv);
  const child = spawn("node", ["src/server.js"], { env, stdio: ["ignore", "pipe", "pipe"] });
  let bootLog = "";
  child.stdout.on("data", (d) => (bootLog += d));
  child.stderr.on("data", (d) => (bootLog += d));
  const base = `http://127.0.0.1:${port}`;
  let up = false;
  for (let i = 0; i < 160 && !up; i++) {
    try {
      const r = await fetch(`${base}/health`);
      up = r.ok;
    } catch {
      await sleep(500);
    }
  }
  if (!up) {
    console.log("SERVER BOOT LOG:\n" + bootLog);
    child.kill("SIGTERM");
    throw new Error(`server on ${port} did not come up`);
  }
  return { child, base };
}

/** A real EIP-3009 authorization from the throwaway payer, wrapped in
 *  the x402 v2 payload shape — real signature, no funds behind it. */
async function paidHeader(base) {
  const unpaid = await fetch(`${base}/v1/check/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.com/" }),
  });
  const challenge = await unpaid.json();
  const accept = (challenge.accepts || []).find((a) => a.asset === USDC);
  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: PAYER,
    to: accept.payTo,
    value: accept.amount,
    validAfter: "0",
    validBefore: String(now + (accept.maxTimeoutSeconds || 300) - 60),
    nonce: "0x" + randomBytes(32).toString("hex"),
  };
  const signature = await payerAccount.signTypedData({
    domain: { name: accept.extra.name, version: accept.extra.version, chainId: 42220, verifyingContract: accept.asset },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message: authorization,
  });
  return Buffer.from(JSON.stringify({ x402Version: 2, accepted: accept, payload: { signature, authorization } })).toString("base64");
}

async function paidCall(base, header, body) {
  const resp = await fetch(`${base}/v1/check/verify`, {
    method: "POST",
    headers: { "content-type": "application/json", "PAYMENT-SIGNATURE": header },
    body: JSON.stringify(body),
  });
  return { status: resp.status, body: await resp.json().catch(() => ({})) };
}
const isGateRefusal = (r) => r.status === 403 && String(r.body?.error || "").startsWith("agent_id");

/* ---------------- Boot A: gate ON ---------------- */
{
  const { child, base } = await boot(18790, { REQUIRE_AGENT_ID: "on", CELO_RPC_URL: STUB_RPC_URL });
  try {
    const health = await (await fetch(`${base}/health`)).json();
    check("A health: gate reported on", health.require_agent_id === true);
    check("A health: no operator identity configured", health.agent_id === null);
    check("A health: receipt log starts empty", health.receipts_count === 0);

    const unpaid = await fetch(`${base}/v1/check/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "https://example.com/" }),
    });
    const challenge = await unpaid.json();
    check("A unpaid call still returns the 402 challenge", unpaid.status === 402, `status ${unpaid.status}`);
    check(
      "A challenge advertises agentIdRequired on every accept",
      (challenge.accepts || []).length === 2 && challenge.accepts.every((a) => a.extra?.agentIdRequired === true),
    );
    const x402 = await (await fetch(`${base}/.well-known/x402.json`)).json();
    check(
      "A x402.json advertises agentIdRequired on every accept",
      (x402.resources || []).every((r) => (r.accepts || []).every((a) => a.extra?.agentIdRequired === true)),
    );

    const header = await paidHeader(base);
    const noId = await paidCall(base, header, { url: "https://example.com/" });
    check("A paid call with no agentId is refused", noId.status === 403 && noId.body?.error === "agent_id_required", JSON.stringify(noId.body).slice(0, 120));
    const foreign = await paidCall(base, header, { url: "https://example.com/", agentId: FOREIGN_ID });
    check("A paid call naming someone else's agentId is refused", foreign.status === 403 && foreign.body?.error === "agent_id_not_owned", JSON.stringify(foreign.body).slice(0, 120));
    const afterRefusals = await (await fetch(`${base}/health`)).json();
    check("A refusals wrote no receipt and settled nothing", afterRefusals.receipts_count === 0);

    const owned = await paidCall(base, header, { url: "https://example.com/", agentId: OWNED_ID });
    check("A paid call naming the payer's own agentId passes the gate", !isGateRefusal(owned) && owned.body?.error !== "agent_id_check_failed", `status ${owned.status}, error ${owned.body?.error || "none"}`);
    const ownedStr = await paidCall(base, header, { url: "https://example.com/", agentId: String(OWNED_ID) });
    check("A the same ownership passes with the number sent as a string", !isGateRefusal(ownedStr), `status ${ownedStr.status}`);
  } finally {
    child.kill("SIGTERM");
  }
}

/* ---------------- Boot B: gate OFF, no identity ---------------- */
{
  const { child, base } = await boot(18791, {});
  try {
    const health = await (await fetch(`${base}/health`)).json();
    check("B health: gate reported open", health.require_agent_id === false);
    check("B health: no identity presented", health.agent_id === null);

    const unpaid = await fetch(`${base}/v1/check/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "https://example.com/" }),
    });
    const challenge = await unpaid.json();
    check(
      "B challenge extras are exactly today's bare shape",
      (challenge.accepts || []).every((a) => Object.keys(a.extra || {}).sort().join(",") === "name,version"),
      JSON.stringify((challenge.accepts || []).map((a) => a.extra)),
    );
    const x402 = await (await fetch(`${base}/.well-known/x402.json`)).json();
    check("B descriptions name no agent number", (x402.resources || []).every((r) => !String(r.description).includes("agentId")));
    const card = await (await fetch(`${base}/.well-known/agent.json`)).json();
    check("B agent card carries no registration", !card.registrations || card.registrations.length === 0);
    const svc = await (await fetch(`${base}/`)).json();
    check("B service card presents no identity", svc.agent_identity === null);
  } finally {
    child.kill("SIGTERM");
  }
}

/* ---------------- Boot C: identity configured, gate OFF ---------------- */
{
  const { child, base } = await boot(18792, { AGENT_ID: String(OWNED_ID), AGENT_CARD_URL: "https://example.com/agent.json" });
  try {
    const health = await (await fetch(`${base}/health`)).json();
    check("C health: configured agent number reported", health.agent_id === OWNED_ID);
    check("C health: gate still open", health.require_agent_id === false);
    const x402 = await (await fetch(`${base}/.well-known/x402.json`)).json();
    check(
      "C descriptions carry the configured number",
      (x402.resources || []).every((r) => String(r.description).includes(`ERC-8004 agentId ${OWNED_ID}.`)),
    );
    check(
      "C accepts stay bare with the gate off",
      (x402.resources || []).every((r) => (r.accepts || []).every((a) => !("agentIdRequired" in (a.extra || {})))),
    );
    const card = await (await fetch(`${base}/.well-known/agent.json`)).json();
    check(
      "C agent card registers the configured number",
      card.registrations?.[0]?.agentId === OWNED_ID && card.registrations?.[0]?.agentRegistry === `eip155:42220:${REGISTRY}`,
      JSON.stringify(card.registrations),
    );
    const svc = await (await fetch(`${base}/`)).json();
    check(
      "C service card presents the configured identity",
      svc.agent_identity?.agent_id === OWNED_ID && svc.agent_identity?.agent_card === "https://example.com/agent.json",
    );
  } finally {
    child.kill("SIGTERM");
  }
}

stubRpc.close();
console.log(failures === 0 ? "\nAGENT-GATE: ALL PASS" : `\nAGENT-GATE: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
