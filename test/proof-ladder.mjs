/**
 * Proof-ladder test — boots the service with a throwaway signing key
 * over a receipt log seeded with three receipts, then walks every
 * public rung the way a stranger would:
 *
 *  1. The signer document publishes the address the receipts' signer
 *     must match — the anchor lives outside the receipts themselves.
 *  2. A genuine receipt verifies: signature verdict and chain-link
 *     verdict both hold, recovered signer equals the published signer.
 *  3. A receipt altered after signing fails the signature verdict
 *     specifically, while its chain link still holds — the rungs
 *     report separately, never as one blended answer.
 *  4. An unknown receipt id returns the clean 404 shape on both the
 *     read and the verify rung.
 *  5. /health reports the log's real state (count and chain head).
 *
 * No payment is made and no real key is used.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const PORT = 18788;
const BASE = `http://127.0.0.1:${PORT}`;
const DATA_DIR = mkdtempSync(join(tmpdir(), "celo-ladder-"));
const testKey = generatePrivateKey();
const expectedSigner = privateKeyToAccount(testKey).address;

process.env.DATA_DIR = DATA_DIR;
process.env.EMBASSY_SIGNING_KEY = testKey;
const { signReceipt, appendReceipt, lastReceiptHash } = await import("../src/server.js");

function receiptShape(id, txByte) {
  return {
    receipt_version: "embassy-receipt/2",
    receipt_id: id,
    prev_receipt_hash: null,
    issued_at: new Date().toISOString(),
    issuer: {
      name: "Agent Embassy",
      agent_id: 9966,
      agent_registry: "eip155:42220:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
      agent_card: "https://aemb.pro/agent.json",
    },
    chain: {
      REQUEST: { endpoint: "POST /v1/check/verify", input_sha256: "0".repeat(64) },
      AUTHORIZATION: {
        payer: "0x0000000000000000000000000000000000000001",
        pay_to: "0xD004278bC57FE4B9F743ABf17d713ed4169A88E9",
        network: "eip155:42220",
        asset: "0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771",
        amount: "1000",
        authorization_nonce: "0x00",
      },
      ACTION: { check: "url_attestation", result: { url: "https://example.com/", reachable: true, http_status: 200 } },
      PROOF: {
        settlement_tx: "0x" + txByte.repeat(64),
        facilitator: "https://api.x402.celo.org",
        explorer: "https://celoscan.io/tx/0x" + txByte.repeat(64),
      },
      LIABILITY_BOUNDARY: "test",
    },
    signature: { value: null, signer: null, key_id: "embassy-receipt-signing-v1", scheme: null },
  };
}

async function seed(id, txByte, tamper = false) {
  const receipt = receiptShape(id, txByte);
  receipt.prev_receipt_hash = lastReceiptHash();
  await signReceipt(receipt);
  if (tamper) receipt.chain.AUTHORIZATION.amount = "999999"; // altered after signing
  appendReceipt(receipt);
  return receipt;
}

const a = await seed("ladder-receipt-a", "1");
const b = await seed("ladder-receipt-b", "2");
await seed("ladder-receipt-c", "3", true);
const lines = readFileSync(join(DATA_DIR, "receipts.jsonl"), "utf8").trim().split("\n");
const expectedHead = createHash("sha256").update(lines[lines.length - 1]).digest("hex");

let failures = 0;
function check(label, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

const child = spawn("node", ["src/server.js"], {
  env: {
    ...process.env,
    PORT: String(PORT),
    CELO_NETWORK: "mainnet",
    DATA_DIR,
    EMBASSY_SIGNING_KEY: testKey,
  },
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

  const signerDoc = await (await fetch(`${BASE}/.well-known/embassy-signer.json`)).json();
  check("signer document publishes the configured signer", signerDoc.signer === expectedSigner, signerDoc.signer || "null");
  check("signer document names the key id", signerDoc.key_id === "embassy-receipt-signing-v1");

  const health = await (await fetch(`${BASE}/health`)).json();
  check("health counts the seeded receipts", health.receipts_count === 3, `got ${health.receipts_count}`);
  check("health reports the true chain head", health.receipt_chain_head === expectedHead);

  const list = await (await fetch(`${BASE}/v1/receipts`)).json();
  check("receipt list returns all three", list.count === 3 && list.receipts.length === 3);
  check("receipt list is newest first", list.receipts[0]?.receipt_id === "ladder-receipt-c");

  const readA = await fetch(`${BASE}/v1/receipts/${a.receipt_id}`);
  check("one receipt reads back", readA.ok && (await readA.json()).receipt_id === a.receipt_id);

  const verifyA = await (await fetch(`${BASE}/v1/receipts/${a.receipt_id}/verify`)).json();
  check("genesis receipt: signature holds", verifyA.signature_valid === true);
  check("genesis receipt: chain link holds", verifyA.chain_link_valid === true);
  check("genesis receipt: recovered signer is the published signer", verifyA.recovered_signer === expectedSigner);
  check("genesis receipt: settlement link present", typeof verifyA.explorer === "string" && verifyA.explorer.includes("celoscan.io"));

  const verifyB = await (await fetch(`${BASE}/v1/receipts/${b.receipt_id}/verify`)).json();
  check("chained receipt: both verdicts hold", verifyB.signature_valid === true && verifyB.chain_link_valid === true);

  const verifyC = await (await fetch(`${BASE}/v1/receipts/ladder-receipt-c/verify`)).json();
  check("altered receipt: signature verdict fails", verifyC.signature_valid === false);
  check("altered receipt: chain link still holds (verdicts stay separate)", verifyC.chain_link_valid === true);

  const missing = await fetch(`${BASE}/v1/receipts/does-not-exist`);
  check("unknown receipt reads 404", missing.status === 404 && (await missing.json()).error === "receipt_not_found");
  const missingVerify = await fetch(`${BASE}/v1/receipts/does-not-exist/verify`);
  check("unknown receipt verifies 404", missingVerify.status === 404);

  const proof = await fetch(`${BASE}/proof`);
  const proofBody = await proof.text();
  check("proof page serves", proof.ok && proofBody.includes("Check a receipt"));
} finally {
  child.kill("SIGTERM");
}

console.log(failures === 0 ? "\nPROOF LADDER: ALL PASS" : `\nPROOF LADDER: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
