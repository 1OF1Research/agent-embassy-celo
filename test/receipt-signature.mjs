/**
 * Receipt-signature test — verifies a receipt signed by this service can be
 * verified by a stranger using ONLY the method the README documents:
 * take the receipt JSON with signature.value set to null, SHA-256 the
 * compact JSON, and ecrecover the EIP-191 signature over that digest;
 * the recovered address must equal signature.signer.
 *
 * A throwaway key is generated at run time; no real key is used or stored.
 */

import { createHash } from "node:crypto";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { recoverMessageAddress } from "viem";

const testKey = generatePrivateKey();
const expectedSigner = privateKeyToAccount(testKey).address;
process.env.EMBASSY_SIGNING_KEY = testKey;

const { signReceipt } = await import("../src/server.js");

// The exact receipt shape the paid handler builds before signing.
const receipt = {
  receipt_version: "embassy-receipt/2",
  receipt_id: "test-receipt-0001",
  prev_receipt_hash: "genesis",
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
    PROOF: { settlement_tx: "0x" + "1".repeat(64), facilitator: "https://api.x402.celo.org", explorer: null },
    LIABILITY_BOUNDARY: "test",
  },
  signature: { value: null, signer: null, key_id: "embassy-receipt-signing-v1", scheme: null },
};

await signReceipt(receipt);

let failures = 0;
const check = (label, ok, detail = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
};

check("receipt carries a signature value", typeof receipt.signature?.value === "string");
check("signer is the configured key", receipt.signature?.signer === expectedSigner, receipt.signature?.signer || "null");

// The documented verification method, exactly as the README states it.
const clone = JSON.parse(JSON.stringify(receipt));
clone.signature.value = null;
const digest = createHash("sha256").update(JSON.stringify(clone)).digest();
let recovered = null;
try {
  recovered = await recoverMessageAddress({
    message: { raw: digest },
    signature: receipt.signature.value,
  });
} catch (err) {
  check("ecrecover runs", false, String(err?.message || err));
}
if (recovered) {
  check("documented method recovers the signer", recovered === receipt.signature.signer, `recovered ${recovered}`);
}

console.log(failures === 0 ? "\nRECEIPT SIGNATURE: ALL PASS" : `\nRECEIPT SIGNATURE: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
