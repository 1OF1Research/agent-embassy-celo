/**
 * Agent Embassy on Celo — a pay-per-call verification surface.
 *
 * One paid endpoint: POST /v1/check/verify
 *   Body: { "url": "https://example.com/page" }
 *   Price: 0.001 of a US dollar stablecoin (USA₮ preferred, USDC accepted)
 *   on Celo mainnet (eip155:42220), settled through Celo's hosted x402
 *   facilitator (https://api.x402.celo.org). The buyer signs an EIP-3009
 *   authorization; the facilitator pays the settlement gas; funds move
 *   buyer -> payTo directly. Every settled call returns the check result
 *   plus a signed Embassy receipt (embassy-receipt/2 shape).
 *
 * Identity: ERC-8004 agentId 9966 on Celo mainnet, registry
 * 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432, agent card
 * https://aemb.pro/agent.json (tokenURI of 9966, verified onchain).
 *
 * Attribution (ERC-8021): the hackathon's rule for x402 is that attribution
 * rides the PayTo address, because x402 does not yet support attribution
 * tags. PayTo below is that address; it is declared in the submission.
 *
 * Written for the Agents on Open Rails hackathon, November 2026.
 * Derived from the live Agent Embassy x402 stack (same @x402 v2 packages,
 * same receipt scheme) — this file is new code for this entry.
 */

import express from "express";
import { createHash, randomUUID } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  x402ResourceServer,
  x402HTTPResourceServer,
  HTTPFacilitatorClient,
} from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExpressAdapter } from "@x402/express";
import { privateKeyToAccount } from "viem/accounts";

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

const PORT = Number(process.env.PORT || 8787);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
const DATA_DIR = process.env.DATA_DIR || join(process.cwd(), "data");
const FACILITATOR_API_KEY = process.env.X402_CELO_API_KEY || "";
const SIGNING_KEY = process.env.EMBASSY_SIGNING_KEY || "";
const NETWORK_MODE = (process.env.CELO_NETWORK || "mainnet").toLowerCase();

/** The Embassy's operating wallet — payTo on every chain, and the owner of
 *  ERC-8004 agentId 9966 on Celo (verified onchain 2026-11-03). */
export const PAY_TO = "0xD004278bC57FE4B9F743ABf17d713ed4169A88E9";
export const AGENT_ID = 9966;
export const AGENT_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";
export const AGENT_CARD = "https://aemb.pro/agent.json";

/** Price of one check: 0.001 in the asset's smallest unit (6 decimals). */
const PRICE_SMALLEST_UNIT = "1000";

/**
 * Network + asset table. Asset addresses, EIP-712 domain name/version are
 * asserted against the facilitator's own /supported response
 * (https://api.x402.celo.org/supported, read 2026-11-03).
 */
const NETWORKS = {
  mainnet: {
    network: "eip155:42220",
    facilitatorUrl: "https://api.x402.celo.org",
    explorerTx: (tx) => `https://celoscan.io/tx/${tx}`,
    assets: [
      {
        symbol: "USA₮",
        address: "0xD2ab3C9A02DBBAB236BfEC45D1d755DF4267F771",
        extra: { name: "Tether America USD", version: "1" },
      },
      {
        symbol: "USDC",
        address: "0xcebA9300f2b948710d2653dD7B07f33A8B32118C",
        extra: { name: "USDC", version: "2" },
      },
    ],
  },
  sepolia: {
    network: "eip155:11142220",
    facilitatorUrl: "https://api.x402.sepolia.celo.org",
    explorerTx: (tx) => `https://celo-sepolia.blockscout.com/tx/${tx}`,
    assets: [
      {
        symbol: "USDC",
        address: "0x01C5C0122039549AD1493B8220cABEdD739BC44E",
        extra: { name: "USDC", version: "2" },
      },
    ],
  },
};
const NET = NETWORKS[NETWORK_MODE] || NETWORKS.mainnet;

const VERIFY_DESCRIPTION =
  "Agent Embassy URL verification on Celo: fetch a URL and return a signed " +
  "attestation of what was observed (reachability, HTTP status, byte count, " +
  "SHA-256 of the body). Price 0.001 USD in USA₮ or USDC on Celo mainnet, " +
  "settled through Celo's hosted x402 facilitator. ERC-8004 agentId 9966.";

/* ------------------------------------------------------------------ */
/* Receipt signing (same scheme as the Embassy's production receipts): */
/* EIP-191 personal_sign over sha256 of the canonical receipt JSON,    */
/* with signature.value nulled in the hashed bytes — signer, key_id,   */
/* and scheme are hashed in place, exactly as a verifier re-hashes.    */
/* ------------------------------------------------------------------ */

const SIGNING_KEY_ID = "embassy-receipt-signing-v1";
let signerAccount = null;
if (SIGNING_KEY) {
  try {
    signerAccount = privateKeyToAccount(SIGNING_KEY);
  } catch {
    signerAccount = null;
  }
}

export function canonicalReceiptBytes(receipt) {
  const clone = JSON.parse(JSON.stringify(receipt));
  if (clone.signature) clone.signature.value = null;
  return JSON.stringify(clone);
}

export async function signReceipt(receipt) {
  if (!signerAccount) {
    receipt.signature = {
      value: null,
      signer: null,
      key_id: SIGNING_KEY_ID,
      scheme: "EIP-191 over sha256(canonical receipt); unsigned in this deployment (no signing key configured)",
    };
    return receipt;
  }
  /* The block must reach its final shape BEFORE the digest is taken:
   * a verifier nulls only signature.value and re-hashes, so signer,
   * key_id, and scheme must already be in place at signing time —
   * filling them in afterwards changes the bytes and the signature
   * no longer verifies by the documented method. */
  receipt.signature = {
    value: null,
    signer: signerAccount.address,
    key_id: SIGNING_KEY_ID,
    scheme: "EIP-191 over sha256(canonical receipt, signature.value excluded)",
  };
  const digest = createHash("sha256").update(canonicalReceiptBytes(receipt)).digest();
  receipt.signature.value = await signerAccount.signMessage({ message: { raw: digest } });
  return receipt;
}

/* Hash-chained append-only receipt log (same pattern as production). */
const RECEIPTS_PATH = join(DATA_DIR, "receipts.jsonl");
function lastReceiptHash() {
  try {
    if (!existsSync(RECEIPTS_PATH)) return "genesis";
    const lines = readFileSync(RECEIPTS_PATH, "utf8").trim().split("\n").filter(Boolean);
    if (!lines.length) return "genesis";
    return createHash("sha256").update(lines[lines.length - 1]).digest("hex");
  } catch {
    return "genesis";
  }
}
function appendReceipt(receipt) {
  mkdirSync(DATA_DIR, { recursive: true });
  appendFileSync(RECEIPTS_PATH, JSON.stringify(receipt) + "\n");
}

/* ------------------------------------------------------------------ */
/* The work: a URL attestation check.                                  */
/* ------------------------------------------------------------------ */

async function runUrlCheck(input) {
  const url = typeof input?.url === "string" ? input.url.trim() : "";
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { inputError: "body.url must be a valid absolute URL" };
  }
  if (!/^https?:$/.test(parsed.protocol)) {
    return { inputError: "body.url must use http or https" };
  }
  if (url.length > 2048) return { inputError: "body.url is too long (max 2048 chars)" };

  const fetchedAt = new Date().toISOString();
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(parsed.toString(), {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "user-agent": "AgentEmbassy-Celo/1.0 (+https://aemb.pro)" },
    });
    const buf = Buffer.from(await resp.arrayBuffer());
    clearTimeout(timer);
    const observed = buf.subarray(0, 1024 * 1024);
    return {
      url: parsed.toString(),
      reachable: true,
      http_status: resp.status,
      bytes_observed: observed.length,
      body_sha256: createHash("sha256").update(observed).digest("hex"),
      truncated_at_1mib: buf.length > observed.length,
      fetched_at: fetchedAt,
    };
  } catch (err) {
    return {
      url: parsed.toString(),
      reachable: false,
      http_status: null,
      bytes_observed: 0,
      body_sha256: null,
      error_class: err?.name === "AbortError" ? "timeout_8s" : "fetch_failed",
      fetched_at: fetchedAt,
    };
  }
}

/* ------------------------------------------------------------------ */
/* x402 wiring                                                         */
/* ------------------------------------------------------------------ */

function buildHttpServer() {
  const facilitator = new HTTPFacilitatorClient({
    url: NET.facilitatorUrl,
    createAuthHeaders: async () => {
      const h = FACILITATOR_API_KEY ? { "X-API-Key": FACILITATOR_API_KEY } : {};
      return { verify: h, settle: h, supported: h };
    },
  });
  const resourceServer = new x402ResourceServer(facilitator).register(
    NET.network,
    new ExactEvmScheme(),
  );
  const routes = {
    "POST /v1/check/verify": {
      accepts: NET.assets.map((a) => ({
        scheme: "exact",
        network: NET.network,
        payTo: PAY_TO,
        price: { asset: a.address, amount: PRICE_SMALLEST_UNIT, extra: a.extra },
        maxTimeoutSeconds: 300,
      })),
      description: VERIFY_DESCRIPTION,
      mimeType: "application/json",
    },
  };
  return new x402HTTPResourceServer(resourceServer, routes);
}

/* ------------------------------------------------------------------ */
/* HTTP surface                                                        */
/* ------------------------------------------------------------------ */

export async function createApp() {
  const httpServer = buildHttpServer();
  await httpServer.initialize();

  const app = express();
  app.use(express.json({ limit: "64kb" }));

  app.get("/health", (_req, res) => {
    res.json({
      ok: true,
      service: "agent-embassy-celo",
      network: NET.network,
      facilitator: NET.facilitatorUrl,
      facilitator_key_configured: Boolean(FACILITATOR_API_KEY),
      receipt_signing_configured: Boolean(signerAccount),
      agent_id: AGENT_ID,
      pay_to: PAY_TO,
    });
  });

  app.get("/", (_req, res) => {
    res.json({
      name: "Agent Embassy",
      what: "Pay-per-call verification, settled on Celo. Every settled call returns a signed outcome receipt.",
      agent_identity: {
        standard: "ERC-8004",
        agent_id: AGENT_ID,
        agent_registry: `${NET.network}:${AGENT_REGISTRY}`,
        agent_card: AGENT_CARD,
      },
      pay_to: PAY_TO,
      network: NET.network,
      facilitator: NET.facilitatorUrl,
      endpoints: [
        {
          method: "POST",
          path: "/v1/check/verify",
          price: "0.001 USD",
          assets: NET.assets.map((a) => ({ symbol: a.symbol, address: a.address })),
          body: { url: "https://example.com/page" },
          returns: "URL attestation + signed Embassy receipt",
        },
      ],
      attribution:
        "ERC-8021 via PayTo address for x402, per the Agents on Open Rails rules (attribution tags are not yet supported by x402).",
    });
  });

  app.get("/.well-known/agent.json", (_req, res) => {
    res.json({
      type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
      name: "Agent Embassy",
      description:
        "Agent Embassy — agents pay for work and prove what happened. Every check returns a signed outcome receipt. This is the Celo deployment.",
      services: [
        { name: "web", endpoint: PUBLIC_BASE_URL || "https://aemb.pro" },
        {
          name: "x402",
          endpoint: `${PUBLIC_BASE_URL || ""}/v1/check/verify`,
          version: "2",
          network: NET.network,
        },
        { name: "email", endpoint: "mailto:agent.embassy@proton.me" },
      ],
      x402Support: true,
      active: true,
      supportedTrust: ["reputation"],
      registrations: [
        { agentId: AGENT_ID, agentRegistry: `${NET.network}:${AGENT_REGISTRY}` },
      ],
    });
  });

  /* The paid route — manual HTTP-server flow so the receipt can carry the
   * real settlement transaction hash: verify -> work -> settle -> receipt. */
  app.post("/v1/check/verify", async (req, res) => {
    const context = {
      adapter: new ExpressAdapter(req),
      path: req.path,
      method: req.method,
      paymentHeader:
        req.header("payment-signature") || req.header("x-payment") || undefined,
      routePattern: "POST /v1/check/verify",
    };

    let processed;
    try {
      processed = await httpServer.processHTTPRequest(context);
    } catch (err) {
      return res.status(502).json({ error: "payment_processing_failed", detail: String(err?.message || err) });
    }

    if (processed.type === "payment-error") {
      const { status, headers, body } = processed.response;
      if (headers) for (const [k, v] of Object.entries(headers)) res.set(k, v);
      /* The v2 challenge rides the PAYMENT-REQUIRED header; mirror the
       * decoded challenge into the body as well so every client shape —
       * header readers and body readers — sees the full requirements. */
      let out = body;
      const hdr = headers?.["payment-required"] || headers?.["PAYMENT-REQUIRED"];
      const stubOnly = out && typeof out === "object" && !Array.isArray(out) && Object.keys(out).length === 1 && typeof out.error === "string" && !out.accepts;
      if (hdr && (!out || (typeof out === "object" && !Object.keys(out).length) || stubOnly)) {
        try {
          out = JSON.parse(Buffer.from(hdr, "base64").toString("utf8"));
        } catch { /* keep the original body */ }
      }
      return res.status(status).json(out ?? { error: "payment_required" });
    }
    if (processed.type !== "payment-verified") {
      return res.status(500).json({ error: "unexpected_payment_state", type: processed.type });
    }

    /* Verified — do the work BEFORE settling, so a bad input never settles. */
    const work = await runUrlCheck(req.body || {});
    if (work.inputError) {
      try {
        await processed.cancellationDispatcher?.cancel({ reason: "invalid_input" });
      } catch { /* best-effort release of the verified authorization */ }
      return res.status(422).json({ error: "invalid_input", detail: work.inputError });
    }

    let settle;
    try {
      settle = await httpServer.processSettlement(
        processed.paymentPayload,
        processed.paymentRequirements,
        processed.declaredExtensions,
        { request: context },
        undefined,
        processed.beforeHandlerSettlement,
      );
    } catch (err) {
      return res.status(502).json({ error: "settlement_failed", detail: String(err?.message || err) });
    }
    if (!settle.success) {
      if (settle.headers) for (const [k, v] of Object.entries(settle.headers)) res.set(k, v);
      return res.status(402).json({
        error: "settlement_failed",
        reason: settle.errorReason,
        detail: settle.errorMessage || null,
      });
    }
    if (settle.headers) for (const [k, v] of Object.entries(settle.headers)) res.set(k, v);

    const auth = processed.paymentPayload?.payload?.authorization || {};
    const receipt = {
      receipt_version: "embassy-receipt/2",
      receipt_id: randomUUID(),
      prev_receipt_hash: lastReceiptHash(),
      issued_at: new Date().toISOString(),
      issuer: {
        name: "Agent Embassy",
        agent_id: AGENT_ID,
        agent_registry: `${NET.network}:${AGENT_REGISTRY}`,
        agent_card: AGENT_CARD,
      },
      chain: {
        REQUEST: {
          endpoint: "POST /v1/check/verify",
          input_sha256: createHash("sha256").update(JSON.stringify(req.body || {})).digest("hex"),
        },
        AUTHORIZATION: {
          payer: auth.from || settle.payer || null,
          pay_to: PAY_TO,
          network: NET.network,
          asset: processed.paymentRequirements.asset,
          amount: processed.paymentRequirements.amount,
          authorization_nonce: auth.nonce || null,
        },
        ACTION: { check: "url_attestation", result: work },
        PROOF: {
          settlement_tx: settle.transaction,
          facilitator: NET.facilitatorUrl,
          explorer: settle.transaction ? NET.explorerTx(settle.transaction) : null,
        },
        LIABILITY_BOUNDARY:
          "This receipt proves the check ran at the stated time and the payment settled on Celo. It does not warrant the checked page's contents, safety, or future state.",
      },
      signature: { value: null, signer: null, key_id: SIGNING_KEY_ID, scheme: null },
    };
    await signReceipt(receipt);
    appendReceipt(receipt);

    return res.json({ result: work, receipt });
  });

  return app;
}

/* istanbul ignore next -- entrypoint */
if (import.meta.url === `file://${process.argv[1]}`) {
  const app = await createApp();
  app.listen(PORT, () => {
    console.log(
      `agent-embassy-celo listening on :${PORT} network=${NET.network} facilitator=${NET.facilitatorUrl} key=${FACILITATOR_API_KEY ? "set" : "UNSET"} signing=${signerAccount ? "set" : "UNSET"}`,
    );
  });
}
