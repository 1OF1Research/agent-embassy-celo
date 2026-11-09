/**
 * Agent Embassy on Celo — a pay-per-call verification surface.
 *
 * Three paid checks, one price (0.001) and one receipt scheme:
 *   POST /v1/check/verify   { "url": "https://example.com/page" }
 *     Fetch a URL; return an attestation of what was observed.
 *   POST /v1/check/ping     { "url": ..., "expect_status": 200, ... }
 *     Fetch a URL; return a pass/fail attestation against the buyer's
 *     own conditions (status, body substring, JSON value).
 *   POST /v1/check/changes  { "url": ..., "known_sha256": "<64 hex>" }
 *     Fetch a URL; return whether its body SHA-256 differs from the
 *     hash the buyer supplies. One call, one comparison — not a watch.
 * Plus a public proof ladder (signer document, receipt reads, a
 * one-click verify rung) and a discovery shelf (x402.json, OpenAPI,
 * llms.txt) so any agent or judge can find the surface, call it, and
 * check every receipt without trusting this server.
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
import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

const PORT = Number(process.env.PORT || 8787);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/$/, "");
/** This deployment's own public address (the prepared deploy config sets
 *  PUBLIC_BASE_URL to the same value). Used only as the fallback for
 *  self-references in the discovery documents — never the production
 *  service's address: this deployment stands alone. */
const DEPLOYMENT_URL = "https://agent-embassy-celo.fly.dev";
const publicBase = () => PUBLIC_BASE_URL || DEPLOYMENT_URL;
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

const PING_DESCRIPTION =
  "Agent Embassy conditional URL check on Celo: fetch a URL and return a " +
  "signed pass/fail attestation against the buyer's own conditions (HTTP " +
  "status, body substring, JSON value; default condition: status 200). " +
  "Price 0.001 USD in USA₮ or USDC on Celo mainnet, settled through Celo's " +
  "hosted x402 facilitator. ERC-8004 agentId 9966.";

const CHANGES_DESCRIPTION =
  "Agent Embassy URL change comparison on Celo: fetch a URL and return a " +
  "signed attestation of whether its body SHA-256 differs from a hash the " +
  "buyer supplies. One call, one comparison — not a standing watch. " +
  "Price 0.001 USD in USA₮ or USDC on Celo mainnet, settled through Celo's " +
  "hosted x402 facilitator. ERC-8004 agentId 9966.";

/** The paid shelf: one table drives the x402 routes, the paid handlers,
 *  the service card, and every discovery document, so the documents a
 *  stranger reads can never drift from the code that answers. */
const PAID_ROUTES = [
  {
    pattern: "POST /v1/check/verify",
    path: "/v1/check/verify",
    action: "url_attestation",
    description: VERIFY_DESCRIPTION,
    example: { url: "https://example.com/page" },
    work: runUrlCheck,
  },
  {
    pattern: "POST /v1/check/ping",
    path: "/v1/check/ping",
    action: "url_conditions",
    description: PING_DESCRIPTION,
    example: { url: "https://example.com/page", expect_status: 200, expect_body_contains: "Example" },
    work: runConditionCheck,
  },
  {
    pattern: "POST /v1/check/changes",
    path: "/v1/check/changes",
    action: "url_change_comparison",
    description: CHANGES_DESCRIPTION,
    example: { url: "https://example.com/page", known_sha256: "<64 hex characters>" },
    work: runChangesCheck,
  },
];

/** The accepts set every paid route offers, in the challenge's own shape. */
function flatAccepts() {
  return NET.assets.map((a) => ({
    scheme: "exact",
    network: NET.network,
    asset: a.address,
    amount: PRICE_SMALLEST_UNIT,
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    extra: a.extra,
  }));
}

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
export function lastReceiptHash() {
  try {
    if (!existsSync(RECEIPTS_PATH)) return "genesis";
    const lines = readFileSync(RECEIPTS_PATH, "utf8").trim().split("\n").filter(Boolean);
    if (!lines.length) return "genesis";
    return createHash("sha256").update(lines[lines.length - 1]).digest("hex");
  } catch {
    return "genesis";
  }
}
export function appendReceipt(receipt) {
  mkdirSync(DATA_DIR, { recursive: true });
  appendFileSync(RECEIPTS_PATH, JSON.stringify(receipt) + "\n");
}

/* Receipt writes serialize through one queue. The chain link is only
 * sound if reading the predecessor hash, signing, and appending happen
 * as one uninterrupted step: two settlements landing in the same
 * instant must never read the same predecessor and fork the chain's
 * linking. The service is single-process by design, so an in-process
 * queue is the whole mechanism — its scope is named, not implied. */
let receiptWriteQueue = Promise.resolve();
export function enqueueReceiptWrite(task) {
  const run = receiptWriteQueue.then(task, task);
  receiptWriteQueue = run.catch(() => {});
  return run;
}

/* Read side of the log, for the public proof ladder. */
function readReceiptLines() {
  try {
    if (!existsSync(RECEIPTS_PATH)) return [];
    return readFileSync(RECEIPTS_PATH, "utf8").split("\n").filter(Boolean);
  } catch {
    return [];
  }
}
function findReceipt(receiptId) {
  for (const line of readReceiptLines()) {
    try {
      const receipt = JSON.parse(line);
      if (receipt.receipt_id === receiptId) return { receipt, line };
    } catch { /* a line that does not parse is skipped, never hidden: the verify rung reports chain state from the raw lines */ }
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* The work: one fetch core, three checks.                             */
/*                                                                     */
/* Fetch boundary: the checks fetch arbitrary URLs for strangers, so   */
/* the target is guarded — literal private, loopback, link-local, and  */
/* shared-space addresses and localhost names are refused, in every    */
/* spelling (IPv6 literals are judged in expanded form, so IPv4-mapped */
/* and IPv4-compatible spellings of a refused address are refused      */
/* too), on the first hop and on every redirect hop. The named limit:  */
/* a public name that resolves to a private address is a               */
/* resolution-time question this surface does not claim to answer.     */
/* ------------------------------------------------------------------ */

function ipv4Octets(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  return octets.every((o) => o <= 255) ? octets : null;
}
function isNonPublicIpv4(o) {
  return (
    o[0] === 10 || o[0] === 127 || o[0] === 0 ||
    (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
    (o[0] === 192 && o[1] === 168) ||
    (o[0] === 169 && o[1] === 254) ||
    (o[0] === 100 && o[1] >= 64 && o[1] <= 127)
  );
}
/* Expand an IPv6 literal (compressed, with an optional embedded IPv4
 * tail) to its eight 16-bit groups, or null when it does not parse.
 * The fetch boundary judges the expanded form only: the URL parser
 * rewrites spellings (a dotted mapped tail comes back as hex groups),
 * so a check written against one spelling silently misses the others —
 * ::ffff:127.0.0.1 and ::ffff:7f00:1 are the same loopback address. */
function expandIpv6(host) {
  let h = host;
  const tail = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (tail) {
    const o = tail.slice(1).map(Number);
    if (o.some((n) => n > 255)) return null;
    h =
      h.slice(0, h.length - tail[0].length) +
      ((o[0] << 8) | o[1]).toString(16) +
      ":" +
      ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = h.split("::");
  if (halves.length > 2) return null;
  const parse = (s) =>
    s === "" ? [] : s.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  const left = parse(halves[0]);
  const right = halves.length === 2 ? parse(halves[1]) : [];
  if (left.some(Number.isNaN) || right.some(Number.isNaN)) return null;
  if (halves.length === 1) return left.length === 8 ? left : null;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...Array(missing).fill(0), ...right];
}

function isNonPublicHost(hostname) {
  let host = String(hostname || "").toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1); // URL keeps IPv6 brackets on
  if (!host) return true;
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const v4 = ipv4Octets(host);
  if (v4) return isNonPublicIpv4(v4);
  if (host.includes(":")) {
    const v6 = expandIpv6(host);
    if (!v6) return true; // an IPv6 literal that does not parse is refused, never waved through
    if (v6.every((g) => g === 0)) return true; // :: — the unspecified address
    /* IPv4-mapped (::ffff:a.b.c.d, in any spelling) and IPv4-compatible
     * (::a.b.c.d, which also covers ::1): the embedded IPv4 decides. */
    if (v6.slice(0, 5).every((g) => g === 0) && (v6[5] === 0xffff || v6[5] === 0)) {
      return isNonPublicIpv4([v6[6] >> 8, v6[6] & 0xff, v6[7] >> 8, v6[7] & 0xff]);
    }
    if (v6[0] >= 0xfe80 && v6[0] <= 0xfebf) return true; // link-local fe80::/10
    if (v6[0] >= 0xfc00 && v6[0] <= 0xfdff) return true; // unique local fc00::/7
    if (v6[0] >= 0xff00) return true; // multicast ff00::/8 — never a fetch target
  }
  return false;
}

/** Returns an input-error string, or null when the target may be fetched. */
export function targetProblem(rawUrl) {
  const url = typeof rawUrl === "string" ? rawUrl.trim() : "";
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return "body.url must be a valid absolute URL";
  }
  if (!/^https?:$/.test(parsed.protocol)) return "body.url must use http or https";
  if (url.length > 2048) return "body.url is too long (max 2048 chars)";
  if (isNonPublicHost(parsed.hostname)) {
    return "body.url must name a public host (private, loopback, and link-local targets are refused)";
  }
  return null;
}

/* The observation is capped at 1 MiB, and the cap is enforced while
 * reading — never after: a response body is streamed and the read is
 * cancelled the moment the cap is crossed, so a hostile or broken
 * target cannot make this service buffer an unbounded body in memory
 * (the work runs after payment verification but before settlement, so
 * an unbounded read would be a crash a stranger could trigger at no
 * settled cost). Returns the first MAX_OBSERVED bytes and whether the
 * body held more. */
const MAX_OBSERVED = 1024 * 1024;
export async function readBodyCapped(resp) {
  if (!resp.body) return { buf: Buffer.alloc(0), truncated: false };
  const reader = resp.body.getReader();
  const chunks = [];
  let kept = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (kept + value.length > MAX_OBSERVED) {
        const room = MAX_OBSERVED - kept;
        if (room > 0) chunks.push(value.subarray(0, room));
        kept = MAX_OBSERVED;
        truncated = true;
        await reader.cancel();
        break;
      }
      chunks.push(value);
      kept += value.length;
    }
  } finally {
    reader.releaseLock();
  }
  return { buf: Buffer.concat(chunks, kept), truncated };
}

/* One guarded fetch: manual redirects (max 5), each hop re-checked
 * against the boundary, one 8-second budget across all hops. Returns
 * { status, buf, truncated } for the final response — buf never holds
 * more than the 1 MiB observation cap; throws on failure. */
async function fetchFinal(parsed) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    let current = parsed;
    for (let hop = 0; hop <= 5; hop++) {
      const resp = await fetch(current.toString(), {
        signal: ctrl.signal,
        redirect: "manual",
        headers: { "user-agent": "AgentEmbassy-Celo/1.0 (+https://aemb.pro)" },
      });
      const isRedirect = resp.status >= 300 && resp.status < 400 && resp.headers.get("location");
      if (!isRedirect) {
        const { buf, truncated } = await readBodyCapped(resp);
        return { status: resp.status, buf, truncated, finalUrl: current.toString() };
      }
      if (hop === 5) {
        const err = new Error("too many redirects");
        err.name = "TooManyRedirects";
        throw err;
      }
      const next = new URL(resp.headers.get("location"), current);
      if (!/^https?:$/.test(next.protocol) || isNonPublicHost(next.hostname)) {
        const err = new Error("redirect to a refused target");
        err.name = "RefusedRedirect";
        throw err;
      }
      current = next;
    }
  } finally {
    clearTimeout(timer);
  }
  throw new Error("unreachable fetch state");
}

/* The shared observation every check is built from. */
async function fetchObservation(input) {
  const problem = targetProblem(input?.url);
  if (problem) return { inputError: problem };
  const parsed = new URL(input.url.trim());
  const fetchedAt = new Date().toISOString();
  try {
    const { status, buf, truncated, finalUrl } = await fetchFinal(parsed);
    return {
      ok: true,
      url: parsed.toString(),
      final_url: finalUrl,
      reachable: true,
      http_status: status,
      bytes_observed: buf.length,
      body_sha256: createHash("sha256").update(buf).digest("hex"),
      truncated_at_1mib: truncated,
      body_text: buf.toString("utf8"),
      fetched_at: fetchedAt,
    };
  } catch (err) {
    return {
      ok: false,
      url: parsed.toString(),
      reachable: false,
      http_status: null,
      error_class:
        err?.name === "AbortError" ? "timeout_8s"
        : err?.name === "TooManyRedirects" ? "too_many_redirects"
        : err?.name === "RefusedRedirect" ? "redirect_refused"
        : "fetch_failed",
      fetched_at: fetchedAt,
    };
  }
}

const publicObservation = (obs) => ({
  url: obs.url,
  reachable: obs.reachable,
  http_status: obs.http_status,
  bytes_observed: obs.bytes_observed,
  body_sha256: obs.body_sha256,
  truncated_at_1mib: obs.truncated_at_1mib,
  fetched_at: obs.fetched_at,
});

/* Check 1 — the attestation: what was observed at the URL. */
async function runUrlCheck(input) {
  const obs = await fetchObservation(input);
  if (obs.inputError) return { inputError: obs.inputError };
  if (!obs.ok) {
    return {
      url: obs.url,
      reachable: false,
      http_status: null,
      bytes_observed: 0,
      body_sha256: null,
      error_class: obs.error_class,
      fetched_at: obs.fetched_at,
    };
  }
  return publicObservation(obs);
}

/* Check 2 — the buyer's own conditions on one fetch. */
const JSON_PATH_SHAPE = /^[\w$-]+(\.[\w$-]+)*$/;
function readJsonPath(root, path) {
  let cur = root;
  for (const part of path.split(".")) {
    if (cur === null || typeof cur !== "object" || !(part in cur)) return { found: false, value: null };
    cur = cur[part];
  }
  return { found: true, value: cur === undefined ? null : cur };
}
export function evaluateConditions(facts, conditions) {
  const outcomes = {};
  if (conditions.expect_status !== undefined) {
    outcomes.status = {
      expected: conditions.expect_status,
      observed: facts.http_status,
      ok: facts.http_status === conditions.expect_status,
    };
  }
  if (conditions.expect_body_contains !== undefined) {
    outcomes.body_contains = {
      expected: conditions.expect_body_contains,
      ok: typeof facts.body_text === "string" && facts.body_text.includes(conditions.expect_body_contains),
    };
  }
  if (conditions.expect_json_path !== undefined) {
    let parsedBody = null;
    let parsedOk = true;
    try {
      parsedBody = JSON.parse(facts.body_text);
    } catch {
      parsedOk = false;
    }
    const { found, value } = parsedOk ? readJsonPath(parsedBody, conditions.expect_json_path) : { found: false, value: null };
    const expected = conditions.expect_json_value === undefined ? null : conditions.expect_json_value;
    outcomes.json_value = {
      path: conditions.expect_json_path,
      expected,
      observed: found ? value : null,
      found,
      body_is_json: parsedOk,
      ok: found && JSON.stringify(value) === JSON.stringify(expected),
    };
  }
  return { outcomes, pass: Object.values(outcomes).every((o) => o.ok) };
}
async function runConditionCheck(input) {
  const conditions = {};
  if (input?.expect_status !== undefined) {
    if (!Number.isInteger(input.expect_status) || input.expect_status < 100 || input.expect_status > 599) {
      return { inputError: "body.expect_status must be an integer HTTP status (100-599)" };
    }
    conditions.expect_status = input.expect_status;
  }
  if (input?.expect_body_contains !== undefined) {
    if (typeof input.expect_body_contains !== "string" || !input.expect_body_contains.length || input.expect_body_contains.length > 512) {
      return { inputError: "body.expect_body_contains must be a string of 1-512 characters" };
    }
    conditions.expect_body_contains = input.expect_body_contains;
  }
  if (input?.expect_json_path !== undefined) {
    if (typeof input.expect_json_path !== "string" || input.expect_json_path.length > 128 || !JSON_PATH_SHAPE.test(input.expect_json_path)) {
      return { inputError: "body.expect_json_path must be a dotted path of word characters (max 128 chars)" };
    }
    conditions.expect_json_path = input.expect_json_path;
    conditions.expect_json_value = input.expect_json_value === undefined ? null : input.expect_json_value;
  }
  if (!Object.keys(conditions).length) conditions.expect_status = 200; // the default condition: the page answers 200

  const obs = await fetchObservation(input);
  if (obs.inputError) return { inputError: obs.inputError };
  if (!obs.ok) {
    return {
      url: obs.url,
      reachable: false,
      http_status: null,
      conditions_applied: conditions,
      outcomes: null,
      pass: false,
      error_class: obs.error_class,
      fetched_at: obs.fetched_at,
    };
  }
  const { outcomes, pass } = evaluateConditions(obs, conditions);
  return {
    ...publicObservation(obs),
    conditions_applied: conditions,
    outcomes,
    pass,
  };
}

/* Check 3 — one comparison against a hash the buyer already holds. */
async function runChangesCheck(input) {
  const known = typeof input?.known_sha256 === "string" ? input.known_sha256.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(known)) {
    return { inputError: "body.known_sha256 must be a 64-character hex SHA-256" };
  }
  const obs = await fetchObservation(input);
  if (obs.inputError) return { inputError: obs.inputError };
  if (!obs.ok) {
    return {
      url: obs.url,
      reachable: false,
      http_status: null,
      known_sha256: known,
      current_sha256: null,
      changed: null,
      error_class: obs.error_class,
      fetched_at: obs.fetched_at,
    };
  }
  return {
    ...publicObservation(obs),
    known_sha256: known,
    current_sha256: obs.body_sha256,
    changed: obs.body_sha256 !== known,
    hash_scope: obs.truncated_at_1mib ? "first_1mib" : "full_body",
  };
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
  const routes = {};
  for (const route of PAID_ROUTES) {
    routes[route.pattern] = {
      accepts: NET.assets.map((a) => ({
        scheme: "exact",
        network: NET.network,
        payTo: PAY_TO,
        price: { asset: a.address, amount: PRICE_SMALLEST_UNIT, extra: a.extra },
        maxTimeoutSeconds: 300,
      })),
      description: route.description,
      mimeType: "application/json",
    };
  }
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
      receipts_count: readReceiptLines().length,
      receipt_chain_head: lastReceiptHash(),
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
      endpoints: PAID_ROUTES.map((r) => ({
        method: "POST",
        path: r.path,
        price: "0.001 USD",
        assets: NET.assets.map((a) => ({ symbol: a.symbol, address: a.address })),
        body: r.example,
        returns: "Check result + signed Embassy receipt",
      })),
      proof: {
        signer: `${publicBase()}/.well-known/embassy-signer.json`,
        receipts: `${publicBase()}/v1/receipts`,
        verify: `${publicBase()}/v1/receipts/<receipt_id>/verify`,
        proof_page: `${publicBase()}/proof`,
      },
      discovery: {
        x402: `${publicBase()}/.well-known/x402.json`,
        openapi: `${publicBase()}/openapi.json`,
        llms: `${publicBase()}/llms.txt`,
        agent_card: `${publicBase()}/.well-known/agent.json`,
      },
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
        { name: "web", endpoint: publicBase() },
        ...PAID_ROUTES.map((r) => ({
          name: "x402",
          endpoint: `${publicBase()}${r.path}`,
          version: "2",
          network: NET.network,
        })),
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

  /* ---------------------------------------------------------------- */
  /* The proof ladder — public, read-only, no payment. Each rung lets  */
  /* a stranger check one claim without trusting this server: the      */
  /* signer is published outside the receipts; a receipt's signature   */
  /* and chain link are re-derived on request; the settlement itself   */
  /* is read on the chain explorer.                                    */
  /* ---------------------------------------------------------------- */

  app.get("/.well-known/embassy-signer.json", (_req, res) => {
    res.json({
      signer: signerAccount?.address ?? null,
      key_id: SIGNING_KEY_ID,
      scheme: "EIP-191 over sha256(canonical receipt, signature.value excluded)",
      receipt_version: "embassy-receipt/2",
      signing_configured: Boolean(signerAccount),
      how_to_verify: [
        "Take the receipt JSON with signature.value set to null.",
        "SHA-256 the compact JSON.",
        "ecrecover the EIP-191 signature over that digest.",
        "The recovered address must equal the receipt's signature.signer and the signer published here.",
      ],
      receipts: `${publicBase()}/v1/receipts`,
      verify_endpoint: `${publicBase()}/v1/receipts/<receipt_id>/verify`,
    });
  });

  app.get("/v1/receipts", (_req, res) => {
    const receipts = [];
    for (const line of readReceiptLines()) {
      try {
        receipts.push(JSON.parse(line));
      } catch { /* unparseable lines are skipped here; the verify rung reports chain state from the raw lines */ }
    }
    res.json({ count: receipts.length, receipts: receipts.slice(-25).reverse() });
  });

  app.get("/v1/receipts/:receiptId", (req, res) => {
    const found = findReceipt(req.params.receiptId);
    if (!found) return res.status(404).json({ error: "receipt_not_found" });
    return res.json(found.receipt);
  });

  app.get("/v1/receipts/:receiptId/verify", async (req, res) => {
    const found = findReceipt(req.params.receiptId);
    if (!found) return res.status(404).json({ error: "receipt_not_found" });
    const { receipt, line } = found;
    const verdict = {
      receipt_id: receipt.receipt_id,
      network: NET.network,
      published_signer: signerAccount?.address ?? null,
      recovered_signer: null,
      signature_valid: false,
      chain_link_valid: false,
      settlement_tx: receipt.chain?.PROOF?.settlement_tx ?? null,
      explorer: receipt.chain?.PROOF?.explorer ?? null,
    };
    if (receipt.signature?.value && receipt.signature?.signer) {
      try {
        const digest = createHash("sha256").update(canonicalReceiptBytes(receipt)).digest();
        verdict.recovered_signer = await recoverMessageAddress({
          message: { raw: digest },
          signature: receipt.signature.value,
        });
        verdict.signature_valid =
          verdict.recovered_signer === receipt.signature.signer &&
          (!verdict.published_signer || verdict.recovered_signer === verdict.published_signer);
      } catch {
        verdict.signature_valid = false;
      }
    } else {
      verdict.signature_note = "this receipt is unsigned (no signing key was configured when it was issued)";
    }
    const lines = readReceiptLines();
    const idx = lines.indexOf(line);
    if (idx >= 0) {
      const expectedPrev =
        idx === 0 ? "genesis" : createHash("sha256").update(lines[idx - 1]).digest("hex");
      verdict.chain_link_valid = receipt.prev_receipt_hash === expectedPrev;
    }
    if (!verdict.explorer && verdict.settlement_tx) verdict.explorer = NET.explorerTx(verdict.settlement_tx);
    return res.json(verdict);
  });

  app.get("/proof", (_req, res) => {
    res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proof — Agent Embassy on Celo</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Inter, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #111; }
  input { width: 100%; padding: 10px; font-size: 15px; border: 1px solid #ccc; border-radius: 8px; }
  button { margin-top: 10px; padding: 10px 18px; font-size: 15px; font-weight: 600; border: 0; border-radius: 8px; background: #111; color: #fff; cursor: pointer; }
  .card { border: 1px solid #e5e5e5; border-radius: 10px; padding: 14px 16px; margin-top: 14px; }
  .ok { color: #15803d; font-weight: 700; } .bad { color: #b91c1c; font-weight: 700; }
  code { font-size: 12px; word-break: break-all; }
  li { margin: 6px 0; } a { color: #111; }
</style>
</head>
<body>
<h1>Check a receipt</h1>
<p>Every paid call on this service returns a signed receipt. Paste a receipt id below and this page re-checks its signature and its place in the receipt chain — the same checks anyone can run by hand from the published signer document. The payment itself is read on the chain explorer.</p>
<input id="rid" placeholder="receipt id">
<button id="go">Verify</button>
<div id="out"></div>
<h2>Recent receipts</h2>
<ul id="recent"></ul>
<script>
  const out = document.getElementById("out");
  async function verify(id) {
    out.innerHTML = "<p>Checking…</p>";
    try {
      const r = await fetch("/v1/receipts/" + encodeURIComponent(id) + "/verify");
      if (!r.ok) { out.innerHTML = "<p class='bad'>No receipt with that id.</p>"; return; }
      const v = await r.json();
      const mark = (b) => b ? "<span class='ok'>holds</span>" : "<span class='bad'>does not hold</span>";
      out.innerHTML = "<div class='card'>" +
        "<p>Signature: " + mark(v.signature_valid) + "</p>" +
        "<p>Chain link: " + mark(v.chain_link_valid) + "</p>" +
        (v.settlement_tx ? "<p>Settlement: <a href='" + v.explorer + "' target='_blank' rel='noopener'>read it on Celoscan</a></p>" : "<p>No settlement transaction on this receipt.</p>") +
        "<p><code>signer " + (v.recovered_signer || "—") + "</code></p></div>";
    } catch (e) { out.innerHTML = "<p class='bad'>The check could not run.</p>"; }
  }
  document.getElementById("go").addEventListener("click", () => verify(document.getElementById("rid").value.trim()));
  fetch("/v1/receipts").then((r) => r.json()).then((d) => {
    const ul = document.getElementById("recent");
    (d.receipts || []).slice(0, 10).forEach((rec) => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = "#"; a.textContent = rec.receipt_id;
      a.addEventListener("click", (e) => { e.preventDefault(); document.getElementById("rid").value = rec.receipt_id; verify(rec.receipt_id); });
      li.appendChild(a);
      ul.appendChild(li);
    });
    if (!d.count) ul.innerHTML = "<li>No receipts yet — the first settled call will appear here.</li>";
  }).catch(() => {});
</script>
</body>
</html>`);
  });

  /* ---------------------------------------------------------------- */
  /* The discovery shelf — generated from PAID_ROUTES, so what an      */
  /* agent reads can never drift from what the server answers.         */
  /* ---------------------------------------------------------------- */

  app.get("/.well-known/x402.json", (_req, res) => {
    res.json({
      x402Version: 2,
      resources: PAID_ROUTES.map((r) => ({
        resource: `${publicBase()}${r.path}`,
        type: "http",
        method: "POST",
        mimeType: "application/json",
        description: r.description,
        accepts: flatAccepts(),
      })),
    });
  });

  app.get("/openapi.json", (_req, res) => {
    const paidPaths = {};
    for (const r of PAID_ROUTES) {
      paidPaths[r.path] = {
        post: {
          summary: r.description,
          requestBody: {
            content: { "application/json": { example: r.example } },
          },
          responses: {
            "200": { description: "Check result plus a signed Embassy receipt (embassy-receipt/2)." },
            "402": { description: "x402 v2 payment challenge (PAYMENT-REQUIRED header and mirrored body); accepts USA₮ and USDC on eip155:42220." },
            "422": { description: "Input refused after payment verification; the authorization is cancelled, nothing settles." },
          },
        },
      };
    }
    res.json({
      openapi: "3.0.3",
      info: {
        title: "Agent Embassy on Celo",
        version: "1.0.0",
        description:
          "Pay-per-call verification settled in USA₮ or USDC on Celo mainnet through Celo's hosted x402 facilitator. Every settled call returns a signed receipt anyone can verify. ERC-8004 agentId 9966.",
      },
      servers: [{ url: publicBase() }],
      paths: {
        "/health": { get: { summary: "Liveness, configuration, and receipt-chain state.", responses: { "200": { description: "Service state." } } } },
        "/": { get: { summary: "Service card: endpoints, prices, proof ladder, discovery links.", responses: { "200": { description: "Service card." } } } },
        "/.well-known/agent.json": { get: { summary: "ERC-8004 agent card for this deployment.", responses: { "200": { description: "Agent card." } } } },
        "/.well-known/embassy-signer.json": { get: { summary: "The receipt signer's published address and the verification recipe.", responses: { "200": { description: "Signer document." } } } },
        "/.well-known/x402.json": { get: { summary: "x402 machine-readable discovery document.", responses: { "200": { description: "Discovery document." } } } },
        "/v1/receipts": { get: { summary: "Recent receipts (public).", responses: { "200": { description: "Receipt list." } } } },
        "/v1/receipts/{receiptId}": { get: { summary: "One receipt in full.", responses: { "200": { description: "Receipt." }, "404": { description: "No such receipt." } } } },
        "/v1/receipts/{receiptId}/verify": { get: { summary: "Re-derived signature and chain-link verdicts for one receipt.", responses: { "200": { description: "Verdicts." }, "404": { description: "No such receipt." } } } },
        "/proof": { get: { summary: "Human proof page: check any receipt in one click.", responses: { "200": { description: "HTML page." } } } },
        ...paidPaths,
      },
    });
  });

  app.get("/llms.txt", (_req, res) => {
    const lines = [
      "# Agent Embassy on Celo",
      "",
      "Pay-per-call verification for agents, settled on Celo mainnet (eip155:42220) through Celo's hosted x402 facilitator. No account, no subscription: pay 0.001 per call in USA₮ (preferred) or USDC, receive the check result plus a signed receipt (embassy-receipt/2) carrying the settlement transaction hash.",
      "",
      "Identity: ERC-8004 agentId 9966 on Celo mainnet. PayTo (also the ERC-8021 attribution for x402): " + PAY_TO + ".",
      "",
      "## Paid endpoints (x402 v2, scheme exact)",
      ...PAID_ROUTES.flatMap((r) => [
        "",
        "### POST " + r.path,
        r.description,
        "Example body: " + JSON.stringify(r.example),
      ]),
      "",
      "## How to pay",
      "Send the POST without payment to receive the 402 challenge (the full requirements ride both the PAYMENT-REQUIRED header and the body). Sign an EIP-3009 authorization for one of the offered assets and retry with the PAYMENT-SIGNATURE header. The facilitator settles and pays the gas; funds move from buyer to PayTo directly.",
      "",
      "## How to verify a receipt",
      "Signer document: " + publicBase() + "/.well-known/embassy-signer.json",
      "One-click verdicts: GET " + publicBase() + "/v1/receipts/<receipt_id>/verify",
      "By hand: set signature.value to null, SHA-256 the compact JSON, ecrecover the EIP-191 signature over that digest; the recovered address must equal signature.signer. The settlement is read independently on Celoscan from chain.PROOF.settlement_tx.",
      "",
      "Discovery: " + publicBase() + "/.well-known/x402.json · " + publicBase() + "/openapi.json · " + publicBase() + "/.well-known/agent.json",
      "",
    ];
    res.type("text/plain").send(lines.join("\n"));
  });

  /* The paid routes — manual HTTP-server flow so the receipt can carry the
   * real settlement transaction hash: verify -> work -> settle -> receipt.
   * One handler factory serves the whole PAID_ROUTES table; the flow is
   * identical per route, only the work function and receipt labels differ. */
  const paidHandler = (route) => async (req, res) => {
    const context = {
      adapter: new ExpressAdapter(req),
      path: req.path,
      method: req.method,
      paymentHeader:
        req.header("payment-signature") || req.header("x-payment") || undefined,
      routePattern: route.pattern,
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
    const work = await route.work(req.body || {});
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
      prev_receipt_hash: null, // assigned inside the serialized write below, before signing
      issued_at: new Date().toISOString(),
      issuer: {
        name: "Agent Embassy",
        agent_id: AGENT_ID,
        agent_registry: `${NET.network}:${AGENT_REGISTRY}`,
        agent_card: AGENT_CARD,
      },
      chain: {
        REQUEST: {
          endpoint: route.pattern,
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
        ACTION: { check: route.action, result: work },
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
    /* Assign the chain link, sign, and append as one serialized step —
     * the signature covers prev_receipt_hash, so the link must be final
     * before the digest is taken, and no other settlement may interleave. */
    try {
      await enqueueReceiptWrite(async () => {
        receipt.prev_receipt_hash = lastReceiptHash();
        await signReceipt(receipt);
        appendReceipt(receipt);
      });
    } catch (err) {
      console.error("receipt write failed:", err?.message || err);
    }

    return res.json({ result: work, receipt });
  };

  for (const route of PAID_ROUTES) app.post(route.path, paidHandler(route));

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
