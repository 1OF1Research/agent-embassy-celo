# Agent Embassy on Celo

Pay-per-call verification, settled on Celo through the x402 protocol — built for the **Agents on Open Rails** hackathon (Open Corridors → **USA₮ with x402** subtrack). Registration and submission close **Nov 9, 2026, 09:00 GMT**.

Agent Embassy is a live agent-payments service: agents pay per call and every call returns a signed outcome receipt. This repository is its Celo deployment, written during the hackathon window. The production service lives elsewhere; this repo is the Celo surface, derived from the same stack — the same `@x402` v2 packages, the same receipt format (`embassy-receipt/2`), the same signing scheme.

## What it does

Three paid checks, one price — **0.001 USD** in **USA₮** (preferred) or **USDC** on Celo mainnet (`eip155:42220`):

| Endpoint | Body | Returns |
| --- | --- | --- |
| `POST /v1/check/verify` | `{ "url": "https://example.com/page" }` | An attestation of what was observed: reachability, HTTP status, byte count, SHA-256 of the body, fetch timestamp. |
| `POST /v1/check/ping` | `{ "url": ..., "expect_status": 200, "expect_body_contains": "...", "expect_json_path": "a.b", "expect_json_value": ... }` | A pass/fail attestation against the buyer's own conditions — each condition named with its outcome. Any subset of conditions may be given; the default is status 200. |
| `POST /v1/check/changes` | `{ "url": ..., "known_sha256": "<64 hex>" }` | Whether the body's current SHA-256 differs from the hash the buyer supplies. One call, one comparison — not a standing watch. |

- **Settlement:** Celo's hosted x402 facilitator (`https://api.x402.celo.org`). The buyer signs an EIP-3009 authorization; the facilitator pays the settlement gas; funds move buyer → merchant directly. The facilitator holds nothing. Sponsored gas is the rail's own design, not a builder contribution, and is not claimed as one.
- **Every settled call returns a signed Embassy receipt** carrying the payer, the amount, and the settlement transaction hash, which anyone can open on Celoscan — see *Verify everything yourself* below.
- Unpaid calls return a standard x402 v2 `402` challenge naming both assets, in the `PAYMENT-REQUIRED` header and mirrored in the body, so header readers and body readers see the same requirements.
- Bad input is refused *after* payment verification and *before* settlement (HTTP 422, the authorization is cancelled): a call with an unusable body never settles.

**Fetch boundary.** The checks fetch arbitrary URLs for strangers, so targets are guarded: literal private, loopback, link-local, and shared-space addresses and localhost names are refused, in every spelling — IPv6 literals are judged in expanded form, so IPv4-mapped and IPv4-compatible spellings of a refused address are refused too — on the first hop and on every redirect hop. Response bodies are read under the same discipline: the 1 MiB observation cap is enforced while streaming, never after an unbounded read. One limit is named plainly: a public name that resolves to a private address is a resolution-time question this surface does not claim to answer.

Why USA₮: it is a US-dollar stablecoin issued by Anchorage Digital Bank, N.A. and supported by Tether, built to move between independent parties on cheap rails. The user it serves is any agent — or person — who needs a verifiable answer for a tenth of a cent, with no account, no card, and no subscription.

## Run it under your own agent identity

Out of the box, this service presents no agent identity at all — no number in its descriptions, no registration on its agent card, none in its receipts. If you run it under your own ERC-8004 agent number, two settings present yours instead:

- `AGENT_ID` — your agent number. Register your own on Celo first: agent numbers live in the ERC-8004 registry contract, `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`. You can check any number yourself with `ownerOf(<number>)` and `tokenURI(<number>)` on that contract, from any Celo RPC.
- `AGENT_CARD_URL` — the public address of your agent card, the page your registration points at.

The number is a setting, never compiled in: the same bytes run under any number, or none. (This hackathon requires an agent identity; this deployment's own number is set in its deployment configuration, the same way yours would be.)

### Open, or agentid only

You also choose who may pay you:

- **Open** — the default (`REQUIRE_AGENT_ID` unset or `off`). Anyone can pay. The box is open.
- **Agentid only** — set `REQUIRE_AGENT_ID=on` and only customers with their own agent number can pay you. The customer sends their `agentId` with the call; before any money moves, the service reads the registry on Celo and checks that the number belongs to the wallet in the customer's signed payment. Everyone else is turned away with a plain refusal naming the reason — no payment taken, no receipt written. The 402 challenge says so up front: while this mode is on, every offer carries `agentIdRequired`. A customer who passes has their agent number recorded in the receipt.

## Attribution (ERC-8021)

The hackathon rules state that for x402 transactions the PayTo wallet address is the attribution, because attribution tags are not yet supported by x402. The PayTo address in every 402 challenge is therefore this project's attribution, and it is declared in the submission in exactly those terms.

## Verify everything yourself

Nothing in this entry asks to be trusted. In ladder order, against the live deployment (`https://agent-embassy-celo.fly.dev` once deployed):

1. **Identity** — this deployment's agent card (`/.well-known/agent.json`) names its registration; read `ownerOf` and `tokenURI` for that number on the registry contract above, from any Celo RPC. The registry entry, not this server, is the identity truth.
2. **The offer** — POST to any check endpoint without payment and read the 402 challenge: both assets, the exact PayTo, the 0.001 price. The discovery documents say the same thing in machine form: `/.well-known/x402.json`, `/openapi.json`, `/llms.txt`, `/.well-known/agent.json`.
3. **A receipt's signature** — the signer is published outside the receipts at `/.well-known/embassy-signer.json`. By hand: take the receipt JSON with `signature.value` set to `null`, SHA-256 the compact JSON, and ecrecover the EIP-191 signature over that digest; the recovered address must equal `signature.signer` and the published signer. Or in one click: `GET /v1/receipts/<receipt_id>/verify` re-derives both the signature verdict and the chain-link verdict — separately, never blended — and the human page at `/proof` renders the same checks.
4. **The settlement** — `chain.PROOF.settlement_tx` in any receipt opens on Celoscan; the payment does not depend on our server's word.
5. **The chain** — receipts are append-only and hash-chained: each names the SHA-256 of the previous line. `GET /v1/receipts` shows the recent log; `/health` reports its count and current head hash.

## Honest note on usage

The judging for this subtrack looks for real settlement between *independent* parties. Settlements from our own wallets prove the rail works; they do not count as independent usage, and we do not present them as such. What this entry puts in front of judges is a real, public, mainnet surface that any outside agent can call from the moment it ships — plus receipts that make every call, ours or anyone's, independently checkable.

## Run it

```bash
npm install
cp .env.example .env   # add X402_CELO_API_KEY from https://x402.celo.org
npm start              # http://localhost:8787
npm run smoke          # boots the service; byte-checks every route's 402 challenge
npm run test:receipt   # signs a test receipt and verifies it by the documented method
npm run test:logic     # the checks' decision logic: fetch boundary, conditions, chain writes
npm run test:ladder    # the proof ladder walked end to end, incl. an altered receipt
npm run test:discovery # the discovery shelf names exactly the shelf the server answers
npm run test:gate      # the configured identity, and open vs agentid-only acceptance
```

Environment:

| Variable | Meaning |
| --- | --- |
| `X402_CELO_API_KEY` | Facilitator API key (sign a message at https://x402.celo.org; free tier includes up to 100 mainnet credits (facilitator's pricing page, read 2026-11-08; the venue FAQ still states 20), 1000 on testnet). Needed for settlement; the 402 challenge works without it. |
| `EMBASSY_SIGNING_KEY` | Dedicated receipt-signing key (statements only, cannot move funds). Without it, receipts are issued unsigned and say so. |
| `CELO_NETWORK` | `mainnet` (default) or `sepolia` (testnet rehearsal; USDC only). |
| `PUBLIC_BASE_URL` | Public URL of this deployment, used in the agent card and discovery documents. |
| `AGENT_ID` | Your ERC-8004 agent number (optional). Unset: the service presents no agent identity. |
| `AGENT_CARD_URL` | Public address of your agent card (optional). |
| `REQUIRE_AGENT_ID` | `on`: agentid only — only customers who present an agent number the registry says is theirs can pay. Unset or `off`: open to anyone. |
| `CELO_RPC_URL` | Celo JSON-RPC endpoint used for the ownership check. Default: the public Celo node for the chosen network. |
| `PORT`, `DATA_DIR` | Listen port; receipt-log directory. |

## Receipts

Every settled call appends one receipt to `data/receipts.jsonl` (append-only, hash-chained: each receipt names the SHA-256 of the previous line; writes are serialized so two same-instant settlements cannot fork the chain's linking) and returns it to the caller. A receipt carries the five stages — REQUEST → AUTHORIZATION → ACTION → PROOF → LIABILITY_BOUNDARY — and a signature block. The PROOF stage names what the receipt proves — the check ran at the stated time and the payment settled on Celo — and the LIABILITY_BOUNDARY states what it does not: the checked page's contents, safety, or future state.

## Layout

- `src/server.js` — the whole service (surface, x402 flow, receipts, proof ladder, discovery shelf).
- `test/smoke.mjs` — boot + per-route 402-challenge byte check (no payment made).
- `test/receipt-signature.mjs` — signs a receipt with a throwaway key and verifies it by the documented method.
- `test/check-logic.mjs` — the fetch boundary, condition evaluator, and receipt-chain writes under parallelism.
- `test/proof-ladder.mjs` — signer document, receipt reads, verify verdicts, incl. an altered receipt failing exactly one verdict.
- `test/discovery.mjs` — the four discovery documents name the same shelf, and every advertised route answers.
- `test/agent-gate.mjs` — the configured identity (a placeholder number, presented everywhere or nowhere) and the acceptance policy: open mode's bare offers, agentid-only mode's advertised requirement and its refusals — ownership read from a named local stub of the registry endpoint, never from the real chain.
- `.env.example` — configuration template. Secrets live in `.env` only, never in this repo.

## License

ISC. Built by Agent Embassy — https://aemb.pro · agent.embassy@proton.me
