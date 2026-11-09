# Agent Embassy on Celo

Pay-per-call verification, settled on Celo through the x402 protocol — built for the **Agents on Open Rails** hackathon (Open Corridors → **USA₮ with x402** subtrack). Registration and submission close **Nov 9, 2026, 09:00 GMT**.

Agent Embassy is a live agent-payments service: agents pay per call and every call returns a signed outcome receipt. This repository is its Celo deployment, written during the hackathon window. The production service (33 tools on Base and other chains) lives elsewhere; this repo is the Celo surface, derived from the same stack — the same `@x402` v2 packages, the same receipt format (`embassy-receipt/2`), the same signing scheme.

## What it does

One paid endpoint:

```
POST /v1/check/verify
{ "url": "https://example.com/page" }
```

- **Price:** 0.001 USD — in **USA₮** (preferred) or **USDC** on Celo mainnet (`eip155:42220`).
- **Settlement:** Celo's hosted x402 facilitator (`https://api.x402.celo.org`). The buyer signs an EIP-3009 authorization; the facilitator pays the settlement gas; funds move buyer → merchant directly. The facilitator holds nothing.
- **Returns:** a URL attestation (reachability, HTTP status, byte count, SHA-256 of the body, fetch timestamp) **plus a signed Embassy receipt** carrying the payer, the amount, and the settlement transaction hash, which anyone can open on Celoscan.
- Unpaid calls return a standard x402 v2 `402` challenge naming both assets.

Why USA₮: it is a US-dollar stablecoin issued by Anchorage Digital Bank, N.A. and supported by Tether, built to move between independent parties on cheap rails. The user it serves is any agent — or person — who needs a verifiable answer for a tenth of a cent, with no account, no card, and no subscription.

## Identity (ERC-8004)

Required by every track of this hackathon, and already held:

- **Agent ID 9966** on Celo mainnet, registry `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`
- Owner / PayTo: `0xD004278bC57FE4B9F743ABf17d713ed4169A88E9`
- Agent card (the registry tokenURI): https://aemb.pro/agent.json
- Verify it yourself: `ownerOf(9966)` and `tokenURI(9966)` on the registry contract via any Celo RPC.

## Attribution (ERC-8021)

The hackathon rules state that for x402 transactions the PayTo wallet address is the attribution, because attribution tags are not yet supported by x402. The PayTo address above is therefore this project's attribution, and it is declared in the submission in exactly those terms.

## Honest note on usage

The judging for this subtrack looks for real settlement between *independent* parties. Settlements from our own wallets prove the rail works; they do not count as independent usage, and we do not present them as such. What this entry puts in front of judges is a real, public, mainnet surface that any outside agent can call from the moment it ships — plus receipts that make every call, ours or anyone's, independently checkable.

## Run it

```bash
npm install
cp .env.example .env   # add X402_CELO_API_KEY from https://x402.celo.org
npm start              # http://localhost:8787
npm run smoke          # boots the service and byte-checks the 402 challenge
npm run test:receipt   # signs a test receipt and verifies it by the documented method below
```

Environment:

| Variable | Meaning |
| --- | --- |
| `X402_CELO_API_KEY` | Facilitator API key (sign a message at x402.celo.org; free tier includes up to 100 mainnet credits (facilitator's pricing page, read 2026-11-08; the venue FAQ still states 20), 1000 on testnet). Needed for settlement; the 402 challenge works without it. |
| `EMBASSY_SIGNING_KEY` | Dedicated receipt-signing key (statements only, cannot move funds). Without it, receipts are issued unsigned and say so. |
| `CELO_NETWORK` | `mainnet` (default) or `sepolia` (testnet rehearsal; USDC only). |
| `PUBLIC_BASE_URL` | Public URL of this deployment, used in the agent card. |
| `PORT`, `DATA_DIR` | Listen port; receipt-log directory. |

## Receipts

Every settled call appends one receipt to `data/receipts.jsonl` (append-only, hash-chained: each receipt names the SHA-256 of the previous line) and returns it to the caller. A receipt carries the five stages — REQUEST → AUTHORIZATION → ACTION → PROOF → LIABILITY_BOUNDARY — and a signature block.

To verify a receipt's signature: take the receipt JSON with `signature.value` set to `null`, SHA-256 the compact JSON, and ecrecover the EIP-191 signature over that digest; the recovered address must equal `signature.signer`. The settlement itself is verified independently on Celoscan from `chain.PROOF.settlement_tx`.

## Layout

- `src/server.js` — the whole service (surface, x402 flow, receipts).
- `test/smoke.mjs` — boot + 402-challenge byte check (no payment made).
- `test/receipt-signature.mjs` — signs a receipt with a throwaway key and verifies it by the documented method.
- `.env.example` — configuration template. Secrets live in `.env` only, never in this repo.

## License

ISC. Built by Agent Embassy — https://aemb.pro · agent.embassy@proton.me
