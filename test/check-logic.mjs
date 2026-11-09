/**
 * Check-logic test — the pure decision logic behind the paid checks,
 * exercised directly (the paid path itself needs a live facilitator
 * authorization, so the logic is proven here as units):
 *
 *  1. The fetch boundary (targetProblem): public targets pass; literal
 *     private, loopback, link-local, and shared-space addresses and
 *     localhost names are refused; malformed and non-http(s) inputs
 *     are refused.
 *  2. The condition evaluator (evaluateConditions): status, substring,
 *     and JSON-value conditions each report their own outcome, and a
 *     single failed condition fails the whole check.
 *  3. Receipt-chain serialization (enqueueReceiptWrite): twenty
 *     parallel writes in the paid handler's exact pattern (read the
 *     predecessor hash, then append) produce one un-forked chain.
 */

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), "celo-logic-"));

const {
  targetProblem,
  evaluateConditions,
  enqueueReceiptWrite,
  lastReceiptHash,
  appendReceipt,
  readBodyCapped,
} = await import("../src/server.js");

let failures = 0;
function check(label, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
}

/* 1 — the fetch boundary */
check("public https URL passes", targetProblem("https://example.com/page") === null);
check("public http URL passes", targetProblem("http://agents.example.org:8080/x") === null);
check("172.32.x.x is public (outside 172.16/12)", targetProblem("http://172.32.0.1/") === null);
check("garbage is refused", targetProblem("not a url") !== null);
check("non-http(s) scheme is refused", targetProblem("ftp://example.com/") !== null);
check("localhost name is refused", targetProblem("http://localhost:8787/health") !== null);
check("*.localhost is refused", targetProblem("http://api.localhost/") !== null);
check("127.0.0.1 is refused", targetProblem("http://127.0.0.1/") !== null);
check("10.x is refused", targetProblem("http://10.1.2.3/") !== null);
check("172.16.x is refused", targetProblem("http://172.16.0.9/") !== null);
check("192.168.x is refused", targetProblem("http://192.168.1.1/") !== null);
check("169.254.x (link-local) is refused", targetProblem("http://169.254.169.254/latest/meta-data") !== null);
check("100.64.x (shared space) is refused", targetProblem("http://100.64.0.1/") !== null);
check("[::1] is refused", targetProblem("http://[::1]/") !== null);
/* The same refused addresses in their other spellings — the URL parser
 * rewrites a dotted mapped tail as hex groups, so both spellings are
 * asserted, plus the IPv4-compatible form and a mapped link-local. */
check("[::ffff:127.0.0.1] (mapped loopback, dotted) is refused", targetProblem("http://[::ffff:127.0.0.1]/") !== null);
check("[::ffff:7f00:1] (mapped loopback, hex) is refused", targetProblem("http://[::ffff:7f00:1]/") !== null);
check("[::ffff:a9fe:a9fe] (mapped link-local) is refused", targetProblem("http://[::ffff:a9fe:a9fe]/") !== null);
check("[::7f00:1] (IPv4-compatible loopback) is refused", targetProblem("http://[::7f00:1]/") !== null);
check("[fe80::1] (link-local) is refused", targetProblem("http://[fe80::1]/") !== null);
check("[fd00::1] (unique local) is refused", targetProblem("http://[fd00::1]/") !== null);
check("public IPv6 passes", targetProblem("https://[2606:4700:4700::1111]/") === null);
check("mapped public IPv4 passes", targetProblem("http://[::ffff:808:808]/") === null);

/* 2 — the condition evaluator */
const facts = {
  http_status: 200,
  body_text: "<html><body>hello world</body></html>",
};
const jsonFacts = {
  http_status: 200,
  body_text: '{"name":"embassy","stats":{"settled":3}}',
};
let r = evaluateConditions(facts, { expect_status: 200 });
check("status match passes", r.pass === true && r.outcomes.status.ok === true);
r = evaluateConditions(facts, { expect_status: 404 });
check("status mismatch fails", r.pass === false && r.outcomes.status.ok === false && r.outcomes.status.observed === 200);
r = evaluateConditions(facts, { expect_body_contains: "hello" });
check("substring present passes", r.pass === true && r.outcomes.body_contains.ok === true);
r = evaluateConditions(facts, { expect_body_contains: "goodbye" });
check("substring absent fails", r.pass === false && r.outcomes.body_contains.ok === false);
r = evaluateConditions(jsonFacts, { expect_json_path: "stats.settled", expect_json_value: 3 });
check("JSON value equal passes", r.pass === true && r.outcomes.json_value.ok === true && r.outcomes.json_value.observed === 3);
r = evaluateConditions(jsonFacts, { expect_json_path: "stats.settled", expect_json_value: 4 });
check("JSON value unequal fails", r.pass === false && r.outcomes.json_value.ok === false);
r = evaluateConditions(jsonFacts, { expect_json_path: "stats.missing", expect_json_value: 1 });
check("JSON path missing fails", r.pass === false && r.outcomes.json_value.found === false);
r = evaluateConditions({ http_status: 200, body_text: "not json" }, { expect_json_path: "a", expect_json_value: 1 });
check("non-JSON body fails the JSON condition", r.pass === false && r.outcomes.json_value.body_is_json === false);
r = evaluateConditions(facts, { expect_status: 200, expect_body_contains: "goodbye" });
check("one failed condition fails the check", r.pass === false && r.outcomes.status.ok === true && r.outcomes.body_contains.ok === false);

/* 3 — receipt-chain serialization under parallel writes */
const N = 20;
await Promise.all(
  Array.from({ length: N }, (_, i) =>
    enqueueReceiptWrite(async () => {
      appendReceipt({ n: i, prev_receipt_hash: lastReceiptHash() });
    }),
  ),
);
const lines = readFileSync(join(process.env.DATA_DIR, "receipts.jsonl"), "utf8").trim().split("\n");
check("all parallel writes landed", lines.length === N, `${lines.length}/${N}`);
let chainOk = true;
for (let i = 0; i < lines.length; i++) {
  const expected = i === 0 ? "genesis" : createHash("sha256").update(lines[i - 1]).digest("hex");
  if (JSON.parse(lines[i]).prev_receipt_hash !== expected) chainOk = false;
}
check("the chain never forked under parallel writes", chainOk);

/* 4 — the capped body read: the 1 MiB observation cap holds while
 * streaming, and the kept bytes are exactly the body's first 1 MiB. */
{
  const small = new Response(new Blob(["hello"]));
  const r1 = await readBodyCapped(small);
  check("small body reads whole, not truncated", r1.buf.toString() === "hello" && r1.truncated === false);

  const big = new Uint8Array(3 * 1024 * 1024);
  for (let i = 0; i < big.length; i++) big[i] = i % 251;
  const stream = new ReadableStream({
    start(controller) {
      for (let off = 0; off < big.length; off += 65536) controller.enqueue(big.subarray(off, off + 65536));
      controller.close();
    },
  });
  const r2 = await readBodyCapped(new Response(stream));
  check("oversized body is capped at 1 MiB", r2.buf.length === 1024 * 1024, `${r2.buf.length} bytes kept`);
  check("oversized body reports truncated", r2.truncated === true);
  check(
    "kept bytes are the body's first 1 MiB",
    createHash("sha256").update(r2.buf).digest("hex") ===
      createHash("sha256").update(big.subarray(0, 1024 * 1024)).digest("hex"),
  );

  const empty = await readBodyCapped(new Response(null));
  check("empty body reads empty, not truncated", empty.buf.length === 0 && empty.truncated === false);
}

console.log(failures === 0 ? "\nCHECK LOGIC: ALL PASS" : `\nCHECK LOGIC: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
