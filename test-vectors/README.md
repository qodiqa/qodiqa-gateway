# QODIQA Webhook Protocol Conformance Suite

This directory is the single, language-neutral definition of the QODIQA
webhook signing protocol's expected behavior. Every SDK — present and
future — validates itself against the exact same file. There are no
per-language copies of these vectors, and there must never be.

> This README covers the **webhook** signing protocol specifically. For
> local (offline) artifact and transparency-proof verification,
> see [`README-artifact.md`](README-artifact.md) and `artifact-v1.json` —
> a separate vector file following the same structural pattern.

This README documents the *process* (how vectors are generated, how to add
an SDK, how to update them). It does not restate the wire protocol itself —
that's documented once, in [`docs/sdk/python/api.md`](../docs/sdk/python/api.md#15-webhook-signature-verification)
and [`docs/sdk/javascript/api.md`](../docs/sdk/javascript/api.md#15-webhook-signature-verification)
(and, as the ground truth, in the header comment of
[`src/core/webhooks/webhookDelivery.js`](../src/core/webhooks/webhookDelivery.js)).
If you're looking for what the protocol *is*, go there. This file is about
how we prove every implementation actually matches it.

## Why the production server is the source of truth

QODIQA is the *sender* of webhooks, not a receiver — `computeSignature()` in
[`src/core/webhooks/webhookDelivery.js`](../src/core/webhooks/webhookDelivery.js)
is the only place in this codebase that ever produces a real, live webhook
signature. Every SDK's verifier exists to accept exactly what that function
emits. Historically, that guarantee was informal: `sdk/python` and
`sdk/javascript` each maintained their own hand-written test fixtures that
encoded the *SDK's own assumption* of the protocol rather than the server's
actual behavior, and both drifted from the real format independently
while their own test suites stayed
green throughout. A self-consistent SDK test suite proves nothing about
interoperability — it can only prove the SDK agrees with itself.

The fix is structural, not just a bug fix: **no test vector's expected
signature is ever hand-written.** Every `expectedSignature` in
`webhook-v1.json` was produced by calling the real `computeSignature()`
function, and the server-side conformance test re-derives every one of them
on every run, so the vectors themselves cannot silently go stale relative
to the code that actually signs production traffic.

## Files in this directory

| File | Purpose |
|---|---|
| `webhook-v1.json` | The canonical, checked-in vector file. **This is the only artifact every SDK consumes.** |
| `webhook-v1.schema.json` | JSON Schema for `webhook-v1.json` — the formal contract for any future SDK's parser. |
| `generate-webhook-vectors.js` | Regenerates `webhook-v1.json` from a signer (the real production one by default). Exports `buildVectorFile()` for programmatic use. |
| `check-vector-drift.js` | Regenerates in memory and diffs against what's checked in; exits non-zero and names the specific vector id(s) that changed if anything drifted. This is what CI runs. Exports `checkDrift()` for programmatic use. |

## Vector format

Each entry in the top-level `vectors` array has two halves:

- **`scenario`** — the genuine, self-consistent `{ secret, timestamp, body,
  expectedSignature }` a real server delivery would have used.
  Server-side conformance tests use **only** this object: they recompute
  `computeSignature(secret, timestamp, body)` and assert it equals
  `expectedSignature`.
- **`verify`** — what is actually handed to an SDK's verifier: `{ body,
  signature, timestamp, secrets, verifyAt, tolerance }`. For a positive
  (`expectedResult: "valid"`) vector this is identical to `scenario`. For a
  negative (`expectedResult: "invalid"`) vector, one or more fields are
  deliberately altered from `scenario` to exercise a specific failure mode,
  and `expectedError` names which of the four canonical error categories
  (`MalformedSignatureError`, `InvalidTimestampError`,
  `ExpiredSignatureError`, `InvalidSignatureError`) must be raised.

`verify.verifyAt` exists so replay-tolerance vectors are deterministic
forever: rather than depending on how long ago the vectors happen to have
been signed relative to whenever the suite runs, each vector pins its own
"current time" for the verifier's test-only clock-override hook (`_now` in
both the Python and JavaScript SDKs). Convert `verifyAt` to whatever
representation your SDK's override expects (both current SDKs take epoch
seconds).

Full field-level documentation lives in `webhook-v1.schema.json`.

## Current coverage

- **10 positive vectors** — one per required payload category (standard
  JSON, Unicode, empty, plain text, long, escaped characters, newlines,
  quotes, UTF-8, emoji).
- **12 negative vectors** — the 11 required categories (modified payload,
  modified signature, modified timestamp, wrong secret, malformed
  signature, malformed timestamp, missing signature, missing timestamp,
  duplicate signature headers, duplicate timestamp headers, unsupported
  signature format) plus one additional vector (`expired-timestamp`)
  covering the replay-tolerance window, which is protocol-critical even
  though it wasn't separately itemized in the original requirements.

## How an SDK must consume the vectors

1. Read `webhook-v1.json` directly — do not copy, transform, or re-encode
   it into a language-specific fixture file. If your test framework can't
   consume JSON directly, write a thin loader, but the loader must read
   this exact file at test time, not a generated/checked-in derivative.
2. For each vector: call your SDK's `body/signature/timestamp/secret(s)`
   verifier with the `verify.*` fields (translating `verifyAt` to your
   verifier's clock-override mechanism, and `tolerance` to its tolerance
   parameter).
3. If `expectedResult === "valid"`: assert the call succeeds.
4. If `expectedResult === "invalid"`: assert the call raises/returns an
   error, and map `expectedError` to whatever your SDK's equivalent
   exception/error type is. Every SDK's four webhook error types
   (malformed signature, invalid timestamp, expired signature, invalid
   signature) should have an obvious 1:1 mapping to the four canonical
   category names — if they don't, that's itself worth flagging.
5. Never generate a signature inside the SDK's own test code to satisfy a
   vector. If a vector's `verify.signature` doesn't produce the expected
   result against your implementation, that is the finding — fix the SDK,
   not the vector, unless the vector itself is proven wrong against
   `computeSignature()` (in which case, fix it at the generator, not by
   hand-editing the JSON).

Reference implementations:
- Server: [`src/core/webhooks/__tests__/webhookProtocolConformance.test.js`](../src/core/webhooks/__tests__/webhookProtocolConformance.test.js)
- Python: [`sdk/python/tests/test_webhook_conformance.py`](../sdk/python/tests/test_webhook_conformance.py)
- JavaScript: [`sdk/javascript/tests/webhook-conformance.test.ts`](../sdk/javascript/tests/webhook-conformance.test.ts)

A future Go/Java/C#/Rust SDK adds a fourth reference implementation the
same way, reading the same `webhook-v1.json`, with zero changes to this
directory.

## CI enforcement

`.github/workflows/test.yml` has a dedicated `webhook-protocol-conformance`
job that:

1. Runs `check-vector-drift.js` against the real production signer —
   fails immediately, naming the affected vector id(s), if the checked-in
   file doesn't match what the server actually produces right now.
2. Runs the server-side conformance test.
3. Runs the Python SDK conformance test.
4. Runs the JavaScript SDK conformance test.

These same tests also run incidentally as part of the broader `unit`,
`sdk-python`, and `sdk-javascript` CI jobs (they live in each project's
normal test directory), but the dedicated job exists so protocol
conformance is never dependent on that incidental coverage holding — it is
its own named, auditable gate. Any of the four steps failing fails CI.

## How to update the vectors when the protocol intentionally changes

1. Change the server's signing behavior in
   `src/core/webhooks/webhookDelivery.js` first. That remains the single
   source of truth throughout this process.
2. If the change is backward-incompatible with `v1` (different header
   name, different canonical message shape, different hash algorithm,
   etc.), bump the protocol version: create `webhook-v2.json` /
   `webhook-v2.schema.json` alongside (not replacing) the `v1` files, and
   update `PROTOCOL_VERSION` in `generate-webhook-vectors.js` — or fork the
   generator if `v1` and `v2` need to coexist during a migration window.
   Every SDK must then explicitly support both versions until `v1` is
   formally deprecated.
3. Update or add scenarios/negative-vector definitions in
   `generate-webhook-vectors.js` as needed for the new behavior.
4. Regenerate: `node test-vectors/generate-webhook-vectors.js`.
5. Confirm no unexpected drift: `node test-vectors/check-vector-drift.js`
   (expect "No drift" immediately after step 4, since you just wrote what
   it compares against — this step matters on the *next* PR, to prove
   nobody's change silently altered signing behavior again).
6. Run all three conformance suites locally (see commands below) before
   committing.
7. Commit `webhook-v1.json` (or the new version's files) alongside the
   server change in the same PR — never as a follow-up. A server change to
   signing behavior without a vector update in the same commit is exactly
   the failure mode this suite exists to prevent.

```bash
# Regenerate from the real server signer
node test-vectors/generate-webhook-vectors.js

# Confirm no drift (should print "No drift")
node test-vectors/check-vector-drift.js

# Run all three conformance suites
npx jest src/core/webhooks/__tests__/webhookProtocolConformance.test.js
(cd sdk/python && pytest sdk/python/tests/test_webhook_conformance.py -v)
(cd sdk/javascript && npx jest test/webhook-conformance.test.ts --verbose)
```

## Isolated testing of the drift detector itself

Both `generate-webhook-vectors.js` and `check-vector-drift.js` accept a
`--signer <path-to-module-exporting-computeSignature>` override, and
`check-vector-drift.js` refuses to write to disk whenever a `--signer`
override is supplied (only the real default signer path may update the
checked-in file). This makes it possible to prove the detector correctly
catches a signing regression without ever touching
`src/core/webhooks/webhookDelivery.js`:

```bash
node test-vectors/check-vector-drift.js --signer /path/to/a/fake-signer.js
```

Use a throwaway module outside the repository (e.g. under a scratch/temp
directory) for the fake signer, and never commit one.
