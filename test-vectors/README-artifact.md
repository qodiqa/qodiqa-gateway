# QODIQA Local Artifact & Transparency-Proof Verification Conformance Suite

This directory is the single, language-neutral definition of what a correct
local (offline) artifact/transparency-proof verifier must accept and reject.
Both `sdk/python` and `sdk/javascript` validate their `ArtifactVerifier`
implementations against the exact same file — `artifact-v1.json`. There are
no per-language copies of these vectors, and there must never be. This
follows the same structural pattern already established for the webhook
protocol (see [`README.md`](README.md)) — read that file first if you haven't;
this one only documents what's specific to artifact/transparency-proof
verification.

## Why the production server is the source of truth

This suite exists precisely because the SDKs previously trusted the server's
`/verify` response instead of verifying anything themselves. It would defeat
the entire point of local verification if the *test vectors proving the new
verifiers work* were themselves hand-written rather than produced by the
real signing/hashing code. So, as with the webhook vectors: **no test
vector's expected signature, hash, or Merkle proof is ever hand-written.**
`generate-artifact-vectors.js` calls the actual production modules —
`src/validation/signArtifact.js`, `src/utils/stableStringify.js`,
`src/infra/crypto/ed25519.js`, `src/core/transparency/merkle.js`, and
`src/core/transparency/log.js` — to produce every genuine artifact,
signature, and inclusion proof in `artifact-v1.json`. Negative ("tampered")
vectors are then derived by deterministically mutating a genuine vector
*after* it was produced, never by fabricating one from scratch.

A fixed, hardcoded, test-only Ed25519 keypair is used (see the header
comment in `generate-artifact-vectors.js`) rather than the file-backed key
stores (`services/artifact/keyStore.js`,
`src/core/transparency/transparencyKeyStore.js`) — this keeps regeneration
deterministic (re-running the generator with no protocol change produces
byte-identical output, module the `generatedAt` timestamp) without touching
any real server key material.

## Files in this directory

| File | Purpose |
|---|---|
| `artifact-v1.json` | The canonical, checked-in vector file. **This is the only artifact every SDK consumes.** |
| `artifact-v1.schema.json` | JSON Schema for `artifact-v1.json` — the formal contract for any future SDK's parser. |
| `generate-artifact-vectors.js` | Regenerates `artifact-v1.json` from the real production signing/hashing/Merkle code. Exports `buildVectorFile()` for programmatic use. |

Unlike the webhook suite, there is currently no dedicated
`check-artifact-vector-drift.js`. Regeneration is verified manually (see
"Updating the vectors" below) by re-running the generator and diffing the
result against what's checked in. Adding an automated drift-check job
mirroring the webhook suite's `check-vector-drift.js` (and a corresponding
CI job) is a reasonable, low-risk follow-up if this protocol starts changing
often — it isn't required for the suite itself.

## Vector format

`artifact-v1.json` has two top-level arrays:

- **`artifactVectors`** — each entry is `{ id, description, tags, artifact,
  keySet, verifyAt, clockToleranceMs, transparencyProof, expected }`.
  `artifact` is exactly what to pass to `ArtifactVerifier.verify()` /
  `verify_artifact()`. `keySet` configures a `StaticKeyProvider`/
  `StaticKeyEntry` trust bundle. `verifyAt` (Unix ms) is the deterministic
  "current time" to pass as the verifier's `_now`/`_now=` test-only
  override, so time-dependent vectors (expiry, future-timestamp) never
  depend on when the suite actually runs. `expected` is a **subset** of
  `ArtifactVerificationResult` fields (camelCase) to assert — fields not
  present are not asserted.
- **`transparencyVectors`** — each entry is `{ id, description, tags, proof,
  transparencyKeySet, expected }`. `proof` is the
  `TransparencyInclusionProof` wire object (or `null` for the "no proof
  supplied" case — see below). `transparencyKeySet` configures a separate
  `StaticKeyProvider` for the transparency trust domain. `expected` is a
  subset of `TransparencyVerificationDetail` fields plus
  `transparencyVerified`.

Full field-level documentation lives in `artifact-v1.schema.json`.

### The `proof: null` case

One transparency vector (`missing-transparency-proof`) has `proof: null` —
there is no proof object to verify, by design. This case must be exercised
through the *full* `ArtifactVerifier` pipeline (call `.verify()` with no
`transparencyProof`/`transparency_proof` argument, using any valid artifact
vector), not through `verifyTransparencyProof`/`verify_transparency_proof`
directly, since the "unavailable" state only exists at the artifact
verifier's level. Both SDKs' conformance suites handle this vector specially
for exactly that reason — check `test_artifact_conformance.py` /
`artifact-conformance.test.ts` for the pattern.

### A deliberately-excluded scenario: non-finite numbers

The original design considered a vector injecting `NaN`/`Infinity` into an
artifact payload to exercise the canonicalizer's rejection path. It is
**not** represented as a shared JSON vector: `JSON.stringify(Infinity)`
serializes to `null`, so the actual non-finite value cannot survive a round
trip through `artifact-v1.json` at all — by the time either SDK's test
loader calls `JSON.parse`/`json.load`, the value would already have become
`null`, not `Infinity`. That case is instead covered as a same-language unit
test directly against each SDK's canonical-JSON module
(`canonical-json.test.ts` / `test_verification_canonical_json.py`), where
the value never needs to cross a JSON boundary.

## Current coverage

- **9 artifact vectors**: valid artifact; tampered payload field; tampered
  signature bytes; wrong public key under the same key id; unknown key id;
  revoked key id; expired artifact; future-timestamped artifact; malformed
  artifact (missing required field).
- **9 transparency vectors**: valid Merkle proof + signatures; wrong Merkle
  root; truncated Merkle path; reordered Merkle path; wrong leaf index;
  unsupported proof version; truncated entry signature; unknown
  transparency signing key; missing proof (`unavailable`).

## How an SDK must consume the vectors

1. Read `artifact-v1.json` directly — do not copy, transform, or re-encode
   it into a language-specific fixture file.
2. For each `artifactVectors` entry: construct an `ArtifactVerifier` with a
   `StaticKeyProvider` built from `keySet`, the vector's `verifyAt` as the
   clock override, and `clockToleranceMs`; call `.verify(artifact)`; assert
   every field named in `expected` matches (translating camelCase field
   names to your language's convention — snake_case in Python).
3. For each `transparencyVectors` entry with `proof !== null`: call
   `verifyTransparencyProof`/`verify_transparency_proof` directly with a
   `StaticKeyProvider` built from `transparencyKeySet`; assert
   `transparencyVerified` (derived from `.all_passed()`/`transparencyDetailAllPassed`)
   and every other field in `expected`.
4. For the one entry with `proof === null`: verify through the full
   `ArtifactVerifier` pipeline instead (see above).
5. Never generate a signature, hash, or Merkle proof inside the SDK's own
   test code to satisfy a vector. If a vector doesn't produce the expected
   result against your implementation, that is the finding — fix the SDK,
   not the vector, unless the vector itself is proven wrong against the
   production signer (in which case, fix it at the generator, not by
   hand-editing the JSON).

Reference implementations:
- Generator: [`generate-artifact-vectors.js`](generate-artifact-vectors.js)
- Python: [`sdk/python/tests/test_artifact_conformance.py`](../sdk/python/tests/test_artifact_conformance.py)
- JavaScript: [`sdk/javascript/tests/artifact-conformance.test.ts`](../sdk/javascript/tests/artifact-conformance.test.ts)

## Updating the vectors when the protocol intentionally changes

1. Change the server's signing/hashing behavior first (`stableStringify.js`,
   `ed25519.js`, `canonicalize.js`, `merkle.js`, `log.js`). That remains the
   single source of truth throughout this process.
2. If the change is backward-incompatible with `v1`, bump the protocol
   version (`artifact-v2.json`/`artifact-v2.schema.json` alongside, not
   replacing, the `v1` files), mirroring the webhook suite's version-bump
   procedure.
3. Update scenario/vector-building logic in `generate-artifact-vectors.js`.
4. Regenerate: `node test-vectors/generate-artifact-vectors.js`.
5. Run both conformance suites locally before committing:

   ```bash
   node test-vectors/generate-artifact-vectors.js
   (cd sdk/python && pytest sdk/python/tests/test_artifact_conformance.py -v)
   (cd sdk/javascript && npx jest test/artifact-conformance.test.ts --verbose)
   ```
6. Commit `artifact-v1.json` (or the new version's files) alongside the
   server change in the same PR — never as a follow-up.
