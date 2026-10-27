# QODIQA Protocol — normative specification (as implemented)

> **Status:** normative,. This document describes what the code at this commit does — the code is the
> source of truth and this text is held to it mechanically:
> - every constant table between `<!-- BEGIN GENERATED -->` markers is rendered from the code and checked in CI
>   (`node scripts/protocol/spec-check.js`);
> - every rule below is exercised by the test vectors in `docs/protocol/vectors/qodiqa-protocol-vectors.json`, generated
>   from the production implementation (`node scripts/protocol/gen-vectors.js --check`) and re-derived without any
>   production code by two independent verifiers, in JavaScript (`scripts/protocol/verify-vectors.js`) and Python
>   (`scripts/protocol/verify_vectors.py`);
> - the audit chain (§9) and transparency log (§10) are covered by the vectors and independent verifier
>.
>
> **Supersedes** 1.0.1, which predates and is kept as a historical document
> (§13 lists every correction). HTTP surface: `docs/api/openapi.json` (generated, diff-checked).

Key words MUST / MUST NOT / SHOULD are normative. All hashes are lowercase hex SHA-256 unless stated; all times are Unix
epoch milliseconds unless stated.

---

## 1. Canonicalization

The single canonical serialization is `src/utils/stableStringify.js` (aliases: `sortedJSON`, `canonicalizeEnvelope`,
`canonicalSerialize`). Every hash and signature in the protocol is computed over its output.

1.1 **Encoding.** Object keys sorted by UTF-16 code unit at every depth; array order preserved; no whitespace; strings and
numbers encoded exactly as ECMAScript `JSON.stringify` encodes them (`-0` → `0`, shortest round-trip digits,
exponent form outside `[1e-7, 1e21)`); `true` / `false` / `null` literal. No Unicode normalization (code points are
serialized as given).

1.2 **`undefined`** (object value or array element) serializes as `null`. *Protocol inputs* — the artifact payload and the
`/ai/chat` and `/sign` bodies — MUST NOT contain `undefined` at all: they are rejected before canonicalization
(`src/validation/canonicalize.js` `hasUndefined`).

1.3 **Errors.** Canonicalization MUST fail (`CanonicalizationError`) on: a non-finite number (`NON_FINITE_NUMBER`); a
function, symbol, bigint or any non-plain object such as a `Date` (`UNSUPPORTED_TYPE`); a key `__proto__`, `constructor`
or `prototype` (`FORBIDDEN_KEY`); a cycle (`CIRCULAR_REFERENCE`); nesting deeper than 1000 (`MAX_DEPTH_EXCEEDED`).
Non-integer numbers are canonicalized by the server, but no protocol field carries one; the Python SDK's canonicalizer
**refuses** non-integer floats by design (cross-language parity policy, `sdk/python/qodiqa/_verification/_canonical_json.py`).

1.4 This is close to, but **not**, RFC 8785 (JCS): `undefined → null` and the rejections above differ.

Vectors: `canonicalization` (valid inputs, the `undefined` construct, every error class).

## 2. Domain separation

A domain-separated hash is `SHA-256(utf8(tag) || utf8(canonical))` — the tag bytes immediately followed by the canonical
bytes, **no separator** (`src/infra/crypto/hashing.js` `domainSeparatedHash`). The registry below is generated from the
source (`scripts/protocol/domainRegistry.js` scans every `QODIQA::…::V<n>` literal):

<!-- BEGIN GENERATED:domain-tags -->
| tag | `ARTIFACT_DOMAINS` constant | defined at |
|---|---|---|
| `QODIQA::ACTION::V2` | — | `src/core/actions/actionHash.js:23`, `src/openapi/routeScanner.js:2132` |
| `QODIQA::ACTION_ARTIFACT::V1` | — | `src/core/actions/actionArtifact.js:22` |
| `QODIQA::ACTION_PLAN::V1` | — | `src/core/actions/planStore.js:22` |
| `QODIQA::AGENT_REQUEST::V1` | — | `src/core/agents/agentAuth.js:24` |
| `QODIQA::APPROVAL::V1` | — | `src/core/approvals/approvalToken.js:24` |
| `QODIQA::ARTIFACT::V1` | `ARTIFACT` | `src/infra/crypto/hashing.js:44` |
| `QODIQA::AUDIT::V1` | `AUDIT` | `src/infra/crypto/hashing.js:50` |
| `QODIQA::AUDIT_CHECKPOINT::V1` | — | `src/core/audit/checkpoint/checkpoint.js:34` |
| `QODIQA::CANONICAL::V1` | `CANONICAL` | `src/infra/crypto/hashing.js:43` |
| `QODIQA::CERTIFICATE::V1` | `CERTIFICATE` | `src/infra/crypto/hashing.js:48` |
| `QODIQA::CERTIFICATION_EVIDENCE::V1` | — | `src/core/certification/evaluationEngine.js:832` |
| `QODIQA::COMPLIANCE_REPORT::V1` | — | `src/core/compliance/reportIntegrity.js:21` |
| `QODIQA::CONSENT::V1` | `CONSENT` | `src/infra/crypto/hashing.js:52` |
| `QODIQA::DELEGATION::V1` | — | `src/core/delegation/delegationToken.js:33` |
| `QODIQA::EVIDENCE::V1` | `EVIDENCE` | `src/core/evidence/generator.js:43`, `src/infra/crypto/hashing.js:49` |
| `QODIQA::EVIDENCE_BUNDLE::V1` | `BUNDLE` | `src/core/evidence/generator.js:44`, `src/infra/crypto/hashing.js:57` |
| `QODIQA::EXECUTION_INVARIANT::V1` | `EXECUTION_INVARIANT` | `src/infra/crypto/hashing.js:54` |
| `QODIQA::EXTERNAL_ANCHOR::V1` | — | `src/core/audit/anchoring/externalAnchors.js:33` |
| `QODIQA::FIELD::V1` | — | `src/infra/crypto/fieldEncryption.js:26` |
| `QODIQA::IDEMPOTENCY::V1` | `IDEMPOTENCY` | `src/infra/crypto/hashing.js:53` |
| `QODIQA::MCP_SERVER_CONFIG::V1` | — | `src/core/mcp/mcpRegistry.js:25` |
| `QODIQA::OUTPUT::V1` | `OUTPUT` | `src/core/audit/entryBuilder.js:171`, `src/infra/crypto/hashing.js:55` |
| `QODIQA::POLICY::RULE::V1` | — | `services/policyHash.js:108` |
| `QODIQA::POLICY::V1` | `POLICY` | `services/policyHash.js:9`, `src/infra/crypto/hashing.js:47` |
| `QODIQA::POLICY_GOVERNANCE::V1` | `POLICY_GOVERNANCE` | `src/infra/crypto/hashing.js:51` |
| `QODIQA::PORTAL_EVIDENCE::V1` | — | `src/core/attestation/attestor.js:422`, `src/core/verification/portal.js:298` |
| `QODIQA::RECEIPT::V1` | `RECEIPT` | `src/infra/crypto/hashing.js:56`, `src/openapi/componentsBuilder.js:852` |
| `QODIQA::REQUEST::V1` | `REQUEST` | `src/infra/crypto/hashing.js:45`, `src/validation/requestHash.js:36` |
| `QODIQA::REQUEST::V2` | `REQUEST_V2` | `src/infra/crypto/hashing.js:46` |
| `QODIQA::TOOL_SCHEMA::V1` | — | `src/core/actions/actionHash.js:24`, `src/core/actions/actionHash.js:68` |
| `QODIQA::TRANSPARENCY::V1` | — | `src/core/transparency/log.js:29`, `src/openapi/componentsBuilder.js:791` |
| `QODIQA::TRANSPARENCY_ROOT::V1` | — | `src/core/transparency/log.js:30` |
| `QODIQA::WITNESS_COSIGN::V1` | — | `src/core/audit/anchoring/witness.js:49` |
<!-- END GENERATED:domain-tags -->

Not every hash in the system is domain-separated: the transparency `payloadHash`, `signatureRef`, the evidence
`packageHash`/`bundleHash` (`canonicalHash`), key fingerprints and generated artifact ids are plain SHA-256 (§12).
RFC 6962 Merkle hashing uses its own byte prefixes, `0x00` leaf / `0x01` node (`src/core/transparency/merkle.js`).

Vectors: `domainTags` (one digest per tag; the production helper must agree for every `ARTIFACT_DOMAINS` tag).

## 3. The signed artifact

3.1 **Wire format.** A JSON object with **exactly** the keys `expiry`, `payload`, `publicKeyId`, `signature`,
`timestamp` — no version field, no other key (§4 step 1–3):

| field | type | meaning |
|---|---|---|
| `payload` | plain object, no `undefined` | the signed claims (§3.3) |
| `publicKeyId` | non-blank string `<tenantId>:key_v<n>` | the signing key |
| `timestamp` | positive finite number (ms) | issue time |
| `expiry` | positive finite number (ms) | expiry |
| `signature` | string, canonical standard base64 of a 64-byte Ed25519 signature: exactly 88 characters ending `==` and round-trip exact | §3.2 |

3.2 **Signature.** `envelopeHash = SHA-256("QODIQA::ARTIFACT::V1" || canonical({expiry, payload, publicKeyId, timestamp}))`;
`signature = base64(Ed25519.sign(privateKey, envelopeHash))` — the signature is over the **raw 32-byte digest**, not its
hex (`src/validation/canonicalize.js` `envelopeHash`, `src/infra/crypto/ed25519.js`). Only Ed25519 exists (no algorithm
negotiation); private keys are PKCS#8 DER, public keys SPKI DER (base64 on the wire, `GET /public-keys`). Code comments
call this the "V2 full-envelope" scheme; its domain tag is `…::V1`.

3.3 **Issuance (`POST /sign`).** `/sign` builds the payload as `{…caller payload, provider (AI routes only), requestId
(UUID v4), requestHash (§5), policyHash (§7), tenantId (from the signing key), callerContext {callerId, callerName,
environment, credentialType}}` and signs it (`src/api/routes/sign.js`). The requested `ttl` is clamped to the maximum
artifact age; the response reports `meta.effectiveTtlMs` and `meta.ttlClamped`. Every `/sign` refusal is a BLOCK decision
body `{decision:'BLOCK', reason, details, requestId}` (OpenAPI `DecisionBlock`).

3.4 **Transport.** On `/ai/chat` (and its aliases) the artifact is sent as the header `x-qodiqa-artifact` =
base64(JSON(artifact)); the header is capped (§4 limits) → `413 ARTIFACT_TOO_LARGE`. `/verify` takes the artifact in
the request body and reads no header.

Vectors: `artifacts` (envelope canonical form, envelope hash and signature for three payloads, verified with the
published test key).

## 4. Artifact verification

Verification (`src/validation/validateArtifact.js`) runs in this order and stops at the first failure; the result is
`{decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED'}` or `{decision: 'BLOCK', reason}`:

1. not a plain object, any key outside the five, any of the five missing, or any present `undefined` → `INVALID_ARTIFACT`;
2. `payload` not a plain object or containing `undefined` → `INVALID_ARTIFACT`;
3. `timestamp` / `expiry` not positive **safe integers** (`1 … 2^53−1`; a fraction, `NaN`, `±Infinity` or a larger value;
   an integral float such as `1.0` is the same JSON number as `1`) → `INVALID_ARTIFACT`;
4. `signature` not a string → `INVALID_ARTIFACT`; any non-canonical spelling (§3.1) → `INVALID_SIGNATURE`;
5. `publicKeyId` blank → `INVALID_ARTIFACT`;
6. **signature verification before any time or key-state check.** An unknown `publicKeyId` is verified against no key and
   yields the **same** `INVALID_SIGNATURE` as a wrong signature — `KEY_NOT_FOUND` is never emitted, so key existence is
   not observable; a canonicalization failure → `INVALID_ARTIFACT`;
6a. `timestamp ≥ expiry` → `INVALID_ARTIFACT`, checked **after** the signature (an unauthenticated caller learns nothing
   about a pair it could not sign; `/sign` still refuses such an envelope at issuance);
7. `timestamp > now + FUTURE_SKEW_MS` → `FUTURE_TIMESTAMP`;
8. `now ≥ expiry` → `EXPIRED`;
9. `now − timestamp > MAX_SKEW_MS` → `TIME_SKEW_EXCEEDED`;
10. key lifecycle on the key's status **timeline** (`src/validation/keyLifecycle.js`): `revoked` → `KEY_REVOKED`;
    `archived` → `KEY_ARCHIVED`; `deprecated` → valid only if the artifact was signed before `deprecatedAt` **and**
    `now < deprecatedAt + DEPRECATED_WINDOW_MS`, else `KEY_DEPRECATED`; `active` → valid unless signed more than
    `FUTURE_SKEW_MS` before `activatedAt` (`KEY_NOT_YET_ACTIVE`); any other status → `KEY_STATUS_UNKNOWN`. A stale
    control-plane timeline → `CONTROL_PLANE_STALE`.

The **acceptance window** is therefore `timestamp ∈ [now − MAX_SKEW_MS, now + FUTURE_SKEW_MS]` and `now < expiry`.

<!-- BEGIN GENERATED:limits -->
| constant | value | source |
|---|---|---|
| future-timestamp tolerance (`FUTURE_SKEW_MS`) | 5000 ms | `src/validation/timeCheck.js` |
| maximum artifact age (`MAX_SKEW_MS` = `MAX_ARTIFACT_AGE_MS`) | 60000 ms | `src/validation/timeCheck.js` |
| deprecated-key verification window (`DEPRECATED_WINDOW_MS`) | 65000 ms | `src/validation/keyLifecycle.js` |
| /sign requested-TTL bounds (`MIN_TTL_MS` … `MAX_TTL_MS`; then clamped to the maximum artifact age) | 1000 … 86400000 ms | `src/validation/schemas/sign.schema.js` |
| /sign HTTP methods | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS | `src/validation/schemas/sign.schema.js` |
| `x-qodiqa-artifact` header cap | `const MAX_ARTIFACT_HDR_BYTES = 8 * 1024;   // 8 KB` | `src/api/routes/aiChat.js:103` |
| canonical signature encoding | `const CANONICAL_SIG_RE = /^[A-Za-z0-9+/]{86}==$/;` | `src/validation/validateArtifact.js:82` |
| artifact wire keys | `const ARTIFACT_SCHEMA = Object.freeze(new Set(['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp']));` | `src/validation/validateArtifact.js:79` |
| nonce key layout (`buildNonceKey('<requestId>', '<tenantId>')`) | `<tenantId>:qodiqa:req:v2:<requestId>` | `src/validation/nonceStore.js` |
| anomaly defaults (`DEFAULT_THRESHOLDS`) | `{"WINDOW_MS":60000,"PER_KEY_MAX":100,"GLOBAL_MAX":5000}` | `src/validation/checkAnomaly.js` |
<!-- END GENERATED:limits -->

On `/ai/chat`, verification failures are *pre-auth* rejects: counted and sampled, never written to the audit chain or the
transparency log. BLOCK decisions are HTTP 200 by default; `QODIQA_BLOCK_HTTP_MODE=status` maps reasons to
400/403/409/429/503/500.

Vectors: `verification` (21 cases — every reason above, both sides of each boundary, all key states; verdicts produced by
production code at a pinned clock and re-derived by both independent verifiers).

## 5. Request binding

5.1 `requestHash = hex(SHA-256("QODIQA::REQUEST::V1" || canonical({body, method: UPPER(method), path})))`
(`src/validation/requestHash.js`). `body` MUST be a plain object without `undefined`.

5.2 **Verification** (`src/validation/verifyRequestBinding.js`): `payload.requestId` MUST be a UUID v4,
`payload.requestHash` MUST be 64 lowercase hex, and the hash recomputed from the request actually received MUST be equal
(constant-time) — otherwise `REQUEST_MISMATCH`.

5.3 **What `/ai/chat` binds:** `{method, path: req.originalUrl without its query string, body}` (`src/api/routes/aiChat.js`).
The query string is **not** part of the binding (§12).

Vectors: `requestBinding` (hashes, including method upper-casing and key-order independence; bound / not-bound outcomes).

## 6. Replay protection

Each artifact's `requestId` is registered once, atomically, by a Lua `SET key 1 NX PX ttl` with
`ttl = floor(expiry − now)` (always ≥ the acceptance window, §4), under the tenant-scoped key layout in §4's table
(`src/validation/nonceStore.js`). A second use → `REPLAY_DETECTED`. After a Redis restart, an artifact issued no later
than `restart + FUTURE_SKEW_MS` whose nonce cannot be proven unused is refused `REPLAY_STATE_UNPROVABLE` (restart barrier;
a surviving nonce still yields `REPLAY_DETECTED`). Production requires Redis AOF persistence. Anomaly limits
(per key and per tenant, per window) are in §4's table. Replay is verified end to end by the acceptance/e2e suites, not by
static vectors (it is stateful).

## 7. Policy hash

`policyHash = hex(SHA-256("QODIQA::POLICY::V1" || canonical(policies with every "_"-prefixed key removed, recursively)))`
over the non-empty policy array (`services/policyHash.js`). It is **informational**: a mismatch between the artifact's
`policyHash` and the live policy set emits `POLICY_DRIFT_DETECTED` and never blocks; the audit entry records the live
value. Vectors: `policyHash`.

## 8. Envelopes

| envelope | shape / construction | source |
|---|---|---|
| management success | `{status:'success', timestamp, requestId, data}` | `src/api/response.js` `success` |
| management error | `{status:'error', timestamp, requestId, error:{code, message, details?}}` | `src/api/response.js` `buildFailureBody` |
| protocol decision (`/ai/chat`, `/verify`, `/sign` refusals) | `{decision, reason, …}`; refusals `{decision:'BLOCK', reason, details, requestId}` | `aiChat.js`, `verify.js`, `sign.js`, `signAuth.js` |
| rate limit (429) | the management error envelope, the decision body, or the flat limiter body — per bucket (OpenAPI `TooManyRequests`) | `src/core/rateLimit/middleware.js` |
| evidence package seal | `packageHash = SHA-256(canonical(content))` (no domain); seal = Ed25519 over `domainSeparatedHash(EVIDENCE, canonical(content))`; `SCHEMA_VERSION 'QODIQA::EVIDENCE::V1'` | `src/core/evidence/generator.js` |
| evidence bundle | signed with `QODIQA::EVIDENCE_BUNDLE::V1` | `src/core/evidence/generator.js` |
| transparency leaf | §10 | `src/core/transparency/enforcementBridge.js` |
| audit checkpoint | `{payload:{v:1, checkpointId, createdAt, chainLength, headHash, pgSeq, evidenceHead, transparencyAnchor, previousCheckpointHash, keyId, keyVersion}, payloadHash, signature}`, domain `QODIQA::AUDIT_CHECKPOINT::V1` | `src/core/audit/checkpoint/checkpoint.js` |

The full HTTP surface (364 operations), with request and response schemas verified against a live server, is the
generated contract `docs/api/openapi.json`.

## 9. Audit schema (v7 — current)

Each audit entry is hash-linked: `hash = hex(SHA-256("QODIQA::AUDIT::V1" || sortedJSON(coreFields)))`, where `coreFields`
is **exactly** the field set of the entry's `schemaVersion`; `prevHash` is the previous entry's `hash` (`"GENESIS"` for
the first entry, or a signed base checkpoint's `headHash` after an operator retention prune). An entry verifies when its
`canonical` equals `sortedJSON(coreFields)` and its `hash` equals the domain hash of `canonical`
(`src/core/audit/entryBuilder.js`; the contracts for v1–v7 are restated
by the independent verifier in `scripts/audit-repro/`).

<!-- BEGIN GENERATED:audit-schema -->
- `CURRENT_SCHEMA_VERSION` = **7** (written by `buildEntry`); `SUPPORTED_SCHEMA_VERSIONS` = `[1, 2, 3, 4, 5, 6, 7, 8]` (any other version is refused).
- `EVIDENCE_SCHEMA_CURRENT` (evidence-chain records, a separate schema) = **4**.

| version | hashed fields (exactly these, canonicalized and domain-hashed) | added |
|---|---|---|
| 1 | 9 fields | `artifactId`, `decision`, `inputHash`, `policyHash`, `prevHash`, `requestHash`, `signature`, `timestamp`, `verificationResult` |
| 2 | 11 fields | `publicKeyId`, `schemaVersion` |
| 3 | 13 fields | `consentProvenance`, `policyDecision` |
| 4 | 14 fields | `callerContext` |
| 5 | 16 fields | `provider`, `model` |
| 6 | 21 fields | `stage`, `reason`, `semantic`, `tokenUsage`, `responseId` |
| 7 | 28 fields | `entryType`, `outputHash`, `tenantId`, `requestId`, `organizationId`, `executionContext`, `executingProvider` |
| 8 | 38 fields | `issuedAt`, `protocolVersion`, `agentId`, `sessionId`, `actionSeq`, `actionHash`, `approvalRef`, `dlp`, `bytesDelivered`, `completionStatus` |
<!-- END GENERATED:audit-schema -->

**Outside the hash** (stored, not integrity-protected): `highResTime`, `nonce`, `traceId` — and, on entries written before
v7 only, `tenantId`, `organizationId`, `requestId` and `executionContext`. On `/ai/chat`, `inputHash` equals the artifact's
`requestHash`; the hash-protected `provider` is the **requested** provider and, from v7, `executingProvider` is the
provider that actually executed (after routing / failover).

**v7 additions**:
- `entryType` ∈ `DECISION` | `INTENT` | `STREAM_OPENED`. An `INTENT` entry is written immediately before a provider is called
  (`decision "ALLOW"`, `stage "PROVIDER_DISPATCH"`, artifact id `<artifactId>:intent`); a `STREAM_OPENED` entry before the
  first streamed byte (`decision "ALLOW"`, `stage "STREAM_OPENED"`, `<artifactId>:stream_opened`). Both are fail-closed (no
  provider call / no byte without them), carry `outputHash: null`, link to their `DECISION` through the hashed `requestId`, and
  each registers its own transparency leaf (payload `entryType`, leaf artifact id = the suffixed id) and evidence-chain record.
- `outputHash` (DECISION only) = `hex(SHA-256("QODIQA::OUTPUT::V1" || UTF-8(delivered content)))` — exactly the output content
  delivered to the client (for a stream, the concatenation of the released chunks); nothing delivered → the hash of the empty
  byte string. A v7 ALLOW must state it.
- `executionContext` is hashed whole (plain JSON values only; non-JSON values are refused at append, never stringified).
- `consentProvenance.subject` and `callerContext.callerId` hold the subject pseudonym (`ap1:` + HMAC under a per-subject,
  crypto-shreddable key), never the raw identifier; appending them requires PostgreSQL (fail-closed).
- Verification: a v7 entry after which an older version appears in the same walk is `SCHEMA_DOWNGRADE` (failure). A v7 DECISION
  with a non-null `executingProvider` and no earlier INTENT/STREAM_OPENED for its `requestId` is `MISSING_INTENT` (failure)
  **only in a walk that starts at GENESIS**; a walk that starts after GENESIS (pruned chain, checkpoint boot, incremental pointer,
  any bounded walk) reports it as the warning `INTENT_BEFORE_START`. An INTENT/STREAM_OPENED without a later DECISION in the
  walk is the warning `ORPHAN_INTENT`. Allow/block/replay statistics count DECISION entries only.

Vectors: `entries.json` (v1–v6), `chains.json`, `anchors.json`, `canonicalization.json` (the frozen v6-era set), enforced by
 against both the production and the independent verifier; v7 entries,
lifecycle rules and mixed v6/v7 chains are covered by (current-schema
chain).

## 10. Transparency log

Every decision that passes pre-auth registers a signed leaf (`entryType 'AUDIT'`) whose payload carries the request id,
decision, reason, stage, artifact/request/policy hashes, provider, key id, audit entry hash, tenant, semantic and
consent provenance, and caller (`enforcementBridge.js`). `entry_hash = SHA-256("QODIQA::TRANSPARENCY::V1" ||
canonical entry)` (`src/core/transparency/log.js`); entries are hash-chained (`previous_entry_hash`) and Ed25519-signed.
Signed roots (`QODIQA::TRANSPARENCY_ROOT::V1`) over RFC 6962 Merkle trees are generated automatically every
`TRANSPARENCY_ROOT_INTERVAL_MS` (default 60 s) when PostgreSQL is enabled; the synchronous `/ai/chat` response carries
`merkleRoot: null` and an `inclusionProofRef`; `GET /v1/transparency/proof/:id` returns the proof once a root covers the
entry. Public entries never include the payload itself. Vectors: `transparency.json`.

## 11. Conformance and drift control

| artifact | regenerate | check (CI) |
|---|---|---|
| protocol vectors | `npm run protocol:vectors` | `npm run protocol:check` (generator `--check` + the JS independent verifier + spec-check); the Python independent verifiers are run separately (CI job `specs-equal-code`): `python scripts/protocol/verify_vectors.py` and, for the protocol-V2 families (`docs/protocol/vectors/v2-*.json`), `python scripts/protocol/verify_v2_vectors.py` — it always imports this repository's `sdk/python` canonicalizer and refuses any other installed `qodiqa` package |
| this document's generated sections | `node scripts/protocol/spec-check.js --write` | included in `npm run protocol:check` |
| OpenAPI contract | `npm run openapi:generate` | `npm run openapi:check`; live route parity and committed-contract tests in the unit gate |
| SDK ↔ OpenAPI | — | `npm run contract:sdk` (static); `scripts/contract/live-contract.js` runs both SDKs against a real server |

## 12. Known deviations and flags (recorded, not changed)

1. **The offline evidence-package verifiers trust the package's own key and domain** (`verifyEvidencePackage` /
   `verifyEvidenceBundle`, `src/core/evidence/generator.js`): the signature is checked against the `publicKey` embedded in
   the package, under the `domain` the package declares, so `valid: true` proves self-consistency — not QODIQA authorship —
   unless the caller pins the key to QODIQA's published keys. The server's public evidence-verification route does **not**
   use these: `POST /v1/attestation/evidence/verify` binds every package to its stored original (H129-A). Filed as
   (MEDIUM, outside scope; not fixed here).
2. **`QODIQA::AUDIT::V1` is reused** for three different inputs (entry hash, `computeAuditRecordHash`, the persisted-record
   hash) — distinguishable by input shape, not by tag.
3. **Undomained hashes** listed in §2.
4. **Query strings are not bound** on `/ai/chat` (§5.3), while `requestHash.js` documents "no query-string stripping" for
   its own input; callers that need the query bound must put it in the body.
5. **The external verifiers' canonicalization is conformant** — `tools/verify/verify.external.js`,
   `tools/verify/verify.bundle.external.js`, `tools/verify/verify.evidence.external.js` and `tools/verify/verify_external.py` now escape, order keys, format
   numbers and refuse exactly like §3; `test/externalVerifierCanonicalConformance.test.js` holds every standalone copy
   to the server's canonicalizer over the vectors plus an adversarial corpus (control characters, lone surrogates,
   non-BMP keys, floats). *Historical (before):* `tools/verify/verify.external.js` / `tools/verify/verify_external.py` implemented a reduced canonicalization (only
   `\\ " \n \r \t` escaped; no forbidden-key or non-finite rejection; Python float/key-order differences) and were **not**
   conformant for control characters, floats or non-BMP keys. The other independent implementations are
   `scripts/audit-repro/verify/canonical.js` and `scripts/protocol/verify-vectors.js`.
6. Two code comments in `validateArtifact.js` still say "zero tolerance" for the future-timestamp and expiry checks; the
   code applies `FUTURE_SKEW_MS` (§4). Comments only.

## 13. Corrections to 1.0.1 (historical)

| 1.0.1 said | the implementation does |
|---|---|
| invalid base64 signature → `INVALID_ARTIFACT`; any padding accepted | non-canonical encoding → `INVALID_SIGNATURE`; exactly 88 characters with `==` |
| zero future-timestamp tolerance | `FUTURE_SKEW_MS` (5 s) |
| `expiry > timestamp` checked at verification | checked at verification after the signature **and** at issuance; `timestamp`/`expiry` must be safe integers (before only issuance checked the order) |
| key → time → signature order; `KEY_NOT_FOUND` | signature first; unknown key = `INVALID_SIGNATURE`; `KEY_NOT_FOUND` never emitted |
| three key states | four (`active`, `deprecated` with a 65 s window, `archived`, `revoked`) plus lifecycle reasons |
| path bound without stripping the query | `/ai/chat` binds the path without its query string |
| every decision audited | pre-auth rejects are counted, not audited |
| audit schema v4 (or v2) current | v7 current; v1–v7 verifiable (§9, generated) |
| replay window = artifact validity; "5 minute" TTL in docs and examples | window `[now−60 s, now+5 s]` ∧ `now < expiry`; `/sign` TTL clamped to 60 s |
| domain registry of 7 tags | 20 tags (§2, generated) |
| payload without `provider` / `callerContext` | both present on AI-route artifacts |
| `test-vectors/artifact-v1.json` | earlier, kept as history; the current vectors are `docs/protocol/vectors/` |
