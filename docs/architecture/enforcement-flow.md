# ENFORCEMENT FLOW

Complete per-request decision pipeline for `POST /ai/chat`. Every step is fail-closed — any failure produces a BLOCK response and no subsequent step runs.

> **Reconciled 2026-10-02 against the implementation.** The normative wire protocol (artifact, canonicalization, domain tags, binding, verification order, audit schema) is [`docs/protocol/QODIQA-PROTOCOL.md`](../protocol/QODIQA-PROTOCOL.md), with generated test vectors; where this walkthrough and that spec differ, the spec (and the code it is generated from) wins. Key corrections: Step 1's order is signature-first and never emits `KEY_NOT_FOUND`; future timestamps have a 5 s tolerance; artifact-validation (Step 1) rejections are **not audited**; BLOCK status is 200 by default, class statuses with `QODIQA_BLOCK_HTTP_MODE=status`; policy lives in the control plane.

---

## Overview

```
POST /ai/chat
  │
  ├─ Per-IP rate limit (ai_chat_ip) + admission control (503 SERVER_OVERLOADED)
  ├─ Content-type guard
  ├─ Input guard (body + prompt validation)
  ├─ Artifact decode (base64 → JSON)
  │
  └─ enforce_and_execute() ─────────────────────────────────────────────────
       │                                                               30s timeout
       ├─ Step 1: validateArtifact()          ← schema + crypto
       ├─ Step 2: verifyRequestBinding()      ← binding check
       ├─ Step 3: registerNonce()             ← replay protection (Redis)
       ├─ Step 4: checkAnomaly()              ← burst detection (Redis)
       ├─ Step 5: checkPolicy()              ← policy engine (Redis for RATE_LIMIT)
       ├─ [policy drift detection — informational]
       ├─ Step 5.5: request-side semantic inspection
       └─ _executeAI()                        ← invariant guard + provider call
            │                                    + output-side semantic inspection
            └─ Audit write (ALLOW, or BLOCK at each stage after Step 1)
```

All execution reaches the AI provider only if steps 1–5 all pass and the execution invariant guard clears.

---

## Pre-enforcement input guards

These run before artifact decoding. They never touch the artifact or enforcement pipeline. **Since none of these rejections — nor the artifact-decode rejections below, nor any Step 1 (`validateArtifact`) rejection — is written to the audit chain or the transparency log**: no caller is authenticated yet, so they are counted and sampled (`PREAUTH_REJECT`, `src/core/preauth/preAuthRejects.js`) instead. The "Audit stage" column below is the stage label on that sampled event.

| Check | Condition | HTTP | Reason | Sampled stage |
|---|---|---|---|---|
| Content-type | `Content-Type` is not `application/json` | 415 | — | — |
| Body structure | `req.body` is not a plain object | 400 | `INVALID_REQUEST_BODY` | `INPUT_GUARD` |
| Prompt present | `prompt` missing, empty, or not a string | 400 | `MISSING_PROMPT` | `INPUT_GUARD` |
| Prompt size | `prompt` exceeds 32 768 bytes | 400 | `PROMPT_TOO_LARGE` | `INPUT_GUARD` |

---

## Artifact decoding

Runs after input guards, before `validateBoundRequest`.

| Check | Condition | HTTP | Reason | Sampled stage |
|---|---|---|---|---|
| Header present | `x-qodiqa-artifact` header absent or empty | 200 | `MISSING_ARTIFACT` | `ARTIFACT_DECODE` |
| Header size | Header value exceeds 8 192 bytes | 413 | `ARTIFACT_TOO_LARGE` | `ARTIFACT_DECODE` |
| Base64 + JSON parse | Decode or parse fails | 200 | `ARTIFACT_DECODE_FAILED` | `ARTIFACT_DECODE` |
| Object type | Decoded value is not a plain object | 200 | `ARTIFACT_INVALID_TYPE` | `ARTIFACT_DECODE` |

With `QODIQA_BLOCK_HTTP_MODE=status` the 200s in this table become 400 (`src/api/blockHttpStatus.js`). `ARTIFACT_TOO_LARGE` is the only block reason in this table that returns HTTP 413 (its check runs before decoding, so the header's byte length is known without needing a body/decision envelope). **(2026-08-xx): every other policy/verification enforcement BLOCK — Layers 1/3/5/6c: policy engine, nonce/replay/anomaly, artifact/signature verification, semantic content inspection — returns HTTP 200**, not 403: `/ai/chat` has no bearer-token/RBAC layer of its own (that's Layer 2, gating `/sign` and `/admin/*` only), so there is no genuine "auth failure" reason to reserve 403 for, and the enforcement outcome (`decision:'BLOCK'`, no provider call) is unchanged — only the HTTP envelope. Matches `/verify`'s own always-200-for-a-pipeline-BLOCK contract. See `src/api/routes/aiChat.js`'s `_blockStatus()`/`IDEMPOTENCY_BLOCK_REASONS` (the only reasons that get a non-200 status here are the 3 idempotency-conflict reasons — see the Idempotency section below) for the exact, current mapping this table is describing.

---

## Step 1 — `validateArtifact()` (verification order as implemented)

**Source**: `src/validation/validateArtifact.js` (normative: `docs/protocol/QODIQA-PROTOCOL.md` §4; executable vectors `docs/protocol/vectors/qodiqa-protocol-vectors.json` → `verification`)
**On first failure**: returns `{ decision: 'BLOCK', reason, details }` — remaining checks do not run.

| # | Check | Reason on failure |
|---|---|---|
| 1 | Artifact is a plain object with exactly the keys `expiry`, `payload`, `publicKeyId`, `signature`, `timestamp`; none `undefined` | `INVALID_ARTIFACT` |
| 2 | `payload` is a plain object with no `undefined` at any depth | `INVALID_ARTIFACT` |
| 3 | `timestamp` and `expiry` are positive finite numbers (Unix ms; no `expiry > timestamp` check at verification) | `INVALID_ARTIFACT` |
| 4 | `signature` is a string (else `INVALID_ARTIFACT`) in canonical base64 of 64 bytes, `/^[A-Za-z0-9+/]{86}==$/` | `INVALID_SIGNATURE` |
| 5 | `publicKeyId` is a non-blank string | `INVALID_ARTIFACT` |
| 6 | Key resolves **and** the Ed25519 signature verifies over the raw 32-byte `SHA-256("QODIQA::ARTIFACT::V1" \|\| stableStringify({expiry, payload, publicKeyId, timestamp}))` — an unknown key is reported as `INVALID_SIGNATURE` (no key-existence oracle; `KEY_NOT_FOUND` is never emitted) | `INVALID_SIGNATURE` |
| 7 | `timestamp ≤ now + 5 000 ms` (`FUTURE_SKEW_MS`) | `FUTURE_TIMESTAMP` |
| 8 | `now < expiry` | `EXPIRED` |
| 9 | `now − timestamp ≤ 60 000 ms` (`MAX_SKEW_MS`) | `TIME_SKEW_EXCEEDED` |
| 10 | Key lifecycle: revoked / archived never verify; a deprecated key verifies only artifacts signed before its retirement and only for 65 s after it; control-plane snapshot stale → refused | `KEY_REVOKED`, `KEY_ARCHIVED`, `KEY_DEPRECATED`, `KEY_NOT_YET_ACTIVE`, `KEY_STATUS_UNKNOWN`, `CONTROL_PLANE_STALE` (503) |
| — | All checks pass | `{ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', … }` |

**Design notes:**
- Time checks run **after** signature verification, so a forged artifact always receives `INVALID_SIGNATURE` and learns nothing about the clock or the key store.
- **Every** Step 1 failure, lifecycle included, is treated as **pre-auth**: counted and sampled, not audited. Every BLOCK from Step 1b onward is audited.
- `payload` is validated only generically. `payload.callerContext` is covered by the signature; `validateBoundRequest.js` reads it back afterward.

**Audit stage on block**: `VALIDATION`

---

## Step 2 — `verifyRequestBinding()` (6 sequential checks)

**Source**: `src/validation/verifyRequestBinding.js`
**On first failure**: returns `{ bound: false, reason: 'REQUEST_MISMATCH', details: { issue: string } }`.

| # | Check | Details on failure |
|---|---|---|
| 1 | `artifact` and `artifact.payload` are plain objects | `{ issue: 'artifact or payload is not a plain object' }` |
| 2 | `artifact.payload.requestId` is a valid UUID v4 | `{ issue: 'missing or malformed requestId in artifact payload — must be a UUID v4' }` |
| 3 | `artifact.payload.requestHash` is a 64-char lowercase hex string | `{ issue: 'missing or malformed requestHash in artifact payload' }` |
| 4 | `request` is a plain object | `{ issue: 'request must be a plain object' }` |
| 5 | `computeRequestHash(method, path, body)` succeeds | `{ issue: 'request canonicalization failed: ...' }` |
| 6 | `crypto.timingSafeEqual(stored, recomputed)` is `true` | `{ issue: 'requestHash does not match actual request' }` |

Check 6 uses `crypto.timingSafeEqual` — not the `===` operator — to prevent timing side-channels.

On success: `{ bound: true, requestId: <uuid-v4> }`

**Audit stage on block**: `VALIDATION`

---

## Step 3 — `registerNonce()` (atomic replay protection)

**Source**: `src/validation/registerNonce.js` → `nonceStore.js` → Redis
**Operation**: atomic Lua `SET NX PX` on the tenant-scoped key `<tenantId>:qodiqa:req:v2:<requestId>` with TTL = `floor(expiry − now)`. Restart barrier: after a Redis restart, an artifact whose nonce cannot be proven unused is refused `REPLAY_STATE_UNPROVABLE`; production requires AOF.

| Check | Condition | Reason |
|---|---|---|
| `requestId` format | Not a valid UUID v4 | `MALFORMED_REQUEST_ID` |
| `expiryMs` format | Not a finite positive number | `INVALID_EXPIRY` |
| TTL pre-check | `expiryMs − now ≤ 0` | `EXPIRED` |
| Store call | Redis unavailable or I/O failure | `NONCE_STORE_ERROR` |
| Atomicity check | `requestId` already exists in store | `REPLAY_DETECTED` |
| Restart barrier | Redis restarted and the nonce cannot be proven unused | `REPLAY_STATE_UNPROVABLE` |

**`MALFORMED_REQUEST_ID` is defense-in-depth inside `registerNonce.js` itself — it is not reachable through this pipeline.** Step 2 (`verifyRequestBinding()`) already validates `requestId` format and returns `REQUEST_MISMATCH` before Step 3 ever runs, so `registerNonce()` is always called with an already-validated UUID v4 (`binding.requestId`). This mirrors `KEY_REVOKED` in Step 1: a reason the code defines but the documented pipeline never actually surfaces.6.

On `REPLAY_DETECTED`, the response includes `requestId` so the caller can record a replay linkage in the audit chain (`replayOf` field).
On all other failures, `requestId` is **not** included in the error response — binding may be untrustworthy.

Log event on replay: `NONCE_V2_REPLAY_DETECTED` (in `nonceStore.js`)

On success: `{ ok: true, requestId }`

**Audit stage on block**: `VALIDATION`

---

## Step 4 — `checkAnomaly()` (sliding-window burst detection)

**Source**: `src/validation/checkAnomaly.js` → `anomalyStore.js` → Redis
**Operation**: Lua-scripted sorted-set sliding window (atomic ZREMRANGEBYSCORE + ZADD + ZCARD per window)

Two windows checked in sequence. Per-key check runs first — if it blocks, the global counter is not incremented.

| Window | Key | Threshold | Block type |
|---|---|---|---|
| Per-key | `anomaly:v2:key:<publicKeyId>` | 100 events per 60 seconds | `SIGNATURE_BURST` |
| Global | `anomaly:v2:global` | 5 000 events per 60 seconds | `RATE_BURST` |
| Store error | — | — | `STORE_ERROR` |

**Log events:**
- `INFO ANOMALY_STATE_INCREMENTED` — emitted after each successful `store.record()`, includes `count`, `threshold`, `type`
- `WARN ANOMALY_THRESHOLD_EXCEEDED` — emitted when a window blocks, includes `publicKeyId`, `count`, `threshold`, `type`, `executionBlocked: true`
- `ERROR ANOMALY_STORE_UNAVAILABLE` — emitted when the store throws

On store error: fails closed with reason `ANOMALY_DETECTED`, type `STORE_ERROR`.

Return on block: `{ block: true, reason: 'ANOMALY_DETECTED', type: 'SIGNATURE_BURST' | 'RATE_BURST' | 'STORE_ERROR' }`
Return on pass: `{ block: false }`

**Audit stage on block**: `VALIDATION`

---

## Step 5 — `checkPolicy()` (policy engine)

**Source**: `src/validation/checkPolicy.js` → `services/policy/evaluatePolicyDecision.js` → `services/policy/engine.js` (`middleware/enforcePolicy.js` was removed in `4bae6188`)

The policy engine evaluates the request against the **live** policy set held in the control plane. Policies are evaluated in order. **First DENY wins.**

**Context fields passed to evaluators:**

| Field | Source |
|---|---|
| `artifact.valid` | `true` (validated upstream) |
| `userId` | `null` (not populated in default pipeline) |
| `callerId` | `artifact.payload.callerContext.callerId` — the authenticated caller identity `/sign` bound into the artifact; `null` for an artifact signed before this remediation shipped. `requireConsent`'s evaluator (`services/policy/evaluators/requireConsent.js`) prefers this over `userId`/`publicKeyId` as `actor_id` for consent lookups — a consent grant issued to one caller does not authorize a different caller sharing the same tenant signing key. |
| `action` | `artifact.payload.provider` |
| `ip` | Normalized client IP (`req.clientIp`); IPv4-mapped IPv6 addresses normalized (this is IP-format normalization, not log sanitization — see `docs/configuration/reference.md` §12 for log sanitization) |
| `timestamp` | `x-qodiqa-timestamp` header (Unix seconds), or `Math.floor(Date.now() / 1000)` if absent |

**Engine evaluation sequence:**

| # | Step | Failure reason |
|---|---|---|
| 1 | Validate context schema | `INVALID_CONTEXT` |
| 2 | Policy array is non-null, non-empty | `NO_POLICIES_LOADED` |
| 3 | At least one enabled policy | `NO_ENABLED_POLICIES` |
| 4 | Build rate-limit snapshot (parallel `store.getCount()`) | store error → count treated as `Infinity` (fail-closed) |
| 5 | For each enabled policy: resolve evaluator from registry | `EVALUATOR_MISSING` |
| 6 | For each enabled policy: call `evaluator.evaluate()` | `EVALUATOR_ERROR` if throws |
| 7 | Evaluator returns `pass !== true` | evaluator's `reason` string; falls back to `POLICY_BLOCKED` if evaluator provides none |
| 8 | All policies pass: commit rate-limit increments (best-effort) | — |

**Built-in evaluator types:**

| Type | Reason on block |
|---|---|
| `REQUIRE_CONSENT` | `CONSENT_MISSING`, `CONSENT_CONTEXT_INCOMPLETE`, `CONSENT_EVALUATION_ERROR`, or the registry's own reason (`CONSENT_NOT_FOUND`, `CONSENT_REVOKED`, `CONSENT_EXPIRED`, `CONSENT_SUSPENDED`, `CONSENT_NOT_ACTIVE`, `CONSENT_SCOPE_MISMATCH`, `CONSENT_STORE_UNAVAILABLE`) |
| `BLOCK_IP` | `IP_BLOCKED` or `IP_MISSING` |
| `TIME_WINDOW` | `OUTSIDE_TIME_WINDOW` or `TIMESTAMP_MISSING` |
| `RATE_LIMIT` | `RATE_LIMIT_EXCEEDED` or `RATE_LIMIT_KEY_MISSING` |

Log event on policy block: `WARN ANOMALY_POLICY_DENIAL` (emitted by `services/policy/evaluatePolicyDecision.js`)
Log event on rate limit block: `WARN POLICY_RATE_LIMIT_EXCEEDED` (emitted by `rateLimit.js`)

**Policy state errors** (not policy evaluation failures):

| Condition | Reason |
|---|---|
| `_getPolicies` or `_policyStore` are undefined | `POLICY_STATE_UNAVAILABLE` |
| `checkPolicy()` throws unexpectedly | `INTERNAL_ERROR` |

**Audit stage on block**: `POLICY_ENFORCEMENT` (policy denial) or `POLICY_CHECK` (state errors)

---

## Policy drift detection (informational)

After step 5 passes, the route compares the live policy hash to `artifact.payload.policyHash`:

```javascript
if (!policyHashesEqual(artifact.payload.policyHash, livePolicyHash)) {
  emit('WARN', 'POLICY_DRIFT_DETECTED', { ... })
}
```

`POLICY_DRIFT_DETECTED` is a WARN event only. It does **not** block execution. It records that the policy set active at signing time differs from the live policy set at execution time. This is expected when policy changes through the policy API (or a control-plane reload) between signing and execution.

---

## Step 5.5 — Semantic Policy Engine

**Source**: `src/core/semantic/index.js` (`runSemanticPolicyEngine()`), invoked from `_runSemanticCheck()` in `src/api/routes/aiChat.js`, identically on the streaming and non-streaming paths.

Runs after the (non-semantic) policy engine and before the execution invariant guard / provider dispatch. It is deterministic in the prompt text and independent of the provider the artifact names, but it is **not** a pure synchronous function: the embedding gates (anchors · head · v9 · v5 · FT-3) run local ONNX inference asynchronously on an inference pool, under a per-tenant classification budget and size caps. The same request-side pipeline runs in `POST /verify`. Output-side inspection runs on the provider response.

Classifiers each independently score the prompt; the highest weighted score selects one of four tiers (`src/core/semantic/scoring/confidence.js`):

| Tier | Threshold (default) |
|---|---|
| `ALLOW` | score < `WARN` (0.35) |
| `WARN` | `WARN` ≤ score < `REVIEW` (0.55) |
| `REVIEW` | `REVIEW` ≤ score < `DENY` (0.55–0.70) |
| `DENY` | score ≥ `DENY` (0.70) |

**Enforcement** (`src/core/semantic/policies/semanticActions.js`, `resolveAction()`) — every tier has explicit, deterministic behavior; none fall through a DENY-only check:

| Tier | Blocks execution? | Configurable? |
|---|---|---|
| `ALLOW` | Never | No |
| `WARN` | No, by default (advisory) | `QODIQA_SEMANTIC_WARN_BLOCKS=true` opts in to blocking |
| `REVIEW` | Yes, by default | `QODIQA_SEMANTIC_REVIEW_BLOCKS=false` opts out |
| `DENY` | Always | No — not configurable under any env var |

When the resolved action blocks, the request is denied with the same `_writeAuditBlock()` path (stage `SEMANTIC_POLICY`) used by every other enforcement failure, and the provider is never reached. When it does not block, the full semantic evidence (decision, score, matched classifiers) is still attached to the `ALLOW` audit entry's `executionContext.semantic` — every decision is recorded, not only blocking ones.

---

## Provider execution

### Execution invariant guard

**Source**: `services/execution-guard.js`

Before any provider call, `assertExecutionInvariant(verifiedCtx)` verifies the frozen context object:

| Field | Requirement |
|---|---|
| `verifiedCtx` | Plain object (not null, not array) |
| `verifiedCtx.verified` | Strictly `=== true` |
| `verifiedCtx.requestHash` | String matching `/^[a-f0-9]{64}$/` |
| `verifiedCtx.artifactId` | Non-empty string |

**On violation:**
1. Increments a module-global violation counter (persistent for process lifetime)
2. Emits `CRITICAL EXECUTION_INVARIANT_VIOLATED` to stderr **before** throwing — the log line is never suppressed even if the caller catches the error
3. Throws `Error('UNVERIFIED_EXECUTION_ATTEMPT')`

The guard runs on every invocation of `executeProviderCall()`. It is a second enforcement layer inside the same process: it rejects any dispatch that does not carry a valid execution token minted after enforcement, and `_executeAI()` is module-private. It does **not** defend against modified gateway code (anyone who can change the gateway can change the guard), and a test-only provider-injection seam (`_providerFn`) exists that is not wired in production.

### Provider dispatch

**Source**: `services/execution.js`

```javascript
executeProviderCall(provider, body, verifiedCtx, traceMeta)
```

1. Assert invariant (above)
2. `resolveProvider(provider)` (`services/providers.js`) is a boolean existence check against the registered provider names (`openai`, `anthropic`, `gemini`, `mistral`, `llama`, `local`)
   - Returns `false` → throw `Error('PROVIDER_UNAVAILABLE')` → HTTP 503
3. `routeProviderCall()` (`services/providers/router.js`) performs the actual dispatch: it re-checks the provider is enabled (throws `PROVIDER_NOT_CONFIGURED` if not), calls the provider's handler with `{ requestId, requestHash, policyHash, tenantId }` (enforcement internals such as the artifact signature and nonce state are not exposed), and — on a retryable failure (`PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_TIMEOUT`, `PROVIDER_CIRCUIT_OPEN`, `PROVIDER_HEALTH_DEGRADED`) — attempts one failover hop to the provider named in `PROVIDER_FAILOVER_<NAME>`, if configured and only after identity, provider scope and consent re-pass for the target. The executing provider is recorded in the unhashed `executionContext` (hash-protecting it is audit schema v7, design decision D4). See [Provider architecture](../../README.md) in the README for the full routing/failover contract.

**Provider error HTTP mapping** (`_providerStatus()` in `src/api/routes/aiChat.js`):

| Reason | HTTP |
|---|---|
| `MISSING_PROVIDER`, `PROVIDER_MODEL_NOT_ALLOWED`, `PROVIDER_INVALID_REQUEST`, `PROVIDER_REQUEST_REJECTED` | 400 |
| `PROVIDER_RESPONSE_INVALID` (route-level: adapter returned a response without a string `output`) | 502 |
| `PROVIDER_TIMEOUT`, `REQUEST_TIMEOUT` | 504 |
| `PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_AUTH_FAILED`, `AUDIT_PERSISTENCE_FAILED` | 503 |
| other (including `PROVIDER_NOT_CONFIGURED`, `PROVIDER_CONFIG_INVALID`, and the adapter-level `PROVIDER_INVALID_RESPONSE` thrown directly by a provider handler) | 500 |

Note the two similarly-named but distinct response-shape codes: `PROVIDER_INVALID_RESPONSE` is thrown by an individual provider adapter (`services/providers/*.js`, via `normalize.js`'s `buildResponse()`) when the raw upstream payload has no usable text output; `PROVIDER_RESPONSE_INVALID` is a redundant, route-level check in `aiChat.js` that fires only if a normalized `ProviderResponse` somehow still lacks a string `output` after passing adapter validation. In practice only the former is expected to occur.

**Audit stage on block**: `PROVIDER_EXECUTION`

---

## Audit writes

Every decision after Step 1 (artifact validation) — EXECUTE or BLOCK — is appended to the audit chain (schema v6, 21 hashed fields; see `docs/protocol/QODIQA-PROTOCOL.md` §9) via `appendMandatory()` (`src/core/audit/audit-log.js`), which retries a small, bounded number of transient filesystem failures before giving up. This write is **mandatory**, not best-effort: the audit chain is the platform's evidence-first source of truth, and it must never be silently bypassed.

**On BLOCK** (at each stage):
- `_writeAuditBlock()` records `decision: 'BLOCK'` with `stage`, `reason`, `artifactId`, `requestHash`, `signature`, `policyHash`
- Log event on success: `INFO AUDIT_BLOCK_RECORDED`
- Log event if `appendMandatory()` still fails after retries: `CRITICAL AUDIT_APPEND_FAILED` — the response is still the BLOCK (200 by default; there is no "more blocked" to fail closed to), but the missing evidence is escalated loudly rather than a routine `ERROR` line, since a block with no audit trail is a forensics gap.

**On EXECUTE:**
- The audit write records `decision: 'ALLOW'` with full execution trace including `provider`, `requestHash`, `policyHash`, `verificationResult: true`
- Log event on success: `INFO AUDIT_EXECUTION_RECORDED`
- **Fail-closed on failure**: if `appendMandatory()` still fails after retries, the route does NOT return `200 EXECUTE` — it throws `AUDIT_PERSISTENCE_FAILED`, which the route handler turns into `503 { decision: "BLOCK", reason: "AUDIT_PERSISTENCE_FAILED" }`. The AI provider has already been called by this point and its response is discarded, never returned to the caller — QODIQA never reports success while silently losing required audit evidence. Log event: `CRITICAL AUDIT_APPEND_FAILED`.

**On the streaming path** (`POST /ai/chat/stream`): the audit write happens after the stream completes. chunks are released only after output-side inspection (check-then-release), but no INTENT / STREAM_OPENED entry precedes delivery, so released content is not withheld if the final audit write fails. `_writeAuditStreamRecord()` still retries via `appendMandatory()` and escalates to `CRITICAL STREAM_AUDIT_FAILED` on exhaustion.

**Audit stages:**

| Stage | Set when |
|---|---|
| `INPUT_GUARD` | Body/prompt validation failure — sampled pre-auth event only, not an audit entry |
| `ARTIFACT_DECODE` | Header decode failure — sampled pre-auth event only |
| `VALIDATION` | Steps 1–4 failure (Step 1 failures: sampled pre-auth event only) |
| `POLICY_CHECK` | `POLICY_STATE_UNAVAILABLE` or `INTERNAL_ERROR` |
| `POLICY_ENFORCEMENT` | Policy engine BLOCK |
| `SEMANTIC_POLICY` | Semantic Policy Engine tier resolved to a blocking action (see Step 5.5) |
| `PROVIDER_EXECUTION` | Provider error, or successful ALLOW/EXECUTE |

**Optional secondary persistence**: when `QODIQA_PG_ENABLED=true`, the audit entry is additionally dual-written to PostgreSQL and triggers an evidence-chain record (`src/infra/postgres/pg-audit-backend.js`). Unlike the file-based chain above, these are non-blocking — a retryable failure is durably queued via the Persistence Recovery Queue (`AUDIT_CHAIN_PG_SAVE` / `EVIDENCE_CHAIN_SAVE`) rather than dropped, but it does not affect the HTTP response either way. See `docs/operations/postgresql-failure.md` §3.4.

**Continuous integrity verification**: a write's own commit-time validation (the hash chain built by `appendMandatory()` above) proves the chain was correctly extended *at write time*. It does not, by itself, protect against the durable file or table being tampered with afterward, or against the two stores above silently drifting apart over time. The live audit chain verifier (`src/core/audit/verifier/`) runs continuously in the background — independent of the request path, adding no latency to any write — periodically re-walking the chain (incrementally, and less frequently in full) and, when dual-write is enabled, periodically re-comparing the file chain against its PostgreSQL mirror. the file ↔ PostgreSQL comparison is a layered divergence verifier (migration 074) plus a 6-hourly row-counter reconciliation that alerts on drift and never auto-repairs (S4, OD-5). Decision Update and `docs/operations/audit-chain-integrity-verification.md` for what it checks and how to interpret a finding. The independent offline verifier is `scripts/audit-repro/verify/qodiqa-audit-verify.js`.

---

## Transparency log writes

Every audited decision — EXECUTE or BLOCK, streaming or non-streaming — is also registered as a leaf in the RFC 6962 Merkle transparency log, immediately after (and using evidence from) the audit write above. This is the same append API (`registrar.register()`, `src/core/transparency/registrar.js`) certification and attestation flows already use — see `src/core/transparency/enforcementBridge.js`'s `registerEnforcementDecision()`, called from `_writeAuditBlock()` and the ALLOW path of `_enforceAndExecute()` in `aiChat.js`, and from `_writeAuditStreamRecord()` in `src/streaming/streamEnforcer.js`.

**Leaf payload** (`entryType: 'AUDIT'`) contains only immutable verification evidence — request ID, artifact hash, a signature reference (a hash of the signature, not the raw bytes), decision, policy hash, semantic evidence (decision/score/matched classifiers, never raw prompt text), timestamp, key identifier, a reference to the corresponding audit chain entry (`auditEntryHash`), provider, and tenant. It never contains prompt text, raw signature bytes, API keys, or other secrets/customer payloads.

**Failure handling** mirrors the audit chain's own ALLOW/BLOCK asymmetry documented above:
- **On BLOCK**: registration is attempted regardless of whether the preceding audit write succeeded. A failure is escalated as `CRITICAL TRANSPARENCY_APPEND_FAILED` but never changes the already-decided BLOCK response — there is no "more blocked" to fail closed to.
- **On EXECUTE**: registration is mandatory and fail-closed, exactly like the audit write it follows. A failure throws `TRANSPARENCY_PERSISTENCE_FAILED`, which the route handler maps to `503` — the AI provider's response is discarded and never returned to the caller, so a request is never reported as successful without durable transparency evidence for that same decision.

**Evidence in the response**: a successful `200 EXECUTE` response includes a `transparency` object — `transparencyId`, `entryHash`, `leafHash` (the RFC 6962 leaf hash of `entryHash`), `signerKeyId`, `persisted`, and `inclusionProofRef` (a link to `GET /transparency/proof/:transparencyId`). `merkleRoot`, `treeSize`, and `signedTreeHeadRef` are `null` until a root is generated covering this entry (roots are generated automatically every `TRANSPARENCY_ROOT_INTERVAL_MS`, default 60 s, or on demand — not synchronously with the request); once generated, the inclusion proof becomes available at the referenced endpoint.

---

## Complete decision table

**:** the HTTP status column below is now sourced
from `src/errors/catalog.js`, the single machine-readable source of truth
for this vocabulary (previously this table, `docs/operations/troubleshooting.md`'s own
table, and `src/reasons.js` were three independent, occasionally-drifting
copies — see `src/errors/__tests__/catalog.governance.test.js`, which now
fails the build if they disagree). The Source step / Audit stage columns
here are pipeline-provenance detail the catalog doesn't carry and remain
this table's own contribution.

**correction:** the "single source of truth" itself
had gone stale — `src/errors/catalog.js`'s `httpStatus` field for every
Artifact-decode/Step-1..5/Semantic-Policy-Engine reason below still said
`403`, unchanged since before the remediation moved every one of these
to `200` in the real route code (`src/api/routes/aiChat.js`'s
`_blockStatus()`, `src/api/routes/verify.js`'s literal `res.status(200)`
calls). Nothing in the application reads `catalog.js`'s `httpStatus` field
to set an actual response (confirmed: `src/reasons.js` is its only consumer,
and it only derives the reason-code string list, never the status) —
`catalog.governance.test.js` checks internal consistency and cross-file
references, not agreement with real route behavior, so this drift was
never caught by CI. Both `catalog.js` and this table are corrected together
here; `consent`-category reasons (`CONSENT_NOT_FOUND`, `CONSENT_REVOKED`,
etc. — a *different* route, `/consent/verify`, which still genuinely
returns 403) were verified unaffected and left untouched, as was
`BYPASS_ATTEMPT` (no confirmed production call site).

**note:** "HTTP" is the default (`QODIQA_BLOCK_HTTP_MODE=decision`). With `QODIQA_BLOCK_HTTP_MODE=status` every 200 BLOCK below takes its class status from `src/api/blockHttpStatus.js` (artifact malformed 400; artifact invalid / binding / anomaly / consent / policy / semantics 403; replay 409; `RATE_LIMIT_EXCEEDED` 429; dependency unavailable 503; internal 500). Rows whose stage is `INPUT_GUARD` / `ARTIFACT_DECODE`, and every Step 1 row, are pre-auth: sampled, not audited.

| Reason | HTTP | Source step | Audit stage |
|---|---|---|---|
| `INVALID_REQUEST_BODY` | 400 | Input guard | `INPUT_GUARD` |
| `MISSING_PROMPT` | 400 | Input guard | `INPUT_GUARD` |
| `PROMPT_TOO_LARGE` | 400 | Input guard | `INPUT_GUARD` |
| `MISSING_ARTIFACT` | 200 | Artifact decode | `ARTIFACT_DECODE` |
| `ARTIFACT_TOO_LARGE` | **413** | Artifact decode | `ARTIFACT_DECODE` |
| `ARTIFACT_DECODE_FAILED` | 200 | Artifact decode | `ARTIFACT_DECODE` |
| `ARTIFACT_INVALID_TYPE` | 200 | Artifact decode | `ARTIFACT_DECODE` |
| `INVALID_ARTIFACT` | 200 | Step 1 (validateArtifact) | `VALIDATION` |
| `INVALID_SIGNATURE` | 200 | Step 1 | `VALIDATION` |
| `KEY_REVOKED`, `KEY_ARCHIVED`, `KEY_DEPRECATED`, `KEY_NOT_YET_ACTIVE`, `KEY_STATUS_UNKNOWN` (`KEY_NOT_FOUND` is never emitted — unknown keys are `INVALID_SIGNATURE`) | 200 | Step 1 (lifecycle, after signature) | `VALIDATION` (pre-auth, sampled) |
| `CONTROL_PLANE_STALE` | 503 | Step 1 / control plane | `VALIDATION` |
| `FUTURE_TIMESTAMP` | 200 | Step 1 | `VALIDATION` |
| `EXPIRED` | 200 | Step 1 | `VALIDATION` |
| `TIME_SKEW_EXCEEDED` | 200 | Step 1 | `VALIDATION` |
| `REQUEST_MISMATCH` | 200 | Step 2 (verifyRequestBinding) | `VALIDATION` |
| `INVALID_EXPIRY` | 200 | Step 3 | `VALIDATION` |
| `NONCE_STORE_ERROR` | 200 | Step 3 | `VALIDATION` |
| `REPLAY_DETECTED` | 200 | Step 3 | `VALIDATION` |
| `REPLAY_STATE_UNPROVABLE` | 200 | Step 3 (restart barrier) | `VALIDATION` |
| `ANOMALY_DETECTED` | 200 | Step 4 (checkAnomaly) | `VALIDATION` |
| `POLICY_STATE_UNAVAILABLE` | 200 | Step 5 (pre-check) | `POLICY_CHECK` |
| `INTERNAL_ERROR` | 200 | Step 5 (exception) | `POLICY_CHECK` |
| `INVALID_CONTEXT` | 200 | Step 5 (policy engine) | `POLICY_ENFORCEMENT` |
| `NO_POLICIES_LOADED` | 200 | Step 5 | `POLICY_ENFORCEMENT` |
| `NO_ENABLED_POLICIES` | 200 | Step 5 | `POLICY_ENFORCEMENT` |
| `EVALUATOR_MISSING` | 200 | Step 5 | `POLICY_ENFORCEMENT` |
| `EVALUATOR_ERROR` | 200 | Step 5 | `POLICY_ENFORCEMENT` |
| `CONSENT_MISSING` and the other `CONSENT_*` reasons listed under Step 5 | 200 | Step 5 (`REQUIRE_CONSENT`) | `POLICY_ENFORCEMENT` |
| `IP_BLOCKED` | 200 | Step 5 (`BLOCK_IP`) | `POLICY_ENFORCEMENT` |
| `OUTSIDE_TIME_WINDOW` | 200 | Step 5 (`TIME_WINDOW`) | `POLICY_ENFORCEMENT` |
| `RATE_LIMIT_EXCEEDED` | 200 | Step 5 (`RATE_LIMIT`) | `POLICY_ENFORCEMENT` |
| `RATE_LIMITED` (per-identity limiter), `CLASSIFICATION_BUDGET_EXHAUSTED` | 429 | Throttles | — |
| `POLICY_BLOCKED` | 200 | Step 5 (evaluator fallback) | `POLICY_ENFORCEMENT` |
| Any `SEMANTIC_REASONS` value (e.g. `SECURITY_OVERRIDE_ATTEMPT`, `CREDENTIAL_EXTRACTION`, `JAILBREAK_ATTEMPT`, …) | 200 | Step 5.5 (Semantic Policy Engine) — `DENY` always, `REVIEW` by default, `WARN` only if `QODIQA_SEMANTIC_WARN_BLOCKS=true` | `SEMANTIC_POLICY` |
| `MISSING_PROVIDER`, `PROVIDER_MODEL_NOT_ALLOWED`, `PROVIDER_INVALID_REQUEST`, `PROVIDER_REQUEST_REJECTED` | 400 | Provider execution | `PROVIDER_EXECUTION` |
| `PROVIDER_RESPONSE_INVALID` | 502 | Provider execution | `PROVIDER_EXECUTION` |
| `PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_AUTH_FAILED`, `AUDIT_PERSISTENCE_FAILED`, `TRANSPARENCY_PERSISTENCE_FAILED` | 503 | Provider execution / evidence write | `PROVIDER_EXECUTION` |
| `PROVIDER_TIMEOUT`, `REQUEST_TIMEOUT` | 504 | Provider execution | `PROVIDER_EXECUTION` |
| `PROVIDER_NOT_CONFIGURED`, `PROVIDER_CONFIG_INVALID`, `PROVIDER_INVALID_RESPONSE` (adapter-level) | 500 | Provider execution | `PROVIDER_EXECUTION` |
| `ALL_CHECKS_PASSED` | **200** | Full pipeline pass | — (EXECUTE) |

---

## Canonical reason vocabulary

**:** `src/reasons.js` now derives its `REASONS`
export directly from `src/errors/catalog.js` — see that file for the
complete, current, machine-readable vocabulary (every code's HTTP status,
description, pipeline category, and retry guidance in one place), rather
than the hand-transcribed code list this section used to duplicate here.

`MALFORMED_REQUEST_ID` is a real string defined in `registerNonce.js`, but
is never actually emitted through this pipeline and is intentionally
excluded from the catalog for that reason. `KEY_REVOKED` is different: it
IS in the catalog and,'s key-lifecycle check, IS emitted (a revoked
key's verified artifact). `KEY_NOT_FOUND` is in the catalog but is not
emitted by `/ai/chat` (unknown keys are `INVALID_SIGNATURE`). See the
note under Step 3 for more on `MALFORMED_REQUEST_ID`.

---

## See also

- `docs/guides/quickstart.md` — setup and first run
- `docs/architecture/overview.md` — component topology and interaction
- `docs/guides/providers.md` — full AI provider reference (registry, failover, streaming, per-provider capabilities)
- `docs/architecture/verification-flow.md` — dry-run verification pipeline and endpoint differences
- `docs/operations/troubleshooting.md` — diagnosis and resolution for each failure mode
- `docs/operations/runbook.md` — key rotation, policy reload, graceful shutdown
- `docs/protocol/QODIQA-PROTOCOL.md` — normative protocol spec and test vectors
- `docs/api/openapi.json` — the generated HTTP contract
