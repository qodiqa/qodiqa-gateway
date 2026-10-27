# ARCHITECTURE OVERVIEW

This document describes how QODIQA's components interact to enforce the invariant:
**no AI execution without a valid, non-replayed, policy-permitted authorization artifact**.

**Related documents:**
- `docs/security/cryptography.md` — cryptographic algorithm details and rationale
- `docs/api/overview.md` — complete API endpoint reference
- `docs/configuration/reference.md` — all environment variables
- `docs/architecture/enforcement-flow.md` — per-step enforcement pipeline with reason codes
- `docs/glossary.md` — term definitions

---

## Core invariant

Every `POST /ai/chat` request must carry an `x-qodiqa-artifact` header containing a base64-encoded, Ed25519-signed authorization artifact. No execution bypass path exists — the provider call layer independently asserts this invariant before any provider dispatch begins.

---

## Component topology

```
Client
  │
  │  POST /ai/chat
  │  x-qodiqa-artifact: <base64>
  ▼
┌─────────────────────────────────────────────────────────────────┐
│  QODIQA Gateway (Express, composed in src/app.js)                │
│                                                                 │
│  ┌────────────────┐    ┌──────────────────────────────────┐    │
│  │  /sign         │    │  /ai/chat                        │    │
│  │  (artifact     │    │  (enforcement + execution)       │    │
│  │   minting)     │    │                                  │    │
│  └────────┬───────┘    └────────────────┬─────────────────┘    │
│           │                             │                        │
│    ┌──────▼──────┐              ┌───────▼────────┐             │
│    │ Key Manager │              │ validateBound  │             │
│    │ (Ed25519    │              │ Request        │             │
│    │  signing)   │              │ (4-step valid) │             │
│    └─────────────┘              └───────┬────────┘             │
│                                         │                        │
│                                  ┌──────▼──────┐               │
│                                  │Policy Engine│               │
│                                  │(evaluators) │               │
│                                  └──────┬──────┘               │
│                                         │                        │
│                                  ┌──────▼──────┐               │
│                                  │ Execution   │               │
│                                  │ Guard +     │               │
│                                  │ Provider    │               │
│                                  └──────┬──────┘               │
│                                         │                        │
│                    ┌────────────────────▼──────────────────┐   │
│                    │  Audit Chain (append-only, hash-chain) │   │
│                    └───────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  Nonce Store │  │Anomaly Store │  │ Rate-Limit Store     │ │
│  │  (Redis)     │  │(Redis)       │  │ (Redis)              │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Signing flow (`POST /sign`)

The `/sign` endpoint creates authorization artifacts. It is authenticated by an individually-issued, individually-revocable signing API key (`Authorization: Bearer sk_...`, resolved via `src/core/signing/signingIdentityStore.js` — ; there is no shared secret) and is the only path through which private key material is accessed.

**Signing produces an artifact envelope:**

1. Generate `requestId` — UUID v4, 128-bit random nonce (`generateRequestId()`)
2. Compute `requestHash` — `SHA-256("QODIQA::REQUEST::V1" || stableStringify({method, path, body}))`, 64-char hex
3. Inject `requestHash`, `requestId`, and `callerContext` into the payload object
4. Construct envelope: `{ expiry, payload, publicKeyId, timestamp }`
5. Compute signing hash: `SHA-256("QODIQA::ARTIFACT::V1" || stableStringify({expiry, payload, publicKeyId, timestamp}))`
6. Sign with Ed25519 private key → 64-byte signature, base64-encoded
7. Return frozen artifact: `{ expiry, payload, publicKeyId, signature, timestamp }`

Both `requestHash` and `requestId` are inside the signed payload. Any post-signing modification to any field in the envelope invalidates the signature. `callerContext` is likewise inside `payload`, so it is protected by the same signature with no additional cryptographic primitive — this is what lets the audit chain and evidence exports *record* which authenticated caller requested a signature, not merely which shared tenant key (`publicKeyId`) produced it. **Trust model:** the artifact is signed by the gateway's own key after bearer-key authentication; the caller never signs. Caller attribution therefore rests on the gateway's API-key authentication and the operator's own systems, not on caller-held cryptography, and it is evidence against the operator only together with the witness-co-signed, customer-held checkpoint anchors (`docs/security/audit-anchoring.md`). See `docs/protocol/QODIQA-PROTOCOL.md` (normative), the superseded §11.3.1 (historical).

**Artifact transmission**: The client JSON-serializes the `artifact` object and base64-encodes it before sending as the `x-qodiqa-artifact` header.

```javascript
const encoded = Buffer.from(JSON.stringify(artifact), 'utf8').toString('base64');
```

---

## Enforcement pipeline (`POST /ai/chat`)

After decoding the artifact from the header, the route calls `_enforceAndExecute()` or
`_enforceAndStream()` depending on whether `stream: true` was requested. Both functions
invoke the shared `_runEnforcementPipeline()` (Steps 1–5) and diverge only at Step 6:
execute vs. stream. This is the only production path to provider execution: every provider alias resolves to this one pipeline, the provider is fixed at `/sign` under the identity's provider scope and re-checked here (`SCOPE_PROVIDER_DENIED`), and a failover hop is re-authorised for identity, scope and consent before it runs. The `_providerFn` parameter is a test seam that `src/app.js` never passes.

### `validateBoundRequest()` (4 sequential steps)

**Step 1: Artifact signature verification** (`validateArtifact.js`)

- Strict schema check: exactly 5 fields (`expiry`, `payload`, `publicKeyId`, `signature`, `timestamp`)
- No extra fields allowed
- Resolve `publicKeyId` to a non-revoked key (`resolveKey()`)
- Timestamp checks (after signature verification): `FUTURE_TIMESTAMP` (more than 5 000 ms ahead, `FUTURE_SKEW_MS`), `EXPIRED` (`now >= expiry`), `TIME_SKEW_EXCEEDED` (backward drift > 60 000 ms); then the key-lifecycle check. Normative order: `docs/protocol/QODIQA-PROTOCOL.md` §4.
- Verify Ed25519 signature over the envelope hash — `INVALID_SIGNATURE` if mismatch
- Skew check runs after signature verification so forged artifacts cannot probe timing via `TIME_SKEW_EXCEEDED`

**Step 2: Request binding** (`verifyRequestBinding.js`)

- Extract `requestId` (UUID v4) and `requestHash` (64-char hex) from `artifact.payload`
- Recompute `requestHash` over the actual incoming request (`{method, path, body}`)
- Timing-safe compare (`crypto.timingSafeEqual`) — `REQUEST_MISMATCH` if different
- Guarantees the artifact was signed for exactly this request, not a different one

**Step 3: Nonce registration** (`registerNonce.js` → `nonceStore.js` → Redis)

- Atomic `SET NX PX` on key `<tenantId>:qodiqa:req:v2:<requestId>` (the tenant prefix is omitted only for keys without a tenant) with TTL = `expiry − now`
- If key already exists: `REPLAY_DETECTED` (log event: `NONCE_V2_REPLAY_DETECTED`)
- If store unavailable: `NONCE_STORE_ERROR` — **fail-closed, no fallback**
- Replay protection requires Redis with durable persistence (AOF `appendonly yes`, `appendfsync everysec`)

**Step 4: Anomaly detection** (`checkAnomaly.js` → `anomalyStore.js` → Redis)

- Two independent sliding-window counters (Lua script: atomic ZREMRANGEBYSCORE + ZADD + ZCARD):
  - Per-key window: key `anomaly:v2:key:<publicKeyId>`, threshold 100 events per 60 seconds
  - Global window: key `anomaly:v2:global`, threshold 5 000 events per 60 seconds
- Per-key check runs first. If it blocks (`SIGNATURE_BURST`), global counter is not incremented
- If store unavailable: `ANOMALY_STORE_UNAVAILABLE` log event, reason `ANOMALY_DETECTED` type `STORE_ERROR` — **fail-closed, no fallback**
- Log events: `ANOMALY_STATE_INCREMENTED` (INFO) on every request, `ANOMALY_THRESHOLD_EXCEEDED` (WARN) on block

**Why this order?**

Nonce registration (step 3) happens after signature and binding checks. This prevents nonce-pollution: a structurally invalid request cannot permanently burn a valid `requestId`. Only a fully valid, correctly signed, correctly bound artifact consumes a nonce.

Anomaly detection (step 4) runs after nonce registration so that replay attempts do not consume anomaly quota — only genuinely novel requests increment the anomaly counters.

---

### Policy engine (`checkPolicy.js` → `enforcePolicy.js` → `engine.js`)

The policy engine evaluates the request against the live policy set. Policies are evaluated in the order of the enforced policy set — the engine iterates enabled policies sequentially; **first DENY wins**.

**Evaluation sequence:**

1. Validate the context object schema
2. Guard: fail if no policies loaded (`NO_POLICIES_LOADED`) or all disabled (`NO_ENABLED_POLICIES`)
3. Build rate-limit snapshot: read all rate-limit counters in parallel from Redis before evaluation begins
4. Evaluate each enabled policy in order:
   - Look up evaluator by `policy.type` in the evaluator registry
   - Call `evaluator.evaluate(context, config, stateSnapshot)`
   - If the evaluator returns anything other than `pass: true` → immediately return BLOCK with the evaluator's reason string
   - `POLICY_BLOCKED` is used only as a fallback if the evaluator returns no reason string
5. All policies passed: commit rate-limit increments (best-effort; failure here does not retroactively change an EXECUTE)

**Policy evaluator types:**

| Type | Reason on block | Description |
|---|---|---|
| `REQUIRE_CONSENT` | `CONSENT_MISSING` | Requires `artifact.valid === true` |
| `BLOCK_IP` | `IP_BLOCKED` | CIDR and exact IP matching |
| `TIME_WINDOW` | `OUTSIDE_TIME_WINDOW` | UTC time-of-day windows |
| `RATE_LIMIT` | `RATE_LIMIT_EXCEEDED` | Per-key sliding window via Redis |

The context field `timestamp` used by `TIME_WINDOW` is always the server clock (Unix seconds). It is never taken from a request header or from the artifact.

**Policy context fields:**

```javascript
{
  artifact:  { valid: boolean },
  userId:    string | null,
  action:    string | null,   // artifact.payload.provider
  ip:        string,          // normalized client IP (resolveClientIp() — not related to log sanitization)
  timestamp: number,          // Unix seconds
}
```

**Policy drift detection**: After policy evaluation, the engine compares the live policy hash to `artifact.payload.policyHash` (which records the policy set active at signing time). A mismatch emits a WARN event but does not block execution — the runtime always enforces the live policy set.

**Policy governance**: this evaluation path is unaffected by the maker-checker layer — it always reads the enforced policy set derived from the control plane (`src/core/policy/store.js` `enforcedPolicies()`; PostgreSQL in production) — `POLICY_FILE` / `policies.json` is import-only and is never re-read on SIGHUP. What changed is *how a change reaches* that set: `src/core/policy/store.js`'s mutators are no longer called directly by any admin route except the governance workflow's `publish()` step, which requires independent review/approval by a different individual than the author. See `docs/guides/policy-governance.md`.

---

### Provider execution

**Execution invariant guard** (`execution-guard.js`):

Before any provider call, `assertExecutionInvariant(verifiedCtx)` verifies:
- `verifiedCtx` is a plain object
- `verifiedCtx.verified === true`
- `verifiedCtx.requestHash` is a valid 64-char hex string
- `verifiedCtx.artifactId` is a non-empty string

Violation: emits `EXECUTION_INVARIANT_VIOLATED` at CRITICAL level to stderr (before throwing), then throws `UNVERIFIED_EXECUTION_ATTEMPT`. This guard runs on every provider call as a second independent defense layer. The `_executeAI()` function is module-private — unreachable from outside `aiChat.js`.

**Provider call** (`execution.js`):

- `executeProviderCall(provider, body, verifiedCtx, traceMeta)` — single exported function; asserts the execution invariant first, then dispatches
- `resolveProvider(provider)` (`services/providers.js`) is an existence check only — it returns `true`/`false` for whether `provider` is a registered name (`openai`, `anthropic`, `gemini`, `mistral`, `llama`, `local`). It throws `PROVIDER_UNAVAILABLE` before routing if the name is unknown, but does not itself dispatch to a handler.
- Actual dispatch, per-provider enablement checks, and failover happen in `routeProviderCall()` (`services/providers/router.js`) — see [Provider architecture](../../README.md) in the README for the full routing/failover contract.
- The provider handler receives `{ requestId, requestHash, policyHash, tenantId }` — enforcement internals (artifact signature, nonce, anomaly state) are not exposed

---

## Key management

**Storage**: On-disk file at `QODIQA_KEYS_PATH` (env) or `data/keys.json` (default). Private key material is encrypted with AES-256-GCM using the `QODIQA_KEY_ENCRYPTION_KEY` (256-bit, 64 hex characters).

**Key identifier format**: `<clientId>:key_v<version>` — example: `my-local-dev:key_v1`

**Key lifecycle:**

```
  generate → active (signing + verification)
                 │
                 ├── rotate() / rotateAsync()  [`opts.mode` is required: 'emergency' or 'graceful'; there is no default]
                 │        ▼
                 │   revoked (no verification — KEY_REVOKED / INVALID_SIGNATURE)
                 │
                 └── rotateKeyGracefully() / rotateKeyGracefullyAsync()  [explicit opt-in only]
                          ▼
                    deprecated (verifies only pre-retirement artifacts, ≤65 s; purge-eligible after 180 days)
                          │
                          │ revoke()
                          ▼
                    revoked (no verification — KEY_REVOKED / INVALID_SIGNATURE)
```

- **Rotation thresholds** (WARN only, startup continues): `KEY_EXPIRING_SOON` < 30 days to `expiresAt`; `KEY_ROTATION_OVERDUE` > 90 days since creation
- **Hard expiry**: If an active key's `expiresAt` has passed at startup, `KEY_EXPIRED_STARTUP` is emitted per key and `KEY_MANAGER_STARTUP_FAILED` causes immediate exit — no grace period
- **Emergency-mode rotation (`{ mode: 'emergency' }`, the only mode of `POST /key-admin/:clientId/rotate`) revokes the outgoing key immediately** — it loses signing and verification capability *within QODIQA* in the same call, the same as an explicit `revoke()`. This is the fix: an operator's ordinary "rotate the key" action is the intuitive incident-response move, and it must not silently leave a potentially compromised key able to verify. **For Vault Transit / HSM-backed keys, this QODIQA-side guarantee does not by itself guarantee the key is also disabled at the external provider** — see `docs/security/key-management.md`'s "External Key Providers (Vault Transit / HSM / KMS)" section and.
- **Deprecated keys exist only when a caller explicitly opted into graceful rotation** (the automatic rotation scheduler, and startup auto-rotation of an aged-out key — both planned maintenance, never incident response). They remain in the store for 180 days (purge eligibility), but (design decision D2) a deprecated key verifies only artifacts signed before its retirement and only for 65 s after it — artifacts live at most 60 s, so in-flight artifacts complete and nothing older verifies.
- **Revoked keys** — whether revoked explicitly or as the default outcome of rotation — block verification for all artifacts signed with them within QODIQA — surfaced as `KEY_REVOKED` (key resolved, lifecycle refused) or `INVALID_SIGNATURE` (key no longer resolvable); `KEY_NOT_FOUND` is never emitted

**Access control** (`keyManager.js`):

- `getSigningKey()` — returns private key material; authorized for `/sign` route only
- `getVerificationKey()`, `getActivePublicKey()`, `listPublicKeys()` — return public material only; no private key exposure to other components

---

## Redis stores

Four of the Redis clients are described here (there are at least 15 managed clients in all; only the nonce, anomaly and rate-limit stores gate readiness), each with its own namespace and reconnect lifecycle:

| Store | Module | Namespace | Operation | Used for |
|---|---|---|---|---|
| **Nonce store** | `src/validation/nonceStore.js` | `qodiqa:req:v2:` | Atomic `SET NX PX` | Per-request replay protection |
| **Anomaly store** | `src/validation/anomalyStore.js` | `anomaly:v2:key:`, `anomaly:v2:global` | Lua sorted-set sliding window | Burst detection |
| **Rate-limit store** | `src/core/policy/store.js` | `ratelimit:v1:` | Lua `INCR + EXPIRE` | Policy rate limiting |
| **Consent cache** | `src/core/consent/ConsentCache.js` | `consent:` | GET/SET with TTL | Consent result caching; invalidated on revocation |

**Fail-closed behavior**: If the nonce or anomaly store becomes unavailable during request processing, the request is blocked — never served without replay/anomaly protection, and never partially executed. The HTTP rate limiter is the one deliberate exception: its security buckets fail closed, its traffic buckets degrade to a per-process limiter with a CRITICAL `RATE_LIMIT_DEGRADED` alert (see SECURITY.md).

**Degraded state (a monitoring concept, not a relaxed-security mode)**: `server.js`'s `_setupRuntimeMonitoring()` tracks a named `DEGRADED` operating state, entered whenever one or more of the three stores above disconnects or fails to initialize, and exited only once `GATEWAY_RUNTIME_RECOVERED`/`GATEWAY_STATE_RECOVERED` fires after all three report ready again. This state can persist indefinitely while a store is down — it is a first-class, ADR-documented concept (note distinguishing it from tamper-detection watermark divergence), not a crash-and-exit path. While `DEGRADED`, the instance keeps emitting structured `*_DEGRADED` events and updating the `redis_store_up`/`execution_integrity_full` Prometheus gauges, and `GET /ready` (`src/api/routes/ready.js`) returns 503 so the load balancer pulls it from rotation — but every degradation event carries `executionBlocked: true`: no request is served with reduced protection during this state. "Degraded" here describes availability/health, not a security posture; the fail-closed guarantee above holds throughout it. Compliance documentation previously described this as "no degraded mode," which was inaccurate as a literal statement —

**One narrower exception exists and should not be confused with the above**: if Redis is reachable but not durably persisted (no AOF, or an unsafe `appendfsync` setting), `REDIS_PERSISTENCE_UNSAFE`/`REPLAY_PROTECTION_DEGRADED` events fire and the server *does* continue serving requests, with a documented caveat that in-flight nonce state could be lost on a Redis crash/restart. Setting `STRICT_REPLAY_PROTECTION=true` closes this gap by refusing startup unless persistence is durably configured (see `docs/deployment/redis-persistence.md`).

**Persistence Recovery Queue is not a Redis store.** `src/core/persistenceRecovery/queue.js` durably persists retryable dual-write/evidence-chain failures in the `persistence_recovery_queue` PostgreSQL table (migration 032), not Redis — Redis availability has no bearing on it. "Durable Postgres-Backed Persistence Recovery Queue" decision.

**PostgreSQL is not a single point of failure for the recovery queue's durability** — measured 1,000 = 1,000 = 1,000 = 1,000 across a PG outage with 0 DLQ. *Availability* still depends on PostgreSQL: restart-while-the-mirror-lags and post-crash boot behaviour are open design decisions. If PostgreSQL itself is unavailable at the exact moment the queue's own INSERT would also fail, `src/core/persistenceRecovery/journal.js` durably persists the operation to a local, disk-backed, crash-safe filesystem journal instead — the same fsync/atomic-rename idiom `audit-log.js` already uses. `journalWorker.js` replays each entry back into the PostgreSQL-backed queue once PostgreSQL recovers. "Durable Filesystem Journal for Persistence Recovery Queue" decision.

**Runtime monitoring**: Each store has an event emitter. `server.js` subscribes to `ready` and `degraded` events and emits gateway-level events:
- Any store unavailable → `REPLAY_PROTECTION_DEGRADED` / `ANOMALY_PROTECTION_DEGRADED` / `POLICY_RATE_LIMIT_DEGRADED` (per store)
- All stores down → `GATEWAY_RUNTIME_DEGRADED`
- Some stores down → `GATEWAY_RUNTIME_PARTIAL_FAILURE`
- All stores restored → `GATEWAY_RUNTIME_RECOVERED` + `GATEWAY_STATE_RECOVERED`

**Automatic reconnection**: Each store attempts reconnection with exponential backoff capped at 30 s, with no attempt limit. The store stays unavailable (requests are blocked) until a reconnection succeeds.

**Startup**: Stores initialize concurrently via `Promise.allSettled()`. A store failure at startup emits `REDIS_STARTUP_FAILED` (per store) and `REDIS_RUNTIME_DEGRADED` (summary). The gateway starts but `/ready` returns 503.

---

## Audit chain

Every enforcement decision — both EXECUTE and BLOCK — is recorded in an append-only, cryptographically hash-chained audit log.

**Storage architecture:**

- **WAL file** (`audit.log.wal`): entry written here first (crash recovery)
- **Main log** (`audit.log`): newline-delimited JSON; entries appended after WAL write
- **Checksum file** (`audit.log.sum`): records entry count and tail hash; detects deletion or truncation
- Each write is fsynced to disk before the function returns

**Chain integrity:**

Each entry contains a `prevHash` field pointing to the previous entry's `hash`. The first modern entry uses `prevHash: "GENESIS"`. Any insertion, deletion, or modification of an entry breaks the hash chain.

**Entry fields:**

```javascript
{
  timestamp:          string,  // ISO-8601
  artifactId:         string,  // UUID v4
  inputHash:          string,  // requestHash (hex)
  decision:           'ALLOW' | 'BLOCK',
  signature:          string,  // artifact signature
  prevHash:           string,  // previous entry hash
  hash:               string,  // this entry hash
  canonical:          string,  // sorted JSON of core fields
  requestHash:        string,
  policyHash:         string,
  verificationResult: boolean,
  schemaVersion:      number,  // 7 by default, 8 when QODIQA_AUDIT_SCHEMA_V8=true; v1–v8 verifiable — see docs/protocol/QODIQA-PROTOCOL.md §9
  publicKeyId:        string | null,  // signing KEY attribution
  consentProvenance:  object | null,  // immutable consent-record snapshot (TRACE-2)
  policyDecision:     object | null,  // matched policy-rule provenance (TRACE-2)
  callerContext:      object | null,  // authenticated CALLER attribution, distinct
                                       // from publicKeyId — null for a pre-NONREP-1
                                       // artifact
  executionContext:   { stage, reason, provider, responseId }
}
```

`publicKeyId`, `consentProvenance`, `policyDecision`, and `callerContext` are all hash-protected core fields (part of `canonical`), not merely descriptive metadata — see `docs/protocol/QODIQA-PROTOCOL.md` §9 (normative) for the per-version hashed-field list; the superseded §11.3 / §11.3.1 (historical) describes the key-attribution-vs-caller-attribution distinction `callerContext` establishes.

**Audit API:**

- `GET /audit/:artifactId` — Retrieve the execution record for a specific artifact, addressed by the artifact ID returned from `POST /sign` (rate-limited: 30/min)
- `GET /audit/chain/integrity` — Full chain integrity walk: validates every entry hash, `prevHash` continuity, and checksum (rate-limited: 30/min, 10-second timeout)

---

## JavaScript SDK

The maintained JavaScript SDK is the in-repo SDK package `sdk/javascript` (package name `@qodiqa/sdk`, not yet published to npm). It is the canonical implementation for new integrations — see `docs/sdk/javascript/api.md` for its full resource-based API (`sign`, `verify`, `chat`, `portal`, `certification`, `transparency`, `evidence`, `webhooks`).

---

## Public API surface

| Endpoint | Auth required | Description |
|---|---|---|
| `GET /health` | None | Liveness probe — always 200 while process is running |
| `GET /ready` | None | Readiness probe — 503 if a Redis store, PostgreSQL, the revocation subscriber, admission, the audit backlog, audit persistence or the transparency journal is unhealthy |
| `GET /metrics` | Ops token | Prometheus metrics |
| `GET /.well-known/qodiqa/keys` | None | List active and deprecated public keys |
| `GET /.well-known/qodiqa/keys/:keyId` | None | Retrieve a specific public key |
| `GET /audit/:artifactId` | Per-operator RBAC key with `READ_AUDIT` | Retrieve enforcement record for an artifact ID |
| `GET /audit/chain/integrity` | Per-operator RBAC key with `READ_AUDIT` | Full audit chain integrity verification |
| `POST /sign` | `Authorization: Bearer <sk_...>` (per-identity signing key) | Create a signed authorization artifact |
| `POST /ai/chat` | `x-qodiqa-artifact` header | Execute an AI request (enforcement + provider call) |
| `POST /verify/v2` | None | Dry-run policy check (no execution, no side effects) |

---

## Fail-closed summary

| Layer | Store unavailable | Behavior |
|---|---|---|
| Replay protection | Nonce store down | All `POST /ai/chat` blocked — `NONCE_STORE_ERROR` |
| Anomaly detection | Anomaly store down | All `POST /ai/chat` blocked — `ANOMALY_DETECTED` type `STORE_ERROR` |
| Rate limiting | Rate-limit store down | `RATE_LIMIT` policies fail closed: store error → count treated as `Infinity` → `RATE_LIMIT_EXCEEDED` |
| Policy engine | Evaluator missing or throws | Request blocked — `EVALUATOR_MISSING` / `EVALUATOR_ERROR` |
| Execution invariant | `verifiedCtx.verified !== true` | Throws before any provider call — `UNVERIFIED_EXECUTION_ATTEMPT` |
| RBAC authorization | No `req.rbacUser`, unknown role, or engine exception | `403 FORBIDDEN` — unconditional, no configuration disables this. See `docs/security/RBAC_MODEL.md`. |

No request reaches the AI provider unless all five validation steps pass and the policy engine returns EXECUTE.

---

## Architecture Governance & Enforcement

Static dependency direction between layers is enforced by `dependency-cruiser`
(`.dependency-cruiser.js`), CI-gated on every push/PR via the `architecture`
job in `.github/workflows/test.yml`. This closes two governance gaps:
production middleware was invisible to the analysis, and the two
already-known layering violations (`Core -> Infrastructure`,
`Core -> Services`) could grow without limit because they were warnings with
no enforcement mechanism.

### Scope

Analysis covers `src/`, `services/`, **and `middleware/`** (the top-level
production middleware directory — distinct from `src/middleware/`, which was
already in scope). All three are passed to every architecture entry point:
`npm run arch:check`, `npm run arch:graph`, `npm run arch:baseline-check`,
and the CI `architecture` job. No command can accidentally analyze a subset.

### Target layering

```
API (src/api) -> Middleware (middleware/) -> Services (services/) ->
Core (src/core) -> Infrastructure (src/infra)
```

Middleware is API-adjacent, not Core: it may depend on API, Infrastructure,
Services, and utilities, but must never become business logic, domain logic,
or orchestration. This is a hard, CI-blocking error (`no-middleware-to-core`),
and the reverse direction is blocked too (`no-infra-to-middleware`,
`no-core-to-middleware`) so a lower layer can never reach up into it — the
same pattern already used to keep Infrastructure and Core out of the API
layer. As of this remediation, middleware has zero violations under these
rules (5 modules, 471 total modules cruised across the full scope).

### Hard errors vs. the regression budget

Six rules are `severity: 'error'` and fail the build immediately on any
violation: `no-circular`, `no-infra-to-services`, `no-infra-to-api`,
`no-core-to-api`, `no-middleware-to-core`, `no-infra-to-middleware`, and
`no-core-to-middleware`.

Two rules — `no-core-to-infra` and `no-core-to-services` — remain
`severity: 'warn'`. Eliminating them outright would mean relocating
widely-used cross-cutting utilities (`services/logger.js`,
`services/secrets/secretsProvider.js`) and touching 50+ pre-existing Core
call sites: a large, separate migration, not this change's scope (see
"Future phased Core decoupling" below). Leaving them as unbounded warnings,
however, meant CI accepted an unlimited and growing number of new violations
forever — the actual defect Finding #4 / Register #104 identified.

**The fix is a regression budget, not a severity change.** The current
warning count is committed to `.arch-baseline.json` as the approved ceiling:

```json
{
  "counts": { "error": 0, "warn": 162, "totalModulesCruised": 471, "totalDependenciesCruised": 1226 }
}
```

 (run in CI as `npm run arch:baseline-check`,
after `npm run arch:check`) re-runs dependency-cruiser and compares the
current warning count to the committed baseline:

| Comparison | Result |
|---|---|
| `current > baseline` | **FAIL** — architecture regressed |
| `current == baseline` | PASS — steady state |
| `current < baseline` | PASS — improvement (rerun with `--write-baseline` to lock in the new, lower ceiling) |

Architecture quality can hold steady or improve; it can never silently
regress again. Both `no-core-to-infra` and `no-core-to-services` violations
count toward the same shared budget.

### Future phased Core decoupling

This change deliberately does not touch any of the 162 existing
warnings (regenerate with
`npm run arch:report`) for deterministic fan-in/fan-out/cluster metrics
identifying where that future migration should start. The report currently
shows `services/logger.js` (160 dependents) and `src/infra/postgres/pool.js`
/ `src/core/audit/audit-log.js` among the highest-coupled nodes touching
Core — consistent with the two documented, narrow exceptions already carved
out of `no-infra-to-services`. A phased migration would relocate or invert
these cross-cutting dependencies module-by-module, using
`npm run arch:baseline-check -- --write-baseline` to ratchet the budget down
after each verified reduction, rather than attempting the full 162-violation
migration in one pass.

---

## Composition Root & Startup Lifecycle

`server.js` was originally a single ~1,570-line file that owned Express app
creation, middleware wiring, route mounting, dependency initialization, and
the startup/listen sequence all at once — an oversized composition root
(Architecture Finding #5). split it into three single-purpose
modules with no behavioral change: identical middleware order, identical
route mounting, identical startup sequence.

```
server.js               server/startup.js            src/app.js
(thin entrypoint)   →    (startup lifecycle)     →    (composition root)
                         dependency init,             Express app creation,
                         startup sequencing,           middleware wiring,
                         infra bootstrap,               route mounting,
                         HTTP server + listen           error handlers
```

### `src/app.js` — application composition

Exports `createApp(ctx)`. Builds and returns a fully configured Express
app: security headers, CSP, proxy validation, CORS, request-ID/client-IP
attachment, tracing, health/ready/metrics/diagnostics mounts, the request
drain, body parsing, every route (unversioned and `/v1` aliases), the
static file mount, and the 404/error handlers — in the same order they
were previously wired directly in `server.js`. It never starts listening,
never connects to Redis/PostgreSQL, and never performs startup validation.
See `docs/api/versioning.md` for why `/v1` is a cosmetic alias today and
what a genuine future `/v2` would require.

### `server/startup.js` — startup lifecycle

Exports `{ ctx, startServer }`. Requiring this module runs, synchronously
and in the same order as before, every startup validation and dependency
initialization step that used to run at the top of `server.js`: env/secret/
CORS validation, key-manager and transparency-signer validation, tenant key
health, ops/RBAC/admin-protection stack assembly, event-loop monitor,
PostgreSQL pool, Redis-backed rate-limit/auth-lockout/recovery-queue/
idempotency stores, alerting, SIEM log shipping, and policy loading. Any
FATAL check still calls `process.exit(1)` at the same point in the sequence
it always did. `startServer(app)` then runs the full async startup sequence
(Redis store initialization, STRICT_REPLAY gating, revocation/org-status
subscribers, `app.listen()`, background schedulers, graceful-shutdown
registration) exactly as `startServer()` did before, now taking the
already-composed `app` as a parameter instead of closing over a
module-level variable.

`ctx` carries the values `src/app.js` mounts as middleware but cannot
safely rebuild itself — the ops-auth lockout, health/admin protection
stacks, tracing handle, and mutable policy accessor are constructed exactly
once in `server/startup.js` and shared by reference, because several of
them (see and Task #27 comments in that file) are required to be
a *single* shared instance across every surface that uses them.

### `server.js` — thin entrypoint

Requires `server/startup.js` (running its startup validation as a side
effect, same as before) and `src/app.js`, builds `app = createApp(ctx)`,
and — only when run as the main module — calls `startServer(app)`. Exposes
the same `module.exports` shape as before (`app` as the default export,
plus `.app` and `.startServer`) for existing consumers (`start.js`,
`test/harness/shutdownIpcWrapper.js`,
`test/serverStartupSmoke.test.js`).

### Middleware directory responsibilities

Two middleware directories exist deliberately, with different scopes (see
each directory's README for the full list):

- [`middleware/`](../../middleware/README.md) — generic HTTP request/response
  infrastructure (request ID, client IP, content-type enforcement, generic
  rate limiting, generic policy enforcement). No QODIQA-specific
  authorization logic.
- [`src/middleware/`](../../src/middleware/README.md) — authentication,
  authorization, administrative protection, and other application-specific
  security middleware (RBAC, admin protection, ops/health auth, API
  versioning).

This split predates and is unchanged by it; already brought
both directories under `.dependency-cruiser.js` governance (see above).

---

## Streaming Path

When `stream: true` is set in the request body, enforcement runs synchronously through
`_runEnforcementPipeline()` (Steps 1–5). If enforcement fails, **a JSON `200` with
`{decision: 'BLOCK', reason, details, requestId}` is returned** and no stream opens. If
enforcement passes, the response switches to `text/event-stream`
(SSE) and chunks are forwarded as they arrive from the AI provider.

The nonce is registered before the first byte is sent. A single audit record is written
after the stream terminates (completed, cancelled, or error). Stream duration is bounded by
`STREAM_MAX_DURATION_MS` (default 5 minutes). See `docs/architecture/streaming.md`.

---

## See also

- `docs/guides/quickstart.md` — setup and first run
- `docs/architecture/enforcement-flow.md` — complete per-request decision pipeline with all reason codes
- `docs/architecture/verification-flow.md` — dry-run verification pipeline and endpoint differences
- `docs/operations/troubleshooting.md` — diagnosis and resolution for all failure modes
- `docs/operations/runbook.md` — key rotation, policy reload, graceful shutdown
- `docs/security/cryptography.md` — cryptographic algorithm details
- `docs/guides/providers.md` — full AI provider reference (registry, failover, streaming, per-provider capabilities)
- `docs/api/overview.md` — complete API endpoint reference
- `docs/configuration/reference.md` — all environment variables
- `docs/glossary.md` — definitions of all QODIQA concepts
- `docs/security/RBAC_MODEL.md` — RBAC fail-closed authorization model and admin bootstrap procedure
- `.dependency-cruiser.js` — full architecture rule set and rationale
- `.arch-baseline.json` — committed architecture regression-budget baseline
- — fan-in/fan-out/cluster metrics for future Core decoupling
- — architecture enforcement expansion report
