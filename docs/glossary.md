# QODIQA Glossary

Complete definitions for every concept used in the QODIQA documentation and implementation.
Terms are listed alphabetically. Each definition is consistent with the implementation.

---

## A

**Anomaly Detection**
A sliding-window rate counter implemented with a Redis Lua sorted set. Two independent windows are evaluated on every request: a per-signing-key window (default 100 requests per 60 seconds) and a global window (default 5,000 requests per 60 seconds). If either window is exceeded — or the anomaly store itself is unavailable — the request is blocked with reason `ANOMALY_DETECTED` (`details.type` distinguishes `SIGNATURE_BURST`, `RATE_BURST`, and `STORE_ERROR`). The counters are atomic and are stored under the key prefix `anomaly:v2:`.

**Artifact**
A cryptographically signed JSON envelope that authorizes a specific AI request. An artifact must be present on every `/ai/chat` call. It carries: the artifact ID, expiry timestamp, signing timestamp, Ed25519 signature, public key identifier, and a payload that includes the request hash, policy hash, provider, and other request-specific fields. The artifact is base64-encoded and transmitted in the `X-Qodiqa-Artifact` HTTP request header. See also: *Decision Artifact*, *Signed Artifact*.

**Artifact Domain**
A human-readable string prefix that is prepended to all hash inputs to prevent cross-protocol hash reuse. QODIQA defines 33 domain tags (15 of them in `ARTIFACT_DOMAINS`); the most common are (see `docs/protocol/QODIQA-PROTOCOL.md`, the authoritative registry):
- `QODIQA::ARTIFACT::V1` — artifact envelope hashing
- `QODIQA::REQUEST::V1` — request binding hashing
- `QODIQA::POLICY::V1` — policy hash computation
- `QODIQA::CERTIFICATE::V1` — certificate artifact hashing
- `QODIQA::EVIDENCE::V1` — evidence chain entry hashing
- `QODIQA::AUDIT::V1` — audit chain entry hashing
- `QODIQA::CANONICAL::V1` — generic domain-separated canonical hashing
- `QODIQA::TRANSPARENCY::V1` — Merkle transparency log entry hashing
- `QODIQA::TRANSPARENCY_ROOT::V1` — Merkle transparency log signed root hashing
- `QODIQA::PORTAL_EVIDENCE::V1` — verification portal evidence hashing
- `QODIQA::CERTIFICATION_EVIDENCE::V1` — certification evidence hashing
- `QODIQA::COMPLIANCE_REPORT::V1` — compliance report hashing

There is no `QODIQA::NONCE::V1` domain — nonce store keys are plain string concatenations (`[tenantId:]qodiqa:req:v2:<requestId>`), not domain-separated hashes; an earlier revision of this entry listed a nonexistent `NONCE` domain and omitted six real ones.

**Artifact Expiry**
The Unix millisecond timestamp at or after which an artifact is no longer valid. QODIQA rejects artifacts with `expiry <= Date.now()` with reason `EXPIRED`. The maximum allowed TTL is clamped by the signing endpoint (`MIN_TTL_MS` to `MAX_TTL_MS`). A short TTL reduces the replay window.

**Artifact Header**
The HTTP request header `X-Qodiqa-Artifact`. Its value must be a base64-encoded JSON string representing a valid signed artifact envelope. Maximum size: 8,192 bytes.

**Artifact ID**
A UUID v4 string that uniquely identifies a specific artifact. After successful enforcement the artifact ID is used as the primary key in the audit chain. The artifact ID is returned to the caller in the `artifactId` field of a successful `EXECUTE` response.

**Attestation**
A cryptographic record that documents a point-in-time evaluation of an AI interaction against a defined set of criteria. Attestations are stored in the database and can be exported in JSON or PDF format. They are distinct from *Certificates*, which are issued only on passing a certification evaluation.

**Audit Chain**
An append-only, hash-chained sequence of audit records. Each record contains a reference to the previous record's hash, creating a tamper-evident chain. The authoritative audit chain is an NDJSON file stored on disk. PostgreSQL is an asynchronous replica. The chain is maintained in a module-level singleton with seven O(1) in-memory indexes. Only one process may write to the chain at a time (see *Single-Writer Invariant*).

**Audit Log**
The on-disk NDJSON file that stores all enforcement decisions. Each line is a JSON object representing one audit entry. Writes are synchronous (`fs.writeFileSync` + `fsync`) and are protected by a Write-Ahead Log (WAL) pattern. The file is sealed with a checksum (`.sum` file) updated atomically after each write.

---

## B

**Backwards Compatibility**
QODIQA guarantees that artifacts signed with any version of the artifact schema that is still in the active or archived key set remain verifiable. There is no `envelopeVersion` field in the current artifact schema — the artifact envelope has exactly five top-level fields (`expiry`, `payload`, `publicKeyId`, `signature`, `timestamp`), and any additional field, including a version field, is rejected as `INVALID_ARTIFACTQODIQA::ARTIFACT::V1`, §19.1); a breaking change to the artifact format would require a new domain prefix version, not a new field.

**Binding** → see *Request Binding*

**Block**
A decision outcome in which QODIQA denies an AI request. The HTTP response status is `200 OK` by default (`QODIQA_BLOCK_HTTP_MODE=decision`; with `=status` it is 400, 403, 409, 429, 503 or 500 by block class) with a JSON body containing `{ decision: "BLOCK", reason: "<REASON_CODE>", details: {}, requestId: "..." }`. A block is always logged to the audit chain.

**Block Reason Code**
A machine-readable string identifier for the cause of a BLOCK decision. All reason codes are stable across versions. Examples: `INVALID_SIGNATURE`, `REPLAY_DETECTED`, `ANOMALY_DETECTED`, `POLICY_BLOCKED`. See *Failure Modes* in `docs/operations/troubleshooting.md`, or `docs/architecture/enforcement-flow.md`'s reason/HTTP-status table, for the complete list.

---

## C

**Caller Attribution** → see *Key Attribution vs. Caller Attribution*

**Caller Context**
The immutable snapshot of an authenticated signing identity (`callerId`, `callerName`, `environment`, `credentialType`) that `POST /sign` embeds directly into `artifact.payload.callerContext` at signing time. Because `payload` is covered by the artifact's full-envelope Ed25519 signature, `callerContext` is cryptographically protected without any new signing primitive. `null` on an artifact signed before this remediation shipped. See *Key Attribution vs. Caller Attribution* below.

**Canonical JSON**
A deterministic serialization of a JSON value in which object keys are sorted lexicographically and no whitespace is added. QODIQA uses `fast-json-stable-stringify` as the canonical serialization library. Canonical JSON is used wherever a hash must be reproducible across implementations and environments.

**Canonicalization**
The process of transforming an artifact or request into a deterministic byte sequence before hashing. QODIQA's canonicalization rules (`docs/protocol/QODIQA-PROTOCOL.md`): (1) object keys are sorted lexicographically, (2) no whitespace, (3) arrays are preserved in order, (4) `undefined` values serialize as `null` (rejected outright at the artifact-schema layer before reaching serialization — they would otherwise silently collide with an explicit `null`), (5) circular references are rejected deterministically, never via a native stack overflow, (6) `NaN`/`Infinity`/`-Infinity` numbers are rejected, (7) object keys `"__proto__"`, `"constructor"`, `"prototype"` are rejected, (8) functions, symbols, bigints, and any value with no defined canonical form (`Date`, `Map`, `Set`, buffers, etc.) are rejected. Canonicalization is implemented in `src/utils/stableStringify.js`; artifact-specific schema checks are layered on top in `src/validation/canonicalize.js`.

**Capability**
A named permission in the RBAC system, called a *permission* in the reference implementation's own code and API (`src/core/rbac/roles.js`'s `PERMISSIONS` map, `requirePermission()`) — "capability" is this glossary's and the protocol spec's term for the same concept; expect the string `permission`, not `capability`, in reference-implementation code, logs, and API responses. Permissions are granted to roles, not directly to users. Example permissions: `READ_AUDIT`, `MANAGE_KEYS`, `MANAGE_CONSENT`. A user inherits all permissions of their assigned role.

**Certificate**
A cryptographically signed artifact issued when an AI interaction passes a certification evaluation. A certificate contains the certification level, score, policy version, and a stable artifact version. Certificates are designed for offline, permanent verification: they include the public key ID required for signature verification and do not require a database lookup.

**Certificate Artifact**
The signed bundle format used for certificates. Structure: `{ version, certificate, signature, keyId, signingAlgorithm, signedAt, domain }`. The `certificate` field is the exact object that was signed. Verification requires only the bundle JSON and the corresponding public key.

**Clock Skew**
The difference between the artifact signing timestamp and the QODIQA server's current clock, checked in two independent directions with different tolerances (`src/validation/timeCheck.js`). Forward drift (an artifact timestamp more than `FUTURE_SKEW_MS` = 5,000 ms ahead of the server clock) is rejected with reason `FUTURE_TIMESTAMP`; a timestamp up to 5 s ahead is accepted. Backward drift (artifact timestamp older than the server clock by more than `MAX_SKEW_MS`, a hardcoded 60,000 ms / 1 minute constant — not independently configurable via an environment variable) is rejected with reason `TIME_SKEW_EXCEEDED`. NTP synchronization is required on all nodes.

**Compliance**
The QODIQA compliance subsystem generates structured reports documenting adherence to defined control frameworks. Reports can be exported as JSON, HTML, or PDF. The compliance engine collects evidence from the audit chain, transparency log, and attestation records.

**Consent**
An explicit, revocable execution-authorization record, keyed by `actor_id`, that permits a specific category of AI interaction. By the platform's default and intended design, `actor_id` is a cryptographically-verified machine/key identity (see `checkPolicy.js`'s canonical binding), not a natural person — QODIQA "consent" is a machine authorization primitive, not GDPR Article 7 end-user consent for the full distinction. An operator may choose to populate `actor_id` with a natural-person identifier instead, in which case the record becomes personal data in its own right, but this is an operator-driven repurposing, not QODIQA's default target. Consent state transitions: `PENDING` → `ACTIVE` → `REVOKED | EXPIRED | SUSPENDED`. Consent is verified on every enforcement-eligible request via the `REQUIRE_CONSENT` policy rule. Revocation is propagated in real time via Redis pub/sub.

**Consent Cache**
A Redis-backed cache for consent verification results. The cache is invalidated immediately on receipt of a revocation event via the `RevocationSubscriber`. If the subscriber is not ready, consent verification falls through to the PostgreSQL `ConsentStore` directly.

**Consent Token**
An opaque string issued to a user to represent their active consent. The token is used as the primary lookup key for consent verification. Consent tokens are tenant-scoped.

**Consistency Proof**
A Merkle consistency proof demonstrating that a newer transparency root is a cryptographic extension of an older root. Computed using the RFC 6962 algorithm. Returned by `GET /transparency/consistency/:fromRootId/:toRootId`.

**CSP (Content Security Policy)**
Two separate CSP configurations are applied: `API_CSP` (all sources `'none'`, the strictest policy, applied to all JSON API endpoints) and `PORTAL_CSP` (applied to the HTML verification portal). The API CSP prevents all resource loading, including scripts and styles. `PORTAL_CSP`'s `script-src` is `'self'` only (remediated — every inline `<script>` and inline event-handler attribute in `public/*.html` was moved to external `public/js/*.js` files); `style-src` still allows `unsafe-inline` for the portal's inline `<style>` blocks, a separate, lower-severity concern since style injection cannot achieve script execution.

---

## D

**Degraded (Execution Integrity)**
A named, monitored operating state (`server.js`'s `_setupRuntimeMonitoring()`) entered whenever one or more of the three Redis-backed stores (nonce, anomaly, rate-limit) is unavailable, and exited only once all three report ready again (`GATEWAY_RUNTIME_RECOVERED`). It is a health/availability concept, not a relaxed-security operating mode: every `*_DEGRADED` event carries `executionBlocked: true`, `GET /ready` returns 503 while it persists, and no request is ever served with reduced replay, anomaly, or rate-limit protection during this state — see **Fail-Closed** below. Compliance documentation prior to's remediation described QODIQA as having "no degraded mode," which was inaccurate as a literal claim against this named state;

**Dead-Letter Queue (DLQ)**
The set of persistence recovery queue items that have failed redelivery beyond the maximum retry count. DLQ items can be inspected via `GET /v1/prq/dlq` and replayed via `POST /v1/prq/dlq/replay`.

**Decision**
The outcome of the enforcement pipeline: either `EXECUTE` (AI call is allowed) or `BLOCK` (AI call is denied). Every decision is written to the audit chain.

**Decision Artifact**
An artifact that has been bound to a specific HTTP request via request hashing. A decision artifact's `payload.requestHash` field contains `SHA-256("QODIQA::REQUEST::V1" || canonicalJSON({ body, method, path }))`. If this hash does not match the hash recomputed from the incoming request, the artifact is rejected with reason `REQUEST_MISMATCH`.

**Domain-Separated Hash**
A hash computed as `SHA-256(DOMAIN_STRING || stableStringify(data))` where `DOMAIN_STRING` is one of the canonical artifact domain strings. Domain separation ensures that a hash computed in one context (e.g., artifact signing) cannot be reused in another context (e.g., request binding), even if the data is identical.

---

## E

**Ed25519**
The digital signature algorithm used for all artifact signing, transparency log root signing, and certificate signing. Ed25519 uses 32-byte keys and produces 64-byte signatures encoded as base64. QODIQA never generates or uses RSA or ECDSA for artifact signing. Ed25519 is specified in RFC 8032.

**Enforcement Pipeline**
The ordered sequence of security checks applied to every `/ai/chat` request before the AI provider is called. The pipeline is fail-closed: any check failure produces an immediate `BLOCK` response. Stages: (1) content-type guard, (2) body schema validation, (3) artifact decoding, (4) `validateBoundRequest` (signature, request binding, nonce, anomaly), (5) policy evaluation, (6) AI execution. Steps 1–5 are implemented in `_runEnforcementPipeline()` in `src/api/routes/aiChat.js`.

**Envelope**
The top-level structure of a signed artifact: exactly `{ expiry, payload, publicKeyId, signature, timestamp }` — five fields, no more, no less; there is no `envelopeVersion` field (see *Backwards Compatibility* above). The envelope domain (`QODIQA::ARTIFACT::V1`) is prepended to the hash input before signing.

**Evidence Chain**
An immutable, hash-chained sequence of cryptographic evidence records (`evidence_chain_records`, PostgreSQL) that document the verification history of an artifact — distinct from the *Evidence Package* and *Evidence Bundle* entries below, which are point-in-time **exports** built FROM this chain (plus the audit chain and transparency log) rather than the chain itself. Each evidence chain record links to the artifact ID and the audit chain entry that produced it — a two-way link only; there is no transparency-log entry field anywhere in the evidence record schema (`CANONICAL_FIELDS_V1`/`V2`/`V3` in `src/core/evidence/chain.js`), so an evidence chain record carries no reference to, and proves nothing about, the transparency log on its own (see *Evidence Bundle* below for the export that adds that link). The record is itself hash-protected (`src/core/evidence/chain.js`, `computeEvidenceHash()`) over a canonical field set that has grown additively — consent provenance and authenticated-caller context are both part of the protected hash for records written after those remediations, `null` and unprotected-by-omission for older records, dispatched per-record by `schema_version` (never a global rehash). Evidence chain records can be queried via `GET /evidence-chain/:chainId` or by artifact via `GET /evidence-chain/records/by-artifact/:artifactId`. Recovery of this chain after data loss follows `docs/operations/audit-chain-integrity-verification.md` (the audit-chain runbook it's derived from) — `docs/operations/transparency-recovery.md` covers the separate transparency log, not this chain.

**Trust assumption**: everything above proves internal consistency and non-repudiation *relative to QODIQA's own signing key* — it does not, on its own, prove that key belongs to the operator it claims to. Establishing that binding (e.g. via `.well-known` key publication, out-of-band key fingerprint verification, or a certificate authority) is an operational/deployment concern outside this chain's scope, unchanged.

**Evidence Package**
A forensic-grade, self-contained export assembled by `generateEvidencePackage()` (`src/core/evidence/generator.js`) for a single artifactId, retrievable via `GET /evidence/package/:artifactId[/json|/pdf]`. Contains the full (never truncated) Ed25519 signature and public key, the canonical audit-chain hash input — which as includes the AI provider and model identity, not just decision/policy/timing fields — policy/audit/verification context (including, a deterministic hash of the specific policy rule that decided, independently recomputable from a copy of the rule definition), and a package-level Ed25519 seal signed with QODIQA's active key — sufficient for any third party to verify the package entirely offline, without a running QODIQA instance. See `docs/security/cryptography.md` §18. Distinct from *Evidence Chain* above; does not by itself prove the underlying decision was entered into the transparency log — see *Evidence Bundle* below for that.

**Evidence Bundle**
The fully self-contained offline export, retrievable via `GET /evidence/package/:artifactId/bundle` and generated by `generateEvidenceBundle()` (`src/core/evidence/generator.js`). Wraps a complete *Evidence Package* (above) together with the artifact's RFC6962 Merkle inclusion proof against a published transparency root (`src/core/transparency/merkle.js`), then seals the two together with one more Ed25519 signature over the combined content — closing the gap an evidence package alone leaves open (that its signature proves QODIQA issued it, but not that the same decision was ever entered into the tamper-evident, externally-auditable transparency log, nor that a given package and a given inclusion proof genuinely belong together rather than being spliced from two different artifacts). Verifiable with the standalone `tools/verify/verify.bundle.external.js` script — zero network access, zero database access, no running QODIQA instance, no transparency service, no external APIs; see `docs/security/evidence-bundle-verification.md`. The `transparency` section may report `available: false` (with a `note`) rather than failing outright when the artifact's decision hasn't yet been covered by a published transparency root — inclusion proofs are only generated periodically, not synchronously with every decision.

**Execute**
A decision outcome in which QODIQA allows the AI request to proceed. The HTTP response status is `200 OK` with a JSON body containing `{ decision: "EXECUTE", reason: "ALL_CHECKS_PASSED", response: "...", artifactId: "...", keyId: "...", requestId: "..." }`.

---

## F

**Fail-Closed**
The design principle that any uncertainty, missing dependency, or unexpected error produces a `BLOCK` decision rather than allowing execution. QODIQA is fail-closed at every stage: if Redis is unavailable the nonce store cannot be checked, so all requests are blocked with HTTP 503. If the policy engine throws an unexpected error, the request is blocked with reason `INTERNAL_ERROR`. This holds throughout the **Degraded** state above — degradation affects availability, never enforcement strictness. The one narrower exception is persistence, not availability: if Redis is reachable but not durably configured (no AOF, or unsafe `appendfsync`), the server continues serving requests with a `REPLAY_PROTECTION_DEGRADED` warning rather than blocking, unless `STRICT_REPLAY_PROTECTION=true` is set (see `docs/deployment/redis-persistence.md`).

**Flapping Detection**
A mechanism in the Redis nonce store client (`src/validation/nonceStore.js`) that detects rapid connect/disconnect cycles (more than 3 events, i.e. the 4th and subsequent, within a 60-second window) and emits a `REDIS_RECONNECT_FLAPPING` or `REDIS_READINESS_FLAPPING` event to the logger. Flapping indicates an unstable Redis connection and triggers alerting.

---

## G

**Gap**
A missing entry in the transparency log sequence. Gaps are detected by the `GapScanner` subsystem (`src/core/transparency/scanner/`). A gap may indicate a failed write, a network partition, or a data integrity issue. Gaps trigger alerting and must be investigated and documented before the transparency log can be certified.

**Gateway**
QODIQA's role as the enforcement boundary between the caller and the AI provider. The gateway pattern means that all AI calls must pass through QODIQA's enforcement pipeline; there is no way to reach the AI provider without a valid signed artifact.

---

## H

**Hash Chain**
Each audit chain entry's hash covers a set of core fields that grows with the schema version (nine at schema v1, more from v5 to v8; see docs/protocol/QODIQA-PROTOCOL.md §9).

**HSM (Hardware Security Module)**
An optional hardware device that provides tamper-resistant key storage and cryptographic operations. QODIQA supports HSM integration via PKCS#11 (`src/infra/keys/providers/hsm.js`) and via cloud KMS services that are themselves HSM-backed (AWS KMS, Azure Key Vault, GCP KMS). The transparency signer also has an `HsmTransparencySigner` class that is not supported in the current release; `TRANSPARENCY_SIGNER=software` must be used. These integrations are tested only against mocks and local emulators, never against a real cloud KMS or HSM.

---

## I

**Inclusion Proof**
A Merkle inclusion proof demonstrating that a specific log entry is part of a transparency root. Returned by `GET /transparency/proof/:transparencyId`. The proof uses the RFC 6962 algorithm and includes the Merkle path required for offline verification.

---

## K

**KEK (Key Encryption Key)**
A 256-bit (32-byte) symmetric key used to encrypt Ed25519 private keys at rest using AES-256-GCM. The KEK is provided via the `QODIQA_KEY_ENCRYPTION_KEY` environment variable (64 hexadecimal characters) or injected by an external KMS at startup. The KEK never appears in logs, responses, or artifacts. It is wiped from process memory during graceful shutdown.

**Key Attribution vs. Caller Attribution**
The two distinct levels of non-repudiation strength QODIQA's evidence can support for a given decision: **`KEY_ONLY`** attribution proves which signing key (`publicKeyId`) produced an artifact, but not which authenticated caller requested that signature — every caller sharing a tenant's signing key is indistinguishable at this level. **`CALLER_BOUND`** attribution additionally proves which specific authenticated caller (`callerContext.callerId` — see *Caller Context*) requested the signature. An offline verifier determines which level applies to a given decision purely by checking whether `callerContext` is present (non-null) on the audit entry / evidence package — no online system required.3.1.

**Key Deprecation**
The verification-only key status produced **only** by explicit graceful-mode rotation (see Key Rotation) — never the default outcome of rotation. A deprecated key cannot sign but remains verifiable until it becomes purge-eligible. Do not confuse with **Key Revocation**, which blocks both signing and verification within QODIQA.

**Key ID**
A stable string identifier for a signing key, formatted as `<clientId>:key_v<N>` where `N` is the key generation number. Key IDs are embedded in artifacts (`publicKeyId` field) and certificates (`keyId` field). Retired keys retain their key ID for permanent artifact verification.

**Key Revocation**
The permanent, irreversible key status that blocks both signing and verification **within QODIQA** (`KEY_REVOKED` while the key still resolves, `INVALID_SIGNATURE` once it does not) — QODIQA will never again select or resolve this key. Reached either via an explicit `POST /key-admin/:clientId/revoke` call, or automatically as the default (`'emergency'` mode) outcome of `POST /key-admin/:clientId/rotate` — the two are distinguished in the `KEY_REVOKED` audit event via the `revocationTrigger` field (`'ROTATION'` vs. absent). For a native signing provider (Vault Transit / HSM), revocation additionally attempts to propagate to the provider's own `revokeKey()`, but that call can fail — QODIQA's revocation alone does not guarantee the external provider has stopped honoring signing requests for the key. See **docs/security/key-management.md**'s "External Key Providers (Vault Transit / HSM / KMS)" section and for the full explanation and required operator follow-up.

**Key Rotation**
The process of generating a new Ed25519 signing key and retiring the previous one. Rotation has two distinct modes: **`'emergency'` mode** (the only mode of `POST /key-admin/:clientId/rotate`; programmatic callers pass it explicitly) immediately **revokes** the previous key within QODIQA — it can no longer sign or verify artifacts through QODIQA, closing the incident-response gap where "rotating" a suspected-compromised key left it still able to verify forged signatures. (For Vault Transit / HSM-backed keys, see the Key Revocation entry above and QODIQA-side revocation does not by itself guarantee the outgoing key is also disabled at the external provider.) **`'graceful'` mode** — reserved for explicit, planned maintenance (the automatic rotation scheduler; startup auto-rotation of an aged-out key) — instead marks the previous key **deprecated**, keeping it in the key store for ongoing artifact verification while blocking further signing. Rotation is triggered via `POST /key-admin/:clientId/rotate` (emergency) or `POST /key-admin/:clientId/rotate-graceful` (graceful); both require `MANAGE_KEYS` permission.

**Key Store**
The encrypted storage for Ed25519 key material. The active store is `data/keys.json`, which contains AES-256-GCM–encrypted private keys. An archive file (`data/key-archive.json`) preserves deprecated key metadata (no private keys). The key store is an append-only-writes, never-update, never-delete structure.

---

## L

**Liveness Probe**
`GET /health`. Returns `{ status: "ok", uptime: <seconds> }` with HTTP 200. This endpoint does not check any dependencies. It is used as the Kubernetes liveness probe.

---

## M

**Merkle Root**
The root hash of a Merkle tree covering a range of transparency log entries. Roots are generated on a scheduled basis by the `rootScheduler`, signed with the transparency signing key, and stored in the `transparency_roots` PostgreSQL table. Merkle roots are the anchors for inclusion and consistency proofs.

**Merkle Tree**
A binary hash tree used by the transparency log to provide cryptographic proof of log completeness. QODIQA's implementation follows RFC 6962 (Certificate Transparency). Leaf nodes are domain-separated hashes of log entries. Internal nodes are `SHA-256(0x01 || left || right)`. Leaf nodes are `SHA-256(0x00 || entry_hash)`.

**Multi-Tenancy**
QODIQA supports multiple tenants. Each tenant has an isolated nonce namespace (`tenantId:requestId`), an isolated anomaly counter namespace, tenant-specific policy overrides, and per-organization quota settings. The tenant hierarchy is: Organization → Tenant(s).

---

## N

**Non-Repudiation** → see *Key Attribution vs. Caller Attribution*

**Nonce**
A single-use token used to prevent replay attacks. The nonce is the artifact's `requestId` (a UUID v4 string). On each request, the nonce is registered in Redis using `SET NX PX` (atomic set-if-not-exists with expiry). If the key already exists, the request is rejected with reason `REPLAY_DETECTED`. The nonce TTL equals the artifact's remaining TTL at enforcement time.

**Nonce Store**
The Redis-backed store for registered nonces. Key prefix: `qodiqa:req:v2:`. The nonce store uses Redis `SET NX PX` for atomic registration. The store also implements flapping detection and bounded exponential backoff for reconnects.

---

## O

**Ops Authentication**
Authentication for the operator API (all endpoints except `/ai/chat`, `/verify`, `/sign`, `/.well-known`, `/public-key`, and public attestation/certification routes). Operators authenticate using either a per-user RBAC API key (preferred) or the shared `QODIQA_OPS_TOKEN` (deprecated, still supported). Per-user keys are SHA-256–hashed before storage. Note: authenticating with the shared token is *necessary but not sufficient* for RBAC-gated routes (`/rbac`, `/key-admin`, `/consent`, etc.) — only a per-user API key carries a role, so the shared token can never satisfy those routes on its own. See *RBAC*.

**Organization**
The top-level grouping entity in the multi-tenant hierarchy. An organization has one or more tenants and defines default quotas (requests per minute, streams, retention days).

---

## P

**Persistence Recovery Queue (PRQ)**
A PostgreSQL-backed durable queue (`persistence_recovery_queue`; no Redis) for retryable dual-write and evidence failures. Items are claimed atomically with `FOR UPDATE SKIP LOCKED`; a local filesystem journal covers the case where PostgreSQL itself is unreachable. Items that fail redelivery are moved to the Dead-Letter Queue. The PRQ ensures that no audit entry is permanently lost even during PG outages.

**Policy**
A declarative JSON rule set that controls whether an AI request is allowed or blocked. Policies are evaluated after artifact verification. Every policy set must contain at least one `REQUIRE_CONSENT` rule. Policy evaluators: `REQUIRE_CONSENT`, `BLOCK_IP`, `TIME_WINDOW`, `RATE_LIMIT`.

**Policy Drift**
The condition in which the policy set active at the time of request differs from the policy set that was active when the artifact was signed. QODIQA detects policy drift by comparing the artifact's `policyHash` field with the current live policy hash. Policy drift is informational only and never causes a block.

**Policy Hash**
A SHA-256 hash computed over the canonical JSON of the active policy set, prefixed with `QODIQA::POLICY::V1`. The policy hash is embedded in artifacts at signing time and serves as a forensic record. It is not enforced at runtime.

**Policy Simulation**
A dry-run evaluation of a policy set against a hypothetical request context. Available via `POST /v1/policy/simulate`. No side effects; no audit record written.

**Provider**
The AI execution backend a signed artifact authorizes a request against, identified by `artifact.payload.provider` and one of eight built-in names: `openai`, `anthropic`, `gemini`, `mistral`, `llama`, `local`, `azure`, `bedrock` (the last two experimental; operator-registered OpenAI-compatible names are also accepted). Providers are registered in `services/providers/router.js` and enabled automatically when their required environment variable is present (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL` respectively) — no provider is enabled by default, and at least one must be enabled for the server to start (`BOOT_VALIDATION_FATAL` otherwise). See *Provider Adapter*, *Provider Router*, *Provider Failover*, and `docs/guides/providers.md` for the complete reference.

**Provider Adapter**
The per-provider execution handler (`services/providers/openai.js`, `anthropic.js`, `gemini.js`, `mistral.js`, `llama.js`, `local.js`) that performs model-allowlist and outbound-payload validation, makes the outbound HTTP call, normalizes errors to canonical `PROVIDER_*` codes, and returns a `ProviderResponse` built by `buildResponse()` (`services/providers/normalize.js`). Adapters are private — only the Provider Router calls them directly.

**Provider Failover**
Automatic retry of a failed provider call against a different, operator-configured provider. Triggered only for retryable errors (`PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_TIMEOUT`) and only one hop deep. Configured per-provider via `PROVIDER_FAILOVER_<PROVIDER_NAME>` (e.g. `PROVIDER_FAILOVER_OPENAI=anthropic`). Implemented in `services/providers/router.js` for `/ai/chat` and `services/providers/router.stream.js` for the streaming path.

**Provider Router**
The single internal entry point for dispatching a provider call: `routeProviderCall()` (`services/providers/router.js`) for non-streaming requests and `routeStreamingProviderCall()` (`services/providers/router.stream.js`) for streaming requests. Confirms the provider is registered and enabled, dispatches to its adapter, and manages failover. External code (`services/execution.js`, `services/execution.stream.js`) never calls a provider adapter directly.

**Public Key**
The Ed25519 public key corresponding to a signing key. Public keys are exported in DER-encoded base64 format. They are exposed via `GET /public-key`, `GET /public-keys`, and `GET /.well-known/qodiqa/keys` (JWKS format). Public keys are never encrypted.

---

## R

**RBAC (Role-Based Access Control)**
Access control for the operator API. Five built-in roles: `admin`, `auditor`, `compliance`, `operator`, `viewer`, each a fixed bundle of the platform's 66 permissions. An admin may additionally define **custom roles** — named, arbitrary subsets of those same 66 permissions, always identified by a `custom:`-prefixed ID so they can never collide with a built-in role name. The authorization engine (`src/core/rbac/authorize.js`) evaluates permissions, never role names, identically for both kinds. RBAC authorization is always enforced and cannot be disabled — there is no configuration flag, missing identity, or failure condition that grants administrative access without an explicit, persisted user record. See `docs/security/RBAC_MODEL.md` for the full fail-closed model, the custom-roles API, and the bootstrap procedure (`npm run rbac:bootstrap-key` (in the container image: `node scripts/rbac-bootstrap-key.js``).

**Readiness Probe**
`GET /ready`. Checks the readiness flag and the required components: the nonce, anomaly and rate-limit Redis stores, the revocation subscriber, PostgreSQL (when enabled), admission, the audit backlog, audit persistence and the transparency journal. Returns HTTP 200 if all are healthy, 503 otherwise. Used as the Kubernetes readiness probe.

**Reason Code**
→ see *Block Reason Code*

**Replay Attack**
An attack in which a valid, previously captured artifact is resubmitted to execute a second AI call. QODIQA prevents replay attacks via the nonce store: each `requestId` can only be registered once. Replays are detected with reason `REPLAY_DETECTED`.

**Replay Protection**
The mechanism that prevents replay attacks. Implemented using Redis `SET NX PX` on the artifact's `requestId`. The nonce TTL equals the artifact's remaining expiry. For full replay protection, `STRICT_REPLAY_PROTECTION=true` (the default) must be set. In strict mode, QODIQA will not start unless Redis AOF persistence is enabled and `appendfsync` is set to `everysec` or `always`.

**Request Binding**
The cryptographic binding of an artifact to a specific HTTP request. The request hash `SHA-256("QODIQA::REQUEST::V1" || canonicalJSON({ body, method, path }))` is computed from the HTTP method, path, and body, and must match the `requestHash` field in the artifact payload. A stolen artifact cannot be replayed against a different request.

**Request Hash**
The deterministic SHA-256 hash of the canonicalized HTTP request triple `(method, path, body)`. Computed at signing time and embedded in the artifact payload. Recomputed at enforcement time and compared using a timing-safe byte comparison.

**Request ID**
A per-request unique identifier generated by the `middleware/requestId.js` middleware. Format: UUID v4 (`crypto.randomUUID()`). Attached to `req.requestId` and returned in the `X-Request-ID` response header and in all JSON error responses.

---

## S

**Sign Endpoint**
`POST /sign`. Accepts a payload and a valid per-identity signing API key (`Authorization: Bearer sk_...`), computes the request hash and policy hash, and returns a signed artifact envelope ready to be attached to an AI request.

**Signed Artifact**
→ see *Artifact*

**Single-Writer Invariant**
The architectural guarantee that only one process writes to the audit chain at a time. Enforced by: (1) the audit chain module being a Node.js module-level singleton, (2) synchronous `fs.writeFileSync` on all WAL writes, (3) `cluster.isWorker` check that terminates with exit code 1, and (4) `multiInstanceGuard.js` that blocks PM2 cluster worker processes.

**SSRF (Server-Side Request Forgery)**
An attack in which an attacker causes QODIQA to make outbound HTTP requests to unintended targets. Mitigated by `services/providers/ssrf.js` which enforces an allowlist of permitted AI provider hostnames (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api.mistral.ai`). The AI provider base URL is never supplied by the caller at runtime.

**Streaming**
An SSE (Server-Sent Events) mode for AI responses. The enforcement pipeline (Steps 1–5) runs synchronously before the SSE stream opens. If any step fails, the stream never opens and a JSON BLOCK body is returned (HTTP 200 by default; the class status under `QODIQA_BLOCK_HTTP_MODE=status`). Once the stream is open, chunks are forwarded as `data: { event: "chunk_forwarded", delta, index }` SSE events. A single audit record is written after the stream terminates.

---

## T

**Tenant**
A logical isolation boundary within an organization. Each tenant has its own nonce namespace, anomaly counters, policy overrides, and quotas. Tenants are registered via `POST /v1/admin/tenants` (requires `MANAGE_USERS` permission).

**Timing-Safe Comparison**
A byte-by-byte comparison that takes constant time regardless of input content, preventing timing side-channel attacks. Used for all security-sensitive comparisons: artifact signature verification, request hash comparison, ops token comparison, RBAC key comparison. Implemented via Node.js `crypto.timingSafeEqual()`.

**Transparency Log**
An append-only, tamper-evident log of all verification decisions — both certification/attestation workflow results and live `POST /ai/chat` enforcement decisions (EXECUTE/DENY, streaming and non-streaming). Each entry is cryptographically linked to its predecessor and to a Merkle root. The transparency log is stored in PostgreSQL and supports RFC 6962 inclusion and consistency proofs. Roots are signed with the transparency signing key, generated on demand (`POST /transparency/admin/roots/generate`) or, where an operator has configured a nonzero `TRANSPARENCY_ROOT_INTERVAL_MS`/`TRANSPARENCY_ROOT_ENTRY_THRESHOLD`, periodically.

**Transparency Proof**
Either an *Inclusion Proof* or a *Consistency Proof* derived from the transparency log's Merkle tree. Proofs allow offline verification that a specific entry is part of a given root, or that two roots represent the same append-only log at different points in time.

**Transparency Signer**
The component responsible for signing Merkle roots (`src/core/transparency/transparencySigner.js`). Only the software signer (`TRANSPARENCY_SIGNER=software`) is supported in this release.

**Trust Boundary**
A line in the system architecture separating two entities with different trust levels. QODIQA defines five trust boundaries: (1) Internet → Load Balancer, (2) Load Balancer → QODIQA instance, (3) QODIQA → Redis, (4) QODIQA → PostgreSQL, (5) QODIQA → AI Provider.

---

## V

**Verification**
The process of checking an artifact and request against all enforcement rules without executing the AI provider call. Available via `POST /verify/v2` (or `POST /v1/verify/v2`). Dry-run: no nonce registered, no anomaly counter incremented, no audit entry written, no AI call made. Returns a per-step result array.

**Verification Pipeline**
The same enforcement pipeline as the execution pipeline, but using dry-run stores that do not mutate Redis state. Used by the `/verify` endpoint.

**Verification Portal**
A public-facing web interface (`GET /portal`) for verifying artifact authenticity offline. The portal accepts a raw artifact and public key and produces a verification result without making any server-side calls.

---

## W

**WAL (Write-Ahead Log)**
A pattern used by the audit chain writer. Before appending a final audit entry, a WAL record is written. On crash recovery, incomplete WAL records are detected and discarded. This ensures the audit chain contains only complete entries.

**Webhook**
An HTTP callback registered via `POST /v1/webhooks` that QODIQA calls when specific events occur (e.g., `sign.created`, `verify.failed`, `policy.blocked`). Webhook payloads are signed with HMAC-SHA256 using a per-endpoint secret. Delivery includes automatic retry with exponential backoff and a circuit breaker.

**JWKS (JSON Web Key Set)**
The format used by `GET /.well-known/qodiqa/keys` to expose active public keys. QODIQA's JWKS format follows RFC 7517 conventions adapted for Ed25519 (`kty: "OKP"`, `crv: "Ed25519"`).

---

