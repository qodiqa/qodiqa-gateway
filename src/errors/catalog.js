'use strict';

/**
 * QODIQA Machine-Readable Error Catalog.
 *
 * Single source of truth for the core enforcement/protocol reason
 * vocabulary — the `reason` codes returned by the `/ai/chat`, `/verify`,
 * and `/sign` decision pipeline (the `{decision, reason, details,
 * requestId}` envelope documented in docs/protocol/QODIQA-PROTOCOL.md — the superseded
 * QODIQA-PROTOCOL-SPEC.md §14.6/§14.7 is historical, API-10). Published in the OpenAPI document as the top-level
 * x-qodiqa-error-catalog (src/openapi/generator.js).
 *
 * Before this file existed, this same vocabulary was independently
 * maintained in three places that could (and did) drift:
 *   - src/reasons.js — a partial, machine-checked subset (~29 codes)
 *   - docs/architecture/enforcement-flow.md's "Complete decision table" — a second,
 *     hand-written table with additional codes
 *   - docs/operations/troubleshooting.md's "Quick-reference: reason codes and HTTP status"
 *     — a third, hand-written table, the most complete of the three
 *
 * This module is now that single source. src/reasons.js re-exports a
 * subset of it (see that file), docs/operations/troubleshooting.md and docs/architecture/enforcement-flow.md
 * point at it instead of duplicating the table, and
 * src/errors/__tests__/catalog.governance.test.js fails the build if this
 * catalog and src/reasons.js (or the values it's checked against) ever
 * disagree.
 *
 * Scope boundary (deliberate, not an oversight): this catalog covers only
 * the core protocol/enforcement reason vocabulary above. It does NOT also
 * catalog the management/admin API's per-route error codes (`BAD_REQUEST`,
 * `CANNOT_MODIFY_BUILTIN`, `USERNAME_TAKEN`, and the many others scattered
 * across src/api/routes/*.js) in the same flat namespace, for a concrete
 * reason: at least one code string — `INTERNAL_ERROR` — is legitimately
 * overloaded between the two domains (403 here, as a Step-5 policy-engine
 * pre-check failure; 500 in the generic src/api/response.js
 * `internalError()` fallback used broadly across the management API).
 * Merging both domains into one map would force a false choice between two
 * real, simultaneously-correct meanings. Cataloging the management API's
 * codes is a reasonable follow-up, but deserves its own envelope-scoped
 * catalog (or a `{ domain, code }` composite key) rather than being forced
 * into this one — see WP-030-REMEDIATION-REPORT.md for the full rationale.
 *
 * @typedef {object} CatalogEntry
 * @property {number} httpStatus
 * @property {string} description  Human-readable, one sentence.
 * @property {string} category     Pipeline stage this code originates from.
 * @property {boolean} retryable   Whether a client should retry (with
 *   backoff) rather than treat this as a terminal failure requiring a
 *   request change.
 */

/** @type {Record<string, CatalogEntry>} */
const ERROR_CATALOG = Object.freeze({
  // ── Success ───────────────────────────────────────────────────────────────
  ALL_CHECKS_PASSED: { httpStatus: 200, category: 'success', retryable: false,
    description: 'Every enforcement check passed; the request may execute.' },

  // ── Input guard ───────────────────────────────────────────────────────────
  INVALID_REQUEST_BODY: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: 'The request body failed basic shape validation.' },
  MISSING_PROMPT: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: 'No prompt was supplied in the request body.' },
  PROMPT_TOO_LARGE: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: 'The prompt exceeds the configured maximum size.' },
  // ── Multi-turn conversations ─────────────────────────────────────────
  PROMPT_AND_MESSAGES: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: send either `prompt` or `messages` (with optional `system`), not both.' },
  INVALID_MESSAGES: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: `messages` must be a non-empty array of { role: system|user|assistant, content: non-empty string } objects and nothing else.' },
  INVALID_SYSTEM: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: `system` must be a non-empty string.' },
  MESSAGES_TOO_MANY: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: more than 50 messages.' },
  MESSAGE_TOO_LARGE: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: one message (or `system`) exceeds 32 768 UTF-8 bytes.' },
  MESSAGES_TOO_LARGE: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: the whole conversation exceeds 131 072 UTF-8 bytes (the server MAX_BODY_BYTES is a separate, earlier bound).' },
  LAST_MESSAGE_NOT_USER: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: the last message of a conversation must be the user turn.' },
  STREAM_TOOLS_UNSUPPORTED: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/ai/chat: tool fields (tools, tool_choice, functions, function_call) are not supported on a streaming request; tool calls go through the action API.' },

  // ── Artifact decode ───────────────────────────────────────────────────────
  MISSING_ARTIFACT: { httpStatus: 200, category: 'artifact_decode', retryable: false,
    description: 'No signed artifact was supplied in the x-qodiqa-artifact header.' },
  ARTIFACT_TOO_LARGE: { httpStatus: 413, category: 'artifact_decode', retryable: false,
    description: 'The base64-decoded artifact exceeds the configured maximum size.' },
  ARTIFACT_DECODE_FAILED: { httpStatus: 200, category: 'artifact_decode', retryable: false,
    description: 'The artifact header could not be base64/JSON-decoded.' },
  ARTIFACT_INVALID_TYPE: { httpStatus: 200, category: 'artifact_decode', retryable: false,
    description: 'The decoded artifact was not a JSON object.' },

  // ── Artifact validation (Step 1) ──────────────────────────────────────────
  INVALID_ARTIFACT: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact failed schema/field validation.' },
  INVALID_SIGNATURE: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The Ed25519 signature does not verify against the claimed public key.' },
  KEY_NOT_FOUND: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The public key ID referenced by the artifact is not registered.' },
  KEY_REVOKED: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The public key referenced by the artifact has been revoked. Emitted by the key-lifecycle check (src/validation/keyLifecycle.js) — revoked keys never verify (API-09: the earlier "not currently emitted" note was stale).' },
  EXPIRED: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact\'s expiry timestamp has passed.' },
  FUTURE_TIMESTAMP: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact\'s timestamp is implausibly far in the future.' },
  TIME_SKEW_EXCEEDED: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact\'s timestamp is outside the allowed clock-skew tolerance.' },
  INVALID_EXPIRY: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact\'s expiry field is malformed or logically invalid (e.g. before its own timestamp).' },

  // ── Request binding (Step 2) ──────────────────────────────────────────────
  REQUEST_MISMATCH: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The actual request (method/path/body) does not match what the artifact was signed for.' },

  // ── Replay protection (Step 3) ────────────────────────────────────────────
  REPLAY_DETECTED: { httpStatus: 200, category: 'replay', retryable: false,
    description: 'The artifact\'s nonce has already been consumed.' },
  NONCE_STORE_ERROR: { httpStatus: 200, category: 'replay', retryable: true,
    description: 'The nonce store (Redis) was unreachable — fails closed rather than risking a replay.' },

  // ── Anomaly detection (Step 4) ────────────────────────────────────────────
  ANOMALY_DETECTED: { httpStatus: 200, category: 'anomaly', retryable: false,
    description: 'The request tripped a signature-burst or rate-burst anomaly heuristic.' },

  // ── Policy enforcement (Step 5) ───────────────────────────────────────────
  POLICY_STATE_UNAVAILABLE: { httpStatus: 200, category: 'policy', retryable: true,
    description: 'The policy engine\'s backing state (e.g. Redis-backed counters) was unreachable.' },
  INTERNAL_ERROR: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'An unexpected exception occurred during Step 5 policy pre-checks. Note: the generic src/api/response.js internalError() helper used broadly across the management API also uses this same code string at HTTP 500 for unrelated failures — see this file\'s "Scope boundary" note above.' },
  INVALID_CONTEXT: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'The policy evaluation context was malformed.' },
  NO_POLICIES_LOADED: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'No policies are loaded — fails closed rather than allowing everything through.' },
  NO_ENABLED_POLICIES: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'Every loaded policy is disabled — fails closed.' },
  EVALUATOR_MISSING: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A policy references an evaluator type with no registered implementation.' },
  EVALUATOR_ERROR: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A policy evaluator threw during evaluation — fails closed.' },
  RESIDENCY_CROSS_REGION_BLOCKED: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A DATA_RESIDENCY policy forbids processing in the region of the provider this request (or its failover target) would use.' },
  RESIDENCY_PROVIDER_REGION_UNKNOWN: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A DATA_RESIDENCY policy is in force and the provider has no declared region: unknown is not allowed (fail closed).' },
  RESIDENCY_PROVIDER_UNKNOWN: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A DATA_RESIDENCY policy could not determine which provider the request is for.' },
  CONSENT_MISSING: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A REQUIRE_CONSENT policy found no matching consent record.' },
  IP_BLOCKED: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A BLOCK_IP policy matched the caller\'s IP address.' },
  IP_MISSING: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A BLOCK_IP policy could not determine the caller\'s IP address.' },
  OUTSIDE_TIME_WINDOW: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A TIME_WINDOW policy denied the request outside its configured allowed hours.' },
  TIMESTAMP_MISSING: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A TIME_WINDOW policy could not resolve a timestamp to evaluate against.' },
  RATE_LIMIT_EXCEEDED: { httpStatus: 200, category: 'policy', retryable: true,
    description: 'A RATE_LIMIT policy denied the request for exceeding its configured threshold.' },
  RATE_LIMIT_KEY_MISSING: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A RATE_LIMIT policy could not resolve a key to rate-limit on.' },
  POLICY_BLOCKED: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A policy evaluator denied the request via its generic fallback reason (no more specific code applies).' },

  // ── Consent (policy enforcement detail) ──────────────────────────────────
  // correction: these 9 codes (all but
  // CONSENT_VERIFICATION_FAILED) are produced by ONE evaluator,
  // services/policy/evaluators/requireConsent.js, and are genuinely
  // overloaded across two call sites the same way INTERNAL_ERROR is (see
  // "Scope boundary" above): as a Step-5 REQUIRE_CONSENT policy result
  // inside /ai/chat's pipeline they resolve through aiChat.js's
  // _blockStatus() to HTTP 200 (httpStatus below reflects this, their
  // primary/designed context, alongside their sibling CONSENT_MISSING in
  // the policy category above); but POST /consent/verify
  // (src/api/routes/consent.js) wraps ANY of `result.reason` from the same
  // evaluator in a literal, always-403 response regardless of which
  // specific code applies. CONSENT_VERIFICATION_FAILED is /consent/verify's
  // own fallback only, never produced by /ai/chat, and stays genuinely 403.
  CONSENT_STORE_UNAVAILABLE: { httpStatus: 200, category: 'consent', retryable: true,
    description: 'The consent registry (Postgres) was unreachable — fails closed. 403 via POST /consent/verify instead — see the category note above.' },
  // the consent verifier's own store-failure code (ConsentVerifier.js); 503 in BLOCK status mode.
  CONSENT_STORE_ERROR: { httpStatus: 200, category: 'consent', retryable: true,
    description: 'The consent store failed while evaluating consent — fails closed. In QODIQA_BLOCK_HTTP_MODE=status it is a dependency_unavailable 503.' },
  CONSENT_NOT_FOUND: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'No consent record exists for the (actor, action, tenant) triple. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_REVOKED: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The matching consent record has been revoked. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_EXPIRED: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The matching consent record has passed its expiry. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_SUSPENDED: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The matching consent record is temporarily suspended. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_NOT_ACTIVE: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The matching consent record is in a state other than ACTIVE (generic fallback). 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_SCOPE_MISMATCH: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The consent record\'s scope does not cover the requested action\'s required scope. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_SCOPE_MISSING: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The policy requires a scope but the consent record has none recorded. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_CONTEXT_INCOMPLETE: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The request context lacked fields (e.g. actor_id) needed to evaluate consent. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_EVALUATION_ERROR: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'An unexpected error occurred while evaluating the REQUIRE_CONSENT policy. 403 via POST /consent/verify instead — see the category note above.' },
  CONSENT_VERIFICATION_FAILED: { httpStatus: 403, category: 'consent', retryable: false,
    description: 'Generic fallback reason for POST /consent/verify only when no more specific consent code applies — never produced by /ai/chat, genuinely 403, not overloaded.' },

  // ── Rate limiting (system-level, distinct from RATE_LIMIT policy above) ──
  RATE_LIMITED: { httpStatus: 429, category: 'system', retryable: true,
    description: 'The system-level rate limiter (distinct from a RATE_LIMIT policy) rejected the request; honor the Retry-After header.' },
  // emitted as the flat 429 body's `error` code by src/core/rateLimit/middleware.js when the
  // limiter's store is unreachable and the surface's failMode is 'closed' (src/core/rateLimit/config.js: auth, /sign, admin).
  RATE_LIMIT_BACKEND_UNAVAILABLE: { httpStatus: 429, category: 'system', retryable: true,
    description: 'The protocol rate limiter could not reach its store and this surface fails closed; the request was refused before the handler ran. Honor the Retry-After header.' },

  // ── Semantic policy engine (Step 5.5) ─────────────────────────────────────
  // SEMANTIC_REASONS values (SECURITY_OVERRIDE_ATTEMPT, CREDENTIAL_EXTRACTION,
  // JAILBREAK_ATTEMPT, and others defined in fixtures/redTeamCorpus.js and
  // the semantic policy engine) are a separate, larger, versioned vocabulary,
  // all at HTTP 200 (correction, 2026-09-13 -- verified against
  // src/api/routes/aiChat.js's _blockStatus(), which returns 200 for every
  // BLOCK reason not in IDEMPOTENCY_BLOCK_REASONS, semantic reasons included;
  // this comment previously said 403, stale since the remediation) with
  // audit stage SEMANTIC_POLICY — intentionally not enumerated individually
  // here; see src/core/policy/semantic/.

  // ── Provider execution ─────────────────────────────────────────────────────
  MISSING_PROVIDER: { httpStatus: 400, category: 'provider', retryable: false,
    description: 'No AI provider was specified and none could be auto-resolved (more than one is enabled).' },
  PROVIDER_MODEL_NOT_ALLOWED: { httpStatus: 400, category: 'provider', retryable: false,
    description: 'The requested model is not in the provider\'s configured allow-list.' },
  PROVIDER_INVALID_REQUEST: { httpStatus: 400, category: 'provider', retryable: false,
    description: 'The provider rejected the request as malformed.' },
  PROVIDER_REQUEST_REJECTED: { httpStatus: 400, category: 'provider', retryable: false,
    description: 'The provider rejected the request for a policy reason on their side (e.g. content filtering).' },
  PROVIDER_RESPONSE_INVALID: { httpStatus: 502, category: 'provider', retryable: true,
    description: 'The provider returned a response QODIQA could not parse.' },
  PROVIDER_UNAVAILABLE: { httpStatus: 503, category: 'provider', retryable: true,
    description: 'The provider was unreachable or returned a 5xx.' },
  PROVIDER_RATE_LIMITED: { httpStatus: 503, category: 'provider', retryable: true,
    description: 'The provider itself rate-limited this request.' },
  PROVIDER_AUTH_FAILED: { httpStatus: 503, category: 'provider', retryable: false,
    description: 'The provider rejected QODIQA\'s own credentials — an operator configuration issue, not transient.' },
  PROVIDER_TIMEOUT: { httpStatus: 504, category: 'provider', retryable: true,
    description: 'The provider did not respond within AI_CHAT_TIMEOUT_MS.' },
  REQUEST_TIMEOUT: { httpStatus: 504, category: 'provider', retryable: true,
    description: 'Alias of PROVIDER_TIMEOUT used in some call paths — same meaning.' },
  // 503 (was 500) — a missing provider is a dependency/configuration outage, not a server bug.
  PROVIDER_CIRCUIT_OPEN: { httpStatus: 503, category: 'provider', retryable: true,
    description: 'The provider circuit breaker is open after repeated provider failures — fails fast, with Retry-After.' },
  PROVIDER_HEALTH_DEGRADED: { httpStatus: 503, category: 'provider', retryable: true,
    description: 'Health-aware routing has marked the provider degraded — fails fast, with Retry-After.' },
  PROVIDER_NOT_CONFIGURED: { httpStatus: 503, category: 'provider', retryable: false,
    description: 'The requested provider has no credentials/configuration on this deployment — an operator setup issue.' },
  PROVIDER_CONFIG_INVALID: { httpStatus: 500, category: 'provider', retryable: false,
    description: 'The provider\'s configuration failed validation at request time — an operator setup issue.' },
  PROVIDER_INVALID_RESPONSE: { httpStatus: 500, category: 'provider', retryable: false,
    description: 'Adapter-level: the provider SDK/client returned a shape the adapter could not normalize.' },

  // ── System ────────────────────────────────────────────────────────────────
  BYPASS_ATTEMPT: { httpStatus: 403, category: 'system', retryable: false,
    description: 'The request attempted to invoke the execution path without going through enforcement.' },
  AUDIT_PERSISTENCE_FAILED: { httpStatus: 503, category: 'system', retryable: true,
    description: 'The mandatory audit write failed after a successful provider execution — a real evidence gap requiring operator follow-up (see docs/security/SECURITY_GUIDE.md).' },

  // ── Idempotency (aiChat.js's idempotency gate — API-9 remediation) ───────
  IDEMPOTENCY_KEY_TOO_LARGE: { httpStatus: 413, category: 'idempotency', retryable: false,
    description: 'The Idempotency-Key header (or its raw byte length) exceeds the configured maximum.' },
  IDEMPOTENCY_KEY_INVALID: { httpStatus: 400, category: 'idempotency', retryable: false,
    description: 'The Idempotency-Key is empty, contains disallowed characters, or was sent as a repeated header.' },
  IDEMPOTENCY_KEY_CONFLICT: { httpStatus: 409, category: 'idempotency', retryable: false,
    description: 'The same key was reused with a request whose fingerprint differs from the original (API-9: was 422, now 409 — a conflict, not a business-rule violation).' },
  IDEMPOTENCY_REQUEST_IN_PROGRESS: { httpStatus: 409, category: 'idempotency', retryable: true,
    description: 'A concurrent request under the same key is still executing.' },
  IDEMPOTENCY_STORE_UNAVAILABLE: { httpStatus: 503, category: 'idempotency', retryable: true,
    description: 'The idempotency store (Redis) is unreachable — fails closed only for requests that supply the header.' },
  IDEMPOTENCY_STREAMING_UNSUPPORTED: { httpStatus: 400, category: 'idempotency', retryable: false,
    description: 'An Idempotency-Key was supplied together with "stream": true, which this gate does not support.' },
  // ── API-09: every enforcement BLOCK reason in src/api/blockHttpStatus.js and every
  // protocol-surface literal the /ai/chat and /sign routes return is catalogued. Previously 45 inventory reasons and
  // 9 route literals were missing. src/errors/__tests__/catalogCompleteness.test.js now fails the build if either set
  // gains a code this catalog lacks. httpStatus is the DEFAULT (`decision`) mode status for an enforcement BLOCK
  // (200); the `status`-mode class status is in blockHttpStatus.js and in the generated spec (x-qodiqa-error-catalog).

  // Artifact decode / validation
  INVALID_JSON: { httpStatus: 200, category: 'artifact_decode', retryable: false,
    description: 'The artifact header decoded, but its content is not valid JSON.' },
  NOT_OBJECT: { httpStatus: 200, category: 'artifact_decode', retryable: false,
    description: 'The decoded artifact (or a signed event) is not a JSON object.' },
  MISSING_SIGNATURE: { httpStatus: 200, category: 'artifact_decode', retryable: false,
    description: 'The artifact carries no signature.' },
  MALFORMED_REQUEST_ID: { httpStatus: 200, category: 'replay', retryable: false,
    description: 'The artifact requestId (its nonce) is not a well-formed identifier, so replay protection cannot register it.' },
  VERSION_MISMATCH: { httpStatus: 200, category: 'artifact_decode', retryable: false,
    description: 'The artifact declares a format version this gateway does not accept.' },
  SIGNATURE_UNVERIFIABLE: { httpStatus: 200, category: 'validation', retryable: true,
    description: 'The signature could not be checked at all (the verifying key material or keyring was unavailable) — fails closed; distinct from INVALID_SIGNATURE.' },
  KEY_ARCHIVED: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The signing key is archived; archived keys never verify.' },
  KEY_DEPRECATED: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The signing key is deprecated and the artifact falls outside the deprecated-key verification window (signed before retirement, within 65 s of it).' },
  KEY_NOT_YET_ACTIVE: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The signing key is not active yet.' },
  KEY_NOT_ACTIVE_AT_SIGNING_TIME: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact claims a signing time at which its key was not active (before the key existed, or after its retirement).' },
  KEY_STATUS_UNKNOWN: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The signing key has no recognised lifecycle status — fails closed.' },
  SIGNING_TIME_UNKNOWN: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact signing time could not be determined, so the key lifecycle check cannot be applied — fails closed.' },
  MISSING_TIMESTAMP: { httpStatus: 200, category: 'validation', retryable: false,
    description: 'The artifact (or a signed control event) has no timestamp.' },

  // Policy
  POLICY_DENIED: { httpStatus: 200, category: 'policy', retryable: false,
    description: 'A policy rule with a DENY effect matched the request.' },

  // Tenant / caller identity
  TENANT_UNKNOWN: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The tenant named by the artifact or signing identity is not registered.' },
  TENANT_INACTIVE: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The tenant exists but is not active.' },
  TENANT_SUSPENDED: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The tenant is suspended.' },
  TENANT_CONTEXT_MISSING: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'No tenant could be attributed to the request — fails closed.' },
  ORG_SUSPENDED: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The organization the tenant belongs to is suspended.' },
  ORG_DISABLED: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The organization the tenant belongs to is disabled.' },
  SIGNING_IDENTITY_REVOKED: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The signing identity that requested the artifact has been revoked since signing.' },
  SCOPE_PROVIDER_DENIED: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The signing identity is not allowed to target this provider (its allowedProviders scope).' },
  IDENTITY_PERMISSION_DENIED: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The signing identity lacks the SIGN_ARTIFACT permission required for the operation.' },
  NO_CALLER_IDENTITY: { httpStatus: 200, category: 'tenant_identity', retryable: false,
    description: 'The artifact carries no authenticated caller identity (callerContext), which the operation requires.' },
  ACTOR_DECOMMISSIONED: { httpStatus: 200, category: 'consent', retryable: false,
    description: 'The actor\'s consents were revoked in bulk (actor decommissioned).' },

  // Output limit
  BUDGET_EXCEEDED_REQUESTS: { httpStatus: 429, category: 'budget', retryable: true,
    description: 'The request quota of a BUDGET rule for the period is used up; the provider was not called.' },
  BUDGET_EXCEEDED_TOKENS: { httpStatus: 429, category: 'budget', retryable: true,
    description: 'The token quota of a BUDGET rule for the period would be exceeded by this request (charged with an upper estimate); the provider was not called.' },
  BUDGET_EXCEEDED_COST: { httpStatus: 429, category: 'budget', retryable: true,
    description: 'The money budget of a BUDGET rule for the period would be exceeded by this request (estimated at the tariff of the rule); the provider was not called.' },
  BUDGET_REQUEST_TOO_LARGE: { httpStatus: 200, category: 'budget', retryable: false,
    description: 'The estimated tokens of the request exceed the per-request limit of a BUDGET rule.' },
  BUDGET_REQUEST_TOO_COSTLY: { httpStatus: 200, category: 'budget', retryable: false,
    description: 'The estimated cost of the request exceeds the per-request limit of a BUDGET rule.' },
  BUDGET_UNAVAILABLE: { httpStatus: 200, category: 'budget', retryable: true,
    description: 'A BUDGET rule is in force and its counters could not be reached: the request is refused rather than run uncounted.' },
  CONTENT_RULE_BLOCKED: { httpStatus: 200, category: 'content_rule', retryable: false,
    description: 'A custom content rule of the tenant (word list, phrase list or pattern) reached its threshold in the request or in the answer; details.contentRule names the rule and the item ids, never the matched text.' },
  CONTENT_RULE_UNAVAILABLE: { httpStatus: 200, category: 'content_rule', retryable: true,
    description: 'A custom content rule could not scan the text completely (for example it is longer than the bound of the pattern engine): the request is refused rather than run unchecked.' },
  CONTENT_RULE_STREAMING_UNSUPPORTED: { httpStatus: 200, category: 'content_rule', retryable: false,
    description: 'An output-direction content rule needs the whole answer, which a stream does not have; repeat the request without stream.' },
  DLP_BLOCKED: { httpStatus: 200, category: 'dlp', retryable: false,
    description: 'A DLP rule with action BLOCK found sensitive data in the request or in the answer (details.dlp names the direction and the rule ids, never the values).' },
  DLP_UNAVAILABLE: { httpStatus: 200, category: 'dlp', retryable: false,
    description: 'A DLP rule is configured but cannot run (module not installed, or REDACT without QODIQA_DLP_TOKEN_KEY): the request is refused rather than forwarded unprotected.' },
  DLP_OUTPUT_STREAMING_UNSUPPORTED: { httpStatus: 200, category: 'dlp', retryable: false,
    description: 'An output-direction DLP rule needs the whole answer, which a stream does not have; repeat the request without stream.' },
  OUTPUT_TOO_LARGE: { httpStatus: 200, category: 'output_limit', retryable: false,
    description: 'The provider output exceeded the output-classification cap and was withheld, never released unclassified.' },

  // Dependencies (fail closed)
  REPLAY_STATE_UNPROVABLE: { httpStatus: 200, category: 'replay', retryable: true,
    description: 'Replay protection could not prove the nonce unused (the nonce store answered too late or ambiguously) — fails closed.' },
  REDIS_UNAVAILABLE: { httpStatus: 200, category: 'system', retryable: true,
    description: 'Redis, required for replay protection and limits, is unavailable — fails closed.' },
  ORG_STATUS_SYNC_UNAVAILABLE: { httpStatus: 200, category: 'tenant_identity', retryable: true,
    description: 'The organization-status synchronisation channel is unavailable, so an org suspension cannot be ruled out — fails closed.' },
  ORG_STATUS_STALE: { httpStatus: 200, category: 'tenant_identity', retryable: true,
    description: 'The organization-status view is older than its staleness bound — fails closed.' },
  SEMANTIC_INSPECTION_UNAVAILABLE: { httpStatus: 200, category: 'semantic', retryable: true,
    description: 'The semantic inspection engine is unavailable, so content cannot be inspected — fails closed.' },

  // Semantic content decisions (src/core/semantic/reasons.js — catalogued here, not changed)
  SECURITY_OVERRIDE_ATTEMPT: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: an attempt to override security instructions.' },
  PROMPT_INJECTION_ATTEMPT: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: prompt injection.' },
  SYSTEM_PROMPT_EXTRACTION: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: an attempt to extract the system prompt.' },
  POLICY_BYPASS_ATTEMPT: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: an attempt to bypass policy.' },
  JAILBREAK_ATTEMPT: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: jailbreak.' },
  TOOL_ABUSE_ATTEMPT: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: tool abuse.' },
  UNAUTHORIZED_TOOL_REQUEST: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: a request for an unauthorized tool.' },
  DATA_EXFILTRATION: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: data exfiltration.' },
  CREDENTIAL_EXTRACTION: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: credential extraction.' },
  PII_EXTRACTION: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: personal-data extraction.' },
  MEMORY_EXTRACTION: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: memory / context extraction.' },
  FILE_SYSTEM_ENUMERATION: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: file-system enumeration.' },
  IMPERSONATION_ATTEMPT: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: impersonation.' },
  EMBEDDING_SIMILARITY_MATCH: { httpStatus: 200, category: 'semantic', retryable: false,
    description: 'Semantic content decision: the prompt matched a known-attack anchor by embedding similarity.' },

  // Route literals (/ai/chat, /sign, admission)
  UNSUPPORTED_FIELD: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: 'The /ai/chat body used a refused provider-shaping field (messages, system, tools, tool_choice, functions, function_call, response_format).' },
  MODEL_TOO_LARGE: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: 'The model identifier exceeds its maximum length.' },
  SERVER_OVERLOADED: { httpStatus: 503, category: 'system', retryable: true,
    description: 'Admission control refused the request before nonce registration (queue full, wait expired, or the audit mirror backlog above its bound); always sent with Retry-After. Safe to resend the same artifact after Retry-After.' },
  CLASSIFICATION_BUDGET_EXHAUSTED: { httpStatus: 429, category: 'system', retryable: true,
    description: 'The caller exhausted its semantic-classification budget; honor the Retry-After header.' },
  INVALID_METHOD: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/sign: request.method is not one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.' },
  PATH_TOO_LONG: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/sign: request.path exceeds 2048 UTF-8 bytes.' },
  BODY_TOO_DEEP: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/sign: request.body nests deeper than 10 levels.' },
  SCOPE_ENVIRONMENT_MISMATCH: { httpStatus: 403, category: 'tenant_identity', retryable: false,
    description: '/sign: the signing identity is scoped to a different environment than this gateway.' },
  AUDIT_UNREPRESENTABLE_TEXT: { httpStatus: 422, category: 'system', retryable: false,
    description: 'A request-derived value (U+0000 or a lone surrogate) cannot be represented in the audit stores; refused before anything was persisted or executed.' },

  // /sign and its signing-credential middleware (src/api/routes/sign.js, src/middleware/signAuth.js)
  SIGNED: { httpStatus: 200, category: 'success', retryable: false,
    description: '/sign: the audit reason recorded when an artifact was issued.' },
  METHOD_NOT_ALLOWED: { httpStatus: 405, category: 'input_guard', retryable: false,
    description: 'The protocol route does not accept this HTTP method.' },
  INVALID_REQUEST: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/sign: the request to be signed could not be canonicalised or bound.' },
  INVALID_TTL: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/sign: ttl is not a positive finite number (a valid ttl above 60 s is clamped, not refused).' },
  // ── Protocol V2 ───────────────────────────────────────────────────────────
  UNSUPPORTED_PROTOCOL_VERSION: { httpStatus: 400, category: 'validation', retryable: false,
    description: 'The artifact carries a protocol-V2 block (payload.qodiqa) with a version this gateway does not accept (V2 acceptance is off, or v is not 2).' },
  PROTOCOL_VERSION_TOO_LOW: { httpStatus: 403, category: 'validation', retryable: false,
    description: 'The artifact uses a protocol version below the minimum configured for the tenant or the gateway (QODIQA_PROTOCOL_MIN_VERSION / minProtocolVersion).' },
  UNSUPPORTED_CRITICAL_CLAIM: { httpStatus: 400, category: 'validation', retryable: false,
    description: 'The artifact marks a claim as critical (qodiqa.crit) that this verifier does not understand.' },
  WRONG_ARTIFACT_KIND: { httpStatus: 403, category: 'validation', retryable: false,
    description: 'The artifact kind (qodiqa.kind) is not the kind this endpoint accepts.' },
  RESERVED_CLAIM: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/sign: the payload contains the reserved claim name "qodiqa" (or a look-alike); caller data belongs under claims.' },
  QUERY_NOT_BINDABLE: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: '/sign: the query string contains a raw "+" or ";" and cannot be bound unambiguously; use %20, %2B or %3B.' },
  // ── Per-artifact revocation ───────────────────────────────────────────────────────────────────────────────
  ARTIFACT_REVOKED: { httpStatus: 403, category: 'validation', retryable: false,
    description: 'An operator revoked this artifact (by its requestId) before it was used. It is refused before its nonce is consumed; request a new artifact from /sign.' },
  ARTIFACT_REVOCATION_STATE_UNAVAILABLE: { httpStatus: 503, category: 'validation', retryable: true,
    description: 'The per-artifact revocation store could not answer, so the request was refused rather than assumed not revoked.' },
  // ── Global kill switch ───────────────────────────────────────────────────────────────────────────────────
  KILL_SWITCH_ACTIVE: { httpStatus: 503, category: 'validation', retryable: true,
    description: 'The global kill switch is active: /sign and /ai/chat refuse every request until an operator releases it. Nothing was signed, no nonce was consumed and no provider was called.' },
  KILL_SWITCH_STATE_UNAVAILABLE: { httpStatus: 503, category: 'validation', retryable: true,
    description: 'The kill-switch state could not be determined (the control-plane snapshot is older than its 5 s bound), so the request was refused rather than assumed allowed.' },
  PROVIDER_REQUIRED: { httpStatus: 400, category: 'provider', retryable: false,
    description: '/sign: no provider was given and more than one is enabled, so none can be inferred.' },
  PROVIDER_NOT_SUPPORTED: { httpStatus: 400, category: 'provider', retryable: false,
    description: '/sign: the requested provider is not one this gateway supports.' },
  KEY_UNAVAILABLE: { httpStatus: 503, category: 'system', retryable: true,
    description: '/sign: the tenant signing key could not be loaded — nothing is signed.' },
  POLICY_UNAVAILABLE: { httpStatus: 503, category: 'system', retryable: true,
    description: '/sign: the enforced policy set (whose hash the artifact carries) is unavailable — nothing is signed.' },
  SIGNING_FAILED: { httpStatus: 500, category: 'system', retryable: false,
    description: '/sign: the signing operation itself failed (local key or native KMS/HSM signer).' },
  UNAUTHORIZED: { httpStatus: 401, category: 'auth', retryable: false,
    description: 'No valid credential was presented.' },
  API_KEY_EXPIRED: { httpStatus: 401, category: 'auth', retryable: false,
    description: 'The presented API key has expired.' },
  FORBIDDEN: { httpStatus: 403, category: 'auth', retryable: false,
    description: 'The authenticated credential lacks the permission this route requires.' },
  AUTH_LOCKED_OUT: { httpStatus: 429, category: 'auth', retryable: true,
    description: 'Too many failed authentication attempts from this source; locked out for the lockout window.' },
  AUTH_BACKEND_UNAVAILABLE: { httpStatus: 503, category: 'auth', retryable: true,
    description: 'The authentication backend (lockout store / credential store) is unavailable — fails closed.' },

  // protocol-surface codes that were emitted but never catalogued — found by widening
  // catalogCompleteness EC-02 to src/app.js, middleware/enforceContentType.js and the `case` / `.code =` / `||`
  // literal shapes. Statuses are what the server sends today (no runtime change).
  MALFORMED_JSON: { httpStatus: 400, category: 'input_guard', retryable: false,
    description: 'The request body is not parseable JSON — refused by the app-level body parser before any route runs (src/app.js).' },
  // Launch plan R-15: an oversize body was previously answered 400 MALFORMED_JSON.
  PAYLOAD_TOO_LARGE: { httpStatus: 413, category: 'input_guard', retryable: false,
    description: 'The request body exceeds the configured size limit (MAX_BODY_BYTES, default 64 KiB) — refused by the app-level body parser before any route runs (src/app.js).' },
  UNSUPPORTED_MEDIA_TYPE: { httpStatus: 415, category: 'input_guard', retryable: false,
    description: 'A POST/PUT/PATCH protocol request whose Content-Type is not application/json (middleware/enforceContentType.js).' },
  NOT_FOUND: { httpStatus: 404, category: 'input_guard', retryable: false,
    description: 'No route matches this protocol or probe path (the BLOCK-shaped 404 of src/app.js).' },
  PROVIDER_CANCELLED: { httpStatus: 504, category: 'provider', retryable: true,
    description: 'Provider execution was cancelled by the route-level timeout (AI_CHAT_TIMEOUT_MS) before or while it was dispatched — the outcome is unknown to the client.' },
  PROVIDER_ERROR: { httpStatus: 200, category: 'provider', retryable: true,
    description: 'Streaming only: the terminal stream_cancelled reason when the provider stream failed without a more specific code (inside the HTTP 200 text/event-stream response).' },
  TRANSPARENCY_PERSISTENCE_FAILED: { httpStatus: 503, category: 'system', retryable: true,
    description: 'The mandatory transparency-log write failed — the request is refused fail-closed (same contract as AUDIT_PERSISTENCE_FAILED).' },
  TRANSPARENCY_JOURNAL_UNAVAILABLE: { httpStatus: 503, category: 'system', retryable: true,
    description: 'neither the transparency recovery queue nor its file journal has been able to take a leaf for longer than QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS, so new executions are refused before the provider is called (Retry-After: 30). BLOCK decisions are unaffected.' },
  CONTROL_PLANE_STALE: { httpStatus: 503, category: 'system', retryable: true,
    description: 'The control-plane snapshot is stale or unavailable, so a control-plane-dependent check fails closed instead of being skipped.' },
});

module.exports = { ERROR_CATALOG };
