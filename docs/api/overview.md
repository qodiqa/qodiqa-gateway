# QODIQA API Reference

Complete reference for every HTTP endpoint exposed by QODIQA. Endpoints are grouped by
function. All endpoints return `Content-Type: application/json` unless noted otherwise.

**Authentication:**
- **Public endpoints**: no authentication required.
- **Client enforcement endpoints** (`/ai/chat`, `/verify`): authenticated by the request
  artifact. **`/sign`**: authenticated by a per-identity signing API key
  (`Authorization: Bearer sk_...`) — see below.
- **Operator endpoints**: require a **per-operator RBAC API key**
  (`Authorization: Bearer ok_<64 hex>`). RBAC is unconditional: there is no flag that turns it
  off (`server/startup.js`; the former `QODIQA_RBAC_ENABLED` wording was inaccurate). The first key is issued out of band
  with `npm run rbac:bootstrap-key`; further operators come from `/rbac`. The deprecated shared
  `Authorization: Bearer <QODIQA_OPS_TOKEN>` authenticates but carries no RBAC identity. It is
  accepted only on `/metrics` and `/diagnostics`; every RBAC-gated route (`/audit`, `/consent`,
  `/rbac`, `/key-admin`, …) answers it with `403 FORBIDDEN` (`test/actor-identity-binding.test.js`).

- **Contract coverage note:** the generated `docs/api/openapi.json`
  under-documents `429` (rate-limited admin/ops routes) and `405` (method catch-alls). Generated
  clients should expect both on any route even where the spec does not list them.

**Versioning:** Only the core protocol routes are dual-mounted (`/ai/chat`, `/ai/chat/stream`, `/verify`,
`/verify/v2`, the portal, transparency and evidence-package surfaces — 27 paths). Several surfaces exist only
unversioned (`/sign`, `/consent`, `/audit`, `/rbac`, `/key-admin`, …) or only under `/v1`
(`/v1/webhooks`, `/v1/admin/*`, …). `docs/api/openapi.json` is the authoritative path list.

Where a route is dual-mounted, e.g. `POST /ai/chat` and `POST /v1/ai/chat`, the two are identical — `/v1` is a
cosmetic alias today (single API version; see `docs/api/versioning.md` for the full
rationale and what changes when a real `/v2` is introduced). Individual routes may be
independently marked deprecated ahead of removal via `Deprecation`/`Sunset`/`Link`
response headers — see `docs/api/versioning.md`'s Deprecation/Sunset section and
`CHANGELOG.md` for the release history of such changes.

**Related documents:**
- `docs/api/versioning.md` — `/v1` aliasing rationale, deprecation/Sunset mechanism
- `src/errors/catalog.js` — machine-readable catalog of every core `reason` code (HTTP status, description, category, retryability)
- `docs/architecture/enforcement-flow.md` — enforcement pipeline detail
- `docs/architecture/verification-flow.md` — verification pipeline detail
- `docs/guides/providers.md` — full AI provider reference (capabilities, limits, error codes per provider)
- `docs/configuration/reference.md` — configuration options
- `docs/glossary.md` — term definitions
- `docs/security/SECURITY_GUIDE.md` — authentication and authorization

---

## Response Envelopes

QODIQA's response surface is scoped by family, not reducible to one or two shapes — a
client MUST NOT assume one family's shape applies to another. The two families documented
immediately below (core protocol, management API) are the two most common by endpoint count,
but they are not the complete set: well-known key discovery, infrastructure probes, the
alerting API, and the shutdown-drain middleware each have their own distinct, intentional
shape (see "Full envelope taxonomy and governance" below for the authoritative, currently
15-type registry — the definitive current count, not restated here as a number in prose
that can drift out of sync with it again).

**Core protocol surface** (`/ai/chat`, `/v1/ai/chat`, `/ai/chat/stream`, `/verify`,
`/v1/verify`, `/sign`, `/.well-known/*`) uses the normative
`{decision, reason, details, requestId}` shape documented endpoint-by-endpoint below and
in §14.6/§14.7. This shape is conformance-tested and consumed by
the published SDKs; it is not affected by the management envelope described next.

**Full envelope taxonomy and governance:** `src/api/response.js`'s header comment is the
authoritative, machine-checked specification of every response envelope used in this API
(management, enforcement, well-known, infrastructure-probe, and the documented pre-existing
exceptions), backed by the `src/api/responseEnvelopes.js` registry and enforced by
`src/api/__tests__/responseEnvelopeGovernance.test.js` — a route file cannot introduce a new,
undocumented response shape without failing that test. See those files for the complete,
current list; this document summarizes the shapes relevant to each endpoint below.

**Management API envelope** — every other endpoint in this document (audit, key
administration, transparency log, policy, consent, RBAC, webhooks, multi-tenant
administration, and similar operational routes) returns exactly one of these two shapes,
built by `src/api/response.js`:

Success:
```json
{
  "status":    "success",
  "timestamp": "<ISO-8601>",
  "requestId": "<string-or-null>",
  "data":      { }
}
```

Failure:
```json
{
  "status":    "error",
  "timestamp": "<ISO-8601>",
  "requestId": "<string-or-null>",
  "error": {
    "code":    "<string>",
    "message": "<string>",
    "details": { }
  }
}
```

`error.details` is only present when the route supplied additional structured context; it
is never a required field. This is the shape a generic client should use to parse the
response body of every endpoint under "Audit Endpoints" through "Multi-Tenant
Administration" below — where an individual endpoint's example response predates this
envelope, treat the shown object as the value of `data` (on success) or fold it into
`error`/`error.details` (on failure), not as the literal top-level response body.

`GET /health`, `GET /ready`, `GET /metrics`, and `GET /diagnostics` are a third, deliberately
minimal case — see "Infrastructure Endpoints" below — and do not use either envelope above.

**A third protocol-family shape exists internally, but never reaches a client.** The pure
policy core (`services/policy/evaluatePolicyDecision.js`) has its own `ENFORCEMENT_ERROR`
result shape for two defensive cases — the policy set failing to load (`POLICY_LOAD_ERROR`)
or the evaluation engine itself throwing (`POLICY_ENGINE_ERROR`). Neither code is ever
client-visible: `checkPolicy.js` — the single shared adapter both `/ai/chat` and `/verify`
call — collapses either case to the ordinary `200 {decision:"BLOCK", reason:"POLICY_BLOCKED", ...}`
shape (2026-08-14 — both routes now agree on 200; formerly `/ai/chat` alone returned 403
here), discarding the more specific internal reason (it's preserved only in server-side audit
logs). This is a second, distinct, genuinely-live route to the `POLICY_BLOCKED` string — see
the note on that code in the block-reason table below, which is reachable via this path even
though the *other* documented trigger for the same string is not.

**Same code, different envelope, depending on which layer produced it — not a defect, a
cross-cutting pattern in this API worth knowing before writing generic error-handling code:**
`UNAUTHORIZED` itself is one example — `opsAuth` (operator/management endpoints) wraps it in
the management envelope above; `signAuth` (`POST /sign`) wraps the identical string in the
core protocol envelope instead. See [Operator Authentication Errors](#operator-authentication-errors)
and `POST /sign`'s own reason table. The `CONSENT_*` codes and the rate-limit codes have the
same property, each documented with its own callout where it's introduced below.

---

## Operator Authentication Errors

Every operator/management endpoint below (Audit, Key Administration, Transparency admin,
Policy, Consent, RBAC, Webhook, and Multi-Tenant Administration endpoints) is gated by two
layers ahead of its own permission check, both returning the [management API
envelope](#response-envelopes):

**Layer 1 — credential resolution** (`error.code`, all HTTP 401 unless noted):

| Code | Cause |
|------|-------|
| `UNAUTHORIZED` | `Authorization` header missing |
| `UNAUTHORIZED` | Operator-key store lookup failed (corrupted/unreadable store file — not a Redis dependency; the operator-key store is a synchronous in-memory/file-JSON lookup) |
| `UNAUTHORIZED` | Credential resolves to a disabled operator account |
| `UNAUTHORIZED` | Token doesn't resolve to any known operator identity or valid `QODIQA_OPS_TOKEN` |
| `AUTH_LOCKED_OUT` | 429 — repeated authentication failures tripped the lockout threshold for this credential |

**Layer 2 — RBAC permission check** (only reached once Layer 1 resolves an identity; always applies; all HTTP 403):

| Code | Cause |
|------|-------|
| `RBAC_RESOLVE_NO_IDENTITY` (surfaced as `FORBIDDEN`) | No resolved operator identity when the RBAC-resolve middleware runs |
| `RBAC_NOT_RESOLVED` (surfaced as `FORBIDDEN`) | Permission check ran without the resolve middleware having run first (defensive) |
| `ENGINE_ERROR` (surfaced as `FORBIDDEN`) | RBAC permission-evaluation engine threw (defensive) |
| `INSUFFICIENT_ROLE` (surfaced as `FORBIDDEN`) | Identity resolved to a valid role, but that role lacks the specific permission the endpoint requires (e.g. `READ_AUDIT`, `MANAGE_KEYS` — see each endpoint group's own heading above for its required permission) |

A successful check produces no distinct body of its own — the request simply proceeds to the
endpoint's own handler and response.

---

## Enforcement Endpoints

These endpoints form the core enforcement pipeline. No operator authentication is required.

---

### `POST /ai/chat`

Execute an AI request through the full enforcement pipeline.

**Authentication**: Artifact-based (X-Qodiqa-Artifact header)

**Request headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | Must be `application/json` |
| `X-Qodiqa-Artifact` | Yes | Base64-encoded signed artifact JSON. Max 8,192 bytes. |
| `Idempotency-Key` | No | Opaque client-generated retry token. See [Idempotent retries](#idempotent-retries) below and `docs/architecture/IDEMPOTENCY_KEY.md`. |

**Request body:**

```json
{
  "prompt": "string (required)",
  "model":  "string (optional — see below)",
  "stream": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `prompt` | string | Yes | The user's message to the AI provider. |
| `model` | string | No | Model identifier. Validated against the per-provider allowed-model list. If omitted, resolved via a **per-provider** default (`services/providers/config.js#resolveDefaultModel()`) — `openai` ships the built-in default `gpt-3.5-turbo` (operator-overridable via `PROVIDER_DEFAULT_MODEL_OPENAI`). `anthropic`, `gemini` and `mistral` have no built-in default, so omitting `model` for a request bound to a different provider (`artifact.payload.provider`) fails with `PROVIDER_MODEL_NOT_ALLOWED` unless the operator has configured one (`PROVIDER_DEFAULT_MODEL_<PROVIDER_NAME>`) — see `docs/guides/providers.md` §6 "Model allowlist extensibility and default model". |
| `stream` | boolean | No | Set `true` for streaming SSE response. Defaults to `false`. |
| `messages` | array | No (instead of `prompt`) | A multi-turn conversation: 1..50 objects `{ "role": "system"|"user"|"assistant", "content": "<non-empty string>" }` and nothing else; each content <= 32,768 UTF-8 bytes, the whole conversation <= 131,072 bytes (the server's `MAX_BODY_BYTES` is an earlier, separate bound); the **last** message must be role `user`. |
| `system` | string | No (only with `messages`) | System instruction; becomes the first message. |

**Multi-turn.** Send either `prompt` or `messages` (+ optional `system`); both together is `400 PROMPT_AND_MESSAGES`. Everything the model reads is part of the signed request body, so **changing, adding, dropping or reordering any turn after signing invalidates the artifact**. QODIQA does not keep conversation state: the caller sends the whole history each time. Every role is screened by the semantic engine - a `system` or `assistant` turn supplied by the caller is as untrusted as a user turn - and a block names the role and position (`details.semantic.conversation`). Invalid shapes give `400` with `INVALID_MESSAGES`, `INVALID_SYSTEM`, `MESSAGES_TOO_MANY`, `MESSAGE_TOO_LARGE`, `MESSAGES_TOO_LARGE` or `LAST_MESSAGE_NOT_USER`. Tool fields (`tools`, `tool_choice`, `functions`, `function_call`, `response_format`) are still refused (`UNSUPPORTED_FIELD`; on a streaming request the tool fields give `400 STREAM_TOOLS_UNSUPPORTED`). `QODIQA_MULTI_TURN_ENABLED=false` restores the single-prompt-only behaviour. Not yet covered: provenance marking of external content and re-screening after transformations.

**Response — 200 EXECUTE:**

```json
{
  "decision":   "EXECUTE",
  "reason":     "ALL_CHECKS_PASSED",
  "response":   "AI provider response text",
  "artifactId": "uuid",
  "keyId":      "clientId:key_v1",
  "requestId":  "<uuid-v4>",
  "transparency": {
    "transparencyId":    "uuid",
    "entryHash":         "hex-sha256",
    "leafHash":          "hex-sha256",
    "signerKeyId":       "tr-clientId:key_v1",
    "persisted":         true,
    "merkleRoot":        null,
    "treeSize":          null,
    "signedTreeHeadRef": null,
    "inclusionProofRef": "/transparency/proof/<transparencyId>"
  },
  "aiDisclosure": {
    "aiGenerated": true,
    "provider":    "openai",
    "model":       "gpt-4o-mini",
    "notice":      "This response was generated by an AI system."
  }
}
```

**`aiDisclosure` — end-user AI disclosure.**

- **What carries it.** Every EXECUTE response carries this block, and the header
  `X-QODIQA-AI-Generated: true`. BLOCK responses carry neither.
- **The notice.** `notice` is the tenant's published wording (tenant semantic
  config `disclosureNotice`, 1–280 characters, set through the governed publish
  path) or the platform default shown above. Display it to the end user.
- **Streaming.** The SSE `stream_started` event carries the same block.

**`transparency.persisted` — check this field.** `true` means the
signed transparency entry was durably written to PostgreSQL (durable-evidence
deployment); `false` means the entry was **signed but not persisted** — the
deployment is sign-only, nothing survives the process, and no inclusion proof
or signed root will ever cover this decision. The response shape is otherwise
byte-identical in both postures, so this field is the only honest per-decision
signal. the production profile (`NODE_ENV=production`) refuses to
boot in the sign-only posture, so `persisted: false` can only appear in
non-production deployments — treat it in clients as an assertion failure for
any evidentiary workflow. The same `persisted` field appears on
`POST /v1/transparency/register` and `POST /v1/transparency/admin/roots/generate`
responses. See docs/operations/deployment-runbook.md §13
("Durable-evidence vs sign-only deployments").

**Response — 200 BLOCK:**

Every policy/verification BLOCK — `Validation` and `Policy` stage reasons below, plus 3 of
the 4 `Artifact decode` stage reasons (`MISSING_ARTIFACT`, `ARTIFACT_DECODE_FAILED`,
`ARTIFACT_INVALID_TYPE` — earlier-pipeline-depth duplicates of the same verification
failure `INVALID_ARTIFACT` checks; `ARTIFACT_TOO_LARGE` is the one exception, still 413) —
resolves as an ordinary 200 response: `decision: 'BLOCK'` is a value the caller reads, not
an HTTP error. This matches `/verify`'s own long-standing always-200-for-a-pipeline-outcome
contract (see `POST /verify` below). The enforcement OUTCOME is unchanged — a BLOCK still
means the AI provider is never called — only the HTTP envelope moved off 403. `Input guard`,
`Execution`, `Post-execution`, and `Pipeline` stage reasons below are unaffected by this
change and keep their own distinct non-200 status (input validation, provider errors,
audit/transparency persistence failures, timeouts) — see each row's own status below.

```json
{
  "decision":  "BLOCK",
  "reason":    "REASON_CODE",
  "details":   {},
  "requestId": "<uuid-v4>"
}
```

**Optional per-class status mode.** Setting `QODIQA_BLOCK_HTTP_MODE=status` (default `decision` = the 200 contract above; any other value is refused at boot) keeps the identical body but carries the block class in the HTTP status:

| status | reasons |
|---|---|
| 400 | malformed artifact: MISSING_ARTIFACT, ARTIFACT_DECODE_FAILED, ARTIFACT_INVALID_TYPE |
| 403 | invalid artifact (signature, key, time), REQUEST_MISMATCH, ANOMALY_DETECTED, consent, policy, tenant/org/identity, request and output semantics, OUTPUT_TOO_LARGE |
| 409 | REPLAY_DETECTED |
| 429 | RATE_LIMIT_EXCEEDED (policy rate rule; no `Retry-After`, the rule's decision carries no window) |
| 503 | dependency unavailable: NONCE_STORE_ERROR, CONSENT_STORE_UNAVAILABLE, POLICY_STATE_UNAVAILABLE, ORG_STATUS_STALE / _SYNC_UNAVAILABLE, SEMANTIC_INSPECTION_UNAVAILABLE |
| 500 | internal evaluation errors (INTERNAL_ERROR, EVALUATOR_ERROR, …) |

The full table is in `src/api/blockHttpStatus.js`.
- **Never 401 or 429 for non-throttles**, because the SDKs map 401 to AuthenticationError and auto-retry 429.
- **Unchanged in both modes:** the statuses that were already non-200 (413, 429 RATE_LIMITED, 429 CLASSIFICATION_BUDGET_EXHAUSTED, 503 SERVER_OVERLOADED, 503 CONTROL_PLANE_STALE, idempotency, input guard, provider errors, timeouts). Also a BLOCK decided after SSE headers were flushed: it stays an in-band `stream_cancelled` event on the 200 stream.
- **SDK note:** in `status` mode the SDKs *throw* the typed error for a BLOCK instead of returning the body.

**Response — 400 Invalid request:**

Returned when the request body fails schema validation or the artifact header is malformed.

**Response — 504 Timeout:**

Returned when the enforcement pipeline exceeds `AI_CHAT_TIMEOUT_MS`. Reason: `REQUEST_TIMEOUT`.

**Timeouts and the audit record.** The 504 is sent as soon as the timer fires; the work already
in flight is aborted (its `AbortSignal` reaches the provider adapter) and records its outcome in the background:

- Timeout **before or during** the provider call, or **after** it but before the ALLOW entry is appended (during the
  output-side semantic check or the representability check): the decision is recorded as `BLOCK`, reason
  `REQUEST_TIMEOUT`, `completionStatus: CANCELLED` — never ALLOW. The cancellation is checked right after the provider
  returns and again immediately before the ALLOW append (no `await` between that check and the append).
- **Residual divergence window:** a timeout that fires *while* the ALLOW entry is being appended, or during the
  transparency registration that follows it, still answers 504 — but the ALLOW/EXECUTE decision is already durably
  recorded, and an append-only chain cannot withdraw it. The window is the duration of those two writes (single-digit
  to tens of milliseconds on a healthy store), not the provider call. A client that receives 504 must therefore treat
  the outcome as **unknown**, not as "not executed": the audit record `GET /audit/{artifactId}` is authoritative — use the `artifactId` returned by `/sign`; the `requestId` in this 504 body is the per-request trace id (`X-Request-ID`).

**Response — 503 Service unavailable:**

Returned when Redis is unavailable (fail-closed). Reason: `REDIS_UNAVAILABLE`.

**Response — 503 Server overloaded:**

Admission control refuses a request when the route family is at its in-flight limit and the FIFO wait queue is full, or the wait exceeded its timeout: `503 {"decision":"BLOCK","reason":"SERVER_OVERLOADED","details":{},"requestId":...}` with `Retry-After` (seconds), in both block-HTTP modes. The check runs before schema validation, artifact decode, signature verification and nonce registration, so a refusal writes nothing to the audit chain or the transparency log, never reaches a provider, and **leaves the artifact nonce unconsumed** — the same artifact may be retried after `Retry-After` (it is not a replay). `/sign` has its own family. Limits: `QODIQA_ADMISSION_AI_CHAT_MAX_INFLIGHT` / `QODIQA_ADMISSION_AI_CHAT_QUEUE` (default 16 / 32), `QODIQA_ADMISSION_SIGN_MAX_INFLIGHT` / `QODIQA_ADMISSION_SIGN_QUEUE` (64 / 128), `QODIQA_ADMISSION_AI_CHAT_QUEUE_TIMEOUT_MS` / `QODIQA_ADMISSION_SIGN_QUEUE_TIMEOUT_MS` (1000 ms each), `QODIQA_ADMISSION_RETRY_AFTER_SEC` (1). `/ready` reports the `admission` component not ready while any family is saturated.

**Which surfaces have admission control:** `/sign`, `/ai/chat` (+ `/ai/chat/stream`), `/verify` and `/verify/v2`, the agent action surface `/v1/actions/*`, and the tool gateway `/v1/tools/call` — each family with its own limit (`QODIQA_ADMISSION_<FAMILY>_*` in `docs/configuration/reference.md`), so a stalled tool call cannot use up the slots of `/verify` or `/sign`. The refusal is always the 503 above, answered before authentication, parsing and any write; `GET /ready` reports not-ready while any family's queue is full.

**Response — 429 Classification budget exhausted:**

Every tenant has a classification budget in embedding windows (one window per 400 characters, then one more per 350; refill `QODIQA_CLASSIFY_BUDGET_REFILL_PER_SEC` = 2,000/s, burst `QODIQA_CLASSIFY_BUDGET_BURST` = 20,000). A prompt whose windows exceed the tenant's remaining budget is refused before it is classified: `429 {"decision":"BLOCK","reason":"CLASSIFICATION_BUDGET_EXHAUSTED",...}` with `Retry-After`, no audit entry, no provider call. The prompt is never truncated. Provider output is always classified and charged afterwards (bounded debt, never refused).

**Output classification cap:** provider output longer than `QODIQA_OUTPUT_CLASSIFY_MAX_CHARS` (65,536) is withheld, never released truncated or unclassified: non-stream → BLOCK `OUTPUT_TOO_LARGE` (200, or 403 in `status` mode), audited as an output block; stream → `stream_cancelled` with reason `OUTPUT_TOO_LARGE` at the chunk that would cross the cap (everything forwarded before it was classified).

**Response — 503 Service shutting down:**

Returned by the request-drain middleware (`src/runtime/requestDrain.js`) for any request received after graceful shutdown has begun — before the request reaches this endpoint's own handler, so no `decision`/`reason` fields are present:

```json
{
  "success": false,
  "error": {
    "code":    "SERVICE_SHUTTING_DOWN",
    "message": "Service unavailable"
  }
}
```

This is the canonical shutdown response, identical for every endpoint except `/health`, `/ready`, `/metrics`, and `/diagnostics` (mounted ahead of the drain middleware).

**Block reason codes:**

| Code | Stage | Cause |
|------|-------|-------|
| `INVALID_REQUEST_BODY` | Input guard | Request body fails Zod schema validation (fallback for any failure not covered by the two specific codes below) |
| `MISSING_PROMPT` | Input guard | `prompt` absent, `null`, empty, or whitespace-only |
| `PROMPT_TOO_LARGE` | Input guard | `prompt` exceeds 32,768 UTF-8 bytes |
| `MODEL_TOO_LARGE` | Input guard | `model` field exceeds its max length |
| `MISSING_ARTIFACT` | Artifact decode | `X-Qodiqa-Artifact` header absent |
| `ARTIFACT_TOO_LARGE` | Artifact decode | Header exceeds 8,192 bytes |
| `ARTIFACT_DECODE_FAILED` | Artifact decode | Header is not valid base64 JSON |
| `ARTIFACT_INVALID_TYPE` | Artifact decode | Decoded JSON is not a plain object |
| `INVALID_ARTIFACT` | Validation | Decoded artifact fails structural validation — not a strict 5-key object, an unrecognized field, a missing/`undefined` required field (at any depth), `timestamp`/`expiry` not a positive finite number, `signature` not valid base64 of the correct length, `publicKeyId` empty, or envelope canonicalization threw. This is a distinct, earlier check from `ARTIFACT_INVALID_TYPE` above — a decoded artifact can be "a plain object" (passing that check) and still fail this one. |
| `INVALID_SIGNATURE` | Validation | Ed25519 signature verification failed, **or** the signing key could not be resolved — deliberately indistinguishable from a bad signature (an unresolved key must not be a distinguishing oracle for an attacker); see `docs/security/SECURITY_GUIDE.md`. `validateArtifact.js`'s own header comment additionally names a `KEY_NOT_FOUND` reason for the key-unresolved case — that code is not emitted anywhere in the codebase and should be treated as historical/aspirational documentation inside that file, not a real wire-visible outcome. |
| `EXPIRED` | Validation | `artifact.expiry < Date.now()`. Emitted at two distinct pipeline depths with the identical code and client experience: the primary check in artifact validation (`timeCheck.js`), and a defensive pre-store re-check immediately before nonce registration (`registerNonce.js`) that guards against clock drift between the two points. A caller cannot distinguish which depth produced a given `EXPIRED` response, and does not need to. |
| `FUTURE_TIMESTAMP` | Validation | `artifact.timestamp > now + 5 000 ms` (`FUTURE_SKEW_MS`; checked after signature verification) |
| `TIME_SKEW_EXCEEDED` | Validation | `now - artifact.timestamp > MAX_SKEW_MS` (backward drift only; `MAX_SKEW_MS` is a hardcoded 60,000 ms constant in `src/validation/timeCheck.js`, not an environment variable). Checked only *after* signature verification succeeds, and preempts nonce/anomaly/policy checks entirely if it blocks. |
| `REQUEST_MISMATCH` | Validation | Request hash does not match artifact payload (covers a malformed artifact/request/hash shape, a canonicalization failure, or — the common case — a timing-safe hash comparison mismatch) |
| `MALFORMED_REQUEST_ID` | Validation | `requestId` is not a UUID v4 |
| `INVALID_EXPIRY` | Validation | Nonce-registration `expiryMs` is not finite/positive |
| `REPLAY_DETECTED` | Validation | Nonce already registered in Redis |
| `NONCE_STORE_ERROR` | Validation | Nonce store unavailable (Redis not ready) or any other store exception. Fails closed, no fallback. |
| `ANOMALY_DETECTED` | Validation | Sliding-window threshold exceeded, or the anomaly store is unavailable (`type` in details: `SIGNATURE_BURST`, `RATE_BURST`, or `STORE_ERROR`) |
| `TENANT_UNKNOWN` | Validation | Resolved tenant is not registered. In practice unreachable via live traffic today for any validly-signed artifact — `payload.tenantId` is always server-derived from the verified signer's own tenant at `/sign` time, so a signature can only ever verify for a tenant that already exists. |
| `TENANT_SUSPENDED` | Validation | Tenant status is `suspended` |
| `TENANT_INACTIVE` | Validation | Tenant status is `disabled`, `inactive`, or any other non-`active` value |
| `ORG_STATUS_SYNC_UNAVAILABLE` | Validation | Organization-status pub/sub subscriber not yet ready (only applies to tenants linked to an organization — see [Multi-Tenant Administration](#multi-tenant-administration)) |
| `ORG_STATUS_STALE` | Validation | Organization-status cache older than the max propagation window (5 s). while the pub/sub subscription has stayed connected since the last confirmation and no reconcile sweep has failed since, a late sweep is tolerated for a further `QODIQA_ORG_STATUS_GRACE_MS` (default 5 s; 0 disables) — status changes on a live subscription are pushed immediately |
| `ORG_SUSPENDED` | Validation | Linked organization status is `suspended` |
| `ORG_DISABLED` | Validation | Linked organization status is `disabled` |
| `NO_POLICIES_LOADED` | Policy | Policy set is empty |
| `NO_ENABLED_POLICIES` | Policy | Policy set is non-empty but no policy has `enabled: true` |
| `INVALID_CONTEXT` | Policy | Policy-evaluation context object failed internal validation (defensive) |
| `EVALUATOR_MISSING` | Policy | A configured policy's `type` does not match any registered evaluator (`REQUIRE_CONSENT`, `BLOCK_IP`, `TIME_WINDOW`, `RATE_LIMIT`) |
| `EVALUATOR_ERROR` | Policy | A policy evaluator threw during evaluation (defensive) |
| `POLICY_STATE_UNAVAILABLE` | Policy | Policy store in unexpected state |
| `INTERNAL_ERROR` | Policy | Unexpected error during policy evaluation |
| `IP_MISSING` | Policy (`BLOCK_IP`) | `BLOCK_IP` policy configured, but no client IP available in the request context |
| `IP_BLOCKED` | Policy (`BLOCK_IP`) | Client IP matches an exact blocklist entry or an IPv4 CIDR range |
| `TIMESTAMP_MISSING` | Policy (`TIME_WINDOW`) | `TIME_WINDOW` policy configured, but no usable timestamp in the request context |
| `OUTSIDE_TIME_WINDOW` | Policy (`TIME_WINDOW`) | Current UTC day/minute falls outside every configured window |
| `RATE_LIMIT_KEY_MISSING` | Policy (`RATE_LIMIT` evaluator) | The context field the policy rate-limits by is falsy. Distinct from the route-level rate-limit gate — see [Rate Limiting](#rate-limiting) below. |
| `RATE_LIMIT_EXCEEDED` | Policy (`RATE_LIMIT` evaluator) | Policy-level rate limit exceeded, or the backing store threw (fails closed, treated as over-limit). Distinct code from the route-level rate-limit gate's own codes — see [Rate Limiting](#rate-limiting) below, including ambiguity note. |
| `CONSENT_MISSING` | Policy (`REQUIRE_CONSENT`) | `REQUIRE_CONSENT` policy configured and the request's artifact carries no valid consent context |
| `CONSENT_CONTEXT_INCOMPLETE` | Policy (`REQUIRE_CONSENT`) | `actorId` or `action` absent from the consent-evaluation context |
| `CONSENT_EVALUATION_ERROR` | Policy (`REQUIRE_CONSENT`) | Consent registry lookup threw (defensive) |
| `CONSENT_REVOCATION_SYNC_UNAVAILABLE` | Policy (`REQUIRE_CONSENT`) | Consent-revocation pub/sub subscriber started but not yet ready — fails closed on a possibly-stale cached ALLOW |
| `CONSENT_STORE_UNAVAILABLE` | Policy (`REQUIRE_CONSENT`) | Consent store (Postgres) not enabled/connected |
| `CONSENT_STORE_ERROR` | Policy (`REQUIRE_CONSENT`) | Consent store lookup threw |
| `CONSENT_NOT_FOUND` | Policy (`REQUIRE_CONSENT`) | No consent record for the `(actorId, action, tenantId)` key. **`action` must be the exact provider string** — see the callout under [Consent Endpoints](#consent-endpoints). |
| `CONSENT_REVOKED` | Policy (`REQUIRE_CONSENT`) | Consent record's effective state is `REVOKED` |
| `CONSENT_EXPIRED` | Policy (`REQUIRE_CONSENT`) | Consent record's effective state is `EXPIRED` (stored as `EXPIRED`, or `ACTIVE` with a lapsed `expiresAt`) |
| `CONSENT_SUSPENDED` | Policy (`REQUIRE_CONSENT`) | Consent record's effective state is `SUSPENDED` and not yet past `suspendedUntil` |
| `CONSENT_NOT_ACTIVE` | Policy (`REQUIRE_CONSENT`) | Consent record's effective state is `PENDING` |
| `CONSENT_SCOPE_MISMATCH` | Policy (`REQUIRE_CONSENT`) | Record is otherwise `ACTIVE` but its granted scope doesn't cover the required scope. A more specific `CONSENT_SCOPE_MISSING` internal string exists but is never surfaced as its own top-level `reason` — it appears only as free text inside this code's `details`. |
| `POLICY_BLOCKED` | Policy | **Live via one path, dead via another — same code, do not assume either cause.** Genuinely reachable when the policy engine's own wrapper fails closed: the policy set fails to load, or the evaluation engine itself throws (both defensive/infra-adjacent, internally logged as `POLICY_LOAD_ERROR`/`POLICY_ENGINE_ERROR` respectively, but that distinction is discarded before the client ever sees it — see the envelope note above). **Not** reachable today as a per-evaluator generic fallback (an evaluator returning a non-passing result with no specific `reason` string) — all 4 currently-registered evaluators (`REQUIRE_CONSENT`, `BLOCK_IP`, `TIME_WINDOW`, `RATE_LIMIT`) always return one of the specific reason codes above; that fallback path only exists for a hypothetical 5th evaluator not following the same contract. |
| `MISSING_PROVIDER` | Execution | `artifact.payload.provider` absent or empty — a defense-in-depth check; `POST /sign` (see below) already refuses to mint an `/ai/chat`-bound artifact without a resolvable provider, so this should only occur for artifacts not obtained via `/sign` |
| `PROVIDER_MODEL_NOT_ALLOWED` | Execution | Model not in the provider's allowlist (`services/providers/config.js`) |
| `PROVIDER_INVALID_REQUEST` | Execution | Outbound request failed adapter payload validation (missing/empty messages, disallowed role, non-string content) — checked both pre-flight and post-dispatch (HTTP 400/422 from the provider) |
| `PROVIDER_REQUEST_REJECTED` | Execution | Outbound request exceeded adapter size limits (>50 messages or >32,768 bytes of content) |
| `PROVIDER_RESPONSE_INVALID` | Execution | Provider returned unexpected response format (route-level check) |
| `PROVIDER_TIMEOUT` | Execution | AI provider call timed out |
| `PROVIDER_CANCELLED` | Execution | The in-flight outbound provider call, or a still-pending dispatch, was aborted (client disconnect, or the route-level timeout signal fired) |
| `PROVIDER_UNAVAILABLE` | Execution | AI provider returned 5xx, a network error occurred, or the provider name is unregistered |
| `PROVIDER_RATE_LIMITED` | Execution | AI provider returned 429 |
| `PROVIDER_AUTH_FAILED` | Execution | AI provider returned 401/403 |
| `PROVIDER_NOT_CONFIGURED` | Execution | Provider is registered but not enabled (required API key or base URL env var unset) |
| `PROVIDER_CONFIG_INVALID` | Execution | A configured provider base URL (`MISTRAL_BASE_URL`, `LLAMA_BASE_URL`, `LOCAL_BASE_URL`) failed URL/SSRF validation |
| `AUDIT_PERSISTENCE_FAILED` | Post-execution | The mandatory audit-chain write failed **after** an otherwise-successful provider call. Fails closed (503) even though the AI response was already generated — never silently returned as a 200 with an unaudited response. |
| `TRANSPARENCY_JOURNAL_UNAVAILABLE` | Pre-execution | the transparency evidence store (recovery queue and file journal) has been unavailable longer than `QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS` (default 60 s); new executions are refused before the provider is called, `Retry-After: 30`. BLOCK decisions keep being answered. |
| `TRANSPARENCY_PERSISTENCE_FAILED` | Post-execution | The mandatory transparency-log write failed after the audit write succeeded. Same fail-closed guarantee as `AUDIT_PERSISTENCE_FAILED`. |
| `REQUEST_TIMEOUT` | Pipeline | `AI_CHAT_TIMEOUT_MS` exceeded |

See also [Semantic Policy Engine](#semantic-policy-engine) below — a second, independent
content-inspection layer that can block `/ai/chat` requests (and provider responses) with its
own separate code taxonomy, and [Rate Limiting](#rate-limiting) for the route-level
(pre-policy) rate-limit gate, which is a distinct mechanism from the `RATE_LIMIT` policy
evaluator above.

**`POST /ai/chat` also returns `405 METHOD_NOT_ALLOWED`** for any non-`POST` method, in the
core protocol `{decision, reason, ...}` shape, the same as every other core-protocol route.

**Notes:**
- Every decision (EXECUTE or BLOCK) is written to the audit chain.
- The AI provider URL is never supplied by the caller. For `openai`, `anthropic`, and `gemini` it is hardcoded in the adapter; for `mistral` it defaults to `https://api.mistral.ai/v1` and can be overridden via `MISTRAL_BASE_URL`; for `llama` and `local` it is entirely operator-configured via `LLAMA_BASE_URL`/`LOCAL_BASE_URL`. See [Provider architecture](../../README.md).
- On a retryable failure (`PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_TIMEOUT`), the router attempts one failover hop to the provider named in `PROVIDER_FAILOVER_<PROVIDER_NAME>`, if configured, before the block reason above is returned to the caller.
- Streaming variant: set `"stream": true` in the request body. See `POST /ai/chat` (streaming).

#### Idempotent retries

Send `Idempotency-Key: <opaque-token>` on any `POST /ai/chat` request to make retries
safe (API-2). This is the mechanism to use when a request times out or the connection
drops before a response arrives: resending the *exact same logical request* under the
*same key* is guaranteed to invoke the AI provider **at most once** and always returns the
canonical outcome of the first successful attempt — never a second charge, a second
provider call, or a second audit artifact.

- **Optional** — omitting the header leaves every existing behavior completely unchanged.
- **Scope** — a key is meaningful only in combination with the exact request it was first
  used with (same authenticated tenant/identity, same provider, same body). Reusing a key
  with a materially different body is rejected, not silently executed and not silently
  replayed.
- **Not supported with `stream: true`** — see status table below.
- A successful replay echoes `Idempotency-Key` and adds `Idempotency-Replayed: true` on
  the response; a fresh (non-replayed) response with a key still echoes `Idempotency-Key`
  but omits `Idempotency-Replayed`.
- Full design (fingerprinting, storage, concurrency, retention, failure-state handling):
  **`docs/architecture/IDEMPOTENCY_KEY.md`**.

| Status | Reason | Cause |
|--------|--------|-------|
| 200 | — | Fresh execution, or a replay of a prior durably-completed execution (`Idempotency-Replayed: true`) |
| 400 | `IDEMPOTENCY_KEY_INVALID` | Key is empty, contains whitespace/control characters, or was sent as a repeated header |
| 413 | `IDEMPOTENCY_KEY_TOO_LARGE` | Key exceeds `IDEMPOTENCY_KEY_MAX_LENGTH` (default 255) or the raw header exceeds `IDEMPOTENCY_HEADER_MAX_BYTES` (default 1024) |
| 400 | `IDEMPOTENCY_STREAMING_UNSUPPORTED` | `Idempotency-Key` sent together with `"stream": true` |
| 409 | `IDEMPOTENCY_KEY_CONFLICT` | Same key reused with a request whose fingerprint (tenant + identity + provider + body) differs from the original |
| 409 | `IDEMPOTENCY_REQUEST_IN_PROGRESS` | A concurrent request under the same key is still executing and did not finish within `IDEMPOTENCY_WAIT_TIMEOUT_MS` (default 10,000 ms) |
| 503 | `IDEMPOTENCY_STORE_UNAVAILABLE` | The idempotency store (Redis) is unreachable — fails closed only for requests that supply the header |

**Client recommendation:** generate one key per logical user action (e.g. a UUID or
ULID), reuse it for every retry of that same action, and only for that action — a fresh
action needs a fresh key.

---

### `POST /ai/chat` (Streaming)

Same as `POST /ai/chat` with `"stream": true` in the request body. The enforcement pipeline
runs synchronously. If enforcement passes, the response switches to SSE.

**Response on enforcement failure (before stream opens):** identical to the non-streaming
block responses above (JSON, same status split — 200 for policy/verification BLOCKs).

**Response on enforcement success:** `Content-Type: text/event-stream`

**SSE event format:** every
frame carries a native `event:` field (matching the `event` property still
present in the JSON `data:` payload — kept for one deprecation cycle for
backward compatibility with existing clients) and a native `id:` field
(`<streamId>:<sequence>`, monotonically increasing) ahead of `data:`. The
first frame also carries a `retry: 3000` hint. This example was previously
stale relative to the actual implementation (`totalChunks` had been renamed
to `chunksTotal`, and a documented `stream_error` event type was never
actually emitted) — the example below reflects the real, current wire
format exactly, as verified by `test/streaming.test.js`:

```
retry: 3000
event: stream_started
id: 3f2a1c9e-...:0
data: {"event":"stream_started","streamId":"3f2a1c9e-...","requestId":"...","artifactId":"...","provider":"openai","model":"gpt-4o-mini","aiDisclosure":{"aiGenerated":true,"provider":"openai","model":"gpt-4o-mini","notice":"This response was generated by an AI system."}}

event: chunk_forwarded
id: 3f2a1c9e-...:1
data: {"event":"chunk_forwarded","delta":"token text","index":0}

event: stream_completed
id: 3f2a1c9e-...:2
data: {"event":"stream_completed","streamId":"3f2a1c9e-...","requestId":"...","chunksTotal":1,"bytesTotal":10,"durationMs":142}

id: 3f2a1c9e-...:3
data: [DONE]
```

On a non-normal termination, `stream_completed` above is replaced by a
`stream_cancelled` event (`{"event":"stream_cancelled","streamId":"...","reason":"<code>","requestId":"..."}`)
— there is no separate `stream_error` event type; provider errors also
surface as `stream_cancelled`. `[DONE]` is always the last frame and, per
OpenAI-style convention, deliberately has no native `event:` field of its
own. `reason` is one of:

| `reason` | Meaning |
|---|---|
| `STREAM_TIMEOUT` | Session exceeded `STREAM_MAX_DURATION_MS`. |
| `CLIENT_DISCONNECT` | The HTTP connection closed before the stream ended. |
| a provider error code | The provider call failed or was cancelled mid-stream. |
| `SEMANTIC_OUTPUT_BLOCKED` | A chunk itself completed a denied output-side pattern and was never forwarded — every chunk before it in this session was already sent. |
| `SEMANTIC_OUTPUT_BLOCKED_FINAL` | The **mandatory end-of-stream recheck** denied the complete response — but by this point every chunk had already been forwarded. See **Streaming output-safety contract**, below. |

**Notes:**
- The nonce is registered before the first SSE byte is written.
- A single audit record is written after the stream terminates.
- Stream is terminated after `STREAM_MAX_DURATION_MS` (default 5 minutes).
- If the HTTP connection closes before the stream ends, the stream is cancelled.
- Not every provider delivers true incremental streaming: `openai`, `anthropic`, `mistral`,
  `llama`, and `local` have a native streaming adapter; `gemini` does not, and a
  `stream: true` request to it is answered as one complete SSE chunk once generation
  finishes, not incrementally. See `docs/guides/providers.md` §5 for the full per-provider matrix.
- See `docs/architecture/streaming.md` for the full streaming design.

#### Streaming output-safety contract

Both response modes run the same output-side semantic/embedding
classification, but they deliver a **different effective
guarantee**:

- **Non-streaming** classifies the complete response before any of it is
  written to the HTTP response. A BLOCK means the caller receives zero bytes
  of that response — `response` is simply absent from the `{decision:'BLOCK',...}` body.
- **Streaming** forwards each chunk as it clears a bounded, interval-based
  check (classify-before-forward; zero-leak for the keyword layer at its
  default cadence, a bounded few-hundred-character leak for the embedding
  layer's coarser default cadence — see `docs/architecture/streaming.md` §15.6).
  A **mandatory** check re-scores the complete accumulated text once after
  the stream would otherwise complete normally (§15.7); if it denies the
  response, the terminal event becomes `stream_cancelled` with
  `reason: "SEMANTIC_OUTPUT_BLOCKED_FINAL"` and the audit/transparency
  record is written as `BLOCK` — but the content itself has **already been
  delivered** to the client. SSE has no mechanism to recall a byte already
  written to the connection; the durable record is truthful about the
  disposition (audit-truth), it does not suppress content that was already
  sent.

A caller or integration that requires a hard guarantee that no denied
content ever reaches the client should use the non-streaming endpoint.,
including why an optional buffered-streaming mode (full non-streaming parity
over SSE) was evaluated and not implemented.

---

### `POST /verify` or `POST /v1/verify`

Dry-run enforcement pipeline. Executes all six enforcement steps (2026-08-27: the
[Semantic Policy Engine](#semantic-policy-engine) is now included — see Step 6 below) but
makes no AI provider call and registers no nonce. Returns a per-step result.

**Authentication**: Artifact-based — but unlike `POST /ai/chat`, the artifact is not
carried in a header. See Request below.

**Request**: A JSON body with exactly two top-level keys — `{ "artifact": {...},
"request": {...} }` (`src/validation/schemas/verify.schema.js`'s `verifyBodySchema`,
`.strict()` — unrecognized keys are rejected). `artifact` is the full artifact object
returned by `POST /sign` (not base64-encoded, not a header). `request` is the same
`{method, path, body}` object that was signed.

**Response — 200 (any outcome), or 400 for malformed request body:**

```json
// EXECUTE
{
  "decision":   "EXECUTE",
  "reason":     "ALL_CHECKS_PASSED",
  "artifactId": "<uuid-v4 | null>",
  "keyId":      "acme-corp:key_v1",
  "callerId":   "<uuid-v4 | null>",
  "tenantId":   "acme-corp",
  "requestId":  "string"
}
```

```json
// BLOCK (steps 1–5)
{ "decision": "BLOCK", "reason": "string", "details": {}, "requestId": "string" }
```

```json
// BLOCK (step 6 — semantic)
{ "decision": "BLOCK", "reason": "string", "details": { "semantic": { "...": "..." } }, "requestId": "string" }
```

**`BLOCK` reason codes:** any Layer 1/1c/3/5 code from `POST /ai/chat`'s block-reason table
above can surface here too — `/verify` runs the identical `validateBoundRequest()` +
`checkPolicy()` pipeline, alias-normalized to the same code strings, against the SAME
tenant-effective policy set `/ai/chat` would use (a tenant's own governed policy set,
with the non-negotiable floor, applied — never the raw global set alone). The one
behavioral difference: nonce/anomaly checks and the `RATE_LIMIT` policy evaluator's counter
are **dry-run** here (see the Notes below) — a `REPLAY_DETECTED`/`RATE_LIMIT_EXCEEDED`
response from `/verify` reflects the *current* stored state, not a state this call itself
changed. Tenant/org gating (`TENANT_UNKNOWN`, `TENANT_SUSPENDED`, etc.) is **not** dry-run —
`/verify` reads live tenant/organization state directly, so those codes reflect real, current
status.

**Step 6 — Semantic Policy Engine.** After steps 1–5 all pass, `/verify` runs the
identical [Semantic Policy Engine](#semantic-policy-engine) pipeline `/ai/chat` runs on the
request `prompt` (same classifier engine, same embedding-similarity gate, same tenant
semantic-config overlay) — so `/verify` can no longer report `EXECUTE` for a request
`/ai/chat` would semantically `BLOCK`. On a semantic block, `reason` is one of that section's
content-match codes and `details.semantic` carries the same evidence shape `/ai/chat`'s audit
entry records for the identical verdict. **Side-effect-free**: this step never appends an
audit entry, never writes a transparency entry, never consumes consent, never calls an AI
provider, and never consumes rate-limit quota beyond `/verify`'s own outer rate limit —
unlike a real semantic block on `/ai/chat`, calling `/verify` leaves no evidentiary trace.
**Scope**: this step only runs when the bound request's body has a non-empty string
`prompt` field — `/verify` can validate an artifact bound to *any* endpoint (`request.path`
need not be `/ai/chat`), and `/ai/chat`'s own schema requires a `prompt` before a real
request would ever reach its semantic stage, so an artifact bound elsewhere (or with no
`prompt`) has no `/ai/chat` semantic verdict to predict and this step is skipped..

**`400` request-body reason codes** (distinct from the pipeline `BLOCK` codes above — these
mean the request never reached the pipeline at all):

| Code | Cause |
|------|-------|
| `MISSING_ARTIFACT` | Body's top-level `artifact` key is `null`/`undefined` |
| `INVALID_ARTIFACT_TYPE` | `artifact` present but not a plain object |
| `MISSING_REQUEST` | Body's top-level `request` key is `null`/`undefined` |
| `INVALID_REQUEST_TYPE` | `request` present but not a plain object |
| `UNEXPECTED_FIELDS` | Body has a top-level key other than `artifact`/`request` (`.strict()` schema) |
| `INVALID_ARTIFACT` | `artifact` exceeds the serialized size/depth limit |
| `INVALID_REQUEST` | `request` exceeds the serialized size/depth limit |
| `INVALID_REQUEST_BODY` | Fallback for any other body-schema failure |

Note: `MISSING_ARTIFACT`/`INVALID_ARTIFACT`/`INVALID_REQUEST_BODY` above reuse the identical
code strings as some `POST /ai/chat` codes but are triggered by a completely different check
(this endpoint's own JSON-body schema, not the header-based artifact decode `/ai/chat` uses)
— same string, different trigger, same client-facing meaning ("this input is malformed").

**Other non-pipeline responses:**

| Status | Code | Cause |
|--------|------|-------|
| 200 | `POLICY_STATE_UNAVAILABLE` | Policy store not wired at mount time |
| 200 | `INTERNAL_ERROR` | Pipeline timeout, or an unhandled throw from policy evaluation |
| 405 | `METHOD_NOT_ALLOWED` | Any HTTP method other than `POST` |

**Notes:**
- **Latency:** `/verify` now costs the semantic stage in addition to
  steps 1–5 — on this machine, the embedding-similarity gate alone (the more expensive of
  the two semantic sub-stages) measures mean 2.4ms / p95 3.3ms warm ** (`npm run
  test:embeddingSimilarity`'s D6 latency check; the keyword-classifier engine that runs
  before it is pure arithmetic, sub-millisecond). Skipped entirely (zero added cost) for a
  request whose body has no `prompt` field — see Step 6 above.
- The verify endpoint always returns HTTP 200 for any pipeline outcome (`EXECUTE` or
  `BLOCK`) — including `POLICY_STATE_UNAVAILABLE` and `INTERNAL_ERROR` above, which are
  still delivered inside the normal `{decision:"BLOCK", reason, ...}` body at 200, not as
  an HTTP error status; only a malformed request body (missing/wrong-typed `artifact` or
  `request`, or unrecognized top-level keys) returns 400.
  Use the `decision` field in the body to determine the pipeline outcome.
- No audit record is written.
- No nonce is registered (dry-run nonce/anomaly stores peek without incrementing —
  `src/api/routes/verify.js`).
- The rate-limit counter is not incremented either — `verify.js:171` wraps the
  policy store via `makeDryRunPolicyStore()` (`src/validation/dryRunStores.js`);
  its `checkAndIncrement()` peeks the real store's `getCount()` only and never
  calls the real store's mutating increment path. No volume of `/verify` or
  `/verify/v2` traffic will ever trip rate limiting; use `POST /ai/chat` to
  test or exercise real rate-limit enforcement.

---

### `POST /sign`

Sign a request and return a complete artifact envelope. `requestHash` and `policyHash` are
always computed server-side from `request` and the live policy set — callers never supply
either. `/sign` is generic artifact-signing infrastructure: `request.path` can bind the
artifact to any downstream endpoint, not only `/ai/chat`.

**Authentication**: `Authorization: Bearer sk_<64 hex chars>` — a per-identity signing API
key, not a shared secret. Every caller of `POST /sign` authenticates as its own
individually-issued, individually-revocable signing identity, resolved via
`src/core/signing/signingIdentityStore.js` and enforced by
`src/middleware/signAuth.js`. Issued via `scripts/provision-signing-identity.js` or
`POST /signing-identities/:id/api-key` — see `docs/configuration/reference.md`.

**Request body:**

```json
{
  "request": {
    "method": "POST",
    "path":   "/ai/chat",
    "body":   { "prompt": "Hello" }
  },
  "payload": {
    "provider": "openai | anthropic | gemini | mistral | llama | local"
  },
  "ttl": 60000
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request.method` | string | Yes | One of `GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS`. |
| `request.path` | string | Yes | The exact path the signed artifact will be bound to (≤ 2048 UTF-8 bytes). For AI execution this must be the literal string `/ai/chat` — see note below. |
| `request.body` | object | Yes | The exact JSON body that will be sent to that path; hashed into `requestHash`. Nesting depth ≤ 10. |
| `payload` | object | No | Arbitrary application context merged into the signed envelope (e.g. `userId`). |
| `payload.provider` | string | **Conditional** | Required only when `request.path` is `/ai/chat` (see below). Ignored for any other path. |
| `ttl` | integer (ms) | No | Artifact lifetime. Default 60000 (the 60 s maximum artifact age). Validated to `[MIN_TTL_MS, MAX_TTL_MS]`, then clamped to 60 000 ms; the response reports `meta.effectiveTtlMs` and `meta.ttlClamped`. |

**`payload.provider` resolution (AI execution only):** when `request.path` is `/ai/chat`,
`/sign` resolves the provider that the resulting artifact authorizes — this is locked into
the signed artifact and is what `/ai/chat` will dispatch to, not a value `/ai/chat` decides
later:

- Supplied explicitly → validated immediately (`400 PROVIDER_NOT_SUPPORTED` if the name isn't
  a registered provider; `400 PROVIDER_NOT_CONFIGURED` if it's registered but its required
  API key/base URL isn't set).
- Omitted, exactly one provider enabled → auto-resolved to that provider.
- Omitted, zero or multiple providers enabled → `400 PROVIDER_REQUIRED` with
  `details.enabledProviders` listing the configured providers; the caller must choose.

For any `request.path` other than `/ai/chat`, `payload.provider` (if present) passes through
unchanged and is not validated against the AI provider registry — the consent registry may
still treat it as an opaque action identifier (see `services/policy/evaluators/requireConsent.js`).

**Note on `request.path` for AI execution**: `src/api/routes/aiChat.js` hashes every mount
(`/ai/chat`, `/ai/chat/stream`, `/v1/ai/chat`, `/v1/ai/chat/stream`) against the same hardcoded
`/ai/chat` path internally, so artifacts must always be signed with `request.path: "/ai/chat"`
regardless of which alias is actually called at execution time.

**Response — 200:**

```json
{
  "artifactId": "<uuid-v4>",
  "artifact": {
    "expiry":      1700000060000,
    "timestamp":   1700000000000,
    "publicKeyId": "acme-corp:key_v1",
    "payload":     { "requestId": "...", "requestHash": "...", "policyHash": "...", "provider": "openai", "tenantId": "acme-corp" },
    "signature":   "base64-encoded Ed25519 signature"
  },
  "meta": {
    "keyId":     "acme-corp:key_v1",
    "expiresAt": 1700000060000,
    "tenantId":  "acme-corp"
  },
  "requestId": "<uuid-v4>"
}
```

The `artifact` object must be JSON-serialized and base64-encoded before sending as the
`x-qodiqa-artifact` header to `/ai/chat`.

**Response — error (400 / 401 / 403 / 503 / 500):**

```json
{ "decision": "BLOCK", "reason": "string", "details": {}, "requestId": "string" }
```

| Reason | Status | Cause |
|--------|--------|-------|
| `UNAUTHORIZED` | 401 | Credential missing, or does not resolve to any signing identity |
| `FORBIDDEN` | 403 | Credential resolves to a signing identity that is disabled, revoked, or lacks the `SIGN_ARTIFACT` permission |
| `SCOPE_ENVIRONMENT_MISMATCH` | 403 | The signing identity's configured environment (e.g. `staging`) does not match the live server's own environment (e.g. `production`) |
| `SCOPE_PROVIDER_DENIED` | 403 | The signing identity's `allowedProviders` scope excludes the resolved `payload.provider` |
| `INVALID_METHOD`, `PATH_TOO_LONG`, `BODY_TOO_DEEP`, `INVALID_TTL`, `INVALID_REQUEST` | 400 | Structural body validation failed (`INVALID_REQUEST` is also the fallback if server-side request-hash computation itself throws) |
| `PROVIDER_REQUIRED` | 400 | AI execution request, no `payload.provider`, and zero or multiple providers enabled |
| `PROVIDER_NOT_SUPPORTED` | 400 | Explicit `payload.provider` isn't a registered provider name |
| `PROVIDER_NOT_CONFIGURED` | 400 | Explicit `payload.provider` is registered but not enabled |
| `KEY_UNAVAILABLE` | 503 | No active signing key for `QODIQA_CLIENT_ID` |
| `POLICY_UNAVAILABLE` | 503 | Policy set could not be loaded |
| `SIGNING_FAILED` | 500 | Policy hashing or Ed25519 signing failed |
| `METHOD_NOT_ALLOWED` | 405 | Any HTTP method other than `POST` |

---

## Semantic Policy Engine

A second, deterministic, non-LLM content-inspection layer that runs on `POST /ai/chat`
independently of the rule-based policy engine documented above. It runs identically on the
request `prompt` and on the AI provider's own output text before that text is returned to
the caller — so a `BLOCK` from this layer can occur even after a successful provider call,
in place of the response that would otherwise have been returned. Source: `src/core/semantic/`.

**Tier-dependent enforcement.** A match is classified into one of four tiers, each with its
own default blocking posture — note the asymmetry between the two middle tiers:

| Tier | Blocks by default? | To change the default |
|------|---------------------|------------------------|
| `DENY` | Always blocks | Not configurable |
| `REVIEW` | **Blocks by default** | Set `policy.enforcement.REVIEW_BLOCKS: false` to opt out |
| `WARN` | **Does not block by default** | Set `policy.enforcement.WARN_BLOCKS: true` to opt in |
| `ALLOW` | Never blocks | Not configurable |

A deployment that never touches `policy.enforcement` therefore blocks `REVIEW`-tier matches
and passes through `WARN`-tier matches, even though the two tier names read as adjacent
severities.

**Content-match codes.** On a block, `reason` is one of the following (all via the same
`{decision:"BLOCK", reason, details, requestId}` envelope as every other `/ai/chat` block):

| Code | Meaning |
|------|---------|
| `SECURITY_OVERRIDE_ATTEMPT` | Attempt to override system-level security instructions |
| `PROMPT_INJECTION_ATTEMPT` | Prompt injection pattern detected |
| `SYSTEM_PROMPT_EXTRACTION` | Attempt to extract the system prompt |
| `POLICY_BYPASS_ATTEMPT` | Attempt to bypass enforcement policy via prompt content |
| `JAILBREAK_ATTEMPT` | Known jailbreak pattern |
| `TOOL_ABUSE_ATTEMPT` | Abuse of a tool-use/function-calling capability (destructive/privileged/admin invocation, self-granting privilege) — distinct from `UNAUTHORIZED_TOOL_REQUEST` below |
| `UNAUTHORIZED_TOOL_REQUEST` | Requesting use of a tool/API/function the caller explicitly acknowledges lacking authorization for, or chaining a tool's output into an unauthorized second access. Backed by its own dedicated classifier |
| `DATA_EXFILTRATION` | Attempt to exfiltrate data via the prompt |
| `CREDENTIAL_EXTRACTION` | Attempt to extract credentials |
| `PII_EXTRACTION` | Attempt to extract personally identifiable information |
| `MEMORY_EXTRACTION` | Attempt to extract conversational/session memory |
| `FILE_SYSTEM_ENUMERATION` | Attempt to enumerate the filesystem via the prompt |
| `IMPERSONATION_ATTEMPT` | Attempt to impersonate another identity |
| `EMBEDDING_SIMILARITY_MATCH` | A separate, non-keyword-classifier mechanism: semantic embedding similarity to a known-bad reference set, above a calibrated threshold |

**Engine-failure collapse.** If the engine itself cannot run (policy/classifier-registry load
failure, text-normalization failure, all classifiers failing, score-aggregation failure, or
any other internal error), the client-visible outcome is always the single code
`SEMANTIC_INSPECTION_UNAVAILABLE` — this fails closed, the same shape as an infrastructure
outage elsewhere in this API, even though none of these failure modes involve Redis or
Postgres. The granular internal failure category is never exposed to the client; it is
recorded only in server-side audit evidence for operators.

**Notes:**
- Runs on both the request `prompt` (before execution) and the provider's response text
  (after a successful provider call, before it is returned) — the same classifier registry,
  same tiers, same codes, for both directions.
- All 14 content-match codes above are backed by a dedicated classifier (or, for
  `EMBEDDING_SIMILARITY_MATCH`, the embedding-similarity gate) and are reachable via real
  traffic — see `src/core/semantic/__tests__/reasonTaxonomyCoherence.test.js`. (Prior to the
 remediation, 2026-08-30, 6 of a then-19 codes were declared but unreachable — 5 with no
  backing classifier, plus `UNAUTHORIZED_TOOL_REQUEST`'s mislabeling described above. The 5
  were removed as obsolete taxonomy debt; `UNAUTHORIZED_TOOL_REQUEST` was fixed by splitting
  its signal into its own classifier.'s
  entry.)

---

## Rate Limiting

A route-level gate (`src/core/rateLimit/middleware.js`) applied ahead of enforcement/policy
logic on `POST /sign`, `POST /verify` and `POST /v1/verify`, `POST /ai/chat`, and management
routes. This is a **distinct mechanism** from the `RATE_LIMIT` policy evaluator documented in
`POST /ai/chat`'s block-reason table above — that evaluator is one configurable policy among
several; this gate is a fixed infrastructure-level control applied before policy evaluation
even begins.

| Code | HTTP | Cause |
|------|------|-------|
| `RATE_LIMIT_BACKEND_UNAVAILABLE` | 429 | Redis not ready at request time, or the rate-limit check itself threw. Fails closed. |
| `RATE_LIMIT_EXCEEDED` | 429 | Window or burst-capacity threshold exceeded, or the dimension is explicitly disabled by policy |

**Four envelope shapes, two spellings — read this before parsing a rate-limit response
programmatically.** Depending on which route triggered the block, the response body takes one
of four distinct shapes (`protocol` on `/sign`, `management` on admin routes, `decision` on
`/verify`, and an inline-reconstructed `legacyFailure` shape elsewhere). Critically, the
`decision` envelope used by `/verify` hardcodes the reason string **`RATE_LIMITED`** —
a different spelling from `RATE_LIMIT_EXCEEDED` used by every other envelope for the
identical underlying block. Do not match on `reason === "RATE_LIMIT_EXCEEDED"` alone if your
integration also calls `/verify`.

**The `decision` envelope also collapses two different causes into one string.** A genuine
quota-exceeded block and a `RATE_LIMIT_BACKEND_UNAVAILABLE` (Redis outage) block both render
through `/verify`'s `decision` envelope as the identical `{"decision":"BLOCK","reason":"RATE_LIMITED",...}`
— no field distinguishes "a real client hit its quota" from "the backend is down." If your
integration needs to tell these apart, use a route whose envelope carries the real code
(`/sign`'s `protocol` envelope, or the management envelope) rather than `/verify`.

---

## Public Key Endpoints

No authentication required.

---

### `GET /public-key`

Return the currently active **consent-artifact signing key** only (`use: "consent_artifact"`)
— a distinct key domain from the general artifact-verification keys served by `/public-keys`
and `/.well-known/qodiqa/keys` below (/ API-8: this is a deliberate, documented
distinction, not a naming accident — Part of the
management API surface — response uses the canonical management envelope (see "Management
API Envelope" above).

**Response — 200:**

```json
{
  "status": "success",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "requestId": "<uuid-v4>",
  "data": {
    "keys": [
      {
        "kid":       "acme-corp:key_v1",
        "use":       "consent_artifact",
        "algorithm": "Ed25519",
        "format":    "base64",
        "publicKey": "base64-DER-encoded public key"
      }
    ]
  }
}
```

---

### `GET /public-keys`

**Canonical** endpoint for listing public signing keys. Returns
all non-revoked keys (active and deprecated). Part of the management API surface — response
uses the canonical management envelope (see "Management API Envelope" above), envelope type
`MANAGEMENT_SUCCESS`.

Implemented by `src/api/routes/publicKeys.js`, which — like `GET /keys` below — delegates to
the single shared `listPublicKeysForApi()` in `src/api/routes/shared/publicKeyListing.js`.
Both endpoints are therefore guaranteed to return byte-identical output; see
`src/api/routes/__tests__/keysPublicKeysParity.test.js`.

**Response — 200:**

```json
{
  "status": "success",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "requestId": "<uuid-v4>",
  "data": {
    "keys": [
      {
        "keyId":      "acme-corp:key_v1",
        "publicKey":  "base64-DER-encoded public key",
        "algorithm":  "ed25519",
        "status":     "active"
      }
    ]
  }
}
```

---

### `GET /keys` — DEPRECATED

**Deprecated legacy alias** of `GET /public-keys`. Kept only for
backward compatibility with existing clients; new integrations should use `/public-keys`.
Calls the identical shared implementation as `/public-keys` and therefore always returns
identical `data.keys` output — the two endpoints cannot silently diverge. Response envelope
type: `MANAGEMENT_SUCCESS`, identical shape to `/public-keys` above.

Every response additionally carries:

| Header | Value |
|--------|-------|
| `Deprecation` | `true` |
| `Link` | `</public-keys>; rel="successor-version"` |

and emits a `KEYS_LEGACY_ENDPOINT_USED` warning log event server-side. No `Sunset` date is
set — there is no committed removal date for this alias.

Prior to `/keys` and `/public-keys` were two independently-implemented handlers with
silently divergent output (`/keys` hardcoded `algorithm: "Ed25519"`; `/public-keys` omitted
the field entirely).

---

### `GET /.well-known/qodiqa/keys` and related discovery endpoints

JWKS-style public key discovery for third-party/SDK verifiers — a separate, independent
surface from `/public-keys` and `/keys` above (see "Response Envelopes" — these use the
`WELL_KNOWN_LIST` / `WELL_KNOWN_SINGLE` / `WELL_KNOWN_ERROR` envelopes, not the management
envelope). Implemented in `src/api/routes/well-known.js`.

| Route | Description |
|-------|-------------|
| `GET /.well-known/qodiqa/keys` | All verifiable (active/deprecated) artifact-signing keys. |
| `GET /.well-known/qodiqa/keys/{keyId}` | A single verifiable key by canonical ID. |
| `GET /.well-known/qodiqa/keys/archived` | Purged/archived keys, for resolving old `keyId`s. |
| `GET /.well-known/qodiqa/transparency-keys` | Transparency-log signing keys — a separate trust domain from the artifact-signing keys above. |
| `GET /.well-known/qodiqa/transparency-keys/{keyId}` | A single transparency key by canonical ID. |

**Response — 200 (list form, `WELL_KNOWN_LIST`):**

```json
{
  "keys": [
    {
      "keyId":     "acme-corp:key_v1",
      "algorithm": "ed25519",
      "publicKey": "base64-encoded public key",
      "status":    "active"
    }
  ],
  "requestId": "uuid-or-null"
}
```

**Response — 200 (single-key form, `WELL_KNOWN_SINGLE`):** same per-key fields as above,
flattened to the top level (`keyId`, `algorithm`, `publicKey`, `status`, `requestId`).

**Response — 404/405/500 (`WELL_KNOWN_ERROR`):** `{ "decision": "BLOCK", "reason": "...",
"details": {}, "requestId": "..." }` — intentionally reuses the enforcement-decision shape
for consistency at this trust boundary.

---

## Infrastructure Endpoints

Require operator authentication unless otherwise noted.

---

### `GET /health`

Liveness probe. No authentication required.

**Response — 200 (always):**

```json
{
  "status": "ok",
  "uptime": 12345.678
}
```

**Note**: This endpoint does not check any dependencies. Use `/ready` for readiness.

---

### `GET /ready`

Readiness probe. No authentication required.

**Response — 200 (ready):**

```json
{
  "ready": true,
  "components": {
    "nonceStore":     true,
    "anomalyStore":   true,
    "rateLimitStore": true
  }
}
```

**Response — 503 (not ready — during startup, or after graceful shutdown begins):**

```json
{
  "ready": false,
  "components": {
    "nonceStore":     true,
    "anomalyStore":   true,
    "rateLimitStore": false
  }
}
```

This is a distinct response contract from the `SERVICE_SHUTTING_DOWN` response documented below — `/ready` is mounted ahead of the request-drain middleware and always reports actual component state, not just shutdown status.

---

### `GET /metrics`

Prometheus text-format metrics exposition. Requires operator authentication.

Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `qodiqa_requests_total` | counter | Total HTTP requests by path and status |
| `qodiqa_blocks_total{reason}` | counter | Block decisions by reason code |
| `qodiqa_execution_integrity_full` | gauge | 1 if enforcement pipeline is fully operational, 0 otherwise |
| `qodiqa_redis_store_up{store}` | gauge | 1 if the named Redis store is connected |
| `qodiqa_http_request_duration_seconds` | histogram | Request latency by endpoint |
| `qodiqa_audit_chain_length` | gauge | Number of entries in the in-memory audit chain |

---

### `GET /diagnostics`

Startup diagnostic information. Requires operator authentication.

Returns the result of startup validation: environment checks, secret checks, key store
status, Redis connectivity, and PostgreSQL connectivity.

---

### `GET /diagnostics/profile/memory`, `GET /diagnostics/profile/gc`, `POST /diagnostics/profile/cpu`

Production CPU/GC/heap profiling. Requires operator authentication (same stack as `/diagnostics`) **plus** a second, independent kill switch: `QODIQA_PROFILING_DIAGNOSTICS_ENABLED=true` (default: disabled in every environment — opt-in only, unlike `/diagnostics`'s `!isProduction` default). When either gate fails, the endpoint returns `404` (not `401`), matching the enumeration-resistance behavior of every other diagnostics kill switch.

| Endpoint | Method | Body / Query | Response |
|---|---|---|---|
| `/diagnostics/profile/memory` | GET | — | `{ heapStatistics, heapSpaceStatistics }` — synchronous `v8` snapshot, zero side effects |
| `/diagnostics/profile/gc` | GET | `?windowMs=<n>` (clamped 1000–30000, default 5000) | `{ windowMs, available, summary, pressure }` — GC pressure over an observation window |
| `/diagnostics/profile/cpu` | POST | `{ "durationMs": <n> }` (clamped 1000–30000, default 5000) | `{ durationMs, available, summary }` — **summarized hot-node output only**, never the raw `.cpuprofile` (a larger information-disclosure surface) |

No endpoint accepts a caller-supplied filesystem path.

---

## Audit Endpoints

Require `READ_AUDIT` permission (roles: admin, auditor, compliance).

---

### Searching the audit chain

There is no `GET /audit` list endpoint (the older text of this document described one; it never existed in the current gateway).
Use `GET /audit-viewer/search`, `GET /audit-viewer/timeline` and `GET /audit-viewer/export` (viewer permissions), or
`GET /audit-store/events` (platform event store). Their parameters and responses are in `docs/api/openapi.json`.

---

### `GET /audit/:artifactId`

Retrieve a single audit entry by artifact ID.

---

### `GET /audit/chain/integrity`

Verify the integrity of the audit chain by replaying the hash links. Response fields are in `docs/api/openapi.json`.

### `GET /audit/chain/verifier/status` and `POST /audit/chain/verifier/verify`

Status of the scheduled chain verifier and a manual verification run (rate limited).

---

## Key Administration Endpoints

Require `MANAGE_KEYS` permission (roles: admin only).

---

### `POST /key-admin/:clientId/rotate`

Rotate the signing key of tenant `clientId`. This default form is the **emergency** rotation: the previous key is revoked, so artifacts it
signed stop verifying. Use `POST /key-admin/:clientId/rotate-graceful` to keep the previous key valid for verification during the grace
window. Both take a rotation lock and are audited. Response fields: `docs/api/openapi.json`.

---

### `POST /key-admin/:clientId/revoke`

Revoke a key of tenant `clientId`. Body: `{ "keyId": "acme-corp:key_v1", "reason": "..." }`. Artifacts signed with a revoked key are
rejected at verification.

Other key-administration routes: `GET /key-admin/:clientId/status`, `POST /key-admin/:clientId/recover`, `GET /key-admin/inventory`,
`GET /key-admin/health`, `POST /key-admin/purge-expired`, `POST /key-admin/kek/rotate`, `POST /key-admin/mac-keys/rotate`.

---

## Transparency Log Endpoints

Mounted at both `/transparency` and `/v1/transparency`. Public read endpoints need
no authentication; admin endpoints need an ops credential plus the listed permission
(see `docs/security/route-guard-registry.json`).

**What the public API exposes.** Only the fields needed to verify an
entry. The log is global, and the public API never offers a tenant filter
(`?tenantId` on `/entries` is ignored). A public entry is exactly:

```json
{
  "id": "1042",
  "transparency_id": "uuid",
  "entry_type": "ARTIFACT",
  "artifact_id": "art_…",
  "evidence_chain_id": null,
  "verification_id": null,
  "payload_hash": "64 hex",
  "previous_entry_hash": "64 hex | null",
  "entry_hash": "64 hex",
  "signer_key_id": "tlk_…",
  "signature": "base64",
  "created_at": "ISO-8601"
}
```

These are never public: the payload, `tenant_id`, the registering operator
(`registered_by`) and `signer_key_version`. `GET /transparency/verify/:transparencyId` recomputes the
payload hash server-side and returns only verdicts.

---

### `GET /transparency/entry/:transparencyId`

One entry: `data.entry` has the shape above. 404 if unknown.

---

### `GET /transparency/entries`

Public entries, paginated (`page`, `pageSize` ≤ 500, `sortOrder`). Optional
filters: `entryType`, `artifactId`, `signerKeyId`, `startTime`, `endTime`. The
response holds `data.entries` plus pagination metadata.

---

### `GET /transparency/root` · `GET /transparency/roots`

The latest signed Merkle root, and a paginated list of signed roots.

---

### `GET /transparency/verify/:transparencyId`

Integrity and authenticity report for one entry (`result`:
`VALID`/`INVALID`/`PARTIAL`/`ERROR`, `signatureValid`, `integrityChecks`,
`firstFailure`). The entry signature is part of the verdict (ST23-01/02 /):
`VALID` requires a signature that verifies under an `active` or `deprecated`
transparency key; an unknown, revoked or invalid signature is `INVALID`, and a key
store that cannot be consulted gives `PARTIAL`. Anonymous calls record
nothing. An authenticated caller with `READ_TRANSPARENCY_LOG` gets a verification
row recorded under their own identity.

---

### `GET /transparency/proof/:transparencyId`

RFC 6962 inclusion proof for the entry against the latest signed root that covers
it. `proof: null` plus a `message` means no root covers it yet.

`proofVerification.valid` is `true` only when the proof verifies structurally
**and** both signatures it rests on authenticate (ST23-04 /):
`ENTRY_SIGNATURE` and `ROOT_SIGNATURE` must verify under transparency keys with
status `active` or `deprecated`. An unknown or revoked key, a missing or invalid
signature is `FAIL`. A key store that cannot be consulted is `SKIP`, and the proof
is then not valid. `structurallyValid` and `authenticated` report the two halves
separately; `failedCheck`/`failureReason` name the first structural failure, else
the first authentication gap.

---

### `/v1/agents` and `/v1/sessions`

Agent identities and their bounded sessions. Admin plane; every call names its tenant (`tenantId` in the body or the query - operator credentials are not tenant-scoped) and runs under that tenant's row-level security, so another tenant's agent or session is a `404`.

- `POST /v1/agents` (MANAGE_AGENTS, operator MFA step-up) `{ tenantId, displayName, ownerUserId?, publicKey?, allowedActionClasses[], maxActionsPerSession?, maxSessionSeconds?, costBudgetMicros? }` → `201` the agent, with a **gateway-issued `agentId` (UUID v4**, as `docs/protocol/PROTOCOL-V2.md` 5.1 requires - sending one is `400 AGENT_ID_IS_ISSUED`). `allowedActionClasses` is a subset of `read, write, file, database, external_api, command, communication, financial, delegate`; an agent can be authorised for no class outside it. `GET /v1/agents?tenantId=&status=`, `GET /v1/agents/:agentId?tenantId=` (READ_AGENTS). `PATCH /v1/agents/:agentId` (MANAGE_AGENTS, step-up) changes limits or status: **revoked is absorbing**; suspending or revoking **ends the agent's active sessions at once**.
- `POST /v1/sessions` (MANAGE_AGENT_SESSIONS: admin, operator; operator MFA step-up like every admin-plane change - a tenant-facing runtime credential that opens sessions without an operator arrives with) `{ tenantId, agentId, ttlSeconds?, maxActions?, costBudgetMicros? }` → `201` the session. The **effective limits are the lowest of the requested ones, the agent's and the platform caps** (24 h, 100 000 actions): a session never has more autonomy than its agent. A session carries `expiresAt`, `maxActions`/`actionsUsed`, `costBudgetMicros`/`costUsedMicros`, the action sequence `nextSeq` and `lastActionHash` (the chain the action authorisation builds on). `GET /v1/sessions/:sessionId?tenantId=` applies expiry; `GET /v1/sessions?tenantId=&agentId=&status=`.
- `POST /v1/sessions/:sessionId/end` and `/kill` (MANAGE_AGENT_SESSIONS, step-up) `{ tenantId, reason? }`. **kill** is the force-stop: it aborts the executions of that session running in the same process at once, emits a CRITICAL `AGENT_SESSION_KILLED` event, and every later check or action reservation refuses the session (`AGENT_SESSION_ENDED`), on every replica, at the next action boundary.
- **State machines are enforced in code, not in the database.** The tables of migrations 100-106 have forced row-level security and column-level grants, but no trigger forbids a transition such as revoked -> active; the application role could perform it with direct SQL. Treat the role that holds the application credential as trusted for these tables, and watch `AGENT_*` / `APPROVAL_*` events; DB-level guards are a possible later hardening.
- **Per-request check.** A request that names an agent session is accepted only if the tenant, the agent and the session match, the session is active and unexpired and the agent is active (`agentStore.checkSession`); an unknown, foreign-tenant or foreign-agent session answers identically (`AGENT_SESSION_UNKNOWN`). **Privilege separation:** the agent acts with its own limits, never with the user's rights; `ownerUserId` is recorded as the user it acts for and travels in the evidence, it is not an authority.

---

### `POST /v1/actions/authorize` · `POST /v1/actions/plans` · `/v1/tool-registry`

Per-action authorisation of an agent. The two `/v1/actions` endpoints are authenticated **like `/sign`** (a tenant signing identity, `Authorization: Bearer sk_...`: environment scope, per-identity rate limit, auth-failure lockout, the global kill switch); the registry is admin plane (operator authentication, RBAC `MANAGE_TOOLS` / `READ_TOOLS`, operator MFA step-up on every change).

- **`POST /v1/actions/authorize`** `{ agentId, sessionId, tool: { server, name }, args, parentRequestHash?, planId?, requestId?, proof?, ttl? }` → `200 { artifactId, artifact, action: { actionHash, seq, prevActionHash, tool: { server, name, schemaHash, version }, parentRequestHash }, meta }`. `artifact` is an **action artifact** (Ed25519, lifetime ≤ 60 s, domain `QODIQA::ACTION_ARTIFACT::V1`, payload `{ requestId, tenantId, qodiqa: { v: 2, kind: "action", bind, agentId, sessionId, seq, actionHash } }`) that authorises exactly that one action; `actionHash = SHA-256("QODIQA::ACTION::V2" || JCS-P1({ v: 2, tenantId, agentId, sessionId, seq, tool: { server, name, schemaHash }, args, parentRequestHash, prevActionHash }))` (V2-FREEZE 5.1; vectors `docs/protocol/vectors/action.json`). **`seq` and `prevActionHash` are assigned by the gateway**, atomically, from the session (a caller cannot name them: the body is strict). Every refusal is a `BLOCK` decision body with its own `reason`: unknown / ended / expired / foreign session (`AGENT_SESSION_*`), `AGENT_PROOF_REQUIRED` / `AGENT_PROOF_INVALID` (an agent with a registered public key proves possession for THIS `requestId`), `TOOL_NOT_REGISTERED` / `TOOL_PENDING_REVIEW` / `TOOL_DISABLED`, `ACTION_ARGS_INVALID` (the registered schema is strict: an argument it does not name is refused), `ACTION_CLASS_NOT_ALLOWED`, `ACTION_APPROVAL_REQUIRED` (a tool that requires approval is refused until the approval flow; nothing in the request turns that off), `ACTION_BUDGET_EXHAUSTED` / `COST_BUDGET_EXHAUSTED` (429), `ACTION_PLAN_*`.
- **`POST /v1/actions/plans`** `{ agentId, sessionId, steps: [{ server, name, maxCalls }], ttlSeconds?, requestId?, proof? }` → `201 { planId, plan }`. The plan is authorised once; every step must be a registered, active tool the agent may use that needs no approval. **While the session has an active plan, an action must carry its `planId` and be a step of it** (`ACTION_PLAN_REQUIRED`, `ACTION_NOT_IN_PLAN`, `ACTION_PLAN_STEP_EXHAUSTED` 429): a tool the agent was talked into using after the plan was authorised is not callable. A new plan replaces the previous one (`ACTION_PLAN_EXPIRED` for the old id). `planHash` identifies exactly the authorised steps.
- **Executing** (`src/core/actions/executor.js`, used by the tool gateway): `beginExecution({ artifact, tool, args, parentRequestHash })` verifies the artifact, re-checks the agent and session, recomputes `actionHash` from what is about to run and compares it in constant time (`ACTION_MISMATCH`; `TOOL_SCHEMA_CHANGED` when an earlier schema version reproduces it), re-validates the arguments, and **consumes** the artifact once and in order in the `action_executions` ledger (`ACTION_REPLAY`, `ACTION_ORDER_VIOLATION`); under audit schema v8 it then writes `ACTION_INTENT` before the action runs (an INTENT that cannot be written stops the action) and `completeExecution` writes `ACTION_COMMIT`.
- **`/v1/tool-registry`** (admin): `POST /` register a tool version `{ tenantId, server, name, schema, actionClass, reversible, requiresApproval?, policy?, description? }` (the first version is active; a changed schema / class / reversibility is a new version in `pending_review`, not callable until approved, and **the registrant cannot approve it**), `GET /?tenantId=&status=`, `GET /entry?tenantId=&server=&name=`, `POST /approve` `{ tenantId, server, name, version }`, `POST /disable`, `POST /policy`. The argument schema is a JSON Schema **subset** (no `$ref`, no `pattern`; `additionalProperties` defaults to `false`); `schemaHash = SHA-256("QODIQA::TOOL_SCHEMA::V1" || JCS-P1(schema))`. Tools are addressed by `(server, name)` in the body or query (names may contain `/`).
- **Limits.** The artifact binds an action, not a plan: plan membership is enforced when the artifact is issued and recorded in the `ACTION_AUTHORIZE_DECISION` event, not re-checked by the executor. An authorised action that is never executed blocks its session at that `seq` (omission is an order violation by design); the agent starts a new session. The `ACTION_INTENT` entry is written right after the ledger transaction, not inside it; a ledger row left in `intent` is closed as `unknown` by `reconcileOpen`.

---

### `/v1/delegations`

Delegation of authority between agents (specification `docs/protocol/DELEGATION.md`, vectors `docs/protocol/vectors/delegation.json`). Authenticated like `/sign` (a tenant signing identity); every statement runs under that tenant, so another tenant's delegation is a 404.

- `POST /v1/delegations` `{ issuerAgentId, issuerSessionId, subjectAgentId, classes[], parentId?, tools?[{server,name}], maxActions?, ttlSeconds?, maxDepth?, requestId?, proof? }` → `201 { delegationId, delegation, token, chainHash, action }`. Without `parentId` this is a **root grant** (classes must be ones the issuer's own identity holds; `maxDepth` 1..8, default 3); with `parentId` the issuer must be the parent's delegate and the child may only **narrow** it: classes, tools (an unrestricted child of a tool-restricted parent is refused), `maxActions`, lifetime; `depth` = parent + 1, never above the root's `maxDepth`; no agent twice in a chain. The issuer needs the class `delegate`; **issuing is itself an authorised action** of the issuer's session (class, live session and budgets are checked and charged; it takes no place in the session's chain of artifacts). Refusals: `DELEGATION_INVALID`, `DELEGATION_ATTENUATION_VIOLATION`, `DELEGATION_DEPTH_EXCEEDED`, `DELEGATION_CYCLE`, `DELEGATION_REVOKED`, `ACTION_CLASS_NOT_ALLOWED`, `AGENT_SESSION_*`, `ACTION_BUDGET_EXHAUSTED`.
- `POST /v1/delegations/verify` `{ chain: [envelopes, root first] }` (checked offline, plus the live state of the leaf when known) or `{ delegationId }` → `200 { valid, ... }` (`valid:false` carries `reason`, `index`).
- `GET /v1/delegations/{id}` → the delegation, its chain of tokens and whether it is valid now. `POST /v1/delegations/{id}/revoke` `{ reason, revokeAgents? }` → `{ revoked[], abortedExecutions, agentsRevoked[] }`: the delegation and **every descendant** at once; executions running under them are aborted; `revokeAgents` also revokes the delegates of the subtree (never the root agent).
- **Acting under a delegation:** `POST /v1/actions/authorize` with `delegationId` - the agent must be the leaf's delegate, the chain valid and unrevoked, the action inside the leaf's classes and tools; one action is counted against **every link with a `maxActions`**. The chain the request ran under is recorded and reaches `ACTION_INTENT` / `ACTION_COMMIT` (`executionContext.delegation`); a chain revoked between authorisation and execution stops the execution (`DELEGATION_REVOKED`). Suspending or revoking an agent revokes the delegations it issued or holds.

---

### `/v1/mcp/servers` and `POST /v1/tools/call`

The tool gateway. Servers are registered by an operator (admin plane: RBAC `MANAGE_MCP_SERVERS` / `READ_MCP_SERVERS`, operator MFA step-up on every change); calls are made with a tenant signing identity, like `/sign`.

- **Register** `POST /v1/mcp/servers` `{ tenantId, serverId, url, identity?, description? }`. `serverId` is the `server` of the tool registry. The URL goes through the SSRF policy of the model providers (https only, no credentials, no fragment, not an IP literal in any spelling, not a private / loopback / link-local / metadata name) and is validated again, on the resolved address, at every connection (DNS rebinding); redirects are never followed. An https server is registered with its **pinned identity** `{ kind: "tls-spki-pin", sha256, trust?: "ca-and-pin" | "pin-only" }` - the SHA-256 of the certificate's public key, so a renewal with the same key keeps working - and a connection whose key differs is dropped. A `configHash` over URL + identity is recomputed on every call (`MCP_SERVER_CONFIG_TAMPERED`). `http` and local destinations exist only with `QODIQA_MCP_ALLOW_LOCAL=true` and **never in production**. There is no stdio transport and nothing here starts a process.
- **Manage** `GET /`, `GET /{serverId}`, `POST /{serverId}/disable` `{ tenantId, reason }` (the next call is refused on every replica, running calls are aborted), `POST /{serverId}/enable`, `POST /{serverId}/identity` (rotate the pin; the URL never changes).
- **Discover** `POST /{serverId}/tools/refresh` asks the server for `tools/list` and registers what it offers in the tool registry as **proposals**: new or changed tools are `pending_review` and are not callable until an operator approves them; the class (`read` when the server hints read-only, otherwise `external_api`) and reversibility are a conservative guess from the server's own, untrusted hints; a schema outside the supported subset or an invalid name is `SKIPPED` with its reason.
- **Call** `POST /v1/tools/call` `{ artifact, tool: { server, name }, args, parentRequestHash? }` (the artifact comes from `/v1/actions/authorize`). In order: the artifact belongs to this tenant; the server is registered, active, its URL acceptable and its configuration intact; the executor re-derives `actionHash` from **this call** (`ACTION_MISMATCH`), re-checks agent, session, order, registered schema, **tool policy** and delegation chain, and consumes the artifact once (`ACTION_REPLAY`); the call goes to the server (pinned, guarded, bounded in time `QODIQA_TOOL_CALL_TIMEOUT_MS` and size `QODIQA_TOOL_MAX_RESPONSE_BYTES`); the result is screened and returned. `200 { decision: "EXECUTE", result: { isError, content[], provenance, delimited }, receipt }`; a result that is withheld is `200 { decision: "BLOCK", reason: "TOOL_RESULT_INJECTION_SUSPECTED" | "TOOL_RESULT_BLOCKED_BY_POLICY" | "TOOL_RESULT_TOO_LARGE" | "TOOL_RESULT_SUSPICIOUS", details, receipt }` with none of its content; a server failure is `502` / `504` `TOOL_CALL_FAILED` (the action is `failed` in the ledger, never a result).
- **The result is untrusted data.** `provenance` says so (`untrusted: true`, server, tool, version, `actionHash`, what was withheld, the screening findings, `contentHash`) and `delimited` renders the text between `<qodiqa:untrusted-tool-result>` delimiters whose closing tag cannot occur inside the data. Screening covers the text and every transformation a model could still read (Unicode-normalised without zero-width / bidi characters, percent-decoded, entity-decoded, base64 segments decoded), instruction conflict (override, role change, secrecy, system-prompt requests, chat-template markers, tool-call lookalikes, exfiltration directives, markdown-image exfiltration), and the semantic policy engine and embedding gate used for model output. Images, audio and binary blobs are **withheld and listed**, never passed on unseen. These are conservative text checks - one layer next to the semantic gates and the structural separation - not a guarantee against every injection.
- **Tool constraints** (`policy.constraints` of the registered tool): `path_prefix`, `url_host`, `sql_operations`, `command_allowlist` on a JSON-pointer argument. **Default deny:** a `file`, `database`, `external_api` or `command` tool is callable only if it carries a constraint of its kind (`ACTION_POLICY_REQUIRED`); a constraint not met is `ACTION_POLICY_DENIED`. Enforced at `/v1/actions/authorize` and again at the gateway with the policy in force then. `policy.maxCallsPerSession` is enforced when the artifact is consumed (`ACTION_TOOL_LIMIT`, serialised per session and tool).
- **Revocation of a compromised tool or server**: the next call is refused on every replica (the stores are read at every call, no cache); a call already running is aborted at once on the process that handled the revocation and, through a one-second watcher of the store, on every other replica - inside the 5 s the plan sets. The same watcher stops a call whose delegation is revoked or whose session is killed.
- **Receipt.** `receipt` is the ledger record of the call (`requestId`, `actionHash`, `seq`, tool and version, `serverConfigHash`, `status`, `outputHash` of what was delivered, times, delegation) with a `receiptHash` over it. It is **not signed**: a signed receipt for actions needs a new domain tag, which is a protocol amendment.

---

### `/v1/approvals` and the approval flow of `/v1/actions/authorize`

Human approval of agent actions. A tool that **requires approval** (irreversible tools by default, or set with `requiresApproval`) never gets an action artifact on the first call.

1. `POST /v1/actions/authorize` (as always) → **`202 { status: "pending", data: { approvalId, actionHash, seq, expiresAt } }`**. The request fixes the action it is about: the position in the session chain (`seq`), `actionHash`, the tool and the exact arguments. While a request is open the session authorises **nothing else** (`SESSION_AWAITING_APPROVAL`, 409): the position must stay the last one so that it can be given back.
2. An operator opens `public/approvals.html` (or `GET /v1/approvals/{id}`), sees the tool and the arguments, and decides: `POST /v1/approvals/{id}/decision` `{ tenantId, decision: "APPROVE" | "DENY", reason?, ttlSeconds?, notBefore? }` (RBAC `DECIDE_APPROVALS`: admin, compliance; **operator MFA step-up**, the code in `X-QODIQA-OTP`). The approver is never the requester: not the signing identity that asked, not the user the agent acts for (compared case-insensitively), not an operator that user provisioned (`APPROVAL_NOT_INDEPENDENT`, also a database CHECK). **Limit:** an agent created without `ownerUserId` has no human principal to exclude, so the only barrier is that an operator is never the signing identity that asked; set `ownerUserId` on every agent that uses approval-gated tools. The gateway signs the decision (`QODIQA::APPROVAL::V1`, `src/core/approvals/approvalToken.js`): approver, `actionHash`, `notBefore`, `expiresAt` (default 10 min, at most 1 h), `mfa: "step-up"`; a denial is signed too.
3. The requester polls `GET /v1/actions/approvals/{id}` (or just asks again) and calls `POST /v1/actions/authorize` again **with the same action and `approvalId`** → `200` with the artifact, now carrying `approvalRef`. The approval is bound to the hash recomputed from what is asked now (`APPROVAL_INVALID` for another argument, tool, agent or session), valid between `notBefore` and `expiresAt`, and **spent once** (`APPROVAL_ALREADY_USED`). While still pending the answer is `202` again; `APPROVAL_DENIED`, `APPROVAL_EXPIRED`, `APPROVAL_CANCELLED` are `403`.
4. The executor re-checks the approval when the action runs: still APPROVED (a cancel after the artifact exists refuses the execution), spent by THIS artifact, naming THIS action, signature intact.
- **States** `PENDING → APPROVED | DENIED | EXPIRED | CANCELLED` (`APPROVED → CANCELLED | EXPIRED` while unspent). A request unanswered for `QODIQA_APPROVAL_TTL_SECONDS` (600, at most 3600) expires. The requester withdraws with `POST /v1/actions/approvals/{id}/cancel`.
- **The place in the session.** A request that ends without the action (denied, expired, cancelled before the artifact exists) **gives its position back**: the chain of artifacts stays contiguous, which the audit verifiers require of `ACTION_INTENT` numbers. If the chain moved on anyway (a concurrent authorisation between the check and the reservation) the place is closed as a failed action and reported (`APPROVAL_POSITION_NOT_RELEASABLE`); a later `ACTION_INTENT` then skips that number. A request cancelled **after** the artifact exists keeps its place: the session waits for an execution that will not happen - open a new session.
- **Announcements.** Every transition is a structured event; a webhook `approval.requested | approval.decided | approval.expired | approval.cancelled` (no arguments in the payload); a notification through the configured alert channels (e-mail, Slack, Teams, …) for new requests (`QODIQA_APPROVAL_NOTIFY=false` turns it off); and, under audit schema v8, the chain entries `APPROVAL_REQUESTED`, `APPROVAL_DECIDED`, `APPROVAL_EXPIRED` and `ACTION_INTENT` with `approvalRef`. The verifiers check the sequence of one approval (`APPROVAL_SEQUENCE_VIOLATION`, AUDIT-V8-FREEZE Amendment 2 - pending the owner's approval).
- Tools that need approval cannot be part of an execution plan (`POST /v1/actions/plans` refuses them).

---

### `GET /v1/proofs/:requestId`

Downloadable proof of one request, `?tenantId=<tenant>` required. Admin plane: operator authentication, RBAC (`READ_AUDIT_PROOFS` — auditor, compliance, admin); read only, so no MFA step-up. The response is the usual envelope with the proof `qodiqa-proof/1` (`docs/protocol/VECTORS-FORMAT.md` section 3) in `data`.

- **Parts.** `auditEntries` (the request's INTENT / STREAM_OPENED, DECISION and COMMIT), `chainPath` (the contiguous chain from the first entry to the head of the earliest signed checkpoint that covers the request) with that `checkpoint`, `transparency` (leaf, inclusion proof, signed root), `receipt` (while it is still in the receipt store), `anchors` (confirmed external anchors of the checkpoint) and the public `keys` the verifier needs. A part that cannot be assembled is **left out**, never invented; the verifier then answers `VALID_PARTIAL` with the reason. The signed artifact is not stored by the gateway: add it when verifying.
- **Chain path withheld by default.** The contiguous path between the request and its checkpoint contains OTHER tenants' raw entries, so a tenant-scoped read gets no `chainPath`/`checkpoint` (`parts.chainPathWithheld` in the access log) and the verifier answers `VALID_PARTIAL` (`CHECKPOINT_ABSENT`). `?fullChain=true` serves it and needs `READ_AUDIT_PROOFS_FULL_CHAIN` (admin only) — for a platform operator producing a complete proof for a tenant.
- **Tenant isolation.** `tenantId` is required; the request is looked up with it, and a request of another tenant answers exactly like an unknown one (`404 NOT_FOUND`). Operator credentials are not tenant-scoped in this system, so this explicit parameter is the isolation boundary. Every read is logged (`PROOF_ACCESSED`: request, tenant, operator, outcome) and counted (`qodiqa_proof_requests_total{outcome}`). `Cache-Control: no-store`.
- **Verify offline:** `node scripts/audit-repro/verify/qodiqa-proof-verify.js --proof response.json --artifact artifact.json --anchors-repo <anchors repository>` (the CLI accepts the response envelope as it is), or the Python verifier `qodiqa_proof_verify.py` — a proof can only be `VALID` with the anchors repository (`docs/protocol/VECTORS-FORMAT.md` 3.1).

---

### `POST /v1/admin/artifact-revocations` · `GET /v1/admin/artifact-revocations/:requestId`

Per-artifact revocation: withdraw ONE signed artifact — identified by its `payload.requestId` — before it is used. Admin plane: operator authentication, RBAC (`MANAGE_ARTIFACT_REVOCATIONS`, admin only) and, for the POST, the operator MFA step-up (`X-QODIQA-OTP`).

- `POST` `{ "requestId": "<uuid>", "reason": "<1–500 chars>" }` → `{ created, record: { requestId, operatorId, reason, tenantId, revokedAt }, ttlSeconds }`. Repeating it is a 200 with `created: false` and keeps the first record.
- A revoked artifact is refused with **`BLOCK ARTIFACT_REVOKED`** (403 in `status` mode) after its signature and request binding are verified and **before its nonce is consumed** — no provider call, an ordinary audited BLOCK at the VALIDATION stage, and a fresh artifact from `/sign` works normally. If the revocation store cannot answer, the request is refused (`ARTIFACT_REVOCATION_STATE_UNAVAILABLE`, 503): "cannot tell" is not "not revoked".
- The set lives in Redis (`artrev:v1:<requestId>`, shared by every replica; process memory without `REDIS_URL`) and each entry expires on its own after 120 s — longer than the 60 s maximum artifact age plus clock skew — so it holds only what was revoked in the last two minutes. After that `GET` reports `revoked: false`; by then the artifact itself is past its age limit.
- The operator action is emitted at CRITICAL (`ARTIFACT_REVOKED`: who, which artifact, why) to the audit/SIEM stream.

---

### `GET /v1/admin/kill-switch` · `POST /v1/admin/kill-switch/activate` · `POST /v1/admin/kill-switch/release`

The global kill switch. Admin plane: operator authentication, RBAC (`READ_KILL_SWITCH` to read, `MANAGE_KILL_SWITCH` — admin only — to change) and, for the two POSTs, the operator MFA step-up (`X-QODIQA-OTP`).

- `POST …/activate` `{ "reason": "<1–500 chars>" }` raises it; `POST …/release` `{ "reason"?: "…" }` lowers it. Both return `{ changed, state, audit }`; repeating a transition is a 200 with `changed: false`.
- While active, every `/sign` and `/ai/chat` request (all aliases, streaming included) is answered **`503 {"decision":"BLOCK","reason":"KILL_SWITCH_ACTIVE"}`** with `Retry-After: 30`, before anything else runs — nothing is signed, no nonce is consumed, no provider is called, nothing is audited for the refused request. `503 KILL_SWITCH_STATE_UNAVAILABLE` means the replica cannot confirm the state (its control-plane snapshot is older than 5 s) and refuses rather than assumes "off".
- The state is a signed control-plane record (PostgreSQL authoritative, Redis notification, 1 s polling fallback): every replica follows within 5 s. A record whose MAC does not verify is treated as active (`tampered: true`).
- `audit` reports the audit-chain `KILL_SWITCH` entry (audit schema v8: BLOCK/`KILL_SWITCH_ON`, ALLOW/`KILL_SWITCH_OFF`, tenant `*`, `executionContext.killSwitch = { operatorId, scope, stateHash }`). It is `{ recorded: false, reason }` when v8 is off or the append failed — the change stands and the gap is escalated at CRITICAL.

Runbook: `docs/operations/alert-runbooks.md#kill-switch`.

---

### `/v1/admin/providers` - dynamic OpenAI-compatible providers

Register an OpenAI-compatible endpoint at runtime. Admin plane: operator authentication, RBAC (`READ_PROVIDERS` to read, `MANAGE_PROVIDERS` - admin only - to change) and the operator MFA step-up on every change.

- `GET /v1/admin/providers`, `GET /v1/admin/providers/{id}` - list / read. `POST /v1/admin/providers` registers `{ id, baseUrl, apiKeyEnv?, models?, defaultModel?, timeoutMs?, maxTokens?, failoverProvider?, enabled? }`; `PUT /v1/admin/providers/{id}` changes any member but the id; `POST .../{id}/disable|enable` stop and resume routing. **There is no delete.**
- The provider is then named `compat-<id>` in artifacts, routing, failover, budgets and policy rules, exactly like a built-in provider. `/sign` infers a provider only when exactly one is enabled in total, dynamic ones included.
- The API key is never sent or stored: `apiKeyEnv` is the NAME of an environment variable that must start with `COMPAT_KEY_` and be provisioned on every replica, together with `COMPAT_KEY_<NAME>_HOSTS` - the comma list of hosts (exact names or `*.example.com`) the key may be sent to; registering or changing a provider so that its host is not in that list is refused, and an entry whose variable or host list is unset on a replica is not callable there. The destination is judged again on every use under the policy in force then (https, port 443, a public DNS name that is not an internal suffix). `baseUrl` must be `https` to a public DNS name (no IP literals, no private or loopback names); the connection re-checks every resolved address and redirect hop, so a name that later resolves to a private or metadata address is refused. Only `QODIQA_COMPAT_ALLOW_LOCAL=true` outside production permits plain http / loopback.
- `POST /v1/admin/providers/compare` `{ inputTokens, outputTokens, providers?, weights? }` returns, for each enabled provider, the estimated cost of a request that size (from the tariff in the ROUTING rules in force), recent average latency, failure rate, degraded flag, calls in flight and a weighted `score` (`weights` `{ cost, latency, failure }`, default 1/1/1, metrics normalised across the compared providers, lowest best; a provider with no price or no latency sample scores the worst value), and `ranked` best first (degraded last). `mixedCurrencies` is true when tariffs are in different currencies (their costs are then not comparable). The platform ships no price list.
- State is a MAC-protected control-plane record (migration 107): every replica follows a change within 5 s or refuses. A record changed in the database without the MAC key is not callable and is escalated (`PROVIDER_REGISTRY_RECORD_TAMPERED`).

---

### `GET /transparency/receipt/:requestId`

The signed receipt of a request's decision (`docs/protocol/PROTOCOL-V2.md` section 6). **No authentication:** knowing the
`requestId` (the UUID in the consumed artifact's `payload.requestId`) is the authorization. The response body is the
receipt and nothing else (no tenant, no reason):

```json
{ "receipt": { "v": 1, "requestId": "…", "decision": "ALLOW", "issuedAt": 1790000000000,
               "entryHash": "<audit DECISION entry hash>", "leafHash": "<Merkle leaf hash>",
               "keyId": "tr-default:key_v1", "signature": "<base64>" } }
```

The same object is returned in the `/ai/chat` response (`receipt`) for an EXECUTE and for a post-authentication BLOCK, and
only when the audit entry and the transparency leaf are persisted — otherwise the field is **absent** (never `null`). It is
signed once, when the response is produced, with a **transparency** key: `signature = base64(Ed25519(SHA-256("QODIQA::RECEIPT::V1"
|| JCS-P1(receipt without signature))))`. Verify it offline with `scripts/audit-repro/verify/qodiqa-receipt-verify.js` and the
keys from `GET /.well-known/qodiqa/transparency-keys`. A receipt proves that the gateway **recorded** the decision, not that
the decision was correct. Receipts are kept for a bounded window (`QODIQA_RECEIPT_TTL_SECONDS`, default 3600 s); after it
this endpoint answers **404** — the durable evidence is the audit entry and the inclusion proof. A replayed artifact is not a
second request: its BLOCK carries no receipt.

---

### `GET /transparency/consistency/:fromRootId/:toRootId`

RFC 6962 consistency proof between two signed roots (`consistencyProof`,
`verification`). Computed from entry hashes only. **Capped:** a
`toRoot` covering more than `QODIQA_TRANSPARENCY_CONSISTENCY_MAX_LEAVES` entries
(default 250,000) returns **422 `CONSISTENCY_RANGE_TOO_LARGE`**. Proofs are
immutable and cached per (from, to) pair.

`verification.valid` is `true` only when the hash relation verifies **and** both
roots' signatures authenticate (ST23-07 /): `FROM_ROOT_SIGNATURE` and
`TO_ROOT_SIGNATURE` under transparency keys with status `active` or `deprecated`
(`SKIP` if the key store cannot be consulted, and then not valid). Root signatures
are re-checked on every request, including cached proofs, so a revoked key takes
effect immediately. `structurallyValid` and `authenticated` report the two halves
separately.

---

### Admin

| Route | Permission |
|---|---|
| `GET /transparency/admin/stats` | `READ_TRANSPARENCY_LOG` |
| `GET /transparency/admin/chain/validate` | `READ_TRANSPARENCY_LOG` |
| `POST /transparency/register` | `MANAGE_TRANSPARENCY_LOG`. 201 `{ transparencyId, entryHash, keyId, persisted, createdAt }` |
| `POST /transparency/admin/roots/generate` | `MANAGE_TRANSPARENCY_LOG` |

There is no gap-scan route. The gap scanner runs on its schedule
(`src/core/transparency/scanner/`).

---

## Policy Endpoints

Require `READ_POLICIES` or `MANAGE_POLICIES` permission.

---

### Reading and changing policies

The active policy set is managed through the policy UI API, `GET|POST /policy-ui/policies` and `GET|PUT /policy-ui/policies/:policyId`
(with `/enable`, `/disable`, `/versions`, `/diff`, `/rollback`, `/history`), and through the governed change workflow under
`/v1/policy/governance/*` (draft, review, approve, publish, rollback, emergency). The older `GET|POST /v1/policy` pair documented here
never existed in the current gateway.

---

### `POST /v1/policy/simulate`

Dry-run a policy evaluation without side effects. Requires `READ_POLICIES` permission.

**Request body:**

```json
{
  "artifact": { ... },
  "context":  { "clientIp": "1.2.3.4", "tenantId": "tenant-1" }
}
```

**Response — 200:**

```json
{
  "decision":     "EXECUTE" | "BLOCK",
  "reason":       "string",
  "matchedRules": [ { "ruleId": "...", "evaluator": "REQUIRE_CONSENT", "result": "PASS" } ]
}
```

---

## Consent Endpoints

Require `MANAGE_CONSENT` permission (roles: admin only).

**`action` MUST be the provider string, not a descriptive capability name.**
For every `REQUIRE_CONSENT` policy evaluation on `/ai/chat` (and `/verify/v2`),
the enforcement path (`src/validation/checkPolicy.js`) resolves the consent
lookup key's `action` as `artifact.payload.provider` — e.g. `"openai"`,
`"anthropic"`, `"local"` — exactly the provider name passed when the artifact
was signed. `ConsentStore.findByKey()` does an exact string match on `action`
with no aliasing: this is deliberate exact-match semantics for a
consent-enforcement platform, not a gap to be patched with a lookup table. A
consent record granted with any other `action` value (e.g. a human-readable
name like `"send-email"`) will **never** be found by `/ai/chat` and every
matching request will be denied with `CONSENT_NOT_FOUND`, even though the
record is correctly persisted and `ACTIVE`. Every example below uses a real
provider string for this reason.

**Consent revocation is not GDPR Article 17 erasure.** Every endpoint below
that revokes consent performs a state transition (`REVOKED`) — it never
deletes a row or scrubs any field, and `consent_audit_log` is never touched.
For an actual Article 17 erasure request, use `POST /v1/admin/dsr/:id/erase`
(see [`docs/guides/dsr.md`](../guides/dsr.md)).

**Field casing:** every request body below uses
camelCase — the same convention as every other resource in this API
(organizations, tenants, webhooks, ...). The legacy snake_case field names
(`actor_id`, `tenant_id`, `granted_by`, ...) are still accepted for backward
compatibility, translated internally to their camelCase equivalent, but are
deprecated: using one sets a `Deprecation: true` response header and logs a
`CONSENT_LEGACY_FIELD_CASING_USED` warning event. New integrations should use
camelCase exclusively. Response bodies (`record: {...}`) are unaffected by
this change and remain snake_case, matching the underlying Postgres schema.

---

### `POST /consent`

Grant consent for a subject.

```json
{
  "actorId": "user-123",
  "action": "openai",
  "lawfulBasis": "consent",
  "purpose": "Answer the user's questions with an AI assistant",
  "purposeCode": "assistant.qna",
  "scope": "standard",
  "requiredScope": "standard",
  "tenantId": "tenant-a",
  "subjectName": "Alice Smith",
  "actionDisplay": "Execute AI chat completion via the openai provider",
  "durationDays": 30
}
```

`actorId`, `action`, **`lawfulBasis`** and **`purpose`** are required. The last
two are required; every other field is optional.

- **`lawfulBasis`** is one of the six GDPR Art. 6(1) bases: `consent`, `contract`,
  `legal_obligation`, `vital_interests`, `public_task`, `legitimate_interests`.
- **`purpose`** is 1–500 characters.
- **`purposeCode`** (optional) matches `^[a-z0-9_.-]{1,64}$`.
- **`specialCategoryCondition`** (`art9_2_a` … `art9_2_j`, the Art. 9(2)
  conditions) is required when the scope is a GDPR Art. 9(1) special category.
  The seeded `biometric` and `medical` scopes are; missing it returns
  **400 `SPECIAL_CATEGORY_CONDITION_REQUIRED`**.
- **Returned record.** It carries `lawful_basis`, `purpose`, `purpose_code`,
  `special_category_condition` and `lawful_basis_status`.
  `LEGACY_UNSPECIFIED` marks records created or without a stated
  basis; they are never auto-labelled.

`action`
must be the exact provider string the request will be signed for (see the
callout above) — use `actionDisplay` for a human-readable label instead of
overloading `action` with one. Use either `expiresAt` (absolute ISO 8601
timestamp) or `durationDays` (relative, converted to an absolute expiry at
grant time) — not both.

### `POST /consent/:id/revoke`

Revoke a single consent record. Revocation is propagated to all instances via
Redis pub/sub within milliseconds.

```json
{ "revokedBy": "admin", "revocationReason": "actor decommissioned", "tenantId": "tenant-a" }
```

All fields are optional.

### `POST /consent/actor/:actorId/revoke`

Revoke every non-terminal consent record for an actor in one call (e.g. when
an actor is decommissioned). Same optional body shape as `revocationReason`
above (no `tenantId` — this route revokes across every tenant for the actor).

### `DELETE /consent/actor/:actorId` — **Deprecated**

Legacy alias for `POST /consent/actor/:actorId/revoke` above, kept only for
backward compatibility. It behaves
identically — it has never deleted anything, despite the verb — but is
misleadingly named: the DELETE verb implies deletion, and this endpoint only
revokes consent. Calling it returns `Deprecation: true`, a `Sunset` date, and
a `Link` header pointing at the successor endpoint, and logs a
`CONSENT_DELETE_ACTOR_DEPRECATED_USED` warning event on every call. New
integrations should use `POST /consent/actor/:actorId/revoke` instead.

### `POST /consent/:id/suspend`

Temporarily suspend consent without revoking.

```json
{ "suspendedBy": "admin", "suspensionReason": "investigation", "suspendedUntil": "2026-08-01T00:00:00Z", "tenantId": "tenant-a" }
```

All fields are optional.

### `POST /consent/:id/resume`

Resume a suspended consent.

```json
{ "resumedBy": "admin", "tenantId": "tenant-a" }
```

All fields are optional.

### `POST /consent/verify`

Ad-hoc verification check — does not create, modify, or delete anything.

```json
{ "actorId": "user-123", "action": "openai", "tenantId": "tenant-a", "requiredScope": "standard" }
```

`actorId` and `action` are required.

### `GET /consent`

List consent records. Paginated. Accepts `?actorId=`, `?action=`,
`?tenantId=`, and `?state=` filters (the first two of which also accept the
deprecated `actor_id`/`tenant_id` query param spellings).

---

### Consent route error codes

Every endpoint above returns the standard [management API envelope](#response-envelopes)
on failure. The `error.code` values specific to this route group:

| Code | Status | Cause |
|------|--------|-------|
| `BAD_REQUEST` | 400 | Zod schema validation failed on the request body/query (any endpoint) |
| `NOT_FOUND` | 404 | Record lookup miss (`GET /consent/:id`, `GET /consent/:id/status`) |
| `INTERNAL_ERROR` | 500 | Registry exception that isn't recognized as a client error. **Caveat:** this classification is a string-prefix match on the thrown error's message (`startsWith('Cannot ')` / `startsWith('Invalid transition')`), not a typed error code — a routine message wording change elsewhere in the registry could silently reclassify a `BAD_REQUEST` into an `INTERNAL_ERROR` with no test able to catch the drift from this route file alone. |
| `METHOD_NOT_ALLOWED` | 405 | Any unmounted method on a `/consent*` route |

**Same codes surfacing through other envelopes for the identical underlying decision:** the
`CONSENT_*` codes from `/ai/chat`'s and `/verify`'s block-reason tables (`CONSENT_NOT_FOUND`,
`CONSENT_REVOKED`, etc.) are the *same* decision produced by a *different* code path —
`ConsentVerifier` invoked directly by `POST /consent/verify` above (this section's management
envelope, 403) versus invoked indirectly through the `REQUIRE_CONSENT` policy evaluator inside
`/ai/chat`'s enforcement pipeline (the core protocol `BLOCK` envelope) versus the same codes
again inside `/verify`'s always-200 body. Three different envelopes, three different
HTTP-status conventions, for what is conceptually one consent decision — a client integrating
against more than one of these surfaces must not assume a shared response shape.

---

## RBAC Endpoints

Require `MANAGE_USERS` or `READ_USERS` permission (roles: admin).

---

### `GET /rbac/users`

List all operator users.

### `POST /rbac/users`

Create a new operator user with role assignment.

**Request body:**

```json
{
  "username": "alice",
  "role":     "auditor",
  "createdBy": "admin"
}
```

**Response — 201:**

```json
{
  "userId":  "uuid",
  "username": "alice",
  "role":    "auditor",
  "apiKey":  "raw API key (shown once only)"
}
```

### `DELETE /rbac/users/:id`

Delete an operator user and invalidate their API key.

---

## Webhook Endpoints

Require `MANAGE_WEBHOOKS` permission (roles: admin only).

---

### `POST /v1/webhooks`

Register a new webhook endpoint.

**Request body:**

```json
{
  "url":        "https://your-server.example.com/webhooks/qodiqa",
  "events":     ["sign.created", "verify.failed", "policy.blocked"],
  "description": "Production webhook"
}
```

**Response — 201:**

```json
{
  "webhookId": "uuid",
  "secret":    "raw HMAC secret (shown once only)"
}
```

---

### `GET /v1/webhooks`

List registered webhooks.

### `DELETE /v1/webhooks/:id`

Delete a webhook registration.

### `POST /v1/webhooks/:id/test`

Send a test event to the webhook endpoint.

---

## Multi-Tenant Administration

Require `MANAGE_USERS` permission (roles: admin only).

---

### `POST /v1/admin/tenants`

Register a new tenant.

**Request body:**

```json
{
  "tenantId":   "tenant-1",
  "tenantName": "Acme Corp Production"
}
```

**`organizationId` (optional):** stored on the tenant record and echoed back
in the response, but does **not** by itself activate organization-status
enforcement — a tenant created with `organizationId` set is not blocked when
its organization is later suspended until it is also linked via
`POST /v1/admin/organizations/:orgId/tenants/:tenantId` (below). Supplying
`organizationId` here emits a `WARN TENANT_ORG_NOT_ENFORCEMENT_LINKED` log
line as an operator-facing reminder of the gap.

### `GET /v1/admin/tenants`

List all registered tenants.

### `PATCH /v1/admin/tenants/:tenantId`

Update a tenant's status (`active`, `suspended`, `disabled`).

### `POST /v1/admin/organizations`

Register a new organization.

### `GET /v1/admin/organizations`

List all organizations.

### `POST /v1/admin/organizations/:orgId/tenants/:tenantId`

Link a tenant to an organization for enforcement. This is the call that
actually activates `assertActiveOrganization()` checks (e.g. blocking a
tenant when its organization is suspended) — creating a tenant with
`organizationId` set does not do this on its own (see the note above).
Auto-registers the tenant if it does not already exist. Idempotent.

### `DELETE /v1/admin/organizations/:orgId/tenants/:tenantId`

Unlink a tenant from an organization; enforcement reverts to inactive.

---

## OpenAPI Specification

### `GET /openapi.json`

Returns the auto-generated OpenAPI 3.1 specification for all routes.

### `GET /openapi.yaml`

Returns the OpenAPI specification in YAML format.

### `GET /`

Serves the Swagger UI if `Accept: text/html` is sent, or redirects to `/openapi.json`.

---

## HTTP Status Code Summary

| Code | Meaning |
|------|---------|
| 200 | Success — including a policy/verification `BLOCK` decision on `/ai/chat` and `/verify` (long-standing): `decision` is the field to check, not the status code. |
| 201 | Resource created |
| 400 | Bad request — schema/shape validation failure (malformed or missing required fields). This is the standard code for any request-body/query/param parse failure across the API (API-9 remediation). |
| 401 | Authentication required |
| 403 | Insufficient permission (RBAC/opsAuth/signAuth) — no longer used for `/ai/chat` policy/verification BLOCK decisions as; still used for genuine authentication/authorization failures on `/sign`, `/admin/*`, and other operator-gated routes. |
| 404 | Endpoint not found or resource does not exist |
| 405 | Method not allowed |
| 409 | Conflict — the request is well-formed but conflicts with existing state (e.g. a username/role already in use, an idempotency key reused with a different body, a rotation already in progress). |
| 413 | Artifact header too large |
| 415 | Unsupported Content-Type (must be application/json) |
| 422 | Unprocessable entity — a post-parse business-rule violation on an otherwise well-formed request (e.g. attempting to modify a built-in RBAC role, a policy failing semantic validation). Reserved for this narrower case; schema-shape failures use 400 instead (see above). |
| 500 | Internal server error |
| 503 | Service unavailable (Redis down, shutting down) |
| 504 | Gateway timeout (AI_CHAT_TIMEOUT_MS exceeded) |

**400 vs 409 vs 422 — the rule applied consistently across this API (API-9 remediation):** a
request that fails to parse (wrong type, missing required field, invalid enum value) is
**400**. A request that parses fine but collides with existing state is **409**. A request
that parses fine but fails a business rule evaluated *after* parsing is **422**. Before this
remediation, several routes (`rbacAdmin.js`, `admin/signingIdentities.js`, `prqDlq.js`) used
422 for plain schema-validation failures — this has been standardized to 400 across the
board; see `CHANGELOG.md`.

**Core protocol `reason` codes:** the `{decision, reason,
details, requestId}` envelope's `reason` field (returned by `/ai/chat`, `/verify`, and the
streaming path) draws from a single machine-readable catalog — `src/errors/catalog.js` —
mapping every code to its HTTP status, a human description, its pipeline category, and
whether it's safe to retry. This replaces what used to be three independently-maintained,
occasionally-drifting copies of the same vocabulary (`src/reasons.js`, `docs/operations/troubleshooting.md`,
and `docs/architecture/enforcement-flow.md`); see those two documents for prose troubleshooting guidance keyed
to the same codes, and `src/errors/__tests__/catalog.governance.test.js` for the drift-
prevention test.

---

## Response Headers

All responses include:

| Header | Value | Description |
|--------|-------|-------------|
| `Cache-Control` | `no-store` | Prevents caching of any response |
| `X-Request-ID` | request ID string | Unique identifier for this request |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents iframe embedding |
| `Strict-Transport-Security` | `max-age=...` | HSTS (production only) |
| `Content-Security-Policy` | API_CSP or PORTAL_CSP | Controls resource loading |
| `Permissions-Policy` | all features denied | Restricts browser features |

---

endpoint is added, an existing endpoint's schema changes, or a reason code is added or renamed.*
