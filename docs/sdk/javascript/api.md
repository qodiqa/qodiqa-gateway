# JavaScript SDK — API Reference

Every symbol on this page is exported from the package entry point
[`sdk/javascript/src/index.ts`](../../../sdk/javascript/src/index.ts) and is
importable as `import { X } from '@qodiqa/sdk'`. Nothing on this page is
aspirational — each signature, default, and thrown error was read directly
from the corresponding source file, cited under each heading.

**Maintained SDK.** `sdk/javascript` (`@qodiqa/sdk`) is the maintained
JavaScript/TypeScript SDK.

## Contents

1. [QodiqaClient](#1-qodiqaclient)
2. [sign — SignResource](#2-sign--signresource)
3. [chat — ChatResource](#3-chat--chatresource)
4. [verify — VerifyResource](#4-verify--verifyresource)
5. [portal — PortalResource](#5-portal--portalresource)
6. [attestation — AttestationResource](#6-attestation--attestationresource)
7. [transparency — TransparencyResource](#7-transparency--transparencyresource)
8. [evidence — EvidenceResource](#8-evidence--evidenceresource)
9. [certification — CertificationResource](#9-certification--certificationresource)
10. [webhooks — WebhooksResource](#10-webhooks--webhooksresource)
11. [simulation — SimulationResource (policy dry-run)](#11-simulation--simulationresource-policy-dry-run)
12. [Error handling](#12-error-handling)
13. [Retry policy](#13-retry-policy)
14. [Pagination](#14-pagination)
15. [Webhook signature verification](#15-webhook-signature-verification)
16. [Local Artifact & Transparency-Proof Verification (offline)](#16-local-artifact--transparency-proof-verification-offline)
17. [TypeScript types](#17-typescript-types)

---

## 1. QodiqaClient

Source: [`sdk/javascript/src/client.ts`](../../../sdk/javascript/src/client.ts)

### Constructor

```typescript
new QodiqaClient(config?: QodiqaClientConfig)
```

Resolves defaults via `resolveConfig`, validates via `validateConfig` (throws
`ValidationError` synchronously on bad input — see
[configuration.md](configuration.md)), then constructs one `HttpClient`, one
`AuthProvider`, and one instance of each resource class below, all sharing the
same resolved configuration.

### Resource accessors (readonly properties)

| Property | Type | Wraps |
|---|---|---|
| `sign` | `SignResource` | `POST /sign` |
| `chat` | `ChatResource` | `POST /ai/chat` |
| `verify` | `VerifyResource` | `POST /verify`, `POST /verify/v2` |
| `portal` | `PortalResource` | `/v1/portal/*` |
| `attestation` | `AttestationResource` | `/v1/attestation/*` |
| `transparency` | `TransparencyResource` | `/v1/transparency/*` |
| `evidence` | `EvidenceResource` | `/v1/attestation/:id/evidence` |
| `certification` | `CertificationResource` | `/v1/certification/*`, `/v1/certifications/*` |
| `webhooks` | `WebhooksResource` | `/v1/webhooks/*` |
| `simulation` | `SimulationResource` | `/v1/policy/simulate`, `/v1/policy/compare`, `/v1/policy/simulate/batch` |

### Convenience methods

These call the HTTP client directly rather than going through a resource class.

#### `healthCheck()`

- **Purpose**: Liveness probe.
- **Signature**: `healthCheck(): Promise<HealthResponse>`
- **Parameters**: none
- **Returns**: `{ status: 'ok', uptime: number }`
- **HTTP**: `GET /health`
- **Exceptions**: `NetworkError`, `TimeoutError` (never returns a non-2xx — this endpoint does not check dependencies)
- **Example**:
  ```typescript
  const health = await client.healthCheck;
  console.log(health.status, health.uptime);
  ```

#### `readinessCheck()`

- **Purpose**: Readiness probe — checks dependency health.
- **Signature**: `readinessCheck(): Promise<ReadyResponse>`
- **Returns**: `{ ready: boolean, components: { nonceStore, anomalyStore, rateLimitStore, persistenceStore, consentSubscriber, consentCache, admission, auditBacklog } }` — eight booleans (`src/api/routes/ready.js`). `consentCache` is informational and never by itself makes `ready` false; `admission` is false while admission control's queue is full and `auditBacklog` while the audit mirror backlog is above its bound (both typed optional in `ReadyResponse`, since older servers omit them).
- **HTTP**: `GET /ready`
- **Exceptions**: `NetworkError`, `TimeoutError`; the server itself returns HTTP 503 (mapped to `ServerError`) if any dependency is down, per [`docs/architecture/overview.md`](../../architecture/overview.md)
- **Notes**: This corresponds to the Kubernetes readiness probe described in the **Readiness Probe** glossary entry.

#### `getPublicKeys()`

- **Purpose**: Fetch all active Ed25519 signing public keys.
- **Signature**: `getPublicKeys(): Promise<KeysResponse>`
- **Returns**: `{ keys: PublicKey[] }` where `PublicKey = { keyId, algorithm, publicKey, status }`
- **HTTP**: `GET /public-keys`

#### `getPublicKey(keyId)`

- **Purpose**: Fetch a single public key by ID via the well-known discovery endpoint.
- **Signature**: `getPublicKey(keyId: string): Promise<PublicKey>`
- **Parameters**: `keyId: string` — must be non-empty
- **Returns**: `PublicKey`
- **HTTP**: `GET /.well-known/qodiqa/keys/:keyId` (`keyId` is `encodeURIComponent`-escaped)
- **Exceptions**: `ValidationError` if `keyId` is empty/whitespace (`assertNonEmpty`); `NotFoundError` if the key does not exist

#### `getAuditChain(artifactId)`

- **Purpose**: Retrieve the full hash-chained audit trail for an artifact.
- **Signature**: `getAuditChain(artifactId: string): Promise<ApiResponse<AuditResponse>>`
- **Parameters**: `artifactId: string` — must be non-empty. Use the `artifactId` returned by `sign.sign()`; the `requestId` in a chat/verify response is the per-HTTP trace id (`X-Request-ID`), not the artifact id.
- **Returns**: the standard success envelope `{ status, timestamp, requestId, data }` whose `data` is `AuditResponse = { artifactId, decision, reason, timestamp, chain: AuditChainEntry[], requestId }` — read `res.data.decision`, not `res.decision`.
- **HTTP**: `GET /audit/:artifactId`
- **Auth**: Requires `apiKey` (ops key) — the route is mounted behind `adminStack('READ_AUDIT')`; without it the SDK throws `AuthenticationError` client-side.
- **Exceptions**: `ValidationError` if `artifactId` is empty; `AuthenticationError`/`AuthorizationError` without a valid ops key or the `READ_AUDIT` permission; `NotFoundError` if no audit record exists
- **Notes**: See the **Audit Chain** and **Hash Chain** glossary entries for the tamper-evident structure of `chain`.

---

## 2. sign — SignResource

Source: [`sdk/javascript/src/resources/sign.ts`](../../../sdk/javascript/src/resources/sign.ts)

### `sign(request, artifactHeader?)`

- **Purpose**: Issue a signed [artifact](../../glossary.md) via `POST /sign`. This is the only way to obtain an artifact through the SDK — artifact signing itself happens server-side.
- **Signature**: `sign(request: SignRequest, artifactHeader?: string): Promise<SignResponse>`
- **Parameters**:
  | Name | Type | Required | Notes |
  |---|---|---|---|
  | `request.request.method` | `HttpMethod` | yes | Must be non-empty |
  | `request.request.path` | `string` | yes | Must be non-empty |
  | `request.request.body` | `Record<string, unknown>` | yes | The body the resulting artifact will be bound to (see **Request Binding** in the glossary) |
  | `request.payload` | `Record<string, unknown>` | no | Arbitrary metadata (e.g. `userId`, `sessionId`) embedded in the artifact payload |
  | `request.payload.provider` | `string` | conditional | Required only when `request.request.path` is `/ai/chat` and the server has more than one AI provider enabled (`400 PROVIDER_REQUIRED` otherwise). With exactly one provider enabled it is auto-resolved when omitted. Ignored for any non-`/ai/chat` path. See `docs/api/overview.md#post-sign`. |
  | `request.ttl` | `number` (ms) | no | Requested artifact lifetime; server clamps to `MIN_TTL_MS`–`MAX_TTL_MS` |
  | `request.request.query` | `string` | no, with `v2` | Protocol V2: the raw query string WITHOUT `?`, bound into the artifact. A raw `+` or `;` is refused (`400 QUERY_NOT_BINDABLE`) — write `%20`, `%2B`, `%3B` |
  | `request.request.headers` | `Record<string,string>` | no, with `v2` | Protocol V2: the values of the headers named in `v2.bind.headers` (lower-case names) |
  | `request.v2` | `SignV2Options` | no | Issue a protocol-V2 artifact (needs `QODIQA_PROTOCOL_V2_ISSUE=true` on the gateway): `{ bind: { headers: string[] }, model?: string \| null, limits?: { maxTokens?: number }, crit?: string[] }`. The artifact then binds method, path, query, the listed headers and the body (JCS-P1), authorizes one model and caps the provider output (`maxTokens`) |
  | `artifactHeader` | `string` (base64) | no | An existing artifact to attach as `x-qodiqa-artifact`, to chain authorization |
- **Returns**: `SignResponse = { artifactId, artifact: Artifact, meta: { keyId, expiresAt, tenantId }, requestId }`
- **Auth**: Requires `signToken` — a per-identity signing API key (`sk_...`), sent as `Authorization: Bearer <signToken>`.
- **Exceptions**:
  - `ValidationError` — thrown client-side if `request.request.method` or `.path` is empty
  - `AuthenticationError` — thrown client-side (before any network call) if no `signToken` is configured
  - `AuthenticationError` — thrown by the server if the sign token is invalid
  - Server responds `400 PROVIDER_REQUIRED` / `PROVIDER_NOT_SUPPORTED` / `PROVIDER_NOT_CONFIGURED` for `/ai/chat`-bound requests with an unresolvable or invalid provider — see notes above
- **Example** (single-provider deployment — `provider` auto-resolves):
  ```typescript
  const signed = await client.sign.sign({
    request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello world' } },
    payload: { userId: 'user_123', sessionId: 'sess_abc' },
    ttl: 60_000, // the server clamps any larger ttl to 60 s
  });
  console.log(signed.artifactId, signed.meta.keyId, signed.meta.expiresAt);
  ```
  **Example** (multiple providers enabled — `provider` must be explicit):
  ```typescript
  const signed = await client.sign.sign({
    request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello world' } },
    payload: { userId: 'user_123', provider: 'openai' },
    ttl: 60_000, // the server clamps any larger ttl to 60 s
  });
  ```
- **Notes**: The returned `artifact` object must be base64-JSON-encoded before use as an `x-qodiqa-artifact` header value: `Buffer.from(JSON.stringify(signed.artifact)).toString('base64')`. The SDK does not do this encoding for you.
  **Example** (protocol V2 — a bound query, a bound header, one authorized model, an output cap):
  ```typescript
  const signed = await client.sign.sign({
    request: { method: 'POST', path: '/v1/ai/chat', query: 'stream=true', headers: { 'x-tenant': 'acme' }, body: { prompt: 'Hello world', model: 'gpt-4' } },
    v2: { bind: { headers: ['x-tenant'] }, model: 'gpt-4', limits: { maxTokens: 256 } },
  });
  // the call to /v1/ai/chat must then carry the same query and the same x-tenant header, or it fails with REQUEST_MISMATCH
  ```

---

## 3. chat — ChatResource

Source: [`sdk/javascript/src/resources/chat.ts`](../../../sdk/javascript/src/resources/chat.ts)

### `create(artifact, request)`

- **Purpose**: Execute an AI prompt through the full QODIQA enforcement pipeline.
- **Signature**: `create(artifact: string, request: ChatRequest, options?: ChatCreateOptions): Promise<ChatResponse>` — `ChatCreateOptions = { idempotencyKey?: string }`
- **Parameters**:
  | Name | Type | Required | Notes |
  |---|---|---|---|
  | `artifact` | `string` (base64) | yes | From `sign.sign(...).artifact`, JSON-stringified and base64-encoded |
  | `request.prompt` | `string` | yes | Must be non-empty |
  | `request.model` | `string` | no | Provider-specific model identifier |
  | `options.idempotencyKey` | `string` | no | Sent as `Idempotency-Key` ([docs/architecture/IDEMPOTENCY_KEY.md](../../architecture/IDEMPOTENCY_KEY.md)); must be non-empty when given. After an outcome-unknown failure (e.g. a 504), retry with a freshly signed artifact and the same key — the server replays the original result instead of running it twice. Not accepted by `stream()` (`IDEMPOTENCY_STREAMING_UNSUPPORTED`). |
- **Returns**: `ChatResponse = { decision: 'EXECUTE' | 'BLOCK', reason, aiText?, responseId?, model?, tokenUsage?: { prompt_tokens, completion_tokens, total_tokens }, requestId }`
- **Auth**: Requires the artifact — sent as `x-qodiqa-artifact`.
- **Exceptions**:
  - `ValidationError` — client-side (before any network call), if `artifact`, `request.prompt` or a given `options.idempotencyKey` is empty/whitespace
  - `VerificationError` — server-side, if the artifact is missing, undecodable, has an invalid/unverifiable signature, is expired, replayed or bound to a different request (any of the `VERIFICATION_REASONS`) — thrown even when the server answers HTTP 200 (this is distinct from a policy `BLOCK` decision — see [Error handling](#12-error-handling))
  - `ServerError` (503 `SERVER_OVERLOADED`, after the automatic resends), `RateLimitError` (429), `ServerError` 502/504 (provider), `ValidationError` 400/422; a 409 `IDEMPOTENCY_*`, 413 or 415 currently surfaces as `UnknownError` — non-BLOCK HTTP errors
- **Example**:
  ```typescript
  const chat = await client.chat.create(artifactB64, { prompt: 'Explain quantum computing.', model: 'gpt-4' });
  if (chat.decision === 'EXECUTE') {
    console.log(chat.aiText, chat.tokenUsage?.total_tokens);
  } else {
    console.log('Blocked:', chat.reason);
  }
  ```
- **Notes**: A policy/consent/semantic `BLOCK` decision is *returned*, not thrown — read `decision` (in the server's default `QODIQA_BLOCK_HTTP_MODE=decision` it is an HTTP 200). An artifact rejection (the 31 artifact-rejection reasons in `VERIFICATION_REASONS` (the server's `artifact_malformed`, `artifact_invalid`, `request_mismatch` and `replay` classes, src/api/blockHttpStatus.js — e.g. `INVALID_SIGNATURE`, `KEY_REVOKED`, `EXPIRED`, `REQUEST_MISMATCH`, `REPLAY_DETECTED`)) is always thrown as `VerificationError`, whatever HTTP status the server used — exactly as `stream()` does for the same response. `create()` is not resent on a 5xx or 429 (the artifact nonce may already be consumed); only a 503 `SERVER_OVERLOADED` is resent — see [Retry policy](#13-retry-policy).

### `stream(artifact, request, options?)`

- **Purpose**: Execute an AI prompt through the same enforcement pipeline as `create()`, requesting an SSE stream (`POST /ai/chat` with `stream: true`) and yielding each event as it arrives instead of waiting for the full response. Added for (previously the only way to reach the server's real streaming capability was to bypass the SDK and hand-roll `fetch`/`EventSource` against the raw endpoint).
- **Signature**: `stream(artifact: string, request: ChatRequest, options?: ChatStreamOptions): AsyncGenerator<ChatStreamEvent>`
- **Parameters**:
  | Name | Type | Required | Notes |
  |---|---|---|---|
  | `artifact` | `string` (base64) | yes | From `sign.sign(...).artifact`, JSON-stringified and base64-encoded — signed with `stream: true` already in `request.body` (see Notes) |
  | `request.prompt` | `string` | yes | Must be non-empty |
  | `request.model` | `string` | no | Provider-specific model identifier |
  | `options.signal` | `AbortSignal` | no | Aborting closes the underlying connection immediately |
  | `options.timeout` | `number` (ms) | no | Overall time budget for the whole streaming session. **Unset by default** — deliberately not inherited from `QodiqaClientConfig.timeout` (whose 30s default would truncate almost every real stream); the server itself bounds a session at `STREAM_MAX_DURATION_MS` (default 5 minutes) |
- **Returns**: `AsyncGenerator<ChatStreamEvent>`, one of:
  | `event` | Shape | When |
  |---|---|---|
  | `stream_started` | `{ event, streamId, requestId, artifactId, provider, model }` | Always first; enforcement passed and SSE headers were flushed |
  | `chunk_forwarded` | `{ event, delta, index }` | One per incremental delta from the provider, strictly ordered by `index` |
  | `stream_completed` | `{ event, streamId, requestId, chunksTotal, bytesTotal, durationMs }` | Terminal event on normal completion |
  | `stream_cancelled` | `{ event, streamId, reason, requestId }` | Terminal event on client disconnect, server-side stream timeout, or a provider error; `reason` is e.g. `'CLIENT_DISCONNECT'`, `'STREAM_TIMEOUT'`, `'SEMANTIC_OUTPUT_BLOCKED'`, `'OUTPUT_TOO_LARGE'`, `'AUDIT_UNREPRESENTABLE_TEXT'`, `'PROVIDER_ERROR'` or another provider error code — a mid-stream error is this event, not an exception |

  Exactly one terminal event (`stream_completed` or `stream_cancelled`) is always the last event yielded. The raw `data: [DONE]\n\n` sentinel that follows it on the wire ends iteration internally and is never itself yielded. Field shapes mirror `src/streaming/streamEnforcer.js` and `docs/architecture/streaming.md` §5 exactly — not the outdated hand-written snippet in `docs/api/overview.md`, which still shows a `stream_error` event this server version never sends and a `totalChunks` field renamed to `chunksTotal`.
- **Auth**: Requires the artifact — sent as `x-qodiqa-artifact`, identically to `create()`.
- **Exceptions**:
  - `ValidationError` — client-side, if `artifact` or `request.prompt` is empty
  - `VerificationError` — server-side, before the stream opens, if the artifact is rejected (any `VERIFICATION_REASONS` code, e.g. signed without `stream: true` in its body → `REQUEST_MISMATCH`, or invalid/expired/replayed), at any HTTP status
  - `BlockedError` — a non-artifact enforcement `BLOCK` (policy, consent, semantic, …) decided before the stream opened, which the default `decision` mode answers as HTTP 200 JSON; in the opt-in `status` mode the same BLOCK arrives as 403/429/503 and maps by status (`AuthorizationError`/`RateLimitError`/`ServerError`) —
  - `ServerError` 503 `SERVER_OVERLOADED` — only after the automatic pre-stream resends are exhausted (see Notes); any other pre-stream error is thrown at once
  - `TimeoutError` — only if `options.timeout` was passed and elapsed
  - `ServerError` — the server sent a `data:` frame that was neither valid JSON nor the `[DONE]` sentinel (a protocol violation)
  - `NetworkError` — the connection dropped or was aborted mid-stream, **or the body ended without the terminal `[DONE]` frame** (a truncated stream: proxy idle timeout, clean reset, server crash between frames). The events already yielded are a partial answer; never treat them as complete.
- **Example**:
  ```typescript
  const CHAT_BODY = { prompt: 'Explain quantum computing.', model: 'gpt-4', stream: true };
  const signed = await client.sign.sign({ request: { method: 'POST', path: '/ai/chat', body: CHAT_BODY } });
  const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');

  for await (const event of client.chat.stream(artifactB64, CHAT_BODY)) {
    if (event.event === 'chunk_forwarded') process.stdout.write(event.delta);
    if (event.event === 'stream_completed') console.log('\ndone:', event.chunksTotal, 'chunks');
  }
  ```
- **Notes**: `request` must be the exact body passed to `sign.sign()`, including `stream: true` — the server binds the artifact to it via `requestHash`. `stream()` sets `stream: true` on the wire body it sends, so the same object can be passed to both calls unmodified. Once the stream has opened it is never retried (see [Retry policy](#13-retry-policy)) — a partially-consumed SSE session is not a safely-repeatable single call. The one pre-stream refusal that is resent is a 503 `SERVER_OVERLOADED` (admission control answers it before the artifact nonce is registered, so the same artifact is still valid): up to `maxRetries` times, after the server's `Retry-After` (else the jittered back-off); a `Retry-After` above 30 s, or one that would outlive `options.timeout`, throws the 503 instead. Never for a request carrying `X-QODIQA-OTP`. A full runnable example is at [`sdk/javascript/examples/node/streaming.js`](../../../sdk/javascript/examples/node/streaming.js); see also [`sdk/javascript/README.md`](../../../sdk/javascript/README.md#chat) and `docs/architecture/streaming.md` for the full server-side protocol.

---

## 4. verify — VerifyResource

Source: [`sdk/javascript/src/resources/verify.ts`](../../../sdk/javascript/src/resources/verify.ts)

> **note.** `verify()` previously also sent the artifact as an
> `x-qodiqa-artifact` header. The `/verify` route (`src/api/routes/verify.js`)
> has never read that header — it takes the artifact only from the request
> body — so the header was a no-op that misrepresented the wire protocol.
> It has been removed; `verify()`'s `artifact` parameter is kept (and still
> validated as non-empty) only for call-site backward compatibility.

### `verify(artifact, request)`

- **Purpose**: Verification via `POST /verify`. The artifact travels only in `request.artifact`; no header is sent.
- **Signature**: `verify(artifact: string, request: VerifyRequest): Promise<VerifyResponse>`
- **Parameters**: `artifact: string` (base64, non-empty — validated client-side, not transmitted); `request: { artifact: Artifact, request: { method, path, body } }`
- **Returns**: `VerifyResponse = { decision, reason, details, requestId, artifactId?, keyId?, callerId? }`
- **Auth**: None.
- **Exceptions**: `ValidationError` (empty `artifact`, or bad request body), `VerificationError`
- **HTTP**: `POST /verify`

### `verifyV2(request)`

- **Purpose**: Verification via `POST /verify/v2`. Server-side, this runs through the exact same handler as `verify()`/`dryRun()` (`_makeVerifyHandler` in `src/api/routes/verify.js` is shared by both `/verify` and `/verify/v2`) — the only difference is the route's rate-limit bucket (`verify_v2` vs. `verify_public`).
- **Signature**: `verifyV2(request: VerifyRequest): Promise<VerifyResponse>`
- **Parameters**: `request: VerifyRequest` (must include a populated `artifact` field)
- **Returns**: `VerifyResponse` — identical shape to `verify()`
- **Auth**: None.
- **Exceptions**: `ValidationError` (bad request body), `VerificationError`
- **HTTP**: `POST /verify/v2`

### `dryRun(request)`

- **Purpose**: Verification via `POST /verify` with the artifact supplied only in the request body. Since `verify()` no longer sends a header either, `dryRun()` and `verify()` now send an identical wire request — `dryRun()` is retained as a distinct method (it predates the header removal) for callers who don't want to also pass a redundant `artifact` string argument.
- **Signature**: `dryRun(request: VerifyRequest): Promise<VerifyResponse>`
- **Parameters**: `request: VerifyRequest` (must include a populated `artifact` field)
- **Returns**: `VerifyResponse`
- **HTTP**: `POST /verify`
- **Example**:
  ```typescript
  const result = await client.verify.verify(artifactB64, {
    artifact: signed.artifact,
    request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello' } },
  });
  console.log(result.decision, result.reason);

  const v2 = await client.verify.verifyV2({
    artifact: signed.artifact,
    request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello' } },
  });

  const dry = await client.verify.dryRun({
    artifact: signed.artifact,
    request: { method: 'POST', path: '/ai/chat', body: {} },
  });
  ```

---

## 5. portal — PortalResource

Source: [`sdk/javascript/src/resources/portal.ts`](../../../sdk/javascript/src/resources/portal.ts)

Synchronous artifact verification through the public verification portal. There is no queued submit/poll API: `verify()` runs the full check suite and returns the complete report in one call. (Earlier versions of this page documented `submit()`, `getStatus()` and `waitForResult()`; none of them exists in `portal.ts`.)

| Method | Signature | HTTP | Returns |
|---|---|---|---|
| `verify(artifact)` | `verify(artifact: Artifact): Promise<ApiResponse<PortalVerifyResult>>` | `POST /v1/portal/verify` | `data = { verificationId, overallResult, failedCheck, failureReason, warnings, checks, metadata, durationMs, verifiedAt }` |
| `getResult(verificationId)` | `getResult(verificationId: string): Promise<ApiResponse<{ verification: PortalVerificationRecord }>>` | `GET /v1/portal/result/:id` | The persisted record (snake_case PostgreSQL row) |

- **Auth**: none (rate-limited only).
- **Body**: the request body *is* the raw artifact object — not base64, not wrapped in `{ artifact, request }`.
- **Exceptions**: `ValidationError` (empty `verificationId`, or a 400 from the server); `RateLimitError`; `NotFoundError` from `getResult()` when the id is unknown **or PostgreSQL is disabled server-side** (the portal history store is PostgreSQL-only, so even an id `verify()` just returned 404s without it).
- **Example**:
  ```typescript
  const { data } = await client.portal.verify(signed.artifact);
  console.log(data.overallResult, data.failedCheck);
  const { data: stored } = await client.portal.getResult(data.verificationId);
  console.log(stored.verification.overall_result);
  ```

---

## 6. attestation — AttestationResource

Source: [`sdk/javascript/src/resources/attestation.ts`](../../../sdk/javascript/src/resources/attestation.ts)

An [attestation](../../glossary.md) documents a point-in-time evaluation of an artifact.

| Method | HTTP | Auth | Returns |
|---|---|---|---|
| `verify({ artifact })` | `POST /v1/attestation/verify` | public | `ApiResponse<AttestationRecord>` |
| `verifyEvidence({ artifact })` | `POST /v1/attestation/evidence/verify` | public | `ApiResponse<unknown>` |
| `verifyChain({ artifact })` | `POST /v1/attestation/chain/verify` | public | `ApiResponse<unknown>` |
| `get(id)` | `GET /v1/attestation/:id` | public | `ApiResponse<AttestationRecord>` |
| `export(id)` | `GET /v1/attestation/:id/export` | **ops key** (`EXPORT_ATTESTATIONS`) | `ApiResponse<AttestationRecord>` |
| `getEvidence(id)` | `GET /v1/attestation/:id/evidence` | **ops key** | `ApiResponse<unknown>` |
| `getSummary(id)` | `GET /v1/attestation/:id/summary` | **ops key** | `ApiResponse<unknown>` |
| `list(params?)` | `GET /v1/attestation/admin/history` | **ops key** | `ApiResponse<PaginatedResponse<AttestationRecord>>` |
| `stats()` | `GET /v1/attestation/admin/stats` | **ops key** | `ApiResponse<unknown>` |

All `id`-taking methods throw `ValidationError` if `id` is empty. Ops-protected
methods throw `AuthenticationError` client-side if no `apiKey` is configured
(via `auth.getAuthHeader()`), before any network call is made.

```typescript
const record = await client.attestation.verify({ artifact: signed.artifact });
console.log(record.data.attestationId, record.data.status); // 'VALID' | 'INVALID'

const history = await client.attestation.list({ page: 1, pageSize: 50 }); // requires apiKey

const exported = await client.attestation.export('att-001'); // requires apiKey
console.log(exported.data.attestationId);
```

### `export(id)`

- **Purpose**: Export an attestation record for audit/regulatory review, matching the server's default (JSON) export.
- **Signature**: `export(id: string): Promise<ApiResponse<AttestationRecord>>`
- **HTTP**: `GET /v1/attestation/:id/export`
- **Auth**: **Ops API key required**, with the `EXPORT_ATTESTATIONS` permission (`requirePermission('EXPORT_ATTESTATIONS')` in `src/api/routes/attestation.js`).
- **Exceptions**: `ValidationError` (empty `id`); `AuthenticationError` client-side if no `apiKey` is configured; `NotFoundError` if the attestation does not exist
- **Scope note**: the server also supports `?format=pdf` on this route, streaming a rendered PDF instead of JSON (see `_streamAttestationPdf` in `src/api/routes/attestation.js`). This method does not expose that mode — `sdk/javascript/src/http.ts`'s `HttpClient` only parses JSON or text response bodies (`readBody()`), not binary ones, so a PDF response would be corrupted if decoded through it. Call the endpoint directly (or via `fetch`) for the PDF export.

---

## 7. transparency — TransparencyResource

Source: [`sdk/javascript/src/resources/transparency.ts`](../../../sdk/javascript/src/resources/transparency.ts)

Wraps the append-only [transparency log](../../glossary.md) (RFC 6962 Merkle tree).

| Method | HTTP | Auth | Returns |
|---|---|---|---|
| `getEntry(id)` | `GET /v1/transparency/entry/:id` | public | `ApiResponse<TransparencyEntryEnvelope>` |
| `listEntries(params?)` | `GET /v1/transparency/entries` | public | `ApiResponse<PaginatedResponse<TransparencyEntry>>` |
| `getRoot(rootId?)` | `GET /v1/transparency/root` (`?rootId=` when given) | public | `ApiResponse<TransparencyLatestRoot>` |
| `listRoots(params?)` | `GET /v1/transparency/roots` (paginated) | public | `ApiResponse<TransparencyRootList>` (`{ roots, page, pageSize, total, … }`) |
| `verifyEntry(id)` | `GET /v1/transparency/verify/:id` | public | `ApiResponse<TransparencyVerifyResult>` |
| `getProof(id)` | `GET /v1/transparency/proof/:id` | public | `ApiResponse<InclusionProof>` |
| `getReceipt(requestId)` | `GET /v1/transparency/receipt/:requestId` | public (the `requestId` is the capability) | `ApiResponse<{ receipt: Receipt }>` — kept for a bounded window (default 1 h), then `NotFoundError` |
| `register(data)` | `POST /v1/transparency/register` | **ops key** | `ApiResponse<TransparencyRegisterResult>` |
| `generateRoot()` | `POST /v1/transparency/admin/roots/generate` | **ops key** | `ApiResponse<TransparencyRootGenerated>` |
| `stats()` | `GET /v1/transparency/admin/stats` | **ops key** | `ApiResponse<unknown>` |
| `validateChain(params?)` | `GET /v1/transparency/admin/chain/validate` (`?startId=&endId=&limit=`, all optional) | **ops key** (`READ_TRANSPARENCY_LOG`) | `ApiResponse<TransparencyChainValidation>` — `data.chainValidation = { valid, checkedCount, failureId, failureDetail }` |

`validateChain()` checks the **transparency log**'s own hash chain. It does not call the audit chain's `/audit/chain/integrity`.

```typescript
const root = await client.transparency.getRoot();
console.log(root.data.rootId, root.data.entryCount);

const proof = await client.transparency.getProof('entry-001');
console.log(proof.data.proof); // string[] — Merkle inclusion path (RFC 6962)
```

### Signed receipts (`Receipt`, `verifyReceipt`)

An `/ai/chat` response carries `receipt` on an EXECUTE and on a post-authentication BLOCK — only when the audit entry and the transparency leaf are persisted, otherwise the key is **absent** (never `null`). It proves that the gateway *recorded* the decision (`entryHash` of the audit entry, `leafHash` of the transparency leaf); it does not prove the decision was correct. Verify it offline with the transparency keys from `GET /.well-known/qodiqa/transparency-keys`:

```typescript
import { verifyReceipt, receiptBindsTo } from '@qodiqa/sdk';
const keys = await (await fetch(`${baseUrl}/.well-known/qodiqa/transparency-keys`)).json();   // { keys: [{ keyId, publicKey, status, … }] }
const chat = await client.chat.create(artifact, { prompt: 'hi' });
if (chat.receipt) {
  const v = verifyReceipt(chat.receipt, keys);                  // { ok, reason }, never throws, fails closed
  if (!v.ok) throw new Error(`receipt rejected: ${v.reason}`);  // BAD_SIGNATURE, UNKNOWN_KEY, FIELD_SET, REVOKED_KEY, …
}
```

`verifyReceipt(receipt, keys, { trustedAt })` — a receipt signed by a since-revoked key verifies only in the timed mode (`trustedAt` from an independent authority, before the key's `revokedAt`). `receiptBindsTo(receipt, { entryHash, leafHash, requestId, decision })` lists the values that differ from evidence you already hold. The signature is `Ed25519(SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature)))` — see `docs/protocol/PROTOCOL-V2.md` section 6; `scripts/audit-repro/verify/qodiqa-receipt-verify.js` verifies a receipt from the command line.

---

## 8. evidence — EvidenceResource

Source: [`sdk/javascript/src/resources/evidence.ts`](../../../sdk/javascript/src/resources/evidence.ts)

Single-method resource for retrieving [evidence chain](../../glossary.md) packages.

### `getPackage(artifactId)`

- **Signature**: `getPackage(artifactId: string): Promise<ApiResponse<unknown>>`
- **HTTP**: `GET /v1/attestation/:artifactId/evidence`
- **Auth**: **Ops API key required.**
- **Exceptions**: `ValidationError` (empty `artifactId`), `AuthenticationError` (no `apiKey` configured)

```typescript
const pkg = await client.evidence.getPackage('att-001'); // requires apiKey
```

> **Note**: `evidence.getPackage(id)` and `attestation.getEvidence(id)` hit the
> identical HTTP route (`GET /v1/attestation/:id/evidence`). Both exist because
> the underlying server exposes the endpoint under two conceptual resources;
> use whichever reads more naturally at the call site.

---

## 9. certification — CertificationResource

Source: [`sdk/javascript/src/resources/certification.ts`](../../../sdk/javascript/src/resources/certification.ts)

| Method | HTTP | Auth | Returns |
|---|---|---|---|
| `evaluate(request)` | `POST /v1/certification/evaluate` | **ops key** | `ApiResponse<CertificationRecord>` |
| `get(id)` | `GET /v1/certification/:id` | public | `ApiResponse<CertificationRecord>` |
| `getSummary(id)` | `GET /v1/certification/:id/summary` | public | `ApiResponse<unknown>` |
| `submitBatch(request)` | `POST /v1/certifications/batch` | **ops key** | `ApiResponse<BatchRecord>` |
| `getBatch(batchId)` | `GET /v1/certifications/batch/:batchId` | **ops key** | `ApiResponse<BatchRecord>` |
| `getBatchResults(batchId)` | `GET /v1/certifications/batch/:batchId/results` | **ops key** | `ApiResponse<unknown>` |
| `cancelBatch(batchId)` | `POST /v1/certifications/batch/:batchId/cancel` | **ops key** | `ApiResponse<unknown>` |
| `list(params?)` | `GET /v1/certification/admin/history` | **ops key** | `ApiResponse<CertificationListResponse>` (`{ certifications, page, pageSize, total, … }`) |
| `stats()` | `GET /v1/certification/admin/stats` | **ops key** | `ApiResponse<unknown>` |

Note the singular `/v1/certification` mount (evaluate, get, summary, admin history/stats) versus the plural
`/v1/certifications/batch/*` mount.

`request: CertificationEvaluateRequest = { artifacts?: Artifact-like[] /* max 50 */, evidencePackages?, chain?, options? }`.
`BatchSubmitRequest = { frameworkId: string /* required */, items: { subjectId: string /* required */, artifacts?, evidencePackages?, controls? }[] }`.

```typescript
const cert = await client.certification.evaluate({ artifacts: [signed.artifact] }); // requires apiKey
console.log(cert.data.id, cert.data.status, cert.data.score);

const batch = await client.certification.submitBatch({
  frameworkId: 'framework-1',
  items: [{ subjectId: 'svc-a', artifacts: [a1] }, { subjectId: 'svc-b', artifacts: [a2] }],
}); // requires apiKey
```

---

## 10. webhooks — WebhooksResource

Source: [`sdk/javascript/src/resources/webhooks.ts`](../../../sdk/javascript/src/resources/webhooks.ts)

Management API for registered [webhook](../../glossary.md) endpoints. **Every
method requires an ops API key.** This is distinct from *receiving* and
verifying webhook deliveries — see [§15](#15-webhook-signature-verification).

| Method | Signature | HTTP |
|---|---|---|
| `create(request)` | `create(request: WebhookCreateRequest): Promise<ApiResponse<WebhookCreateResult>>` | `POST /v1/webhooks` |
| `list(tenantId, params?)` | `list(tenantId: string, params?: PaginationParams): Promise<ApiResponse<WebhookListResponse>>` | `GET /v1/webhooks?tenantId=` (required server-side; there is no cross-tenant list) |
| `get(id, tenantId)` | `get(id: string, tenantId: string): Promise<ApiResponse<WebhookRecord>>` | `GET /v1/webhooks/:id?tenantId=` |
| `update(id, request, tenantId)` | `update(id: string, request: WebhookUpdateRequest, tenantId: string): Promise<ApiResponse<WebhookRecord>>` | `PATCH /v1/webhooks/:id?tenantId=` |
| `delete(id, tenantId)` | `delete(id: string, tenantId: string): Promise<ApiResponse<void>>` | `DELETE /v1/webhooks/:id?tenantId=` |
| `test(id, tenantId)` | `test(id: string, tenantId: string): Promise<ApiResponse<unknown>>` | `POST /v1/webhooks/:id/test?tenantId=` |
| `getDeliveries(id, tenantId)` | `getDeliveries(id: string, tenantId: string): Promise<ApiResponse<unknown>>` | `GET /v1/webhooks/:id/deliveries?tenantId=` |
| `metrics()` | `metrics(): Promise<ApiResponse<unknown>>` | `GET /v1/webhooks/metrics` |

(API-15): the server answers 400 without `tenantId` on every per-id webhook route; before the argument existed these five methods could never succeed against a real gateway. `list()` likewise takes `tenantId` as its first, required argument. Mutations (`create`, `update`, `delete`, `test`) also require the operator MFA step-up — see `otpProvider` in [configuration.md](configuration.md).

`create()` validates client-side before the network call: `request.tenantId`
and `request.url` must be non-empty (`ValidationError` otherwise), and
`request.eventTypes` must be a non-empty array (`ValidationError`:
`"request.eventTypes" must be a non-empty array of event type strings.`).

```typescript
const webhook = await client.webhooks.create({
  tenantId: 'tenant-1',
  url: 'https://example.com/webhook',
  eventTypes: ['attestation.completed', 'certification.evaluated'],
});
console.log(webhook.data.id, webhook.data.secret); // secret: HMAC signing secret, returned once
```

---

## 11. simulation — SimulationResource (policy dry-run)

Source: [`sdk/javascript/src/resources/simulation.ts`](../../../sdk/javascript/src/resources/simulation.ts)

Read-only [policy simulation](../../glossary.md) (see the **Policy Simulation** entry): evaluates a
context against the live or a supplied draft policy set with **zero side
effects** — no nonce registered, no anomaly counter incremented, no audit
record written, no AI provider contacted. `executionPrevented: true` is always
present in every response.

### `simulate(request)`

- **Signature**: `simulate(request: SimulationRequest): Promise<SimulationResult>`
- **Parameters**: `request: { context?: SimulationContext, policies?: PolicyDefinition[], scenario?: string }`
- **Returns**: `SimulationResult` — includes `decision`, `reason`, `policyId`, `riskLevel`, `matchedRules`, `failedRules`, `evaluationTrace`, `explanation`, `executionPrevented: true`, `durationMs`
- **HTTP**: `POST /v1/policy/simulate`

### `compare(request)`

- **Signature**: `compare(request: PolicyComparisonRequest): Promise<PolicyComparisonResult>`
- **Parameters**: `request: { context?, currentPolicies?, proposedPolicies: PolicyDefinition[], scenario? }` — `proposedPolicies` is required
- **Returns**: `PolicyComparisonResult` — `{ comparison: true, decisionChanged, old, proposed, changedRules, executionPrevented: true }`
- **HTTP**: `POST /v1/policy/compare`

### `batch(request)`

- **Signature**: `batch(request: BatchSimulationRequest): Promise<BatchSimulationResult>`
- **Parameters**: `request: { simulations: BatchSimulationItem[], policies?: PolicyDefinition[] }` — up to 100 items
- **Returns**: `BatchSimulationResult` — `{ batchId, total, allowed, blocked, totalDurationMs, results: SimulationResult[], executionPrevented: true }`
- **HTTP**: `POST /v1/policy/simulate/batch`

```typescript
const result = await client.simulation.simulate({
  context: { userId: 'my-key:key_v1', action: 'openai', ip: '192.168.1.1' },
});
console.log(result.decision, result.executionPrevented); // e.g. 'BLOCK', true
```

---

## 12. Error handling

Source: [`sdk/javascript/src/errors.ts`](../../../sdk/javascript/src/errors.ts)

Every SDK error extends `QodiqaError`, which extends `Error`:

```typescript
class QodiqaError extends Error {
  readonly status: number | undefined;
  readonly requestId: string | undefined;
  readonly details: Record<string, unknown>;
}
```

### HTTP-mapped error classes

| Class | HTTP status | Thrown when |
|---|---|---|
| `AuthenticationError` | 401 | Missing/invalid `apiKey` or `signToken` — either client-side (before any request) or server-side. (A missing/invalid *artifact* is a `VerificationError`; an empty artifact string is a client-side `ValidationError`.) |
| `AuthorizationError` | 403 | Authenticated but not permitted (`reason === 'FORBIDDEN'`) |
| `ValidationError` | 400 (also raised for 422 responses) | Malformed request payload, client-side or server-side |
| `VerificationError` | any (200 in the server's default mode; 400/403/409 in `status` mode) | Server reason is one of the 31 artifact-rejection reasons in `VERIFICATION_REASONS` (the server's `artifact_malformed`, `artifact_invalid`, `request_mismatch` and `replay` classes, src/api/blockHttpStatus.js — e.g. `INVALID_SIGNATURE`, `KEY_REVOKED`, `EXPIRED`, `REQUEST_MISMATCH`, `REPLAY_DETECTED`) — the artifact itself was rejected. Thrown by both `chat.create()` and `chat.stream()` |
| `BlockedError` | 200 | `chat.stream()` only: a non-artifact enforcement `BLOCK` (policy, consent, semantic, …) decided before the stream opened — `create()` returns the same decision instead. Carries `reason` and `decision: 'BLOCK'` |
| `MfaRequiredError` (subclass of `AuthenticationError`) | 401 | Operator MFA step-up: `MFA_REQUIRED` (no `X-QODIQA-OTP`) or `MFA_INVALID` (wrong/reused code). Set `otpProvider` to answer it automatically |
| `MfaEnrollmentRequiredError` (subclass of `AuthorizationError`) | 403 | `MFA_ENROLLMENT_REQUIRED` — enroll first (POST /rbac/me/mfa/enroll + /confirm) |
| `MfaLockedError` | 429 | `MFA_LOCKED` — 5 failed codes in 15 minutes; never retried; carries `retryAfter` |
| `NotFoundError` | 404 | Resource does not exist |
| `RateLimitError` | 429 | Rate limit exceeded; carries `retryAfter: number \| undefined` |
| `ServerError` | 5xx | Unhandled server-side failure |
| `KillSwitchError` (subclass of `ServerError`) | 503 | The gateway's global kill switch is active (`KILL_SWITCH_ACTIVE`) or its state cannot be confirmed (`KILL_SWITCH_STATE_UNAVAILABLE`): /sign and /ai/chat are refused until an operator releases it. Nothing was signed, no nonce consumed, no provider called — retrying later is safe, but the SDK never retries it automatically. Carries `retryAfter` |
| `NetworkError` | n/a | `fetch` rejected for a reason other than the configured timeout (DNS failure, connection refused, aborted by caller) |
| `TimeoutError` | n/a | The request did not complete within `timeout` ms |
| `UnknownError` | any | Status/reason combination not mapped to any class above — today this includes `409` (`IDEMPOTENCY_KEY_CONFLICT`, `IDEMPOTENCY_REQUEST_IN_PROGRESS`), `413` and `415`; read `err.status` / `err.reason` |

### Webhook verification error classes

| Class | HTTP status (as constructed) | Thrown when |
|---|---|---|
| `InvalidSignatureError` | 401 | No configured secret produces a matching HMAC |
| `ExpiredSignatureError` | 401 | Signature timestamp is outside the tolerance window |
| `MalformedSignatureError` | 400 | The `X-QODIQA-Signature` header cannot be parsed, or contains no `sha256=` component |
| `InvalidTimestampError` | 400 | The `X-QODIQA-Timestamp` header is missing or not a valid ISO-8601 UTC timestamp |

### The `createError` factory

`createError(status, reason, message, requestId?, details?): QodiqaError` maps
an HTTP status + server `reason` string to the correct subclass, in this
priority order: `MFA_REQUIRED`/`MFA_INVALID` → `MfaRequiredError`;
`MFA_ENROLLMENT_REQUIRED` → `MfaEnrollmentRequiredError`; `MFA_LOCKED` →
`MfaLockedError`; `401`/`UNAUTHORIZED`/`UNAUTHENTICATED` → `AuthenticationError`;
a `VERIFICATION_REASONS` reason → `VerificationError` (at any status);
`403`/`FORBIDDEN` → `AuthorizationError`; `404`/`NOT_FOUND` → `NotFoundError`;
`429`/`RATE_LIMITED`/`RATE_LIMIT_EXCEEDED` → `RateLimitError` (with
`retryAfter` from `details.retryAfter` when present); `400`/`422`/`VALIDATION_ERROR`/`INVALID_REQUEST`
→ `ValidationError`; any `5xx` → `ServerError`; a `2xx` (a pre-stream BLOCK) → `BlockedError`;
otherwise → `UnknownError`. Every error carries the server `reason` as `err.reason`.

How `reason`, `requestId` and `details` are read from a response: the decision envelope's `reason`; a management envelope's `error.code`; the flat protocol-limiter 429 body (`{ error, surface, dimension, reason, retryAfterSeconds }`, `/sign`) maps its `error` code (e.g. `RATE_LIMIT_EXCEEDED`) to `err.reason` and keeps the limiter window name (`BURST`, `SUSTAINED`, …) in `details.blockedBy`, with `surface`, `dimension` and `retryAfterSeconds` (change — previously that window name surfaced as `err.reason`; code that matched on it should read `details.blockedBy`). `requestId` comes from the body, else from the `X-Request-ID` response header (the per-HTTP trace id). A `Retry-After` header — delta-seconds or an HTTP-date, on any status and any body shape, a proxy's HTML 503 included — is parsed into `details.retryAfter` (seconds); an unparseable value is ignored.
This is internal — you never call it directly, but its priority order explains
which class you'll observe for a given server response.

### Handling errors

```typescript
import {
  QodiqaError, AuthenticationError, RateLimitError,
  VerificationError, ValidationError, NetworkError, TimeoutError,
} from '@qodiqa/sdk';

try {
  const chat = await client.chat.create(artifactB64, { prompt: 'hello' });
} catch (err) {
  if (err instanceof AuthenticationError) {
    console.error('Auth failed:', err.message);
  } else if (err instanceof RateLimitError) {
    console.error('Rate limited. Retry after:', err.retryAfter, 'seconds');
  } else if (err instanceof VerificationError) {
    console.error('Verification failed:', err.message, err.details);
  } else if (err instanceof ValidationError) {
    console.error('Bad request:', err.message, err.details);
  } else if (err instanceof NetworkError) {
    console.error('Network problem:', err.message);
  } else if (err instanceof TimeoutError) {
    console.error('Request timed out');
  } else if (err instanceof QodiqaError) {
    console.error('HTTP status:', err.status, 'Request ID:', err.requestId, 'Details:', err.details);
  } else {
    throw err;
  }
}
```

---

## 13. Retry policy

Source: [`sdk/javascript/src/utils/retry.ts`](../../../sdk/javascript/src/utils/retry.ts)

`HttpClient.request()` wraps every call in `withRetry` with `{ maxRetries: config.maxRetries, baseDelay: 500, maxDelay: 30_000, jitter: true, shouldRetry }`, where `shouldRetry` is `shouldRetryRequest(err, method, path)`:

- **`503 SERVER_OVERLOADED`** (admission control — refused before the request is decoded, verified or its nonce registered): always retried, on every method, `/ai/chat` included.
- **Idempotent methods (`GET`, `PUT`, `DELETE`)**: `429`, `500`, `502`, `503`, `504` (`isRetryable(status)`).
- **`POST`/`PATCH`**: only a `429` (the request limiters answer before the handler runs) — and **never on `/ai/chat`**, where a 429 can come from the per-identity limiter *after* the artifact nonce was consumed. A `5xx` on a `POST` may already have been processed (a provider error after the nonce was consumed, a created webhook), so it is surfaced to the caller, not resent: resending would hide the original error behind a `REPLAY_DETECTED` or create a duplicate.
- **Never retried**: `TimeoutError` (thrown immediately — it already exhausted the caller's time budget), `MfaLockedError`, any request carrying an MFA code (`X-QODIQA-OTP`, whether sent by the `otpProvider` resend or by the caller — the server accepts a TOTP code at most once per step, so a resend would be refused as `MFA_INVALID`, hiding the original error, and count toward the MFA lockout), and any error not listed above (`400`, `401`, `403`, `404`, `409`, `422`, etc.)
- **MFA step-up** (not a retry): with `otpProvider` configured, a `401 MFA_REQUIRED` is answered by resending that one request once with `X-QODIQA-OTP: await otpProvider()` — the step-up refuses before the handler runs, so nothing was changed. The resend is a fresh request with its own `timeout`, so the time spent in `otpProvider()` is not charged against the first request's budget. `MFA_INVALID` is never resent.
- **Backoff**: exponential with full jitter — `delay = random(0, min(baseDelay * 2^attempt, maxDelay))`
- **`Retry-After` precedence**: when the error carries a server-stated wait — `RateLimitError.retryAfter`, or the parsed `Retry-After` header in `details.retryAfter` on **any** status (e.g. 503 `SERVER_OVERLOADED`, which the admission controller always sends with `Retry-After`) — that value (seconds → ms) is the wait, instead of the computed back-off. A retry sooner than that would be refused by construction, so a `Retry-After` longer than `maxDelay` (30 s) is **not** shortened: the error is thrown instead.
- **Time budget**: the request's single `timeout` timer covers every attempt and every wait. A retry whose wait would end at or after the deadline is not attempted — the real error (e.g. the 503) is thrown rather than a client-side `TimeoutError`.

Approximate delays with the defaults (`baseDelay = 500ms`, `maxRetries = 2`), when the server sends no `Retry-After`:

| Attempt | Delay (uniformly random, upper bound) |
|---|---|
| 1st retry | 0–500ms |
| 2nd retry | 0–1000ms |

### `withRetry` (exported helper)

```typescript
export function withRetry<T>(
  fn: () => Promise<T>,
  config: RetryConfig,
  onRetry?: (attempt: number, delay: number, error: unknown) => void,
): Promise<T>
```

`RetryConfig = { maxRetries: number; baseDelay?: number /* default 500 */; maxDelay?: number /* default 30_000 */; jitter?: boolean /* default true */; shouldRetry?: (err: unknown) => boolean; deadline?: number /* epoch ms */ }`

```typescript
import { withRetry } from '@qodiqa/sdk';

const result = await withRetry(
  () => myAsyncOperation(),
  { maxRetries: 3, baseDelay: 200, jitter: true },
  (attempt, delay, err) => console.log(`Retry ${attempt} in ${delay}ms:`, err),
);
```

---

## 14. Pagination

Source: [`sdk/javascript/src/utils/pagination.ts`](../../../sdk/javascript/src/utils/pagination.ts)

Every list method (`attestation.list`, `transparency.listEntries`,
`certification.list`, `webhooks.list(tenantId, params?)`, `transparency.listRoots`) accepts
`PaginationParams = { page?, pageSize?, sortOrder?: 'asc' | 'desc' }`. Most return
`ApiResponse<PaginatedResponse<T>>` where
`PaginatedResponse<T> = { records: T[], page, pageSize, total, hasMore }`; `webhooks.list`
returns `ApiResponse<WebhookListResponse>` and `transparency.listRoots` returns
`ApiResponse<TransparencyRootList>` (`{ roots, page, pageSize, total, … }`).

### `PageFetcher<T>`

`type PageFetcher<T> = (page: number, pageSize: number) => Promise<PaginatedResponse<T>>`

### `PagePage<T>` — iterate whole pages

```typescript
class PagePage<T> implements AsyncIterableIterator<PaginatedResponse<T>> {
  constructor(fetcher: PageFetcher<T>, options?: { startPage?: number; pageSize?: number });
}
```
Defaults: `startPage: 1`, `pageSize: 50`. Stops iterating once a fetched page's
`hasMore` is `false`.

### `PageIterator<T>` — iterate individual items

```typescript
class PageIterator<T> implements AsyncIterableIterator<T> {
  constructor(fetcher: PageFetcher<T>, options?: { startPage?: number; pageSize?: number });
}
```
Internally wraps a `PagePage<T>` and flattens `records` across pages.

```typescript
import { PageIterator, PagePage } from '@qodiqa/sdk';

const items = new PageIterator(
  (page, pageSize) => client.transparency.listEntries({ page, pageSize }).then((r) => r.data),
  { pageSize: 50 },
);
for await (const entry of items) {
  console.log(entry.id);
}

const pages = new PagePage(
  (page, pageSize) => client.transparency.listEntries({ page, pageSize }).then((r) => r.data),
  { pageSize: 50 },
);
for await (const page of pages) {
  console.log(`Page has ${page.records.length} entries`);
}
```

Note that the fetcher must unwrap `.data` from the `ApiResponse` envelope
before returning it, since `PageFetcher<T>` expects a raw `PaginatedResponse<T>`.

---

## 15. Webhook signature verification

Source: [`sdk/javascript/src/webhooks/verifier.ts`](../../../sdk/javascript/src/webhooks/verifier.ts)

Matches the server's actual wire format
(`src/core/webhooks/webhookDelivery.js`): QODIQA signs every webhook
delivery with HMAC-SHA256, sent in the `X-QODIQA-Signature` request header,
with the delivery timestamp sent *separately* in its own
`X-QODIQA-Timestamp` header:

```
X-QODIQA-Timestamp: 2026-01-01T00:00:00.000Z
X-QODIQA-Signature: sha256=<hex_hmac>
```

If an intermediary proxy folds duplicate `X-QODIQA-Signature` headers into
one comma-separated value, each `sha256=` component is checked in turn. The
HMAC is computed over `<raw_X-QODIQA-Timestamp_header_value> + "." +
<raw_request_body>` — **always use the raw bytes as received**, never a
re-serialized JSON string, and pass the timestamp through exactly as
received (never reformatted), or verification will fail.

### `verifyWebhookSignature(options)`

- **Signature**: `verifyWebhookSignature(options: WebhookVerifyOptions): void`
- **Parameters** (`WebhookVerifyOptions`):
  | Name | Type | Default | Notes |
  |---|---|---|---|
  | `body` | `string \| Buffer` | required | Raw request body |
  | `signature` | `string` | required | Value of `X-QODIQA-Signature` |
  | `timestamp` | `string` | required | Value of `X-QODIQA-Timestamp`, passed through unmodified |
  | `secret` | `string \| string[]` | required | One or more secrets; verification succeeds if any matches (supports rotation) |
  | `tolerance` | `number` (seconds) | `DEFAULT_TOLERANCE_SECONDS` (`300`) | Maximum accepted timestamp age |
- **Returns**: `void` — returns normally on success, throws on any failure.
- **Exceptions**: `MalformedSignatureError` (unparseable signature header, or no `sha256=` component present), `InvalidTimestampError` (`X-QODIQA-Timestamp` missing or not a valid ISO-8601 UTC value), `ExpiredSignatureError` (age > tolerance), `InvalidSignatureError` (no secret produces a matching HMAC, verified with `crypto.timingSafeEqual`)
- **Example**:
  ```typescript
  import { verifyWebhookSignature } from '@qodiqa/sdk';

  verifyWebhookSignature({
    body: rawBody,
    signature: req.headers['x-qodiqa-signature'] as string,
    timestamp: req.headers['x-qodiqa-timestamp'] as string,
    secret: process.env.QODIQA_WEBHOOK_SECRET!,
  });
  ```

### `WebhookVerifier` (reusable class)

```typescript
class WebhookVerifier {
  constructor(secret: string | string[], options?: { tolerance?: number });
  verify(body: string | Buffer, signature: string, timestamp: string, options?: { _now?: number }): void;
}
```

Prefer this over the free function when handling multiple endpoints or
building middleware, since the secret(s) and tolerance are configured once.

```typescript
const verifier = new WebhookVerifier(process.env.QODIQA_WEBHOOK_SECRET!);
app.post('/webhooks/qodiqa', (req, res) => {
  verifier.verify(
    req.rawBody,
    req.headers['x-qodiqa-signature'] as string,
    req.headers['x-qodiqa-timestamp'] as string,
  );
  // signature valid — process the event
});

// Secret rotation: verification succeeds if ANY secret matches.
const rotating = new WebhookVerifier([
  process.env.QODIQA_WEBHOOK_SECRET_NEW!,
  process.env.QODIQA_WEBHOOK_SECRET_OLD!,
]);
```

### `DEFAULT_TOLERANCE_SECONDS`

`export const DEFAULT_TOLERANCE_SECONDS = 300;` — 5 minutes.

> **Capturing the raw body**: Express's `express.json()` and Fastify's default
> JSON parser both discard the raw bytes. Use `express.raw({ type: 'application/json' })`
> on the webhook route specifically, or Fastify's `addContentTypeParser` to
> stash the buffer before parsing. See [examples.md](examples.md) (the
> `sdk/javascript/examples/express/webhook.js`, `sdk/javascript/examples/fastify/webhook.js`, and
> `examples/nextjs/webhook.ts` walkthroughs) for full route-level examples.

---

## 16. Local Artifact & Transparency-Proof Verification (offline)

Source: [`sdk/javascript/src/verification/`](../../../sdk/javascript/src/verification/)

**remediation.** `ArtifactVerifier` performs the complete
verification pipeline entirely offline: schema validation, canonical JSON
reconstruction (byte-identical to the server's own `stableStringify`, via
the same `fast-json-stable-stringify` package), payload-hash computation,
public-key resolution, Ed25519 signature verification, timestamp/expiry
checks, and optional transparency-proof verification. **None of this depends
on calling the server's `/verify` endpoint or trusting its response.**
`verify.ts`'s `POST /verify` (§4 above) remains available as an optional
remote convenience and is never used internally by `ArtifactVerifier`.

### `ArtifactVerifier`

```typescript
class ArtifactVerifier {
  constructor(options: {
    keys: KeyProvider;                              // required — artifact-signing trust source
    transparencyKeys?: KeyProvider;                 // separate trust source for transparency proofs
    clockToleranceMs?: number;                      // default 0, matches the server's zero-tolerance stance
    requireTransparency?: boolean;                  // default false
  });
  verify(
    artifact: Artifact,
    options?: { transparencyProof?: TransparencyInclusionProof },
  ): Promise<ArtifactVerificationResult>;
}
```

- **Never throws for content problems.** A malformed artifact, bad
  signature, unknown/revoked key, expired artifact, or unverifiable
  transparency proof — every one of these resolves to a structured
  `ArtifactVerificationResult`, never a rejected promise. Only constructor
  misconfiguration (`keys` missing; `requireTransparency: true` with no
  `transparencyKeys`) throws `ValidationError` synchronously.
- See [configuration.md § Key provider configuration](configuration.md#key-provider-configuration)
  for `StaticKeyProvider`, `RemoteKeyProvider`, and `createKeyProvider`, and
  why the artifact and transparency key sources must always be two separate
  instances.

### `verifyArtifact(artifact, options)` — one-shot convenience function

```typescript
function verifyArtifact(
  artifact: Artifact,
  options: ArtifactVerifierOptions & { transparencyProof?: TransparencyInclusionProof },
): Promise<ArtifactVerificationResult>;
```

Equivalent to constructing an `ArtifactVerifier` and calling `.verify()`
once; use the class directly when verifying many artifacts against the same
trust bundle, so the `RemoteKeyProvider`'s cache is reused.

### `ArtifactVerificationResult`

| Field | Type | Meaning |
|---|---|---|
| `verificationStatus` | `'valid' \| 'invalid' \| 'error'` | Overall outcome. `'error'` is distinct from `'invalid'` — it means a `KeyProvider` itself failed (e.g. a network error resolving a remote key), not that the artifact was proven bad. |
| `signatureValid` | `boolean` | The actual cryptographic check — Ed25519 signature over the envelope hash. This is what catches tampering. |
| `payloadHashValid` | `boolean` | **Not** an independent stored-hash comparison — the real artifact envelope has no separately-stored payload hash field; this means "the envelope hash was computed without a structural error." |
| `canonicalizationValid` | `boolean` | The payload could be canonicalized without violating the protocol (no forbidden keys, no non-finite numbers, no exotic types). |
| `keyValid` | `boolean` | The resolved key's status is `active` or `deprecated` (not unknown, not `revoked`). |
| `keyId` / `keyStatus` | `string \| null` | The artifact's `publicKeyId` and its resolved status, once key resolution is reached. |
| `keySource` | `'live' \| 'archived' \| null` | Which discovery tier resolved the key — `'archived'` means it was only resolvable via `RemoteKeyProvider`'s archived-key fallback, i.e. it had already been purged from the live keystore. `null` when no key was resolved. Purely diagnostic — never affects `keyValid`. |
| `expiryValid` / `timestampValid` | `boolean` | Expiry and future-timestamp checks, ± `clockToleranceMs`. |
| `transparencyVerified` | `'verified' \| 'failed' \| 'unavailable'` | Distinguishes "no proof was supplied" (`'unavailable'`) from "a proof was supplied and failed" (`'failed'`) — these are never conflated. |
| `transparencyDetail` | `TransparencyVerificationDetail \| null` | Per-check breakdown when a proof was supplied (see below). |
| `verificationErrors` / `verificationWarnings` | `string[]` | Human-readable detail; always empty on a fully valid result. |
| `failedStage` | `'STRUCTURE' \| 'CANONICALIZATION' \| 'KEY_RESOLUTION' \| 'FUTURE_TIMESTAMP' \| 'EXPIRED' \| 'INVALID_SIGNATURE' \| 'TRANSPARENCY' \| null` | Which pipeline stage stopped verification — reuses the server's own `reason` vocabulary from `validateArtifact.js` where they map 1:1, plus `'TRANSPARENCY'` for the SDK-only local proof stage. |
| `verifiedAt` | `number` | Unix ms epoch the verification ran at. |

The pipeline is fail-closed and stops at the first failing stage — fields for
stages never reached keep their default (`false`/`null`). For example, an
artifact with an unresolvable key never reaches the future-timestamp check,
so `timestampValid`/`expiryValid` stay `false` even though nothing about the
timestamp itself was actually wrong; consult `failedStage` to know which
check actually failed.

### Transparency-proof verification

Pass a `transparencyProof` (the object returned by
`client.transparency.getProof(id).data.proof`) to `verify()` to additionally,
fully locally:

1. Recompute the entry's `entryHash` from its own canonical fields (a
   strictly stronger check than the server's own `verifyInclusionProof`,
   which trusts `entryHash` as given).
2. Reconstruct the Merkle root from the leaf hash and the audit path (RFC
   6962), and confirm it matches `proof.root.rootHash`.
3. Verify the entry and root Ed25519 signatures against the configured
   `transparencyKeys` provider — the separate trust domain from artifact
   keys.
4. Confirm `leafIndex` is within `[0, treeSize)`.

```typescript
const result = await verifier.verify(artifact, {
  transparencyProof: (await client.transparency.getProof(transparencyId)).data.proof,
});
console.log(result.transparencyVerified); // 'verified' | 'failed' | 'unavailable'
```

If no `transparencyProof` is supplied, `transparencyVerified` is
`'unavailable'` and this **never** affects `verificationStatus` unless the
verifier was constructed with `requireTransparency: true`.

### `TransparencyVerificationDetail`

| Field | Meaning |
|---|---|
| `entryHashValid` | Recomputed `entryHash` matches the one on the entry. |
| `merklePathValid` | The audit path reconstructs `root.rootHash`, `proof.merkleRoot` (if present) agrees with it, and the path is exactly the RFC 6962 path of `proof.leafIndex` in a tree of `proof.treeSize` leaves, with `proof.treeSize` equal to the signed root's `entryCount` — a proof for one leaf position does not verify as another. |
| `leafIndexValid` | `0 <= leafIndex < treeSize`. |
| `keyValid` / `keyStatus` | The transparency signing key resolved and is `active`/`deprecated`. |
| `entrySignatureValid` / `rootSignatureValid` | Ed25519 signature checks on the entry and root respectively. |

### Lower-level building blocks (also exported)

`stableStringify`, `CanonicalizationError` (canonical JSON — matches the
server's `src/utils/stableStringify.js` byte-for-byte), `verifyInclusionPath`
(RFC 6962 Merkle audit-path verification only), `verifyTransparencyProof` /
`transparencyDetailAllPassed` (the transparency-proof check used internally
by `ArtifactVerifier`, usable standalone). These are the same primitives
`ArtifactVerifier` is built from — most integrations only need
`ArtifactVerifier`/`verifyArtifact` directly.

---

## 17. TypeScript types

All types are exported from `@qodiqa/sdk` and defined in
[`sdk/javascript/src/types.ts`](../../../sdk/javascript/src/types.ts):

**Core**: `HttpMethod`, `Decision` (`'EXECUTE' | 'BLOCK'`), `KeyStatus`, `ConsentState`

**Artifact**: `Artifact`, `ArtifactPayload`

**Sign / Verify / Chat**: `SignRequest`, `SignResponse`, `SignMeta`, `VerifyRequest`, `VerifyResponse`, `ChatRequest`, `ChatResponse`, `TokenUsage`

**Chat streaming**: `ChatStreamOptions`, `ChatStreamEvent` (discriminated union of `ChatStreamStartedEvent`, `ChatStreamChunkEvent`, `ChatStreamCompletedEvent`, `ChatStreamCancelledEvent`) — see [`stream(artifact, request, options?)`](#streamartifact-request-options)

**Keys / Audit / Health**: `PublicKey`, `KeysResponse`, `AuditChainEntry`, `AuditResponse`, `HealthResponse`, `ReadyResponse`

**Attestation / Certification**: `AttestationVerifyRequest`, `AttestationRecord`, `CertificationEvaluateRequest`, `CertificationRecord`, `BatchSubmitRequest`, `BatchRecord`

**Transparency**: `TransparencyEntry`, `TransparencyRoot`, `InclusionProof`, `TransparencyVerifyResult`

**Portal**: `PortalSubmitRequest`, `PortalResult`

**Webhooks**: `WebhookCreateRequest`, `WebhookRecord`, `WebhookUpdateRequest`

**Pagination / envelope**: `PaginationParams`, `PaginatedResponse<T>`, `ApiResponse<T>`

**Policy simulation**: `RiskLevel`, `TraceOutcome`, `PolicyVersion`, `SimulationContext`, `PolicyDefinition`, `TraceEntry`, `MatchedRule`, `FailedRule`, `SimulationRequest`, `SimulationResult`, `PolicyComparisonRequest`, `PolicyComparisonSide`, `ChangedRule`, `PolicyComparisonResult`, `BatchSimulationItem`, `BatchSimulationRequest`, `BatchSimulationResult`

## Scope note: Consent and RBAC endpoints

The QODIQA server exposes Consent-management endpoints (`POST /consent`,
`POST /consent/:consentId/revoke`, `POST /consent/actor/:actorId/revoke`,
`POST /consent/:consentId/suspend`, `POST /consent/:consentId/resume`, `GET
/consent` — see
[`docs/api/overview.md`](../../api/overview.md#consent-endpoints)) and RBAC
endpoints (`/rbac/*`). **Neither has a dedicated resource class in this SDK
version** (there is no `client.consent` or `client.rbac`). Consent state is
still relevant to SDK users indirectly — it is enforced server-side on every
`/ai/chat` call via the `REQUIRE_CONSENT` policy rule, it can be exercised
through the [`simulation`](#11-simulation--simulationresource-policy-dry-run)
resource by inspecting `matchedRules`/`failedRules`, and consent lifecycle
changes are reported via the `consent.granted` / `consent.revoked` webhook
event types (see `sdk/javascript/examples/express/webhook.js`). Calling these endpoints from
JavaScript today requires a raw `fetch`/`HttpClient`-style call against the
documented routes rather than a typed resource method. If this SDK ever grows
a typed `client.consent` resource, its revocation methods must be named
`revoke*` (e.g. `revokeConsent`, `revokeActorConsent`), never `delete*` —
revocation is a state transition, not a deletion, and GDPR Article 17 erasure
is a separate operation entirely (`POST /v1/admin/dsr/:id/erase`; see
[`docs/guides/dsr.md`](../../guides/dsr.md)). This mirrors the
remediation applied to the HTTP API itself —

## 12. Operations: every documented operation (`client.operations`)

`client.operations` is generated from `docs/api/openapi.json` and covers **all** documented operations (364 in this version), not only the typed resources above. One method per
`operationId`, plus `call(id, args)`, `list()` and `describe(id)`:

```ts
await client.operations.getPolicyVersion({ path: { policyId: 'p1', v: 3 } });
await client.operations.listAlerts();
for await (const ev of client.operations.streamAlerts()) { /* SSE */ }
const pdf = await client.operations.getEvidencePackagePdf({ path: { artifactId } });   // Uint8Array
```

`path` is required exactly when the template has parameters; unknown or missing path/query parameters, a body on an operation without one, and unknown headers are rejected before any
request. Credentials follow the contract: operator operations use `apiKey`, signing operations `signToken`, public operations send none. Request and response bodies of this layer are
`unknown`: use the typed resources for the main flows. A drift between this table and the contract fails `npm run sdk:check` (part of `npm run contract:check`).
