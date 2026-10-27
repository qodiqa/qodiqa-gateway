# Python SDK — API Reference

Every symbol on this page is exported from the package `__init__`
([`sdk/python/qodiqa/__init__.py`](../../../sdk/python/qodiqa/__init__.py)) and
importable as `from qodiqa import X` (or `from qodiqa.exceptions import X` for
exception classes, which are also re-exported from the top-level package).
Each signature, default, and thrown error was read directly from the cited
source file.

Every resource is available in two forms with an identical method surface:
the synchronous class on `QodiqaClient` (e.g. `SignResource` on
`client.sign`) and the `async`-prefixed class on `AsyncQodiqaClient` (e.g.
`AsyncSignResource` on `client.sign`, where every method is `async def` and
must be awaited). This reference documents the synchronous signature for each
method; the async version is identical except for `async`/`await` — **with
one exception**: `AsyncChatResource.stream()` is deliberately not an
`async def`; see §3.

## Contents

1. [QodiqaClient / AsyncQodiqaClient](#1-qodiqaclient--asyncqodiqaclient)
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
16. [Local Artifact & Transparency-Proof Verification](#16-local-artifact--transparency-proof-verification)
17. [Typed models](#17-typed-models)

---

## 1. QodiqaClient / AsyncQodiqaClient

Source: [`sdk/python/qodiqa/client.py`](../../../sdk/python/qodiqa/client.py)

### Constructor

```python
QodiqaClient(
    *,
    api_key: Optional[str] = None,
    sign_token: Optional[str] = None,
    base_url: str = "http://localhost:3000",
    timeout: float = 30.0,
    max_retries: int = 2,
    default_headers: Optional[dict] = None,
    user_agent: Optional[str] = None,
    verify_ssl: bool = True,
    proxy: Optional[str] = None,
) -> QodiqaClient
```

Builds an immutable `ClientConfig` (raises `ValidationError` on invalid input —
see [configuration.md](configuration.md)), then one `HttpClient`
(`httpx.Client`-backed), one `AuthProvider`, and one instance of every resource
class below. `AsyncQodiqaClient` has the identical constructor signature and
builds an `AsyncHttpClient` (`httpx.AsyncClient`-backed) instead.

### Resource accessors (instance attributes)

| Attribute | Sync class | Async class | Wraps |
|---|---|---|---|
| `.sign` | `SignResource` | `AsyncSignResource` | `POST /sign` |
| `.chat` | `ChatResource` | `AsyncChatResource` | `POST /ai/chat` |
| `.verify` | `VerifyResource` | `AsyncVerifyResource` | `POST /verify` |
| `.portal` | `PortalResource` | `AsyncPortalResource` | `/v1/portal/*` |
| `.attestation` | `AttestationResource` | `AsyncAttestationResource` | `/v1/attestation/*` |
| `.transparency` | `TransparencyResource` | `AsyncTransparencyResource` | `/v1/transparency/*`, `/audit/chain/integrity` |
| `.evidence` | `EvidenceResource` | `AsyncEvidenceResource` | `/v1/attestation/:id/evidence` |
| `.certification` | `CertificationResource` | `AsyncCertificationResource` | `/v1/certification/*`, `/v1/certifications/*` |
| `.webhooks` | `WebhooksResource` | `AsyncWebhooksResource` | `/v1/webhooks/*` |
| `.simulation` | `SimulationResource` | `AsyncSimulationResource` | `/v1/policy/simulate`, `/v1/policy/compare`, `/v1/policy/simulate/batch` |

### Lifecycle

| Method | Sync | Async |
|---|---|---|
| Close connection pool | `client.close()` | `await client.aclose()` |
| Context manager | `with QodiqaClient(...) as client:` | `async with AsyncQodiqaClient(...) as client:` |

### Convenience methods

#### `health_check()`

- **Purpose**: Liveness probe.
- **Signature**: `health_check() -> HealthResponse`
- **Returns**: `{"status": "ok", "uptime": float}`
- **HTTP**: `GET /health`

#### `readiness_check()`

- **Purpose**: Readiness probe — dependency health.
- **Signature**: `readiness_check() -> ReadyResponse`
- **Returns**: `{"ready": bool, "components": {...}}` with eight booleans — `nonceStore`, `anomalyStore`, `rateLimitStore`, `persistenceStore`, `consentSubscriber`, `consentCache`, `admission`, `auditBacklog` (`src/api/routes/ready.js`). `consentCache` is informational and never by itself makes `ready` false; `admission` is false while admission control's queue is full and `auditBacklog` while the audit mirror backlog is above its bound (both declared `total=False` in `HealthComponents`, since older servers omit them). A not-ready server answers 503, raised as `ServerError`.
- **HTTP**: `GET /ready`

#### `get_public_keys()`

- **Signature**: `get_public_keys() -> KeysResponse`
- **Returns**: `{"keys": List[PublicKey]}`
- **HTTP**: `GET /public-keys`

#### `get_public_key(key_id)`

- **Signature**: `get_public_key(key_id: str) -> PublicKey`
- **Parameters**: `key_id: str` — must be non-empty
- **Returns**: `PublicKey`
- **HTTP**: `GET /.well-known/qodiqa/keys/:key_id`
- **Exceptions**: `ValidationError` if `key_id` is empty/whitespace

#### `get_audit_chain(artifact_id)`

- **Purpose**: `/audit/:artifactId` is an operator endpoint — it requires `api_key` (not `sign_token`) and returns `401 UNAUTHORIZED` without it.
- **Signature**: `get_audit_chain(artifact_id: str) -> ApiResponse[AuditResponse]`
- **Parameters**: `artifact_id: str` — must be non-empty. Use the `artifactId` returned by `sign.sign()`; the `requestId` in a chat/verify response is the per-HTTP trace id (`X-Request-ID`), not the artifact id.
- **Returns**: the standard success envelope `{"status", "timestamp", "requestId", "data"}` whose `data` is `AuditResponse = {"artifactId", "decision", "reason", "timestamp", "chain": List[AuditChainEntry], "requestId"}` — read `audit["data"]["decision"]`.
- **HTTP**: `GET /audit/:artifactId` (server: `adminStack('READ_AUDIT')`)
- **Exceptions**: `ValidationError` if `artifact_id` is empty; `AuthenticationError` without `api_key` (client-side) or with an invalid one; `AuthorizationError` without `READ_AUDIT`; `NotFoundError` if no audit record exists

```python
with QodiqaClient(sign_token="...", api_key="ok_" + "a" * 64) as client:
    health = client.health_check()
    ready = client.readiness_check()
    keys = client.get_public_keys()
    audit = client.get_audit_chain("art_abc123")  # requires api_key; use signed["artifactId"]
    print(audit["data"]["decision"], len(audit["data"]["chain"]))
```

---

## 2. sign — SignResource

Source: [`sdk/python/qodiqa/resources/sign.py`](../../../sdk/python/qodiqa/resources/sign.py)

### `sign(request, artifact_header=None)`

- **Purpose**: Issue a signed artifact via `POST /sign`.
- **Signature**: `sign(request: SignRequest, artifact_header: Optional[str] = None) -> SignResponse`
- **Parameters**:
  | Name | Type | Required | Notes |
  |---|---|---|---|
  | `request["request"]["method"]` | `str` | yes | Must be non-empty |
  | `request["request"]["path"]` | `str` | yes | Must be non-empty |
  | `request["request"]["body"]` | `dict` | yes | Body the resulting artifact binds to |
  | `request["payload"]` | `dict` | no | Arbitrary metadata embedded in the artifact |
  | `request["payload"]["provider"]` | `str` | conditional | Required only when `request["request"]["path"]` is `/ai/chat` and the server has more than one AI provider enabled (`400 PROVIDER_REQUIRED` otherwise). Auto-resolved when omitted and exactly one provider is enabled. Ignored for any non-`/ai/chat` path. See `docs/api/overview.md#post-sign`. |
  | `request["ttl"]` | `int` (ms) | no | Requested lifetime; server clamps to its configured min/max |
  | `request["request"]["query"]` | `str` | no, with `v2` | Protocol V2: the raw query string WITHOUT `?`, bound into the artifact. A raw `+` or `;` is refused (`400 QUERY_NOT_BINDABLE`) — write `%20`, `%2B`, `%3B` |
  | `request["request"]["headers"]` | `Dict[str, str]` | no, with `v2` | Protocol V2: the values of the headers named in `v2["bind"]["headers"]` (lower-case names) |
  | `request["v2"]` | `SignV2Options` | no | Issue a protocol-V2 artifact (needs `QODIQA_PROTOCOL_V2_ISSUE=true` on the gateway): `{"bind": {"headers": [...]}, "model"?: str \| None, "limits"?: {"maxTokens": int}, "crit"?: [...]}`. The artifact then binds method, path, query, the listed headers and the body (JCS-P1), authorizes one model and caps the provider output (`maxTokens`) |
  | `artifact_header` | `Optional[str]` (base64) | no | Existing artifact to attach as `x-qodiqa-artifact`, to chain authorization |
- **Returns**: `SignResponse = {"artifactId", "artifact": Artifact, "meta": {"keyId", "expiresAt", "tenantId"}, "requestId"}`
- **Auth**: Requires `sign_token`.
- **Exceptions**: `ValidationError` (empty `method`/`path`), `AuthenticationError` (no `sign_token` configured, client-side; or rejected server-side); server responds `400 PROVIDER_REQUIRED` / `PROVIDER_NOT_SUPPORTED` / `PROVIDER_NOT_CONFIGURED` for `/ai/chat`-bound requests with an unresolvable or invalid provider
- **Example** (single-provider deployment — `provider` auto-resolves):
  ```python
  signed = client.sign.sign({
      "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hello"}},
      "payload": {"userId": "u_123"},
      "ttl": 60_000,  # the server clamps any larger ttl to 60 s
  })
  print(signed["artifactId"], signed["meta"]["keyId"], signed["meta"]["expiresAt"])
  ```
  **Example** (multiple providers enabled — `provider` must be explicit):
  ```python
  signed = client.sign.sign({
      "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hello"}},
      "payload": {"userId": "u_123", "provider": "openai"},
      "ttl": 60_000,  # the server clamps any larger ttl to 60 s
  })
  ```
- **Notes**: Encode the artifact yourself before use as a header:
  `base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()`.
  **Example** (protocol V2 — a bound query, a bound header, one authorized model, an output cap):
  ```python
  signed = client.sign.sign({
      "request": {"method": "POST", "path": "/v1/ai/chat", "query": "stream=true", "headers": {"x-tenant": "acme"}, "body": {"prompt": "hello", "model": "gpt-4"}},
      "v2": {"bind": {"headers": ["x-tenant"]}, "model": "gpt-4", "limits": {"maxTokens": 256}},
  })
  # the call to /v1/ai/chat must then carry the same query and the same x-tenant header, or it fails with REQUEST_MISMATCH
  ```

---

## 3. chat — ChatResource

Source: [`sdk/python/qodiqa/resources/chat.py`](../../../sdk/python/qodiqa/resources/chat.py)

### `create(artifact, request, *, idempotency_key=None)`

- **Signature**: `create(artifact: str, request: ChatRequest, *, idempotency_key: Optional[str] = None) -> ChatResponse`
- **Parameters**: `artifact: str` (base64, non-empty); `request["prompt"]: str` (non-empty), `request["model"]: Optional[str]`; `idempotency_key` — sent as `Idempotency-Key` ([docs/architecture/IDEMPOTENCY_KEY.md](../../architecture/IDEMPOTENCY_KEY.md)), must be non-blank when given. After an outcome-unknown failure (e.g. a 504), retry with a freshly signed artifact and the same key; the server replays the original result. `stream()` does not accept a key (`IDEMPOTENCY_STREAMING_UNSUPPORTED`).
- **Returns**: `ChatResponse = {"decision": "EXECUTE" | "BLOCK", "reason", "aiText"?, "responseId"?, "model"?, "tokenUsage"?: {"prompt_tokens", "completion_tokens", "total_tokens"}, "requestId"}`
- **Auth**: Requires the artifact — sent as `x-qodiqa-artifact`.
- **Exceptions**: `ValidationError` (client-side: empty `artifact`, `prompt` or a blank `idempotency_key`); `VerificationError` (the artifact was rejected — any `VERIFICATION_REASONS` code, e.g. missing, invalid signature, expired, replayed, request mismatch — raised even when the server answers HTTP 200); `ServerError` (503 `SERVER_OVERLOADED` after the automatic resends, 502/504 provider errors); `RateLimitError` (429); `ValidationError` (400/422); a 409 `IDEMPOTENCY_*`, 413 or 415 currently surfaces as `UnknownError` — read `status`/`reason`
- **Example**:
  ```python
  chat = client.chat.create(artifact_b64, {"prompt": "Explain quantum computing.", "model": "gpt-4"})
  if chat["decision"] == "EXECUTE":
      print(chat.get("aiText"))
  else:
      print("Blocked:", chat.get("reason"))
  ```
- **Notes**: A policy/consent/semantic `"BLOCK"` decision is a normal return value,
  not an exception — read `decision` (in the server's default
  `QODIQA_BLOCK_HTTP_MODE=decision` it is an HTTP 200). An artifact rejection
  (the 31 artifact-rejection reasons in `VERIFICATION_REASONS` (the server's `artifact_malformed`, `artifact_invalid`, `request_mismatch` and `replay` classes, src/api/blockHttpStatus.js — e.g. `INVALID_SIGNATURE`, `KEY_REVOKED`, `EXPIRED`, `REQUEST_MISMATCH`, `REPLAY_DETECTED`)) is always raised as `VerificationError`, whatever HTTP status the
  server used — exactly as `stream()` does for the same response.
  `create()` is not resent on a 5xx or 429 (the artifact nonce may already be
  consumed); only a 503 `SERVER_OVERLOADED` is resent (see [Retry policy](#13-retry-policy)).

### `stream(artifact, request, *, timeout=None)`

- **Signature**: `stream(artifact: str, request: ChatRequest, *, timeout: Optional[float] = None) -> Iterator[ChatStreamEvent]`
  (async: `AsyncChatResource.stream(...) -> AsyncIterator[ChatStreamEvent]`, **not** an `async def` — do not `await` the call itself, only iterating it is asynchronous)
- **Parameters**: same as `create()`, plus `timeout: Optional[float]` — overall
  time budget for the streaming session in seconds. `None` by default (no
  client-side cap); the server itself bounds a session at
  `STREAM_MAX_DURATION_MS` (default 5 minutes — see
  [`docs/architecture/streaming.md`](../../architecture/streaming.md) §9).
- **Wire body**: sends `{**request, "stream": True}`, always forcing the flag.
  `request` (and whatever was passed to `sign.sign()`) must independently
  include `"stream": True` in the signed body, or the server's `requestHash`
  binding check fails closed with `REQUEST_MISMATCH` (`VerificationError`)
  before any SSE byte is sent.
- **Returns**: an iterator/async-iterator of `ChatStreamEvent`, a discriminated
  union on the `"event"` key:

  | `event` | Fields | Meaning |
  |---|---|---|
  | `stream_started` | `streamId, requestId, artifactId, provider, model` | Always first; enforcement passed, SSE headers flushed |
  | `chunk_forwarded` | `delta, index` | One per incremental delta, strictly ordered by `index` (0, 1, 2, …) |
  | `stream_completed` | `streamId, requestId, chunksTotal, bytesTotal, durationMs` | Terminal — normal completion |
  | `stream_cancelled` | `streamId, reason, requestId` | Terminal — e.g. `CLIENT_DISCONNECT`, `STREAM_TIMEOUT`, `SEMANTIC_OUTPUT_BLOCKED`(`_FINAL`), `OUTPUT_TOO_LARGE`, `AUDIT_UNREPRESENTABLE_TEXT`, `PROVIDER_ERROR` or another provider code. A mid-stream failure is this event, not an exception. |

  Exactly one of `stream_completed` / `stream_cancelled` is ever yielded, and
  it is always the last event — the raw `[DONE]` sentinel that follows it on
  the wire is consumed internally to end iteration, never yielded itself.
- **Exceptions**: `ValidationError` (empty `artifact`/`prompt` — raised
  **immediately**, when `stream()` is called, not lazily on first iteration);
  `VerificationError` (pre-stream artifact rejection, any status);
  `BlockedError` (a non-artifact enforcement BLOCK — policy, consent,
  semantic, … — decided before the stream opened, answered HTTP 200 JSON in the
  server's default `decision` mode; in the opt-in `status` mode it arrives as
  403/429/503 and maps by status); `ServerError` 503
  `SERVER_OVERLOADED` only after the automatic pre-stream resends (see Cleanup);
  `ServerError` (a `data:` frame that is neither `[DONE]` nor valid JSON — a
  protocol violation); `TimeoutError` (`timeout` given and exceeded);
  `NetworkError` (dropped connection, any other unexpected low-level failure
  reading the stream, **or a body that ended without the terminal `[DONE]`
  frame** — a truncated stream; the events already yielded are a partial
  answer, never a complete one). With no `timeout`, the connect phase still
  keeps `ClientConfig.timeout`; read/write/pool are uncapped.
- **Example**:
  ```python
  for event in client.chat.stream(artifact_b64, {"prompt": "Tell me a story", "stream": True}):
      if event["event"] == "chunk_forwarded":
          print(event["delta"], end="", flush=True)
      elif event["event"] == "stream_completed":
          print(f"\n[done — {event['chunksTotal']} chunks]")
  ```
  Async:
  ```python
  async for event in client.chat.stream(artifact_b64, {"prompt": "Tell me a story", "stream": True}):
...
  ```
- **Cleanup**: breaking the `for`/`async for` loop early, or calling
  `.close()` (sync) / `await .aclose()` (async) on the returned generator
  explicitly, stops consumption and releases the underlying connection. Once
  the stream has opened it is never retried — a partially-consumed streaming
  session is not restartable as a single idempotent HTTP call the way a JSON
  request is (mirrors the server's own `IDEMPOTENCY_STREAMING_UNSUPPORTED`
  rejection). The one pre-stream refusal that is resent is a 503
  `SERVER_OVERLOADED` (admission control answers it before the artifact nonce
  is registered): up to `max_retries` times, after the server's `Retry-After`
  (else the jittered back-off); a `Retry-After` above 30 s, or one that would
  outlive `timeout`, raises the 503 instead. Never for a request carrying
  `X-QODIQA-OTP`.
- **Source**: [`sdk/python/qodiqa/_sse.py`](../../../sdk/python/qodiqa/_sse.py) (frame parsing),
  [`sdk/python/qodiqa/_http.py`](../../../sdk/python/qodiqa/_http.py) (`HttpClient.stream()` / `AsyncHttpClient.stream()`)

---

## 4. verify — VerifyResource

Source: [`sdk/python/qodiqa/resources/verify.py`](../../../sdk/python/qodiqa/resources/verify.py)

| Method | Signature | HTTP | Notes |
|---|---|---|---|
| `verify(artifact, request)` | `verify(artifact: str, request: VerifyRequest) -> VerifyResponse` | `POST /verify` | Artifact sent only in the request body (`request["artifact"]`); the `artifact` string is validated non-empty but not transmitted |
| `dry_run(request)` | `dry_run(request: VerifyRequest) -> VerifyResponse` | `POST /verify` | Artifact supplied only in the request body |

`VerifyResponse = {"decision", "reason", "details", "requestId", "artifactId"?, "keyId"?}`.
`verify()` raises `ValidationError` if `artifact` is empty.

The `/verify` route reads the artifact only from the request body; it does not inspect the `x-qodiqa-artifact` header, and no SDK method sends one. `verify()` and `dry_run()` therefore send an identical wire request — `verify()` keeps its `artifact` argument only for call-site backward compatibility.

The Python SDK has **no `verify_v2()`** (`POST /verify/v2`, the same handler under the higher `verify_v2` rate-limit bucket) — a recorded JS/Python parity gap (the JS SDK has `verifyV2()`; `scripts/contract/sdk-openapi-check.js` lists it as a reviewed parity exception). Call `/verify/v2` directly if you need that bucket.

```python
result = client.verify.verify(artifact_b64, {
    "artifact": signed["artifact"],
    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hi"}},
})
print(result["decision"])  # "EXECUTE" or "BLOCK"

dry = client.verify.dry_run({
    "artifact": signed["artifact"],
    "request": {"method": "POST", "path": "/ai/chat", "body": {}},
})
```

---

## 5. portal — PortalResource

Source: [`sdk/python/qodiqa/resources/portal.py`](../../../sdk/python/qodiqa/resources/portal.py)

Synchronous artifact verification through the public verification portal. There is no queued submit/poll API: `verify()` runs the full check suite and returns the complete report in one call. (Earlier versions of this page documented `submit()`, `get_status()` and `wait_for_result()`; none of them exists in `portal.py`.)

| Method | Signature | HTTP | Returns |
|---|---|---|---|
| `verify(artifact)` | `verify(artifact: Artifact) -> ApiResponse[PortalVerifyResult]` | `POST /v1/portal/verify` | `data = {"verificationId", "overallResult", "failedCheck", "failureReason", "warnings", "checks", "metadata", "durationMs", "verifiedAt"}` |
| `get_result(verification_id)` | `get_result(verification_id: str) -> ApiResponse[{"verification": PortalVerificationRecord}]` | `GET /v1/portal/result/:id` | The persisted record (snake_case PostgreSQL row) |

- **Auth**: none (rate-limited only). The request body *is* the raw artifact dict — not base64, not wrapped.
- **Exceptions**: `ValidationError` (empty `verification_id`, or a server 400); `RateLimitError`; `NotFoundError` from `get_result()` when the id is unknown **or PostgreSQL is disabled server-side** (the portal history store is PostgreSQL-only).
- **Example**:
  ```python
  report = client.portal.verify(signed["artifact"])
  print(report["data"]["overallResult"], report["data"]["failedCheck"])
  stored = client.portal.get_result(report["data"]["verificationId"])
  print(stored["data"]["verification"]["overall_result"])
  ```

---

## 6. attestation — AttestationResource

Source: [`sdk/python/qodiqa/resources/attestation.py`](../../../sdk/python/qodiqa/resources/attestation.py)

| Method | HTTP | Auth | Returns |
|---|---|---|---|
| `verify(artifact)` | `POST /v1/attestation/verify` | public | `ApiResponse` wrapping `AttestationRecord` |
| `verify_evidence(artifact)` | `POST /v1/attestation/evidence/verify` | public | `ApiResponse` |
| `verify_chain(artifact)` | `POST /v1/attestation/chain/verify` | public | `ApiResponse` |
| `get(id)` | `GET /v1/attestation/:id` | public | `ApiResponse` wrapping `AttestationRecord` |
| `get_evidence(id)` | `GET /v1/attestation/:id/evidence` | **ops key** | `ApiResponse` |
| `get_summary(id)` | `GET /v1/attestation/:id/summary` | **ops key** | `ApiResponse` |
| `list(params=None)` | `GET /v1/attestation/admin/history` | **ops key** | `ApiResponse` (paginated) |
| `stats()` | `GET /v1/attestation/admin/stats` | **ops key** | `ApiResponse` |

`id`-taking methods raise `ValidationError` if `id` is empty. Ops-protected
methods raise `AuthenticationError` client-side if no `api_key` is configured,
before any network call.

```python
record = client.attestation.verify(signed["artifact"])
print(record["data"]["attestationId"], record["data"]["status"])  # "VALID" | "INVALID"

history = client.attestation.list({"page": 1, "page_size": 50})  # requires api_key
```

> **Pagination parameter naming**: resource `list`/`list_entries` methods
> accept a dict using Python-conventional snake_case keys — `page`,
> `page_size`, `sort_order` — which `BaseResource._pagination_params`
> translates to the wire format `page`, `pageSize`, `sortOrder` before sending.

---

## 7. transparency — TransparencyResource

Source: [`sdk/python/qodiqa/resources/transparency.py`](../../../sdk/python/qodiqa/resources/transparency.py)

| Method | HTTP | Auth |
|---|---|---|
| `get_entry(id)` | `GET /v1/transparency/entry/:id` | public |
| `list_entries(params=None)` | `GET /v1/transparency/entries` | public |
| `get_root(root_id=None)` | `GET /v1/transparency/root` (`?rootId=` when given) | public |
| `list_roots(params=None)` | `GET /v1/transparency/roots` (paginated; `data = {"roots", "page", "pageSize", "total", …}`) | public |
| `verify_entry(id)` | `GET /v1/transparency/verify/:id` | public |
| `get_proof(id)` | `GET /v1/transparency/proof/:id` | public |
| `get_receipt(request_id)` | `GET /v1/transparency/receipt/:requestId` | public (the `requestId` is the capability); kept for a bounded window (default 1 h), then `NotFoundError` |
| `register(data)` | `POST /v1/transparency/register` | **ops key** |
| `generate_root()` | `POST /v1/transparency/admin/roots/generate` | **ops key** |
| `stats()` | `GET /v1/transparency/admin/stats` | **ops key** |
| `validate_chain(start_id=None, end_id=None, limit=None)` | `GET /v1/transparency/admin/chain/validate` (`?startId=&endId=&limit=`) | **ops key** (`READ_TRANSPARENCY_LOG`) |

`validate_chain()` checks the **transparency log**'s own hash chain (`data["chainValidation"] = {"valid", "checkedCount", "failureId", "failureDetail"}`); it does not call the audit chain's `/audit/chain/integrity`.

```python
root = client.transparency.get_root()
print(root["data"]["rootId"], root["data"]["entryCount"])

proof = client.transparency.get_proof("entry-001")
print(proof["data"]["proof"])  # List[str] — Merkle inclusion path (RFC 6962)
```

### Signed receipts (`Receipt`, `verify_receipt`)

An `/ai/chat` response carries `receipt` on an EXECUTE and on a post-authentication BLOCK — only when the audit entry and the transparency leaf are persisted, otherwise the key is **absent** (never `None`). It proves that the gateway *recorded* the decision (`entryHash` of the audit entry, `leafHash` of the transparency leaf); it does not prove the decision was correct. Verify it offline with the transparency keys from `GET /.well-known/qodiqa/transparency-keys`:

```python
from qodiqa import verify_receipt, receipt_binds_to
keys = httpx.get(f"{base_url}/.well-known/qodiqa/transparency-keys").json()   # {"keys": [{"keyId", "publicKey", "status", ...}]}
chat = client.chat.create(artifact_b64, {"prompt": "hi"})
if "receipt" in chat:
    ok, reason = verify_receipt(chat["receipt"], keys)           # never raises, fails closed
    if not ok:
        raise RuntimeError(f"receipt rejected: {reason}")        # BAD_SIGNATURE, UNKNOWN_KEY, FIELD_SET, REVOKED_KEY, ...
```

`verify_receipt(receipt, keys, *, trusted_at=None)` — a receipt signed by a since-revoked key verifies only in the timed mode (`trusted_at` in ms from an independent authority, before the key's `revokedAt`). `receipt_binds_to(receipt, entry_hash=…, leaf_hash=…, request_id=…, decision=…)` lists the values that differ from evidence you already hold. The signature is `Ed25519(SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature)))` — see `docs/protocol/PROTOCOL-V2.md` section 6.

---

## 8. evidence — EvidenceResource

Source: [`sdk/python/qodiqa/resources/evidence.py`](../../../sdk/python/qodiqa/resources/evidence.py)

### `get_package(artifact_id)`

- **Signature**: `get_package(artifact_id: str) -> ApiResponse`
- **HTTP**: `GET /v1/attestation/:artifactId/evidence`
- **Auth**: **Ops API key required.**
- **Exceptions**: `ValidationError` (empty `artifact_id`), `AuthenticationError` (no `api_key`)

```python
pkg = client.evidence.get_package("att-001")  # requires api_key
```

> Identical wire route to `attestation.get_evidence(id)` — exposed under two
> resource names because the server groups the endpoint under both concepts.

---

## 9. certification — CertificationResource

Source: [`sdk/python/qodiqa/resources/certification.py`](../../../sdk/python/qodiqa/resources/certification.py)

| Method | Signature | HTTP | Auth |
|---|---|---|---|
| `evaluate(artifacts, **extra)` | `evaluate(artifacts: List[Artifact], **extra: Any) -> ApiResponse` | `POST /v1/certification/evaluate` | **ops key** |
| `get(id)` | `get(id: str) -> ApiResponse` | `GET /v1/certification/:id` | public |
| `get_summary(id)` | `get_summary(id: str) -> ApiResponse` | `GET /v1/certification/:id/summary` | public |
| `submit_batch(framework_id, items)` | `submit_batch(framework_id: str, items: List[Dict[str, Any]]) -> ApiResponse` | `POST /v1/certifications/batch` | **ops key** |
| `get_batch(batch_id)` | `get_batch(batch_id: str) -> ApiResponse` | `GET /v1/certifications/batch/:batchId` | **ops key** |
| `get_batch_results(batch_id)` | `get_batch_results(batch_id: str) -> ApiResponse` | `GET /v1/certifications/batch/:batchId/results` | **ops key** |
| `cancel_batch(batch_id)` | `cancel_batch(batch_id: str) -> ApiResponse` | `POST /v1/certifications/batch/:batchId/cancel` | **ops key** |
| `list(params=None)` | `list(params: Optional[PaginationParams] = None) -> ApiResponse` | `GET /v1/certification/admin/history` | **ops key** |
| `stats()` | `stats() -> ApiResponse` | `GET /v1/certification/admin/stats` | **ops key** |

`evaluate` sends `{"artifacts": artifacts, **extra}` — the server validates the body strictly as
`{artifacts (max 50), evidencePackages?, chain?, options?}`, so `**extra` may only carry those three keys.
`submit_batch` sends `{"frameworkId": framework_id, "items": items}`; each item needs a `subjectId`
(plus optional `artifacts`, `evidencePackages`, `controls`).

```python
cert = client.certification.evaluate([signed["artifact"]])  # requires api_key
print(cert["data"]["id"], cert["data"]["status"], cert["data"].get("score"))

batch = client.certification.submit_batch(
    "framework-1",
    [{"subjectId": "svc-a", "artifacts": [a1]}, {"subjectId": "svc-b", "artifacts": [a2]}],
)  # requires api_key
```

---

## 10. webhooks — WebhooksResource

Source: [`sdk/python/qodiqa/resources/webhooks.py`](../../../sdk/python/qodiqa/resources/webhooks.py)

**Every method requires an ops API key.** This manages registered webhook
*endpoints* — for verifying inbound *deliveries*, see
[§15](#15-webhook-signature-verification).

| Method | Signature | HTTP |
|---|---|---|
| `create(request)` | `create(request: WebhookCreateRequest) -> ApiResponse` | `POST /v1/webhooks` |
| `list(tenant_id, params=None)` | `list(tenant_id: str, params: Optional[PaginationParams] = None) -> ApiResponse` | `GET /v1/webhooks?tenantId=` (required server-side; no cross-tenant list) |
| `get(id, tenant_id)` | `get(id: str, tenant_id: str) -> ApiResponse` | `GET /v1/webhooks/:id?tenantId=` |
| `update(id, request, tenant_id)` | `update(id: str, request: WebhookUpdateRequest, tenant_id: str) -> ApiResponse` | `PATCH /v1/webhooks/:id?tenantId=` |
| `delete(id, tenant_id)` | `delete(id: str, tenant_id: str) -> ApiResponse` | `DELETE /v1/webhooks/:id?tenantId=` |
| `test(id, tenant_id)` | `test(id: str, tenant_id: str) -> ApiResponse` | `POST /v1/webhooks/:id/test?tenantId=` |
| `get_deliveries(id, tenant_id)` | `get_deliveries(id: str, tenant_id: str) -> ApiResponse` | `GET /v1/webhooks/:id/deliveries?tenantId=` |
| `metrics()` | `metrics() -> ApiResponse` | `GET /v1/webhooks/metrics` |

(API-15): the server answers 400 without `tenantId` on every per-id webhook route; before the argument existed these five methods could never succeed against a real gateway. `list()` likewise takes `tenant_id` as its first, required argument. Mutations (`create`, `update`, `delete`, `test`) also require the operator MFA step-up — see `otp_provider` in [configuration.md](configuration.md).

`create()` validates client-side: `request["tenantId"]` and `request["url"]`
must be non-empty strings, and `request["eventTypes"]` must be a non-empty
list — all raise `ValidationError` otherwise.

```python
webhook = client.webhooks.create({
    "tenantId": "tenant-1",
    "url": "https://example.com/webhook",
    "eventTypes": ["attestation.completed", "certification.evaluated"],
})
print(webhook["data"]["id"], webhook["data"]["secret"])  # secret returned once
```

---

## 11. simulation — SimulationResource (policy dry-run)

Source: [`sdk/python/qodiqa/resources/simulation.py`](../../../sdk/python/qodiqa/resources/simulation.py)

Read-only policy dry-run: no nonce registered, no anomaly counter incremented,
no audit record written, no AI provider contacted. `executionPrevented: True`
is always present in the response.

| Method | Signature | HTTP |
|---|---|---|
| `simulate(request)` | `simulate(request: Dict[str, Any]) -> Dict[str, Any]` | `POST /v1/policy/simulate` |
| `compare(request)` | `compare(request: Dict[str, Any]) -> Dict[str, Any]` | `POST /v1/policy/compare` |
| `batch(request)` | `batch(request: Dict[str, Any]) -> Dict[str, Any]` | `POST /v1/policy/simulate/batch` |

- `simulate`: `request` keys — `context` (optional dict: `userId`, `action`,
  `tenantId`, `requestId`, `ip`, `timestamp`), `policies` (optional list of
  policy-definition dicts; omit to use the live policy set), `scenario`
  (optional label). Response `data` includes `decision`, `reason`,
  `evaluationTrace`, `matchedRules`, `failedRules`, `riskLevel`,
  `explanation`, `executionPrevented: True`.
- `compare`: `request` keys — `context` (optional), `currentPolicies`
  (optional; omit to use the live set), `proposedPolicies` (**required**
  list), `scenario` (optional). Response `data` includes `old`, `proposed`,
  `decisionChanged`, `changedRules`, `executionPrevented: True`.
- `batch`: `request` keys — `simulations` (list of up to 100 dicts, each with
  `context`, optional `policies`, optional `scenario`), `policies` (optional
  shared policy set applied when an item omits its own). Response `data`
  includes `batchId`, `total`, `allowed`, `blocked`, `results`,
  `executionPrevented: True`.

```python
result = client.simulation.simulate({
    "context": {"userId": "my-key:key_v1", "action": "openai", "ip": "192.168.1.1"},
})
print(result["data"]["decision"], result["data"]["executionPrevented"])
```

---

## 12. Error handling

Source: [`sdk/python/qodiqa/exceptions.py`](../../../sdk/python/qodiqa/exceptions.py)

Every SDK exception extends `QodiqaError(Exception)`:

```python
class QodiqaError(Exception):
    message: str
    status: Optional[int]
    request_id: Optional[str]
    details: Dict[str, Any]
```

### HTTP-mapped exception classes

| Class | HTTP status | Raised when |
|---|---|---|
| `AuthenticationError` | 401 | Missing/invalid `api_key` or `sign_token` — client-side or server-side. (A missing/invalid *artifact* is a `VerificationError`; an empty artifact string is a client-side `ValidationError`.) |
| `AuthorizationError` | 403 | Authenticated but not permitted (`reason == "FORBIDDEN"`) |
| `ValidationError` | 400 (also for 422 responses) | Malformed payload, client-side or server-side |
| `VerificationError` | any (200 in the server's default mode; 400/403/409 in `status` mode) | Server reason is one of the 31 artifact-rejection reasons in `VERIFICATION_REASONS` (the server's `artifact_malformed`, `artifact_invalid`, `request_mismatch` and `replay` classes, src/api/blockHttpStatus.js — e.g. `INVALID_SIGNATURE`, `KEY_REVOKED`, `EXPIRED`, `REQUEST_MISMATCH`, `REPLAY_DETECTED`) — the artifact itself was rejected. Raised by both `chat.create()` and `chat.stream()` |
| `BlockedError` | 200 | `chat.stream()` only: a non-artifact enforcement `BLOCK` (policy, consent, semantic, ...) decided before the stream opened — `create()` returns the same decision instead. Carries `reason` and `decision == "BLOCK"` |
| `MfaRequiredError` (subclass of `AuthenticationError`) | 401 | Operator MFA step-up: `MFA_REQUIRED` (no `X-QODIQA-OTP`) or `MFA_INVALID` (wrong/reused code). Pass `otp_provider` to answer it automatically |
| `MfaEnrollmentRequiredError` (subclass of `AuthorizationError`) | 403 | `MFA_ENROLLMENT_REQUIRED` — enroll first (POST /rbac/me/mfa/enroll + /confirm) |
| `MfaLockedError` | 429 | `MFA_LOCKED` — 5 failed codes in 15 minutes; never retried; carries `retry_after` |
| `NotFoundError` | 404 | Resource does not exist |
| `RateLimitError` | 429 | Rate limit exceeded; carries `retry_after: Optional[float]` |
| `ServerError` | 5xx | Unhandled server-side failure |
| `KillSwitchError` (subclass of `ServerError`) | 503 | The gateway's global kill switch is active (`KILL_SWITCH_ACTIVE`) or its state cannot be confirmed (`KILL_SWITCH_STATE_UNAVAILABLE`): /sign and /ai/chat are refused until an operator releases it. Nothing was signed, no nonce consumed, no provider called — retrying later is safe, but the SDK never retries it automatically. Carries `retry_after` |
| `NetworkError` | n/a | `httpx.RequestError` (connection failure, DNS, etc.) |
| `TimeoutError` | n/a | `httpx.TimeoutException` (the per-attempt `timeout`), or `chat.stream(..., timeout=...)` exceeding its overall budget |
| `UnknownError` | any | Status/reason combination not otherwise mapped — today this includes `409` (`IDEMPOTENCY_KEY_CONFLICT`, `IDEMPOTENCY_REQUEST_IN_PROGRESS`), `413` and `415`; read `exc.status` / `exc.reason` |

### Webhook verification exception classes

| Class | Status (as constructed) | Raised when |
|---|---|---|
| `InvalidSignatureError` | 401 | No configured secret produces a matching HMAC |
| `ExpiredSignatureError` | 401 | Timestamp is outside the tolerance window |
| `MalformedSignatureError` | 400 | `X-QODIQA-Signature` header cannot be parsed |
| `InvalidTimestampError` | 400 | `t=` component is not a valid positive integer |

### Reserved (not currently raised) exception classes

`SigningError`, `SerializationError`, and `CryptoKeyError` are exported from
`qodiqa.exceptions` "preserved from prior SDK version" (per the source
docstring), but **no operation in this HTTP-client SDK raises them** — they
exist for import compatibility with code written against the earlier,
local-signing version of the package.

### The `create_error` factory

`create_error(status, reason, message, request_id=None, details=None) ->
QodiqaError` maps an HTTP status + server `reason` string to the correct
class, in this priority order: `MFA_REQUIRED`/`MFA_INVALID` →
`MfaRequiredError`; `MFA_ENROLLMENT_REQUIRED` → `MfaEnrollmentRequiredError`;
`MFA_LOCKED` → `MfaLockedError`; `401`/`UNAUTHORIZED`/`UNAUTHENTICATED` →
`AuthenticationError`; a `VERIFICATION_REASONS` reason → `VerificationError`
(at any status); `403`/`FORBIDDEN` → `AuthorizationError`;
`404`/`NOT_FOUND` → `NotFoundError`; `429`/`RATE_LIMITED`/`RATE_LIMIT_EXCEEDED`
→ `RateLimitError` (with `retry_after` from `details["retryAfter"]` when
present); `400`/`422`/`VALIDATION_ERROR`/`INVALID_REQUEST` → `ValidationError`;
any `5xx` → `ServerError`; a `2xx` (a pre-stream BLOCK) → `BlockedError`;
otherwise → `UnknownError`. Every error carries the server `reason` as `exc.reason`. Internal — explains which
class you'll observe for a given server response.

How `reason`, `request_id` and `details` are read from a response: the decision envelope's `reason`; a
management envelope's `error.code`; the flat protocol-limiter 429 body (`{error, surface, dimension, reason,
retryAfterSeconds}`, `/sign`) maps its `error` code (e.g. `RATE_LIMIT_EXCEEDED`) to `exc.reason` and keeps the
limiter window name (`BURST`, `SUSTAINED`, …) in `details["blockedBy"]`, with `surface`, `dimension` and
`retryAfterSeconds` (change — previously the window name surfaced as `exc.reason`; code that matched on it
should read `details["blockedBy"]`). `request_id` comes from the body, else from the `X-Request-ID` response
header (the per-HTTP trace id). A `Retry-After` header — delta-seconds or an HTTP-date, on any status and any body
shape, a proxy's HTML 503 included — is parsed into `details["retryAfter"]` (seconds); an unparseable value is
ignored.

### Handling errors

```python
from qodiqa.exceptions import (
    QodiqaError, AuthenticationError, RateLimitError,
    VerificationError, ValidationError, NetworkError, TimeoutError,
)

try:
    result = client.verify.verify(artifact_b64, request)
except AuthenticationError as exc:
    print("Auth failed:", exc.message)
except RateLimitError as exc:
    print(f"Rate limited. Retry after {exc.retry_after}s")
except VerificationError as exc:
    print("Signature invalid:", exc.message, exc.details)
except ValidationError as exc:
    print("Bad request:", exc.message, exc.details)
except NetworkError as exc:
    print("Network problem:", exc.message)
except TimeoutError:
    print("Request timed out")
except QodiqaError as exc:
    print(f"Error [{exc.status}]: {exc.message} (request_id={exc.request_id})")
```

---

## 13. Retry policy

Source: [`sdk/python/qodiqa/_http.py`](../../../sdk/python/qodiqa/_http.py)

Both `HttpClient.request()` and `AsyncHttpClient.request()` loop up to
`config.max_retries + 1` total attempts with `base_delay = 0.5` seconds,
`max_delay = 30.0` seconds.

- **Retry condition** (`should_retry_request(err, method, path)`, / API-03):
  - `503 SERVER_OVERLOADED` (admission control — refused before the request is
    decoded, verified or its nonce registered): always retried, `/ai/chat` included;
  - idempotent methods (`GET`, `PUT`, `DELETE`): `429`, `500`, `502`, `503`, `504`;
  - `POST`/`PATCH`: only a `429` (the request limiters answer before the handler
    runs) — and **never on `/ai/chat`**, where a 429 can come from the
    per-identity limiter after the artifact nonce was consumed. A `5xx` on a
    `POST` may already have been processed, so it is raised, not resent;
  - never: `MfaLockedError`; any request carrying an MFA code (`X-QODIQA-OTP`,
    from the `otp_provider` resend, per-call headers or the client's default
    headers — the server accepts a TOTP code at most once per step, so a resend
    would be refused as `MFA_INVALID` and count toward the lockout); a
    `httpx.TimeoutException` is converted to `TimeoutError` and raised
    immediately (it already exhausted the budget); any other error (e.g. `400`,
    `401`, `404`, `409`) is raised immediately
- **MFA step-up** (not a retry): with `otp_provider` configured, a `401
  MFA_REQUIRED` is answered by resending that one request once with
  `X-QODIQA-OTP: otp_provider()` — the step-up refuses before the handler runs,
  so nothing was changed. `MFA_INVALID` is never resent.
- **Backoff**: exponential with full jitter —
  `delay = random.uniform(0, min(base_delay * 2**attempt, max_delay))`
- **`Retry-After` precedence**: when the error carries a
  server-stated wait — `RateLimitError.retry_after`, or the parsed `Retry-After`
  header in `details["retryAfter"]` on **any** status (e.g. 503
  `SERVER_OVERLOADED`, which the admission controller always sends with
  `Retry-After`) — that value is the wait instead of the computed back-off. A
  retry sooner would be refused by construction, so a `Retry-After` longer than
  `max_delay` (30 s) is **not** shortened: the error is raised instead.
- **Timeout semantics**: `timeout` applies per attempt (httpx); unlike the JS
  SDK there is no single overall budget across retries for JSON calls
- **Sleep mechanism**: `time.sleep(delay)` in the sync client,
  `await asyncio.sleep(delay)` in the async client

There is no separately exported `with_retry`-style helper in the Python SDK —
retry is applied internally by `HttpClient`/`AsyncHttpClient` and is not a
public function you can reuse for your own operations (unlike the JavaScript
SDK's exported `withRetry`).

---

## 14. Pagination

Source: [`sdk/python/qodiqa/_pagination.py`](../../../sdk/python/qodiqa/_pagination.py)

List methods (`attestation.list`, `transparency.list_entries`,
`certification.list`, `webhooks.list`, `transparency.list_roots`) accept a
`PaginationParams`-shaped dict with snake_case keys — `{"page": int,
"page_size": int, "sort_order": "asc" | "desc"}` — and return `ApiResponse`
wrapping `PaginatedResponse = {"records": List[T], "page", "pageSize",
"total", "hasMore"}` (note: the *response* fields are camelCase, matching the
wire format, while *request* keys are snake_case, translated internally by
`BaseResource._pagination_params`).

### Sync: `PagePage` / `PageIterator`

```python
from qodiqa._pagination import PageIterator, PagePage

# Items, across all pages
items = PageIterator(
    lambda page, size: client.transparency.list_entries({"page": page, "pageSize": size})["data"],
    page_size=50,
)
for entry in items:
    print(entry["id"])

# Whole pages
pages = PagePage(
    lambda page, size: client.transparency.list_entries({"page": page, "pageSize": size})["data"],
    page_size=20,
)
for page in pages:
    for entry in page["records"]:
        print(entry["id"])
```

Constructor: `PageIterator(fetcher, *, start_page: int = 1, page_size: int =
50)` / `PagePage(fetcher, *, start_page: int = 1, page_size: int = 50)`.
`fetcher: Callable[[int, int], PaginatedResponse-like dict]` — **must return
the raw `{"records": ..., "hasMore": ...}` dict, not the `ApiResponse`
envelope**, so unwrap `["data"]` from the resource method's return value as
shown above.

### Async: `AsyncPagePage` / `AsyncPageIterator`

```python
from qodiqa._pagination import AsyncPageIterator

async for entry in AsyncPageIterator(
    lambda page, size: client.transparency.list_entries({"page": page, "pageSize": size})["data"],
    page_size=50,
):
    print(entry["id"])
```

Same unwrapping requirement applies; `fetcher` must be an async callable
(`await`ed internally).

---

## 15. Webhook signature verification

Source: [`sdk/python/qodiqa/webhook_verifier.py`](../../../sdk/python/qodiqa/webhook_verifier.py)

Matches the server's actual wire format (`src/core/webhooks/webhookDelivery.js`):
QODIQA signs each webhook delivery with HMAC-SHA256, sent in
`X-QODIQA-Signature: sha256=<hex_hmac>`, with the delivery timestamp sent
*separately* in its own `X-QODIQA-Timestamp` header (ISO-8601 UTC, e.g.
`2026-01-01T00:00:00.000Z`). The HMAC covers
`<raw_X-QODIQA-Timestamp_header_value> + "." + <raw_request_body>` — always
pass the **raw bytes** as received, never a re-serialized JSON string, and
pass the timestamp through exactly as received (never reformatted).

> As of this writing `sdk/javascript`'s webhook verifier still implements the
> older `t=<unix_timestamp>,v1=<hex>` combined-header format, which does not
> match the server either — that is a separate, not-yet-fixed defect in the
> JavaScript SDK. Do not treat the two SDKs as protocol-equivalent until it
> is corrected.

### `verify_webhook_signature(...)`

- **Signature**:
  ```python
  def verify_webhook_signature(
      *,
      body: Union[str, bytes],
      signature: str,
      timestamp: str,
      secret: Union[str, List[str]],
      tolerance: int = DEFAULT_TOLERANCE_SECONDS,
  ) -> None
  ```
- **Parameters**: `body` — raw request body; `signature` — value of
  `X-QODIQA-Signature`; `timestamp` — value of `X-QODIQA-Timestamp`; `secret`
  — one secret or a list (verification succeeds if any matches, supporting
  rotation); `tolerance` — max accepted timestamp age in seconds, default
  `DEFAULT_TOLERANCE_SECONDS` (`300`)
- **Returns**: `None` on success; raises on failure
- **Exceptions**: `MalformedSignatureError`, `InvalidTimestampError`,
  `ExpiredSignatureError`, `InvalidSignatureError` (checked with
  `hmac.compare_digest` for constant-time comparison)
- **Example**:
  ```python
  from qodiqa import verify_webhook_signature

  @app.post("/webhooks/qodiqa")
  async def webhook(request: Request):
      verify_webhook_signature(body=await request.body,
          signature=request.headers["x-qodiqa-signature"],
          timestamp=request.headers["x-qodiqa-timestamp"],
          secret=WEBHOOK_SECRET,
      )
      event = await request.json
  ```

### `WebhookVerifier` (reusable class)

```python
class WebhookVerifier:
    def __init__(self, secret: Union[str, List[str]], *, tolerance: int = DEFAULT_TOLERANCE_SECONDS) -> None: ...
    def verify(self, *, body: Union[str, bytes], signature: str, timestamp: str) -> None: ...
```

```python
verifier = WebhookVerifier(WEBHOOK_SECRET)
verifier.verify(body=raw_body, signature=signature, timestamp=timestamp)

# Secret rotation — verification succeeds if ANY secret matches
verifier = WebhookVerifier([NEW_WEBHOOK_SECRET, OLD_WEBHOOK_SECRET])
```

### `DEFAULT_TOLERANCE_SECONDS`

`DEFAULT_TOLERANCE_SECONDS: int = 300` (5 minutes).

> **Capturing the raw body per framework**: FastAPI — `await request.body()`
> **before** `await request.json()` (reading JSON first consumes the stream);
> Flask — `request.get_data()` (safe to call before `get_json()`, the body is
> cached); Django — `request.body` (cached on first access; do not call
> `request.POST` first). See [examples.md](examples.md#webhook-receivers) for
> full route-level examples.

---

## 16. Local Artifact & Transparency-Proof Verification

Source: [`sdk/python/qodiqa/_verification/`](../../../sdk/python/qodiqa/_verification/)
(private implementation package; every symbol below is re-exported flatly
from `qodiqa`, matching this SDK's `_http.py`/`_pagination.py` convention).

**remediation.** `ArtifactVerifier` (sync) / `AsyncArtifactVerifier`
(async) perform the complete verification pipeline entirely offline: schema
validation, canonical JSON reconstruction (a from-scratch, carefully-checked
port matching the server's `stableStringify` byte-for-byte for every value
type a real QODIQA artifact contains — see note on floats below), payload-hash
computation, public-key resolution, Ed25519 signature verification
(`cryptography`), timestamp/expiry checks, and optional transparency-proof
verification. **None of this depends on calling the server's `/verify`
endpoint or trusting its response.** `resources/verify.py`'s `POST /verify`
(§4 above) remains available as an optional remote convenience and is never
used internally here.

### `ArtifactVerifier` / `AsyncArtifactVerifier`

```python
class ArtifactVerifier:
    def __init__(
        self, *, keys: KeyProvider, transparency_keys: Optional[KeyProvider] = None,
        clock_tolerance_ms: int = 0, require_transparency: bool = False,
    ) -> None: ...
    def verify(self, artifact: Artifact, *, transparency_proof: Optional[dict] = None) -> ArtifactVerificationResult: ...

class AsyncArtifactVerifier:
    def __init__(self, *, keys, transparency_keys=None, clock_tolerance_ms=0, require_transparency=False) -> None: ...
    async def verify(self, artifact, *, transparency_proof=None) -> ArtifactVerificationResult: ...
```

- **Never raises for content problems.** A malformed artifact, bad
  signature, unknown/revoked key, expired artifact, or unverifiable
  transparency proof — every one of these resolves to a structured
  `ArtifactVerificationResult`, never a raised exception. Only constructor
  misconfiguration (`keys` missing; `require_transparency=True` with no
  `transparency_keys`) raises `ValidationError` synchronously.
- `AsyncArtifactVerifier` accepts either a sync, no-I/O provider (like
  `StaticKeyProvider`) or a genuinely async one (`AsyncRemoteKeyProvider`) —
  it detects at call time whether `get_public_key()` returned an awaitable
  and only awaits when it actually is one. Do not pass a *blocking* sync
  `RemoteKeyProvider` to `AsyncArtifactVerifier`; use `AsyncRemoteKeyProvider`
  there so real network I/O doesn't stall the event loop.
- See [configuration.md § Key provider configuration](configuration.md#key-provider-configuration)
  for `StaticKeyProvider`, `RemoteKeyProvider`/`AsyncRemoteKeyProvider`, and
  `create_key_provider`/`create_async_key_provider`, and why the artifact and
  transparency key sources must always be two separate instances.

### `verify_artifact(artifact, **kwargs)` — one-shot convenience function

```python
def verify_artifact(
    artifact, *, keys: KeyProvider, transparency_keys: Optional[KeyProvider] = None,
    clock_tolerance_ms: int = 0, require_transparency: bool = False,
    transparency_proof: Optional[dict] = None,
) -> ArtifactVerificationResult: ...
```

Equivalent to constructing an `ArtifactVerifier` and calling `.verify()`
once; use the class directly when verifying many artifacts against the same
trust bundle, so a `RemoteKeyProvider`'s cache is reused.

### `ArtifactVerificationResult` (frozen dataclass)

| Field | Type | Meaning |
|---|---|---|
| `verification_status` | `'valid' \| 'invalid' \| 'error'` | Overall outcome. `'error'` is distinct from `'invalid'` — it means a `KeyProvider` itself failed (e.g. a network error resolving a remote key), not that the artifact was proven bad. |
| `signature_valid` | `bool` | The actual cryptographic check — Ed25519 signature over the envelope hash. This is what catches tampering. |
| `payload_hash_valid` | `bool` | **Not** an independent stored-hash comparison — the real artifact envelope has no separately-stored payload hash field; this means "the envelope hash was computed without a structural error." |
| `canonicalization_valid` | `bool` | The payload could be canonicalized without violating the protocol (no forbidden keys, no non-finite numbers, no unsupported types, no non-integer floats — see below). |
| `key_valid` | `bool` | The resolved key's status is `active` or `deprecated` (not unknown, not `revoked`). |
| `key_id` / `key_status` | `str \| None` | The artifact's `publicKeyId` and its resolved status, once key resolution is reached. |
| `key_source` | `str \| None` | Which discovery tier resolved the key — `"archived"` means it was only resolvable via `RemoteKeyProvider`'s archived-key fallback, i.e. it had already been purged from the live keystore. `None` when no key was resolved. Purely diagnostic — never affects `key_valid`. |
| `expiry_valid` / `timestamp_valid` | `bool` | Expiry and future-timestamp checks, ± `clock_tolerance_ms`. |
| `transparency_verified` | `'verified' \| 'failed' \| 'unavailable'` | Distinguishes "no proof was supplied" (`'unavailable'`) from "a proof was supplied and failed" (`'failed'`) — these are never conflated. |
| `transparency_detail` | `TransparencyVerificationDetail \| None` | Per-check breakdown when a proof was supplied. |
| `verification_errors` / `verification_warnings` | `List[str]` | Human-readable detail; always empty on a fully valid result. |
| `failed_stage` | `str \| None` | One of `STRUCTURE`, `CANONICALIZATION`, `KEY_RESOLUTION`, `FUTURE_TIMESTAMP`, `EXPIRED`, `INVALID_SIGNATURE`, `TRANSPARENCY` — reuses the server's own `reason` vocabulary from `validateArtifact.js` where they map 1:1, plus `TRANSPARENCY` for the SDK-only local proof stage. |
| `verified_at` | `int` | Unix ms epoch the verification ran at. |

The pipeline is fail-closed and stops at the first failing stage — fields for
stages never reached keep their default. Consult `failed_stage` to know
which check actually failed rather than inferring it from which booleans are
`False`.

### A note on numbers and canonical JSON

Python has no shared canonicalization package with the JS server, so this
SDK's `stable_stringify` is a from-scratch port, not a shared library call.
It matches the server exactly for strings, integers, booleans, `None`, and
whole-number floats (`5.0` formats identically to `5`, matching JS's
`JSON.stringify`, which never emits a trailing `.0`). A **non-integer**
float (e.g. `3.14`) is rejected outright (`CanonicalizationError` with code
`NON_INTEGER_FLOAT`) rather than attempting a lossy, best-effort match of
ECMA-262's Number-to-string algorithm — real QODIQA artifact payloads only
ever carry strings, integers, and booleans in practice, so this is a
deliberate, documented restriction rather than a silent gap.

### Transparency-proof verification

Pass a `transparency_proof` dict (the object returned by
`client.transparency.get_proof(id)["data"]["proof"]`) to `verify()` to
additionally, fully locally:

1. Recompute the entry's `entryHash` from its own canonical fields (a
   strictly stronger check than the server's own `verifyInclusionProof`,
   which trusts `entryHash` as given).
2. Reconstruct the Merkle root from the leaf hash and the audit path (RFC
   6962), and confirm it matches `proof["root"]["rootHash"]`.
3. Verify the entry and root Ed25519 signatures against the configured
   `transparency_keys` provider — the separate trust domain from artifact
   keys.
4. Confirm `leafIndex` is within `[0, treeSize)`.

```python
proof = client.transparency.get_proof(transparency_id)["data"]["proof"]
result = verifier.verify(artifact, transparency_proof=proof)
print(result.transparency_verified)  # 'verified' | 'failed' | 'unavailable'
```

If no `transparency_proof` is supplied, `transparency_verified` is
`'unavailable'` and this **never** affects `verification_status` unless the
verifier was constructed with `require_transparency=True`.

### `TransparencyVerificationDetail` (frozen dataclass)

| Field | Meaning |
|---|---|
| `entry_hash_valid` | Recomputed `entryHash` matches the one on the entry. |
| `merkle_path_valid` | The audit path reconstructs `root.rootHash`, `proof.merkleRoot` (if present) agrees with it, and the path is exactly the RFC 6962 path of `proof.leafIndex` in a tree of `proof.treeSize` leaves, with `proof.treeSize` equal to the signed root's `entryCount` — a proof for one leaf position does not verify as another. |
| `leaf_index_valid` | `0 <= leafIndex < treeSize`. |
| `key_valid` / `key_status` | The transparency signing key resolved and is `active`/`deprecated`. |
| `entry_signature_valid` / `root_signature_valid` | Ed25519 signature checks on the entry and root respectively. |

### Lower-level building blocks (also exported)

`stable_stringify`, `CanonicalizationError` (canonical JSON), `verify_inclusion_path`
(RFC 6962 Merkle audit-path verification only). These are the same
primitives `ArtifactVerifier` is built from — most integrations only need
`ArtifactVerifier`/`AsyncArtifactVerifier`/`verify_artifact` directly.

---

## 17. Typed models

All are `TypedDict` classes defined in
[`sdk/python/qodiqa/models.py`](../../../sdk/python/qodiqa/models.py) and
re-exported from `qodiqa`:

**Core**: `HttpMethod`, `Decision`, `KeyStatus`, `ConsentState`

**Artifact**: `Artifact`, `ArtifactPayload`

**Sign / Verify / Chat**: `SignRequest`, `SignResponse`, `SignMeta`,
`VerifyRequest`, `VerifyResponse`, `ChatRequest`, `ChatResponse`, `TokenUsage`

**Chat streaming**: `ChatStreamEvent` (union), `ChatStreamStartedEvent`,
`ChatStreamChunkEvent`, `ChatStreamCompletedEvent`, `ChatStreamCancelledEvent`

**Keys / Audit / Health**: `PublicKey`, `KeysResponse`, `AuditChainEntry`,
`AuditResponse`, `HealthResponse`, `ReadyResponse`

**Attestation / Certification**: `AttestationRecord`, `CertificationRecord`,
`BatchRecord`

**Transparency**: `TransparencyEntry`, `TransparencyRoot`, `InclusionProof`,
`TransparencyVerifyResult`

**Portal**: `PortalResult`, `PortalStatus`

**Webhooks**: `WebhookCreateRequest`, `WebhookRecord`, `WebhookUpdateRequest`

**Pagination / envelope**: `PaginationParams`, `PaginatedResponse`,
`ApiResponse`

**Configuration**: `ClientConfig` (frozen dataclass — see
[configuration.md](configuration.md))

`ClientConfig` and the models above are all `mypy --strict`-checked, per
`[tool.mypy]` in `pyproject.toml`.

## Scope note: Consent and RBAC endpoints

Identical scope boundary to the JavaScript SDK: the QODIQA server exposes
Consent-management endpoints (`POST /consent`, `POST
/consent/:consentId/revoke`, `POST /consent/actor/:actorId/revoke`, `POST
/consent/:consentId/suspend`, `POST /consent/:consentId/resume`, `GET
/consent` — see
[`docs/api/overview.md`](../../api/overview.md#consent-endpoints)) and RBAC
endpoints (`/rbac/*`), **neither of which has a dedicated resource on
`QodiqaClient`** (there is no `client.consent` or `client.rbac`). Consent is
enforced server-side via the `REQUIRE_CONSENT` policy rule and is observable
through [`client.simulation`](#11-simulation--simulationresource-policy-dry-run)
(`matchedRules`/`failedRules`) and through the `consent.granted` /
`consent.revoked` webhook event types. Calling the Consent/RBAC HTTP endpoints
directly from Python requires an ad hoc `httpx` call against the documented
routes rather than a typed resource method. If this SDK ever grows a typed
consent resource, its revocation methods must be named `revoke_*` (e.g.
`revoke_consent`, `revoke_actor_consent`), never `delete_*` — revocation is a
state transition, not a deletion, and GDPR Article 17 erasure is a separate
operation entirely (`POST /v1/admin/dsr/:id/erase`; see
[`docs/guides/dsr.md`](../../guides/dsr.md)). This mirrors the
remediation applied to the HTTP API itself —

## Operations: every documented operation (`client.operations`)

`client.operations` (sync and async) is generated from `docs/api/openapi.json` and covers **all** documented operations (364 in this version). The method name is the snake_case
`operationId`; `call(name)`, `list()` and `describe(name)` are also available:

```python
client.operations.get_policy_version(path={"policyId": "p1", "v": 3})
client.operations.list_alerts()
for event in client.operations.stream_alerts():   # SSE operations are iterators
    ...
pdf = client.operations.get_evidence_package_pdf(path={"artifactId": artifact_id})   # bytes
```

Parameter mistakes (unknown or missing path/query parameters, a body where none is accepted, unknown headers) raise `ValidationError` before any request. Credentials follow the
contract: operator operations use `api_key`, signing operations `sign_token`, public operations send none. Bodies are plain JSON values; use the typed resources for the main flows.
