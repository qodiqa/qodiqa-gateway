# qodiqa — Official Python SDK

The official Python client for the [QODIQA](https://github.com/qodiqa/qodiqa-gateway) AI enforcement platform.

## Installation

**`qodiqa` is not published to PyPI.** `pip install qodiqa` does not install this SDK on a clean
machine. [Corrected 2026-10-09, this section previously led with `pip install qodiqa`.]
Install from the repository:

```bash
pip install /path/to/qodiqa/sdk/python      # or, for development: pip install -e sdk/python
```

Requires Python ≥ 3.9. Runtime dependencies (`pyproject.toml`): `httpx>=0.25.0` (HTTP) and `cryptography>=41`
(Ed25519, for offline artifact/transparency-proof verification).

The import name is `qodiqa` (`from qodiqa import QodiqaClient`).

**Test status.** The SDK covers a subset of the HTTP API and is tested mostly against
a mock transport. Its `pyproject.toml` classifier is "Development Status :: 4 - Beta" (corrected from
"5 - Production/Stable" on 2026-10-09). The `ttl` in the examples is clamped by the
server to the 60 s maximum artifact age.

## Quick start

```python
import base64, json
from qodiqa import QodiqaClient

client = QodiqaClient(
    api_key="ok_your_ops_key",
    sign_token="your_sign_token",
    base_url="http://localhost:3000",
)

# 1. Sign the outgoing AI request. "provider" is omitted from payload here —
#    /sign auto-resolves it to the single enabled AI provider. With more than
#    one provider configured, pass "payload": {"provider": "openai"}
#    explicitly (400 PROVIDER_REQUIRED otherwise).
signed = client.sign.sign({
    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "Hello"}},
    "payload": {"userId": "user_123"},
    "ttl": 300_000,
})

artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()

# 2. Execute the enforced chat
result = client.chat.create(artifact_b64, {"prompt": "Hello"})

if result["decision"] == "EXECUTE":
    print(result.get("aiText"))

    # Evidence durability: `transparency.persisted` is the only
    # per-decision signal distinguishing a durable-evidence deployment
    # (entry written to PostgreSQL — proofs and signed roots will cover it)
    # from a sign-only one (signed, but nothing survives the process).
    # Production servers refuse to boot sign-only, so assert on it in any
    # evidentiary workflow:
    assert result.get("transparency", {}).get("persisted") is True,         "transparency entry was NOT durably persisted — sign-only deployment"
else:
    print("Blocked:", result.get("reason"))

client.close()
```

## Async support

```python
import asyncio
from qodiqa import AsyncQodiqaClient

async def main():
    async with AsyncQodiqaClient(sign_token="tok") as client:
        health = await client.health_check()
        print(health["status"])

asyncio.run(main())
```

## Streaming

`client.chat.stream(artifact, request)` executes `POST /ai/chat` with
`stream: true` and yields each SSE event as it arrives, instead of waiting for
the full response. `request` must be signed with `stream: True` already
present in its body — the server binds the artifact to the exact request body
it was signed with, so a mismatch fails closed with `REQUEST_MISMATCH`
(`VerificationError`).

```python
signed = client.sign.sign({
    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "Tell me a story", "stream": True}},
    "payload": {"userId": "user_123"},
})
artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()

for event in client.chat.stream(artifact_b64, {"prompt": "Tell me a story", "stream": True}):
    if event["event"] == "chunk_forwarded":
        print(event["delta"], end="", flush=True)
    elif event["event"] == "stream_completed":
        print(f"\n[done — {event['chunksTotal']} chunks, {event['durationMs']}ms]")
    elif event["event"] == "stream_cancelled":
        # reason is one of: "CLIENT_DISCONNECT", "STREAM_TIMEOUT", a provider
        # error code, "SEMANTIC_OUTPUT_BLOCKED", or "SEMANTIC_OUTPUT_BLOCKED_FINAL"
        # — see "Streaming output-safety contract" below for the last two.
        print(f"\n[cancelled: {event['reason']}]")
```

Breaking out of the `for` loop early, or calling `.close()` on the returned
generator, stops consumption and releases the connection. There is no
client-side timeout unless you pass one explicitly (`timeout=30.0`, seconds)
— the server itself bounds a session at `STREAM_MAX_DURATION_MS` (default 5
minutes).

Async version — `client.chat.stream(...)` is not itself awaited, only
iterating it is:

```python
async with AsyncQodiqaClient(sign_token="tok") as client:
    async for event in client.chat.stream(artifact_b64, {"prompt": "Tell me a story", "stream": True}):
        if event["event"] == "chunk_forwarded":
            print(event["delta"], end="", flush=True)
```

Every error `stream()` can raise is a `QodiqaError` subclass: `ValidationError`
(empty `artifact`/`prompt`, raised immediately, not on first iteration),
`AuthenticationError`/`VerificationError` (pre-stream enforcement failure),
`ServerError` (malformed SSE frame), `TimeoutError` (`timeout` exceeded), or
`NetworkError` (dropped connection). See `examples/streaming.py` for the full
runnable version, including error handling.

### Streaming output-safety contract

`client.chat.create()` (non-streaming) classifies the AI provider's complete
response before returning it — a `BLOCK` decision means you never receive
the text at all. `client.chat.stream()` forwards each chunk incrementally as
it clears a bounded output check, and runs one more, mandatory check over
the full accumulated response after the stream would otherwise finish
normally. If *that* check is what denies the response, you will have
**already received every `chunk_forwarded` event** — the only signal is the
terminal event changing from `stream_completed` to `stream_cancelled` with
`reason == "SEMANTIC_OUTPUT_BLOCKED_FINAL"`. This is intentional: once a
chunk has been written to the SSE connection there is no protocol-level way
to retract it, so the server's audit record is corrected instead
(audit-truth over content-suppression). If your integration needs a hard
guarantee that denied content never reaches you, use `client.chat.create()`
instead of `client.chat.stream()`. Full mechanics:
,
 (in the main QODIQA
repository).

## Configuration

```python
from qodiqa import QodiqaClient

client = QodiqaClient(
    api_key="ok_...",          # Ops API key (required for ops endpoints)
    sign_token="...",           # Sign token (required for POST /sign)
    base_url="https://gateway.example.com",
    timeout=30.0,               # Request timeout in seconds
    max_retries=2,              # GET/PUT/DELETE on 429/5xx; POST/PATCH only on 429 (never /ai/chat); SERVER_OVERLOADED always
    default_headers={"x-tenant-id": "my-tenant"},  # Merged into every request
    user_agent="my-app/1.0.0 (qodiqa-python)",     # Override User-Agent
    verify_ssl=True,            # Verify TLS certificates
    proxy=None,                 # Optional HTTP/HTTPS proxy URL
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str \| None` | `None` | Ops API key (`ok_…` prefix, 64-char suffix) |
| `sign_token` | `str \| None` | `None` | Sign token for `/sign` endpoint |
| `base_url` | `str` | `http://localhost:3000` | API base URL |
| `timeout` | `float` | `30.0` | Per-request timeout (seconds) |
| `max_retries` | `int` | `2` | Max retries on retryable errors |
| `default_headers` | `dict \| None` | `{}` | Extra headers merged into every request |
| `user_agent` | `str \| None` | `qodiqa-python/{version} python/{version}` | Override the `User-Agent` header |
| `verify_ssl` | `bool` | `True` | Verify TLS certificates |
| `proxy` | `str \| None` | `None` | HTTP/HTTPS proxy URL passed to `httpx` |

All fields are validated once, at construction time, by the immutable `ClientConfig`
dataclass: `base_url` must be a valid `http`/`https` URL, `api_key` (when provided)
must match `ok_[0-9a-f]{64}`, `timeout` must be positive, and `max_retries` must be
a non-negative integer. Any violation raises `ValidationError` immediately.

**Retry policy.** A request is resent only when that is safe: `503 SERVER_OVERLOADED` (admission control, refused
before processing) on every method; `GET`/`PUT`/`DELETE` on `429`/`500`/`502`/`503`/`504`; `POST`/`PATCH` only on
`429` and never on `/ai/chat` (the artifact nonce may already be consumed). Never retried: timeouts, `MFA_LOCKED`,
other `4xx`, and any request carrying an MFA code (`X-QODIQA-OTP`) — a TOTP code is accepted once per step, so a
resend would fail as `MFA_INVALID` and count toward the MFA lockout. A server `Retry-After` (delta-seconds or
HTTP-date, on a `429` or a `503` such as `SERVER_OVERLOADED`) replaces the jittered back-off and is never shortened:
above 30 s the error is raised instead of retrying early. `chat.stream()` resends only a pre-stream
`503 SERVER_OVERLOADED`; a stream whose body ends without the terminal `[DONE]` frame raises `NetworkError`
(truncated — the events already yielded are partial).

**Exactly-once chat retries.** `client.chat.create(artifact, request, idempotency_key="...")` sends the
`Idempotency-Key` header: after an outcome-unknown failure (e.g. a 504), retry
with a freshly signed artifact and the same key, and the server replays the original result instead of executing
twice. `chat.stream()` does not accept a key (the server rejects that combination).

## Resources

All resources are available as properties on `QodiqaClient` / `AsyncQodiqaClient`:

| Resource | Property | Description |
|----------|----------|-------------|
| Sign | `client.sign` | Issue signed artifacts |
| Chat | `client.chat` | Execute enforced AI prompts |
| Verify | `client.verify` | Verify artifacts |
| Portal | `client.portal` | Verification portal (see note below) |
| Attestation | `client.attestation` | Attestation records |
| Transparency | `client.transparency` | Transparency log |
| Evidence | `client.evidence` | Evidence packages |
| Certification | `client.certification` | Certification evaluation |
| Webhooks | `client.webhooks` | Webhook management |
| Simulation | `client.simulation` | Read-only policy dry-run evaluation |
| Agents / sessions | `client.agents`, `client.sessions` | Agent identities and sessions (operator key + MFA step-up) |
| Actions | `client.actions` | Per-action authorisation (`authorize`, `authorize_and_wait`, plans, approval status) |
| Tools | `client.tools` | The tool gateway: run ONE authorised action, get the screened result |
| Delegations | `client.delegations` | Delegation of authority between agents |
| Tool registry / MCP servers | `client.tool_registry`, `client.mcp_servers` | What an agent may call (operator key + MFA step-up) |
| Approvals | `client.approvals` | Human approval of agent actions, the operator's side |

**Agents (protocol V2).** An agent registered with a public key signs a proof of possession for every request
(`sign_agent_proof`, `generate_agent_key_pair`); a tool that needs a human approval makes `actions.authorize()` return a
pending object (`is_approval_pending`) - `authorize_and_wait()` waits for it. The result of `tools.call()` is untrusted data:
put `result["delimited"]` between your instructions and the data.

```python
from qodiqa import QodiqaClient, sign_agent_proof

client = QodiqaClient(base_url=URL, api_key=OPS_KEY, sign_token=SIGN_KEY, otp_provider=get_otp)
ctx = {"tenantId": T, "agentId": A, "sessionId": S, "requestId": REQ}
auth = client.actions.authorize_and_wait({"agentId": A, "sessionId": S, "requestId": REQ, "proof": sign_agent_proof(ctx, key),
                                          "tool": {"server": "files", "name": "read"}, "args": {"path": "/a"}})
out = client.tools.call({"artifact": auth["artifact"], "tool": {"server": "files", "name": "read"}, "args": {"path": "/a"}})
```

**Portal** (`client.portal`) is the public verification portal — a **synchronous**,
unauthenticated (rate-limited only) service that runs QODIQA's full artifact-verification
check suite and returns a complete report in one call. It answers a different question
than `client.verify.verify()`: `verify()` simulates whether a signed artifact would
currently pass enforcement; `portal.verify()` independently re-validates an artifact's
cryptographic/structural integrity — signature, key resolution, timestamps, replay
history — useful for third-party auditors or a caller who wants to check an artifact
without holding a signing key of their own.

```python
result = client.portal.verify(signed_artifact)  # POST /v1/portal/verify — request body
                                                  # IS the raw artifact, not wrapped

print(result["data"]["verificationId"])   # UUID — save this for get_result() later
print(result["data"]["overallResult"])    # "VERIFIED" | "VERIFIED_WITH_WARNINGS" | "FAILED"
print(result["data"]["checks"])           # [{"check", "result": "PASS"|"FAIL"|"WARN"|"SKIP", "reason"?}]

# get_result() requires PostgreSQL to be enabled server-side (Postgres-only
# history store) -- 404s (NotFoundError) if PostgreSQL was disabled at
# verify() time or is disabled now, even for this exact verification_id.
record = client.portal.get_result(result["data"]["verificationId"])
print(record["data"]["verification"]["overall_result"])  # note: snake_case -- a raw
                                                           # PostgreSQL row, unlike
                                                           # verify()'s camelCase report
```

> **Not (yet) exposed:** the server also has real `GET /v1/portal/report/:id` (a
> camelCase-mapped report view, with an optional `?format=pdf`) and
> `GET /v1/portal/evidence/:id` (an evidence package) routes — out of scope for this
> resource's current rewrite. Re-examined 2026-08-15 and confirmed still
> intentionally deferred: a post-launch SDK expansion candidate, not
> pre-launch scope. The report route is callable directly today;
> the evidence package is internal audit data (it embeds the submitter address in its
> hashed content) and requires an operator API key with `READ_VERIFICATION_PORTAL`.
> `getResult()`/`get_result()` records no longer include `submission_ip`.

### Verify

```python
result = client.verify.verify(artifact_b64, {
    "artifact": signed["artifact"],
    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hi"}},
})
print(result["decision"], result["reason"])  # "EXECUTE" | "BLOCK", ...

# dry_run() sends exactly the same wire request as verify(): the /verify route
# reads the artifact only from the body, and neither method sends an
# x-qodiqa-artifact header. verify() keeps its artifact_b64 argument only for
# call-site compatibility (it is validated, not transmitted).
result = client.verify.dry_run({
    "artifact": signed["artifact"],
    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hi"}},
})
```

The Python SDK has no `verify_v2()` (`POST /verify/v2`, the same handler under a higher rate-limit bucket) — a
recorded parity gap with the JS SDK's `verifyV2()`.

Both `verify()` and `dry_run()` run the full six-step dry-run pipeline server-side: no
nonce is registered, no anomaly counter incremented, no audit record written, no AI
provider contacted.

**Semantic parity:** step 6 runs the same Semantic Policy Engine
`/ai/chat` runs on the request `prompt` — a `result["decision"] == "BLOCK"` here can now be
a content-match reason (e.g. `"SECURITY_OVERRIDE_ATTEMPT"`, `"PII_EXTRACTION"`; see the
[main API reference](../../docs/api/overview.md#semantic-policy-engine) for the full code
table), with `result["details"]["semantic"]` carrying the same evidence shape `/ai/chat`'s
audit trail records for the identical verdict. Side-effect-free (no audit write, no
transparency entry, no consent consumption, no provider call) and only runs when
`request["request"]["body"]["prompt"]` is a non-empty string — an artifact bound to a
non-`/ai/chat` endpoint (`request.path` can be anything the artifact was signed for) skips
it entirely, matching the fact that `/ai/chat` itself would never reach that stage for such
a request either.

### Simulation (policy dry-run)

`client.simulation` runs read-only policy evaluations: no nonce is registered, no
anomaly counter is incremented, no audit record is written, and no AI provider is
contacted. Every response includes `executionPrevented: True`.

```python
# Single simulation against the live (or a provided draft) policy set
result = client.simulation.simulate({
    "context": {"userId": "my-key:key_v1", "action": "openai", "ip": "192.168.1.1"},
})
print(result["data"]["decision"])            # "EXECUTE" or "BLOCK"
print(result["data"]["executionPrevented"])  # True

# Compare current vs. proposed policies against the same context
comparison = client.simulation.compare({
    "context": {"userId": "my-key:key_v1", "action": "openai"},
    "proposedPolicies": [
        {"id": "rl-1", "type": "RATE_LIMIT", "priority": 10, "enabled": True, "config": {"max": 100}},
    ],
})
print(comparison["data"]["decisionChanged"])

# Batch up to 100 simulations concurrently
batch = client.simulation.batch({
    "simulations": [
        {"context": {"userId": "a", "action": "openai"}},
        {"context": {"userId": "b", "action": "anthropic"}},
    ],
})
print(batch["data"]["total"], batch["data"]["allowed"], batch["data"]["blocked"])
```

An `AsyncSimulationResource` with identical async methods is available on
`AsyncQodiqaClient.simulation`.

### Convenience methods

```python
health   = client.health_check()
ready    = client.readiness_check()
keys     = client.get_public_keys()
key      = client.get_public_key("key-id")
chain    = client.get_audit_chain("artifact-id")  # requires an ops api_key; returns the envelope:
print(chain["data"]["decision"], len(chain["data"]["chain"]))  # the audit record is chain["data"]
```

## Error handling

All SDK errors inherit from `qodiqa.exceptions.QodiqaError`:

```python
from qodiqa.exceptions import (
    AuthenticationError,   # 401
    AuthorizationError,    # 403
    ValidationError,       # 400
    VerificationError,     # Cryptographic / policy failures
    NotFoundError,         # 404
    RateLimitError,        # 429
    ServerError,           # 5xx
    NetworkError,          # Connection failure
    TimeoutError,          # Request timeout
)

try:
    result = client.verify.verify(artifact_b64, request)
except VerificationError as exc:
    print("Signature invalid:", exc.message)
except RateLimitError as exc:
    print(f"Rate limited. Retry after {exc.retry_after}s")
except QodiqaError as exc:
    print(f"Error [{exc.status}]: {exc.message} (request_id={exc.request_id})")
```

> Note: `client.verify.verify()` / `dry_run()` do **not** raise
> `VerificationError` for a cryptographic failure — `/verify` answers it as a
> normal `200` with `result["decision"] == "BLOCK"`; check `result["reason"]`.
> `client.chat.create()` and `client.chat.stream()` **do** raise
> `VerificationError` for every artifact-rejection reason in
> `VERIFICATION_REASONS` (invalid signature, expired, replayed, request
> mismatch, missing artifact, …), at any HTTP status — including the 200
> `decision: "BLOCK"` body of the server's default mode (/ API-02;
> between 2026-08-14, and `create()` returned these as a value —
> no longer). Any *other* BLOCK (policy, consent, semantic, …) is returned by
> `create()` as `decision == "BLOCK"` and raised by `stream()` as
> `BlockedError` when it is decided before the stream opens (in the server's
> opt-in `status` mode it arrives as 403/429/503 and maps by status class).

The package also exports `SigningError`, `SerializationError`, and `CryptoKeyError`
(carried over from a prior, local-signing version of this SDK). No HTTP-client
operation in the current SDK raises them. `SigningError` and `CryptoKeyError` are
kept purely for import compatibility, reserved for future local artifact-signing
support — but `SerializationError` is *not* future-only: its subclass
`CanonicalizationError` is actively raised today by the offline
`ArtifactVerifier`/`verify_artifact()` canonicalization routine (`stable_stringify()`),
a currently-shipped feature, not a future one.

[Webhook signature verification](#webhook-signature-verification) raises its own
subset of `QodiqaError`: `InvalidSignatureError`, `ExpiredSignatureError`,
`MalformedSignatureError`, and `InvalidTimestampError`.

## Pagination

`PageIterator` and `PagePage` expect the fetcher to return the raw
`PaginatedResponse`-shaped dict (`entries` / `hasNextPage` — matching
`transparency.list_entries()`; some other list endpoints use a differently-named
array under their own response, e.g. `webhooks.list()` -> `endpoints`,
`certification.list()` -> `certifications`, and aren't compatible with these
generic iterators without a wrapper fetcher that renames the key), so unwrap the
`data` field of the `ApiResponse` envelope that resource methods return:

```python
from qodiqa._pagination import PageIterator

items = PageIterator(
    lambda page, size: client.transparency.list_entries({"page": page, "pageSize": size})["data"],
    page_size=50,
)
for entry in items:
    print(entry["id"])
```

Async version:

```python
from qodiqa._pagination import AsyncPageIterator

async for entry in AsyncPageIterator(
    lambda page, size: client.transparency.list_entries({"page": page, "pageSize": size})["data"],
    page_size=50,
):
    print(entry["id"])
```

## Webhook signature verification

QODIQA signs each webhook delivery with HMAC-SHA256, sent in the
`X-QODIQA-Signature` header as `sha256=<hex_hmac>`, with the delivery
timestamp sent *separately* in its own `X-QODIQA-Timestamp` header (an
ISO-8601 UTC value, e.g. `2026-01-01T00:00:00.000Z`). The HMAC covers
`<raw_X-QODIQA-Timestamp_header_value> + "." + <raw_request_body>` — always
verify against the **raw** bytes as received, never a re-serialized JSON
string, and pass the timestamp through exactly as received.

```python
from qodiqa import verify_webhook_signature, WebhookVerifier
from qodiqa.exceptions import (
    InvalidSignatureError,
    ExpiredSignatureError,
    MalformedSignatureError,
    InvalidTimestampError,
)

# Convenience function
verify_webhook_signature(
    body=request.body,
    signature=request.headers["X-QODIQA-Signature"],
    timestamp=request.headers["X-QODIQA-Timestamp"],
    secret=WEBHOOK_SECRET,
)

# Reusable verifier (preferred when verifying multiple endpoints)
verifier = WebhookVerifier(WEBHOOK_SECRET)
verifier.verify(
    body=request.body,
    signature=request.headers["X-QODIQA-Signature"],
    timestamp=request.headers["X-QODIQA-Timestamp"],
)

# Secret rotation — verification succeeds if ANY secret matches
rotating_verifier = WebhookVerifier([NEW_WEBHOOK_SECRET, OLD_WEBHOOK_SECRET])
```

Both raise `MalformedSignatureError` (signature header unparseable or missing a
`sha256=` component), `InvalidTimestampError` (`X-QODIQA-Timestamp` missing or not
a valid ISO-8601 UTC timestamp), `ExpiredSignatureError` (timestamp outside
`tolerance`, default `DEFAULT_TOLERANCE_SECONDS` = 300s), or
`InvalidSignatureError` (no secret produces a matching HMAC, compared with
`hmac.compare_digest`). See `examples/fastapi_webhook.py`, `examples/flask_webhook.py`,
and `examples/django_webhook.py` for framework-specific raw-body capture.

## Context manager

Both sync and async clients support the context manager protocol:

```python
with QodiqaClient() as client:
    client.health_check()

async with AsyncQodiqaClient() as client:
    await client.health_check()
```

## Examples

| File | Description |
|------|-------------|
| `examples/basic_client.py` | Synchronous sign → chat flow |
| `examples/async_client.py` | Async sign → chat → transparency |
| `examples/streaming.py` | Sync and async SSE streaming via `chat.stream()`, with cancellation and error handling |
| `examples/fastapi_integration.py` | FastAPI middleware with lifespan |
| `examples/flask_integration.py` | Flask decorator-based enforcement |
| `examples/cli.py` | CLI tool for all major operations |
| `examples/fastapi_webhook.py` | FastAPI webhook signature verification |
| `examples/flask_webhook.py` | Flask webhook signature verification |
| `examples/django_webhook.py` | Django webhook signature verification |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

Apache-2.0

## Protecting an existing app: the artifact guard

```python
# FastAPI / Starlette (ASGI)
from qodiqa import RemoteKeyProvider
from qodiqa.middleware.fastapi import QodiqaArtifactMiddleware
app.add_middleware(QodiqaArtifactMiddleware, keys=RemoteKeyProvider(discovery_url="https://gateway.example.com/.well-known/qodiqa/keys"), protect=["/protected"])
# request.scope["qodiqa"]["payload"] in the endpoint

# Django: MIDDLEWARE += ["qodiqa.middleware.django.QodiqaArtifactMiddleware"];  QODIQA_GUARD = {"KEYS": ..., "PROTECT": ["/protected/"]}
# request.qodiqa["payload"] in the view
```

A request passes only with an `x-qodiqa-artifact` header (base64 JSON) that verifies offline and is bound to **this** request: `payload.requestHash` must equal `request_hash(method, path, body)` (V1: path without query,
parsed JSON body, `{}` when none). Missing/invalid artifact: 401; valid artifact for another request: 403 `QODIQA_REQUEST_MISMATCH`. The guard does not consume the artifact's nonce (replay protection is the gateway's,
`POST /verify`, or pass `replay_guard`). V1 binding only.

**Known limits of the guard:**

- **Replay is open by default.** The same valid artifact passes any number of times, and a long-lived artifact stays valid until it expires. For anything that must be single-use, pass the replay hook, or call the gateway (`POST /verify`).
- **The key is not tied to a tenant.** The guard checks that the signing key is in your trust bundle and active, and reports `payload.tenantId`; it does not check that the key belongs to that tenant. Put only the keys you trust for the protected routes in the bundle, and check the reported tenant yourself if the bundle mixes tenants.
- **The query string is not part of the binding** (V1 binds method, path and body). Do not authorise on query parameters.
- **Path matching is literal.** `protect`/`exclude` prefixes are case-sensitive and not normalised; if a proxy or the framework case-folds or resolves dot segments after the guard, route and guard can disagree. Normalise before the guard or protect with a prefix that the framework matches exactly.
- **Bodies with non-integer numbers cannot be bound.** The Python request hash refuses decimals (and numbers above 2^53 are hashed exactly, where JavaScript rounds), so a JavaScript-signed artifact for a body such as `{"temperature":0.7}` is refused with 403 `QODIQA_REQUEST_MISMATCH` by the Python guard. Real QODIQA payloads carry strings, integers and booleans.

