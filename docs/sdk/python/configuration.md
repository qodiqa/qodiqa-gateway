# Python SDK — Configuration

Both `QodiqaClient` and `AsyncQodiqaClient` accept the same set of
**keyword-only** constructor arguments
([`sdk/python/qodiqa/client.py`](../../../sdk/python/qodiqa/client.py)). Every
argument is forwarded into an internal, immutable `ClientConfig` dataclass
([`sdk/python/qodiqa/config.py`](../../../sdk/python/qodiqa/config.py)),
validated once in `ClientConfig.__post_init__`, and frozen — `ClientConfig` is
declared `@dataclass(frozen=True)`, so configuration cannot be mutated after
the client is constructed. To change configuration, construct a new client.

## Constructor arguments

| Argument | Type | Default | Description |
|---|---|---|---|
| `api_key` | `Optional[str]` | `None` | Ops API key. Required for every method documented as "ops-protected". Must match `^ok_[0-9a-f]{64}$` when provided. |
| `sign_token` | `Optional[str]` | `None` | Per-identity signing API key (`sk_...`), sent as `Authorization: Bearer <sign_token>`. Required for `client.sign.sign(...)`. |
| `base_url` | `str` | `"http://localhost:3000"` | Base URL of the QODIQA server. Must parse as `http`/`https` with a non-empty network location. |
| `timeout` | `float` | `30.0` | Per-request timeout in **seconds** (note: seconds, not milliseconds — the JS SDK's `timeout` is milliseconds). Must be `> 0`. |
| `max_retries` | `int` | `2` | Max retry attempts for retryable errors (see [Retry policy](api.md#13-retry-policy)). Must be a non-negative integer. |
| `default_headers` | `Optional[dict]` | `{}` | Extra headers merged into every request. |
| `user_agent` | `Optional[str]` | `` f"qodiqa-python/{__version__} python/{sys.version.split()[0]}" `` | Overrides the `User-Agent` header. |
| `verify_ssl` | `bool` | `True` | Whether to verify TLS certificates (passed to `httpx` as `verify=`). |
| `proxy` | `Optional[str]` | `None` | HTTP/HTTPS proxy URL, passed to `httpx.Client`/`httpx.AsyncClient` as `proxy=`. |
| `otp_provider` | `Optional[Callable]` | `None` | Operator MFA step-up. Called only when the server answers `401 MFA_REQUIRED` to a mutation (the OpenAPI marks these `x-qodiqa-mfa-step-up`); the request is resent once with `X-QODIQA-OTP`. Return a fresh TOTP code each call — a code is accepted at most once per 30-second step. Unset: `MfaRequiredError` is raised. |

### Validation rules (`ClientConfig._validate`)

All four rules raise `ValidationError` synchronously, before any HTTP client is
constructed:

| Rule | Failure behavior |
|---|---|
| `base_url` must parse with scheme `http`/`https` and a non-empty `netloc` | `ValidationError`: `Invalid base_url: "…" — must be a valid http or https URL.` |
| `api_key`, when provided, must match `ok_[0-9a-f]{64}` | `ValidationError`: `Invalid api_key: must start with "ok_" followed by exactly 64 hexadecimal characters (total 67 chars).` |
| `timeout` must be `> 0` | `ValidationError`: `timeout must be a positive number (seconds).` |
| `max_retries` must be a non-negative `int` | `ValidationError`: `max_retries must be a non-negative integer.` |

## Example

```python
from qodiqa import QodiqaClient

client = QodiqaClient(
    api_key="ok_" + "a" * 64,
    sign_token="my-sign-token",
    base_url="https://gateway.example.com",
    timeout=15.0,
    max_retries=3,
    default_headers={"x-tenant-id": "my-tenant"},
    user_agent="my-app/1.0.0 (qodiqa-python)",
    verify_ssl=True,
    proxy=None,
)
```

The async client takes the identical keyword arguments:

```python
from qodiqa import AsyncQodiqaClient

client = AsyncQodiqaClient(sign_token="my-sign-token", timeout=15.0)
```

## Environment variables

**The SDK itself does not read any environment variables.** `ClientConfig`
only uses the keyword arguments passed to the client constructor — there is no
implicit `os.environ["QODIQA_API_KEY"]` lookup inside the SDK. Every example
under `sdk/python/examples/` follows the convention of reading `os.environ` in
application code and passing the result into the constructor:

```python
import os
from qodiqa import QodiqaClient

client = QodiqaClient(
    api_key=os.environ.get("QODIQA_API_KEY"),
    sign_token=os.environ.get("QODIQA_SIGN_TOKEN"),
    base_url=os.environ.get("QODIQA_BASE_URL", "http://localhost:3000"),
)
```

The variable names used by convention (`sdk/python/examples/cli.py` and others) are:

| Variable | Maps to | Required for |
|---|---|---|
| `QODIQA_API_KEY` | `api_key` | Ops-protected endpoints (webhooks, admin stats/history, batch certification) |
| `QODIQA_SIGN_TOKEN` | `sign_token` | `client.sign.sign(...)` |
| `QODIQA_BASE_URL` | `base_url` | Overriding the default `http://localhost:3000` |
| `QODIQA_WEBHOOK_SECRET` | `secret` argument to `verify_webhook_signature` / `WebhookVerifier` | Webhook signature verification (unrelated to client configuration) |

## Key provider configuration

Source: [`sdk/python/qodiqa/_verification/_key_providers.py`](../../../sdk/python/qodiqa/_verification/_key_providers.py)

`ArtifactVerifier`/`AsyncArtifactVerifier` (see
[api.md §16](api.md#16-local-artifact--transparency-proof-verification))
are configured separately from `QodiqaClient` — they need a public-key
**trust source**, not server credentials, since their entire point is
verifying signatures without asking the server whether they're valid. Three
implementations are available, each with a sync and (where relevant) async
form:

| Class | Use case | Network access |
|---|---|---|
| `StaticKeyProvider` | Embedded/pinned trust bundle, keys known ahead of time. Usable from both `ArtifactVerifier` and `AsyncArtifactVerifier` since it performs no I/O. | None |
| `RemoteKeyProvider` / `AsyncRemoteKeyProvider` | Fetch from a `/.well-known/qodiqa/keys`-shaped discovery endpoint, with a TTL cache. Use the `Async*` form with `AsyncArtifactVerifier` so key fetches don't block the event loop. | Yes, cached |
| `create_key_provider(fn)` / `create_async_key_provider(fn)` | Fully custom resolution logic (e.g. your own key-management service) | Whatever `fn` does |

```python
from qodiqa import StaticKeyProvider, RemoteKeyProvider, AsyncRemoteKeyProvider, create_key_provider

# Static — no network access at all.
static_keys = StaticKeyProvider([
    {"keyId": "dev-local:key_v1", "publicKey": "<base64 SPKI DER>", "status": "active"},
])

# Remote (sync) — fetches and caches the key list (default TTL 5 minutes).
remote_keys = RemoteKeyProvider(discovery_url="https://api.example.com/.well-known/qodiqa/keys")

# Remote (async) — for use with AsyncArtifactVerifier.
async_remote_keys = AsyncRemoteKeyProvider(discovery_url="https://api.example.com/.well-known/qodiqa/keys")

# Custom — plug in any lookup you like.
from qodiqa import ResolvedKey
import base64

def lookup(key_id: str):
    key = my_key_management_service.lookup(key_id)
    return ResolvedKey(pub_der=base64.b64decode(key.public_key_der), status=key.status) if key else None

custom_keys = create_key_provider(lookup)
```

### Archived-key fallback — long-term verification

`RemoteKeyProvider` / `AsyncRemoteKeyProvider` transparently extend
verification to keys that have since been purged from the live keystore:
when a `key_id` is absent from the live `/.well-known/qodiqa/keys` list (but
the live fetch itself succeeded), they automatically retry against `GET
/.well-known/qodiqa/keys/archived` before giving up. No code change is
required to benefit from this — the `remote_keys` construction above already
does it.

```python
# archived_discovery_url defaults to f"{discovery_url}/archived" whenever
# discovery_url ends with "/qodiqa/keys" — pass it explicitly only if you're
# proxying/renaming the endpoint.
remote_keys_custom = RemoteKeyProvider(
    discovery_url="https://api.example.com/.well-known/qodiqa/keys",
    archived_discovery_url="https://api.example.com/.well-known/qodiqa/keys/archived",
)
```

Key properties:

- **The live lookup is always the fast path.** The archived tier is only ever queried after a *successful* live fetch that doesn't contain the key — a network/HTTP failure on the primary request resolves to `None` immediately, exactly as before this remediation; the fallback is not attempted in that case.
- **Cached independently**, same `cache_ttl_ms` as the live list, so repeated lookups for an already-resolved archived key don't refetch on every call. `refresh()` bypasses both caches.
- **No fallback is derived for `/qodiqa/transparency-keys`** — only the artifact-signing key discovery endpoint has an archived tier.
- Resolved keys carry `status="deprecated"` either way (the wire-only `"archived"` marker the endpoint returns is normalized away) — `ResolvedKey.source` (`"live"` / `"archived"`) is the diagnostic-only field that distinguishes the two, surfaced on `ArtifactVerificationResult.key_source` after a `verify()` call. See [docs/security/key-management.md § Archived Key Verification](../../security/key-management.md#archived-key-verification) for the full server-side design (rate limiting, cache TTL, operational expectations).
- **JS/Python asymmetry:** unlike the JavaScript SDK's `RemoteKeyProvider` (which accepts `archivedDiscoveryUrl: null` to explicitly disable the fallback), `archived_discovery_url` here has **no dedicated "disable" value** — passing `None` means "auto-derive from `discovery_url`," not "off." There is currently no clean way to opt a Python `RemoteKeyProvider`/`AsyncRemoteKeyProvider` out of the fallback short of pointing `discovery_url` at something that doesn't end in `/qodiqa/keys` (so nothing is derived) or supplying an intentionally unreachable `archived_discovery_url`, which still incurs a failed request per miss. If you need parity with the JS SDK's explicit-disable behavior, request it as a follow-up.

### Two separate trust domains — never share a provider between them

`keys` resolves **artifact-signing** keys (`/.well-known/qodiqa/keys`); the
optional `transparency_keys` resolves **transparency-log-signing** keys
(`/.well-known/qodiqa/transparency-keys`). These are genuinely separate key
stores server-side — by design, compromise of one cannot compromise the
other. Pointing both at the same discovery URL or the same static key list
silently defeats that separation. Always configure two distinct provider
instances if you verify transparency proofs.

### Unknown and revoked keys always fail closed

Every `KeyProvider` implementation returns `None` for a `key_id` it does not
recognize, and `ArtifactVerifier` treats both "unknown key" and "key
resolved but its status is not `active`/`deprecated`" as a `KEY_RESOLUTION`
failure — never a silently-selected fallback key.

## Context manager support

Both clients implement the context-manager protocol so the underlying `httpx`
connection pool is always released:

```python
with QodiqaClient(sign_token="...") as client:
    client.health_check()
# client.close() called automatically

async with AsyncQodiqaClient(sign_token="...") as client:
    await client.health_check()
# await client.aclose() called automatically
```

Calling `client.close()` (or `await client.aclose()`) manually is equivalent
and required if you are not using the `with`/`async with` form.

## Next: [api.md](api.md) — full API reference
