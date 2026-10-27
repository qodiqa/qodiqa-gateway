# QODIQA Python SDK

Developer documentation for `qodiqa`, the official Python client for the
[QODIQA](../../../README.md) AI enforcement platform.

This documentation set is generated from and verified against the SDK source
at [`sdk/python/qodiqa`](../../../sdk/python/qodiqa). Every method, type, and
default described here exists in that source tree.

For the package's own quick-reference README (installation, quick start,
resource examples, error handling, pagination), see
[`sdk/python/README.md`](../../../sdk/python/README.md). This documentation set
expands on that README with a full audit trail: every exported symbol, every
configuration default, and every example verified against the implementation.

## Contents

| Document | Covers |
|---|---|
| [installation.md](installation.md) | Supported Python versions, pip install, dependencies, dev setup |
| [configuration.md](configuration.md) | Every `ClientConfig` field, defaults, validation rules, environment-variable conventions |
| [api.md](api.md) | Full reference for `QodiqaClient`/`AsyncQodiqaClient`, every resource, the exception hierarchy, retry, pagination, webhook verification, and local (offline) artifact/transparency-proof verification |
| [examples.md](examples.md) | Walkthroughs of every file under `sdk/python/examples/` |

## What this SDK is

`qodiqa` is an HTTP client (built on `httpx`) for the QODIQA server's public
and ops-protected REST API. Like the JavaScript SDK, it performs no local
Ed25519 **signing** or artifact construction — those still happen
server-side in QODIQA's
[enforcement pipeline](../../architecture/overview.md#enforcement-pipeline-post-aichat).
**Verifying** a signed artifact, however, is now available fully offline —
see point 5. The SDK:

1. Calls `POST /sign` to obtain a signed
   [artifact](../../glossary.md) for a given request.
2. Attaches that artifact to enforced calls: `POST /ai/chat` (`chat.create()` /
   `chat.stream()`) sends it in the `x-qodiqa-artifact` header; `POST /verify`
   (`verify.verify()` / `dry_run()`) sends it only in the request body's
   `artifact` field — the `/verify` route reads the body and ignores the
   header, so no header is sent
   ([`resources/verify.py`](../../../sdk/python/qodiqa/resources/verify.py)).
3. Wraps every other documented QODIQA HTTP endpoint (attestation,
   transparency, certification, evidence, webhooks, policy simulation) in a
   typed method (`TypedDict` responses) with client-side validation and a
   mapped exception hierarchy.
4. Verifies inbound webhook deliveries using constant-time HMAC comparison
   (`hmac.compare_digest`).
5. **Verifies a signed artifact's Ed25519 signature, canonical JSON, key
   validity, and transparency-log inclusion proof entirely offline**, via
   `ArtifactVerifier`/`AsyncArtifactVerifier`/`verify_artifact()` — no
   network call to the server's `/verify` endpoint is required or used
   internally. See [api.md §16](api.md#16-local-artifact--transparency-proof-verification).

Both a synchronous client (`QodiqaClient`, built on `httpx.Client`) and an
asynchronous client (`AsyncQodiqaClient`, built on `httpx.AsyncClient`) are
provided with an identical resource surface.

Architecture terms used throughout this documentation (artifact, decision,
enforcement pipeline, policy hash, transparency log, attestation, certificate)
are defined once, canonically, in [`docs/glossary.md`](../../glossary.md) and are
used with the same meaning here.

## Package facts

Verified against [`sdk/python/pyproject.toml`](../../../sdk/python/pyproject.toml)
and [`sdk/python/qodiqa/_version.py`](../../../sdk/python/qodiqa/_version.py):

| Fact | Value |
|---|---|
| Distribution name | `qodiqa` |
| Version | `1.0.0` (`pyproject.toml` `version`, `qodiqa/_version.py` `__version__`) |
| Supported Python | `>=3.9` (tested/classified through 3.13) |
| Runtime dependencies | `httpx>=0.25.0`; `cryptography>=41` (Ed25519 verification for local artifact/transparency-proof verification) |
| Typed | Yes — ships `py.typed`; `mypy --strict` clean |
| License | Apache-2.0 |

## Minimal working example

```python
import base64, json
from qodiqa import QodiqaClient

client = QodiqaClient(
    sign_token="your-sign-token",
    base_url="http://localhost:3000",
)

# "provider" is omitted from payload — /sign auto-resolves it to the single
# enabled AI provider (400 PROVIDER_REQUIRED if zero or more than one are enabled).
signed = client.sign.sign({
    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "Hello"}},
    "payload": {"userId": "user_123"},
    "ttl": 60_000,  # the server clamps any larger ttl to 60 s
})

artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
chat = client.chat.create(artifact_b64, {"prompt": "Hello"})

print(chat["aiText"] if chat["decision"] == "EXECUTE" else chat["reason"])
client.close()
```

See [api.md](api.md) for the full signature and behavior of every call used above.

## Cross-references

- [`README.md`](../../../README.md) — platform overview, enforcement pipeline, provider architecture
- [`docs/architecture/overview.md`](../../architecture/overview.md) — execution flow the SDK's `sign` → `chat`/`verify` calls trigger server-side
- [`docs/glossary.md`](../../glossary.md) — canonical definitions for Artifact, Decision, Policy, Consent, Transparency Log, Attestation, Certificate
- [`docs/api/overview.md`](../../api/overview.md) — the raw HTTP endpoints this SDK wraps
- the protocol specification (`docs/protocol/QODIQA-PROTOCOL.md`) — artifact envelope format, canonicalization, and domain-separated hashing referenced by the `Artifact` type
- [JavaScript SDK documentation](../javascript/README.md) — equivalent client for JavaScript/TypeScript
