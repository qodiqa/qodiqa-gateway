# Python SDK — Examples

All examples below live under
[`sdk/python/examples/`](../../../sdk/python/examples/) and are verified
against the current SDK source.

```bash
cd sdk/python
pip install -e ".[dev]"
```

## Core usage

### `sdk/python/examples/basic_client.py` — synchronous sign → chat

Constructs a `QodiqaClient`, runs `health_check()`, `sign.sign(...)`, then
`chat.create(...)`, discriminating `VerificationError` from the generic
`QodiqaError`, and closes the client in a `finally` block.

```bash
python sdk/python/examples/basic_client.py
```

### `sdk/python/examples/async_client.py` — async sign → chat → transparency

Uses `async with AsyncQodiqaClient(...) as client:` for automatic cleanup,
then awaits `health_check()`, `sign.sign(...)`, `chat.create(...)`, and
`transparency.list_entries(...)`.

```bash
python sdk/python/examples/async_client.py
```

### `sdk/python/examples/streaming.py` — SSE streaming via `chat.stream()`

Signs a request with `stream: True` in the body, then consumes
`client.chat.stream(...)` — synchronously by default, or with `--async` for
the `AsyncQodiqaClient` version. Demonstrates incremental token printing,
`Ctrl+C` cancellation (closes the generator from a `SIGINT` handler), and
discriminates `VerificationError` (body/signature mismatch), `TimeoutError`,
and the generic `QodiqaError`. See [api.md §3](api.md#3-chat--chatresource)
for the full event-shape reference.

```bash
QODIQA_SIGN_TOKEN=<token> python sdk/python/examples/streaming.py
QODIQA_SIGN_TOKEN=<token> python sdk/python/examples/streaming.py --async
```

### `sdk/python/examples/verify_artifact_offline.py` — local (offline) artifact verification

Signs an artifact the normal way, then verifies its Ed25519 signature,
canonical JSON, and key validity **entirely locally**, using
`ArtifactVerifier` with two separate `RemoteKeyProvider` instances (one for
artifact-signing keys, one for transparency-signing keys — a real trust-domain
separation, never share one provider between them). No call to `POST /verify`
is made or needed. See [api.md §16](api.md#16-local-artifact--transparency-proof-verification)
for the full result shape and [configuration.md](configuration.md#key-provider-configuration)
for the available key-provider options.

```bash
QODIQA_SIGN_TOKEN=<token> QODIQA_BASE_URL=http://localhost:3000 python sdk/python/examples/verify_artifact_offline.py
```

### `sdk/python/examples/cli.py` — command-line tool

Built on `argparse` with subcommands `health`, `keys`, `sign`, `chat`,
`verify`, `audit`; reads `QODIQA_API_KEY`, `QODIQA_SIGN_TOKEN`, and
`QODIQA_BASE_URL` from the environment; maps `VerificationError` to exit code
`2`, `RateLimitError` to exit code `3`, and any other `QodiqaError` to exit
code `1`.

```bash
python sdk/python/examples/cli.py health
python sdk/python/examples/cli.py sign --path /ai/chat --user user_123
python sdk/python/examples/cli.py chat --artifact <b64> --prompt "Hello"
python sdk/python/examples/cli.py verify --artifact <b64> --path /ai/chat
python sdk/python/examples/cli.py audit --id art_abc123
```

## Web framework integration

### `sdk/python/examples/fastapi_integration.py` — request signing + enforcement

Uses FastAPI's `lifespan` context manager to construct one shared
`AsyncQodiqaClient` for the app's lifetime and a `Depends(get_client)`
provider. Routes: `GET /health`, `POST /sign` (maps `AuthenticationError` →
401), `POST /chat` (maps `VerificationError` → 403), `POST /verify`.

```bash
pip install fastapi uvicorn
python sdk/python/examples/fastapi_integration.py
```

### `sdk/python/examples/flask_integration.py` — synchronous signing + enforcement

Lazily constructs a per-request-context `QodiqaClient` stored on Flask's `g`
object, closed in a `teardown_appcontext` handler. Includes a
`require_artifact` decorator that verifies an `Authorization: Artifact
<base64>` header before allowing the decorated view to run.

```bash
pip install flask
python sdk/python/examples/flask_integration.py
```

## Webhook receivers

Each of the following demonstrates the framework-specific technique for
capturing the **raw** request body — required because HMAC verification must
be computed over the exact bytes QODIQA sent, not a re-serialized JSON string.

### `sdk/python/examples/fastapi_webhook.py`

Two options: a reusable `WebhookVerifier` instance (preferred), and the
`verify_webhook_signature` free function. Both read `await request.body()`
strictly before `json.loads(...)`, and map `ExpiredSignatureError`,
`InvalidSignatureError`, `MalformedSignatureError`, `InvalidTimestampError` to
HTTP 401 via `HTTPException`.

```bash
pip install fastapi uvicorn
python sdk/python/examples/fastapi_webhook.py
```

### `sdk/python/examples/flask_webhook.py`

Uses `request.get_data()` for the raw bytes (safe to call before
`get_json()`, since Flask caches the body), verified with a module-level
`WebhookVerifier`.

```bash
pip install flask
python sdk/python/examples/flask_webhook.py
```

### `sdk/python/examples/django_webhook.py`

A `@csrf_exempt @require_POST` view function using `request.body` (cached by
Django on first access — do **not** call `request.POST` beforehand, as that
consumes the stream). Includes wiring instructions for `urls.py`.

## Running the bundled test suite

```bash
cd sdk/python
pip install -e ".[dev]"
python -m pytest
```

`asyncio_mode = "auto"` is set in `pyproject.toml`, so async test functions
run without an explicit `@pytest.mark.asyncio` decorator. Tests live under
`sdk/python/tests/`, covering the client, HTTP layer, config, auth, exceptions,
pagination, webhook verifier, and every resource (`test/resources/`).

## Related

- [api.md](api.md) — full signature reference for every call used above
- [configuration.md](configuration.md) — `ClientConfig` fields and the
  `QODIQA_*` environment-variable convention followed by these examples
