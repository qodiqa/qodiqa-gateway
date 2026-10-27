# JavaScript SDK — Examples

All examples below live under
[`sdk/javascript/examples/`](../../../sdk/javascript/examples/) and are
verified against the current SDK source (not hypothetical usage). Build the
SDK once before running any of them:

```bash
cd sdk/javascript
npm install
npm run build
```

## Node.js

### `sdk/javascript/examples/node/basic.js` — full walkthrough (CommonJS)

Exercises, in order: `healthCheck`, `readinessCheck`, `getPublicKeys`,
`sign.sign`, `chat.create`, `verify.verify`, `getAuditChain`,
`transparency.listEntries`, and `portal.verify` + `portal.getResult`.
`getAuditChain` needs `QODIQA_API_KEY` (ops key with `READ_AUDIT`) and returns
the standard envelope, so the example reads the record from `.data`.
Sign/chat steps are skipped automatically if `QODIQA_SIGN_TOKEN` is unset.

```bash
QODIQA_SIGN_TOKEN=your-token \
QODIQA_BASE_URL=http://localhost:3000 \
node sdk/javascript/examples/node/basic.js
```

### `sdk/javascript/examples/node/cli.js` — command-line tool

A dependency-free CLI (custom `parseArgs`, no `yargs`/`commander`) exposing
`health`, `keys`, `sign`, `chat`, `verify`, and `audit` subcommands, with a
`catch` block that discriminates every exported error class
(`AuthenticationError`, `ValidationError`, `RateLimitError`, `TimeoutError`,
`NetworkError`, generic `QodiqaError`).

```bash
node sdk/javascript/examples/node/cli.js health
node sdk/javascript/examples/node/cli.js keys
QODIQA_SIGN_TOKEN=<token> node sdk/javascript/examples/node/cli.js sign --prompt "Hello" --user user_123
QODIQA_SIGN_TOKEN=<token> node sdk/javascript/examples/node/cli.js chat --prompt "Explain quantum computing"
node sdk/javascript/examples/node/cli.js verify --artifact <base64> --prompt "Hello world"
node sdk/javascript/examples/node/cli.js audit --artifact-id art_abc123
```

### `examples/typescript/basic.ts` — typed, full-surface walkthrough

The most complete example: health/readiness, key discovery, sign, chat,
verify, dry-run verify, transparency log, attestation, and certification
evaluation, all with explicit response types imported from `@qodiqa/sdk`.

```bash
npx ts-node examples/typescript/basic.ts
```

### `sdk/javascript/examples/node/verify-artifact-offline.js` — local (offline) artifact verification

Signs an artifact the normal way, then verifies its Ed25519 signature,
canonical JSON, and key validity **entirely locally**, using
`ArtifactVerifier` with two separate `RemoteKeyProvider` instances (one for
artifact-signing keys, one for transparency-signing keys — a real trust-domain
separation, never share one provider between them). No call to `POST /verify`
is made or needed. See [api.md §16](api.md#16-local-artifact--transparency-proof-verification-offline)
for the full result shape and [configuration.md](configuration.md#key-provider-configuration)
for the available key-provider options.

```bash
QODIQA_SIGN_TOKEN=<token> QODIQA_BASE_URL=http://localhost:3000 node sdk/javascript/examples/node/verify-artifact-offline.js
```

## Express

### `sdk/javascript/examples/express/middleware.js` — sign + verify middleware

Two composable middlewares:

- `qodiqaSignMiddleware` — signs the incoming request and attaches
  `req.qodiqaArtifact`, `req.qodiqaArtifactB64`, `req.qodiqaArtifactId`
- `qodiqaVerifyMiddleware` — verifies the attached artifact and returns `403`
  on a `BLOCK` decision before the route handler runs

```bash
npm install express
QODIQA_API_KEY=ok_<64hex> QODIQA_SIGN_TOKEN=<token> node sdk/javascript/examples/express/middleware.js
# GET  /health
# POST /api/chat   { "prompt": "...", "model"?: "..." }
```

### `sdk/javascript/examples/express/webhook.js` — receiving webhooks

Demonstrates two verification styles side by side:

- **Option A**: the `verifyWebhookSignature` free function inside a
  route handler using `express.raw({ type: 'application/json' })` to preserve
  the exact bytes QODIQA signed
- **Option B**: a reusable `WebhookVerifier` instance used as Express
  middleware (`qodiqaWebhookMiddleware`), including a commented-out example of
  constructing it with two secrets for rotation

Both switch on the parsed event's `type` field (`sign.created`, `verify.passed`,
`verify.failed`, `policy.blocked`, `consent.granted`, `consent.revoked`,
`key.rotated`) and return `401` for any of `ExpiredSignatureError`,
`InvalidSignatureError`, `MalformedSignatureError`, `InvalidTimestampError`.

> **Why `express.raw()` matters**: `express.json()` parses and discards the
> exact byte sequence QODIQA signed. HMAC verification recomputes the digest
> over the raw body — if you parse first, verification will fail even for a
> genuine, unmodified delivery.

## Fastify

### `sdk/javascript/examples/fastify/middleware.js` — plugin + pre-handler hooks

A `qodiqaPlugin` Fastify plugin registers two decorators —
`qodiqaSignHook` and `qodiqaVerifyHook` — used as `preHandler` hooks on
`POST /api/chat`, mirroring the Express middleware's sign→verify flow but in
Fastify's hook idiom.

```bash
npm install fastify
QODIQA_SIGN_TOKEN=<token> QODIQA_BASE_URL=http://localhost:3000 node sdk/javascript/examples/fastify/middleware.js
```

### `sdk/javascript/examples/fastify/webhook.js` — receiving webhooks

Fastify does not expose a raw-body option out of the box; this example
registers a custom `addContentTypeParser('application/json', { parseAs: 'buffer' }, ...)`
that stores the raw buffer on `req.rawBody` before JSON-parsing, then verifies
with a shared `WebhookVerifier` instance.

## Next.js (App Router)

### `examples/nextjs/route.ts` — `app/api/ai/chat/route.ts`

Exports `POST` (sign → `chat.create`, mapping `AuthenticationError` to `401`
and any other `QodiqaError` to its `status`) and `GET` (health probe). The
QODIQA client is instantiated once at module scope, reused across invocations
within the same cold start.

### `examples/nextjs/webhook.ts` — `app/api/webhooks/qodiqa/route.ts`

Captures the raw body via `Buffer.from(await request.arrayBuffer())` (App
Router does not run a body parser by default the way Pages Router did), then
calls `verifyWebhookSignature` directly.

## Running the bundled test suite

```bash
cd sdk/javascript
npm test              # jest
npm run test:coverage # jest --coverage
```

Tests live under `sdk/javascript/tests/` and cover the client, HTTP layer,
retry logic, every resource class, and the webhook verifier
(`test/webhook-verifier.test.ts`, `test/resources/*.test.ts`).

## Related

- [api.md](api.md) — full signature reference for every call used above
- [configuration.md](configuration.md) — `QodiqaClientConfig` and the
  `QODIQA_*` environment-variable convention followed by these examples
