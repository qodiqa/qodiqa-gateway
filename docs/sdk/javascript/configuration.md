# JavaScript SDK — Configuration

All configuration is passed to the `QodiqaClient` constructor as a single
`QodiqaClientConfig` object. Configuration is resolved and validated exactly
once, at construction time, by
[`resolveConfig`](../../../sdk/javascript/src/config.ts) and
[`validateConfig`](../../../sdk/javascript/src/config.ts). There is no mutable
configuration state after construction — a client's `baseUrl`, `timeout`, etc.
cannot be changed later; construct a new client instead.

## `QodiqaClientConfig`

Source: [`sdk/javascript/src/config.ts`](../../../sdk/javascript/src/config.ts)

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | `string \| undefined` | `undefined` | Ops API key. Required for every method documented as "ops-protected" (webhooks, admin stats/history, batch certification). Must match `^ok_[0-9a-f]{64}$` (`ok_` + 64 lowercase hex chars, 67 characters total). |
| `signToken` | `string \| undefined` | `undefined` | Per-identity signing API key (`sk_...`), sent as `Authorization: Bearer <signToken>`. Required to call `client.sign.sign(...)`. No format is validated client-side — the server rejects invalid tokens with `AuthenticationError`. |
| `baseUrl` | `string` | `'http://localhost:3000'` | Base URL of the QODIQA server. Must be a syntactically valid `http:` or `https:` URL (checked by `isValidUrl`, which parses with the WHATWG `URL` constructor). |
| `timeout` | `number` | `30_000` | Per-request timeout in **milliseconds**, enforced via `AbortController`. For a JSON call it is one overall budget covering the call, its automatic retries and their back-off waits; a retry whose wait (including a server `Retry-After`) would end after the budget is not attempted and the real error is thrown instead of a `TimeoutError`. Not applied to `chat.stream()` unless passed per call. Must be `> 0`. |
| `maxRetries` | `number` | `2` | Maximum retry attempts for retryable errors (see [Retry policy](api.md#13-retry-policy)). Must be a non-negative integer. Set to `0` to disable retries entirely. |
| `defaultHeaders` | `Record<string, string>` | `{}` | Extra headers merged into every request, after the SDK's own headers (`Content-Type`, `Accept`, `User-Agent`) but before any per-call headers such as the artifact or auth header. |
| `userAgent` | `string` | `` '@qodiqa/sdk/1.0.0 node/' + process.version `` (`DEFAULT_USER_AGENT`, `src/config.ts`) | Overrides the `User-Agent` header sent on every request. |
| `otpProvider` | `() => string \| Promise<string>` | `undefined` | Operator MFA step-up. Called only when the server answers `401 MFA_REQUIRED` to a mutation (webhooks, admin, RBAC, keys, …; the OpenAPI marks these `x-qodiqa-mfa-step-up`); the request is resent once with `X-QODIQA-OTP`, as a fresh request with its own `timeout` (the wait for `otpProvider()` is not charged against the first request), and a request carrying `X-QODIQA-OTP` is never auto-retried. Return a fresh TOTP code each call — a code is accepted at most once per 30-second step. Unset: `MfaRequiredError` is thrown. |

### Validation rules (`validateConfig`)

All four rules below throw `ValidationError` synchronously from the
`QodiqaClient` constructor — invalid configuration never reaches the network
layer:

| Rule | Failure behavior |
|---|---|
| `baseUrl` must parse as `http:` or `https:` | Throws `ValidationError`: `Invalid baseUrl: "…" — must be a valid http or https URL.` |
| `apiKey`, when provided, must match `/^ok_[0-9a-f]{64}$/` | Throws `ValidationError`: `Invalid apiKey: must start with "ok_" followed by exactly 64 hexadecimal characters (total 67 chars).` |
| `timeout` must be `> 0` | Throws `ValidationError`: `timeout must be a positive integer (milliseconds).` |
| `maxRetries` must be a non-negative integer | Throws `ValidationError`: `maxRetries must be a non-negative integer.` |

## Example

```typescript
import { QodiqaClient } from '@qodiqa/sdk';

const client = new QodiqaClient({
  apiKey: 'ok_' + 'a'.repeat(64),
  signToken: 'my-sign-token',
  baseUrl: 'https://gateway.example.com',
  timeout: 15_000,
  maxRetries: 3,
  defaultHeaders: { 'x-tenant-id': 'my-tenant' },
  userAgent: 'my-app/1.0.0 (@qodiqa/sdk)',
});
```

## Environment variables

**The SDK itself does not read any environment variables.** `resolveConfig`
only reads fields off the `config` object passed to the constructor — there is
no implicit `process.env.QODIQA_API_KEY` lookup inside the SDK. Every example
under `sdk/javascript/examples/` follows the convention of reading
`process.env` in application code and passing the result into the constructor:

```typescript
const client = new QodiqaClient({
  apiKey: process.env.QODIQA_API_KEY,
  signToken: process.env.QODIQA_SIGN_TOKEN,
  baseUrl: process.env.QODIQA_BASE_URL ?? 'http://localhost:3000',
});
```

The variable names used by convention across the examples and CLI
(`sdk/javascript/examples/node/basic.js`, `sdk/javascript/examples/node/cli.js`, `examples/typescript/basic.ts`,
`examples/express/*`, `examples/fastify/*`, `examples/nextjs/*`) are:

| Variable | Maps to | Required for |
|---|---|---|
| `QODIQA_API_KEY` | `apiKey` | Ops-protected endpoints (webhooks, admin stats/history, batch certification) |
| `QODIQA_SIGN_TOKEN` | `signToken` | `client.sign.sign(...)` |
| `QODIQA_BASE_URL` | `baseUrl` | Overriding the default `http://localhost:3000` |
| `QODIQA_WEBHOOK_SECRET` | `secret` argument to `verifyWebhookSignature` / `WebhookVerifier` | Webhook signature verification (unrelated to `QodiqaClientConfig`) |

## Key provider configuration

Source: [`sdk/javascript/src/verification/keyProviders.ts`](../../../sdk/javascript/src/verification/keyProviders.ts)

`ArtifactVerifier` (see [api.md §16](api.md#16-local-artifact--transparency-proof-verification-offline))
is configured separately from `QodiqaClient` — it needs a public-key **trust
source**, not server credentials, since its entire point is verifying
signatures without asking the server whether they're valid. Three
implementations of the `KeyProvider` interface are available:

| Class | Use case | Network access |
|---|---|---|
| `StaticKeyProvider` | Embedded/pinned trust bundle, keys known ahead of time | None |
| `RemoteKeyProvider` | Fetch from a `/.well-known/qodiqa/keys`-shaped discovery endpoint, with a TTL cache | Yes, cached |
| `createKeyProvider(fn)` | Fully custom resolution logic (e.g. your own key-management service) | Whatever `fn` does |

```typescript
import { StaticKeyProvider, RemoteKeyProvider, createKeyProvider } from '@qodiqa/sdk';

// Static — no network access at all.
const staticKeys = new StaticKeyProvider([
  { keyId: 'dev-local:key_v1', publicKey: '<base64 SPKI DER>', status: 'active' },
]);

// Remote — fetches and caches the key list (default TTL 5 minutes).
const remoteKeys = new RemoteKeyProvider({
  discoveryUrl: 'https://api.example.com/.well-known/qodiqa/keys',
  cacheTtlMs: 300_000,
});

// Custom — plug in any lookup you like.
const customKeys = createKeyProvider(async (keyId) => {
  const key = await myKeyManagementService.lookup(keyId);
  return key ? { pubDer: Buffer.from(key.publicKeyDer, 'base64'), status: key.status } : null;
});
```

### Archived-key fallback — long-term verification

`RemoteKeyProvider` transparently extends verification to keys that have
since been purged from the live keystore: when a `keyId` is absent from the
live `/.well-known/qodiqa/keys` list (but the live fetch itself succeeded),
it automatically retries against `GET /.well-known/qodiqa/keys/archived`
before giving up. No code change is required to benefit from this — the
`remoteKeys` construction above already does it.

```typescript
// archivedDiscoveryUrl defaults to `${discoveryUrl}/archived` whenever
// discoveryUrl ends with '/qodiqa/keys' — override it explicitly only if
// you're proxying/renaming the endpoint, or pass `null` to disable the
// fallback entirely.
const remoteKeysNoFallback = new RemoteKeyProvider({
  discoveryUrl: 'https://api.example.com/.well-known/qodiqa/keys',
  archivedDiscoveryUrl: null,
});
```

Key properties:

- **The live lookup is always the fast path.** The archived tier is only ever queried after a *successful* live fetch that doesn't contain the key — a network/HTTP failure on the primary request resolves to `null` immediately, exactly as before this remediation; the fallback is not attempted in that case.
- **Cached independently**, same `cacheTtlMs` as the live list, so repeated lookups for an already-resolved archived key don't refetch on every call. `refresh()` bypasses both caches.
- **No fallback is derived for `/qodiqa/transparency-keys`** — only the artifact-signing key discovery endpoint has an archived tier.
- Resolved keys carry `status: 'deprecated'` either way (the wire-only `'archived'` marker the endpoint returns is normalized away) — `ResolvedKey.source` (`'live' | 'archived'`) is the diagnostic-only field that distinguishes the two, surfaced on `ArtifactVerificationResult.keySource` after a `verify()` call. See [docs/security/key-management.md § Archived Key Verification](../../security/key-management.md#archived-key-verification) for the full server-side design (rate limiting, cache TTL, operational expectations).
- **JS/Python asymmetry:** only this SDK supports `archivedDiscoveryUrl: null` to explicitly disable the fallback. The Python SDK's `archived_discovery_url` has no equivalent "disable" value — passing `None` there means "auto-derive," not "off." See [docs/sdk/python/configuration.md § Archived-key fallback](../python/configuration.md) if you need parity across both SDKs.

### Two separate trust domains — never share a provider between them

`ArtifactVerifier`'s `keys` option resolves **artifact-signing** keys
(`/.well-known/qodiqa/keys`); its optional `transparencyKeys` option resolves
**transparency-log-signing** keys (`/.well-known/qodiqa/transparency-keys`).
These are genuinely separate key stores server-side — by design, compromise
of one cannot compromise the other. Pointing both options at the same
discovery URL or the same static key list silently defeats that separation.
Always configure two distinct provider instances if you verify transparency
proofs.

### Unknown and revoked keys always fail closed

Every `KeyProvider` implementation returns `null` for a `keyId` it does not
recognize, and `ArtifactVerifier` treats both "unknown key" and "key resolved
but its status is not `active`/`deprecated`" as a `KEY_RESOLUTION` failure —
never a silently-selected fallback key.

## Configuration is immutable per client

Because validation runs once in the constructor and the resolved values are
captured by closure inside `HttpClient` and `AuthProvider`, there is no setter
API to change `baseUrl`, `timeout`, `apiKey`, etc. after construction. To talk
to a different server or use different credentials, construct a second
`QodiqaClient` instance.

## Next: [api.md](api.md) — full API reference
