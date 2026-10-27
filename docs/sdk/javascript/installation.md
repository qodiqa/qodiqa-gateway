# JavaScript SDK — Installation

## Supported Node.js versions

`@qodiqa/sdk` requires **Node.js 18.0.0 or later**
([`sdk/javascript/package.json`](../../../sdk/javascript/package.json), `engines.node`).
This requirement is not arbitrary — the SDK's `HttpClient`
([`sdk/javascript/src/http.ts`](../../../sdk/javascript/src/http.ts)) uses the
native `fetch` API and `AbortController`, and its request-body cloning
(`init.body = JSON.stringify(structuredClone(options.body))`) depends on the
global `structuredClone`, both of which are unavailable in earlier Node.js
versions without a polyfill. The SDK has exactly **one runtime (production)
dependency**, `fast-json-stable-stringify` (`^2.1.0`, `dependencies` in
`package.json`) — the canonical-JSON encoder used by local artifact
verification, byte-identical to the server's own canonicalizer. Everything
else (`fetch`, `AbortController`, `structuredClone`, `node:crypto`) ships with
the Node.js runtime itself.

The SDK also runs in any modern JavaScript runtime that provides the Fetch API
(Next.js Edge/Node runtimes, Deno, Bun, modern browsers), since it makes no
Node-specific system calls outside of the webhook-verification module (see
below).

**Browser caveat (current server CORS policy, `src/infra/cors/corsPolicy.js`;
scope is an open design decision):** the server allows only
`GET, HEAD, POST, OPTIONS` cross-origin and only the request headers
`Content-Type, Authorization, X-Ops-Token, X-Request-ID, X-Qodiqa-Artifact`,
and exposes only `X-Request-ID` and `Content-Disposition`. From a browser,
therefore, `webhooks.update()`/`webhooks.delete()` (PATCH/DELETE), the MFA
step-up resend (`X-QODIQA-OTP`) and `chat.create(…, { idempotencyKey })`
(`Idempotency-Key`) fail CORS preflight, and `Retry-After` is not readable (the
SDK then falls back to its own back-off). Use the SDK server-side for those
calls.

## Package manager installation

> **Publication status: not verified.** Whether `@qodiqa/sdk` is published to
> the npm registry has not been verified for this release (this repository's
> release process does not publish it, and nothing here was checked against
> the registry). The supported path is to **build it from this repository**:
>
> ```bash
> # from the repository root (needs network access for the SDK's devDependencies)
> npm run sdk:build        # = npm --prefix sdk/javascript install && npm --prefix sdk/javascript run build
> # then, in your project:
> npm install /path/to/qodiqa/sdk/javascript
> ```
>
> The `dist/` output is not committed (`.gitignore`), so a fresh clone has no
> `dist/` until this build runs. The registry commands below apply only once a
> published package exists.

```bash
npm install @qodiqa/sdk
```

```bash
pnpm add @qodiqa/sdk
```

```bash
yarn add @qodiqa/sdk
```

## Module resolution

The package publishes both CommonJS and ESM builds plus TypeScript
declarations, resolved via the `exports` map in `package.json`:

```json
{
  "types": "./dist/index.d.ts",
  "import": "./dist/index.mjs",
  "require": "./dist/index.js",
  "default": "./dist/index.js"
}
```

Both import styles work without extra configuration:

```typescript
// ESM / TypeScript
import { QodiqaClient } from '@qodiqa/sdk';
```

```javascript
// CommonJS
const { QodiqaClient } = require('@qodiqa/sdk');
```

## TypeScript support

The package ships hand-written `.d.ts` declarations (`dist/index.d.ts`,
`dist/index.d.mts`) generated from the TypeScript source under `src/`. No
`@types/qodiqa__sdk` package is needed — types are bundled. See
[api.md](api.md#17-typescript-types) for the full list of exported types.

## Building from source (contributing / running the bundled examples)

The examples under `sdk/javascript/examples/` `require`/`import` `@qodiqa/sdk`
as if it were an installed package, so the local build must exist before
running them:

```bash
cd sdk/javascript
npm install
npm run build      # runs tsup — emits dist/index.js, dist/index.mjs, dist/index.d.ts
```

Other scripts defined in [`sdk/javascript/package.json`](../../../sdk/javascript/package.json):

| Script | Command | Purpose |
|---|---|---|
| `npm run dev` | `tsup --watch` | Rebuild on file change |
| `npm run typecheck` | `tsc --noEmit` | Type-check without emitting |
| `npm test` | `jest` | Run the unit test suite (`test/`) |
| `npm run test:coverage` | `jest --coverage` | Run tests with coverage report |
| `npm run lint` | `eslint src --ext .ts` | Lint the source tree |

## Verifying the install

```bash
node -e "const { QodiqaClient } = require('@qodiqa/sdk'); console.log(typeof QodiqaClient)"
# => function
```

## Next steps

- [configuration.md](configuration.md) — every `QodiqaClientConfig` option and its default
- [api.md](api.md) — full API reference
- [examples.md](examples.md) — runnable examples for Node.js, Express, Fastify, and Next.js
