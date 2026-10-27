# QODIQA JavaScript / TypeScript SDK

Developer documentation for `@qodiqa/sdk`, the official JavaScript/TypeScript
client for the [QODIQA](../../../README.md) AI enforcement platform.

This documentation set is generated from and verified against the SDK source at
[`sdk/javascript/src`](../../../sdk/javascript/src). Every method, type, and
default described here exists in that source tree — nothing in this set is
speculative or planned.

For the package's own quick-reference README (installation one-liner, resource
call examples, error handling, retry/pagination summary), see
[`sdk/javascript/README.md`](../../../sdk/javascript/README.md). This documentation
set expands on that README with a full audit trail: every exported symbol,
every configuration default, and every example verified against the
implementation.

## Contents

| Document | Covers |
|---|---|
| [installation.md](installation.md) | Supported Node.js versions, npm/pnpm/yarn install, building from source |
| [configuration.md](configuration.md) | Every `QodiqaClientConfig` option, defaults, validation rules, environment-variable conventions |
| [api.md](api.md) | Full reference for `QodiqaClient`, every resource class, error hierarchy, retry, pagination, webhook verification, and local (offline) artifact/transparency-proof verification |
| [examples.md](examples.md) | Walkthroughs of every file under `sdk/javascript/examples/` |

## What this SDK is

`@qodiqa/sdk` is an HTTP client for the QODIQA server's public and
ops-protected REST API. It does not perform local Ed25519 **signing** or
artifact construction — those still happen server-side, in QODIQA's
[enforcement pipeline](../../architecture/overview.md#enforcement-pipeline-post-aichat).
**Verifying** a signed artifact, however, is now available fully offline —
see point 5. The SDK's job is to:

1. Call `POST /sign` to obtain a signed [artifact](../../glossary.md) (see
   the **Artifact** entry in the glossary) for a given request.
2. Attach that artifact to enforced calls: `POST /ai/chat` (`chat.create()` /
   `chat.stream()`) sends it in the `x-qodiqa-artifact` header; `POST /verify`
   and `POST /verify/v2` (`verify.verify()` / `verifyV2()` / `dryRun()`) send it
   only in the request body's `artifact` field — the `/verify` route reads the
   body and ignores the header, so no header is sent
   ([`resources/verify.ts`](../../../sdk/javascript/src/resources/verify.ts)).
3. Wrap every other documented QODIQA HTTP endpoint (attestation, transparency,
   certification, evidence, webhooks, policy simulation) in a typed method with
   validated inputs and a mapped exception hierarchy.
4. Verify inbound webhook deliveries using constant-time HMAC comparison.
5. **Verify a signed artifact's Ed25519 signature, canonical JSON, key
   validity, and transparency-log inclusion proof entirely offline**, via
   `ArtifactVerifier`/`verifyArtifact()` — no network call to the server's
   `/verify` endpoint is required or used internally. See
   [api.md §16](api.md#16-local-artifact--transparency-proof-verification-offline).

Architecture terms used throughout this documentation (artifact, decision,
enforcement pipeline, policy hash, transparency log, attestation, certificate)
are defined once, canonically, in [`docs/glossary.md`](../../glossary.md) and are
used with the same meaning here.

## Package facts

Verified against [`sdk/javascript/package.json`](../../../sdk/javascript/package.json):

| Fact | Value |
|---|---|
| Package name | `@qodiqa/sdk` |
| Version | `1.0.0` |
| Supported Node.js | `>=18.0.0` |
| Production dependencies | `fast-json-stable-stringify` (canonical JSON for local artifact verification, byte-identical to the server's own canonicalizer) — otherwise zero, uses native `fetch`, `structuredClone`, and `node:crypto` |
| Module formats | CommonJS (`dist/index.js`) and ESM (`dist/index.mjs`), plus `dist/index.d.ts` |
| License | Apache-2.0 |

## Minimal working example

`QODIQA_SIGN_TOKEN` below is just this example's own shell-variable name for the
`sk_...` per-identity signing API key (`Authorization: Bearer sk_...` — remediation; see `docs/configuration/reference.md`). There is no shared secret to
configure.

```typescript
import { QodiqaClient } from '@qodiqa/sdk';

const client = new QodiqaClient({
  signToken: process.env.QODIQA_SIGN_TOKEN,
  baseUrl: process.env.QODIQA_BASE_URL ?? 'http://localhost:3000',
});

// payload.provider is omitted — /sign auto-resolves it to the single enabled
// AI provider (400 PROVIDER_REQUIRED if zero or more than one are enabled).
const signed = await client.sign.sign({
  request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello' } },
  payload: { userId: 'user_123' },
  ttl: 60_000, // the server clamps any larger ttl to 60 s
});

const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
const chat = await client.chat.create(artifactB64, { prompt: 'Hello' });

console.log(chat.decision === 'EXECUTE' ? chat.aiText : chat.reason);
```

See [api.md](api.md) for the full signature and behavior of every call used above.

## Cross-references

- [`README.md`](../../../README.md) — platform overview, enforcement pipeline, provider architecture
- [`docs/architecture/overview.md`](../../architecture/overview.md) — execution flow the SDK's `sign` → `chat`/`verify` calls trigger server-side
- [`docs/glossary.md`](../../glossary.md) — canonical definitions for Artifact, Decision, Policy, Consent, Transparency Log, Attestation, Certificate
- [`docs/api/overview.md`](../../api/overview.md) — the raw HTTP endpoints this SDK wraps
- the protocol specification (`docs/protocol/QODIQA-PROTOCOL.md`) — artifact envelope format, canonicalization, and domain-separated hashing referenced by the `Artifact` type
- [Python SDK documentation](../python/README.md) — equivalent client for Python
