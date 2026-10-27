# @qodiqa/sdk

Official JavaScript / TypeScript SDK for the **QODIQA** AI enforcement platform.

**This is the maintained JavaScript/TypeScript SDK.**

One production dependency (`fast-json-stable-stringify`, the canonical-JSON encoder used by offline artifact verification). Full TypeScript support. Works with Node.js 18+, Next.js, and any modern JavaScript runtime that provides the Fetch API.

---

## Table of contents

1. [Installation](#1-installation)
2. [Quick start](#2-quick-start)
3. [Authentication](#3-authentication)
4. [Configuration](#4-configuration)
5. [Resources](#5-resources)
   - [sign](#sign)
   - [chat](#chat)
   - [verify](#verify)
   - [portal](#portal)
   - [attestation](#attestation)
   - [transparency](#transparency)
   - [evidence](#evidence)
   - [certification](#certification)
   - [webhooks](#webhooks)
   - [Webhook signature verification](#webhook-signature-verification)
   - [simulation](#simulation)
   - [Client convenience methods](#client-convenience-methods)
6. [Error handling](#6-error-handling)
7. [Retry policy](#7-retry-policy)
8. [Pagination](#8-pagination)
9. [TypeScript usage](#9-typescript-usage)
10. [Examples](#10-examples)

---

## 1. Installation

**`@qodiqa/sdk` is not published to npm.** `npm install @qodiqa/sdk` (or `yarn add` / `pnpm add`)
does not resolve on a clean machine. [Corrected 2026-10-09, this section previously
led with registry install commands.] Install from the repository:

```bash
# 1. in the QODIQA repository root: build the SDK (installs this package's devDependencies,
#    which needs network access, and runs tsup; dist/ is not committed)
npm run sdk:build

# 2. in your project: install from the local path
npm install /path/to/qodiqa/sdk/javascript
```

Requires Node.js **18.0.0 or later** (uses the native `fetch` API and `structuredClone`).
Rebuild after changing `sdk/javascript/src`. See
[`docs/sdk/javascript/installation.md`](../../docs/sdk/javascript/installation.md).

**Test status.** The SDK covers a subset of the HTTP API (generated operation tables cover the HTTP API; see docs/api/REFERENCE.md for the current operation count)
and is tested mostly against a mock transport. The server it talks to has real-runtime provider
evidence only for the `local` (Ollama) provider. `import ... from '@qodiqa/sdk'` in the examples below
resolves once the package is installed from the local path as above.

---

## 2. Quick start

```typescript
import { QodiqaClient } from '@qodiqa/sdk';

const client = new QodiqaClient({
  signToken: process.env.QODIQA_SIGN_TOKEN,
  apiKey: process.env.QODIQA_API_KEY,          // only needed for ops endpoints
  baseUrl: process.env.QODIQA_BASE_URL ?? 'http://localhost:3000',
});

// Health check
const health = await client.healthCheck();
console.log(health.status); // 'ok'

// Sign a request. payload.provider is omitted here — /sign auto-resolves it
// to the single enabled AI provider. With more than one provider configured,
// pass payload: { provider: 'openai' } explicitly (400 PROVIDER_REQUIRED
// otherwise). See "sign" under Resources below.
const signed = await client.sign.sign({
  request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello' } },
  payload: { userId: 'user_123' },
  ttl: 300_000,
});

// Execute enforced AI chat
const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
const chat = await client.chat.create(artifactB64, { prompt: 'Hello' });

if (chat.decision === 'EXECUTE') {
  console.log(chat.aiText);

  // Evidence durability: `transparency.persisted` is the only
  // per-decision signal distinguishing a durable-evidence deployment
  // (entry written to PostgreSQL — proofs and signed roots will cover it)
  // from a sign-only one (signed, but nothing survives the process).
  // Production servers refuse to boot sign-only, so assert on it in any
  // evidentiary workflow:
  if (chat.transparency?.persisted !== true) {
    throw new Error('transparency entry was NOT durably persisted — sign-only deployment');
  }
} else {
  console.log('Blocked:', chat.reason);
}
```

---

## 3. Authentication

The QODIQA API uses three distinct authentication mechanisms depending on the endpoint.

### Sign Token

Used exclusively with `POST /sign` to issue signed artifacts.

```typescript
const client = new QodiqaClient({ signToken: 'your-sign-token' });
```

Passed as an `Authorization: Bearer <signToken>` header automatically by calling
`client.sign.sign(...)` — as of the TRUST-1 remediation, `POST /sign` no longer
accepts a shared secret via a dedicated `x-qodiqa-sign-token` header; every caller
authenticates with its own individually-issued signing API key via the standard
`Authorization` header instead.

### Artifact Auth

A base64-encoded, signed artifact is passed as the `x-qodiqa-artifact` header when calling `/ai/chat`. Obtain an artifact via `POST /sign` first.

```typescript
const artifactB64 = Buffer.from(JSON.stringify(signedArtifact)).toString('base64');
await client.chat.create(artifactB64, { prompt: '...' });
```

`/verify` and `/verify/v2` do **not** use this header — both read the
artifact only from the request body (`request.artifact`). `verify.verify()`
still accepts an `artifact` string argument for backward compatibility (it
is validated but not transmitted); see [verify](#verify) below.

### Ops API Key

A `Bearer ok_<64-hex>` token required for all operations-protected endpoints (webhooks, admin stats, batch operations, etc.).

```typescript
const client = new QodiqaClient({ apiKey: 'ok_' + '0'.repeat(64) });
await client.webhooks.list('tenant-1'); // tenantId is required
await client.attestation.stats();
```

The SDK validates the key format at construction time and throws `ValidationError` immediately if the format is wrong.

---

## 4. Configuration

```typescript
import { QodiqaClient } from '@qodiqa/sdk';

const client = new QodiqaClient({
  // Ops API key — must match /^ok_[0-9a-f]{64}$/
  apiKey: 'ok_abc...',

  // Sign token for POST /sign
  signToken: 'my-sign-token',

  // API base URL. Default: 'http://localhost:3000'
  baseUrl: 'https://gateway.example.com',

  // Request timeout in milliseconds. Default: 30_000
  timeout: 15_000,

  // Maximum retry attempts for retryable errors. Default: 2
  maxRetries: 3,

  // Extra headers merged into every request
  defaultHeaders: { 'x-tenant-id': 'my-tenant' },

  // Override User-Agent header
  userAgent: 'my-app/1.0.0 (@qodiqa/sdk)',
});
```

`resolveConfig` fills in all defaults, then `validateConfig` enforces rules:

| Rule | Behaviour |
|---|---|
| `baseUrl` must be a valid `http` or `https` URL | Throws `ValidationError` |
| `apiKey` (when provided) must match `ok_[0-9a-f]{64}` | Throws `ValidationError` |
| `timeout` must be > 0 | Throws `ValidationError` |
| `maxRetries` must be >= 0 | Throws `ValidationError` |

---

## 5. Resources

### sign

**`client.sign.sign(request, artifactHeader?)`**

Issues a signed artifact via `POST /sign`. Requires `signToken`.

`payload.provider` is conditional, and only meaningful when `request.path` is
`/ai/chat`: omit it and the server auto-resolves to the single enabled AI
provider; with more than one provider enabled, set it explicitly or `/sign`
returns `400 PROVIDER_REQUIRED`.

```typescript
const signed = await client.sign.sign({
  request: {
    method: 'POST',
    path: '/ai/chat',
    body: { prompt: 'Hello world' },
  },
  payload: {
    userId: 'user_123',
    sessionId: 'sess_abc',
  },
  ttl: 60_000, // ms; 60 s is the default and the maximum (larger values are clamped — meta.ttlClamped)
});

console.log(signed.artifactId);     // 'art_...'
console.log(signed.meta.keyId);     // key used to sign
console.log(signed.meta.expiresAt); // Unix timestamp
console.log(signed.meta.tenantId);  // your tenant
```

---

### chat

**`client.chat.create(artifact, request, options?)`**

Execute an AI prompt through QODIQA enforcement via `POST /ai/chat`. The `artifact` parameter is a base64-encoded artifact string.

```typescript
const chat = await client.chat.create(artifactB64, {
  prompt: 'Summarise the quarterly report.',
  model: 'gpt-4',       // optional
});

// chat.decision is 'EXECUTE' | 'BLOCK'
if (chat.decision === 'EXECUTE') {
  console.log(chat.aiText);           // AI-generated text
  console.log(chat.model);            // model used
  console.log(chat.tokenUsage);       // { prompt_tokens, completion_tokens, total_tokens }
} else {
  console.log(chat.reason);           // e.g. 'POLICY_VIOLATION'
}
```

`options.idempotencyKey` (optional) sends the `Idempotency-Key` header
The SDK never resends `/ai/chat` on its own; after an outcome-unknown
failure (e.g. a `504`), retry with a freshly signed artifact and the **same** key and the server replays the
original result instead of executing twice. `chat.stream()` does not take a key (the server rejects that
combination with `IDEMPOTENCY_STREAMING_UNSUPPORTED`).

```typescript
const key = crypto.randomUUID();
const chat = await client.chat.create(artifactB64, { prompt: 'Summarise the quarterly report.' }, { idempotencyKey: key });
```

**`client.chat.stream(artifact, request, options?)`**

Same enforcement as `create()`, but requests an SSE stream via `POST /ai/chat`
with `stream: true` and yields each event as it arrives instead of waiting
for the full response. Returns an `AsyncGenerator<ChatStreamEvent>` — iterate
it with `for await`.

`request` must be **the same body** passed to `sign.sign()`, with `stream:
true` already included — the server binds the artifact to the exact request
body via `requestHash`, so signing without `stream: true` and then calling
`chat.stream()` fails closed with `VerificationError` (`REQUEST_MISMATCH`)
before any token is streamed. `chat.stream()` sets `stream: true` on the wire
body it sends, so the same object can be reused for both calls:

```typescript
const CHAT_BODY = { prompt: 'Summarise the quarterly report.', model: 'gpt-4', stream: true };

const signed = await client.sign.sign({
  request: { method: 'POST', path: '/ai/chat', body: CHAT_BODY },
  payload: { userId: 'user_123' },
});
const artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');

// Cancellation: pass an AbortSignal (e.g. tied to a UI "stop generating"
// button, or your own deadline). Breaking out of the loop early has the
// same effect — the underlying connection is closed either way.
const controller = new AbortController();
setTimeout(() => controller.abort(), 60_000); // optional caller-side deadline

try {
  for await (const event of client.chat.stream(artifactB64, CHAT_BODY, { signal: controller.signal })) {
    switch (event.event) {
      case 'stream_started':
        console.log('provider:', event.provider, 'model:', event.model);
        break;
      case 'chunk_forwarded':
        process.stdout.write(event.delta);
        break;
      case 'stream_completed':
        console.log('\ndone —', event.chunksTotal, 'chunks,', event.durationMs, 'ms');
        break;
      case 'stream_cancelled':
        // 'CLIENT_DISCONNECT' | 'STREAM_TIMEOUT' | a provider error code |
        // 'SEMANTIC_OUTPUT_BLOCKED' | 'SEMANTIC_OUTPUT_BLOCKED_FINAL' — see
        // "Streaming output-safety contract" below for the last two.
        console.log('\ncancelled:', event.reason);
        break;
    }
  }
} catch (err) {
  if (err instanceof VerificationError) {
    console.error('artifact/request mismatch:', err.message); // e.g. forgot stream: true when signing
  } else if (err instanceof TimeoutError) {
    console.error('stream exceeded options.timeout'); // only thrown if you passed one — see below
  } else if (err instanceof QodiqaError) {
    console.error(`[${err.status ?? 'n/a'}] ${err.message}`);
  }
  throw err;
}
```

No client-side timeout is applied unless you pass `options.timeout` — the
server itself bounds a session at `STREAM_MAX_DURATION_MS` (default 5
minutes), so most callers don't need
one. Once the stream has opened it is never retried (see [Retry policy](#7-retry-policy)) — a
partially-consumed SSE session isn't a safely-repeatable single call the way
a JSON request is. Before it opens, only a 503 `SERVER_OVERLOADED` is resent
(after `Retry-After`; the artifact's nonce was not consumed). If the body ends
**without the terminal `[DONE]` frame** (a proxy idle timeout, a reset, a server
crash between frames) the loop throws `NetworkError` after the events already
yielded — treat them as a partial answer, never a complete one. A mid-stream
failure (provider error, output block, timeout) is not an exception: it is the
terminal `stream_cancelled` event with its `reason`.

A non-artifact enforcement BLOCK decided before the stream opens (policy,
consent, semantic, …) is thrown as `BlockedError` (`err.reason`), since a
stream cannot yield "the decision is BLOCK"; `chat.create()` returns the same
decision as a value instead. (In the server's opt-in `status` block-HTTP mode
the same BLOCK arrives as 403/429/503 and surfaces by status class.)

A full runnable version of this example, including a live server, is at
[`examples/node/streaming.js`](examples/node/streaming.js).

**Streaming output-safety contract.** `chat.create()` (non-streaming)
classifies the AI provider's complete response before returning it — a
`decision: 'BLOCK'` result means you never receive the text at all.
`chat.stream()` forwards each chunk incrementally as it clears a bounded
output check, and runs one more, mandatory check over the full accumulated
response after the stream would otherwise finish normally. If *that* check
is what denies the response, you may **already have received
`chunk_forwarded` events** — the only signal is the terminal event changing
from `stream_completed` to `stream_cancelled` with
`reason: 'SEMANTIC_OUTPUT_BLOCKED_FINAL'`. (Since the output window is
check-then-release: each `chunk_forwarded` passed its own window check before
it was sent, and a still-held tail is withheld when the final check denies —
so what you may already hold is the text released *before* the final check,
not every chunk.) This is intentional: once a chunk
has been written to the SSE connection there is no protocol-level way to
retract it, so the server's audit record is corrected instead (audit-truth
over content-suppression). If your integration needs a hard guarantee that
denied content never reaches you, use `chat.create()` instead of
`chat.stream()`. Full mechanics:,
.

---

### verify

**`client.verify.verify(artifact, request)`** — `POST /verify`

```typescript
const result = await client.verify.verify(artifactB64, {
  artifact: signedArtifact,
  request: {
    method: 'POST',
    path: '/ai/chat',
    body: { prompt: 'Hello' },
  },
});

console.log(result.decision);   // 'EXECUTE' | 'BLOCK'
console.log(result.reason);
console.log(result.artifactId);
console.log(result.keyId);
```

**`client.verify.verifyV2(request)`** — `POST /verify/v2`

Runs the identical validation pipeline as `verify()` (same server-side
handler), under the `/verify/v2` route's separate, higher rate-limit
bucket.

```typescript
const result = await client.verify.verifyV2({
  artifact: signedArtifact,
  request: { method: 'POST', path: '/ai/chat', body: { prompt: 'Hello' } },
});
```

**`client.verify.dryRun(request)`** — `POST /verify` (body-only)

```typescript
const result = await client.verify.dryRun({
  artifact: signedArtifact,
  request: { method: 'POST', path: '/ai/chat', body: {} },
});
```

Neither `/verify` nor `/verify/v2` reads the `x-qodiqa-artifact` header — the
artifact is always taken from `request.artifact` in the body, so `verify()`,
`verifyV2()`, and `dryRun()` all send the same wire request; they exist as
separate methods for endpoint/rate-limit-bucket selection and backward
compatibility, not different transport behavior.

**Semantic parity:** `verify()`/`verifyV2()`/`dryRun()`
now also run the same Semantic Policy Engine `/ai/chat` runs on the request
`prompt` — a `result.decision === 'BLOCK'` here can now be a content-match
reason (e.g. `'SECURITY_OVERRIDE_ATTEMPT'`, `'PII_EXTRACTION'`; see the
[main API reference](../../docs/api/overview.md#semantic-policy-engine)
for the full code table), with `result.details.semantic` carrying the same
evidence shape `/ai/chat`'s audit trail records for the identical verdict.
Side-effect-free (no audit write, no transparency entry, no consent
consumption, no provider call) and only runs when `request.body.prompt` is
a non-empty string — the `dryRun()` example above sends `body: {}` (no
`prompt`), which skips this step entirely, and any artifact bound to a
non-`/ai/chat` endpoint behaves the same way, matching the fact that
`/ai/chat` itself would never reach that stage for such a request either.

---

### portal

The public verification portal — a **synchronous**, unauthenticated (rate-limited only)
service that runs QODIQA's full artifact-verification check suite and returns a complete
report in one call. It answers a different question than [`verify`](#verify): `verify`
simulates whether a signed artifact would currently pass enforcement; `portal.verify`
independently re-validates an artifact's cryptographic/structural integrity — signature,
key resolution, timestamps, replay history — useful for third-party auditors or a caller
who wants to check an artifact without holding a signing key of their own.

**`client.portal.verify(artifact)`** — `POST /v1/portal/verify`

The request body **is** the raw artifact object — not wrapped in `{artifact, request}`.
No pending/in-progress state: the full check suite runs and the response is a complete
report, one call, no polling.

```typescript
const result = await client.portal.verify(signedArtifact);

console.log(result.data.verificationId);   // UUID — save this for getResult() later
console.log(result.data.overallResult);    // 'VERIFIED' | 'VERIFIED_WITH_WARNINGS' | 'FAILED'
console.log(result.data.checks);           // [{ check, result: 'PASS'|'FAIL'|'WARN'|'SKIP', reason? }]
if (result.data.warnings.length > 0) {
  console.log(result.data.warnings);       // [{ check, reason }]
}
```

**`client.portal.getResult(verificationId)`** — `GET /v1/portal/result/:id`

Retrieves a previously-run verification by the `verificationId` a prior `verify()` call
returned. **Requires PostgreSQL to be enabled server-side** — the portal's history store
is Postgres-only, and this 404s (`NotFoundError`) if PostgreSQL was disabled at `verify()`
time (nothing was ever persisted) or is disabled now, even for a `verificationId`
`verify()` itself just returned.

```typescript
const record = await client.portal.getResult(result.data.verificationId);
console.log(record.data.verification.overall_result); // note: snake_case — a raw
                                                        // PostgreSQL row, unlike verify()'s
                                                        // camelCase report above
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

---

### attestation

**Public (no auth)**

```typescript
// Generate attestation
const att = await client.attestation.verify({ artifact });

// Verify an evidence package (e.g. previously obtained from getEvidence()) —
// NOT a signed artifact. The server checks
// evidencePackage.packageType === 'QODIQA::PORTAL_EVIDENCE::V1'.
const ev = await client.attestation.verifyEvidence({ evidencePackage });

// Verify a chain by evidence ID range — NOT a signed artifact.
const chain = await client.attestation.verifyChain({ evidenceIds: ['evid-001'] });

// Fetch by ID
const record = await client.attestation.get('att-001');
```

**Ops-protected (requires `apiKey`)**

```typescript
// Export (JSON) — requires the EXPORT_ATTESTATIONS permission
const exported = await client.attestation.export('att-001');
console.log(exported.data.attestationId, exported.data.status);

// Evidence package
const pkg = await client.attestation.getEvidence('att-001');

// Summary
const summary = await client.attestation.getSummary('att-001');

// History (paginated)
const history = await client.attestation.list({ page: 1, pageSize: 50 });

// Admin stats
const stats = await client.attestation.stats();
```

> `export()` covers only the server's default JSON export. The server also
> supports `?format=pdf` (`GET /v1/attestation/:id/export?format=pdf`),
> streaming a rendered PDF — this isn't exposed as a typed method since the
> SDK's `HttpClient` only parses JSON/text response bodies, not binary ones.
> Call the endpoint directly if you need the PDF export.

---

### transparency

**Public**

```typescript
// Single entry
const entry = await client.transparency.getEntry('entry-001');

// List (paginated)
const entries = await client.transparency.listEntries({ page: 1, pageSize: 50 });

// Latest root
const root = await client.transparency.getRoot();

// Verify entry — use the entry's transparencyId (a UUID), not the plain
// numeric `id` field from listEntries()/getEntry().
const verification = await client.transparency.verifyEntry('entry-001');
console.log(verification.data.result);          // 'VALID' | 'INVALID' | 'PARTIAL' | 'ERROR'
console.log(verification.data.signatureValid);   // boolean | null

// Inclusion proof — `proof` is `null` until a root has been generated
// covering this entry (see generateRoot() below).
const proof = await client.transparency.getProof('entry-001');
console.log(proof.data.proof); // string[] | null
```

**Ops-protected**

```typescript
// Register a new entry — entryType is required; artifactId/evidenceChainId/
// verificationId/payload/tenantId are all optional.
const newEntry = await client.transparency.register({
  entryType: 'ARTIFACT',
  artifactId: 'art-001',
  tenantId: 'my-tenant',
});

// Generate a root covering all entries not yet included in a prior root —
// required before getProof() returns a populated array for new entries.
const root = await client.transparency.generateRoot();

// Admin stats
const stats = await client.transparency.stats();

// Validate the transparency log's own hash chain
// (GET /v1/transparency/admin/chain/validate; ops key with READ_TRANSPARENCY_LOG).
// All three parameters are optional. This is NOT the audit chain's
// /audit/chain/integrity check.
const integrity = await client.transparency.validateChain({ limit: 1000 });
console.log(integrity.data.chainValidation.valid, integrity.data.chainValidation.checkedCount);
```

---

### evidence

```typescript
// Retrieve evidence package (requires apiKey)
const pkg = await client.evidence.getPackage('att-001');
```

---

### certification

**Public** (except `evaluate()`, which needs the ops key)

```typescript
// Run evaluation — requires apiKey (mounted on the admin router,
// SUBMIT_BATCH_CERTIFICATION). artifacts is an array (max 50 per request);
// optional evidencePackages/chain/options may also be included. There is no
// `evaluationLevel` field.
const cert = await client.certification.evaluate({
  artifacts: [artifact],
});

// Get record
const record = await client.certification.get('cert-001');

// Summary
const summary = await client.certification.getSummary('cert-001');
```

**Ops-protected**

```typescript
// Submit batch — frameworkId is required, and each item needs its own
// subjectId (not a bare artifact).
const batch = await client.certification.submitBatch({
  frameworkId: 'default',
  items: [
    { subjectId: 'subject-1', artifacts: [artifact1] },
    { subjectId: 'subject-2', artifacts: [artifact2] },
  ],
});
console.log(batch.data.batchId);

// Batch status
const batchStatus = await client.certification.getBatch(batch.data.batchId);

// Batch results
const results = await client.certification.getBatchResults(batch.data.batchId);

// Cancel batch
await client.certification.cancelBatch(batch.data.batchId);

// List all (paginated)
const all = await client.certification.list({ page: 1, pageSize: 50 });

// Stats
const stats = await client.certification.stats();
```

---

### webhooks

All webhook methods require an ops API key.

```typescript
// Create
const webhook = await client.webhooks.create({
  tenantId: 'tenant-1',
  url: 'https://example.com/webhook',
  eventTypes: ['attestation.completed', 'certification.evaluated'],
  description: 'Production webhook',
});
console.log(webhook.data.endpoint.id);
console.log(webhook.data.secret); // HMAC signing secret — only ever returned here

// List — tenantId is required (there is no cross-tenant list)
const list = await client.webhooks.list('tenant-1', { page: 1, pageSize: 50 });

// Get
const wh = await client.webhooks.get('wh-001', 'tenant-1'); // every per-id call takes the owning tenantId

// Update — the field is `enabled`, not `active`
const updated = await client.webhooks.update('wh-001', {
  enabled: false,
  description: 'Disabled temporarily',
}, 'tenant-1');

// Delete
await client.webhooks.delete('wh-001', 'tenant-1');

// Send test event
await client.webhooks.test('wh-001', 'tenant-1');

// Delivery log
const deliveries = await client.webhooks.getDeliveries('wh-001', 'tenant-1');

// Metrics
const metrics = await client.webhooks.metrics();
```

---

### Webhook signature verification

QODIQA signs each webhook delivery with HMAC-SHA256, sent in the
`X-QODIQA-Signature` header as `sha256=<hex_hmac>`, with the delivery
timestamp sent *separately* in its own `X-QODIQA-Timestamp` header (an
ISO-8601 UTC value, e.g. `2026-01-01T00:00:00.000Z`). The HMAC covers
`<raw_X-QODIQA-Timestamp_header_value> + "." + <raw_request_body>` — always
verify against the **raw** bytes as received, never a re-serialized JSON
string, and pass the timestamp through exactly as received.

```typescript
import { verifyWebhookSignature, WebhookVerifier } from '@qodiqa/sdk';
import {
  InvalidSignatureError,
  ExpiredSignatureError,
  MalformedSignatureError,
  InvalidTimestampError,
} from '@qodiqa/sdk';

// Convenience function
verifyWebhookSignature({
  body: rawBody,
  signature: req.headers['x-qodiqa-signature'] as string,
  timestamp: req.headers['x-qodiqa-timestamp'] as string,
  secret: process.env.QODIQA_WEBHOOK_SECRET!,
});

// Reusable verifier (preferred when verifying multiple endpoints)
const verifier = new WebhookVerifier(process.env.QODIQA_WEBHOOK_SECRET!);
verifier.verify(
  rawBody,
  req.headers['x-qodiqa-signature'] as string,
  req.headers['x-qodiqa-timestamp'] as string,
);

// Secret rotation — verification succeeds if ANY secret matches
const rotatingVerifier = new WebhookVerifier([
  process.env.QODIQA_WEBHOOK_SECRET_NEW!,
  process.env.QODIQA_WEBHOOK_SECRET_OLD!,
]);
```

Both raise `MalformedSignatureError` (signature header unparseable or missing
a `sha256=` component), `InvalidTimestampError` (`X-QODIQA-Timestamp` missing
or not a valid ISO-8601 UTC timestamp), `ExpiredSignatureError` (timestamp
outside `tolerance`, default `DEFAULT_TOLERANCE_SECONDS` = 300s), or
`InvalidSignatureError` (no secret produces a matching HMAC, compared with
`crypto.timingSafeEqual`). See `examples/express/webhook.js`,
`examples/fastify/webhook.js`, and `examples/nextjs/webhook.ts` for
framework-specific raw-body capture.

---

### simulation

Read-only policy dry-run evaluation. No nonce is registered, no anomaly counter is
incremented, no audit record is written, and no AI provider is contacted —
`executionPrevented: true` is always present in every response.

```typescript
// Single simulation against the live (or a provided draft) policy set
const result = await client.simulation.simulate({
  context: { userId: 'my-key:key_v1', action: 'openai', ip: '192.168.1.1' },
});
console.log(result.decision); // 'EXECUTE' | 'BLOCK'
console.log(result.evaluationTrace);
console.log(result.executionPrevented); // true

// Compare current vs. proposed policies against the same context
const comparison = await client.simulation.compare({
  context: { userId: 'my-key:key_v1', action: 'openai' },
  proposedPolicies: [
    { id: 'rl-1', type: 'RATE_LIMIT', priority: 10, enabled: true, config: { max: 100 } },
  ],
});
console.log(comparison.decisionChanged);
console.log(comparison.changedRules);

// Batch up to 100 simulations concurrently
const batch = await client.simulation.batch({
  simulations: [
    { context: { userId: 'a', action: 'openai' } },
    { context: { userId: 'b', action: 'anthropic' } },
  ],
});
console.log(batch.total, batch.allowed, batch.blocked);
```

---

### agents, actions, tools, delegations, approvals (protocol V2)

`client.agents`, `client.sessions`, `client.toolRegistry`, `client.mcpServers`, `client.approvals` use the operator key (and the
MFA step-up: configure `otpProvider`); `client.actions`, `client.tools`, `client.delegations` use the signing key.

```ts
import { QodiqaClient, signAgentProof, isApprovalPending } from '@qodiqa/sdk';

const ctx = { tenantId, agentId, sessionId, requestId };
const res = await client.actions.authorize({ agentId, sessionId, requestId, proof: signAgentProof(ctx, privateKey),
  tool: { server: 'files', name: 'read' }, args: { path: '/a' } });
const artifact = isApprovalPending(res) ? (await client.actions.authorizeAndWait({ /* same request */ })).artifact : res.artifact;
const out = await client.tools.call({ artifact, tool: { server: 'files', name: 'read' }, args: { path: '/a' } });
// out.result is UNTRUSTED DATA - put out.result.delimited between your instructions and the data.
```

### Client convenience methods

These are available directly on the `QodiqaClient` instance.

```typescript
// GET /health
const health = await client.healthCheck();
console.log(health.status);  // 'ok'
console.log(health.uptime);  // seconds

// GET /ready
const ready = await client.readinessCheck();
console.log(ready.ready);               // boolean
console.log(ready.components);          // { nonceStore, anomalyStore, rateLimitStore, persistenceStore, consentSubscriber, consentCache }

// GET /public-keys
const keys = await client.getPublicKeys();
for (const key of keys.keys) {
  console.log(`${key.keyId} [${key.algorithm}] ${key.status}`);
}

// GET /.well-known/qodiqa/keys/:keyId
const key = await client.getPublicKey('key-001');

// GET /audit/:artifactId — requires an ops API key (READ_AUDIT). The response is
// the standard success envelope; the audit record is `.data`. Use the
// artifactId returned by sign.sign(), not a chat response's requestId.
const audit = await client.getAuditChain('art-001');
console.log(audit.data.decision);
console.log(audit.data.chain.length);
```

---

## 6. Error handling

All errors extend `QodiqaError`, which extends `Error`.

```typescript
import {
  QodiqaError,
  AuthenticationError,   // 401
  AuthorizationError,    // 403
  ValidationError,       // 400 / 422
  VerificationError,     // artifact fails to verify — signature invalid, expired, tampered
  NotFoundError,         // 404
  RateLimitError,        // 429 — has retryAfter: number | undefined
  ServerError,           // 5xx
  NetworkError,          // fetch / DNS failure
  TimeoutError,          // AbortSignal timeout
  UnknownError,          // anything else
} from '@qodiqa/sdk';

try {
  const chat = await client.chat.create(artifactB64, { prompt: 'hello' });
} catch (err) {
  if (err instanceof AuthenticationError) {
    // Missing or invalid sign token / ops key (an artifact rejection is a VerificationError)
    console.error('Auth failed:', err.message);

  } else if (err instanceof RateLimitError) {
    console.error('Rate limited. Retry after:', err.retryAfter, 'seconds');

  } else if (err instanceof VerificationError) {
    // Artifact signature invalid, expired, or tampered
    console.error('Verification failed:', err.message, err.details);

  } else if (err instanceof ValidationError) {
    console.error('Bad request:', err.message, err.details);

  } else if (err instanceof NetworkError) {
    console.error('Network problem:', err.message);

  } else if (err instanceof TimeoutError) {
    console.error('Request timed out');

  } else if (err instanceof QodiqaError) {
    // Catch-all for any QODIQA-specific error
    console.error('HTTP status:', err.status);
    console.error('Request ID:', err.requestId);
    console.error('Details:', err.details);

  } else {
    throw err; // Re-throw non-QODIQA errors
  }
}
```

### Error properties

| Property | Type | Description |
|---|---|---|
| `message` | `string` | Human-readable error message |
| `status` | `number \| undefined` | HTTP status code |
| `requestId` | `string \| undefined` | QODIQA request ID — from the response body, else the `X-Request-ID` response header (the per-HTTP trace id) |
| `details` | `Record<string, unknown>` | Raw details from the error response, plus `retryAfter` (seconds, parsed from a `Retry-After` header on any status) and, for the `/sign` limiter's 429, `blockedBy` (the limiter window, e.g. `BURST`), `surface`, `dimension` |
| `reason` | `string \| undefined` | Server reason / error code (e.g. `SERVER_OVERLOADED`, `RATE_LIMIT_EXCEEDED`) |
| `retryAfter` | `number \| undefined` | Seconds to wait before retry (`RateLimitError` and `MfaLockedError`) |

### VerificationError

A cryptographic/protocol verification failure — the artifact itself couldn't be verified,
as opposed to a policy decision about an otherwise-valid, verified request:

| Reason code | Meaning |
|---|---|
| `INVALID_SIGNATURE` | Artifact signature does not match |
| `EXPIRED` | Artifact TTL has elapsed |
| `KEY_NOT_FOUND` | Public key not found, revoked, or expired |
| `FUTURE_TIMESTAMP` | Artifact timestamp is in the future |
| `TIME_SKEW_EXCEEDED` | Artifact timestamp predates the server clock beyond tolerance |
| `REQUEST_MISMATCH` | Request content does not match the signed hash |
| `REPLAY_DETECTED` | Artifact `requestId` has already been used |
| `INVALID_ARTIFACT` | Artifact structure is malformed |

The table lists common examples; the full set is the 26 codes in the exported
`VERIFICATION_REASONS` (the server's `artifact_malformed`, `artifact_invalid`,
`request_mismatch` and `replay` classes, `src/api/blockHttpStatus.js` — e.g. also
`MISSING_ARTIFACT`, `KEY_REVOKED`, `SIGNATURE_UNVERIFIABLE`).

**Since / API-02, `chat.create()` and `chat.stream()` both throw `VerificationError`
for every one of these reasons, at any HTTP status** — including the HTTP 200
`decision: 'BLOCK'` body the server sends in its default `decision` block-HTTP mode.
(Between 2026-08-14, and `create()` returned them as a BLOCK value; that is no
longer the case.) Every *other* BLOCK — policy, consent, semantic, rate rule, … — is still
returned by `create()` as `decision: 'BLOCK'` with its `reason`, and thrown by `stream()` as
`BlockedError` when it is decided before the stream opens. The SDK's error factory checks
the reason before the HTTP status, so an artifact rejection is never misclassified as a
401/403 authentication/authorization failure.

---

## 7. Retry policy

The SDK retries automatically using **exponential back-off with full jitter**, but only when a resend is safe —
the policy depends on the method and the path (full rules: [`docs/sdk/javascript/api.md` §13](../../docs/sdk/javascript/api.md#13-retry-policy)):

- **`503 SERVER_OVERLOADED`** (admission control, refused before the request was processed): always retried, on every
  method, `/ai/chat` included.
- **`GET` / `PUT` / `DELETE`**: retried on `429`, `500`, `502`, `503`, `504`.
- **`POST` / `PATCH`**: retried **only on `429`**, and **never on `/ai/chat`** (the artifact nonce may already be
  consumed). A `5xx` on a `POST` is surfaced, not resent.
- **Never retried**: `TimeoutError`, `MFA_LOCKED`, any other `4xx`, and **any request carrying an MFA code
  (`X-QODIQA-OTP`)** — a TOTP code is accepted once per step, so a resend would fail as `MFA_INVALID` and count
  toward the MFA lockout.

```typescript
const client = new QodiqaClient({
  maxRetries: 3,   // default: 2. Set to 0 to disable retries.
});
```

Retry timing (default `baseDelay = 500ms`, `maxDelay = 30s`, full jitter): each delay is a uniformly random value
between 0 and the upper bound below.

| Attempt | Upper bound of the delay |
|---|---|
| 1st retry | 500ms |
| 2nd retry | 1000ms |
| 3rd retry | 2000ms |

When a retryable response carries a `Retry-After` header (delta-seconds or an HTTP-date) — a `429`, or a `503`
such as `SERVER_OVERLOADED` — that wait replaces the exponential schedule. It is never shortened: a `Retry-After`
above 30 s, or one that would outlive the call's `timeout` budget, makes the SDK throw the error at once instead
of retrying early or ending in a client-side `TimeoutError`.

You can also use the exported `withRetry` helper for your own operations:

```typescript
import { withRetry } from '@qodiqa/sdk';

const result = await withRetry(
  () => myAsyncOperation(),
  { maxRetries: 3, baseDelay: 200, jitter: true },
  (attempt, delay, err) => console.log(`Retry ${attempt} in ${delay}ms:`, err),
);
```

---

## 8. Pagination

All list endpoints accept `PaginationParams`:

```typescript
const page = await client.transparency.listEntries({
  page: 1,
  pageSize: 50,
  sortOrder: 'desc',
});
// page.data.entries     — items on this page
// page.data.total       — total count
// page.data.hasNextPage — whether more pages exist
```

Note: this generic shape (`entries`/`hasNextPage`) matches `transparency.listEntries()`.
Some other list endpoints use a differently-named array under their own response
(e.g. `webhooks.list()` -> `endpoints`, `certification.list()` -> `certifications`,
`attestation.list()` -> `attestations`) — check the specific resource method's
own return type before assuming this generic shape applies.

For iterating all items across pages, use the exported `PageIterator`:

```typescript
import { PageIterator } from '@qodiqa/sdk';

const iter = new PageIterator(
  (page, pageSize) =>
    client.transparency.listEntries({ page, pageSize }).then((r) => r.data),
  { pageSize: 50 },
);

for await (const entry of iter) {
  console.log(entry.id);
}
```

For iterating page-by-page, use `PagePage`:

```typescript
import { PagePage } from '@qodiqa/sdk';

const pages = new PagePage(
  (page, pageSize) =>
    client.transparency.listEntries({ page, pageSize }).then((r) => r.data),
  { pageSize: 50 },
);

for await (const page of pages) {
  console.log(`Page has ${page.entries.length} entries`);
}
```

---

## 9. TypeScript usage

The SDK is written in TypeScript and ships with full type declarations.

```typescript
import type {
  // Core
  HttpMethod, Decision, KeyStatus,
  // Artifacts
  Artifact, ArtifactPayload, SignRequest, SignResponse, SignMeta,
  // Chat
  ChatRequest, ChatResponse, TokenUsage,
  // Verify
  VerifyRequest, VerifyResponse,
  // Keys
  PublicKey, KeysResponse,
  // Audit
  AuditChainEntry, AuditResponse,
  // Health
  HealthResponse, ReadyResponse,
  // Attestation
  AttestationVerifyRequest, AttestationRecord,
  // Certification
  CertificationEvaluateRequest, CertificationRecord,
  BatchSubmitRequest, BatchRecord,
  // Transparency
  TransparencyEntry, TransparencyRoot, InclusionProof, TransparencyVerifyResult,
  // Portal
  PortalSubmitRequest, PortalResult,
  // Webhooks
  WebhookCreateRequest, WebhookRecord, WebhookUpdateRequest,
  // Pagination
  PaginationParams, PaginatedResponse,
  // API wrapper
  ApiResponse,
} from '@qodiqa/sdk';
```

All types are exported from the top-level `@qodiqa/sdk` package.

### Strict null safety

```typescript
const chat = await client.chat.create(artifactB64, { prompt: 'hello' });

// TypeScript knows these may be undefined:
if (chat.aiText) {
  console.log(chat.aiText.toUpperCase()); // safe
}

// RateLimitError.retryAfter is number | undefined
if (err instanceof RateLimitError && err.retryAfter !== undefined) {
  await sleep(err.retryAfter * 1000);
}
```

---

## 10. Examples

The `examples/` directory contains ready-to-run examples:

| File | Description |
|---|---|
| `examples/node/basic.js` | CommonJS — health, keys, sign, chat, verify, audit, portal |
| `examples/node/cli.js` | Node.js CLI — multi-command tool with full error handling |
| `examples/typescript/basic.ts` | Full TypeScript example with all resources |
| `examples/express/middleware.js` | Express middleware for enforced AI routes |
| `examples/fastify/middleware.js` | Fastify plugin with sign + verify pre-handler hooks |
| `examples/nextjs/route.ts` | Next.js App Router API route |

### Running the Node.js example

```bash
cd sdk/javascript
npm install
npm run build

QODIQA_SIGN_TOKEN=your-token \
QODIQA_BASE_URL=http://localhost:3000 \
node examples/node/basic.js
```

### Running the CLI

```bash
cd sdk/javascript && npm run build

# Health check
node examples/node/cli.js health

# Sign a request
QODIQA_SIGN_TOKEN=<token> node examples/node/cli.js sign --prompt "Hello" --user user_123

# Enforced AI chat
QODIQA_SIGN_TOKEN=<token> node examples/node/cli.js chat --prompt "Explain quantum computing"

# Audit chain
node examples/node/cli.js audit --artifact-id art_abc123
```

### Running tests

```bash
npm test
# or with coverage:
npm run test:coverage
```

---

## License

Apache-2.0 — Copyright (c) QODIQA

## Protecting an existing app: `artifactGuard`

```js
const express = require('express');
const { artifactGuard, RemoteKeyProvider } = require('@qodiqa/sdk');

const app = express();
app.use(express.json());
app.use('/protected', artifactGuard({ keys: new RemoteKeyProvider({ discoveryUrl: 'https://gateway.example.com/.well-known/qodiqa/keys' }) }));
app.post('/protected/echo', (req, res) => res.json({ tenant: req.qodiqa.payload.tenantId }));
```

A request passes only with an `x-qodiqa-artifact` header (base64 JSON) that verifies offline and is bound to **this** request: `payload.requestHash` must equal `requestHash(method, path, body)` (V1: path without
query, parsed JSON body, `{}` when none). Missing/invalid artifact: 401; valid artifact for another request: 403 `QODIQA_REQUEST_MISMATCH`. The guard does not consume the artifact's nonce: replay protection is the
gateway's (`POST /verify`), or pass `replayGuard`. V1 binding only (the V2 binding that also covers the query and headers is not implemented here yet).

**Known limits of the guard:**

- **Replay is open by default.** The same valid artifact passes any number of times, and a long-lived artifact stays valid until it expires. For anything that must be single-use, pass the replay hook, or call the gateway (`POST /verify`).
- **The key is not tied to a tenant.** The guard checks that the signing key is in your trust bundle and active, and reports `payload.tenantId`; it does not check that the key belongs to that tenant. Put only the keys you trust for the protected routes in the bundle, and check the reported tenant yourself if the bundle mixes tenants.
- **The query string is not part of the binding** (V1 binds method, path and body). Do not authorise on query parameters.
- **Path matching is literal.** `protect`/`exclude` prefixes are case-sensitive and not normalised; if a proxy or the framework case-folds or resolves dot segments after the guard, route and guard can disagree. Normalise before the guard or protect with a prefix that the framework matches exactly.
- **Base64 is parsed leniently** (whitespace, unpadded base64url); the signature still covers the content, so this cannot change what is authorised.

