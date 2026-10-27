# QODIQA Provider Reference

Complete reference for QODIQA's AI provider abstraction layer: the interfaces, registry,
routing/failover logic, and the eight provider adapters (`azure` and `bedrock` are experimental) that actually exist in this codebase.
Every claim in this document is backed by a specific file under `services/providers/` or
`services/execution*.js` — nothing here is aspirational or planned.

For the high-level architecture summary, see [Provider architecture](../../README.md)
in the root README. This document is the detailed reference; the README section is the overview.

## Contents

1. [Terminology](#1-terminology)
2. [Architecture and execution flow](#2-architecture-and-execution-flow)
3. [Registry, selection, and lifecycle](#3-registry-selection-and-lifecycle)
4. [Failover](#4-failover)
5. [Streaming](#5-streaming)
6. [Common behavior across all providers](#6-common-behavior-across-all-providers)
7. [Provider: openai](#7-provider-openai)
8. [Provider: anthropic](#8-provider-anthropic)
9. [Provider: gemini](#9-provider-gemini)
10. [Provider: mistral](#10-provider-mistral)
11. [Provider: llama](#11-provider-llama)
12. [Provider: local](#12-provider-local)
12a. [Providers added in azure, bedrock, compat-&lt;id&gt;]()
13. [Error code reference](#13-error-code-reference)
14. [Security notes](#14-security-notes)

---

## 1. Terminology

See [`docs/glossary.md`](../glossary.md) for the canonical, single-source definitions of **Provider**,
**Provider Adapter**, **Provider Router**, and **Provider Failover**. In short:

- **Provider** — one of eight named AI execution backends (`openai`, `anthropic`, `gemini`, `mistral`, `llama`, `local`, and the experimental `azure`, `bedrock`), selected by `artifact.payload.provider`.
- **Provider Adapter** — the per-provider handler function (`services/providers/<name>.js`)
  that validates, executes, and normalizes a single provider call.
- **Provider Router** — `routeProviderCall()` (`services/providers/router.js`) and
  `routeStreamingProviderCall()` (`services/providers/router.stream.js`), the only code that
  calls adapters directly.
- **Provider Registry** — the frozen `REGISTRY` object inside `router.js` mapping provider
  names to adapter functions.

## 2. Architecture and execution flow

```
POST /ai/chat
  └─ enforcement pipeline (steps 1–5: artifact validation, request binding,
     nonce, anomaly, policy) — see docs/architecture/enforcement-flow.md
        │
        ▼ (only on ALLOW)
  assertExecutionInvariant(verifiedCtx)        [services/execution-guard.js]
        │
        ▼
  executeProviderCall(provider, body, verifiedCtx, traceMeta)   [services/execution.js]
        │  • resolveProvider(provider) — existence check only (services/providers.js)
        │  • builds meta = { requestId, requestHash, policyHash, tenantId }
        ▼
  routeProviderCall(provider, body, meta)      [services/providers/router.js]
        │  • re-checks the provider is enabled (getProviderConfig)
        │  • dispatches to the adapter
        │  • on retryable failure, attempts one failover hop
        ▼
  <adapter>(body, meta)                        [services/providers/<name>.js]
        │  a thin config object passed into the shared pipeline:
        ▼
  runProviderCall(spec, body, meta)            [services/providers/baseAdapter.js]
        │  1. model allowlist check
        │  2. outbound payload validation (messages, roles, size limits)
        │  3. (provider-specific) message transformation
        │  4. outbound HTTP call, with up to 1 in-adapter retry on
        │     PROVIDER_RATE_LIMITED / PROVIDER_UNAVAILABLE
        │  5. response validation + normalization
        ▼
  buildResponse(...)                           [services/providers/normalize.js]
        │  → frozen ProviderResponse: { output, model, provider, tokenUsage,
        │    executionMetadata: { responseId, latencyMs } }
        ▼
  aiChat.js route: aiText = response.output → { decision: 'EXECUTE', ... }
```

The streaming path (`POST /ai/chat` with `"stream": true`) mirrors this exactly, substituting
`executeStreamingProviderCall()` / `routeStreamingProviderCall()` and yielding `{ delta }`
chunks instead of returning one response. See [Streaming](#5-streaming) and
`docs/architecture/streaming.md`.

**No provider adapter is ever called directly by route code.** `execution.js` and
`execution.stream.js` are the only two call sites for the router, and the router is the only
call site for adapters. This is enforced by module structure, not a runtime check.

## 3. Registry, selection, and lifecycle

The provider registry (`REGISTRY` in `services/providers/router.js`) is a `Object.freeze`d map
built once at module load:

```js
{ openai: callOpenAI, anthropic: callAnthropic, gemini: callGemini,
  mistral: callMistral, llama: callLlama, local: callLocal }
```

- **Registration**: static — there is no runtime API to register a new provider. Adding a
  provider requires a code change to `router.js` (and `router.stream.js` for native streaming),
  `config.js`, and a new adapter file.
- **Discovery**: `listProviders()` returns all eight built-in names regardless of configuration;
  `listEnabledProviders()` (both in `router.js`, re-exported from `services/providers.js`)
  filters to only those currently enabled.
- **Selection**: per-request, via `artifact.payload.provider` — set at sign time (`POST /sign`)
  and never chosen by the `/ai/chat` caller directly. There is no implicit default when the
  deployment has more than one provider enabled — `/sign` returns `400 PROVIDER_REQUIRED` and
  the caller must choose explicitly. When exactly one provider is enabled, `/sign` auto-resolves
  to it if `payload.provider` is omitted (see `docs/api/overview.md#post-sign`).
- **Enablement (lifecycle)**: a provider is **enabled** the instant its required environment
  variable is present, checked fresh on every dispatch via `getProviderConfig(name).enabled`
  (`services/providers/config.js`) — there is no separate on/off flag, and enablement can only
  change by restarting the process (env vars are read once, into a frozen `CONFIGS` object, at
  module load).
- **Capability detection**: native streaming support is a static registry lookup
  (`STREAMING_REGISTRY` in `router.stream.js` — see [Streaming](#5-streaming)), not detected at
  runtime from the provider's response.
- **Startup requirement**: at least one provider must be enabled or the process exits
  (`NO_PROVIDER_CONFIGURED`, `server.js`). On success, `PROVIDERS_CONFIGURED` is logged with the
  enabled provider list.
- **Deprecated/removed providers**: none. All eight providers documented here are current. There
  is no legacy provider code path in `services/providers/`.

## 4. Failover

Implemented identically for non-streaming (`router.js`) and streaming (`router.stream.js`):

- Triggered only when the primary adapter throws with `.code` in
  `{ PROVIDER_UNAVAILABLE, PROVIDER_RATE_LIMITED, PROVIDER_TIMEOUT }`.
- The failover target is read from the *primary* provider's config:
  `getProviderConfig(primary).failoverProvider`, set from
  `PROVIDER_FAILOVER_<PROVIDER_NAME>` (uppercase provider name).
- Exactly **one hop**: failover from the failover target is not attempted (`_dispatch`'s
  `depth > 1` guard in `router.js`; the streaming router does not recurse into a second
  failover at all).
- The failover target is re-validated the same way as any dispatch — if it is unregistered or
  disabled, the failover attempt itself fails and the *failover's* error is what the caller
  ultimately sees (not the original error).
- The hop runs only after identity, provider scope and consent re-pass for the target. On success, the executing provider is recorded in the audit entry's unhashed `executionContext`; the hash-protected `provider` field is the requested one (hash-protecting the executing provider is audit schema v7, design decision D4). Log
  events: `PROVIDER_ROUTING_DECISION` → `PROVIDER_FAILOVER` → `PROVIDER_FAILOVER_SUCCESS` or
  `PROVIDER_FAILOVER_FAILED` (streaming: `PROVIDER_STREAM_*` equivalents).

## 5. Streaming

Five of the six providers have a **native** streaming adapter, registered in
`STREAMING_REGISTRY` (`services/providers/router.stream.js`):

| Provider | Streaming adapter | Mechanism |
|---|---|---|
| `openai` | `openai.stream.js` | OpenAI SDK v4, `stream: true` |
| `anthropic` | `anthropic.stream.js` | Native `fetch`, `Accept: text/event-stream`, manual SSE line parsing |
| `mistral` | `mistral.stream.js` | OpenAI SDK (Mistral base URL), `stream: true` |
| `llama` | `llama.stream.js` | OpenAI SDK (deployment-specific base URL), `stream: true` |
| `local` | `local.stream.js` | OpenAI SDK (local base URL), `stream: true` |

`mistral` and `llama` both expose an OpenAI-compatible chat completions API (§4.4/§4.5) — their
streaming adapters are a direct, minimal port of `local.stream.js`'s own proven
SDK-client-plus-`stream:true` recipe, differing only in configuration source and URL validation
(mirroring their respective non-streaming adapters exactly).'s classify-before-forward
semantic gate and mandatory final recheck apply to their output identically to every other
native-streaming provider — `streamEnforcer.js` has no provider-specific branching, so this
required no change to the semantic path itself.

`gemini` has **no native streaming adapter** and, after evaluation, stays that way: its
REST API has no OpenAI-compatible streaming shape — a native adapter would require a bespoke SSE
parser for the `streamGenerateContent` endpoint that this codebase has no live Gemini credential
to verify against the real service, unlike mistral/llama's exact reuse of an already-proven
client+flag recipe. A streaming request to gemini is transparently handled by
`_wrapNonStreaming()`: the full non-streaming call is made via `routeProviderCall()`, and the
complete response is yielded as a single `{ delta }` chunk. A `PROVIDER_STREAM_FALLBACK` event is
logged so this is observable. Callers still receive a valid SSE stream — just with one chunk
instead of many, delivered only once the full response is ready (no incremental delivery, no
latency benefit over the non-streaming endpoint for this provider specifically). See
`docs/architecture/streaming.md` for the full SSE event contract.

## 6. Common behavior across all providers

Every adapter (`services/providers/{openai,anthropic,gemini,mistral,llama,local}.js`, plus
`openai.stream.js`/`anthropic.stream.js`/`local.stream.js`) is a thin configuration object
executed by **one shared engine**, `services/providers/baseAdapter.js`. There is no per-adapter
copy of validation, retry, timeout/cancellation, error classification, or logging logic —
`baseAdapter.js` is the single place that implements all of it, and every adapter's `spec` object
supplies only what genuinely differs: endpoint, request/response shape transforms, transport
(the `openai` SDK vs. native `fetch`), and auth resolution. See
["Adding a new provider"](#adding-a-new-provider) below for the exact hook contract.

- **Outbound payload limits**: at most **50 messages** (`PROVIDER_REQUEST_REJECTED` if
  exceeded) and at most **32,768 bytes** of combined UTF-8 message content
  (`PROVIDER_REQUEST_REJECTED` if exceeded). Enforced once, by
  `baseAdapter.js`'s `validateOutboundMessages()`; per-provider extra rules (anthropic requires
  at least one non-`system` message, gemini requires at least one `user` message) are passed in
  as a small `extra(messages)` hook, not a separate validator.
- **Allowed message roles**: `system`, `user`, `assistant`. Any other role, a non-string
  `content`, a non-array `messages`, or an empty `messages` array →
  `PROVIDER_INVALID_REQUEST`.
- **Retry**: exactly `MAX_RETRIES = 1` additional attempt (2 attempts total) after a retryable
  failure (`PROVIDER_RATE_LIMITED`, `PROVIDER_UNAVAILABLE`), with the delay computed by
  `services/providers/retryBackoff.js` — **exponential backoff with full jitter**
  (`PROVIDER_RETRY_BASE_MS` default 250 ms, `PROVIDER_RETRY_MAX_MS` default 4000 ms,
  `PROVIDER_RETRY_JITTER` default on), not a fixed delay. This only applies to same-provider
  retries inside `runProviderCall()`; cross-provider failover (§4) is a separate mechanism.
  Streaming calls (`runProviderStream()`) have no retry loop at all — a failed native stream
  either succeeds via router-level failover or fails outright, exactly as before this
  consolidation.
- **Timeout**: configurable per provider via `<PROVIDER>_TIMEOUT_MS`, default `30000` ms. `runProviderCall()` runs every adapter under ONE deadline for the whole call - time to headers
  AND the body, whatever the transport (the SDK's own `timeout` and the fetch helper's timer cover only part of it): at the deadline the derived `AbortSignal` handed to the adapter is
  aborted (the socket is torn down) and the call fails as `PROVIDER_TIMEOUT` (`providerMayHaveExecuted`, so it is never re-sent or failed over). A stream has an IDLE deadline of the same length:
  no first chunk, or no chunk for that long, is `PROVIDER_TIMEOUT`; a stream that keeps delivering is not cut by it (the route bounds the total). The caller's own signal still wins:
  cancellation is `PROVIDER_CANCELLED`, not a timeout. Response bodies read by the fetch helper are size-bounded (8 MiB); an output over 4 MiB or containing a NUL is an invalid response.
- **Redirects**: never followed - fetch adapters use `redirect: 'error'`, SDK adapters use the SDK's own fetch with `redirect: 'manual'` (a 3xx is an ordinary error status), so credentials
  never travel to a redirect target.
- **Unusable answers**: a 200 whose body is not the expected document (not JSON, `null`, wrong shape) is `PROVIDER_INVALID_RESPONSE` (`providerMayHaveExecuted`): not retried, not failed over.
  Token counts a provider reports are accepted only as real numbers between 0 and 1,000,000,000; anything else is recorded as unknown.
- **Response normalization**: every adapter's successful path ends the same way inside
  `runProviderCall()` — `buildResponse()` (`services/providers/normalize.js`), which throws
  `PROVIDER_INVALID_RESPONSE` if the extracted text output is not a non-empty string, and
  otherwise returns a frozen `ProviderResponse`:
  ```
  { output: string, model: string|null, provider: string|null,
    tokenUsage: { inputTokens, outputTokens, totalTokens },
    executionMetadata: { responseId, latencyMs } }
  ```
- **Fail-closed**: every adapter validates its SSRF-relevant configuration (hardcoded URL or
  configured base URL) either at **module load time** (`openai`, `anthropic`, `gemini`,
  `mistral` — a bad configuration means the module throws and the process cannot start) or at
  **first-call time** (`llama`, `local` — a bad `*_BASE_URL` throws `PROVIDER_CONFIG_INVALID`
  the first time the provider is actually invoked, since the base URL isn't known until the
  env var is read). No provider silently falls back to an unvalidated destination. Each
  provider file still calls the `ssrf.js` validator itself at its own call site (so it stays
  independently testable/observable — see `ssrfDispatchIntegration.test.js`); only the
  emit-and-throw boilerplate around a failing result is shared, via `baseAdapter.js`'s
  `assertUrlSafeAtLoad()`.
- **Telemetry**: every adapter emits `PROVIDER_REQUEST_VALIDATED` → `PROVIDER_EXECUTION_START`
  → (`PROVIDER_EXECUTION_COMPLETE` or `PROVIDER_EXECUTION_FAILED` [+ `PROVIDER_RETRY_SCHEDULED`
  if retrying]) via `services/logger.js`. Streaming adapters emit the equivalent
  `PROVIDER_STREAM_START` → `PROVIDER_STREAM_FIRST_CHUNK` → `PROVIDER_STREAM_COMPLETE` sequence.

### Model allowlist extensibility and default model

`services/providers/config.js` is still the single authoritative allowlist (§ module doc
comment; unchanged), but it is no longer a pure code-only artifact — two environment-variable
families let an operator extend or configure it without a code change:

- **`PROVIDER_ALLOWED_MODELS_EXTRA_<PROVIDER_NAME>`** — comma-separated model identifiers ADDED
  to that provider's built-in allowlist (e.g. `PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI=gpt-5,gpt-5-mini`).
  Additive only — there is no syntax to remove or replace a built-in entry. Entries are trimmed;
  an empty entry (trailing comma) is dropped silently; an entry over 128 characters or containing
  a control character is dropped with a `PROVIDER_ALLOWED_MODELS_EXTRA_INVALID_ENTRY` WARN log
  (it could never validate against a real request either way — `modelValidation.js` rejects
  those same shapes before checking Set membership). A configured extension for `llama`/`local`
  is a no-op (`PROVIDER_ALLOWED_MODELS_EXTRA_IGNORED` WARN) because their built-in allowlist is
  already empty/unrestricted — adding entries to an empty Set would narrow it, the opposite of
  additive.
- **`PROVIDER_DEFAULT_MODEL_<PROVIDER_NAME>`** — overrides the model used when a request omits
  `model`. `openai`, `llama`, and `local` ship a non-null built-in default (`gpt-3.5-turbo`,
  unchanged by this mechanism — the only default ever documented or exercised by the SDK
  examples); `anthropic`/`gemini`/`mistral` ship `null` instead, meaning the caller must supply
  `model` explicitly. llama/local keep the literal despite never having "chosen" it as a sensible
  guess: their allowlist is empty (unrestricted, see §11/§12), so the string was never actually
  incompatible for them — unlike anthropic/gemini/mistral's strict, disjoint allowlists, which is
  the real incompatibility this mechanism exists to close. A malformed override is dropped
  (`PROVIDER_DEFAULT_MODEL_INVALID` WARN), falling back to the built-in value. **Load-time
  invariant**: a configured default (built-in or overridden) that is not a member of its own
  provider's effective allowlist fails the whole module load — the server cannot start — rather
  than silently shipping a request with a model that will only be discovered as wrong when a real
  call is attempted; skipped for an empty/unrestricted allowlist, where any non-empty default is
  valid by that provider's own policy.
- **`resolveDefaultModel(providerName)`** (exported from `config.js`) is the single function both
  `src/api/routes/aiChat.js` (non-streaming) and `src/streaming/streamEnforcer.js` (streaming)
  call to resolve an omitted model — replacing what were previously two independently-hardcoded
  `DEFAULT_MODEL = 'gpt-3.5-turbo'` constants, one per file, that could have drifted from each
  other. Because the function is per-provider, streaming and non-streaming always agree, and a
  provider with no configured default resolves to `null` — the existing model-allowlist
  validation (`modelValidation.js`) then rejects a null/missing model as
  `PROVIDER_MODEL_NOT_ALLOWED`, exactly like any other invalid model; no new error code exists.
- **The `public/console.html`/`public/js/console.js` "Execution Studio" tool's `#studio-model`
  input has its own, deliberately SEPARATE pre-fill hint** — a
  purely client-side convenience that saves a keystroke when trying the `local` provider in that
  UI. It is **not** authoritative and is **not** read by, or connected to, `resolveDefaultModel()`
  in any way: leaving the Studio field blank sends no `model` field at all, and the server's own
  resolution above applies exactly as it would for any other client. considered exposing the
  real server-side default to the browser (reunification) but rejected it — none of the existing
  GET routes (`/health`, `/ready`, `/public-key`) are a config-exposure surface, and creating a
  new, unauthenticated one to eliminate a single harmless UI hint was judged a disproportionate
  amount of new API surface for a cosmetic convenience. The two values may legitimately differ
  (e.g. an operator who sets `PROVIDER_DEFAULT_MODEL_LOCAL` to something other than
  `"qwen2.5:7b"`) — that is expected, not a bug, and does not affect actual execution.

See `services/providers/config.js`'s module doc comment for the complete parsing/precedence
contract, `services/providers/__tests__/config.test.js` for the server-side regression suite, and
`scripts/__tests__/consoleStudioModelHint.test.js` for the Studio-hint regression coverage.

### Adding a new provider

A new provider needs a `spec` object passed to `runProviderCall()` (non-streaming) and,
optionally, `runProviderStream()` (streaming) — see any existing adapter file for a complete
example. At minimum, supply:

| Hook | Purpose |
|---|---|
| `name` | canonical provider name used in every log event and in `buildResponse()` |
| `transport` | one of `TRANSPORTS.sdk` / `TRANSPORTS.sdkStream` / `TRANSPORTS.fetch` — selects the error-classification name set for that transport |
| `validate` | `{ extra? }` — an optional extra outbound-validation rule beyond the shared message/role/size checks |
| `transformRequest(body, ctx)` | build the provider-specific request payload |
| `execute(payload, ctx)` | perform the network call (via the SDK client or `fetchJSON()`) and return the raw response |
| `logFields(raw)` | fields merged into the `PROVIDER_EXECUTION_COMPLETE` log event (e.g. `responseId`, `usage`) |
| `parseResponse(raw, ctx)` | extract `{ output, model, tokenUsage, executionMetadata }` from the raw response |
| `beforeValidatedEmit(ctx)` / `getExecutionContext(ctx)` | optional auth/config hooks — see the ordering note in `baseAdapter.js`'s `runProviderCall()` doc comment |

No new provider needs to write its own retry loop, timeout handling, `AbortController` logic,
error classification, or structured logging — all of that is inherited automatically by calling
into `runProviderCall()`/`runProviderStream()`. The only code that should ever live in a new
provider file is what's listed in the table above, plus the provider's own SSRF/base-URL
validation call (see §6 "Fail-closed").

---

## 7. Provider: openai

**Purpose**: OpenAI Chat Completions API.
**Source**: `services/providers/openai.js` (+ `openai.stream.js` for streaming).

| | |
|---|---|
| Capabilities | Non-streaming and native streaming chat completions |
| Authentication | Bearer API key via the `openai` npm SDK client |
| Enabling variable | `OPENAI_API_KEY` |
| Timeout variable | `OPENAI_TIMEOUT_MS` (default `30000` ms) |
| Base URL | Hardcoded `https://api.openai.com/v1`; **not configurable** — `OPENAI_BASE_URL` is read only to emit `PROVIDER_BASE_URL_OVERRIDE_IGNORED` if set, then ignored |
| Model allowlist | `gpt-4`, `gpt-4-turbo`, `gpt-4-turbo-preview`, `gpt-4o`, `gpt-4o-mini`, `gpt-3.5-turbo`, `gpt-3.5-turbo-16k` — extensible via `PROVIDER_ALLOWED_MODELS_EXTRA_OPENAI` (§6, "Model allowlist extensibility") |
| Default model | `gpt-3.5-turbo` when `model` is omitted from a request; overridable via `PROVIDER_DEFAULT_MODEL_OPENAI` |
| Requirements | Valid, non-revoked OpenAI API key |
| Limitations | Same 50-message / 32,768-byte limits as all providers (§6); model must be in the effective allowlist (built-in + any configured extension) |

**Error normalization** (`_normalizeError`): `APIConnectionTimeoutError`/`ETIMEDOUT`/
`ECONNABORTED`/timeout-matching message → `PROVIDER_TIMEOUT`; HTTP 429 → `PROVIDER_RATE_LIMITED`;
401/403 → `PROVIDER_AUTH_FAILED`; 400/422 → `PROVIDER_INVALID_REQUEST`; ≥500 → `PROVIDER_UNAVAILABLE`;
`APIConnectionError`/`ECONNREFUSED`/`ENOTFOUND`/`ECONNRESET` → `PROVIDER_UNAVAILABLE`; anything
else → `PROVIDER_UNAVAILABLE` (default).

---

## 8. Provider: anthropic

**Purpose**: Anthropic Messages API.
**Source**: `services/providers/anthropic.js` (+ `anthropic.stream.js`).

| | |
|---|---|
| Capabilities | Non-streaming and native streaming (SSE) chat completions |
| Authentication | `x-api-key` header + `anthropic-version: 2023-06-01` header, via native `fetch` (no SDK dependency) |
| Enabling variable | `ANTHROPIC_API_KEY` |
| Timeout variable | `ANTHROPIC_TIMEOUT_MS` (default `30000` ms) |
| Other config | `ANTHROPIC_MAX_TOKENS` (default `4096`) — sent as `max_tokens` on every request; Anthropic requires this field |
| Base URL | Hardcoded `https://api.anthropic.com` + `/v1/messages`; not configurable (no override-ignored warning is emitted since no `ANTHROPIC_BASE_URL` variable is ever read) |
| Model allowlist | `claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`, `claude-3-5-sonnet-20241022`, `claude-3-5-haiku-20241022`, `claude-3-opus-20240229`, `claude-3-sonnet-20240229`, `claude-3-haiku-20240307` — extensible via `PROVIDER_ALLOWED_MODELS_EXTRA_ANTHROPIC` |
| Default model | None (built-in) — `model` must be supplied explicitly, unless an operator sets `PROVIDER_DEFAULT_MODEL_ANTHROPIC` |
| Requirements | Valid Anthropic API key; request must contain at least one non-`system` message (`PROVIDER_INVALID_REQUEST` otherwise) |
| Message transformation | `system`-role messages are extracted and joined into a top-level `system` string field — Anthropic's Messages API does not accept `role: "system"` inside the `messages` array |
| Limitations | Same 50-message / 32,768-byte limits as all providers (§6) |

**Error normalization**: `AbortError`/`ETIMEDOUT`/`ECONNABORTED`/timeout message → `PROVIDER_TIMEOUT`;
429 → `PROVIDER_RATE_LIMITED`; 401/403 → `PROVIDER_AUTH_FAILED`; 400/422 → `PROVIDER_INVALID_REQUEST`;
≥500 → `PROVIDER_UNAVAILABLE`; `ECONNREFUSED`/`ENOTFOUND`/`ECONNRESET`/fetch `TypeError` →
`PROVIDER_UNAVAILABLE`; default → `PROVIDER_UNAVAILABLE`.

---

## 9. Provider: gemini

**Purpose**: Google Gemini `generateContent` REST API.
**Source**: `services/providers/gemini.js`. **No streaming adapter exists** — evaluated and deliberately not implemented; streaming requests fall back to `_wrapNonStreaming()` (§5).

| | |
|---|---|
| Capabilities | Non-streaming chat completions only (native streaming: evaluated, not implemented — see below) |
| Authentication | API key as a `?key=` query parameter (not a header) |
| Enabling variable | `GEMINI_API_KEY` |
| Timeout variable | `GEMINI_TIMEOUT_MS` (default `30000` ms) |
| Base URL | Hardcoded `https://generativelanguage.googleapis.com`, API version `v1beta`; not configurable |
| Model allowlist | `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.0-flash`, `gemini-2.0-flash-lite`, `gemini-1.5-pro`, `gemini-1.5-flash` — extensible via `PROVIDER_ALLOWED_MODELS_EXTRA_GEMINI` |
| Default model | None (built-in) — `model` must be supplied explicitly, unless an operator sets `PROVIDER_DEFAULT_MODEL_GEMINI` |
| Requirements | Valid Gemini API key; request must contain at least one `user`-role message (`PROVIDER_INVALID_REQUEST` otherwise) |
| Message transformation | `assistant` role → `model` role (Gemini's term); `system`-role messages are joined and sent as `systemInstruction` rather than inline in `contents` |
| Limitations | No native streaming — every streaming request receives the complete response as a single SSE chunk, delivered only once generation finishes (no incremental delivery, no latency benefit over the non-streaming endpoint); same 50-message / 32,768-byte limits as all providers (§6); Gemini does not return a `responseId` — `executionMetadata.responseId` is always `null` for this provider |

**Error normalization**: identical pattern to Anthropic (native `fetch`-based) — timeout
patterns → `PROVIDER_TIMEOUT`; 429 → `PROVIDER_RATE_LIMITED`; 401/403 → `PROVIDER_AUTH_FAILED`;
400/422 → `PROVIDER_INVALID_REQUEST`; ≥500 or connection errors → `PROVIDER_UNAVAILABLE`.

---

## 10. Provider: mistral

**Purpose**: Mistral AI chat completions (OpenAI-compatible API).
**Source**: `services/providers/mistral.js` (+ `mistral.stream.js` for native streaming, added).

| | |
|---|---|
| Capabilities | Non-streaming **and** native streaming chat completions (streaming added) |
| Authentication | Bearer API key via the `openai` npm SDK client pointed at Mistral's base URL |
| Enabling variable | `MISTRAL_API_KEY` |
| Timeout variable | `MISTRAL_TIMEOUT_MS` (default `30000` ms) |
| Base URL | Defaults to `https://api.mistral.ai/v1`; **the one provider whose base URL is genuinely configurable** via `MISTRAL_BASE_URL` — validated against the same SSRF allowlist at module load (both the non-streaming and streaming adapter each validate independently); an invalid override throws `PROVIDER_CONFIG_INVALID` and the module fails to load |
| Model allowlist | `mistral-large-latest`, `mistral-medium-latest`, `mistral-small-latest`, `open-mixtral-8x7b`, `open-mixtral-8x22b`, `open-mistral-7b`, `codestral-latest`, `mistral-embed` — extensible via `PROVIDER_ALLOWED_MODELS_EXTRA_MISTRAL` |
| Default model | None (built-in) — `model` must be supplied explicitly, unless an operator sets `PROVIDER_DEFAULT_MODEL_MISTRAL` |
| Requirements | Valid Mistral API key |
| Limitations | Same 50-message / 32,768-byte limits as all providers (§6) |

**Error normalization**: identical logic to `openai.js` (both use the `openai` SDK) —
`APIConnectionTimeoutError`/timeout → `PROVIDER_TIMEOUT`; 429 → `PROVIDER_RATE_LIMITED`; 401/403
→ `PROVIDER_AUTH_FAILED`; 400/422 → `PROVIDER_INVALID_REQUEST`; ≥500 or `APIConnectionError`/
connection-refused-class errors → `PROVIDER_UNAVAILABLE`.

---

## 11. Provider: llama

**Purpose**: Llama-family models via any OpenAI-compatible chat completions API — cloud-hosted
(Groq, Together AI, Fireworks AI) or self-managed (llama.cpp, vLLM).
**Source**: `services/providers/llama.js` (+ `llama.stream.js` for native streaming, added).

| | |
|---|---|
| Capabilities | Non-streaming **and** native streaming chat completions (streaming added) |
| Authentication | Optional bearer key via the `openai` SDK client; if `LLAMA_API_KEY` is unset, the literal string `'llama'` is used as a placeholder (the SDK requires a non-empty `apiKey` even against deployments with no auth) |
| Enabling variable | `LLAMA_BASE_URL` (this, not an API key, is what enables the provider) |
| Optional variables | `LLAMA_API_KEY`, `LLAMA_TIMEOUT_MS` (default `30000` ms) |
| Base URL validation | Tried first against the strict public-provider validator (covers cloud-hosted deployments on an allowlisted-style HTTPS hostname); if that fails, tried against the relaxed local validator (permits private-network/`http://` destinations). Validated once, at first client construction (each of the non-streaming and streaming adapter maintains its own independent cached client and validation state) — an invalid URL throws `PROVIDER_CONFIG_INVALID`. |
| Model allowlist | **None** (empty set) — any non-empty string model name is accepted, since Llama deployment model names are deployment-specific. Operators wanting to restrict models must do so via policy, not provider config. `PROVIDER_ALLOWED_MODELS_EXTRA_LLAMA` is a documented no-op here — adding entries to an already-unrestricted allowlist would narrow it. |
| Default model | None (built-in) — deployment-specific model names cannot be guessed; an operator may set `PROVIDER_DEFAULT_MODEL_LLAMA` |
| Requirements | A reachable `LLAMA_BASE_URL` |
| Limitations | Same 50-message / 32,768-byte limits as all providers (§6); no model allowlist enforcement at the adapter layer |

**Error normalization**: identical logic to `openai.js`/`mistral.js` (all built on the `openai` SDK).

---

## 12. Provider: local

**Purpose**: Self-hosted local AI runtimes exposing an OpenAI-compatible chat completions API —
Ollama, llama.cpp server, LM Studio, Jan.ai, or any future runtime with the same contract.
**Source**: `services/providers/local.js` (+ `local.stream.js` — **this is one of the five
providers with native streaming support**, see §5).

| | |
|---|---|
| Capabilities | Non-streaming **and** native streaming chat completions |
| Authentication | Optional bearer key via the `openai` SDK client; if `LOCAL_API_KEY` is unset, the literal string `'local'` is used as a placeholder for the same SDK-requirement reason as `llama` |
| Enabling variable | `LOCAL_BASE_URL` |
| Optional variables | `LOCAL_API_KEY`, `LOCAL_TIMEOUT_MS` (default `30000` ms) |
| Base URL validation | The relaxed local validator only (`validateLocalProviderUrl`) — permits `http://` and private-network/localhost destinations by design, since this provider exists specifically for operator-controlled infrastructure. An unset `LOCAL_BASE_URL`, or one that fails even the relaxed check (unparseable, or a non-`http`/`https` scheme), throws `PROVIDER_CONFIG_INVALID` at first use. A one-time `LOCAL_PROVIDER_ENDPOINT_CONFIGURED` INFO event is logged on first successful validation, noting that the operator is responsible for the endpoint's security. |
| Model allowlist | **None** (empty set) — model names are runtime-specific (e.g. `llama3.2`, `mistral`, `phi3`); any non-empty string is accepted. `PROVIDER_ALLOWED_MODELS_EXTRA_LOCAL` is a documented no-op here — adding entries to an already-unrestricted allowlist would narrow it. |
| Default model | None (built-in) — operator-defined runtime model names cannot be guessed; an operator may set `PROVIDER_DEFAULT_MODEL_LOCAL` |
| Requirements | A reachable `LOCAL_BASE_URL` |
| Limitations | Same 50-message / 32,768-byte limits as all providers (§6); no model allowlist enforcement |

**Error normalization**: identical logic to `openai.js`/`mistral.js`/`llama.js`.

---

## 12a. Providers added in azure, bedrock, compat-<id>

**azure** (`services/providers/azure.js`, `azure.stream.js`). Azure OpenAI through the SDK's `AzureOpenAI` client. The request's `model` is the **deployment** name; the URL is
`{AZURE_OPENAI_ENDPOINT}/openai/deployments/{deployment}/chat/completions?api-version={AZURE_OPENAI_API_VERSION}`. Auth is the `api-key` header or a Microsoft Entra bearer token
(client-credentials flow against `login.microsoftonline.com`, cached until a minute before expiry, `services/providers/azureAuth.js`); Entra wins when both are set unless
`AZURE_OPENAI_AUTH=api-key`. The endpoint must be an `https://<resource>.openai.azure.com` or `<resource>.cognitiveservices.azure.com` name (anchored patterns in `ssrf.js`), is checked on
first use, and goes through the guarded agent. Streaming is supported.

**bedrock** (`services/providers/bedrock.js`, `sigv4.js`). AWS Bedrock Converse API (`POST https://bedrock-runtime.<region>.amazonaws.com/model/<modelId>/converse`), signed with an
in-repo SigV4 implementation verified against the published AWS signing examples. System messages become Converse `system` blocks; roles are merged to alternate; the conversation must
start with a user turn. Credentials are `BEDROCK_*` (deliberately not the ambient `AWS_*` names). No streaming (Converse streaming uses binary event-stream framing; a stream request is
served by the non-streaming path). Redirects are refused.

**compat-<id>** (`services/providers/compat.js`, `src/core/providers/compatRegistry.js`). OpenAI-compatible endpoints registered at runtime through `/v1/admin/providers`, see
`docs/api/overview.md`. Streaming is supported.

Status in the provider register: **simulated** - exercised against recorded/mocked responses and the official SigV4 examples, not yet against the live services (that is).
All fetch-based adapters now refuse HTTP redirects (`redirect: 'error'`).

**Cost accounting.** After every successful call the tokens the provider reported are counted in `qodiqa_provider_tokens_total{provider,direction}`, and - when a ROUTING rule in force carries a tariff for the executing provider (`pricing`, millionths of a currency per million tokens, optional `byModel`) - the cost in `qodiqa_provider_cost_micros_total{provider,currency}` and a `COST_ACCOUNTED` event (a BUDGET rule's own accounting takes precedence and is not duplicated). Nothing is invented: no usage or no tariff, no cost. `POST /v1/admin/providers/compare` ranks the providers (see `docs/api/overview.md`).

## 13. Error code reference

All codes below are set as `.code` on a thrown `Error` and propagate to the `/ai/chat` route,
which maps them to an HTTP status (see `docs/architecture/enforcement-flow.md` and `docs/api/overview.md` for
the full route-level mapping table).

| Code | Layer | Meaning |
|---|---|---|
| `MISSING_PROVIDER` | Route (`aiChat.js`) | `artifact.payload.provider` absent or empty |
| `PROVIDER_MODEL_NOT_ALLOWED` | Adapter | Requested model not in that provider's allowlist |
| `PROVIDER_INVALID_REQUEST` | Adapter | Outbound payload failed validation (missing/empty messages, disallowed role, non-string content, or — Anthropic/Gemini only — no non-system/user message) |
| `PROVIDER_REQUEST_REJECTED` | Adapter | Outbound payload exceeded size limits (§6) |
| `PROVIDER_AUTH_FAILED` | Adapter | Upstream HTTP 401/403, or (`openai`/`anthropic`/`gemini`/`mistral` only — defensive, should be unreachable since these providers are only dispatchable when enabled, which itself requires the key) API key missing at call time |
| `PROVIDER_RATE_LIMITED` | Adapter | Upstream HTTP 429 — retryable |
| `PROVIDER_TIMEOUT` | Adapter | Outbound call exceeded its configured timeout — retryable |
| `PROVIDER_UNAVAILABLE` | Adapter or Router | Upstream 5xx/network error (adapter), or the provider name is unregistered (router) — retryable |
| `PROVIDER_NOT_CONFIGURED` | Router | Provider registered but not enabled (missing API key or base URL) |
| `PROVIDER_CONFIG_INVALID` | Adapter (module load or first use), or `config.js` (module load) | A configured base URL failed SSRF/URL validation (adapter); or a configured/built-in default model is not a member of its own provider's effective allowlist — either fails the whole server startup, not just one provider |
| `PROVIDER_INVALID_RESPONSE` | Adapter (via `normalize.js`) | Raw upstream payload had no usable text output |
| `PROVIDER_RESPONSE_INVALID` | Route (`aiChat.js`) | Redundant post-normalization check — should be unreachable if the adapter's own `PROVIDER_INVALID_RESPONSE` check is working |
| `PROVIDER_SSRF_REJECTED` | Module load (`openai`/`anthropic`/`gemini`) | The hardcoded canonical base URL itself failed SSRF validation — indicates a code defect, not a runtime/config issue; the module throws and the process cannot start |

## 14. Security notes

See [`docs/security/THREAT_MODEL.md`](../security/THREAT_MODEL.md) (Boundary 5) and
 for
the full threat-model treatment. In summary:

- Provider destinations are never taken from the incoming request — only from the signed
  artifact's `provider` name (resolved against the static registry) and, for `mistral`/`llama`/
  `local`, from deployment-time environment variables.
- `openai`, `anthropic`, `gemini` (and `mistral` by default) are constrained to an explicit
  HTTPS hostname allowlist with IP literals and private-network hosts rejected.
- `llama` and `local` are an intentional, narrower-trust exception: they accept
  operator-configured HTTP and private-network destinations because they exist specifically for
  self-hosted/cloud-hosted deployments the operator controls. This is a deliberate design
  trade-off, not a gap.
- Provider API keys are read from environment variables only, never logged (redacted by
  `services/logSanitizer.js`), and never embedded in artifacts or audit records.
