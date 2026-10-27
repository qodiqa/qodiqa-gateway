# QODIQA Streaming Enforcement

**Component:** #38 — Streaming Enforcement
**Version:** 1.0.0
**Status:** Implemented

---

## Table of Contents

1. [Streaming Architecture Overview](#1-streaming-architecture-overview)
2. [Authorization Flow](#2-authorization-flow)
3. [Enforcement Lifecycle Diagram](#3-enforcement-lifecycle-diagram)
4. [Runtime State Management](#4-runtime-state-management)
5. [SSE Event Lifecycle](#5-sse-event-lifecycle)
6. [Cancellation Semantics](#6-cancellation-semantics)
7. [Provider Abstraction](#7-provider-abstraction)
8. [Security Guarantees](#8-security-guarantees)
9. [Fail-Closed Behavior](#9-fail-closed-behavior)
10. [Artifact Integration](#10-artifact-integration)
11. [Observability and Metrics](#11-observability-and-metrics)
12. [Performance Characteristics](#12-performance-characteristics)
13. [Operational Guidance](#13-operational-guidance)
14. [Troubleshooting](#14-troubleshooting)
15. [Output-Side Semantic Enforcement](#15-output-side-semantic-enforcement)

---

## 1. Streaming Architecture Overview

Streaming is a **response delivery mode**, not an alternative execution path. The QODIQA deterministic enforcement pipeline is identical for streaming and non-streaming requests. The fork occurs only after all five enforcement steps have passed, at the point where the response is delivered to the client.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         POST /ai/chat  { stream: true }                      │
└─────────────────────────────────────┬────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    INPUT VALIDATION  (unchanged)                              │
│                                                                              │
│  Content-Type guard → Zod body schema → artifact header parse               │
│  stream: z.boolean().optional() added to aiChatBodySchema                   │
└─────────────────────────────────────┬────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│               DETERMINISTIC ENFORCEMENT PIPELINE (unchanged)                 │
│                                                                              │
│  Step 1  validateBoundRequest() → Ed25519 signature verification            │
│  Step 2  validateBoundRequest() → request binding (requestHash)             │
│  Step 3  validateBoundRequest() → nonce registration (replay protection)    │
│  Step 4  validateBoundRequest() → anomaly detection                         │
│  Step 5  checkPolicy()          → IP block / consent / rate limit / time    │
│                                                                              │
│  Any failure → JSON BLOCK, HTTP 200 by default (SSE headers never sent)     │
└─────────────────────────────────────┬────────────────────────────────────────┘
                                      │ All 5 steps pass
                          ┌───────────┴───────────┐
                          │                       │
               stream:false (default)       stream:true
                          │                       │
                          ▼                       ▼
               ┌──────────────────┐   ┌───────────────────────┐
               │  _executeAI()    │   │  streamResponse()      │
               │  (existing path) │   │  streamEnforcer.js     │
               └──────────────────┘   └───────────────────────┘
```

### Module inventory

| Module | Purpose |
|---|---|
| `src/api/routes/aiChat.js` | Route handler; forks on `stream === true`; runs `_enforceAndStream()` |
| `src/streaming/streamEnforcer.js` | SSE lifecycle manager; called only after all 5 steps pass |
| `src/streaming/streamRegistry.js` | In-memory session tracker; pure state, no I/O |
| `services/execution.stream.js` | Streaming execution layer; asserts invariant before first yield |
| `services/providers/router.stream.js` | Streaming provider router; handles native adapters and fallback |
| `services/providers/openai.stream.js` | OpenAI native streaming adapter (SDK v4) |
| `services/providers/anthropic.stream.js` | Anthropic native streaming adapter (native fetch + SSE) |
| `services/providers/local.stream.js` | Local model streaming adapter (OpenAI SDK) |

---

## 2. Authorization Flow

All five enforcement steps run synchronously in `_enforceAndStream()` before `streamResponse()` is called. Any step failure returns a JSON `{decision:'BLOCK', reason, details, requestId}` response — HTTP 200 in the default `QODIQA_BLOCK_HTTP_MODE=decision`, the class status (e.g. 403) only with `QODIQA_BLOCK_HTTP_MODE=status` (`src/api/blockHttpStatus.js`), and 429 + `Retry-After` for `RATE_LIMITED` (`src/api/routes/aiChat.js`). SSE headers are not sent until all steps pass and `streamResponse()` invokes `res.flushHeaders()`.

```
Client                    aiChat.js                  validateBoundRequest()   checkPolicy()
  │                          │                                │                     │
  │── POST /ai/chat ─────────►                               │                     │
  │   { stream: true }       │                               │                     │
  │                          │── Step 1: sig verify ────────►│                     │
  │                          │── Step 2: request binding ───►│                     │
  │                          │── Step 3: nonce register ────►│                     │
  │                          │── Step 4: anomaly detect ────►│                     │
  │                          │◄─ result ────────────────────►│                     │
  │                          │                                                     │
  │                          │── Step 5: policy check ─────────────────────────►  │
  │                          │◄─ policyResult ─────────────────────────────────◄  │
  │                          │                                                     │
  │                          │  [any failure → return res.status(blockHttpStatus(reason)).json()]
  │◄── 200 BLOCK ────────────│
  │                          │
  │                          │  [all pass → call streamResponse()]
  │                          │
  │◄── HTTP 200 ─────────────│  (status line only; body is SSE stream)
  │◄── Content-Type: text/event-stream
  │◄── stream_started event ─│
  │◄── chunk_forwarded ... ──│
  │◄── stream_completed ─────│
  │◄── [DONE] ───────────────│
```

The `verifiedCtx` object passed to `executeStreamingProviderCall()` is produced only inside `_enforceAndStream()` and only after all five steps pass:

```js
const verifiedCtx = Object.freeze({
  verified:    true,
  requestHash: artifact.payload.requestHash,
  artifactId:  requestId,
  tenantId,
});
```

This object is frozen. `assertExecutionInvariant()` is called as the first operation in `executeStreamingProviderCall()` to re-verify it before any provider call is made.

---

## 3. Enforcement Lifecycle Diagram

```
_enforceAndStream()                streamResponse()              executeStreamingProviderCall()
        │                                 │                                  │
        │── Steps 1–5 ──────────────────► │                                  │
        │                                 │                                  │
        │  [enforcement failure]           │                                  │
        │── BLOCK JSON (200 default) ──   │                                  │
        │                                 │                                  │
        │  [all steps pass]               │                                  │
        │────────────────────────────────►│                                  │
        │                                 │── register streamId ────────────  │
        │                                 │── set AbortController ─────────   │
        │                                 │── set timeout timer ────────────  │
        │                                 │── attach req.on('close') ───────  │
        │                                 │── set SSE headers ──────────────  │
        │                                 │── res.flushHeaders() ───────────  │
        │                                 │── emit stream_started ──────────  │
        │                                 │                                  │
        │                                 │── assertExecutionInvariant() ───►│
        │                                 │                                  │
        │                                 │  for await (chunk of generator): │
        │                                 │    ◄── { delta } ───────────────◄│
        │                                 │    ── recordChunk() ─────────────│
        │                                 │    ── inc metrics ───────────────│
        │                                 │    ── emit chunk_forwarded ──────│
        │                                 │                                  │
        │                                 │  [generator exhausts normally]   │
        │                                 │── emit stream_completed ─────────│
        │                                 │                                  │
        │                                 │  [abort / error / timeout]       │
        │                                 │── emit stream_cancelled ─────────│
        │                                 │                                  │
        │                                 │── emit [DONE] ───────────────────│
        │                                 │── finalizeStream() ──────────────│
        │                                 │── write audit record ────────────│
        │                                 │── update metrics ────────────────│
        │                                 │── res.end() ─────────────────────│
```

---

## 4. Runtime State Management

Session state is maintained in `src/streaming/streamRegistry.js` — a module-level singleton `Map`. No I/O is performed. All methods are infallible.

### Fields tracked per session

| Field | Type | Set by | Updated by |
|---|---|---|---|
| `streamId` | `string` (UUID) | `createStream()` | — |
| `requestId` | `string` | `createStream()` | — |
| `artifactId` | `string` | `createStream()` | — |
| `provider` | `string` | `createStream()` | — |
| `model` | `string` | `createStream()` | — |
| `tenantId` | `string` | `createStream()` | — |
| `startTime` | `number` (ms) | `createStream()` | — |
| `completionTime` | `number` (ms) | — | `finalizeStream()` |
| `bytesStreamed` | `number` | `createStream()` (0) | `recordChunk()` |
| `chunksStreamed` | `number` | `createStream()` (0) | `recordChunk()` |
| `terminationReason` | `string` | `createStream()` (null) | `finalizeStream()` |
| `status` | `string` | `'active'` | `finalizeStream()` |

### Lifecycle

```
createStream()          recordChunk() × N       finalizeStream()
      │                       │                       │
      ▼                       ▼                       ▼
  _active.set()      state.bytesStreamed +=N    state.completionTime = now
                     state.chunksStreamed++      state.terminationReason = ...
                                                 state.status = ...
                                                 _active.delete(streamId)
                                                 return { ...state }  ← snapshot
```

`finalizeStream()` removes the session from the active map and returns a final snapshot. This snapshot is used by `streamEnforcer.js` for the audit record `byteCount` field.

---

## 5. SSE Event Lifecycle

**Native framing:** every frame carries a
native `event:` field and a native `id:` field (`<streamId>:<sequence>`,
monotonically increasing) ahead of `data:`; the first frame also carries a
`retry: 3000` hint. The `event:` field's value matches the `event` property
still present in the JSON `data:` payload — kept for one deprecation cycle
so any consumer that only reads `data:` (as both bundled SDKs did before
this remediation) keeps working unmodified. `[DONE]` remains a bare,
data-only sentinel with no native `event:` field of its own (OpenAI-style
convention, not something this remediation changes) but still carries a
native `id:` line.

### Event sequence (normal completion)

```
retry: 3000
event: stream_started
id: <streamId>:0
data: {"event":"stream_started","streamId":"...","requestId":"...","provider":"openai","model":"gpt-4o-mini","aiDisclosure":{"aiGenerated":true,"provider":"openai","model":"gpt-4o-mini","notice":"This response was generated by an AI system."}}\n\n
event: chunk_forwarded
id: <streamId>:1
data: {"event":"chunk_forwarded","delta":"Hello","index":0}\n\n
event: chunk_forwarded
id: <streamId>:2
data: {"event":"chunk_forwarded","delta":" world","index":1}\n\n
event: stream_completed
id: <streamId>:3
data: {"event":"stream_completed","streamId":"...","requestId":"...","chunksTotal":2,"bytesTotal":11,"durationMs":142}\n\n
id: <streamId>:4
data: [DONE]\n\n
```

### Event sequence (provider error)

```
retry: 3000
event: stream_started
id: <streamId>:0
data: {"event":"stream_started","streamId":"...","requestId":"...","provider":"openai","model":"gpt-4o-mini","aiDisclosure":{"aiGenerated":true,"provider":"openai","model":"gpt-4o-mini","notice":"This response was generated by an AI system."}}\n\n
event: chunk_forwarded
id: <streamId>:1
data: {"event":"chunk_forwarded","delta":"Partial","index":0}\n\n
event: stream_cancelled
id: <streamId>:2
data: {"event":"stream_cancelled","streamId":"...","reason":"PROVIDER_TIMEOUT","requestId":"..."}\n\n
id: <streamId>:3
data: [DONE]\n\n
```

### Event sequence (client disconnect / timeout)

```
event: stream_started
id: <streamId>:0
data: {"event":"stream_started",...}\n\n
event: chunk_forwarded
id: <streamId>:1
data: {"event":"chunk_forwarded","delta":"...","index":0}\n\n
[connection drops or timeout fires]
event: stream_cancelled
id: <streamId>:2
data: {"event":"stream_cancelled","streamId":"...","reason":"CLIENT_DISCONNECT","requestId":"..."}\n\n
id: <streamId>:3
data: [DONE]\n\n
```

### Event field reference

| Event | Field | Type | Description |
|---|---|---|---|
| `stream_started` | `streamId` | string | Unique session identifier |
| `stream_started` | `requestId` | string | Correlates to artifact and audit record |
| `stream_started` | `artifactId` | string | Same as `requestId` for V2 artifacts |
| `stream_started` | `provider` | string | Provider name from artifact payload |
| `stream_started` | `model` | string | Model name used for this session |
| `stream_started` | `aiDisclosure` | object | (EU AI Act Art. 50): `{ aiGenerated: true, provider, model, notice }`, same as the JSON EXECUTE response; the stream also carries the header `X-QODIQA-AI-Generated: true` |
| `chunk_forwarded` | `delta` | string | Incremental text from provider |
| `chunk_forwarded` | `index` | number | 0-based sequential chunk index |
| `stream_completed` | `chunksTotal` | number | Total chunks forwarded |
| `stream_completed` | `bytesTotal` | number | Total bytes forwarded |
| `stream_completed` | `durationMs` | number | Wall-clock duration of session |
| `stream_cancelled` | `reason` | string | `CLIENT_DISCONNECT`, `STREAM_TIMEOUT`, `OUTPUT_TOO_LARGE`, `SEMANTIC_OUTPUT_BLOCKED`, `SEMANTIC_OUTPUT_BLOCKED_FINAL`, the provider's error code, or `PROVIDER_ERROR` when the provider error has no code (`src/streaming/streamEnforcer.js`). The audit DECISION's `terminationReason` can additionally be `AUDIT_UNREPRESENTABLE_TEXT` when the provider's error code is not representable in the mirror. |
| `[DONE]` | — | — | Raw sentinel; always the final event |

### Invariants

- `stream_started` is always the first event. No chunk is emitted before it.
- `[DONE]` is always the last event, regardless of termination path.
- Exactly one terminal event (`stream_completed` or `stream_cancelled`) precedes `[DONE]`.
- `chunk_forwarded` events are strictly ordered by `index` (0, 1, 2, …).
- The native `id:` field is strictly monotonically increasing across every
  frame in a session, including `[DONE]`.
- `retry:` appears only once, on the `stream_started` frame.

---

## 6. Cancellation Semantics

Cancellation is coordinated through a single `AbortController` shared between the timeout timer and the client-disconnect listener. Both abort paths funnel to the same signal.

```
                    ┌─────────────────────────────┐
                    │       AbortController        │
                    │   ac.abort(reason)           │
                    └───────────┬─────────────────┘
                                │
             ┌──────────────────┼──────────────────┐
             │                  │                  │
     ┌───────▼──────┐   ┌───────▼──────┐   ┌──────▼──────┐
     │   Timeout    │   │   Client     │   │  Provider   │
     │   timer      │   │  disconnect  │   │  AbortError │
     │              │   │              │   │             │
     │ ac.abort(    │   │ req.on(      │   │ generator   │
     │  'stream_    │   │  'close',    │   │ throws      │
     │   timeout')  │   │  fn)         │   │ AbortError  │
     └──────────────┘   └──────────────┘   └─────────────┘
             │                  │                  │
             └──────────────────▼──────────────────┘
                      checked at top of every
                      chunk loop iteration
                      if (ac.signal.aborted) → break
```

### Termination reason mapping

| Cause | `ac.signal.reason` | `terminationReason` | Audit `decision` |
|---|---|---|---|
| Timeout | `'stream_timeout'` | `STREAM_TIMEOUT` | `BLOCK` |
| Client disconnect | `'client_disconnect'` | `CLIENT_DISCONNECT` | `BLOCK` |
| Provider `AbortError` | (signal already aborted) | same as above | `BLOCK` |
| Provider error | — (not an abort) | `err.code \|\| 'PROVIDER_ERROR'` | `BLOCK` |
| Normal completion | — | `COMPLETE` | `ALLOW` |

### Cleanup guarantees

Regardless of termination path, `streamEnforcer.js` always executes the cleanup block:

1. `clearTimeout(_timeoutId)` — prevents timer from firing after stream ends
2. `req.off('close', _onClientClose)` — removes listener
3. `streamRegistry.finalizeStream(streamId, ...)` — removes session from active map
4. Audit record written
5. Metrics decremented / incremented
6. `res.end()` called

---

## 7. Provider Abstraction

All streaming calls are routed through `services/providers/router.stream.js`. The router is provider-agnostic: it consults a registry of native streaming handlers and falls back to wrapping the non-streaming adapter for providers without native support.

```
routeStreamingProviderCall(provider, body, meta, signal)
          │
          ├── getProviderConfig(provider)
          │     not found / disabled → throw PROVIDER_NOT_CONFIGURED
          │
          ├── STREAMING_REGISTRY[provider]
          │     found (openai / anthropic / local) → yield* nativeHandler(body, meta, signal)
          │     not found (gemini / mistral / llama) → yield* _wrapNonStreaming(provider, body, meta)
          │                                             (yields full response as one chunk)
          │
          └── on retryable error (PROVIDER_UNAVAILABLE / RATE_LIMITED / TIMEOUT)
                if config.failoverProvider set:
                  try failover provider (native if available, wrapped otherwise)
                else:
                  rethrow original error
```

### Native streaming adapters

| Provider | Adapter | Transport |
|---|---|---|
| `openai` | `openai.stream.js` | OpenAI SDK v4, `stream: true` |
| `anthropic` | `anthropic.stream.js` | Native `fetch`, `Accept: text/event-stream`, SSE line parser |
| `local` | `local.stream.js` | OpenAI SDK (local base URL), `stream: true` |

### Non-streaming fallback

Providers without a native streaming adapter (`gemini`, `mistral`, `llama`) are handled by `_wrapNonStreaming()`, which calls `routeProviderCall()` (the existing non-streaming path) and yields the complete response text as a single `{ delta }` chunk. A `PROVIDER_STREAM_FALLBACK` log event is emitted to record that fallback occurred.

### AbortSignal threading

All native adapters receive the caller's `AbortSignal`. For Anthropic, where Node 18 does not support `AbortSignal.any()`, a `_composeSignals(a, b)` helper is used to merge the per-provider timeout signal with the caller signal.

---

## 8. Security Guarantees

### Authorization always precedes the first token

`streamResponse()` is only callable from `_enforceAndStream()`, which is only called after all five enforcement steps pass. `streamResponse()` is not exported or reachable from outside `aiChat.js`. The first SSE event (`stream_started`) is emitted only inside `streamResponse()`, after `res.flushHeaders()` confirms all headers are set — which can only happen after authorization is complete.

### Execution invariant re-assertion

`assertExecutionInvariant(verifiedCtx, 'executeStreamingProviderCall')` is the first statement in `executeStreamingProviderCall()`. It independently verifies:

- `verifiedCtx.verified === true`
- `verifiedCtx.requestHash` is a 64-character hex string
- `verifiedCtx.artifactId` is a non-empty string
- `verifiedCtx.tenantId` is a non-empty string

If any check fails, `UNVERIFIED_EXECUTION_ATTEMPT` is thrown and logged at `CRITICAL` level before any provider call. This is a second layer of defence that is independent of the route handler.

### Streamed content is never logged

The `delta` field from each chunk is written to the SSE wire and used only for its byte length (for metrics and audit counters). It is never passed to `emit()`, never stored in `streamRegistry`, and never included in the audit record. The security invariant is tested by `streaming.test.js` test case "chunk delta content does not appear in audit executionContext".

### Cryptographic link preserved

The streaming audit record carries `artifact.payload.requestHash` and `artifact.signature` — the same fields used in the non-streaming audit path. The cryptographic chain is unbroken.

### Evidentiary Guarantees Gap (Streaming vs. Non-Streaming)

Streaming execution passes through the identical enforcement pipeline as non-streaming execution (Section 2), and its audit record carries the identical cryptographic chain (above). It does **not**, however, provide identical evidentiary content or identical reliability guarantees. An operator or auditor relying on streaming audit records should be aware of four specific narrowings, none of which weaken enforcement itself:

- **No token usage.** `tokenUsage` is always `null` on streaming audit records — SSE provider adapters do not return usage figures in the incremental chunk stream (see "Audit record shows `tokenUsage: null`" in Section 13/Operational Guidance for the field-level detail).
- **No streamed-content audit.** The `delta` field of each chunk is written to the SSE wire and used only for its byte length; it is never logged, never stored in `streamRegistry`, and never included in the audit record (see "Streamed content is never logged," above). The audit record therefore evidences that a request was authorized and executed, and how many bytes were streamed, but not the streamed content itself.
- **No idempotency-key support.** A request carrying both `Idempotency-Key` and `"stream": true` is rejected outright with `IDEMPOTENCY_STREAMING_UNSUPPORTED` (HTTP 400) before enforcement begins — an SSE stream has no single response body to cache and replay, so streaming requests carry no exactly-once execution guarantee the way non-streaming idempotency-keyed requests do (see `docs/api/overview.md` and `docs/architecture/IDEMPOTENCY_KEY.md` for the non-streaming behavior this does not extend to).
- **Weaker output-safety guarantee than non-streaming.** Non-streaming classifies the complete response before any of it is ever written to the HTTP response — a BLOCK means zero bytes reach the caller. Streaming forwards chunks incrementally as they clear a bounded, interval-based check (§15.3/§15.6), and its mandatory end-of-stream recheck (§15.7) can only correct the audit trail after the fact, not withhold content already sent over an open SSE connection. See §15.6–§15.7 for the full mechanics and  for the evaluated alternatives and the design decision.

These are documented, permanent characteristics of SSE delivery, not defects pending a fix — a compliance or forensic process that requires token-usage figures, full content evidence, exactly-once execution guarantees, or a zero-leaked-content output-safety guarantee should use the non-streaming endpoint.

---

## 9. Fail-Closed Behavior

Every failure mode terminates the stream immediately and writes a `BLOCK` audit record.

| Failure | Mechanism | Audit decision |
|---|---|---|
| Enforcement step 1–5 fails | Returns a JSON BLOCK before SSE headers are sent — HTTP 200 in the default `QODIQA_BLOCK_HTTP_MODE=decision`, the block-class status with `=status` (`src/api/blockHttpStatus.js`) | Existing BLOCK audit via `_writeAuditBlock()` |
| Provider disconnects / throws | `catch (err)` in chunk loop; `stream_cancelled` SSE event | `BLOCK` |
| Client disconnects | `req.on('close')` → `ac.abort()` → loop break on next chunk | `BLOCK` |
| Timeout | `setTimeout` → `ac.abort()` → loop break on next chunk | `BLOCK` |
| Execution invariant fails | `assertExecutionInvariant()` throws before first yield | `BLOCK` (via provider error path) |
| Provider not configured | `getProviderConfig()` returns disabled; throws before first yield | `BLOCK` (via provider error path) |
| Missing `provider` in artifact | `streamEnforcer.js` provider field guard; returns 400 JSON | No SSE emitted |

In all cases:

- `res.end()` is always called.
- `streamRegistry.finalizeStream()` is always called.
- `streamingActiveStreams` gauge is always decremented.
- One and only one audit record is written per session.

---

## 10. Artifact Integration

A single audit record is written per streaming session, after stream termination, by `_writeAuditStreamRecord()` in `streamEnforcer.js`.

### Audit record structure

```js
{
  artifactId:         requestId,           // matches artifact.payload.requestHash UUID
  inputHash:          artifact.payload.requestHash,
  decision:           'ALLOW' | 'BLOCK',   // ALLOW only on normal completion
  signature:          artifact.signature,
  requestHash:        artifact.payload.requestHash,
  policyHash:         policyHash,
  verificationResult: true | false,
  tenantId:           tenantId,
  executionContext: {
    stage:            'PROVIDER_EXECUTION',
    provider:         provider,
    responseId:       streamId,            // streaming session UUID
    model:            model,
    tokenUsage:       null,                // not available from SSE adapters
    streamId:         streamId,
    startTimestamp:   startTime,           // ms since epoch
    endTimestamp:     Date.now(),          // ms since epoch
    durationMs:       durationMs,
    chunkCount:       chunkIndex,          // number of deltas forwarded
    byteCount:        finalState.bytesStreamed,
    completionStatus: 'COMPLETE' | 'CLIENT_DISCONNECT' | 'STREAM_TIMEOUT' | 'PROVIDER_ERROR' | ...,
    terminationReason: terminationReason,
  },
}
```

### When the audit record is written

The audit append occurs after `res.end()` would be called in the normal flow but is placed before it in the code to ensure the record is written even if `res.end()` throws. The `already_executed` guard in the audit log prevents duplicate entries if `_writeAuditStreamRecord()` is somehow called twice for the same session.

### Decision mapping

| Stream outcome | `decision` | `verificationResult` |
|---|---|---|
| Generator exhausted normally | `ALLOW` | `true` |
| Client disconnect | `BLOCK` | `false` |
| Timeout | `BLOCK` | `false` |
| Provider error | `BLOCK` | `false` |

---

## 11. Observability and Metrics

Nine Prometheus-format metrics are exported from `src/observability/metrics.js`. All are in-memory, infallible, and follow the `qodiqa_streaming_*` naming convention.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `qodiqa_streaming_active_streams` | Gauge | — | Currently active SSE sessions |
| `qodiqa_streaming_completed_total` | Counter | `termination_reason` | Sessions completed normally |
| `qodiqa_streaming_cancelled_total` | Counter | `reason` | Sessions cancelled (disconnect / timeout / policy) |
| `qodiqa_streaming_rejected_total` | Counter | `reason` | Requests rejected at enforcement (before SSE) |
| `qodiqa_streaming_enforcement_failures_total` | Counter | — | Mid-stream enforcement failures |
| `qodiqa_streaming_bytes_total` | Counter | — | Total bytes of AI output forwarded |
| `qodiqa_streaming_chunks_total` | Counter | — | Total SSE chunks forwarded |
| `qodiqa_streaming_duration_ms` | Histogram | — | Session end-to-end duration |
| `qodiqa_streaming_provider_latency_ms` | Histogram | — | Time from session start to first chunk |

### Update points

| Metric | Incremented at |
|---|---|
| `streamingActiveStreams` | `+1` after `res.flushHeaders()` / `-1` after `res.end()` |
| `streamingChunksTotal` | `+1` per chunk in the forwarding loop |
| `streamingBytesTotal` | `+byteLen` per chunk |
| `streamingProviderLatencyMs` | Observed on first chunk (latency from `startTime`) |
| `streamingCompletedTotal` | `+1` on normal completion (label: `termination_reason="COMPLETE"`) |
| `streamingCancelledTotal` | `+1` on any non-normal termination (label: `reason=<reason>`) |
| `streamingEnforcementFailuresTotal` | `+1` on provider error (mid-stream) |
| `streamingRejectedTotal` | `+1` in `_enforceAndStream()` when enforcement blocks |
| `streamingDurationMs` | Observed after `res.end()` |

### Structured log events

| Event name | Level | Emitted at |
|---|---|---|
| `STREAM_STARTED` | `INFO` | After `stream_started` SSE event |
| `STREAM_PROVIDER_ERROR` | `WARN` | On provider error in chunk loop |
| `STREAM_AUDIT_RECORDED` | `INFO` | After audit append succeeds |
| `STREAM_TERMINATED` | `INFO` | After `res.end()` |
| `PROVIDER_STREAM_ROUTING_DECISION` | `INFO` | In router, before dispatch |
| `PROVIDER_STREAM_FALLBACK` | `INFO` | When wrapping non-streaming provider |
| `PROVIDER_STREAM_FAILOVER` | `WARN` | When failover is attempted |
| `PROVIDER_STREAM_FAILOVER_SUCCESS` | `INFO` | When failover succeeds |
| `PROVIDER_STREAM_FAILOVER_FAILED` | `WARN` | When failover also fails |

---

## 12. Performance Characteristics

### Memory usage is O(1) per active stream

The chunk loop processes one `{ delta }` object at a time. Each delta is:
1. Written immediately to the SSE wire via `res.write()`.
2. Measured for byte length.
3. Discarded.

No accumulator array is built. No complete response buffer exists at any point. The only per-session memory beyond the `streamRegistry` entry is the `chunkIndex` counter.

### Incremental forwarding

SSE response headers include:
- `Content-Type: text/event-stream` — enables SSE framing
- `Cache-Control: no-cache, no-transform` — disables proxy caching and transform
- `X-Accel-Buffering: no` — disables nginx proxy buffering
- `Connection: keep-alive` — keeps the TCP connection open

`res.flushHeaders()` is called before the chunk loop, ensuring HTTP headers (and the connection itself) reach the client before the first chunk arrives from the provider.

### Provider-side streaming

Native streaming adapters use provider SDKs' built-in streaming mechanisms:
- OpenAI: `client.chat.completions.create({ stream: true })` returns an async iterable
- Anthropic: native `fetch` with `Accept: text/event-stream`; response body read via `ReadableStream.getReader()` with incremental SSE line parsing

Bytes are consumed from the provider as they arrive and forwarded without any intermediate buffering.

### Timeout behavior

The stream timeout (`STREAM_MAX_DURATION_MS`, default 300,000 ms) covers the entire session including time-to-first-chunk. It does not restart per chunk. Slow providers that hold the connection open indefinitely are guaranteed to be terminated.

The timeout timer is created with `.unref()` where available, so it does not prevent Node.js process exit during testing.

---

## 13. Operational Guidance

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `STREAM_MAX_DURATION_MS` | `300000` | Maximum duration of a single streaming session (ms). Sessions exceeding this are terminated with `STREAM_TIMEOUT`. |
| `AI_CHAT_TIMEOUT_MS` | `30000` | Request-level timeout in `_enforceAndStream()` for the enforcement steps before streaming begins. |

### Enabling streaming

Send `stream: true` in the JSON body of a `POST /ai/chat` request:

```json
{
  "prompt": "Explain quantum entanglement",
  "model":  "gpt-4o-mini",
  "stream": true
}
```

The `/ai/chat/stream` and `/v1/ai/chat/stream` paths are aliases of `/ai/chat` (same handler); streaming is selected only by `"stream": true` in the (signed) body, on any alias — a body without it gets a JSON response on the `/stream` paths too.

The `x-qodiqa-artifact` header is required on all requests regardless of `stream`.

### Capacity planning

- `qodiqa_streaming_active_streams` tracks concurrent sessions. Each session holds one open TCP connection and one entry in the stream registry map.
- `qodiqa_streaming_bytes_total` and `qodiqa_streaming_duration_ms` are the primary indicators of throughput and session health.
- Sessions that terminate with `reason="STREAM_TIMEOUT"` in `qodiqa_streaming_cancelled_total` indicate that `STREAM_MAX_DURATION_MS` may need to be increased for long-running provider calls, or that provider latency is degraded.

### Provider failover

Configure `failoverProvider` in the provider config to enable automatic streaming failover. If the primary provider fails with a retryable error (`PROVIDER_UNAVAILABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_TIMEOUT`), the router will attempt the failover provider. A `PROVIDER_STREAM_FAILOVER` log event is emitted when failover is attempted.

---

## 14. Troubleshooting

### Client receives `stream_cancelled` immediately after `stream_started`

**Cause:** The provider failed before yielding any chunks.
**Check:** `STREAM_PROVIDER_ERROR` log event. The `reason` field contains the provider error code.
**Resolution:** Check provider API key, network connectivity, and provider status.

### Stream terminates with `reason: "STREAM_TIMEOUT"`

**Cause:** The session exceeded `STREAM_MAX_DURATION_MS`.
**Check:** `STREAM_TERMINATED` log event; `qodiqa_streaming_cancelled_total{reason="STREAM_TIMEOUT"}` counter.
**Resolution:** Increase `STREAM_MAX_DURATION_MS` or investigate provider latency via `qodiqa_streaming_provider_latency_ms` histogram.

### Enforcement blocks before SSE headers are sent (JSON BLOCK response)

**Cause:** One of the five enforcement steps failed.
**Check:** The JSON body is `{"decision":"BLOCK","reason":…}` — HTTP 200 in the default `QODIQA_BLOCK_HTTP_MODE=decision`, the block-class status with `=status` (`src/api/blockHttpStatus.js`). Cross-reference with the audit log for `stage` and `reason`.
**Note:** A pre-stream BLOCK on a streaming request is functionally identical to one on a non-streaming request — all enforcement ran, authorization was denied, no SSE content was sent.

### `qodiqa_streaming_enforcement_failures_total` is increasing

**Cause:** Provider errors are occurring mid-stream (after at least the `stream_started` event was sent).
**Check:** `STREAM_PROVIDER_ERROR` log events. These are WARN-level.
**Note:** Each mid-stream provider failure also increments `qodiqa_streaming_cancelled_total`.

### `qodiqa_streaming_active_streams` is not returning to baseline

**Cause:** A session did not call `res.end()` before the process restarted, or the gauge was incremented without a corresponding decrement.
**Note:** `streamingActiveStreams` is decremented in the cleanup block, which executes even on error paths. This gauge is in-memory and resets to 0 on process restart. It is not a persistent counter.

### Audit record shows `tokenUsage: null`

**Expected behavior.** SSE streaming adapters do not return token usage in the incremental chunk stream. Token usage is reported only in the final response from non-streaming calls. `tokenUsage: null` in streaming audit records is correct.

### No streaming support for a specific provider

Providers without a native streaming adapter (`gemini`, `mistral`, `llama`) are automatically handled via `_wrapNonStreaming()`, which calls the non-streaming adapter and yields the complete response as a single chunk. Clients receive a valid SSE stream with one `chunk_forwarded` event. The `PROVIDER_STREAM_FALLBACK` log event is emitted to identify this path.

### `stream_cancelled` with `reason: "SEMANTIC_OUTPUT_BLOCKED"` or `"SEMANTIC_OUTPUT_BLOCKED_FINAL"`

**Cause:** The output-side semantic gate (§15) denied the response.
`SEMANTIC_OUTPUT_BLOCKED` means a mid-stream chunk itself completed a
denied pattern and was never forwarded — everything before it was already
sent. `SEMANTIC_OUTPUT_BLOCKED_FINAL` means the mandatory end-of-stream
recheck (§15.7) caught it only after the entire response had already been
forwarded — **the client already has the full content**; only the terminal
event and the audit record reflect the denial.
**Check:** `STREAM_SEMANTIC_OUTPUT_BLOCKED` / `STREAM_SEMANTIC_OUTPUT_BLOCKED_FINAL`
WARN log events; `qodiqa_streaming_semantic_blocked_total` /
`qodiqa_streaming_semantic_blocked_final_total` counters (by `reason` label).
**Note:** This is not a bug — see §15.6–§15.7 for why the final case cannot
retract already-delivered content, and
for why a non-streaming call is the correct choice when that guarantee
matters.

---

## 15. Output-Side Semantic Enforcement

Everything above enforces authorization — *who* is asking and *whether they're allowed to ask at
all* — before the first token is streamed. It says nothing about what the **provider generates**.
adds a second gate, entirely inside `streamResponse()`'s chunk-forwarding loop, that
classifies the model's own output as it is produced and can abort the stream mid-flight if that
output itself is malicious (a leaked system prompt, a completed jailbreak, an echoed policy-bypass
instruction). See `docs/architecture/content-screening.md` §3.4 for the shared-engine architecture; this
section covers only the streaming-specific mechanics.

### 15.1 Where it sits in the pipeline

> **[ status note, 2026-10-06 — supersedes parts of §15.1, §15.2, §15.6 and the summary in
> "Evidentiary Guarantees Gap"]** the output window is **check-then-release**
> (`src/streaming/outputSemanticWindow.js` header; `src/streaming/streamEnforcer.js:557-600`; decision record
>): provider text is accumulated into a pending buffer of at most
> `QODIQA_STREAM_SEMANTIC_EMBEDDING_INTERVAL_CHARS` (default 400) characters, and `evaluate()` returns a `released`
> string that is the **only** text written as `chunk_forwarded` — text is released only after the keyword engine
> **and** the embedding gate have both passed that exact buffer. A block, detector timeout
> (`QODIQA_STREAM_SEMANTIC_EMBEDDING_TIMEOUT_MS`, default 5000 ms), detector error, client disconnect or provider
> error discards the pending buffer. Consequences for the text below: chunks are **not** forwarded "exactly as
> before" — delivery arrives in bursts of up to ~400 characters; there **is** a pending-release buffer (§15.2's "nothing
> is ever delayed before forwarding" is no longer true); and §15.6's "up to 399 already-forwarded characters covered
> only by the previous embedding verdict" no longer applies — that stale-verdict leak is closed at the default. What
> remains is §15.7: `evaluateFinal()` scores the whole response once more after every buffer has passed and
> been released, so a block that only the whole-response score finds is recorded truthfully
> (`SEMANTIC_OUTPUT_BLOCKED_FINAL`) but cannot recall already-released text. The non-streaming path still withholds
> the complete response until classified.

```
Provider Stream (executeStreamingProviderCall)
        │  one chunk at a time
        ▼
outputWindow.evaluate(chunk.delta)          [src/streaming/outputSemanticWindow.js]
        │  runs runSemanticPolicyEngine() — the SAME engine and classifier
        │  registry the request-side gate uses, over a bounded trailing window
        │  of already-seen response text plus the new chunk
        ▼
   blocks? ──yes──▶ chunk is NEVER forwarded, ac.abort('semantic_output_block'),
        │            loop breaks, SEMANTIC_OUTPUT_BLOCKED termination
        no
        ▼
 forward chunk exactly as before (chunk_forwarded SSE event, metrics, registry)
```

This is a classify-**before**-forward design: every chunk is evaluated before `_writeSSE()` ever
sees it. A chunk that completes a malicious pattern is discarded, not retracted — nothing is ever
sent and then un-sent, because that isn't possible over an already-open SSE connection.

### 15.2 The sliding window (`src/streaming/outputSemanticWindow.js`)

`createOutputSemanticWindow({ requestId, tenantId, provider })` returns one `evaluate(deltaText)`
function, called once per provider chunk. It owns exactly two pieces of state:

- **`trailingText`** — the last `windowSizeChars` characters of response text seen so far
  (already-forwarded text plus the newest chunk). Bounded and non-growing regardless of total
  stream length — this is also the "maximum buffered characters" figure; there is no second,
  separate pending-release buffer, because nothing is ever delayed before forwarding.
- **`sinceLastPass`** — characters accumulated since the last classification pass, reset to 0
  every time a pass runs.

| Env var | Default | Effect |
|---|---|---|
| `QODIQA_STREAM_SEMANTIC_WINDOW_CHARS` | `4000` | Trailing-context size kept for classification. Larger catches attacks whose pattern spans more text; does not change latency or leak bound. |
| `QODIQA_STREAM_SEMANTIC_INTERVAL_CHARS` | `1` | Re-classify only after this many *new* characters accumulate since the last pass. `1` means "classify every chunk" (the strongest, default setting). |

"Minimum confidence" and "abort threshold" are **not** separate streaming knobs — they are the
same `QODIQA_SEMANTIC_THRESHOLD_{WARN,REVIEW,DENY}` / `QODIQA_SEMANTIC_REVIEW_BLOCKS` /
`QODIQA_SEMANTIC_WARN_BLOCKS` config `policies/semanticPolicy.js` already loads for the request
side, applied identically. A second, looser gate for streaming output would let malicious content
through that the non-streaming path would have blocked — exactly what this remediation must not
do.

### 15.3 Detection latency and the deterministic leak bound

At the default `QODIQA_STREAM_SEMANTIC_INTERVAL_CHARS=1`, every chunk is classified — using the
full trailing window plus that chunk — *before* it is forwarded. If that classification blocks,
the chunk is discarded outright. **Maximum leaked content at the default configuration is
therefore zero characters of the chunk that completes a malicious pattern** — every chunk
forwarded before it was individually judged non-blocking at the moment it was sent.

Raising the interval trades that guarantee for throughput: classification only re-runs after
`classificationIntervalChars` new characters accumulate, and chunks arriving in between are
forwarded under the last verdict computed. The worst case is deterministic and proportional to
the configured value: **up to `classificationIntervalChars − 1` characters of content already
forwarded under a stale (non-blocking) verdict before the next pass catches a pattern that
completed inside that window.** This is a documented, opt-in tradeoff — never automatic — and one
a deployment makes explicitly by raising the env var above its default of `1`.

Detection latency (time from "the malicious pattern is fully present in the trailing window" to
"the block is applied") is one classification pass — a single synchronous call into the same
engine the request side uses (sub-millisecond per classifier; see the calibration benchmark in
`docs/architecture/content-screening.md` §13). It does not grow with total stream length, because the
window itself is capped.

Both properties — the zero-leak default and the proportional leak bound under a raised interval —
are asserted directly in
 (deterministic-abort-point and
configuration describe blocks), not just documented.

### 15.4 Termination and audit

A semantic block sets `status = 'blocked'`, `terminationReason = 'SEMANTIC_OUTPUT_BLOCKED'` — no
new SSE event type or termination-handling branch was needed: `streamResponse()`'s existing
non-`'completed'`/non-`'error'` branch already emits the `stream_cancelled` event with
`reason: terminationReason`, and `_writeAuditStreamRecord()`'s existing
`decision = status === 'completed' ? 'ALLOW' : 'BLOCK'` already records it as a BLOCK. The one
additive field is `executionContext.outputSemantic` — the response-side evidence object
(`evidence.surface === 'RESPONSE_STREAM'`), present on every session (ALLOW or BLOCK), mirroring
the non-streaming path's evidence-on-every-outcome model.

### 15.5 Known limitation (see docs/architecture/content-screening.md §3.4)

The classifiers this gate reuses were calibrated for request-style attack phrasing. A response
that *echoes or completes* that phrasing (a leaked instruction, a jailbroken continuation) is
detected reliably. A response that discloses an actual secret value without request-style framing
may not trip `credential-extraction`/`pii-extraction` — confirmed during manual red-team
validation of this remediation. This is a classifier-signal calibration gap, not a pipeline gap,
and is out of scope here per the "reuse existing classifiers, do not create new ones" constraint
this work operates under.

### 15.6 The embedding-similarity layer's own, coarser cadence

Section 15.3 above describes the **keyword classifier's** cadence and its
zero-leak-at-defaults guarantee. The embedding-similarity gate
(`../core/semantic/embeddingGate.js`, the same one the request side and the
non-streaming output side use) runs inside the identical `evaluate()` call
but on its own, deliberately coarser, cadence — because each embedding check
costs real ONNX inference time (~10–25ms measured, SEM-C session 2) that the
keyword layer's per-chunk default does not pay:

| Env var | Default | Effect |
|---|---|---|
| `QODIQA_STREAM_SEMANTIC_EMBEDDING_INTERVAL_CHARS` | `400` | Embedding gate re-checks only after this many new characters accumulate since its last pass. Chunks arriving in between are forwarded under the *previous* embedding verdict. |

At the default, **up to 399 already-forwarded characters are covered only by
the embedding gate's previous (non-blocking) verdict** before the next pass
re-evaluates the trailing window and could catch a pattern that completed
inside that gap — a bounded, deterministic leak in exactly the same shape as
§15.3's keyword-layer leak bound, but present even at this layer's own
*default* setting (§15.3's keyword-layer leak is zero at its default; it only
appears if an operator raises `QODIQA_STREAM_SEMANTIC_INTERVAL_CHARS` above
`1`).

### 15.7 The mandatory end-of-stream recheck cannot recall forwarded chunks

Because the mid-stream embedding cadence is coarse by design (15.6), and
because scoring the **complete** response text as one artifact is not the
same computation as scoring a trailing window regardless of how small that
window's update interval is, `outputSemanticWindow.js` also exposes
`evaluateFinal()`: a mandatory, unconditional embedding-gate call over the
**entire accumulated response text**, made once after the chunk-forwarding
loop exhausts normally (`streamEnforcer.js`, `status === 'completed'`
branch — never runs if a mid-stream block already terminated the loop).

**By the time this call returns, every chunk of the response has already
been written to the SSE connection.** SSE has no recall mechanism: once
`res.write()` has accepted a chunk's frame, there is no protocol-level
operation that un-sends it. If `evaluateFinal()` blocks:

- `terminationReason` becomes `SEMANTIC_OUTPUT_BLOCKED_FINAL` (distinct from
  the mid-stream `SEMANTIC_OUTPUT_BLOCKED`, so audit tooling can tell the two
  apart — see `metrics.streamingSemanticBlockedFinalTotal`, kept separate
  from `streamingSemanticBlockedTotal` for exactly this reason);
- the terminal SSE event flips from `stream_completed` to `stream_cancelled`
  with that reason;
- the durable audit and transparency records are written as `decision:
  'BLOCK'` instead of `'ALLOW'`.

**The content itself is not withheld — it was already delivered in full.**
This is a deliberate design property (SEM-C session 3 decision record,
carried in `outputSemanticWindow.js`'s own header comment): **audit-truth
over content-suppression**, for this one specific check. It is not possible
to do otherwise without buffering the entire response before forwarding any
of it — which is a different delivery mode with its own latency and memory
trade-offs, evaluated and **not adopted** for the default streaming path;
and the design decision.

**This is a materially different output-safety contract from non-streaming.**
The non-streaming path's `_runOutputSemanticCheck()` (`src/api/routes/aiChat.js`)
classifies the complete response **before** any of it is ever written to the
HTTP response — a non-streaming BLOCK means zero bytes reach the caller.
Streaming can only guarantee that content **already released** is bounded by
the leak windows in §15.3/§15.6, and that a block caught only by the final
recheck is truthfully recorded — not that it was withheld. A tenant or
integration with a compliance/forensic requirement for zero-leaked-content
guarantees should use the non-streaming endpoint; there is currently no
streaming configuration that closes this specific gap (raising
`QODIQA_STREAM_SEMANTIC_EMBEDDING_INTERVAL_CHARS` down to `1` shrinks
§15.6's mid-stream leak but does not change this section's final-recheck
behavior at all, since `evaluateFinal()` runs unconditionally regardless of
the mid-stream interval).

This was previously documented only in `outputSemanticWindow.js`'s source
header, and `SEMANTIC_OUTPUT_BLOCKED_FINAL` had no direct test coverage.
Both are addressed by this section, and
's
`streamResponse — mandatory final recheck (audit-truth over suppression)`
describe block.

### 15.8 Production tuning recommendations

- **Leave `QODIQA_STREAM_SEMANTIC_INTERVAL_CHARS` at its default of `1`** unless classification
  cost is measurably a bottleneck for a specific high-throughput deployment. The default gives
  the strongest guarantee (zero leaked characters from a blocking chunk) at negligible cost —
  classification is sub-millisecond per pass and the window is bounded.
- If raising the interval, treat the resulting `classificationIntervalChars − 1` leak bound as a
  real, disclosed risk acceptance, not a tuning knob to maximize throughput blindly — document
  the chosen value and the accepted bound together in deployment-specific runbooks.
- `QODIQA_STREAM_SEMANTIC_WINDOW_CHARS` mainly matters for attacks whose pattern is long relative
  to typical chunk size; the shipped default (`4000`) comfortably covers every classifier signal
  in the bundled registry (see `docs/architecture/content-screening.md` §4's signal list).
- Monitor `qodiqa_streaming_semantic_blocked_total` (by `reason` label) alongside the existing
  `qodiqa_streaming_cancelled_total` — a sustained rate of semantic blocks for a specific provider
  or model is an operational signal worth routing to security review, not just an audit-log entry.
