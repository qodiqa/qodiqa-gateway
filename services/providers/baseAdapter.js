'use strict';

/**
 * Shared provider execution engine.
 *
 * Every provider adapter (openai/anthropic/gemini/mistral/llama/local, and their
 * streaming counterparts) executes through the pipeline implemented here:
 * cancellation check -> model allowlist check -> outbound validation -> auth/
 * config resolution -> request transform -> network execution (with retry for
 * non-streaming calls) -> response validation/normalization -> logging.
 *
 * Provider files supply only what genuinely differs between them: endpoint,
 * request/response shape transforms, transport (SDK vs fetch), and auth
 * resolution. Everything else — retry loop, timeout/cancellation composition,
 * error classification, structured logging, response normalization — lives
 * here exactly once.
 *
 * This module intentionally reproduces a handful of pre-existing, provider-
 * specific inconsistencies (see comments below at TRANSPORTS, `runProviderCall`,
 * and `logFields`) rather than unifying them — unifying them would be an
 * observable behavior change, which the remediation this module implements is
 * explicitly required NOT to make.
 */

const { emit }                        = require('../logger');
const { validateModel }                = require('./modelValidation');
const { buildResponse }                = require('./normalize');
const { composeSignals }               = require('./signalUtil');
const { computeProviderRetryDelayMs }  = require('./retryBackoff');

// ── Shared outbound-payload limits ────────────────────────────────────────────
// Identical across every provider today; each provider file re-exports these
// two constants (tests read them off the provider module, e.g.
// require('../openai').MAX_MESSAGES).

const MAX_MESSAGES      = 50;
const MAX_CONTENT_BYTES = 32_768;
const ALLOWED_ROLES     = new Set(['system', 'user', 'assistant']);

const MAX_RETRIES = 1;

// ── Outbound message validation ───────────────────────────────────────────────

/**
 * Validate the shared { model, messages } outbound shape.
 *
 * @param {object} body
 * @param {{ extra?: (messages: Array) => (string|null) }} [opts]
 *   `extra` — optional provider-specific check run after the generic checks
 *   pass (anthropic requires >=1 non-system message; gemini requires >=1
 *   user message). Returns a rejection code, or null/undefined to pass.
 * @returns {string|null} rejection code, or null if valid
 */
function validateOutboundMessages(body, opts) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'PROVIDER_INVALID_REQUEST';
  }

  const { messages } = body;

  if (!Array.isArray(messages) || messages.length === 0) {
    return 'PROVIDER_INVALID_REQUEST';
  }

  if (messages.length > MAX_MESSAGES) {
    return 'PROVIDER_REQUEST_REJECTED';
  }

  let totalBytes = 0;
  for (const msg of messages) {
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      return 'PROVIDER_INVALID_REQUEST';
    }
    if (typeof msg.role !== 'string' || !ALLOWED_ROLES.has(msg.role)) {
      return 'PROVIDER_INVALID_REQUEST';
    }
    if (typeof msg.content !== 'string') {
      return 'PROVIDER_INVALID_REQUEST';
    }
    totalBytes += Buffer.byteLength(msg.content, 'utf8');
  }

  if (totalBytes > MAX_CONTENT_BYTES) {
    return 'PROVIDER_REQUEST_REJECTED';
  }

  if (typeof opts?.extra === 'function') {
    const extraCode = opts.extra(messages);
    if (extraCode) return extraCode;
  }

  return null;
}

function estimateContentBytes(messages) {
  let total = 0;
  for (const msg of messages) {
    if (typeof msg.content === 'string') {
      total += Buffer.byteLength(msg.content, 'utf8');
    }
  }
  return total;
}

// ── Error classification ──────────────────────────────────────────────────────
//
// Two genuinely different transport shapes exist today, plus one variant of
// the SDK shape used only by the streaming SDK-based adapters:
//   - `sdk`       (openai.js, mistral.js, llama.js, local.js — non-streaming):
//                 timeout-by-name only on APIConnectionTimeoutError; network
//                 error by name only on APIConnectionError.
//   - `sdkStream` (openai.stream.js, local.stream.js): same as `sdk`, but ALSO
//                 treats AbortError as a timeout — a pre-existing asymmetry
//                 between the streaming and non-streaming SDK adapters,
//                 preserved here rather than "fixed".
//   - `fetch`     (anthropic.js/anthropic.stream.js, gemini.js — timeout-by-name
//                 is AbortError; network error by name is TypeError, not
//                 APIConnectionError).

const TRANSPORTS = Object.freeze({
  sdk: Object.freeze({
    timeoutNames: new Set(['APIConnectionTimeoutError']),
    networkNames: new Set(['APIConnectionError']),
  }),
  sdkStream: Object.freeze({
    timeoutNames: new Set(['APIConnectionTimeoutError', 'AbortError']),
    networkNames: new Set(['APIConnectionError']),
  }),
  fetch: Object.freeze({
    timeoutNames: new Set(['AbortError']),
    networkNames: new Set(['TypeError']),
  }),
});

function classifyTransportError(err, transport) {
  if (typeof err.code === 'string' && /^PROVIDER_/.test(err.code)) {
    return err.code;
  }

  // a 200 whose body could not be read as the expected document is an INVALID RESPONSE (the call was answered, so it is never re-sent), not an outage
  if (err.name === 'SyntaxError') return 'PROVIDER_INVALID_RESPONSE';
  // F9V-02: the SDKs' own fetch (node-fetch) throws a FetchError of type invalid-json for an empty or truncated JSON body of a 200
  // a 200 whose body then fails at the transport layer (bad gzip, chunked body cut short) was ANSWERED: never re-sent, never failed over
  if (err.name === 'FetchError' && (err.code === 'Z_DATA_ERROR' || err.code === 'Z_BUF_ERROR' || err.code === 'ERR_STREAM_PREMATURE_CLOSE')) return 'PROVIDER_INVALID_RESPONSE';
  if (err.type === 'invalid-json' || (err.name === 'FetchError' && /invalid json response body/i.test(String(err.message)))) return 'PROVIDER_INVALID_RESPONSE';

  if (transport.timeoutNames.has(err.name) ||
      err.code === 'ETIMEDOUT' ||
      err.code === 'ECONNABORTED' ||
      (typeof err.message === 'string' && /timed?\s*out/i.test(err.message))) {
    return 'PROVIDER_TIMEOUT';
  }

  if (typeof err.status === 'number') {
    if (err.status === 429)                        return 'PROVIDER_RATE_LIMITED';
    if (err.status === 401 || err.status === 403)  return 'PROVIDER_AUTH_FAILED';
    if (err.status === 400 || err.status === 422)  return 'PROVIDER_INVALID_REQUEST';
    if (err.status >= 500)                         return 'PROVIDER_UNAVAILABLE';
    // every OTHER 4xx (404 model/endpoint not found, 405, 409, 410, 413, 415, ...)
    // is the provider refusing THIS request, not the provider being down. Classified as a non-retryable request
    // error: it does not count against the circuit breaker (router CIRCUIT_BREAKER_FAILURE_CODES) and is not a
    // failover trigger (RETRYABLE_CODES). 401/403 stay PROVIDER_AUTH_FAILED (operator credential/configuration,
    // also non-retryable and not breaker-counted); 408 keeps its pre-existing PROVIDER_UNAVAILABLE fall-through
    // and 429 stays PROVIDER_RATE_LIMITED.
    if (err.status >= 400 && err.status < 500 && err.status !== 408) return 'PROVIDER_INVALID_REQUEST';
  }

  if (transport.networkNames.has(err.name) ||
      err.code === 'ECONNREFUSED' ||
      err.code === 'ENOTFOUND' ||
      err.code === 'ECONNRESET') {
    return 'PROVIDER_UNAVAILABLE';
  }

  return 'PROVIDER_UNAVAILABLE';
}

// Cancellation (route-level timeout or client disconnect) is disambiguated
// from a genuine provider-side timeout/error by checking the *caller's*
// signal, not the error shape — every transport can raise the same AbortError
// whether our signal or its own internal timeout fired. Cancellation must
// never be classified as PROVIDER_TIMEOUT/PROVIDER_UNAVAILABLE (a "real"
// failure), nor retried, nor sent to a failover provider.
function classifyError(rawErr, signal, transport) {
  if (signal?.aborted) return 'PROVIDER_CANCELLED';
  return classifyTransportError(rawErr, transport);
}

function isRetryable(code) {
  return code === 'PROVIDER_RATE_LIMITED' || code === 'PROVIDER_UNAVAILABLE';
}

// RT-06: a chat completion is not idempotent. A provider that ANSWERED with a 5xx may
// already have run (and billed) the completion, so it is not sent a second time; only a 429 (the provider refused before
// processing) or a failure with no HTTP response at all (connection refused/reset, DNS) is retried.
function shouldRetry(code, rawErr) {
  if (!isRetryable(code)) return false;
  if (code === 'PROVIDER_RATE_LIMITED') return true;
  if (mayHaveExecuted(code, rawErr)) return false; // a reset after delivery is not provably unsent
  return !(rawErr && typeof rawErr.status === 'number');
}

// did the provider possibly RUN the completion? True for an answered 5xx, a timeout (the request was sent;
// the outcome is unknown) and a connection reset (possibly after delivery). False only for failures that provably never
// reached the provider (refused connection, DNS, 429 refusal, circuit open, health-degraded). The router consults the same
// flag before failing over to ANOTHER provider, so "answered => never resent" holds across providers too.
function mayHaveExecuted(code, rawErr) {
  if (code === 'PROVIDER_TIMEOUT' || code === 'PROVIDER_INVALID_RESPONSE') return true;
  if (rawErr && rawErr.providerMayHaveExecuted === true) return true;
  if (rawErr && typeof rawErr.status === 'number' && rawErr.status >= 500) return true;
  const c = rawErr && (rawErr.code || (rawErr.cause && rawErr.cause.code));
  return c === 'ECONNRESET' || c === 'EPIPE' || c === 'UND_ERR_SOCKET';
}

function throwCoded(code, providerMayHaveExecuted = false) {   // PROVIDER_INVALID_RESPONSE from an adapter keeps its flag
  const err = new Error(code);
  err.code  = code;
  if (providerMayHaveExecuted) err.providerMayHaveExecuted = true;
  throw err;
}

// ── Load-time URL/config assertion ────────────────────────────────────────────

/**
 * Shared emit-CRITICAL-and-throw boilerplate for a provider's module-load-time
 * base-URL validation. The provider file computes `check` itself (calling
 * ssrf.js's validator directly) — this only centralizes what happens with an
 * invalid result, so a test spying on the validator function still observes
 * the provider file calling it directly.
 *
 * `errorMessage` is the exact thrown Error message with `check.reason`
 * appended (each provider's original wording differs slightly, e.g.
 * `PROVIDER_SSRF_REJECTED: ` vs `PROVIDER_CONFIG_INVALID: mistral base URL `),
 * so this helper does not impose its own separator/punctuation.
 *
 * @param {{ provider: string, url: string, check: { valid: boolean, reason: string|null },
 *           eventCode: string, logMessage: string, errorMessage: string }} args
 */
function assertUrlSafeAtLoad({ provider, url, check, eventCode, logMessage, errorMessage }) {
  if (check.valid) return;
  emit('CRITICAL', eventCode, {
    provider,
    reason:  check.reason,
    url:     (() => { try { return new URL(url).origin; } catch { return null; } })(),   // F9R-02: never the raw value (it may carry credentials)
    message: logMessage,
  });
  throw new Error(`${errorMessage}${check.reason}`);
}

// ── Lazy client helper (SDK-based providers) ──────────────────────────────────

/**
 * Shared lazy-singleton-with-reset pattern for the four SDK-based providers.
 * `resolveConfig()` is provider-owned: it may throw PROVIDER_AUTH_FAILED /
 * PROVIDER_CONFIG_INVALID, and must return { apiKey, baseURL, timeoutMs }.
 *
 * @param {{ resolveConfig: () => { apiKey: string, baseURL: string, timeoutMs: number }, OpenAIClass: Function }} args
 */
/**
 * the fetch the OpenAI SDK uses for every SDK-based adapter: node-fetch (which honours the guarded `agent`) with redirects NOT followed: a 3xx comes back as an
 * ordinary error status and is never chased to another host (which would carry the api-key / Authorization header with it).
 * (openai 4 -> 7): openai >= 5 no longer bundles node-fetch, so it is a direct dependency now (the same node-fetch 2.7.0 the SDK used to bring).
 */
let _nodeFetch = null;
function noRedirectFetch(url, init) {
  if (!_nodeFetch) {
    try { _nodeFetch = require('node-fetch'); } catch { _nodeFetch = null; }
    if (_nodeFetch && _nodeFetch.default) _nodeFetch = _nodeFetch.default;
  }
  if (!_nodeFetch) { const e = new Error('PROVIDER_UNAVAILABLE'); e.code = 'PROVIDER_UNAVAILABLE'; throw e; }       // cannot guarantee "no redirect": refuse rather than follow
  return _nodeFetch(url, { ...init, redirect: 'manual' });
}

/**
 * (openai 4 -> 7): openai >= 5 dropped the `httpAgent` client option (v4 handed it to fetch as `init.agent`; v5+ silently ignores it), so the SSRF-guarded agent
 * (item 3.8 /) now rides on the fetch the SDK calls. Without this the guard is bypassed while every mocked test stays green. `guardedAgent` is exposed for tests.
 */
function guardedFetch(agent, baseFetch = noRedirectFetch) {
  if (!agent) return baseFetch;
  const f = (url, init) => baseFetch(url, { ...init, agent });
  f.guardedAgent = agent;
  return f;
}

function createLazyClient({ resolveConfig, OpenAIClass }) {
  let client = null;

  function get() {
    if (client) return client;
    const cfg = resolveConfig();
    client = new OpenAIClass({
      apiKey:     cfg.apiKey,
      baseURL:    cfg.baseURL,
      timeout:    cfg.timeoutMs,
      maxRetries: 0,
      fetch:      guardedFetch(cfg.httpAgent),                               // no redirects; item 3.8 guarded agent for operator-configured endpoints
    });
    return client;
  }

  function reset() { client = null; }

  return { get, reset };
}

// ── Fetch-with-timeout helper (fetch-based providers) ─────────────────────────
//
// Composes the caller's cancellation signal (route-level timeout / client
// disconnect) with this call's own network timeout so either one aborts the
// outbound fetch.

async function fetchWithTimeout(url, options, timeoutMs, callerSignal) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), timeoutMs);
  const signal     = composeSignals(callerSignal, controller.signal);
  try {
    // a provider endpoint never legitimately redirects; following one would let a compromised or misconfigured endpoint steer the request (and its credentials) elsewhere.
    return await fetch(url, { redirect: 'error', ...options, signal });
  } finally {
    clearTimeout(timer);
  }
}

const MAX_BODY_BYTES = 8 * 1024 * 1024;

function invalidResponse(why) {
  const e = new Error('PROVIDER_INVALID_RESPONSE');
  e.code = 'PROVIDER_INVALID_RESPONSE'; e.providerMayHaveExecuted = true; e.detail = why;
  return e;
}

/**
 * the timeout covers the WHOLE call - headers AND body - and the body is read with a size bound (a hostile or broken endpoint can neither hold the call open by sending a
 * body slowly nor make the gateway buffer an unbounded answer). A body that is not JSON is PROVIDER_INVALID_RESPONSE (answered: not re-sent, not failed over).
 */
async function fetchJSON(url, options, timeoutMs, callerSignal, { maxBytes = MAX_BODY_BYTES } = {}) {
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), timeoutMs);
  const signal     = composeSignals(callerSignal, controller.signal);
  try {
    const res = await fetch(url, { redirect: 'error', ...options, signal });
    if (!res.ok) {
      const httpErr  = new Error(`HTTP ${res.status}`);
      httpErr.status = res.status;
      throw httpErr;
    }
    const declared = Number(res.headers && res.headers.get ? res.headers.get('content-length') : NaN);
    if (Number.isFinite(declared) && declared > maxBytes) throw invalidResponse('body too large');
    const chunks = []; let total = 0;
    if (res.body && typeof res.body.getReader === 'function') {
      const reader = res.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();           // aborts (timeout / caller) reject here
        if (done) break;
        total += value.length;
        if (total > maxBytes) { try { await reader.cancel(); } catch { /* best effort */ } throw invalidResponse('body too large'); }
        chunks.push(value);
      }
    } else if (typeof res.text === 'function') {
      const text = await res.text();
      if (text.length > maxBytes) throw invalidResponse('body too large');
      chunks.push(Buffer.from(text, 'utf8'));
    } else {
      try { return await res.json(); } catch { throw invalidResponse('body is not JSON'); }       // a minimal Response double
    }
    try { return JSON.parse(Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8')); } catch { throw invalidResponse('body is not JSON'); }
  } finally {
    clearTimeout(timer);
  }
}

function providerTimeoutMs(name) {
  try { const c = require('./config').getProviderConfig(name); if (c && Number.isFinite(c.timeoutMs) && c.timeoutMs > 0) return c.timeoutMs; } catch { /* default below */ }
  return 30_000;
}

function timeoutError() {
  const e = new Error('PROVIDER_TIMEOUT');
  e.code = 'PROVIDER_TIMEOUT';
  return e;
}

/**
 * run `fn(callSignal)` under the provider's configured timeout. The deadline aborts the derived signal handed to the adapter (so the socket is torn down, not just abandoned)
 * and rejects with PROVIDER_TIMEOUT, covering time-to-headers, a body that stalls and a body that drips. The caller's own signal still wins (cancellation is not a timeout).
 */
async function withDeadline(name, callerSignal, fn) {
  const ms = providerTimeoutMs(name);
  const dl = new AbortController();
  const callSignal = composeSignals(callerSignal, dl.signal);
  let timer;
  const deadline = new Promise((_resolve, reject) => { timer = setTimeout(() => { dl.abort(); reject(timeoutError()); }, ms); });
  const run = Promise.resolve().then(() => fn(callSignal));
  run.catch(() => {});                                    // a late rejection after the deadline must not become an unhandled rejection
  try { return await Promise.race([run, deadline]); } finally { clearTimeout(timer); }
}

// ── Non-streaming pipeline ────────────────────────────────────────────────────

/**
 * @param {object} spec
 *   spec.name              — canonical provider name, e.g. 'openai'
 *   spec.transport         — one of TRANSPORTS.{sdk,fetch}
 *   spec.validate          — { extra? } passed to validateOutboundMessages
 *   spec.beforeValidatedEmit?(meta) — optional; runs after outbound validation,
 *                             BEFORE the PROVIDER_REQUEST_VALIDATED emit
 *                             (anthropic/gemini's inline API-key check).
 *   spec.transformRequest(body, ctx) -> requestPayload
 *   spec.getExecutionContext?(ctx)   -> extra fields merged into ctx, run AFTER
 *                             the PROVIDER_REQUEST_VALIDATED emit (openai/
 *                             mistral/llama/local's lazy client construction,
 *                             which performs their auth/config check).
 *   spec.execute(requestPayload, ctx) -> raw provider response (thenable)
 *   spec.logFields(raw)    -> fields merged into PROVIDER_EXECUTION_COMPLETE
 *                             (e.g. { responseId, usage })
 *   spec.parseResponse(raw, ctx) -> fields passed to buildResponse() (output,
 *                             model, provider, tokenUsage, executionMetadata)
 * @param {object} body
 * @param {object} meta
 * @param {AbortSignal} [signal]
 */
async function runProviderCall(spec, body, meta, signal) {
  const model    = body && typeof body.model === 'string' ? body.model : null;
  const safeMeta = meta && typeof meta === 'object' ? meta : {};

  if (signal?.aborted) throwCoded('PROVIDER_CANCELLED');

  const modelCheck = validateModel(spec.name, model);
  if (!modelCheck.ok) throwCoded(modelCheck.code);

  const rejectionCode = validateOutboundMessages(body, spec.validate);
  if (rejectionCode) {
    emit('WARN', 'PROVIDER_REQUEST_REJECTED', {
      provider:  spec.name,
      model,
      requestId: safeMeta.requestId ?? null,
      code:      rejectionCode,
    });
    throwCoded(rejectionCode);
  }

  const ctx = { model, meta: safeMeta, signal };

  if (typeof spec.beforeValidatedEmit === 'function') {
    spec.beforeValidatedEmit(ctx);
  }

  emit('INFO', 'PROVIDER_REQUEST_VALIDATED', {
    provider:       spec.name,
    model,
    requestId:      safeMeta.requestId   ?? null,
    requestHash:    safeMeta.requestHash ?? null,
    policyHash:     safeMeta.policyHash  ?? null,
    messageCount:   body.messages.length,
    estimatedBytes: estimateContentBytes(body.messages),
  });

  if (typeof spec.getExecutionContext === 'function') {
    Object.assign(ctx, spec.getExecutionContext(ctx));
  }

  const requestPayload = spec.transformRequest(body, ctx);

  let lastCode;
  let lastMayHaveExecuted = false;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const startMs = Date.now();
    emit('INFO', 'PROVIDER_EXECUTION_START', {
      provider:    spec.name,
      model,
      attempt,
      requestId:   safeMeta.requestId   ?? null,
      requestHash: safeMeta.requestHash ?? null,
      policyHash:  safeMeta.policyHash  ?? null,
    });

    try {
      // one deadline for the WHOLE call, whatever the transport (an SDK or fetch timeout that only covers the headers is not enough)
      const raw       = await withDeadline(spec.name, signal, (callSignal) => spec.execute(requestPayload, { ...ctx, signal: callSignal }));
      const latencyMs = Date.now() - startMs;

      // anything wrong with the ANSWER (null, wrong shape, unusable body) is PROVIDER_INVALID_RESPONSE - the call was answered, so it is neither re-sent nor failed over
      let response;
      try {
        emit('INFO', 'PROVIDER_EXECUTION_COMPLETE', {
          provider:  spec.name,
          model,
          attempt,
          requestId: safeMeta.requestId ?? null,
          latencyMs,
          ...(spec.completeLogIncludesHash
            ? { requestHash: safeMeta.requestHash ?? null, policyHash: safeMeta.policyHash ?? null }
            : {}),
          ...spec.logFields(raw),
        });

        const parsed = spec.parseResponse(raw, ctx);
        response = buildResponse({
          ...parsed,
          provider: spec.name,
          executionMetadata: { ...parsed.executionMetadata, latencyMs },
        });
      } catch (shapeErr) {
        if (shapeErr && typeof shapeErr.code === 'string' && /^PROVIDER_/.test(shapeErr.code)) throw shapeErr;
        throw invalidResponse('unusable response');
      }
      return response;

    } catch (rawErr) {
      const latencyMs = Date.now() - startMs;
      const code      = classifyError(rawErr, signal, spec.transport);
      const willRetry = attempt < MAX_RETRIES && shouldRetry(code, rawErr);

      emit('WARN', 'PROVIDER_EXECUTION_FAILED', {
        provider:  spec.name,
        model,
        attempt,
        requestId: safeMeta.requestId ?? null,
        latencyMs,
        code,
        willRetry,
      });

      lastCode = code;
      lastMayHaveExecuted = mayHaveExecuted(code, rawErr);

      if (willRetry) {
        const delayMs = computeProviderRetryDelayMs(attempt + 1);
        emit('INFO', 'PROVIDER_RETRY_SCHEDULED', {
          provider:  spec.name,
          model,
          attempt:   attempt + 1,
          requestId: safeMeta.requestId ?? null,
          delayMs,
        });
        await new Promise(r => setTimeout(r, delayMs));
        continue;
      }

      throwCoded(code, lastMayHaveExecuted);
    }
  }

  throwCoded(lastCode || 'PROVIDER_UNAVAILABLE', lastMayHaveExecuted);
}

// ── Streaming pipeline ────────────────────────────────────────────────────────
//
// No retry loop — same-provider retries never happened for streaming calls
// before this remediation (only router.stream.js's failover does). Reproduced
// as-is.

/**
 * @param {object} spec
 *   spec.name, spec.transport, spec.validate — same as runProviderCall
 *   spec.beforeStart?(ctx)     — optional; runs before PROVIDER_STREAM_START
 *                                (anthropic.stream's API-key check)
 *   spec.transformRequest(body, ctx) -> requestPayload
 *   spec.execute(requestPayload, ctx) -> async iterable of raw provider chunks; calls
 * ctx.markStreamAccepted() once the provider answered 2xx
 *   spec.parseChunk(rawChunk) -> string|null — extracted delta text, or null/
 *                                empty to skip yielding
 * @param {object} body
 * @param {object} meta
 * @param {AbortSignal} [signal]
 */
async function* runProviderStream(spec, body, meta, signal) {
  const model    = body && typeof body.model === 'string' ? body.model : null;
  const safeMeta = meta && typeof meta === 'object' ? meta : {};

  const modelCheck = validateModel(spec.name, model);
  if (!modelCheck.ok) throwCoded(modelCheck.code);

  const rejectionCode = validateOutboundMessages(body, spec.validate);
  if (rejectionCode) {
    emit('WARN', 'PROVIDER_REQUEST_REJECTED', {
      provider:  spec.name,
      model,
      requestId: safeMeta.requestId ?? null,
      code:      rejectionCode,
    });
    throwCoded(rejectionCode);
  }

  // set by the adapter (ctx.markStreamAccepted()) once the provider has ACCEPTED the streaming request —
  // HTTP 2xx received and the response stream opened. From then on the provider may already be executing (and
  // billing) the call, so ANY later failure — an in-band error frame before the first token, a dropped socket, a
  // truncated body — is flagged providerMayHaveExecuted and is never re-sent or failed over.
  // Failures before acceptance (connection refused, DNS, an HTTP 429 refusal) are unaffected and may still fail over.
  let streamAccepted = false;
  const ctx = { model, meta: safeMeta, signal, markStreamAccepted() { streamAccepted = true; } };

  if (typeof spec.beforeStart === 'function') {
    spec.beforeStart(ctx);
  }

  emit('INFO', 'PROVIDER_STREAM_START', {
    provider:  spec.name,
    model,
    requestId: safeMeta.requestId ?? null,
    ...(spec.streamStartIncludesPolicyHash === false ? {} : { policyHash: safeMeta.policyHash ?? null }),
  });

  const requestPayload = spec.transformRequest(body, ctx);
  const startMs        = Date.now();
  let   firstChunk      = true;
  // adapters whose protocol has a documented terminal signal supply spec.isTerminalChunk; a stream that
  // ends (cleanly, at the transport level) without ever presenting it is TRUNCATED and must fail, never complete.
  const requireTerminal = typeof spec.isTerminalChunk === 'function';
  let   sawTerminal     = false;

  // an IDLE deadline for the stream - no chunk (or no first chunk) within the provider's configured timeout is PROVIDER_TIMEOUT and tears the connection down; a stream that
  // keeps delivering is not cut by it (the route bounds the total).
  const idleMs = providerTimeoutMs(spec.name);
  const dl = new AbortController();
  ctx.signal = composeSignals(signal, dl.signal);
  const iterator = spec.execute(requestPayload, ctx)[Symbol.asyncIterator]();
  const nextChunk = () => {
    let timer;
    const idle = new Promise((_resolve, reject) => { timer = setTimeout(() => { dl.abort(); reject(timeoutError()); }, idleMs); });
    const pending = iterator.next();
    pending.catch(() => {});
    return Promise.race([pending, idle]).finally(() => clearTimeout(timer));
  };

  try {
    for (;;) {
      const step = await nextChunk();
      if (step.done) break;
      const rawChunk = step.value;
      if (requireTerminal && !sawTerminal && spec.isTerminalChunk(rawChunk)) sawTerminal = true;
      const delta = spec.parseChunk(rawChunk);
      if (typeof delta === 'string' && delta.length > 0) {
        if (firstChunk) {
          emit('INFO', 'PROVIDER_STREAM_FIRST_CHUNK', {
            provider:  spec.name,
            model,
            requestId: safeMeta.requestId ?? null,
            latencyMs: Date.now() - startMs,
          });
          firstChunk = false;
        }
        yield { delta };
      }
    }
  } catch (rawErr) {
    // Unlike runProviderCall, none of the three streaming adapters have ever
    // special-cased signal.aborted here (no `_classifyError`/cancellation
    // disambiguation exists in the original openai.stream.js/
    // anthropic.stream.js/local.stream.js) — an aborted signal surfaces
    // through whatever code classifyTransportError derives from the raw
    // error shape (typically PROVIDER_TIMEOUT via the AbortError name).
    // Preserved as-is rather than "fixed" to avoid an observable-behavior
    // change this remediation must not introduce.
    // carry "the provider may already have run this" so the stream router does not fail it over.
    // once ANY output chunk has been yielded the provider has demonstrably executed the call, whatever
    // the error class (a mid-stream 429-shaped error or a bare TypeError would otherwise read as "not executed"
    // and let the router start a second provider after partial output). An adapter may also flag an in-stream
    // provider error explicitly.
    const code = classifyTransportError(rawErr, spec.transport);
    // an error after the provider accepted the stream (even before the first output chunk) is flagged too.
    throwCoded(code, mayHaveExecuted(code, rawErr) || rawErr?.providerMayHaveExecuted === true || !firstChunk
      || streamAccepted);
  }

  if (requireTerminal && !sawTerminal) {
    // the provider accepted the request (HTTP 200, stream opened) and then the stream ended without its
    // terminal marker — output (if any) is incomplete. PROVIDER_UNAVAILABLE (a provider-side failure, breaker-
    // counted) flagged providerMayHaveExecuted: the call ran, so it is never re-sent or failed over (
    //).
    emit('WARN', 'PROVIDER_STREAM_INCOMPLETE', {
      provider:  spec.name,
      model,
      requestId: safeMeta.requestId ?? null,
      emittedOutput: !firstChunk,
      message:   'Stream ended without the protocol terminal signal — treated as a failed (truncated) stream.',
    });
    throwCoded('PROVIDER_UNAVAILABLE', true);
  }

  emit('INFO', 'PROVIDER_STREAM_COMPLETE', {
    provider:  spec.name,
    model,
    requestId: safeMeta.requestId ?? null,
    latencyMs: Date.now() - startMs,
  });
}

/**
 * terminal-signal detector for the OpenAI Chat Completions streaming protocol and its compatible
 * implementations (Mistral, OpenAI-compatible Llama servers, Ollama's /v1 endpoint). Per the OpenAI API reference
 * ("The chat completion chunk object"), every chunk carries `choices[].finish_reason`, which is `null` until the
 * choice's final chunk, where it is one of `stop` | `length` | `content_filter` | `tool_calls` | `function_call`.
 * The wire-level `data: [DONE]` sentinel is consumed silently by the openai SDK (streaming.js) and is not observable
 * to the adapter, so a non-null finish_reason is the only terminal signal available at this layer. `length` and
 * `content_filter` are provider-decided ends (not transport truncation) and count as terminal.
 */
function isOpenAICompatibleTerminalChunk(chunk) {
  const choices = chunk && Array.isArray(chunk.choices) ? chunk.choices : null;
  if (!choices) return false;
  return choices.some((c) => c && typeof c.finish_reason === 'string' && c.finish_reason.length > 0);
}

module.exports = {
  isOpenAICompatibleTerminalChunk,
  MAX_MESSAGES,
  MAX_CONTENT_BYTES,
  ALLOWED_ROLES,
  TRANSPORTS,
  validateOutboundMessages,
  classifyError,
  classifyTransportError,
  isRetryable,
  shouldRetry,
  mayHaveExecuted,
  assertUrlSafeAtLoad,
  createLazyClient,
  noRedirectFetch,
  guardedFetch,
  fetchWithTimeout,
  fetchJSON,
  runProviderCall,
  runProviderStream,
};
