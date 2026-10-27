'use strict';

/**
 * Streaming provider router.
 *
 * Routes streaming requests to native streaming adapters when available.
 * For providers without native streaming support (gemini only, as —
 *), falls back to wrapping
 * the non-streaming adapter as a single-chunk stream.
 *
 * Design properties:
 *   • Provider-agnostic: routing logic does not encode any provider behavior.
 *   • Fail-closed: unknown or disabled providers throw immediately.
 *   • Failover: retryable streaming failures attempt the configured failover provider.
 *   • Fallback: providers without streaming adapters yield a single chunk.
 *   • No enforcement logic — the invariant is asserted upstream in execution.stream.js.
 */

const { callOpenAIStream }    = require('./openai.stream');
const { callAnthropicStream } = require('./anthropic.stream');
const { callMistralStream }   = require('./mistral.stream');
const { callLlamaStream }     = require('./llama.stream');
const { callAzureStream }     = require('./azure.stream');   // (bedrock: no native streaming, like gemini)
const { callLocalStream }     = require('./local.stream');
const { routeProviderCall }   = require('./router');
const { getProviderConfig }          = require('./config');
const compat = require('./compat');   // dynamic OpenAI-compatible providers
// the streaming handler of a registered `compat-<id>` provider (undefined for any other name without native streaming)
const _compatStream = (name) => { const r = require('../../src/core/providers/compatRegistry'); return r.isCompatName(name) && r.allNames().includes(name) ? compat.streamHandlerFor(name) : undefined; };
const { validateModelAgainstConfig } = require('./modelValidation');
const { emit }                = require('../logger');
const { getCircuitBreaker }      = require('./providerCircuitBreaker');
const { CIRCUIT_BREAKER_CONFIG } = require('./circuitBreakerConfig');
const providerHealth = require('./providerHealth');
const providerLoad = require('./providerLoad');
const { monoNowMs } = require('../../src/infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

// Providers with native streaming support. mistral and llama added —
// both are OpenAI-SDK-compatible endpoints (mirrors local.stream.js exactly,
// only config resolution differs), so adding native streaming reuses the
// proven pattern rather than inventing a new one. gemini is deliberately NOT
// listed for why: its
// REST API has no OpenAI-compatible streaming shape, and this codebase has no
// live Gemini credential to verify a from-scratch SSE parser's wire-format
// assumptions against the real service, unlike mistral/llama's exact reuse of
// an already-proven client+flag recipe.
const STREAMING_REGISTRY = Object.freeze({
  openai:    callOpenAIStream,
  anthropic: callAnthropicStream,
  mistral:   callMistralStream,
  llama:     callLlamaStream,
  local:     callLocalStream,
  azure:     callAzureStream,
});

const RETRYABLE_CODES = new Set([
  'PROVIDER_UNAVAILABLE',
  'PROVIDER_RATE_LIMITED',
  'PROVIDER_TIMEOUT',
  // A fast-failed request never reached the provider — failover should still
  // be attempted (Register #107, mirrors router.js).
  'PROVIDER_CIRCUIT_OPEN',
  // FAILOVER-4, mirrors router.js — routed away before contacting the
  // provider because its recent health history is degraded.
  'PROVIDER_HEALTH_DEGRADED',
]);

// Failures that count against a provider's circuit breaker — narrower than
// RETRYABLE_CODES for the same reason as router.js's identically-named set.
const CIRCUIT_BREAKER_FAILURE_CODES = new Set([
  'PROVIDER_UNAVAILABLE',
  'PROVIDER_RATE_LIMITED',
  'PROVIDER_TIMEOUT',
]);

function _isRetryable(err) {
  // same rule as router.js — a stream the first provider may already have started is never re-sent.
  return RETRYABLE_CODES.has(err?.code) && !err?.providerMayHaveExecuted;
}

function _countsAgainstBreaker(err) {
  return CIRCUIT_BREAKER_FAILURE_CODES.has(err?.code);
}

function _circuitOpenError() {
  const err = new Error('PROVIDER_CIRCUIT_OPEN');
  err.code  = 'PROVIDER_CIRCUIT_OPEN';
  return err;
}

function _healthDegradedError() {
  const err = new Error('PROVIDER_HEALTH_DEGRADED');
  err.code  = 'PROVIDER_HEALTH_DEGRADED';
  return err;
}

/**
 * Wrap a native streaming handler with the same circuit breaker registry
 * router.js's _dispatch() consults (Register #107) — the state machine
 * itself lives in exactly one module (providerCircuitBreaker.js); this is
 * simply its second (streaming) call site, since native stream handlers
 * bypass _dispatch() entirely. Also records into the same providerHealth.js
 * tracker _dispatch() does (FAILOVER-4) — one shared health signal per
 * provider regardless of which call site observed it. Latency here is
 * measured end-to-end across the whole generator (first chunk to
 * exhaustion) rather than time-to-first-byte, since that's the cost this
 * caller actually pays; a fair enough proxy for "is this provider slow
 * right now" without adding per-chunk instrumentation.
 */
async function* _guardedStream(provider, handler, body, meta, signal) {
  const breaker = getCircuitBreaker(provider, CIRCUIT_BREAKER_CONFIG);
  const permit = breaker.acquire();
  if (!permit.allowed) {
    emit('WARN', 'PROVIDER_CIRCUIT_OPEN', {
      provider,
      requestId: meta.requestId ?? null,
      message:   'Circuit breaker is OPEN for this provider — fast-failing without contacting it.',
    });
    throw _circuitOpenError();
  }

  const start = monoNowMs(); // monotonic (same-process): feeds providerHealth's latency penalty (a routing decision)
  let settled = false; // success or a breaker-counted failure was reported
  const endLoad = providerLoad.begin(provider);   // in-flight count (least-loaded routing)
  try {
    yield* handler(body, meta, signal);
    providerHealth.recordOutcome(provider, { ok: true, timedOut: false, latencyMs: monoNowMs() - start }); // monotonic (same-process)
    breaker.onSuccess();
    settled = true;
  } catch (err) {
    providerHealth.recordOutcome(provider, {
      ok: false,
      timedOut: err?.code === 'PROVIDER_TIMEOUT',
      latencyMs: monoNowMs() - start, // monotonic (same-process)
    });
    if (_countsAgainstBreaker(err)) { breaker.onFailure(); settled = true; }
    throw err;
  } finally {
    endLoad();
    // 3.7: an abandoned stream (client went away) or an uncounted error must not strand the half-open probe slot
    if (!settled && permit.probe) breaker.releaseProbe(permit.probeId);
  }
}

/**
 * Wrap a non-streaming provider response as a single-chunk generator.
 * Used for providers without native streaming support.
 */
async function* _wrapNonStreaming(provider, body, meta, signal) {
  emit('INFO', 'PROVIDER_STREAM_FALLBACK', {
    provider,
    requestId: meta.requestId ?? null,
    note:      'Provider has no native streaming adapter — forwarding full response as one chunk.',
  });

  const response = await routeProviderCall(provider, body, meta, signal);
  if (typeof response?.output === 'string' && response.output.length > 0) {
    yield { delta: response.output };
  }
}

/**
 * Route a streaming provider call with optional native streaming and failover.
 *
 * @param {string}      provider
 * @param {object}      body      — { model, messages }
 * @param {object}      meta      — { requestId, requestHash, policyHash, tenantId }
 * @param {AbortSignal} [signal]
 * @yields {{ delta: string }}
 * @throws {Error} PROVIDER_NOT_CONFIGURED — provider registered but disabled
 * @throws {Error} PROVIDER_UNAVAILABLE    — provider name not registered
 * @throws {Error} PROVIDER_*              — provider call failed after all attempts
 */
const { authorizeFailover, reportRouting, refuse } = require('./failoverAuth');
const ST = require('../../src/observability/stageTimer'); // bench stage timer (no-op when off)

async function* routeStreamingProviderCall(provider, body, meta, signal) {
  const _tSel = ST.ON ? ST.start() : 0; // S29 provider selection, entry → first yield*
  if (typeof provider !== 'string' || !provider) {
    const err = new Error('PROVIDER_UNAVAILABLE');
    err.code  = 'PROVIDER_UNAVAILABLE';
    throw err;
  }

  const config = getProviderConfig(provider);
  if (!config || !config.enabled) {
    emit('WARN', 'PROVIDER_NOT_CONFIGURED', {
      provider,
      requestId: meta?.requestId ?? null,
      message:   'Provider is registered but not enabled — API key or base URL missing.',
    });
    const err = new Error('PROVIDER_NOT_CONFIGURED');
    err.code  = 'PROVIDER_NOT_CONFIGURED';
    throw err;
  }

  // ── Model allowlist — validated before selecting a native stream
  // handler or falling back to the non-streaming wrapper, sourced solely
  // from config.js via modelValidation.js. Each provider adapter also
  // re-validates independently (defense in depth): a failover target's
  // native stream handler is invoked directly below, bypassing this
  // top-of-function check, so the adapter-level check is what actually
  // enforces the allowlist on that path.
  const modelCheck = validateModelAgainstConfig(config, body?.model);
  if (!modelCheck.ok) {
    // a MISSING model (request omitted it and the provider has no configured default) is an operator
    // configuration gap, not a disallowed model — say which variable fixes it. Same refusal code as before.
    if (typeof body?.model !== 'string' || body.model.length === 0) {
      emit('WARN', 'PROVIDER_MODEL_MISSING', {
        provider,
        requestId: meta?.requestId ?? null,
        envVar:    `PROVIDER_DEFAULT_MODEL_${provider.toUpperCase()}`,
        message:   'Request omitted `model` and this provider has no default model configured — set the named env var or send `model`. Nothing was sent to the provider.',
      });
    }
    emit('WARN', 'PROVIDER_MODEL_NOT_ALLOWED', {
      provider,
      requestId: meta?.requestId ?? null,
      message:   'Requested model is not in the provider allowlist.',
    });
    const err = new Error(modelCheck.code);
    err.code  = modelCheck.code;
    throw err;
  }

  const safeMeta        = meta && typeof meta === 'object' ? meta : {};
  const nativeHandler   = STREAMING_REGISTRY[provider] || _compatStream(provider);
  const hasNativeStream = typeof nativeHandler === 'function';

  emit('INFO', 'PROVIDER_STREAM_ROUTING_DECISION', {
    requestedProvider: provider,
    hasNativeStreaming: hasNativeStream,
    requestId:         safeMeta.requestId ?? null,
  });

  if (ST.ON) ST.end('S29', _tSel);
  if (!hasNativeStream) {
    // Delegates to routeProviderCall() (router.js), which already applies
    // its own health-aware routing check (FAILOVER-4) — no need to repeat
    // it here.
    yield* _wrapNonStreaming(provider, body, safeMeta, signal);
    return;
  }

  let primaryEmitted = false;
  try {
    // FAILOVER-4 (mirrors router.js's _dispatch()) — skip the primary native
    // stream handler entirely when it's observably degraded and its
    // configured failover target is not, rather than only reacting after a
    // real streaming failure. Thrown INSIDE this try so it's caught by the
    // same failover logic below as any other retryable error.
    if (config.failoverProvider
        && providerHealth.isDegraded(provider)
        && !providerHealth.isDegraded(config.failoverProvider)) {
      emit('WARN', 'PROVIDER_HEALTH_DEGRADED_SKIP', {
        provider,
        failoverTarget: config.failoverProvider,
        health:         providerHealth.snapshot(provider),
        requestId:      safeMeta.requestId ?? null,
        message:        'Primary provider is observably degraded — routing streaming call directly to its configured failover target.',
      });
      throw _healthDegradedError();
    }

    // failover is forbidden once the primary has emitted ANY output chunk — the primary has then
    // demonstrably executed (and billed) the call, and a second provider would duplicate the execution and
    // splice two models' output into one stream. Tracked here at the router, independently of the adapter
    // layer's own flag (baseAdapter.runProviderStream), so it also holds for any handler that does not go
    // through runProviderStream. for-await (not yield*) is used only to observe emission; an early consumer
    // return still closes the inner generator (AsyncIteratorClose), exactly as yield* did.
    for await (const chunk of _guardedStream(provider, nativeHandler, body, safeMeta, signal)) {
      primaryEmitted = true;
      yield chunk;
    }
  } catch (err) {
    if (primaryEmitted && err && typeof err === 'object' && !err.providerMayHaveExecuted) {
      err.providerMayHaveExecuted = true;
    }
    if (primaryEmitted && RETRYABLE_CODES.has(err?.code) && config.failoverProvider) {
      emit('WARN', 'PROVIDER_STREAM_FAILOVER_SUPPRESSED', {
        primaryProvider: provider,
        code:            err?.code ?? null,
        requestId:       safeMeta.requestId ?? null,
        message:         'Primary provider failed after emitting output — failover suppressed (would re-execute the call on a second provider).',
      });
    }
    if (!primaryEmitted && _isRetryable(err)) {
      const failoverTarget = config.failoverProvider;
      if (typeof failoverTarget === 'string' && failoverTarget && failoverTarget !== provider) {
        // same gate as the non-streaming router.
        const auth = await authorizeFailover(safeMeta, provider, failoverTarget, err, body);
        if (!auth.ok) throw refuse(safeMeta, provider, failoverTarget, err, auth.reason);
        reportRouting(safeMeta, { requestedProvider: provider, executingProvider: failoverTarget, failover: { from: provider, to: failoverTarget, cause: err.code ?? null } });
        emit('WARN', 'PROVIDER_STREAM_FAILOVER', {
          primaryProvider:  provider,
          failoverProvider: failoverTarget,
          failoverReason:   err.code,
          requestId:        safeMeta.requestId ?? null,
          message:          'Primary provider streaming failed with retryable error; attempting failover.',
        });

        const failoverConfig  = getProviderConfig(failoverTarget);
        const failoverHandler = STREAMING_REGISTRY[failoverTarget] || _compatStream(failoverTarget);

        try {
          if (typeof failoverHandler === 'function' && failoverConfig?.enabled) {
            yield* _guardedStream(failoverTarget, failoverHandler, body, safeMeta, signal);
          } else if (failoverConfig?.enabled) {
            yield* _wrapNonStreaming(failoverTarget, body, safeMeta, signal);
          } else {
            throw err; // failover also unconfigured — rethrow original
          }

          emit('INFO', 'PROVIDER_STREAM_FAILOVER_SUCCESS', {
            primaryProvider:  provider,
            failoverProvider: failoverTarget,
            requestId:        safeMeta.requestId ?? null,
          });
          return;
        } catch (failoverErr) {
          emit('WARN', 'PROVIDER_STREAM_FAILOVER_FAILED', {
            primaryProvider:  provider,
            failoverProvider: failoverTarget,
            primaryCode:      err.code,
            failoverCode:     failoverErr.code,
            requestId:        safeMeta.requestId ?? null,
            message:          'Failover streaming provider also failed.',
          });
          throw failoverErr;
        }
      }
    }

    throw err;
  }
}

module.exports = { routeStreamingProviderCall };
