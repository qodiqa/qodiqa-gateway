'use strict';

/**
 * Provider router — routes requests to the correct provider adapter and handles
 * failover when a primary provider fails with a retryable error.
 *
 * Design properties:
 *   • The router is the ONLY consumer of individual provider handlers.  External
 *     callers (execution.js) interact with routeProviderCall() only.
 *   • Provider selection is based on the `provider` field from the signed artifact.
 *     The router cannot change which provider a request is directed to without an
 *     audit record — only the failover path changes the actual call target.
 *   • Failover: if the primary provider throws a retryable error (PROVIDER_UNAVAILABLE,
 *     PROVIDER_RATE_LIMITED, PROVIDER_TIMEOUT) and a failover provider is configured
 *     via PROVIDER_FAILOVER_<PRIMARY_NAME>, the router tries the failover and emits
 *     a PROVIDER_FAILOVER audit event.  The audit record on success reflects the
 *     actual provider used, not the requested provider.
 *   • The router never modifies: policies, artifacts, audit outputs, or cryptographic
 *     evidence.  Only model execution varies.
 *   • If a provider is not configured (disabled), the router throws PROVIDER_NOT_CONFIGURED.
 *   • If a provider name is not registered, the router throws PROVIDER_UNAVAILABLE.
 * • Model allowlist: every dispatch attempt — including each failover
 *     attempt, against the failover target's own allowlist — is validated by
 *     modelValidation.js BEFORE the provider handler is invoked. This is the
 *     single choke point every non-streaming provider call passes through, so
 *     an unlisted model never reaches a handler via this path. If the model
 *     is not allowed, the router throws PROVIDER_MODEL_NOT_ALLOWED.
 *   • Cancellation: an optional AbortSignal may be passed through to the provider
 *     handler so that route-level timeouts and client disconnects reach the
 *     outbound network call.  If the signal is already aborted when dispatch
 *     reaches this router — including between failover attempts — the router
 *     throws PROVIDER_CANCELLED immediately, without invoking (or retrying)
 *     the handler.  PROVIDER_CANCELLED is intentionally excluded from
 *     RETRYABLE_CODES so a cancelled call never triggers failover.
 *
 * Failover configuration:
 *   PROVIDER_FAILOVER_OPENAI=anthropic    — if openai fails, try anthropic
 *   PROVIDER_FAILOVER_ANTHROPIC=openai    — if anthropic fails, try openai
 *   PROVIDER_FAILOVER_GEMINI=anthropic    — etc.
 *   (Any enabled provider name is a valid failover target.)
 *
 * Telemetry events:
 *   PROVIDER_ROUTING_DECISION  — emitted before each dispatch attempt
 *   PROVIDER_FAILOVER          — emitted when switching to failover provider
 *   PROVIDER_FAILOVER_FAILED   — emitted when failover also fails
 */

const { callOpenAI }    = require('./openai');
const { callAnthropic } = require('./anthropic');
const { callGemini }    = require('./gemini');
const { callMistral }   = require('./mistral');
const { callLlama }     = require('./llama');
const { callLocal }     = require('./local');
const { callAzure }     = require('./azure');       //
const { callBedrock }   = require('./bedrock');     //
const { getProviderConfig }          = require('./config');
const compat = require('./compat');   // dynamic OpenAI-compatible providers
const compatRegistry = () => require('../../src/core/providers/compatRegistry');
const { validateModelAgainstConfig } = require('./modelValidation');
const { emit }          = require('../logger');
const { getCircuitBreaker } = require('./providerCircuitBreaker');
const { CIRCUIT_BREAKER_CONFIG } = require('./circuitBreakerConfig');
const providerHealth = require('./providerHealth');
const providerLoad = require('./providerLoad');
const { monoNowMs } = require('../../src/infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

// ── Provider registry ─────────────────────────────────────────────────────────
// Maps canonical provider names to their handler functions.
// Handlers are private to this module — external code uses routeProviderCall().

const REGISTRY = Object.freeze({
  openai:    callOpenAI,
  anthropic: callAnthropic,
  gemini:    callGemini,
  mistral:   callMistral,
  llama:     callLlama,
  local:     callLocal,
  azure:     callAzure,
  bedrock:   callBedrock,
});

// ── Error classification ──────────────────────────────────────────────────────

const RETRYABLE_CODES = new Set([
  'PROVIDER_UNAVAILABLE',
  'PROVIDER_RATE_LIMITED',
  'PROVIDER_TIMEOUT',
  // A fast-failed request never reached the provider — failover should still
  // be attempted against the configured failover target (Register #107).
  'PROVIDER_CIRCUIT_OPEN',
  // FAILOVER-4: routed away BEFORE ever contacting the provider because its
  // recent latency/timeout/failure history is observably degraded — flows
  // through the same failover-attempt logic as every other retryable code.
  'PROVIDER_HEALTH_DEGRADED',
]);

// Failures that count against a provider's circuit breaker (Register #107).
// Deliberately narrower than RETRYABLE_CODES: PROVIDER_CIRCUIT_OPEN itself
// must never re-count (no actual attempt was made), and PROVIDER_CANCELLED /
// config-time errors (PROVIDER_NOT_CONFIGURED, PROVIDER_MODEL_NOT_ALLOWED)
// never reach this classification at all since they're thrown before the
// breaker gate below.
const CIRCUIT_BREAKER_FAILURE_CODES = new Set([
  'PROVIDER_UNAVAILABLE',
  'PROVIDER_RATE_LIMITED',
  'PROVIDER_TIMEOUT',
]);

function _isRetryable(err) {
  // never fail over a completion the first provider may already have run (answered 5xx, timeout after
  // send, connection reset) — a second provider call would double the execution and its billing.
  return RETRYABLE_CODES.has(err?.code) && !err?.providerMayHaveExecuted;
}

function _countsAgainstBreaker(err) {
  return CIRCUIT_BREAKER_FAILURE_CODES.has(err?.code);
}

function _cancelledError() {
  const err = new Error('PROVIDER_CANCELLED');
  err.code  = 'PROVIDER_CANCELLED';
  return err;
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

// ── Router ────────────────────────────────────────────────────────────────────

/**
 * Route a provider call with optional failover.
 *
 * @param {string}      provider     — canonical provider name from the artifact
 * @param {object}      body         — { model, messages }
 * @param {object}      meta         — { requestId, requestHash, policyHash }
 * @param {AbortSignal} [signal]     — cancellation: route-level timeout or client disconnect
 * @returns {Promise<object>}        — normalized ProviderResponse
 * @throws {Error} PROVIDER_NOT_CONFIGURED  — provider not enabled
 * @throws {Error} PROVIDER_UNAVAILABLE     — provider not registered
 * @throws {Error} PROVIDER_CANCELLED       — signal was already aborted before/during dispatch
 * @throws {Error} PROVIDER_CIRCUIT_OPEN    — provider's circuit breaker is OPEN (Register #107)
 * @throws {Error} <PROVIDER_*>             — provider call failed after all attempts
 */
async function routeProviderCall(provider, body, meta, signal) {
  if (typeof provider !== 'string' || !provider) {
    const err = new Error('PROVIDER_UNAVAILABLE');
    err.code  = 'PROVIDER_UNAVAILABLE';
    throw err;
  }

  const safeMeta = meta && typeof meta === 'object' ? meta : {};

  return _dispatch(provider, body, safeMeta, 0, signal);
}

const { authorizeFailover, reportRouting, refuse } = require('./failoverAuth');
// stage timer (bench only; no-op unless QODIQA_BENCH_STAGE_TIMING=true). S29 = selection
// (registry, config, model allowlist, breaker, health) up to the handler call; S30 = the handler call.
const ST = require('../../src/observability/stageTimer');

async function _dispatch(provider, body, meta, depth, signal) {
  const _tSel = ST.ON ? ST.start() : 0;
  // Cancellation takes priority over every other check — never spend work
  // resolving a provider, validating config, or dispatching once the caller
  // has already cancelled.
  if (signal?.aborted) {
    throw _cancelledError();
  }

  // Guard against infinite failover chains
  if (depth > 1) {
    const err = new Error('PROVIDER_UNAVAILABLE');
    err.code  = 'PROVIDER_UNAVAILABLE';
    throw err;
  }

  const handler = REGISTRY[provider] || (compatRegistry().isCompatName(provider) && compatRegistry().allNames().includes(provider) ? compat.handlerFor(provider) : null);
  if (!handler) {
    emit('WARN', 'PROVIDER_UNAVAILABLE', {
      provider,
      requestId: meta.requestId ?? null,
      message:   'Provider name not in registry.',
    });
    const err = new Error('PROVIDER_UNAVAILABLE');
    err.code  = 'PROVIDER_UNAVAILABLE';
    throw err;
  }

  const config = getProviderConfig(provider);
  if (!config || !config.enabled) {
    emit('WARN', 'PROVIDER_NOT_CONFIGURED', {
      provider,
      requestId: meta.requestId ?? null,
      message:   'Provider is registered but not enabled — API key or base URL missing.',
    });
    const err = new Error('PROVIDER_NOT_CONFIGURED');
    err.code  = 'PROVIDER_NOT_CONFIGURED';
    throw err;
  }

  // ── Model allowlist — validated before provider selection/dispatch,
  // sourced solely from config.js via modelValidation.js. Re-run on every
  // failover attempt against the failover target's own config, since a model
  // valid for one provider is not necessarily valid for another.
  const modelCheck = validateModelAgainstConfig(config, body?.model);
  if (!modelCheck.ok) {
    // a MISSING model (request omitted it and the provider has no configured default) is an operator
    // configuration gap, not a disallowed model — say which variable fixes it. Same refusal code as before.
    if (typeof body?.model !== 'string' || body.model.length === 0) {
      emit('WARN', 'PROVIDER_MODEL_MISSING', {
        provider,
        requestId: meta.requestId ?? null,
        envVar:    `PROVIDER_DEFAULT_MODEL_${provider.toUpperCase()}`,
        message:   'Request omitted `model` and this provider has no default model configured — set the named env var or send `model`. Nothing was sent to the provider.',
      });
    }
    emit('WARN', 'PROVIDER_MODEL_NOT_ALLOWED', {
      provider,
      requestId: meta.requestId ?? null,
      message:   'Requested model is not in the provider allowlist.',
    });
    const err = new Error(modelCheck.code);
    err.code  = modelCheck.code;
    throw err;
  }

  // ── Circuit breaker (Register #107) — gates the actual outbound call only,
  // after config/model validation above so those never count against it.
  // Fast-fails while OPEN rather than waiting out the full provider timeout.
  // The allowRequest() check lives INSIDE the try block below so a fast-fail
  // is caught by the same catch/failover logic as a real handler failure —
  // otherwise an OPEN primary would never fail over.
  const breaker = getCircuitBreaker(provider, CIRCUIT_BREAKER_CONFIG);
  let _probeId;
  let _probe = false; // admitted as the half-open recovery probe (3.7)

  try {
    const _permit = breaker.acquire();
    _probe = _permit.probe;
    _probeId = _permit.probeId;
    if (!_permit.allowed) {
      emit('WARN', 'PROVIDER_CIRCUIT_OPEN', {
        provider,
        requestId: meta.requestId ?? null,
        message:   'Circuit breaker is OPEN for this provider — fast-failing without contacting it.',
      });
      throw _circuitOpenError();
    }

    // ── Health-aware routing (FAILOVER-4) — the circuit breaker above only
    // reacts once a provider has crossed the hard consecutive-failure
    // threshold; this redirects EARLIER, at the primary dispatch (depth 0)
    // only, when the primary's own recent latency/timeout/failure history
    // (providerHealth.js, populated from real outcomes below) already shows
    // it's degraded AND its configured failover target is not itself also
    // degraded. Without this, every request during a sustained-but-not-yet-
    // circuit-tripping degradation independently pays the primary's full
    // timeout before ever trying the known-better failover target — exactly
    // the SLA gap this finding identified. minSamples in providerHealth.js
    // guards against redirecting on a single blip.
    if (depth === 0 && config.failoverProvider
        && providerHealth.isDegraded(provider)
        && !providerHealth.isDegraded(config.failoverProvider)) {
      emit('WARN', 'PROVIDER_HEALTH_DEGRADED_SKIP', {
        provider,
        failoverTarget: config.failoverProvider,
        health:         providerHealth.snapshot(provider),
        requestId:      meta.requestId ?? null,
        message:        'Primary provider is observably degraded (recent latency/timeout/failure history) — routing directly to its configured failover target without attempting it first.',
      });
      throw _healthDegradedError();
    }

    emit('INFO', 'PROVIDER_ROUTING_DECISION', {
      requestedProvider: provider,
      selectedProvider:  provider,
      failoverDepth:     depth,
      requestId:         meta.requestId ?? null,
    });

    const _healthStart = monoNowMs(); // monotonic (same-process): feeds providerHealth's latency penalty (a routing decision)
    let result;
    let _tCall = 0;
    if (ST.ON) { ST.end('S29', _tSel); _tCall = ST.start(); }
    try {
      result = await providerLoad.track(provider, () => handler(body, meta, signal));   // in-flight count (least-loaded routing)
      if (ST.ON) ST.end('S30', _tCall);
    } catch (handlerErr) {
      if (ST.ON) ST.end('S30', _tCall);
      providerHealth.recordOutcome(provider, {
        ok: false,
        timedOut: handlerErr?.code === 'PROVIDER_TIMEOUT',
        latencyMs: monoNowMs() - _healthStart, // monotonic (same-process)
      });
      throw handlerErr;
    }
    providerHealth.recordOutcome(provider, { ok: true, timedOut: false, latencyMs: monoNowMs() - _healthStart }); // monotonic (same-process)

    breaker.onSuccess();
    // the provider that actually executed (depth 0: the requested one).
    if (depth === 0) reportRouting(meta, { requestedProvider: provider, executingProvider: provider, failover: null });
    return result;
  } catch (err) {
    if (_countsAgainstBreaker(err)) breaker.onFailure();
    else if (_probe) breaker.releaseProbe(_probeId); // 3.7: an uncounted outcome must not strand the half-open probe slot

    if (_isRetryable(err) && depth === 0) {
      const failoverTarget = config.failoverProvider;

      if (failoverTarget && typeof failoverTarget === 'string' && failoverTarget !== provider) {
        // the configured pair is necessary, never sufficient —
        // the caller must authorize THIS target (consent, identity scope).
        const auth = await authorizeFailover(meta, provider, failoverTarget, err, body);
        if (!auth.ok) throw refuse(meta, provider, failoverTarget, err, auth.reason);

        emit('WARN', 'PROVIDER_FAILOVER', {
          primaryProvider:  provider,
          failoverProvider: failoverTarget,
          failoverReason:   err.code,
          requestId:        meta.requestId ?? null,
          message:          'Primary provider failed with retryable error; attempting failover.',
        });

        try {
          const result = await _dispatch(failoverTarget, body, meta, depth + 1, signal);
          // Failover succeeded — emit the routing outcome
          emit('INFO', 'PROVIDER_FAILOVER_SUCCESS', {
            primaryProvider:  provider,
            failoverProvider: failoverTarget,
            requestId:        meta.requestId ?? null,
          });
          reportRouting(meta, { requestedProvider: provider, executingProvider: failoverTarget, failover: { from: provider, to: failoverTarget, cause: err.code ?? null } });
          return result;
        } catch (failoverErr) {
          emit('WARN', 'PROVIDER_FAILOVER_FAILED', {
            primaryProvider:  provider,
            failoverProvider: failoverTarget,
            primaryCode:      err.code,
            failoverCode:     failoverErr.code,
            requestId:        meta.requestId ?? null,
            message:          'Failover provider also failed.',
          });
          // Throw the failover error (the more recent failure)
          throw failoverErr;
        }
      }
    }

    throw err;
  }
}

/**
 * Return the list of all registered provider names.
 * @returns {string[]}
 */
function listProviders() {
  return [...Object.keys(REGISTRY), ...compatRegistry().allNames()];
}

/**
 * Return the list of currently enabled provider names.
 * @returns {string[]}
 */
function listEnabledProviders() {
  return listProviders().filter(name => {
    const cfg = getProviderConfig(name);
    return cfg && cfg.enabled;
  });
}

module.exports = { routeProviderCall, listProviders, listEnabledProviders };
