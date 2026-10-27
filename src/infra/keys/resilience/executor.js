'use strict';

/**
 * Shared resilience execution pipeline —.
 *
 * This is THE centralized implementation of timeout + bounded jittered retry
 * + circuit breaker + health tracking + metrics + structured logging for a
 * single provider operation. Both ResilientSigningProvider (NativeSigningProvider)
 * and ResilientKekProvider (KekProvider) call this exact function for every
 * method — neither decorator re-implements any part of this pipeline, so
 * there is exactly one place that can have a resilience bug, and every
 * current and future provider type gets identical behavior for free.
 *
 * Order of operations per attempt: circuit breaker gate -> deadline-bounded
 * call -> outcome recording (metrics + health + circuit breaker) -> retry
 * decision (bounded, jittered, transient-failures-only).
 */

const { withDeadline } = require('./withDeadline');
const { classifyFailure, isRetryableCategory, computeBackoffMs } = require('./retryPolicy');
const { emit } = require('../../../../services/logger');

let _metrics = null;
function _getMetrics() {
  if (!_metrics) _metrics = require('../../../observability/metrics');
  return _metrics;
}

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * @param {object} ctx
 * @param {string} ctx.providerName
 * @param {object} ctx.config             resilience/config.js shape
 * @param {import('./circuitBreaker').SigningCircuitBreaker} ctx.circuitBreaker
 * @param {import('./healthMonitor').SigningHealthMonitor}   ctx.health
 * @param {string} operation              short operation name, e.g. "sign"
 * @param {(signal: AbortSignal) => Promise<any>} fn
 * @param {object} [opts]
 * @param {boolean} [opts.retryable]                        default false
 * @param {(result:any) => boolean} [opts.resultIsFailure]   for never-throws contracts (healthCheck)
 * @param {(err:Error & {__resultPayload?: any}) => any} [opts.mapError]               convert a final failure into a resolved value
 * @returns {Promise<any>}
 */
async function executeResilientOperation(ctx, operation, fn, opts = {}) {
  const { providerName, config, circuitBreaker: cb, health } = ctx;
  const { retryable = false, resultIsFailure, mapError } = opts;
  const metrics = _getMetrics();

  if (!cb.allowRequest()) {
    metrics.signingCircuitRejectedTotal.inc({ provider: providerName, operation });
    emit('WARN', 'SIGNING_CIRCUIT_BREAKER_REJECTED', { provider: providerName, operation, state: cb.state });
    /** @type {any} */ const err = new Error(
      `Signing circuit breaker is OPEN for provider "${providerName}" — rejecting "${operation}" ` +
      `without contacting the provider`,
    );
    err.code = 'SIGNING_CIRCUIT_OPEN';
    if (mapError) return mapError(err);
    throw err;
  }

  const maxAttempts = retryable ? config.maxRetries : 1;
  let attempt = 0;
  let lastErr;

  while (attempt < maxAttempts) {
    attempt++;
    const startedAt = Date.now();

    try {
      const result = await withDeadline(
        (signal) => fn(signal),
        config.timeoutMs,
        { provider: providerName, operation },
      );

      if (resultIsFailure && resultIsFailure(result)) {
        /** @type {any} */ const synthetic = new Error((result && result.detail) || `"${operation}" reported an unhealthy result`);
        synthetic.__resultPayload = result;
        throw synthetic;
      }

      const elapsedMs = Date.now() - startedAt;
      metrics.signingLatencyMs.observe({ provider: providerName, operation }, elapsedMs);
      cb.onSuccess();
      health.recordSuccess(elapsedMs);

      if (attempt > 1) {
        metrics.signingRetrySuccessTotal.inc({ provider: providerName, operation });
        emit('INFO', 'SIGNING_RETRY_SUCCEEDED', { provider: providerName, operation, attempt, elapsedMs });
      }

      return result;
    } catch (err) {
      lastErr = err;
      const elapsedMs = Date.now() - startedAt;
      const category  = classifyFailure(err);
      const isTimeout = category === 'TIMEOUT';

      if (isTimeout) {
        metrics.signingTimeoutsTotal.inc({ provider: providerName, operation });
        emit('WARN', 'SIGNING_TIMEOUT', {
          provider: providerName, operation, attempt, elapsedMs, timeoutMs: config.timeoutMs,
        });
      }
      metrics.signingFailuresTotal.inc({ provider: providerName, operation, category });

      cb.onFailure();
      health.recordFailure({ timedOut: isTimeout, error: err });

      const canRetry = retryable && attempt < maxAttempts && isRetryableCategory(category);

      if (!canRetry) {
        if (attempt > 1) {
          metrics.signingRetryExhaustedTotal.inc({ provider: providerName, operation });
          emit('WARN', 'SIGNING_RETRY_EXHAUSTED', {
            provider: providerName, operation, attempts: attempt, category, error: err.message,
          });
        }
        emit('ERROR', 'SIGNING_OPERATION_FAILED', {
          provider: providerName, operation, attempt, elapsedMs, category,
          error: err.message, requestId: err.requestId ?? null, traceId: err.traceId ?? null,
        });
        if (mapError) return mapError(err);
        throw err;
      }

      const backoffMs = computeBackoffMs(attempt, config);
      metrics.signingRetriesTotal.inc({ provider: providerName, operation });
      emit('INFO', 'SIGNING_RETRY_SCHEDULED', {
        provider: providerName, operation, attempt, nextAttempt: attempt + 1, backoffMs, category, error: err.message,
      });
      await _sleep(backoffMs);
    }
  }

  // Unreachable in practice (the loop above always returns or throws) — kept
  // as a defensive fallback so this can never silently resolve undefined.
  if (mapError) return mapError(lastErr);
  throw lastErr;
}

module.exports = { executeResilientOperation };
