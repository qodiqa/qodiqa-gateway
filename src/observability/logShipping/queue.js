'use strict';

// Asynchronous dispatch queue with per-destination retry and failure isolation.
//
// Design invariants:
//   • ship() is synchronous and returns immediately — never awaited by caller.
//   • Each destination is dispatched independently.  One destination's failure
//     never affects another.
//   • Exponential backoff: 1s, 2s, 4s, … capped at 30s per retry.
//   • Maximum retries: configurable via config.maxRetries (default 3).
//   • Retryable errors: network failures (ECONNREFUSED/ETIMEDOUT/ENOTFOUND),
//     HTTP 429, 502, 503, 504 — as signalled by err.retryable.
//   • Non-retryable errors: authentication failures, bad payloads, config errors.
//   • All failures are swallowed — they must never propagate to callers.
//   • Per-destination in-flight events are capped at config.maxQueueDepth
//     (default 10,000) to bound memory if a destination is persistently
//     unreachable; events beyond the cap are dropped and counted rather than
//     queued without limit (see logs_dropped_total / qodiqa_logship_dropped_total).
//   • drain(timeoutMs) lets callers (graceful shutdown) wait for in-flight
//     dispatches to settle, bounded so shutdown never hangs indefinitely.

const _defaultTaskRunner = require('../../runtime/backgroundTasks/BackgroundTaskRunner');
const metrics             = require('../metrics');

const RETRYABLE_CODES = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET']);

// Default cap on in-flight events per destination (see config.maxQueueDepth).
// Protects against unbounded memory growth if a destination is persistently
// slow/unreachable — events beyond the cap are dropped and counted, not
// queued indefinitely.
const DEFAULT_MAX_QUEUE_DEPTH = 10_000;

function _isRetryable(err) {
  if (!err) return false;
  if (err.retryable === true) return true;
  if (err.code && RETRYABLE_CODES.has(err.code)) return true;
  return false;
}

async function _sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function _setHealthGauge(destinationName, status) {
  // 1 = healthy, 0 = degraded, -1 = unknown — see metrics.js for the gauge definition.
  const value = status === 'healthy' ? 1 : status === 'degraded' ? 0 : -1;
  try { metrics.logShipDestinationHealthy.set({ destination: destinationName }, value); } catch { /* metrics must never break dispatch */ }
}

async function _dispatchWithRetry(destination, events, maxRetries, state) {
  let attempt = 0;
  while (true) {
    try {
      await destination.send(events);
      state.exported    += events.length;
      state.lastSuccess  = new Date().toISOString();
      metrics.logShipExportedTotal.inc({ destination: destination.name }, events.length);
      _setHealthGauge(destination.name, 'healthy');
      return;
    } catch (err) {
      if (attempt < maxRetries && _isRetryable(err)) {
        state.retried += events.length;
        metrics.logShipRetriesTotal.inc({ destination: destination.name }, events.length);
        const delay = Math.min(1000 * Math.pow(2, attempt), 30_000);
        await _sleep(delay);
        attempt++;
      } else {
        // Non-retryable or max retries exhausted — record failure, do NOT throw
        state.failed      += events.length;
        state.lastFailure  = new Date().toISOString();
        metrics.logShipFailuresTotal.inc({ destination: destination.name }, events.length);
        _setHealthGauge(destination.name, 'degraded');
        return;
      }
    }
  }
}

/**
 * Create an async dispatch queue for the given destinations.
 *
 * @param {Array<{ name: string, send: Function }>} destinations
 * @param {{ maxRetries: number }}                  config
 * @param {object}   [opts]
 * @param {object}   [opts._taskRunner]  Injected BackgroundTaskRunner (testing).
 * @returns {{ ship, getHealth, getMetrics }}
 */
function createQueue(destinations, config, opts = {}) {
  const _taskRunner    = opts._taskRunner || _defaultTaskRunner;
  const _maxQueueDepth = config.maxQueueDepth > 0 ? config.maxQueueDepth : DEFAULT_MAX_QUEUE_DEPTH;
  // Per-destination mutable state — never exposed directly
  const _state = new Map();
  for (const dest of destinations) {
    _state.set(dest.name, {
      exported:    0,
      failed:      0,
      retried:     0,
      dropped:     0,
      queueDepth:  0,
      lastSuccess: null,
      lastFailure: null,
      latencySamples: [],
    });
  }

  // In-flight dispatch promises, for graceful shutdown draining. Cleared as
  // each dispatch settles regardless of outcome (never left dangling).
  const _inFlight = new Set();

  /**
   * Enqueue a log event for export to all active destinations.
   * Returns immediately — never blocks.
   *
   * @param {object|object[]} events
   */
  function ship(events) {
    const batch = Array.isArray(events) ? events : [events];
    if (batch.length === 0) return;

    for (const dest of destinations) {
      const state = _state.get(dest.name);

      if (state.queueDepth >= _maxQueueDepth) {
        state.dropped += batch.length;
        try { metrics.logShipDroppedTotal.inc({ destination: dest.name }, batch.length); } catch { /* never break ship() */ }
        continue;
      }

      state.queueDepth++;
      try { metrics.logShipQueueDepth.set({ destination: dest.name }, state.queueDepth); } catch { /* never break ship() */ }

      const start = Date.now();
      // Finding 3.6: runs through BackgroundTaskRunner for consistent
      // isolation/logging/metrics across every background job.
      // _dispatchWithRetry() already never rejects (its own internal
      // retry/backoff swallows failures into `state`) — this doesn't
      // change that behavior, it adds structured logging/metrics on top.
      const task = _taskRunner.runTask('log-shipping-dispatch', () => _dispatchWithRetry(dest, batch, config.maxRetries, state))
        .then(() => {
          const lat = Date.now() - start;
          state.latencySamples.push(lat);
          if (state.latencySamples.length > 100) state.latencySamples.shift();
          try { metrics.logShipDispatchDurationMs.observe({ destination: dest.name }, lat); } catch { /* never break ship() */ }
        })
        .catch(() => {
          // runTask() never rejects for this non-critical task — defensive catch
        })
        .finally(() => {
          state.queueDepth = Math.max(0, state.queueDepth - 1);
          try { metrics.logShipQueueDepth.set({ destination: dest.name }, state.queueDepth); } catch { /* never break ship() */ }
          _inFlight.delete(task);
        });
      _inFlight.add(task);
    }
  }

  /**
   * Await in-flight dispatches, bounded by timeoutMs so shutdown never hangs
   * indefinitely on an unreachable destination. Never throws.
   *
   * @param {number} [timeoutMs=5000]
   */
  async function drain(timeoutMs = 5000) {
    if (_inFlight.size === 0) return;
    try {
      await Promise.race([Promise.all(Array.from(_inFlight)), _sleep(timeoutMs)]);
    } catch {
      // Individual dispatch failures are already swallowed by _dispatchWithRetry;
      // this catch only guards against the race itself never rejecting unexpectedly.
    }
  }

  /**
   * Health status for each destination.
   *
   * status: 'healthy'  — never failed, or last success is more recent than last failure
   *         'degraded' — last failure is more recent than last success
   *         'unknown'  — no traffic yet
   *
   * @returns {object}  destination name → health object
   */
  function getHealth() {
    const out = {};
    for (const [name, s] of _state.entries()) {
      let status = 'unknown';
      if (s.lastSuccess && !s.lastFailure)                    status = 'healthy';
      else if (!s.lastSuccess && s.lastFailure)               status = 'degraded';
      else if (s.lastSuccess && s.lastFailure)
        status = s.lastSuccess >= s.lastFailure ? 'healthy' : 'degraded';

      out[name] = {
        destination:  name,
        status,
        lastSuccess:  s.lastSuccess,
        lastFailure:  s.lastFailure,
        queuedEvents: s.queueDepth,
      };
    }
    return out;
  }

  /**
   * Aggregate metrics for each destination.
   *
   * @returns {object}  destination name → metrics object
   */
  function getMetrics() {
    const out = {};
    for (const [name, s] of _state.entries()) {
      const samples = s.latencySamples;
      const avgLatency = samples.length
        ? Math.round(samples.reduce((a, b) => a + b, 0) / samples.length)
        : null;

      out[name] = {
        logs_exported_total:     s.exported,
        logs_failed_total:       s.failed,
        logs_retried_total:      s.retried,
        logs_dropped_total:      s.dropped,
        destination_latency_ms:  avgLatency,
        queue_depth:             s.queueDepth,
      };
    }
    return out;
  }

  return { ship, getHealth, getMetrics, drain };
}

module.exports = { createQueue, _isRetryable };
