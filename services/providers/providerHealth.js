'use strict';

const { monoNowMs } = require('../../src/infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

/**
 * Provider health tracker (FAILOVER-4).
 *
 * Complements providerCircuitBreaker.js's binary CLOSED/OPEN state with a
 * continuous rolling health signal per provider — recent latency, timeout
 * frequency, and failure rate — computed from real call outcomes recorded
 * by router.js on every dispatch attempt. The circuit breaker answers "has
 * this provider crossed the hard failure threshold" (fast-fail); this module
 * answers "is this provider trending unhealthy right now", which lets
 * router.js route AROUND a provider that is still technically CLOSED but
 * observably degrading, rather than only reacting after a request actually
 * fails against it (the static "pay the full primary timeout, then fail
 * over" behavior FAILOVER-4 identified).
 *
 * Deliberately NOT a hard-coded provider priority list: nothing here ranks
 * providers against each other or encodes which provider is "better" — it
 * only measures each provider's own recent behavior against configurable
 * thresholds, and router.js only ever redirects to whatever failover target
 * is already operator-configured for that primary (PROVIDER_FAILOVER_<X>).
 * A future adapter can add/replace providers without touching this
 * module — it keys purely on the provider name strings already flowing
 * through router.js.
 *
 * Environment variables:
 *   PROVIDER_HEALTH_WINDOW_MS       — rolling observation window (default 60000)
 *   PROVIDER_HEALTH_MIN_SAMPLES     — minimum samples before a score is
 *                                     trusted enough to redirect routing
 *                                     (default 5 — avoids overreacting to a
 *                                     single blip)
 *   PROVIDER_HEALTH_DEGRADED_SCORE  — score (0..1) below which a provider is
 *                                     considered degraded (default 0.5)
 *   PROVIDER_HEALTH_SLOW_LATENCY_MS — average latency above which the score
 *                                     is penalized (default 5000)
 */

function _parseFloat(val, fallback) {
  const n = parseFloat(val);
  return Number.isFinite(n) ? n : fallback;
}
function _parseInt(val, fallback) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function _config() {
  return {
    windowMs:       _parseInt(process.env.PROVIDER_HEALTH_WINDOW_MS, 60_000),
    minSamples:     _parseInt(process.env.PROVIDER_HEALTH_MIN_SAMPLES, 5),
    degradedScore:  _parseFloat(process.env.PROVIDER_HEALTH_DEGRADED_SCORE, 0.5),
    slowLatencyMs:  _parseInt(process.env.PROVIDER_HEALTH_SLOW_LATENCY_MS, 5_000),
  };
}

class ProviderHealth {
  constructor(name) {
    this.name    = name;
    this._events = []; // { ts, ok, timedOut, latencyMs }
  }

  /** @param {{ ok: boolean, timedOut?: boolean, latencyMs?: number }} outcome */
  recordOutcome({ ok, timedOut = false, latencyMs = 0 }) {
    this._events.push({ ts: monoNowMs(), ok: !!ok, timedOut: !!timedOut, latencyMs: Number(latencyMs) || 0 }); // monotonic (same-process)
    this._prune();
  }

  _prune() {
    const cutoff = monoNowMs() - _config().windowMs; // monotonic (same-process)
    while (this._events.length && this._events[0].ts < cutoff) this._events.shift();
  }

  /**
   * Composite health snapshot over the current rolling window.
   * score: 1 = fully healthy, 0 = fully unhealthy. A provider with zero
   * recent samples is reported as fully healthy (score 1, samples 0) —
   * "unknown" must never be treated as "degraded", only as "not yet enough
   * evidence to redirect away from" (see isDegraded()'s minSamples gate).
   */
  snapshot() {
    this._prune();
    const { slowLatencyMs } = _config();
    const n = this._events.length;
    if (n === 0) return { samples: 0, failureRate: 0, timeoutRate: 0, avgLatencyMs: 0, successSamples: 0, successLatencyMs: 0, score: 1 };

    const failures     = this._events.filter(e => !e.ok).length;
    const timeouts      = this._events.filter(e => e.timedOut).length;
    const avgLatencyMs  = this._events.reduce((sum, e) => sum + e.latencyMs, 0) / n;
    const failureRate   = failures / n;
    const timeoutRate   = timeouts / n;
    const latencyPenalty = avgLatencyMs > slowLatencyMs
      ? Math.min(1, (avgLatencyMs - slowLatencyMs) / slowLatencyMs)
      : 0;

    const score = Math.max(0, 1 - (failureRate * 0.5 + timeoutRate * 0.35 + latencyPenalty * 0.15));
    // the latency of the calls that SUCCEEDED (a provider that fails instantly is not "fast")
    const ok = this._events.filter(e => e.ok);
    const successLatencyMs = ok.length ? ok.reduce((sum, e) => sum + e.latencyMs, 0) / ok.length : 0;
    return { samples: n, failureRate, timeoutRate, avgLatencyMs, successSamples: ok.length, successLatencyMs, score };
  }

  /** True only when enough recent evidence exists AND the score is below threshold. */
  isDegraded() {
    const { minSamples, degradedScore } = _config();
    const s = this.snapshot();
    return s.samples >= minSamples && s.score < degradedScore;
  }
}

// ── Registry (one tracker per provider name, mirrors providerCircuitBreaker.js) ──

const _registry = new Map();

function _get(name) {
  if (!_registry.has(name)) _registry.set(name, new ProviderHealth(name));
  return _registry.get(name);
}

function recordOutcome(name, outcome) { _get(name).recordOutcome(outcome); }
function isDegraded(name)             { return _get(name).isDegraded(); }
function snapshot(name)               { return _get(name).snapshot(); }

/** Clear all tracked provider health state. Used in tests to reset between runs. */
function resetAll() { _registry.clear(); }

/** Snapshot of every tracked provider's health, for observability. */
function snapshotAll() {
  const out = {};
  for (const [name] of _registry) out[name] = snapshot(name);
  return out;
}

module.exports = { recordOutcome, isDegraded, snapshot, snapshotAll, resetAll };
