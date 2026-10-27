'use strict';

/**
 * Rate Limit Observability Metrics —
 *
 * Per-surface, per-dimension counters and gauges covering:
 *
 * Counters (cumulative for process lifetime):
 *   rl_requests_total         — all requests processed by rate limiting
 *   rl_requests_allowed_total — requests passed through
 *   rl_limited_total          — requests rejected (HTTP 429)
 *   rl_redis_failures_total   — Redis errors causing fail-closed 429s
 *   rl_burst_consumed_total   — burst capacity consumed events
 *   rl_latency_ms_total       — cumulative middleware processing time (ms)
 *
 * Gauges (point-in-time, overwritten on each update):
 *   rl_quota_utilization      — count / maxRequests × 1000 per surface+dimension
 *   rl_active_buckets         — approximate active key count (informational)
 *
 * Rejection reasons (on rl_limited_total):
 *   SUSTAINED — sliding window exceeded
 *   BURST     — burst window exceeded
 *   DISABLED  — identity explicitly disabled
 *   BACKEND   — Redis unavailable
 *
 * Usage:
 *   const metrics = require('./metrics');
 *   metrics.inc('rl_requests_total', { surface: 'portal' });
 *   metrics.snapshot(); // { counters: {...}, gauges: {...} }
 */

const _counters = new Map();
const _gauges   = new Map();

function _label(name, labels = {}) {
  const parts = Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}="${v}"`);
  return `${name}{${parts.join(',')}}`;
}

function inc(name, labels = {}) {
  const k = _label(name, labels);
  _counters.set(k, (_counters.get(k) || 0) + 1);
}

function add(name, value, labels = {}) {
  const k = _label(name, labels);
  _counters.set(k, (_counters.get(k) || 0) + value);
}

function get(name, labels = {}) {
  return _counters.get(_label(name, labels)) || 0;
}

function set(name, value, labels = {}) {
  _gauges.set(_label(name, labels), value);
}

function getGauge(name, labels = {}) {
  return _gauges.get(_label(name, labels)) ?? 0;
}

function snapshot() {
  return {
    counters: Object.fromEntries(_counters),
    gauges:   Object.fromEntries(_gauges),
  };
}

function _reset() {
  _counters.clear();
  _gauges.clear();
}

module.exports = { inc, add, get, set, getGauge, snapshot, _reset };
