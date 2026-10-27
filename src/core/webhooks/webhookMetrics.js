'use strict';

/**
 * Webhook Delivery Metrics — Component #28
 *
 * In-process counters and histograms for webhook delivery observability.
 * Mirrors the pattern used by src/core/persistenceRecovery/metrics.js.
 *
 * Metrics exposed:
 *   webhook_deliveries_total         — successful deliveries (by event_type)
 *   webhook_delivery_failures_total  — failed deliveries (by event_type)
 *   webhook_retries_total            — retry attempts (by event_type)
 *   webhook_delivery_latency_ms      — cumulative delivery latency
 *   webhook_queue_depth_total        — enqueue count (approximates queue depth)
 */

// ── Simple counter ────────────────────────────────────────────────────────────

const _counters = new Map();
const _latency  = new Map();

function _key(name, labels) {
  if (!labels) return name;
  const parts = Object.keys(labels).sort().map(k => `${k}="${labels[k]}"`).join(',');
  return `${name}{${parts}}`;
}

function inc(name, labels) {
  const k = _key(name, labels);
  _counters.set(k, (_counters.get(k) || 0) + 1);
}

function add(name, value, labels) {
  const k = _key(name, labels);
  _latency.set(k, (_latency.get(k) || 0) + value);
}

function snapshot() {
  return {
    counters: Object.fromEntries(_counters),
    latency:  Object.fromEntries(_latency),
  };
}

function reset() {
  _counters.clear();
  _latency.clear();
}

module.exports = { inc, add, snapshot, reset };
