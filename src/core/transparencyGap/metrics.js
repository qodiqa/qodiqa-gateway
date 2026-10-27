'use strict';

/**
 * Transparency Gap Metrics — Component #14
 *
 * In-process counters for the transparency gap subsystem.
 * Used for admin stats, snapshot visibility, and resolution rate tracking.
 *
 * These complement the Prometheus metrics in src/observability/metrics.js,
 * which provide the Prometheus-format exposition for dashboards.
 */

const _counters = new Map();
const _gauges   = new Map();

function _key(name, labels) {
  if (!labels || Object.keys(labels).length === 0) return name;
  const suffix = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(',');
  return `${name}{${suffix}}`;
}

// ── Counter operations ────────────────────────────────────────────────────────

function inc(name, labels = {}) {
  const k = _key(name, labels);
  _counters.set(k, (_counters.get(k) ?? 0) + 1);
}

function add(name, value, labels = {}) {
  const k = _key(name, labels);
  _counters.set(k, (_counters.get(k) ?? 0) + value);
}

function getCounter(name, labels = {}) {
  return _counters.get(_key(name, labels)) ?? 0;
}

// ── Gauge operations ──────────────────────────────────────────────────────────

function set(name, value, labels = {}) {
  _gauges.set(_key(name, labels), value);
}

function incGauge(name, labels = {}) {
  const k = _key(name, labels);
  _gauges.set(k, (_gauges.get(k) ?? 0) + 1);
}

function decGauge(name, labels = {}) {
  const k = _key(name, labels);
  const cur = _gauges.get(k) ?? 0;
  _gauges.set(k, Math.max(0, cur - 1));
}

function getGauge(name, labels = {}) {
  return _gauges.get(_key(name, labels)) ?? 0;
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

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

module.exports = {
  inc,
  add,
  set,
  incGauge,
  decGauge,
  getCounter,
  getGauge,
  snapshot,
  _reset,
};
