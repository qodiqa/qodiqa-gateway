'use strict';

/**
 * Persistence Recovery Queue Metrics — Component #13
 *
 * In-process counters for recovery queue observability.
 * Same pattern as src/core/rateLimit/metrics.js.
 */

const _counters = new Map();

function _key(name, labels) {
  if (!labels || Object.keys(labels).length === 0) return name;
  const suffix = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(',');
  return `${name}{${suffix}}`;
}

function inc(name, labels = {}) {
  const k = _key(name, labels);
  _counters.set(k, (_counters.get(k) ?? 0) + 1);
}

function add(name, value, labels = {}) {
  const k = _key(name, labels);
  _counters.set(k, (_counters.get(k) ?? 0) + value);
}

function get(name, labels = {}) {
  return _counters.get(_key(name, labels)) ?? 0;
}

function snapshot() {
  return Object.fromEntries(_counters);
}

function _reset() {
  _counters.clear();
}

module.exports = { inc, add, get, snapshot, _reset };
