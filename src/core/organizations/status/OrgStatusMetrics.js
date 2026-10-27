'use strict';

/**
 * OrgStatusMetrics — Prometheus-compatible metrics for bounded organization-
 * suspension propagation.
 *
 * Uses prom-client if installed; falls back to in-memory accumulators so the
 * rest of the system works identically in environments without prom-client.
 * Mirrors src/core/consent/revocation/RevocationMetrics.js.
 */

function _tryPrometheus() {
  try { return require(/** @type {string} */ ('prom-client')); } catch { return null; }
}

const prom = _tryPrometheus();

function _counter(name, help, labelNames) {
  if (prom) {
    const existing = prom.register.getSingleMetric(name);
    if (existing) return existing;
    return new prom.Counter({ name, help, labelNames });
  }
  const counts = new Map();
  return {
    inc(labels = {}) {
      const key = JSON.stringify(labels);
      counts.set(key, (counts.get(key) || 0) + 1);
    },
    _counts: counts,
  };
}

function _histogram(name, help, buckets) {
  if (prom) {
    const existing = prom.register.getSingleMetric(name);
    if (existing) return existing;
    return new prom.Histogram({ name, help, buckets });
  }
  const observations = [];
  return {
    observe(value) { observations.push(value); },
    _observations: observations,
  };
}

const published = _counter(
  'qodiqa_org_status_published_total',
  'Total organization status-change events published to the Redis pub/sub channel',
  ['result'],
);

const received = _counter(
  'qodiqa_org_status_received_total',
  'Total organization status-change events received from the Redis pub/sub channel',
  ['result'],
);

const statusApplied = _counter(
  'qodiqa_org_status_applied_total',
  'Total local organization status applications (pub/sub push or reconciliation sweep)',
  ['source'],
);

const propagationLatency = _histogram(
  'qodiqa_org_status_propagation_latency_ms',
  'Time from status-change event receipt to local application completion (ms)',
  [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000],
);

const reconcileSweeps = _counter(
  'qodiqa_org_status_reconcile_sweeps_total',
  'Total periodic/on-reconnect reconciliation sweeps against the authoritative Redis store',
  ['result'],
);

const staleDenials = _counter(
  'qodiqa_org_status_stale_denials_total',
  'Total requests denied because local organization status knowledge exceeded the documented bounded-propagation window, or the sync channel was unavailable',
  ['reason'],
);

// requests allowed past the bound under the connected/no-failed-sweep grace.
const staleGraceAllowed = _counter(
  'qodiqa_org_status_stale_grace_allowed_total',
  'Total requests allowed beyond the bounded-propagation window because the subscription stayed connected and no reconcile sweep failed since the last confirmation (late sweep only)',
  [],
);

const subscriberReconnects = _counter(
  'qodiqa_org_status_subscriber_reconnects_total',
  'Total Redis pub/sub client reconnect events by role (publisher / subscriber)',
  ['type'],
);

module.exports = {
  published,
  received,
  statusApplied,
  propagationLatency,
  reconcileSweeps,
  staleDenials,
  staleGraceAllowed,
  subscriberReconnects,
};
