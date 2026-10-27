'use strict';

/**
 * RevocationMetrics — Prometheus-compatible metrics for instant consent revocation.
 *
 * Uses prom-client if installed; falls back to in-memory accumulators so the
 * rest of the system works identically in environments without prom-client.
 *
 * Exported counters / histograms:
 *   published           — events sent to Redis pub/sub
 *   received            — events received from Redis pub/sub
 *   cacheInvalidations  — local cache invalidations triggered by received events
 *   propagationLatency  — histogram of receive→invalidation latency in ms
 *   subscriberReconnects— Redis pub/sub client reconnect events
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
  'qodiqa_consent_revocation_published_total',
  'Total revocation events published to the Redis pub/sub channel',
  ['result'],
);

const received = _counter(
  'qodiqa_consent_revocation_received_total',
  'Total revocation events received from the Redis pub/sub channel',
  ['result'],
);

const cacheInvalidations = _counter(
  'qodiqa_consent_revocation_cache_invalidations_total',
  'Total consent cache invalidations triggered by received revocation events',
  ['scope'],
);

const propagationLatency = _histogram(
  'qodiqa_consent_revocation_propagation_latency_ms',
  'Time from revocation event receipt to local cache invalidation completion (ms)',
  [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000],
);

const subscriberReconnects = _counter(
  'qodiqa_consent_subscriber_reconnects_total',
  'Total Redis pub/sub client reconnect events by role (publisher / subscriber)',
  ['type'],
);

module.exports = {
  published,
  received,
  cacheInvalidations,
  propagationLatency,
  subscriberReconnects,
};
