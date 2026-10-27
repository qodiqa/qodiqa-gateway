'use strict';

/**
 * QODIQA Anomaly Detector
 *
 * Real-time statistical anomaly detection using sliding-window counters.
 * Monitors the following dimensions:
 *
 *   Global metrics:
 *     - Total request volume (spikes)
 *     - Block rate (fraction of requests blocked)
 *     - Error rate (provider/audit failures)
 *
 *   Per-tenant metrics:
 *     - Request volume per tenant
 *     - Block rate per tenant
 *
 *   Per-key metrics:
 *     - Requests per public key
 *
 *   Governance metrics:
 *     - RBAC denial rate
 *     - Ops auth failure rate
 *     - Audit activity rate
 *
 * Anomaly thresholds are configurable via environment variables.
 * Baselines self-adapt to historical traffic using the WindowedCounter.
 *
 * Design: All counters are in-memory (fast, no I/O on hot path).
 * Periodic snapshots are written to PostgreSQL by the BaselineEngine.
 */

const { WindowedCounter } = require('../anomaly/WindowedCounter');
const { ALERT_TYPE, ANOMALY_SUBTYPE, SEVERITY } = require('../constants');

// ── Configuration ─────────────────────────────────────────────────────────────

const SIGMA_THRESHOLD = parseFloat(process.env.ANOMALY_SIGMA_THRESHOLD ?? '3.0');
const BLOCK_RATE_THRESHOLD = parseFloat(process.env.ANOMALY_BLOCK_RATE_THRESHOLD ?? '0.50');  // 50%
const ERROR_RATE_THRESHOLD = parseFloat(process.env.ANOMALY_ERROR_RATE_THRESHOLD ?? '0.20');  // 20%
const GOVERNANCE_RATE_THRESHOLD = parseFloat(process.env.ANOMALY_GOVERNANCE_RATE_THRESHOLD ?? '0.10');
const PER_TENANT_SIGMA = parseFloat(process.env.ANOMALY_PER_TENANT_SIGMA ?? '4.0');
const WINDOW_MS  = parseInt(process.env.ANOMALY_WINDOW_MS  ?? String(60 * 60_000), 10);  // 1 hour
const BUCKET_MS  = parseInt(process.env.ANOMALY_BUCKET_MS  ?? String(60_000),       10);  // 1 minute
const MAX_TENANT_COUNTERS = parseInt(process.env.ANOMALY_MAX_TENANTS ?? '1000', 10);
const MAX_KEY_COUNTERS    = parseInt(process.env.ANOMALY_MAX_KEYS    ?? '5000', 10);

// Minimum samples before anomaly scoring is enabled
const MIN_SAMPLES = parseInt(process.env.ANOMALY_MIN_SAMPLES ?? '10', 10);

// ── Counter Registry ──────────────────────────────────────────────────────────

// Global counters
const _global = {
  requests: new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
  blocks:   new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
  allows:   new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
  errors:   new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
};

const _governance = {
  rbacDenials:   new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
  opsFailures:   new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
  auditActivity: new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
  keyEvents:     new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
};

// Per-tenant counters (LRU-capped)
const _tenantCounters = new Map();  // tenantId → { requests, blocks }
// Per-key counters (LRU-capped)
const _keyCounters    = new Map();  // keyId → WindowedCounter

// ── Counter helpers ───────────────────────────────────────────────────────────

function _tenantCounter(tenantId) {
  if (!_tenantCounters.has(tenantId)) {
    if (_tenantCounters.size >= MAX_TENANT_COUNTERS) {
      // Evict oldest entry
      const oldest = _tenantCounters.keys().next().value;
      _tenantCounters.delete(oldest);
    }
    _tenantCounters.set(tenantId, {
      requests: new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
      blocks:   new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }),
    });
  }
  return _tenantCounters.get(tenantId);
}

function _keyCounter(keyId) {
  if (!_keyCounters.has(keyId)) {
    if (_keyCounters.size >= MAX_KEY_COUNTERS) {
      const oldest = _keyCounters.keys().next().value;
      _keyCounters.delete(oldest);
    }
    _keyCounters.set(keyId, new WindowedCounter({ bucketMs: BUCKET_MS, windowMs: WINDOW_MS }));
  }
  return _keyCounters.get(keyId);
}

// ── Event ingestion (called by DetectionEngine on every event) ────────────────

function ingest(event) {
  const name = event.eventType ?? '';

  // Track requests and decisions
  if (name === 'GATEWAY_ALLOW') {
    _global.requests.increment();
    _global.allows.increment();
    if (event.tenantId) _tenantCounter(event.tenantId).requests.increment();
    if (event.publicKeyId) _keyCounter(event.publicKeyId).increment();
  }

  if (name === 'GATEWAY_BLOCK') {
    _global.requests.increment();
    _global.blocks.increment();
    if (event.tenantId) {
      const tc = _tenantCounter(event.tenantId);
      tc.requests.increment();
      tc.blocks.increment();
    }
    if (event.publicKeyId) _keyCounter(event.publicKeyId).increment();
  }

  // Track errors
  if (event.severity === 'ERROR' || event.severity === 'FATAL') {
    _global.errors.increment();
  }

  // Track governance events
  if (name === 'RBAC_DENY') _governance.rbacDenials.increment();
  if (name === 'OPS_AUTH_INVALID_TOKEN') _governance.opsFailures.increment();
  if (name.startsWith('AUDIT_')) _governance.auditActivity.increment();
  if (name.startsWith('KEY_') || name.includes('KEY')) _governance.keyEvents.increment();
}

// ── Detection logic ───────────────────────────────────────────────────────────

/**
 * Analyze a platform event and detect anomalous patterns.
 * Called after ingest() has updated counters.
 *
 * @param {object} event
 * @returns {{ triggered: boolean, alert?: object }}
 */
function analyze(event) {
  const name = event.eventType ?? '';

  // Only run detection on decision events (not every single log line)
  const isDecisionEvent = name === 'GATEWAY_ALLOW' || name === 'GATEWAY_BLOCK';
  const isGovEvent = ['RBAC_DENY','OPS_AUTH_INVALID_TOKEN'].includes(name);
  const isKeyEvent = name.startsWith('KEY_') || name.includes('KEY');

  if (!isDecisionEvent && !isGovEvent && !isKeyEvent) {
    return { triggered: false };
  }

  // Run all anomaly checks — return first triggered alert
  const checks = [
    _checkGlobalVolume,
    _checkBlockRate,
    _checkErrorRate,
    _checkTenantAnomaly,
    _checkKeyUsageAnomaly,
    _checkGovernanceAnomaly,
  ];

  for (const check of checks) {
    const result = check(event);
    if (result.triggered) return result;
  }

  return { triggered: false };
}

// ── Individual anomaly checks ─────────────────────────────────────────────────

function _checkGlobalVolume(event) {
  const stats = _global.requests.stats();
  if (stats.count < MIN_SAMPLES) return { triggered: false };

  const { anomalous, zscore, current, mean } = _global.requests.isAnomalous(SIGMA_THRESHOLD);
  if (!anomalous) return { triggered: false };

  return {
    triggered: true,
    alert: _buildAnomaly({
      subtype:     ANOMALY_SUBTYPE.VOLUME_SPIKE,
      severity:    _zscoreToSeverity(zscore),
      confidence:  _zscoreToConfidence(zscore),
      title:       `Global request volume spike detected (${Math.round(zscore)}σ above baseline)`,
      description: `Global request volume is significantly above the rolling baseline. ` +
                   `Current bucket: ${current} requests, baseline mean: ${mean.toFixed(1)}, ` +
                   `z-score: ${zscore.toFixed(2)}σ. This may indicate a DoS attack, ` +
                   `mass replay campaign, or legitimate traffic spike requiring capacity review.`,
      tags:        ['anomaly', 'volume', 'global'],
      evidence: {
        current, mean, stddev: stats.stddev, zscore: zscore.toFixed(3),
        windowTotal: stats.windowTotal, sigmaThreshold: SIGMA_THRESHOLD,
      },
      event,
    }),
  };
}

function _checkBlockRate(event) {
  const totalWindow  = _global.requests.windowTotal();
  const blockedWindow = _global.blocks.windowTotal();

  if (totalWindow < MIN_SAMPLES) return { triggered: false };

  const blockRate = totalWindow > 0 ? blockedWindow / totalWindow : 0;
  if (blockRate < BLOCK_RATE_THRESHOLD) return { triggered: false };

  return {
    triggered: true,
    alert: _buildAnomaly({
      subtype:     ANOMALY_SUBTYPE.BLOCK_RATE_SPIKE,
      severity:    blockRate > 0.80 ? SEVERITY.CRITICAL : SEVERITY.HIGH,
      confidence:  90,
      title:       `Abnormal block rate: ${(blockRate * 100).toFixed(1)}% of requests blocked`,
      description: `${(blockRate * 100).toFixed(1)}% of requests in the current window are being blocked ` +
                   `(${blockedWindow} of ${totalWindow}). ` +
                   `Threshold is ${(BLOCK_RATE_THRESHOLD * 100)}%. ` +
                   `This may indicate a mass attack, misconfigured client, or policy misconfiguration.`,
      tags:        ['anomaly', 'block-rate'],
      evidence:    { blockRate, blockedWindow, totalWindow, threshold: BLOCK_RATE_THRESHOLD },
      event,
    }),
  };
}

function _checkErrorRate(event) {
  const totalWindow = _global.requests.windowTotal();
  const errorWindow = _global.errors.windowTotal();

  if (totalWindow < MIN_SAMPLES) return { triggered: false };

  const errorRate = totalWindow > 0 ? errorWindow / totalWindow : 0;
  if (errorRate < ERROR_RATE_THRESHOLD) return { triggered: false };

  return {
    triggered: true,
    alert: _buildAnomaly({
      subtype:     ANOMALY_SUBTYPE.ERROR_RATE_SPIKE,
      severity:    SEVERITY.HIGH,
      confidence:  85,
      title:       `Elevated error rate: ${(errorRate * 100).toFixed(1)}% of requests`,
      description: `${(errorRate * 100).toFixed(1)}% of requests resulted in errors ` +
                   `(${errorWindow} errors vs ${totalWindow} requests). ` +
                   `This may indicate infrastructure degradation, provider failures, or active attacks.`,
      tags:        ['anomaly', 'error-rate'],
      evidence:    { errorRate, errorWindow, totalWindow, threshold: ERROR_RATE_THRESHOLD },
      event,
    }),
  };
}

function _checkTenantAnomaly(event) {
  const tenantId = event.tenantId;
  if (!tenantId) return { triggered: false };

  const tc = _tenantCounter(tenantId);
  const stats = tc.requests.stats();
  if (stats.count < MIN_SAMPLES) return { triggered: false };

  const { anomalous, zscore, current, mean } = tc.requests.isAnomalous(PER_TENANT_SIGMA);
  if (!anomalous) return { triggered: false };

  return {
    triggered: true,
    alert: _buildAnomaly({
      subtype:     ANOMALY_SUBTYPE.TENANT_ANOMALY,
      severity:    _zscoreToSeverity(zscore),
      confidence:  _zscoreToConfidence(zscore),
      title:       `Tenant ${tenantId} showing anomalous request volume (${zscore.toFixed(1)}σ)`,
      description: `Tenant ${tenantId} request volume is ${zscore.toFixed(1)} standard deviations ` +
                   `above its historical baseline. Current bucket: ${current}, mean: ${mean.toFixed(1)}. ` +
                   `This may indicate credential sharing, replay campaign, or abnormal automation.`,
      tags:        ['anomaly', 'tenant'],
      evidence:    { tenantId, current, mean, stddev: stats.stddev, zscore: zscore.toFixed(3) },
      event,
    }),
  };
}

function _checkKeyUsageAnomaly(event) {
  const keyId = event.publicKeyId;
  if (!keyId) return { triggered: false };

  const kc = _keyCounter(keyId);
  const stats = kc.stats();
  if (stats.count < MIN_SAMPLES) return { triggered: false };

  const { anomalous, zscore, current, mean } = kc.isAnomalous(SIGMA_THRESHOLD);
  if (!anomalous) return { triggered: false };

  return {
    triggered: true,
    alert: _buildAnomaly({
      subtype:     ANOMALY_SUBTYPE.KEY_USAGE_ANOMALY,
      severity:    _zscoreToSeverity(zscore),
      confidence:  _zscoreToConfidence(zscore),
      title:       `Anomalous usage of key ${keyId} (${zscore.toFixed(1)}σ above baseline)`,
      description: `Key ${keyId} is being used at ${zscore.toFixed(1)}σ above its historical baseline. ` +
                   `Current: ${current} requests in bucket, mean: ${mean.toFixed(1)}. ` +
                   `This may indicate a compromised key being used in a replay or brute-force campaign.`,
      tags:        ['anomaly', 'key-usage'],
      evidence:    { keyId, current, mean, stddev: stats.stddev, zscore: zscore.toFixed(3) },
      event,
    }),
  };
}

function _checkGovernanceAnomaly(event) {
  const name = event.eventType ?? '';

  if (name === 'RBAC_DENY') {
    const stats = _governance.rbacDenials.stats();
    if (stats.count < MIN_SAMPLES) return { triggered: false };
    const { anomalous, zscore, current } = _governance.rbacDenials.isAnomalous(SIGMA_THRESHOLD);
    if (!anomalous) return { triggered: false };

    return {
      triggered: true,
      alert: _buildAnomaly({
        subtype:     ANOMALY_SUBTYPE.GOVERNANCE_ANOMALY,
        severity:    SEVERITY.HIGH,
        confidence:  88,
        title:       `Anomalous RBAC denial rate (${zscore.toFixed(1)}σ above baseline)`,
        description: `The rate of RBAC permission denials is significantly elevated: ` +
                     `${current} denials in current bucket, z-score ${zscore.toFixed(2)}σ. ` +
                     `This may indicate unauthorized access attempts or misconfigured credentials.`,
        tags:        ['anomaly', 'governance', 'rbac'],
        evidence:    { current, zscore: zscore.toFixed(3), actor: event.actor },
        event,
      }),
    };
  }

  return { triggered: false };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _buildAnomaly({ subtype, severity, confidence, title, description, tags, evidence, event }) {
  return {
    type:        ALERT_TYPE.ANOMALY,
    subtype,
    severity,
    confidence,
    title,
    description,
    tags,
    evidence,
    context:     {},
    sourceEvent: event.eventType,
    requestId:   event.requestId,
    artifactId:  event.artifactId,
    tenantId:    event.tenantId,
    publicKeyId: event.publicKeyId,
    clientIp:    event.clientIp,
    component:   event.component ?? 'ANOMALY_DETECTOR',
  };
}

function _zscoreToSeverity(zscore) {
  if (zscore >= 6) return SEVERITY.CRITICAL;
  if (zscore >= 4) return SEVERITY.HIGH;
  if (zscore >= 3) return SEVERITY.MEDIUM;
  return SEVERITY.LOW;
}

function _zscoreToConfidence(zscore) {
  if (zscore >= 5) return 95;
  if (zscore >= 4) return 88;
  if (zscore >= 3) return 75;
  return 60;
}

/**
 * Return current counter snapshot for dashboard/metrics use.
 */
function getCounterSnapshot() {
  return {
    global: {
      requests:  _global.requests.windowTotal(),
      blocks:    _global.blocks.windowTotal(),
      allows:    _global.allows.windowTotal(),
      errors:    _global.errors.windowTotal(),
      blockRate: _computeRate(_global.blocks, _global.requests),
      errorRate: _computeRate(_global.errors, _global.requests),
    },
    governance: {
      rbacDenials:   _governance.rbacDenials.windowTotal(),
      opsFailures:   _governance.opsFailures.windowTotal(),
      auditActivity: _governance.auditActivity.windowTotal(),
      keyEvents:     _governance.keyEvents.windowTotal(),
    },
    tenantCount: _tenantCounters.size,
    keyCount:    _keyCounters.size,
  };
}

function _computeRate(numerator, denominator) {
  const d = denominator.windowTotal();
  return d > 0 ? numerator.windowTotal() / d : 0;
}

module.exports = { ingest, analyze, getCounterSnapshot };
