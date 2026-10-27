'use strict';

/**
 * Retention configuration for dashboard data.
 *
 * All bounds are configurable via environment variables.  Defaults are sized
 * for a production deployment with up to 100M cumulative audit records while
 * keeping dashboard memory usage bounded.
 *
 * Variables:
 *   DASHBOARD_MAX_EXECUTIONS   — max recent ALLOW entries kept in memory
 *   DASHBOARD_MAX_BLOCKED      — max recent BLOCK entries kept in memory
 *   DASHBOARD_MAX_REPLAYS      — max recent REPLAY_DETECTED entries
 *   DASHBOARD_MAX_ANOMALIES    — max recent ANOMALY_DETECTED entries
 *   DASHBOARD_MAX_TIME_BUCKETS — max per-minute activity buckets (1 bucket = 1 minute)
 */

function _parsePositiveInt(val, def) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) && n > 0 ? n : def;
}

const DEFAULT_RETENTION = Object.freeze({
  maxExecutions:  10_000,
  maxBlocked:     10_000,
  maxReplays:      5_000,
  maxAnomalies:    5_000,
  maxTimeBuckets:  1_440,  // 24 hours × 60 minutes
});

function loadRetentionConfig() {
  return Object.freeze({
    maxExecutions:  _parsePositiveInt(process.env.DASHBOARD_MAX_EXECUTIONS,   DEFAULT_RETENTION.maxExecutions),
    maxBlocked:     _parsePositiveInt(process.env.DASHBOARD_MAX_BLOCKED,      DEFAULT_RETENTION.maxBlocked),
    maxReplays:     _parsePositiveInt(process.env.DASHBOARD_MAX_REPLAYS,      DEFAULT_RETENTION.maxReplays),
    maxAnomalies:   _parsePositiveInt(process.env.DASHBOARD_MAX_ANOMALIES,    DEFAULT_RETENTION.maxAnomalies),
    maxTimeBuckets: _parsePositiveInt(process.env.DASHBOARD_MAX_TIME_BUCKETS, DEFAULT_RETENTION.maxTimeBuckets),
  });
}

module.exports = { loadRetentionConfig, DEFAULT_RETENTION };
