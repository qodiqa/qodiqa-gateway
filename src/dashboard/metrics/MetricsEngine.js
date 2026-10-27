'use strict';

/**
 * Dashboard MetricsEngine.
 *
 * Maintains named counters, per-tenant breakdown, and sliding time-bucket
 * aggregation for the operational dashboard.  Separate from the Prometheus
 * metrics in src/observability/metrics.js — these are for dashboard display,
 * not for scraping.
 *
 * Exported counters (via getCounters()):
 *   executions_total   — total ALLOW decisions (synonym: allowed_total)
 *   allowed_total      — same as executions_total
 *   blocked_total      — total BLOCK decisions
 *   replay_total       — BLOCK where reason === REPLAY_DETECTED
 *   anomaly_total      — BLOCK where reason === ANOMALY_DETECTED
 *
 * Time buckets:
 *   One entry per minute-level ISO key, bounded by retention.maxTimeBuckets.
 *   Oldest buckets are evicted when the bound is exceeded.
 *   getTimeBuckets(windowMinutes) returns buckets within the specified window,
 *   sorted oldest-first.
 *
 * Multi-tenant:
 *   getByTenant() returns per-tenantId counters: { allowed, blocked, replays, anomalies }.
 */

function _minuteKey(isoTimestamp) {
  try {
    if (!isoTimestamp) throw new RangeError('empty');
    const d = new Date(isoTimestamp);
    if (isNaN(d.getTime())) throw new RangeError('invalid date');
    d.setSeconds(0, 0);
    return d.toISOString();
  } catch {
    const d = new Date();
    d.setSeconds(0, 0);
    return d.toISOString();
  }
}

class MetricsEngine {
  constructor(retention) {
    this._retention = retention;
    this.reset();
  }

  // ── Mutation ──────────────────────────────────────────────────────────────

  reset() {
    this._total     = 0;
    this._allowed   = 0;
    this._blocked   = 0;
    this._replays   = 0;
    this._anomalies = 0;
    this._byReason      = Object.create(null);
    this._byAnomalyType = Object.create(null);
    this._byTenant      = Object.create(null);
    // Map<minuteKey, { minute, allowed, blocked }> — insertion-ordered for pruning
    this._timeBuckets   = new Map();
  }

  /**
   * Record a single audit event.
   *
   * @param {{ decision: string, reason?: string, tenantId?: string,
   *           timestamp?: string, anomalyType?: string }} fields
   */
  record({ decision, reason, tenantId, timestamp, anomalyType } = {}) {
    this._total++;
    const minuteKey = _minuteKey(timestamp);

    if (!this._timeBuckets.has(minuteKey)) {
      this._timeBuckets.set(minuteKey, { minute: minuteKey, allowed: 0, blocked: 0 });
    }

    if (decision === 'ALLOW') {
      this._allowed++;
      this._timeBuckets.get(minuteKey).allowed++;
      if (tenantId) this._tenant(tenantId).allowed++;

    } else if (decision === 'BLOCK') {
      this._blocked++;
      this._timeBuckets.get(minuteKey).blocked++;
      if (reason) this._byReason[reason] = (this._byReason[reason] || 0) + 1;

      if (reason === 'REPLAY_DETECTED') {
        this._replays++;
        if (tenantId) this._tenant(tenantId).replays++;
      }
      if (reason === 'ANOMALY_DETECTED') {
        this._anomalies++;
        const at = anomalyType || 'UNKNOWN';
        this._byAnomalyType[at] = (this._byAnomalyType[at] || 0) + 1;
        if (tenantId) this._tenant(tenantId).anomalies++;
      }
      if (tenantId) this._tenant(tenantId).blocked++;
    }

    this._pruneBuckets();
  }

  // ── Read ──────────────────────────────────────────────────────────────────

  /** Overview shape consumed by the dashboard /overview endpoint. */
  getOverview() {
    return {
      totalRequests:     this._total,
      allowedRequests:   this._allowed,
      blockedRequests:   this._blocked,
      replayAttempts:    this._replays,
      anomaliesDetected: this._anomalies,
      byReason:          { ...this._byReason },
    };
  }

  /** Named counters suitable for structured metrics export. */
  getCounters() {
    return {
      executions_total: this._allowed,
      allowed_total:    this._allowed,
      blocked_total:    this._blocked,
      replay_total:     this._replays,
      anomaly_total:    this._anomalies,
    };
  }

  getByReason()      { return { ...this._byReason }; }
  getByAnomalyType() { return { ...this._byAnomalyType }; }

  /** Deep copy of per-tenant counters for safe external consumption. */
  getByTenant() {
    const out = Object.create(null);
    for (const [k, v] of Object.entries(this._byTenant)) out[k] = { ...v };
    return out;
  }

  /**
   * Return time-bucket entries whose minute key falls within the last
   * windowMinutes minutes, sorted oldest-first.
   *
   * @param {number} windowMinutes
   * @returns {{ minute: string, allowed: number, blocked: number }[]}
   */
  getTimeBuckets(windowMinutes) {
    const cutoff = _minuteKey(new Date(Date.now() - windowMinutes * 60_000).toISOString());
    const result = [];
    for (const [key, val] of this._timeBuckets) {
      if (key >= cutoff) result.push({ ...val });
    }
    return result.sort((a, b) => a.minute.localeCompare(b.minute));
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  _tenant(tenantId) {
    if (!this._byTenant[tenantId]) {
      this._byTenant[tenantId] = { allowed: 0, blocked: 0, replays: 0, anomalies: 0 };
    }
    return this._byTenant[tenantId];
  }

  _pruneBuckets() {
    if (this._timeBuckets.size <= this._retention.maxTimeBuckets) return;
    // Remove oldest (smallest) keys.  Sort to handle any out-of-order arrivals.
    const excess = this._timeBuckets.size - this._retention.maxTimeBuckets;
    const keys   = [...this._timeBuckets.keys()].sort();
    for (let i = 0; i < excess; i++) this._timeBuckets.delete(keys[i]);
  }
}

module.exports = { MetricsEngine, _minuteKey };
