'use strict';

/**
 * AggregationStore — pre-computed dashboard metrics with incremental updates.
 *
 * Eliminates the O(n) full audit-chain scan that previously occurred on every
 * dashboard request.  Instead:
 *
 *   1. initialize(getAuditChain) — one-time full-chain scan at startup.
 *   2. Bus subscriptions (audit.allow / audit.block) — O(1) incremental update
 *      per audit event, fired synchronously after each successful audit append.
 *   3. reinitialize() — full rescan, used only in tests when the stub chain
 *      is mutated between test cases.
 *
 * Entry storage:
 *   Four bounded arrays (executions, blocked, replays, anomalies).  Entries are
 *   stored as "safe" projections: only display-relevant fields, no raw crypto
 *   hashes except when needed.  Each array is capped by the retention config.
 *   When an array is full, the oldest entry (index 0) is evicted on each push.
 *
 * Tenant isolation:
 *   getXxx(tenantId) filters the bounded array by tenantId when supplied.
 *   getMetrics().getByTenant() exposes per-tenant counters.
 *
 * Thread safety:
 *   Node.js is single-threaded.  All operations (including bus event handlers)
 *   execute synchronously.  No locks are required.
 */

// ── Entry projection helpers ──────────────────────────────────────────────────

function _safeEntry(entry) {
  return {
    artifactId:         entry.artifactId,
    timestamp:          entry.timestamp,
    decision:           entry.decision,
    tenantId:           entry.tenantId                     ?? null,
    reason:             entry.executionContext?.reason      ?? null,
    stage:              entry.executionContext?.stage       ?? null,
    provider:           entry.executionContext?.provider    ?? null,
    model:              entry.executionContext?.model       ?? null,
    replayOf:           entry.executionContext?.replayOf    ?? null,
    anomalyType:        entry.executionContext?.anomalyType ?? null,
    requestHash:        (entry.requestHash  !== 'UNAVAILABLE') ? entry.requestHash  : null,
    policyHash:         (entry.policyHash   !== 'UNAVAILABLE') ? entry.policyHash   : null,
    verificationResult: entry.verificationResult            ?? null,
  };
}

// Fallback when the full audit entry is not available (e.g. getArtifactById
// is not mocked in a test environment).
function _safeFromRecord(record, decision) {
  return {
    artifactId:         record.artifactId ?? null,
    timestamp:          record.timestamp  ?? new Date().toISOString(),
    decision,
    tenantId:           null,
    reason:             record.reason     ?? null,
    stage:              record.stage      ?? null,
    provider:           record.provider   ?? null,
    model:              null,
    replayOf:           null,
    anomalyType:        null,
    requestHash:        null,
    policyHash:         null,
    verificationResult: false,
  };
}

// ── AggregationStore ──────────────────────────────────────────────────────────

class AggregationStore {
  constructor(bus, metricsEngine, retention) {
    this._metrics    = metricsEngine;
    this._retention  = retention;
    this._executions = [];
    this._blocked    = [];
    this._replays    = [];
    this._anomalies  = [];
    this._chainFn    = null;   // stored so reinitialize() needs no argument
    this._iterateFn  = null;   // production paged history walk (initializeFromIterator)

    // Incremental-update subscriptions — these survive reinitialize() calls
    bus.subscribe('audit.allow', ({ record, entry }) => this._onAllow(record, entry));
    bus.subscribe('audit.block', ({ record, entry }) => this._onBlock(record, entry));
  }

  // ── Initialization ────────────────────────────────────────────────────────

  /**
   * Scan the full audit chain once and build initial state.
   * Should be called exactly once after construction, before any requests.
   *
   * @param {() => object[]} getAuditChain
   */
  // the production getAuditChain() is async (streamed from the durable
  // store). Test stubs remain plain sync functions returning arrays — when
  // the chain fn returns a non-promise the scan stays fully synchronous, so
  // existing stub-based callers keep their read-immediately-after semantics.
  // With the async production fn this returns a promise (exposed by
  // store/index.js as initializationComplete).
  initialize(getAuditChain) {
    this._chainFn = getAuditChain;
    this._iterateFn = null;
    return this._scanChain();
  }

  /**
   *production initialisation. `forEachChainEntry(visit)` walks the whole history page by page
   * (audit-log.forEachChainEntry: one page in memory, event loop yielded between pages, only entries that existed
   * when the walk started — later ones arrive through the bus subscriptions above, never twice). Same entries, same
   * order and same resulting state as initialize(getAuditChain), without materialising the history: the previous
   * full-array scan exhausted the heap at boot above ~200k audit entries.
   *
   * @param {(visit: (entry: object) => void) => Promise<number>} forEachChainEntry
   * @returns {Promise<number>} entries visited
   */
  initializeFromIterator(forEachChainEntry) {
    this._iterateFn = forEachChainEntry;
    this._chainFn = null;
    return this._iterateFn((entry) => { if (!entry.legacy) this._processEntry(entry); });
  }

  /**
   * Reset all state and re-scan the chain from scratch.
   * Used in tests when the stub chain is mutated.
   * In production this is never called — state is maintained incrementally.
   */
  reinitialize() {
    if (this._iterateFn) { this._reset(); return this.initializeFromIterator(this._iterateFn); }
    if (!this._chainFn) return;
    this._reset();
    return this._scanChain();
  }

  // Shared by initialize()/reinitialize(): sync when the chain fn is sync
  // (test stubs), promise-returning when it is async.
  _scanChain() {
    const result = this._chainFn();
    const apply = (chain) => {
      for (const entry of chain) {
        if (!entry.legacy) this._processEntry(entry);
      }
    };
    if (result && typeof result.then === 'function') return result.then(apply);
    apply(result);
  }

  // ── Public read API ───────────────────────────────────────────────────────

  getMetrics() { return this._metrics; }

  getExecutions(tenantId) {
    return tenantId
      ? this._executions.filter(e => e.tenantId === tenantId)
      : this._executions.slice();
  }

  getBlocked(tenantId) {
    return tenantId
      ? this._blocked.filter(e => e.tenantId === tenantId)
      : this._blocked.slice();
  }

  getReplays(tenantId) {
    return tenantId
      ? this._replays.filter(e => e.tenantId === tenantId)
      : this._replays.slice();
  }

  getAnomalies(tenantId) {
    return tenantId
      ? this._anomalies.filter(e => e.tenantId === tenantId)
      : this._anomalies.slice();
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  _reset() {
    this._metrics.reset();
    this._executions = [];
    this._blocked    = [];
    this._replays    = [];
    this._anomalies  = [];
  }

  _processEntry(entry) {
    this._metrics.record({
      decision:    entry.decision,
      reason:      entry.executionContext?.reason,
      tenantId:    entry.tenantId,
      timestamp:   entry.timestamp,
      anomalyType: entry.executionContext?.anomalyType,
    });
    this._pushToBuffers(_safeEntry(entry));
  }

  _onAllow(record, entry) {
    const safe = entry ? _safeEntry(entry) : _safeFromRecord(record, 'ALLOW');
    this._metrics.record({
      decision:  'ALLOW',
      tenantId:  safe.tenantId,
      timestamp: record.timestamp,
    });
    this._push(this._executions, safe, this._retention.maxExecutions);
  }

  _onBlock(record, entry) {
    const reason = entry?.executionContext?.reason ?? record.reason ?? null;
    const aType  = entry?.executionContext?.anomalyType ?? null;
    const safe   = entry ? _safeEntry(entry) : _safeFromRecord(record, 'BLOCK');
    this._metrics.record({
      decision:    'BLOCK',
      reason,
      tenantId:    safe.tenantId,
      timestamp:   record.timestamp,
      anomalyType: aType,
    });
    this._push(this._blocked, safe, this._retention.maxBlocked);
    if (reason === 'REPLAY_DETECTED')  this._push(this._replays,   safe, this._retention.maxReplays);
    if (reason === 'ANOMALY_DETECTED') this._push(this._anomalies, safe, this._retention.maxAnomalies);
  }

  _pushToBuffers(safe) {
    if (safe.decision === 'ALLOW') {
      this._push(this._executions, safe, this._retention.maxExecutions);
    } else {
      this._push(this._blocked, safe, this._retention.maxBlocked);
      if (safe.reason === 'REPLAY_DETECTED')  this._push(this._replays,   safe, this._retention.maxReplays);
      if (safe.reason === 'ANOMALY_DETECTED') this._push(this._anomalies, safe, this._retention.maxAnomalies);
    }
  }

  // O(1) push, O(n) eviction when full — acceptable for bounded n (~10K)
  _push(arr, item, maxSize) {
    arr.push(item);
    if (arr.length > maxSize) arr.shift();
  }
}

module.exports = { AggregationStore };
