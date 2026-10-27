'use strict';

/**
 * AggregationStore singleton.
 *
 * Initialization order:
 *   1. DashboardBus is required → logger bridge is set up
 *   2. MetricsEngine singleton is required
 *   3. Retention config is required
 *   4. AggregationStore is constructed → bus subscriptions registered
 * 5. store.initializeFromIterator(forEachChainEntry) → one-time paged history walk
 *
 * After step 5, all new audit events flow through the bus bridge into
 * store._onAllow / store._onBlock — no further chain scans occur.
 */

const { AggregationStore } = require('./AggregationStore');
const bus                  = require('../bus');
const metricsEngine        = require('../metrics');
const retention            = require('../retention');
const auditLog             = require('../../core/audit/audit-log');

const store = new AggregationStore(bus, metricsEngine, retention);
// initialisation is async; expose the boot-scan promise so callers
// (tests, readiness checks) can await scan completion. Incremental bus
// subscriptions are installed in the constructor, so no live event is lost
// while the historical scan streams in.
// the history is walked page by page (bounded memory, event loop yielded between pages) instead
// of materialising every entry with getAuditChain() — that exhausted the heap at boot above ~200k audit entries.
// getAuditChain is used only when a test double of the audit-log module provides nothing else.
const _started = Date.now();
store.initializationComplete = typeof auditLog.forEachChainEntry === 'function'
  ? store.initializeFromIterator(auditLog.forEachChainEntry).then((visited) => {
    try { require('../../../services/logger').emit('INFO', 'DASHBOARD_HISTORY_SCAN_COMPLETED', { entries: visited, durationMs: Date.now() - _started }); } catch { /* logging is best-effort */ }
    return visited;
  }, (err) => {
    try { require('../../../services/logger').emit('ERROR', 'DASHBOARD_HISTORY_SCAN_FAILED', { error: err.message, durationMs: Date.now() - _started }); } catch { /* */ }
    throw err;
  })
  : store.initialize(auditLog.getAuditChain);

module.exports = store;
