'use strict';

/**
 * DashboardBus singleton.
 *
 * Bridges the logger's in-process eventBus to the dashboard's own LocalEventBus
 * so that dashboard components (SSE manager, AggregationStore) do not depend
 * directly on services/logger.  Any future RedisPubSub implementation need only
 * replace the LocalEventBus here — all subscribers remain unchanged.
 *
 * Channels published by this module:
 *
 *   'log'          — every structured log record (mirrors logger.eventBus 'log')
 *   'audit.allow'  — { record, entry } for AUDIT_EXECUTION_RECORDED events
 *   'audit.block'  — { record, entry } for AUDIT_BLOCK_RECORDED events (new appends only)
 *
 * The bridge is set up once at module-load time.  All event handling is
 * synchronous (EventEmitter.emit is synchronous), so incremental updates to
 * the AggregationStore happen in the same tick as the original log emission.
 */

const { LocalEventBus } = require('./LocalEventBus');

const bus = new LocalEventBus();

// ── Logger → DashboardBus bridge ─────────────────────────────────────────────
// Wrapped in try/catch so a missing or mocked logger never crashes the module.
try {
  const { eventBus: loggerBus } = require('../../services/logger');

  loggerBus.on('log', async (record) => {
    // Always re-publish every log record for SSE streaming.
    bus.publish('log', record);

    // Route successful audit append events to typed channels.
    // The 'note' field is present only on the 'already_in_chain' error path —
    // those must not increment AggregationStore counters a second time.
    if (record.note) return;

    if (record.eventType === 'AUDIT_EXECUTION_RECORDED') {
      bus.publish('audit.allow', { record, entry: await _lookupEntry(record.artifactId) });
    } else if (record.eventType === 'AUDIT_BLOCK_RECORDED') {
      bus.publish('audit.block', { record, entry: await _lookupEntry(record.artifactId) });
    }
  });
} catch { /* logger module unavailable — bridge disabled, dashboard still functions */ }

// ── Helpers ───────────────────────────────────────────────────────────────────

// Lazy require so Jest mocks applied before test execution are honoured.
// Returns null (not throws) if the entry is not found or audit-log is mocked
// without getArtifactById.
async function _lookupEntry(artifactId) {
  if (!artifactId) return null;
  try {
    const auditLog = require('../../core/audit/audit-log');
    const fn = auditLog.getArtifactById;
    // getArtifactById() is async — the just-appended entry is always in
    // the in-memory tail window, so this resolves on the fast path.
    return typeof fn === 'function' ? await fn(artifactId) : null;
  } catch { return null; }
}

module.exports = bus;
