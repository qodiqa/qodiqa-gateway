'use strict';

/**
 * Persistence Recovery Journal Worker — Component #13 (FAILOVER-1 remediation)
 *
 * Background poller that drains the local filesystem journal (journal.js)
 * back into the PostgreSQL-backed persistence_recovery_queue once PostgreSQL
 * is reachable again.
 *
 * This worker is only ever needed for the narrow window the journal exists
 * to cover: a sustained PostgreSQL outage during which recoveryManager's
 * normal queue.enqueue() itself failed and fell back to journal.appendEntry().
 * During that window the journal is the only durable record of the affected
 * operation; this worker's job is simply to get each entry back into the
 * PG-backed queue (the platform's single source of truth for pending retry
 * work) as soon as PostgreSQL is reachable, then delete the local copy.
 *
 * IDEMPOTENCY / CRASH SAFETY:
 *   queue.enqueue() is `ON CONFLICT (operation_id) DO UPDATE` — replaying the
 *   same journal entry twice (e.g. because the process crashed after a
 *   successful re-enqueue but before journal.removeEntry() ran) is a no-op
 *   update, never a duplicate row. This worker never talks to the final
 *   destination table (attestations, certifications, ...) directly — it only
 *   ever re-enqueues into persistence_recovery_queue, so all of the existing
 *   worker.js retry/backoff/DLQ machinery still applies to the replayed
 *   operation exactly as it would to one that was never journaled at all.
 */

const journal    = require('./journal');
const queue      = require('./queue');
const metrics    = require('./metrics');
const obsMetrics = require('../../observability/metrics');
const pgPool     = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const _defaultTaskRunner = require('../../runtime/backgroundTasks/BackgroundTaskRunner');

const SOURCE        = 'PERSISTENCE_RECOVERY_JOURNAL_WORKER';
const POLL_INTERVAL = parseInt(process.env.PRQ_JOURNAL_POLL_INTERVAL_MS || '5000', 10);

let _timer   = null;
let _running = false;

// ── Replay one entry ─────────────────────────────────────────────────────────

async function _replayOne(entry) {
  const { journalId, operation } = entry;
  const startMs = Date.now();

  try {
    await queue.enqueue(operation);
    await journal.removeEntry(journalId);

    const latencyMs = Date.now() - startMs;
    metrics.inc('journal_replayed_total', { operationType: operation.operationType });
    metrics.add('journal_replay_latency_ms', latencyMs, { operationType: operation.operationType });
    obsMetrics.prqJournalReplayedTotal.inc({});
    obsMetrics.prqJournalReplayDurationMs.observe({}, latencyMs);

    emit('INFO', 'JOURNAL_ENTRY_REPLAYED', {
      source:        SOURCE,
      journalId,
      operationId:   operation.operationId,
      operationType: operation.operationType,
      latencyMs,
    });
    return true;
  } catch (err) {
    metrics.inc('journal_replay_failed_total', { operationType: operation.operationType });
    obsMetrics.prqJournalReplayFailedTotal.inc({ operationType: operation.operationType });
    emit('WARN', 'JOURNAL_ENTRY_REPLAY_FAILED', {
      source:        SOURCE,
      journalId,
      operationId:   operation.operationId,
      operationType: operation.operationType,
      error:         err.message,
    });
    return false;
  }
}

// ── Poll loop ─────────────────────────────────────────────────────────────────

// ER 2026-10-06: a background poller must never be what keeps a process alive (every other monitor here unrefs its
// timer). A running server stays alive through its HTTP listener; a leaked/unstopped worker no longer pins the process
// (the CI coverage job hung for hours on this). stop() still clears the timer explicitly.
function _unref(t) { if (t && typeof t.unref === 'function') t.unref(); return t; }

async function _poll({ _taskRunner = _defaultTaskRunner } = {}) {
  if (!_running) return;

  const result = await _taskRunner.runTask('persistence-recovery-journal-worker', async () => {
    // Refresh depth/age/size gauges every tick regardless of PostgreSQL
    // readiness — these are most valuable to an operator during exactly the
    // outage window when replay itself can't proceed yet.
    const stats = await journal.getStats();
    obsMetrics.prqJournalDepth.set({}, stats.depth);
    obsMetrics.prqJournalOldestEntryAgeSeconds.set({}, Math.floor(stats.oldestEntryAgeMs / 1000));
    obsMetrics.prqJournalBytes.set({}, stats.totalBytes);

    // No point attempting replay if PostgreSQL — the replay target — isn't
    // even enabled/ready. The journal itself is untouched either way.
    if (!pgPool.isEnabled() || !queue._isReady()) return;

    const entries = await journal.listEntries();
    for (const entry of entries) {
      // Stop attempting further entries the moment one fails — if PostgreSQL
      // just dropped again mid-scan, there is no point burning through the
      // rest of a possibly-large journal on doomed attempts before the next
      // scheduled tick.
      const ok = await _replayOne(entry);
      if (!ok) break;
    }
  });

  if (!result.ok) {
    emit('ERROR', 'JOURNAL_PROCESSING_FAILED', { source: SOURCE, error: result.error.message });
  }

  if (_running) {
    _timer = _unref(setTimeout(_poll, POLL_INTERVAL));
  }
}

/**
 * Start the background poll loop.
 */
function start() {
  if (_running) return;
  _running = true;
  emit('INFO', 'JOURNAL_WORKER_STARTED', { source: SOURCE, pollIntervalMs: POLL_INTERVAL });
  _timer = _unref(setTimeout(_poll, POLL_INTERVAL));
}

/**
 * Stop the background poll loop.
 */
function stop() {
  if (!_running) return;
  _running = false;
  if (_timer) {
    clearTimeout(_timer);
    _timer = null;
  }
  emit('INFO', 'JOURNAL_WORKER_STOPPED', { source: SOURCE });
}

function isRunning() {
  return _running;
}

module.exports = {
  start,
  stop,
  isRunning,
  _replayOne,
  _poll,
};
