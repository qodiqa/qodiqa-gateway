'use strict';

/**
 * Queue-depth monitor —
 *
 * Every durable backlog the write path can build has a drain worker already:
 *
 *   queue                  drained by
 *   ─────────────────────  ─────────────────────────────────────────────────
 *   prq_pending            persistenceRecovery/worker.js (all operation types)
 *   prq_retrying           same worker (PENDING rows with retry_count > 0)
 *   transparency_pending   same worker, TRANSPARENCY_SAVE handler (D3)
 *   prq_dlq                operator replay: POST /v1/prq/dlq/:id/replay (dlqManager)
 *   prq_journal            persistenceRecovery/journalWorker.js (back into the queue)
 * audit_mirror_writer audit-log.js serialized mirror writer
 * transparency_unrooted transparency/rootScheduler.js
 *
 * What was missing was continuous visibility: the PRQ gauges were refreshed
 * only when someone called GET /v1/prq/stats, and nothing alerted on depth.
 * This monitor samples every queue on an interval, publishes the gauges, and
 * raises one OPERATIONAL/QUEUE_BACKLOG alert when a queue crosses its
 * threshold (edge-triggered: re-armed once the queue drops back below).
 *
 * Thresholds (alert when depth >= threshold; 0 disables that alert):
 *   QODIQA_ALERT_PRQ_PENDING_DEPTH            default 500
 *   QODIQA_ALERT_PRQ_RETRYING_DEPTH           default 100
 *   QODIQA_ALERT_TRANSPARENCY_PENDING_DEPTH   default 100
 *   QODIQA_ALERT_PRQ_DLQ_DEPTH                default 1   (any DLQ item needs an operator)
 *   QODIQA_ALERT_PRQ_JOURNAL_DEPTH            default 1   (journal use means PG refused an enqueue)
 *   QODIQA_ALERT_AUDIT_MIRROR_WRITER_DEPTH    default 1000
 *   QODIQA_ALERT_TRANSPARENCY_UNROOTED_SPAN   default 50000
 * Interval: QODIQA_QUEUE_MONITOR_INTERVAL_MS, default 15000.
 *
 * Never throws; a failed sample of one queue leaves the others intact.
 */

const { emit: _defaultEmit } = require('../../../services/logger');
const _defaultTaskRunner     = require('../../runtime/backgroundTasks/BackgroundTaskRunner');

const SOURCE = 'QUEUE_DEPTH_MONITOR';

function _envInt(key, fallback) {
  const raw = process.env[key];
  if (raw == null || raw === '') return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

const QUEUES = Object.freeze({
  prq_pending:           { env: 'QODIQA_ALERT_PRQ_PENDING_DEPTH',          def: 500,    severity: 'MEDIUM' },
  prq_retrying:          { env: 'QODIQA_ALERT_PRQ_RETRYING_DEPTH',         def: 100,    severity: 'MEDIUM' },
  transparency_pending:  { env: 'QODIQA_ALERT_TRANSPARENCY_PENDING_DEPTH', def: 100,    severity: 'HIGH' },
  prq_dlq:               { env: 'QODIQA_ALERT_PRQ_DLQ_DEPTH',              def: 1,      severity: 'HIGH' },
  prq_journal:           { env: 'QODIQA_ALERT_PRQ_JOURNAL_DEPTH',          def: 1,      severity: 'HIGH' },
  audit_mirror_writer:   { env: 'QODIQA_ALERT_AUDIT_MIRROR_WRITER_DEPTH',  def: 1000,   severity: 'MEDIUM' },
  transparency_unrooted: { env: 'QODIQA_ALERT_TRANSPARENCY_UNROOTED_SPAN', def: 50_000, severity: 'MEDIUM' },
});

function thresholds() {
  const out = {};
  for (const [q, d] of Object.entries(QUEUES)) out[q] = _envInt(d.env, d.def);
  return out;
}

/**
 * @param {object} [opts]  every dependency is injectable for tests
 */
function createQueueMonitor(opts = {}) {
  const {
    intervalMs       = _envInt('QODIQA_QUEUE_MONITOR_INTERVAL_MS', 15_000),
    _queue           = require('./queue'),
    _journal         = require('./journal'),
    _mirrorDepth     = () => require('../audit/audit-log').mirrorWriterDepth(),
    _logStore        = require('../transparency/logStore'),
    _createAlert     = (spec) => require('../../alerting/engine/AlertEngine').createAlert(spec),
    _metrics         = require('../../observability/metrics'),
    _emit            = _defaultEmit,
    _taskRunner      = _defaultTaskRunner,
    _thresholds      = thresholds(),
  } = opts;

  let _timer  = null;
  let _running = false;
  const _firing = new Set();
  let _last = null;

  const _setGauge = (name, labels, v) => { try { _metrics[name].set(labels, v); } catch { /* fail-safe */ } };

  async function sample() {
    const depths = {};

    try {
      const rows = await _queue.getDepthByType();
      let pending = 0; let retrying = 0; let dlq = 0; let tPending = 0;
      const types = new Set(rows.map((r) => r.operationType));
      for (const t of types) {
        for (const st of ['PENDING', 'DLQ']) _setGauge('prqQueueDepth', { operation_type: t, status: st }, 0);
        _setGauge('prqRetryingDepth', { operation_type: t }, 0);
        _setGauge('prqOldestPendingAgeSeconds', { operation_type: t }, 0);
      }
      for (const r of rows) {
        _setGauge('prqQueueDepth', { operation_type: r.operationType, status: r.status }, r.depth);
        if (r.status === 'PENDING') {
          pending += r.depth; retrying += r.retrying;
          if (r.operationType === 'TRANSPARENCY_SAVE') tPending += r.depth;
          _setGauge('prqRetryingDepth', { operation_type: r.operationType }, r.retrying);
          _setGauge('prqOldestPendingAgeSeconds', { operation_type: r.operationType }, Math.round(r.oldestAgeSeconds));
        } else if (r.status === 'DLQ') {
          dlq += r.depth;
        }
      }
      Object.assign(depths, { prq_pending: pending, prq_retrying: retrying, transparency_pending: tPending, prq_dlq: dlq });
      _setGauge('prqDlqDepth', {}, dlq);
    } catch (err) {
      _emit('WARN', 'QUEUE_MONITOR_SAMPLE_FAILED', { source: SOURCE, queue: 'prq', error: err.message });
    }

    try {
      const j = await _journal.getStats();
      depths.prq_journal = j.depth;
      _setGauge('prqJournalDepth', {}, j.depth);
      _setGauge('prqJournalOldestEntryAgeSeconds', {}, Math.round((j.oldestEntryAgeMs || 0) / 1000));
      _setGauge('prqJournalBytes', {}, j.totalBytes || 0);
    } catch (err) {
      _emit('WARN', 'QUEUE_MONITOR_SAMPLE_FAILED', { source: SOURCE, queue: 'prq_journal', error: err.message });
    }

    try {
      depths.audit_mirror_writer = Number(_mirrorDepth()) || 0;
    } catch (err) {
      _emit('WARN', 'QUEUE_MONITOR_SAMPLE_FAILED', { source: SOURCE, queue: 'audit_mirror_writer', error: err.message });
    }

    try {
      const [entry, root] = await Promise.all([_logStore.getLatestEntry(), _logStore.getLatestRoot()]);
      if (entry) {
        const span = Math.max(0, Number(entry.id) - (root ? Number(root.seq_to) : 0));
        depths.transparency_unrooted = span;
        _setGauge('transparencyUnrootedIdSpan', {}, span);
      }
    } catch (err) {
      _emit('WARN', 'QUEUE_MONITOR_SAMPLE_FAILED', { source: SOURCE, queue: 'transparency_unrooted', error: err.message });
    }

    await _evaluate(depths);
    _last = { at: new Date().toISOString(), depths };
    return depths;
  }

  async function _evaluate(depths) {
    for (const [q, depth] of Object.entries(depths)) {
      const threshold = _thresholds[q];
      if (!threshold) continue;
      if (depth >= threshold) {
        if (_firing.has(q)) continue;
        _firing.add(q);
        try { _metrics.queueBacklogAlertsTotal.inc({ queue: q }); } catch { /* fail-safe */ }
        _emit('WARN', 'QUEUE_BACKLOG_THRESHOLD_CROSSED', { source: SOURCE, queue: q, depth, threshold });
        try {
          await _createAlert({
            type:        'OPERATIONAL',
            subtype:     'QUEUE_BACKLOG',
            severity:    QUEUES[q].severity,
            sourceEvent: 'QUEUE_BACKLOG_THRESHOLD_CROSSED',
            title:       `Queue backlog: ${q} depth ${depth} >= ${threshold}`,
            description: `The ${q} queue reached depth ${depth} (alert threshold ${threshold}; ${QUEUES[q].env}).`,
            component:   'persistence',
            context:     { queue: q, depth, threshold },
          });
        } catch (err) {
          _emit('ERROR', 'QUEUE_BACKLOG_ALERT_FAILED', { source: SOURCE, queue: q, error: err.message });
        }
      } else if (_firing.has(q)) {
        _firing.delete(q);
        _emit('INFO', 'QUEUE_BACKLOG_RECOVERED', { source: SOURCE, queue: q, depth, threshold });
      }
    }
  }

  async function _tick() {
    if (!_running) return;
    await _taskRunner.runTask('queue-depth-monitor', () => sample());
    if (_running) {
      _timer = setTimeout(_tick, intervalMs);
      if (_timer.unref) _timer.unref();
    }
  }

  function start() {
    if (_running || !intervalMs) return;
    _running = true;
    _emit('INFO', 'QUEUE_MONITOR_STARTED', { source: SOURCE, intervalMs, thresholds: _thresholds });
    _timer = setTimeout(_tick, 0);
    if (_timer.unref) _timer.unref();
  }

  function stop() {
    _running = false;
    if (_timer) { clearTimeout(_timer); _timer = null; }
  }

  return { start, stop, sample, isRunning: () => _running, getStatus: () => ({ running: _running, firing: [..._firing], last: _last }) };
}

module.exports = { createQueueMonitor, thresholds, QUEUES };
