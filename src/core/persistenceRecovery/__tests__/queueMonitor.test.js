'use strict';

/**
 * queue-depth monitor (queueMonitor.js)
 *
 * QM-01  every queue's depth is published to its gauge
 * QM-02  crossing a threshold raises exactly one OPERATIONAL/QUEUE_BACKLOG alert
 * QM-03  edge-triggered: no repeat while above, re-armed after recovering
 * QM-04  a failing source leaves the other queues sampled
 * QM-05  threshold 0 disables that alert; env overrides the defaults
 * QM-06  start()/stop() drive the sample loop through the task runner
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { createQueueMonitor, thresholds } = require('../queueMonitor');

function gaugeMetrics() {
  const store = {};
  const g = (name) => ({ set: jest.fn((labels, v) => { store[`${name}${JSON.stringify(labels)}`] = v; }) });
  return {
    store,
    m: {
      prqQueueDepth: g('prqQueueDepth'), prqRetryingDepth: g('prqRetryingDepth'),
      prqOldestPendingAgeSeconds: g('prqOldestPendingAgeSeconds'), prqDlqDepth: g('prqDlqDepth'),
      prqJournalDepth: g('prqJournalDepth'), prqJournalOldestEntryAgeSeconds: g('prqJournalOldestEntryAgeSeconds'),
      prqJournalBytes: g('prqJournalBytes'), transparencyUnrootedIdSpan: g('transparencyUnrootedIdSpan'),
      queueBacklogAlertsTotal: { inc: jest.fn() },
    },
  };
}

function deps(state, overrides = {}) {
  const { store, m } = gaugeMetrics();
  const alerts = [];
  const mon = createQueueMonitor({
    intervalMs: 0,
    _queue: { getDepthByType: jest.fn(async () => state.rows) },
    _journal: { getStats: jest.fn(async () => state.journal) },
    _mirrorDepth: () => state.mirror,
    _logStore: { getLatestEntry: jest.fn(async () => state.entry), getLatestRoot: jest.fn(async () => state.root) },
    _createAlert: jest.fn(async (spec) => { alerts.push(spec); return spec; }),
    _metrics: m,
    _emit: jest.fn(),
    _thresholds: { prq_pending: 10, prq_retrying: 5, transparency_pending: 3, prq_dlq: 1, prq_journal: 1, audit_mirror_writer: 100, transparency_unrooted: 1000 },
    ...overrides,
  });
  return { mon, store, m, alerts };
}

const quiet = () => ({
  rows: [{ operationType: 'TRANSPARENCY_SAVE', status: 'PENDING', depth: 2, retrying: 1, oldestAgeSeconds: 12.4 },
         { operationType: 'EVIDENCE_CHAIN_SAVE', status: 'DLQ', depth: 0, retrying: 0, oldestAgeSeconds: 0 }],
  journal: { depth: 0, oldestEntryAgeMs: 0, totalBytes: 0 },
  mirror: 3, entry: { id: 500 }, root: { seq_to: 480 },
});

test('QM-01 depths are published', async () => {
  const { mon, store } = deps(quiet());
  const d = await mon.sample();
  expect(d).toEqual({ prq_pending: 2, prq_retrying: 1, transparency_pending: 2, prq_dlq: 0, prq_journal: 0, audit_mirror_writer: 3, transparency_unrooted: 20 });
  expect(store['prqQueueDepth{"operation_type":"TRANSPARENCY_SAVE","status":"PENDING"}']).toBe(2);
  expect(store['prqOldestPendingAgeSeconds{"operation_type":"TRANSPARENCY_SAVE"}']).toBe(12);
  expect(store['transparencyUnrootedIdSpan{}']).toBe(20);
  expect(store['prqDlqDepth{}']).toBe(0);
});

test('QM-02 a crossing raises one QUEUE_BACKLOG alert', async () => {
  const s = quiet();
  s.rows.push({ operationType: 'EVIDENCE_CHAIN_SAVE', status: 'DLQ', depth: 4, retrying: 0, oldestAgeSeconds: 0 });
  const { mon, alerts, m } = deps(s);
  await mon.sample();
  expect(alerts).toHaveLength(1);
  expect(alerts[0]).toEqual(expect.objectContaining({ type: 'OPERATIONAL', subtype: 'QUEUE_BACKLOG', severity: 'HIGH', context: { queue: 'prq_dlq', depth: 4, threshold: 1 } }));
  expect(m.queueBacklogAlertsTotal.inc).toHaveBeenCalledWith({ queue: 'prq_dlq' });
});

test('QM-03 edge-triggered, re-armed after recovery', async () => {
  const s = quiet();
  const { mon, alerts } = deps(s);
  s.journal = { depth: 3, oldestEntryAgeMs: 5000, totalBytes: 10 };
  await mon.sample(); await mon.sample();
  expect(alerts).toHaveLength(1);
  expect(mon.getStatus().firing).toEqual(['prq_journal']);
  s.journal = { depth: 0, oldestEntryAgeMs: 0, totalBytes: 0 };
  await mon.sample();
  expect(mon.getStatus().firing).toEqual([]);
  s.journal = { depth: 1, oldestEntryAgeMs: 0, totalBytes: 1 };
  await mon.sample();
  expect(alerts).toHaveLength(2);
});

test('QM-04 a failing source does not stop the others', async () => {
  const s = quiet();
  const { mon } = deps(s, { _queue: { getDepthByType: jest.fn(async () => { throw new Error('PG down'); }) } });
  const d = await mon.sample();
  expect(d.prq_pending).toBeUndefined();
  expect(d.prq_journal).toBe(0);
  expect(d.audit_mirror_writer).toBe(3);
  expect(d.transparency_unrooted).toBe(20);
});

test('QM-05 threshold 0 disables; env overrides defaults', async () => {
  const s = quiet(); s.mirror = 10_000;
  const { mon, alerts } = deps(s, { _thresholds: { prq_pending: 10, prq_retrying: 5, transparency_pending: 3, prq_dlq: 1, prq_journal: 1, audit_mirror_writer: 0, transparency_unrooted: 1000 } });
  await mon.sample();
  expect(alerts).toHaveLength(0);

  process.env.QODIQA_ALERT_PRQ_DLQ_DEPTH = '7';
  try { expect(thresholds().prq_dlq).toBe(7); } finally { delete process.env.QODIQA_ALERT_PRQ_DLQ_DEPTH; }
  expect(thresholds()).toEqual({ prq_pending: 500, prq_retrying: 100, transparency_pending: 100, prq_dlq: 1, prq_journal: 1, audit_mirror_writer: 1000, transparency_unrooted: 50000 });
});

test('QM-06 start() runs samples through the registered task; stop() ends the loop', async () => {
  const s = quiet();
  const runTask = jest.fn(async (name, fn) => { await fn(); return { ok: true }; });
  const { mon } = deps(s, { intervalMs: 5, _taskRunner: { runTask } });
  mon.start();
  await new Promise((r) => setTimeout(r, 40));
  mon.stop();
  const n = runTask.mock.calls.length;
  expect(n).toBeGreaterThanOrEqual(2);
  expect(runTask.mock.calls[0][0]).toBe('queue-depth-monitor');
  await new Promise((r) => setTimeout(r, 30));
  expect(runTask.mock.calls.length).toBe(n);
});
