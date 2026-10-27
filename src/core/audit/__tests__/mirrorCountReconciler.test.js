'use strict';

/**
 * S4 — mirrorCountReconciler (OD-5: periodic cross-check, CRITICAL on drift, NO automatic healing).
 *
 *   RU-01 in sync → INFO AUDIT_MIRROR_COUNT_RECONCILED, no CRITICAL
 *   RU-02 mismatch → CRITICAL AUDIT_MIRROR_COUNT_DRIFT {reason MISMATCH, stored, exact, delta, trigger}
 *   RU-03 persisting drift re-alerts on every run, consecutiveDriftRuns escalates, firstDetectedAt is kept
 *   RU-04 back in sync (after an owner rebuild) → DRIFT_CLEARED once, streak reset
 *   RU-05 counter row missing → CRITICAL {reason COUNTER_MISSING}
 *   RU-06 check cannot run → WARN RECONCILE_FAILED, never thrown, never CRITICAL, streak untouched
 *   RU-07 never writes: the default check is the backend's read-only cross-check — its only SQL is the check function
 *   RU-08 PG disabled → SKIPPED, no query
 *   RU-09 boot validation: trigger BOOT, non-fatal on drift and on failure; kill switch QODIQA_AUDIT_MIRROR_RECONCILE=off
 *   RU-10 schedule: registered task name, default 6 h, env interval, runs through the task runner, never on the lag path
 *   RU-11 the drift event becomes a CRITICAL operational alert (OperationalDetector)
 *   RU-12 the 60 s lag query is unchanged: pgCountQuery reads only the O(1) counter, never the check or the full count
 */

describe('S4 mirrorCountReconciler', () => {
  let rec; let events;
  const emitFn = (level, type, data) => events.push({ level, type, data });
  const on = () => true;
  const check = (stored, exact) => async () => ({ stored, exact, inSync: stored !== null && stored === exact });

  beforeEach(() => {
    jest.resetModules();
    delete process.env.QODIQA_AUDIT_MIRROR_RECONCILE;
    delete process.env.QODIQA_AUDIT_MIRROR_RECONCILE_INTERVAL_MS;
    rec = require('../mirrorCountReconciler');
    rec._resetState();
    events = [];
  });
  afterEach(() => { rec._resetState(); jest.useRealTimers(); });

  test('RU-01 in sync → INFO RECONCILED, no CRITICAL', async () => {
    const out = await rec.reconcileOnce({ trigger: 'SCHEDULED', check: check(42, 42), emitFn, pgEnabled: on });
    expect(out).toMatchObject({ status: 'IN_SYNC', stored: 42, exact: 42, trigger: 'SCHEDULED' });
    expect(events.map((e) => `${e.level}:${e.type}`)).toEqual(['INFO:AUDIT_MIRROR_COUNT_RECONCILED']);
  });

  test('RU-02 mismatch → CRITICAL AUDIT_MIRROR_COUNT_DRIFT with the figures', async () => {
    const out = await rec.reconcileOnce({ trigger: 'SCHEDULED', check: check(17, 12), emitFn, pgEnabled: on });
    expect(out).toMatchObject({ status: 'DRIFT', reason: 'MISMATCH', stored: 17, exact: 12, delta: 5, consecutiveDriftRuns: 1 });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ level: 'CRITICAL', type: 'AUDIT_MIRROR_COUNT_DRIFT', data: { reason: 'MISMATCH', stored: 17, exact: 12, delta: 5, trigger: 'SCHEDULED' } });
    expect(typeof events[0].data.firstDetectedAt).toBe('string');
  });

  test('RU-03 persisting drift is re-alerted on every run with an escalating streak', async () => {
    const outs = [];
    for (let i = 0; i < 3; i++) outs.push(await rec.reconcileOnce({ check: check(10, 12), emitFn, pgEnabled: on }));
    expect(outs.map((o) => o.consecutiveDriftRuns)).toEqual([1, 2, 3]);
    expect(new Set(outs.map((o) => o.firstDetectedAt)).size).toBe(1);
    expect(events.filter((e) => e.level === 'CRITICAL')).toHaveLength(3);
    expect(outs[0].delta).toBe(-2);
  });

  test('RU-04 back in sync after an owner rebuild → DRIFT_CLEARED once, streak reset', async () => {
    await rec.reconcileOnce({ check: check(10, 12), emitFn, pgEnabled: on });
    await rec.reconcileOnce({ check: check(10, 12), emitFn, pgEnabled: on });
    events = [];
    await rec.reconcileOnce({ check: check(12, 12), emitFn, pgEnabled: on });
    expect(events.map((e) => e.type)).toEqual(['AUDIT_MIRROR_COUNT_DRIFT_CLEARED', 'AUDIT_MIRROR_COUNT_RECONCILED']);
    expect(events[0].data).toMatchObject({ stored: 12, exact: 12, driftRuns: 2 });
    events = [];
    await rec.reconcileOnce({ check: check(12, 12), emitFn, pgEnabled: on });
    expect(events.map((e) => e.type)).toEqual(['AUDIT_MIRROR_COUNT_RECONCILED']);
    const again = await rec.reconcileOnce({ check: check(13, 12), emitFn, pgEnabled: on });
    expect(again.consecutiveDriftRuns).toBe(1);
  });

  test('RU-05 counter row missing → CRITICAL COUNTER_MISSING', async () => {
    const out = await rec.reconcileOnce({ check: async () => ({ stored: null, exact: 5, inSync: false }), emitFn, pgEnabled: on });
    expect(out).toMatchObject({ status: 'DRIFT', reason: 'COUNTER_MISSING', stored: null, exact: 5, delta: null });
    expect(events[0]).toMatchObject({ level: 'CRITICAL', type: 'AUDIT_MIRROR_COUNT_DRIFT', data: { reason: 'COUNTER_MISSING' } });
  });

  test('RU-06 the check cannot run → WARN RECONCILE_FAILED, never thrown, never CRITICAL, streak untouched', async () => {
    await rec.reconcileOnce({ check: check(1, 2), emitFn, pgEnabled: on });
    events = [];
    for (const msg of ['connection refused', 'function qodiqa_audit_chain_mirror_count_check() does not exist', 'permission denied for function']) {
      const out = await rec.reconcileOnce({ check: async () => { throw new Error(msg); }, emitFn, pgEnabled: on });
      expect(out).toMatchObject({ status: 'FAILED', error: msg });
    }
    expect(events.every((e) => e.level === 'WARN' && e.type === 'AUDIT_MIRROR_COUNT_RECONCILE_FAILED')).toBe(true);
    const next = await rec.reconcileOnce({ check: check(1, 2), emitFn, pgEnabled: on });
    expect(next.consecutiveDriftRuns).toBe(2);   // a failed run neither clears nor advances the drift streak
  });

  test('RU-07 never writes: the default check sends exactly one read-only statement, the check function', async () => {
    const queries = [];
    jest.doMock('../../../infra/postgres/rolePools', () => ({
      system: { query: async (sql, params, label) => { queries.push({ sql, label }); return { rows: [{ stored: '9', exact: '7', in_sync: false }] }; } },
    }));
    jest.doMock('../../../infra/postgres/pool', () => ({ isEnabled: () => true, query: async (sql) => { queries.push({ sql, label: 'pgPool' }); return { rows: [] }; } }));
    const r = require('../mirrorCountReconciler');
    const out = await r.reconcileOnce({ emitFn });
    expect(out).toMatchObject({ status: 'DRIFT', stored: 9, exact: 7 });
    expect(queries).toEqual([{ sql: 'SELECT stored, exact, in_sync FROM qodiqa_audit_chain_mirror_count_check()', label: 'audit_chain_mirror_count_check' }]);
    const src = require('fs').readFileSync(require.resolve('../mirrorCountReconciler'), 'utf8').replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '');
    expect(src).not.toMatch(/\.query\(/);                                    // no SQL of its own: only the backend's read-only check
    expect(src).not.toMatch(/require\([^)]*(scripts\/dr|auditChainMirrorCount|audit-mirror-rebuild)/);   // no path to the owner rebuild
    r._resetState();
  });

  test('RU-08 PG disabled → SKIPPED without querying', async () => {
    const spy = jest.fn();
    expect(await rec.reconcileOnce({ check: spy, emitFn, pgEnabled: () => false })).toMatchObject({ status: 'SKIPPED', reason: 'PG_DISABLED' });
    expect(spy).not.toHaveBeenCalled();
    expect(events).toEqual([]);
  });

  test('RU-09 boot validation: trigger BOOT, non-fatal; kill switch disables it', async () => {
    await expect(rec.validateAtBoot({ check: check(3, 4), emitFn, pgEnabled: on })).resolves.toMatchObject({ status: 'DRIFT', trigger: 'BOOT' });
    await expect(rec.validateAtBoot({ check: async () => { throw new Error('down'); }, emitFn, pgEnabled: on })).resolves.toMatchObject({ status: 'FAILED', trigger: 'BOOT' });
    process.env.QODIQA_AUDIT_MIRROR_RECONCILE = 'off';
    const spy = jest.fn();
    await expect(rec.validateAtBoot({ check: spy, emitFn, pgEnabled: on })).resolves.toMatchObject({ status: 'SKIPPED', reason: 'DISABLED' });
    expect(spy).not.toHaveBeenCalled();
    expect(rec.startReconciler({ _taskRunner: { runTask: jest.fn() } })).toBe(false);
  });

  test('RU-10 schedule: registered task, 6 h default, env interval, through the task runner', async () => {
    const { REGISTRY } = require('../../../runtime/backgroundTasks/taskRegistry');
    expect(REGISTRY[rec.TASK_NAME]).toMatchObject({ subsystem: 'audit-log', criticality: 'non-critical', file: 'src/core/audit/mirrorCountReconciler.js' });
    expect(rec.DEFAULT_INTERVAL_MS).toBe(6 * 60 * 60 * 1000);
    jest.useFakeTimers();
    const calls = [];
    const runner = { runTask: (name, fn) => { calls.push(name); return Promise.resolve(fn()).then((result) => ({ ok: true, result })); } };
    const c = jest.fn(check(5, 5));
    expect(rec.startReconciler({ _taskRunner: runner, check: c, emitFn, pgEnabled: on })).toBe(true);
    expect(rec.startReconciler({ _taskRunner: runner })).toBe(false);   // already running
    jest.advanceTimersByTime(6 * 60 * 60 * 1000 - 1);
    expect(calls).toEqual([]);
    jest.advanceTimersByTime(1);
    expect(calls).toEqual(['audit-mirror-count-reconcile']);
    rec.stopReconciler();
    process.env.QODIQA_AUDIT_MIRROR_RECONCILE_INTERVAL_MS = '1000';
    rec.startReconciler({ _taskRunner: runner, check: c, emitFn, pgEnabled: on });
    jest.advanceTimersByTime(3000);
    expect(calls).toHaveLength(4);
    jest.useRealTimers();
    await Promise.resolve();
    expect(c.mock.calls.length).toBeGreaterThanOrEqual(1);
  });

  test('RU-11 the drift event becomes a CRITICAL operational alert', () => {
    const { analyze } = require('../../../alerting/detection/OperationalDetector');
    const { SEVERITY, OPERATIONAL_SUBTYPE } = require('../../../alerting/constants');
    const r = analyze({ eventType: 'AUDIT_MIRROR_COUNT_DRIFT', reason: 'MISMATCH', trigger: 'BOOT', stored: 17, exact: 12, delta: 5, consecutiveDriftRuns: 2 });
    expect(r.triggered).toBe(true);
    expect(r.alert).toMatchObject({ severity: SEVERITY.CRITICAL, subtype: OPERATIONAL_SUBTYPE.AUDIT_MIRROR_COUNT_DRIFT, sourceEvent: 'AUDIT_MIRROR_COUNT_DRIFT',
      evidence: { reason: 'MISMATCH', stored: 17, exact: 12, delta: 5, consecutiveDriftRuns: 2, trigger: 'BOOT' } });
    expect(r.alert.description).toMatch(/NOT repaired automatically/);
    expect(analyze({ eventType: 'AUDIT_MIRROR_COUNT_RECONCILED' }).triggered).toBe(false);
  });

  test('RU-12 the 60 s lag query is unchanged: only the O(1) counter, never the check or the full count', async () => {
    const queries = [];
    jest.doMock('../../../infra/postgres/rolePools', () => ({ system: { query: async (sql, p, label) => { queries.push(label); return { rows: [{ n: '11' }] }; } } }));
    jest.doMock('../../../infra/postgres/pool', () => ({ isEnabled: () => true }));
    delete process.env.QODIQA_AUDIT_LAG_COUNT;
    const lag = require('../pgLagMonitor');
    for (let i = 0; i < 5; i++) expect((await lag.pgCountQuery()).rows[0].cnt).toBe(11);
    expect(queries).toEqual(Array(5).fill('audit_chain_mirror_count'));
    const src = require('fs').readFileSync(require.resolve('../pgLagMonitor'), 'utf8');
    expect(src).not.toMatch(/mirrorCountReconciler|mirrorCountCheck|mirror_count_check/);
  });
});
