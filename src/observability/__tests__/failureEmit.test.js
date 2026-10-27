'use strict';

/**
 * (design decision 3 / O9) — first N per failure type per window in full, the rest counted.
 *
 *   FE-01  firstN: the first N occurrences are emitted in full, the rest counted in ONE summary with the exact count
 * FE-02 firstN defaults to 1 — the behaviour of every existing caller is unchanged
 *   FE-03  failureEmit: default N = 10 per event type; each type has its own window
 *   FE-04  QODIQA_LOG_FAILURE_FIRST_N=0 is the rollback switch (every event passes); invalid values fall back to 10
 * FE-05 the seven O9 event types are exactly the ones routed through failureEmit (source scan)
 */

const fs = require('fs');
const path = require('path');
const { aggregatedEmit, failureEmit, failureFirstN, FAILURE_EVENT_TYPES, WINDOW_MS, _resetForTests } = require('../aggregatedEmit');

describe('failureEmit (O9)', () => {
  let out; const emit = (level, type, payload) => out.push({ level, type, payload });
  const saved = process.env.QODIQA_LOG_FAILURE_FIRST_N;
  beforeEach(() => { jest.useFakeTimers(); out = []; _resetForTests(); delete process.env.QODIQA_LOG_FAILURE_FIRST_N; });
  afterEach(() => {
    _resetForTests(); jest.useRealTimers();
    if (saved === undefined) delete process.env.QODIQA_LOG_FAILURE_FIRST_N; else process.env.QODIQA_LOG_FAILURE_FIRST_N = saved;
  });

  test('FE-01 first N in full, the rest counted', () => {
    for (let i = 0; i < 25; i++) aggregatedEmit(emit, 'ERROR', 'X', { i }, 'k', { firstN: 5 });
    expect(out.map((e) => e.payload.i)).toEqual([0, 1, 2, 3, 4]);
    jest.advanceTimersByTime(WINDOW_MS);
    expect(out[5]).toEqual({ level: 'ERROR', type: 'LOG_EVENTS_AGGREGATED', payload: { eventType: 'X', key: 'k', suppressed: 20, windowMs: WINDOW_MS } });
    aggregatedEmit(emit, 'ERROR', 'X', { i: 99 }, 'k', { firstN: 5 });
    expect(out[6].payload).toEqual({ i: 99 });                                  // a new window starts in full
  });

  test('FE-02 default firstN = 1', () => {
    for (let i = 0; i < 3; i++) aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { i }, 'q');
    expect(out).toHaveLength(1);
  });

  test('FE-03 failureEmit: 10 per type per window, types independent', () => {
    expect(failureFirstN()).toBe(10);
    for (let i = 0; i < 40; i++) { failureEmit(emit, 'ERROR', 'PG_AUDIT_PERSIST_FAILED', { i }); failureEmit(emit, 'WARN', 'JOURNAL_ENTRY_WRITTEN', { i }); }
    expect(out.filter((e) => e.type === 'PG_AUDIT_PERSIST_FAILED')).toHaveLength(10);
    expect(out.filter((e) => e.type === 'JOURNAL_ENTRY_WRITTEN')).toHaveLength(10);
    jest.advanceTimersByTime(WINDOW_MS);
    const sums = out.filter((e) => e.type === 'LOG_EVENTS_AGGREGATED').map((e) => [e.payload.eventType, e.payload.suppressed]).sort();
    expect(sums).toEqual([['JOURNAL_ENTRY_WRITTEN', 30], ['PG_AUDIT_PERSIST_FAILED', 30]]);
  });

  test('FE-04 rollback switch and invalid values', () => {
    process.env.QODIQA_LOG_FAILURE_FIRST_N = '0';
    for (let i = 0; i < 30; i++) failureEmit(emit, 'ERROR', 'PG_AUDIT_PERSIST_FAILED', { i });
    expect(out).toHaveLength(30);
    process.env.QODIQA_LOG_FAILURE_FIRST_N = 'abc';
    expect(failureFirstN()).toBe(10);
    process.env.QODIQA_LOG_FAILURE_FIRST_N = '3';
    expect(failureFirstN()).toBe(3);
  });

  test('FE-05 the seven O9 event types are the ones routed through failureEmit', () => {
    expect([...FAILURE_EVENT_TYPES].sort()).toEqual(['AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED', 'CONSENT_AUDIT_LOG_FAILED', 'EVIDENCE_CHAIN_PERSIST_FAILED',
      'JOURNAL_ENTRY_WRITTEN', 'PG_AUDIT_PERSIST_FAILED', 'RECOVERY_ENQUEUE_FAILED', 'TRANSPARENCY_ENTRY_PENDING']);
    const root = path.join(__dirname, '..', '..', '..');
    const files = ['src/core/audit/checksumAnchor.js', 'src/core/consent/ConsentStore.js', 'src/core/evidence/chainStore.js', 'src/core/persistenceRecovery/journal.js',
      'src/core/persistenceRecovery/recoveryManager.js', 'src/core/transparency/enforcementBridge.js', 'src/infra/postgres/pg-audit-backend.js'];
    const routed = new Set(); const direct = [];
    for (const f of files) {
      const src = fs.readFileSync(path.join(root, f), 'utf8');
      for (const t of FAILURE_EVENT_TYPES) {
        if (new RegExp(`failureEmit\\([^,]+, '(WARN|ERROR)', '${t}'`).test(src)) routed.add(t);
        if (new RegExp(`(^|[^.\\w])emit\\('(WARN|ERROR)', '${t}'`, 'm').test(src)) direct.push(`${f}:${t}`);
      }
    }
    expect([...routed].sort()).toEqual([...FAILURE_EVENT_TYPES].sort());
    expect(direct).toEqual([]);
  });
});
