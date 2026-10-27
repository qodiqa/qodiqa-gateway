'use strict';

/**
 * a hung PostgreSQL anchor write must not silence the anchor health signal.
 *
 * (e161bbf4) serialized the PG anchor writes: _drain() awaits each pgPool.query() before issuing the next. When
 * the server stops answering on an established connection (a silent partition) that query never settles — the
 * server-side statement_timeout cannot fire and the pool has no client-side timeout — so the writer stopped for good:
 * no failure, backend gauge stuck at 1, lastPgWriteOk stuck at true, callers pending forever (independent closure
 * verification).
 *
 * The fake database models the real one where it matters (one row, the migration-062 forward-only trigger with its
 * SQLSTATE and text) and lets each test HANG a query and release it later — a silent partition followed by a late
 * result. Timers are real; the write deadline is derived from the pool's own timeouts, set small here.
 */

const STATEMENT_MS = 100;
const ACQUIRE_MS = 50;
const DEADLINE_MS = STATEMENT_MS + ACQUIRE_MS + 2000;   // the documented derivation (checksumAnchor.js)

function makeDb() {
  const db = { row: null, history: [], hangNext: 0, hung: [], issued: [], failNext: null };
  const apply = (count, tailHash) => {
    const old = db.row;
    if (old && (count < old.count || (count === old.count && tailHash !== old.tailHash))) {
      const e = new Error(`audit_checksum_anchor is forward-only: count ${old.count} -> ${count} refused for role qodiqa_app`);
      e.code = '42501';
      throw e;
    }
    db.row = { count, tailHash };
    db.history.push(count);
    return { rows: [], rowCount: 1 };
  };
  db.query = jest.fn((sql, params, label) => {
    if (label !== 'audit_checksum_anchor_upsert') return Promise.resolve({ rows: [], rowCount: 0 });
    const [count, tailHash] = params;
    db.issued.push(count);
    if (db.failNext) { const e = db.failNext; db.failNext = null; return Promise.reject(e); }
    if (db.hangNext > 0) {
      db.hangNext--;
      // A silent partition: nothing comes back until the test releases it (then it reaches the server late).
      return new Promise((resolve, reject) => db.hung.push({ count, release: () => { try { resolve(apply(count, tailHash)); } catch (e) { reject(e); } } }));
    }
    try { return Promise.resolve(apply(count, tailHash)); } catch (e) { return Promise.reject(e); }
  });
  return db;
}

function load(db) {
  jest.resetModules();
  jest.doMock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn(() => true), query: db.query }));
  const emit = jest.fn();
  jest.doMock('../../../../services/logger', () => ({ emit }));
  const gauge = { set: jest.fn() };
  jest.doMock('../../../observability/metrics', () => ({
    auditChecksumAnchorBackend: gauge, auditChecksumAnchorLastWriteTimestamp: { set: jest.fn() },
  }));
  return { anchor: require('../checksumAnchor'), emit, gauge };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const failures = (emit) => emit.mock.calls.filter((c) => c[1] === 'AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED');
const gaugeLast = (gauge) => (gauge.set.mock.calls.length ? gauge.set.mock.calls[gauge.set.mock.calls.length - 1][1] : undefined);
/** Resolves to 'settled' or 'pending' after `ms` — never hangs the test, so the pre-fix code FAILS instead of timing out. */
const settledWithin = (p, ms) => Promise.race([p.then(() => 'settled'), sleep(ms).then(() => 'pending')]);
const monotonic = (h) => h.every((v, i) => i === 0 || v >= h[i - 1]);

let saved;
beforeEach(() => {
  saved = { s: process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS, a: process.env.QODIQA_PG_ACQUIRE_TIMEOUT_MS };
  process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS = String(STATEMENT_MS);
  process.env.QODIQA_PG_ACQUIRE_TIMEOUT_MS = String(ACQUIRE_MS);
});
afterEach(() => {
  for (const [k, v] of [['QODIQA_PG_STATEMENT_TIMEOUT_MS', saved.s], ['QODIQA_PG_ACQUIRE_TIMEOUT_MS', saved.a]]) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  jest.dontMock('../../../infra/postgres/pool');
  jest.dontMock('../../../../services/logger');
  jest.dontMock('../../../observability/metrics');
});
jest.setTimeout(30_000);

describe('bounded PG anchor writes (silent partition)', () => {
  test('N04-01 a normal write succeeds (no deadline involvement)', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await anchor.saveChecksumPg(1, 'a');
    expect(db.row).toEqual({ count: 1, tailHash: 'a' });
    expect(gaugeLast(gauge)).toBe(1);
    expect(failures(emit)).toHaveLength(0);
    expect(anchor.getBackendStatus().pgWritesTimedOut).toBe(0);
  });

  test('N04-02 an immediate PostgreSQL error keeps the existing failure behaviour', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    db.failNext = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:5432'), { code: 'ECONNREFUSED' });
    await anchor.saveChecksumPg(1, 'a');
    expect(failures(emit)).toHaveLength(1);
    expect(failures(emit)[0][2].error).toMatch(/ECONNREFUSED/);
    expect(gaugeLast(gauge)).toBe(0);
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(false);
    expect(anchor.getBackendStatus().pgWritesTimedOut).toBe(0);
  });

  test('N04-03 a silently hung write becomes a failure at the deadline: reported, gauge 0, caller settles, writer not blocked', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await anchor.saveChecksumPg(1, 'a');                    // healthy first
    db.hangNext = 1;
    const t0 = Date.now();
    const p = anchor.saveChecksumPg(2, 'b');
    expect(await settledWithin(p, DEADLINE_MS + 1500)).toBe('settled');
    const elapsed = Date.now() - t0;
    expect(elapsed).toBeGreaterThanOrEqual(DEADLINE_MS - 50);   // not a premature false failure
    expect(failures(emit)).toHaveLength(1);
    expect(failures(emit)[0][2].error).toMatch(/did not complete within/);
    expect(gaugeLast(gauge)).toBe(0);
    const st = anchor.getBackendStatus();
    expect(st.lastPgWriteOk).toBe(false);
    expect(st.pgWritesTimedOut).toBe(1);
    expect(st.pgWritesQueued).toBe(0);
  });

  test('N04-04 after a timed-out write, a later valid write executes and restores health', async () => {
    const db = makeDb(); const { anchor, gauge } = load(db);
    db.hangNext = 1;
    expect(await settledWithin(anchor.saveChecksumPg(5, 'e'), DEADLINE_MS + 1500)).toBe('settled');
    expect(gaugeLast(gauge)).toBe(0);
    await anchor.saveChecksumPg(6, 'f');
    expect(db.row).toEqual({ count: 6, tailHash: 'f' });
    expect(gaugeLast(gauge)).toBe(1);
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(true);
  });

  test('N04-05 a LATE success of the abandoned write does not restore health', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    db.hangNext = 1;
    expect(await settledWithin(anchor.saveChecksumPg(10, 'j'), DEADLINE_MS + 1500)).toBe('settled');
    expect(gaugeLast(gauge)).toBe(0);
    const setsBefore = gauge.set.mock.calls.length;
    db.hung[0].release();                                    // the partitioned query finally reaches the server
    await sleep(20);
    expect(db.row).toEqual({ count: 10, tailHash: 'j' });    // it committed (legitimately monotonic)...
    expect(gauge.set.mock.calls.length).toBe(setsBefore);     // ...but health was not touched
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(false);
    expect(anchor.getBackendStatus().pgLateResults).toBe(1);
    expect(emit).toHaveBeenCalledWith('INFO', 'AUDIT_CHECKSUM_ANCHOR_PG_LATE_RESULT', expect.objectContaining({ count: 10, outcome: 'committed' }));
  });

  test('N04-06 a LATE result of the abandoned write cannot overwrite the newer anchor or disturb health', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    db.hangNext = 1;
    const pA = anchor.saveChecksumPg(100, 'A');
    expect(await settledWithin(pA, DEADLINE_MS + 1500)).toBe('settled');
    await anchor.saveChecksumPg(101, 'B');                   // B issued after A was abandoned, commits first
    expect(gaugeLast(gauge)).toBe(1);
    const setsBefore = gauge.set.mock.calls.length;
    const failsBefore = failures(emit).length;
    db.hung[0].release();                                    // A arrives late: the guard refuses it
    await sleep(20);
    expect(db.row).toEqual({ count: 101, tailHash: 'B' });
    expect(monotonic(db.history)).toBe(true);
    expect(gauge.set.mock.calls.length).toBe(setsBefore);
    expect(failures(emit).length).toBe(failsBefore);
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(true);
    expect(emit).toHaveBeenCalledWith('INFO', 'AUDIT_CHECKSUM_ANCHOR_PG_LATE_RESULT', expect.objectContaining({ count: 100, outcome: 'failed' }));
  });

  test('N04-07 concurrent writes around a hang stay ordered and monotonic; every caller settles', async () => {
    const db = makeDb(); const { anchor } = load(db);
    db.hangNext = 1;
    const calls = [];
    for (let k = 1; k <= 50; k++) calls.push(anchor.saveChecksumPg(k, `t${k}`));
    expect(await settledWithin(Promise.all(calls), DEADLINE_MS + 2000)).toBe('settled');
    expect(db.row.count).toBe(50);
    expect(monotonic(db.history)).toBe(true);
    db.hung.forEach((h) => h.release());
    await sleep(20);
    expect(db.row.count).toBe(50);
    expect(monotonic(db.history)).toBe(true);
  });

  test('N04-08 preserved: a same-process stale write is still benign (INFO, health untouched)', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await anchor.saveChecksumPg(26654, 'b');
    await anchor.saveChecksumPg(26653, 'a');
    expect(db.row).toEqual({ count: 26654, tailHash: 'b' });
    expect(failures(emit)).toHaveLength(0);
    expect(gauge.set.mock.calls.some((c) => c[1] === 0)).toBe(false);
    expect(anchor.getBackendStatus().pgStaleWritesRefused).toBe(1);
  });

  test('N04-09 preserved: same count with a different tail hash is a genuine failure', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await anchor.saveChecksumPg(7, 'x');
    await anchor.saveChecksumPg(7, 'FORK');
    expect(db.row).toEqual({ count: 7, tailHash: 'x' });
    expect(failures(emit)).toHaveLength(1);
    expect(gaugeLast(gauge)).toBe(0);
  });

  test('N04-10 preserved: another writer\'s higher anchor is a genuine failure', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await anchor.saveChecksumPg(100, 'p');
    db.row = { count: 150, tailHash: 'other' };              // another writer advanced the row
    await anchor.saveChecksumPg(120, 'q');
    expect(db.row).toEqual({ count: 150, tailHash: 'other' });
    expect(failures(emit)).toHaveLength(1);
    expect(gaugeLast(gauge)).toBe(0);
    expect(anchor.getBackendStatus().pgStaleWritesRefused).toBe(0);
  });

  test('N04-11 the deadline is derived from the pool timeouts (statement + acquire + 2,000 ms), defaults 33,500 ms', () => {
    const db = makeDb(); const { anchor } = load(db);
    expect(anchor._anchorWriteDeadlineMs()).toBe(DEADLINE_MS);
    delete process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS; delete process.env.QODIQA_PG_ACQUIRE_TIMEOUT_MS;
    expect(anchor._anchorWriteDeadlineMs()).toBe(30_000 + 1_500 + 2_000);
  });
});
