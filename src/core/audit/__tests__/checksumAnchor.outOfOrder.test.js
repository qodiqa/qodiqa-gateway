'use strict';

/**
 * concurrent PG checksum-anchor writes arriving out of order.
 *
 * audit-log.js calls checksumAnchor.saveChecksumPg() fire-and-forget after every durable batch. Before the fix each
 * call issued its own pgPool.query() on whatever pool connection it got, so two back-to-back upserts (26653, 26654)
 * could COMMIT in reverse order; migration 062's forward-only trigger then refused the stale one ("count 26654 ->
 * 26653 refused") — the anchor stayed correct, but the refusal was reported as AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED
 * and set qodiqa_audit_checksum_anchor_backend to 0 (a false durability signal).
 *
 * The fake pool below models the real database exactly where it matters: one anchor row, the migration-062 trigger
 * (NEW.count < OLD.count, or equal count with a different tail_hash → SQLSTATE 42501 with the trigger's own message),
 * and an explicit COMMIT ORDER chosen by the test, so the race is reproduced deterministically.
 */

const FORWARD_ONLY = (oldC, newC) => `audit_checksum_anchor is forward-only: count ${oldC} -> ${newC} refused for role qodiqa_app`;

function makeDb({ seed = null } = {}) {
  const db = {
    row: seed ? { ...seed } : null,
    history: seed ? [seed.count] : [],
    pending: [],          // issued, not yet committed: { count, tailHash, resolve, reject }
    issued: [],           // every query issued, in issue order (counts)
    failNext: null,       // an Error to throw for the next committed query (genuine failure injection)
  };
  db.query = jest.fn((sql, params, label) => {
    if (label !== 'audit_checksum_anchor_upsert') return Promise.resolve({ rows: [], rowCount: 0 });
    return new Promise((resolve, reject) => {
      const [count, tailHash] = params;
      db.issued.push(count);
      db.pending.push({ count, tailHash, resolve, reject });
    });
  });
  // Commit one issued query (by index into `pending`) through the migration-062 guard.
  db.commit = (i) => {
    const q = db.pending.splice(i, 1)[0];
    if (db.failNext) { const e = db.failNext; db.failNext = null; q.reject(e); return; }
    const old = db.row;
    if (old && (q.count < old.count || (q.count === old.count && q.tailHash !== old.tailHash))) {
      const e = new Error(FORWARD_ONLY(old.count, q.count));
      e.code = '42501';
      q.reject(e);
      return;
    }
    db.row = { count: q.count, tailHash: q.tailHash };
    db.history.push(q.count);
    q.resolve({ rows: [], rowCount: 1 });
  };
  return db;
}

function load(db, { pgEnabled = true } = {}) {
  jest.resetModules();
  jest.doMock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn(() => pgEnabled), query: db.query }));
  const emit = jest.fn();
  jest.doMock('../../../../services/logger', () => ({ emit }));
  const gauge = { set: jest.fn() };
  jest.doMock('../../../observability/metrics', () => ({
    auditChecksumAnchorBackend: gauge,
    auditChecksumAnchorLastWriteTimestamp: { set: jest.fn() },
  }));
  const anchor = require('../checksumAnchor');
  return { anchor, emit, gauge };
}

const tick = () => new Promise((r) => setImmediate(r));
async function settle() { for (let i = 0; i < 5; i++) await tick(); }

// Drive the DB until every caller's promise settled: at each step commit the pending query chosen by `pick`.
async function drive(db, promises, pick) {
  let done = false;
  const all = Promise.all(promises).then(() => { done = true; });
  for (let guard = 0; !done && guard < 10_000; guard++) {
    await settle();
    if (done) break;
    if (db.pending.length) db.commit(pick(db.pending.length));
  }
  await all;
}
const NEWEST_FIRST = (n) => n - 1;   // the adversarial order that produced (later query commits first)
const OLDEST_FIRST = () => 0;

const failures = (emit) => emit.mock.calls.filter((c) => c[1] === 'AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED');
const zeroed = (gauge) => gauge.set.mock.calls.some((c) => c[1] === 0);
const monotonic = (h) => h.every((v, i) => i === 0 || v >= h[i - 1]);

function prng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }

afterEach(() => {
  jest.dontMock('../../../infra/postgres/pool');
  jest.dontMock('../../../../services/logger');
  jest.dontMock('../../../observability/metrics');
});

describe('PG checksum anchor: ordering, stale writes, genuine failures', () => {
  test('N03-01 the first anchor write succeeds: row created, gauge 1, status ok', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await drive(db, [anchor.saveChecksumPg(1, 'h1')], OLDEST_FIRST);
    expect(db.row).toEqual({ count: 1, tailHash: 'h1' });
    expect(gauge.set).toHaveBeenLastCalledWith({}, 1);
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(true);
    expect(failures(emit)).toHaveLength(0);
  });

  test('N03-02 a newer anchor write succeeds after an older one', async () => {
    const db = makeDb(); const { anchor, gauge } = load(db);
    await drive(db, [anchor.saveChecksumPg(26653, 'a')], OLDEST_FIRST);
    await drive(db, [anchor.saveChecksumPg(26654, 'b')], OLDEST_FIRST);
    expect(db.row).toEqual({ count: 26654, tailHash: 'b' });
    expect(db.history).toEqual([26653, 26654]);
    expect(zeroed(gauge)).toBe(false);
  });

  test('N03-03 a stale write after this process committed a newer anchor is refused by the guard, kept out, and NOT reported as a failure', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await drive(db, [anchor.saveChecksumPg(26654, 'b')], OLDEST_FIRST);
    await drive(db, [anchor.saveChecksumPg(26653, 'a')], OLDEST_FIRST);
    expect(db.issued).toEqual([26654, 26653]);                       // the stale write still went to the guard
    expect(db.row).toEqual({ count: 26654, tailHash: 'b' });          // ...which kept the newer anchor
    expect(failures(emit)).toHaveLength(0);
    expect(zeroed(gauge)).toBe(false);
    const st = anchor.getBackendStatus();
    expect(st.lastPgWriteOk).toBe(true);
    expect(st.pgStaleWritesRefused).toBe(1);
    expect(emit).toHaveBeenCalledWith('INFO', 'AUDIT_CHECKSUM_ANCHOR_PG_STALE_WRITE_REFUSED',
      expect.objectContaining({ incomingCount: 26653, currentCount: 26654 }));
  });

  test('N03-04 the original race: 26653 and 26654 issued concurrently, the later one committing first — no refusal, no failure, final 26654', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await drive(db, [anchor.saveChecksumPg(26653, 'a'), anchor.saveChecksumPg(26654, 'b')], NEWEST_FIRST);
    expect(db.row).toEqual({ count: 26654, tailHash: 'b' });
    expect(failures(emit)).toHaveLength(0);
    expect(zeroed(gauge)).toBe(false);
    expect(anchor.getBackendStatus().pgStaleWritesRefused).toBe(0);  // the race is removed, not merely relabelled
    expect(monotonic(db.history)).toBe(true);
  });

  test('N03-05 no ordering of concurrent increasing writes can roll the anchor back or raise a failure (5 schedulers × 50 seeds)', async () => {
    for (let seed = 1; seed <= 50; seed++) {
      const rnd = prng(seed);
      for (const [name, pick] of [['newest-first', NEWEST_FIRST], ['oldest-first', OLDEST_FIRST],
        ['random', (n) => Math.floor(rnd() * n)], ['second-newest', (n) => Math.max(0, n - 2)], ['middle', (n) => n >> 1]]) {
        const db = makeDb(); const { anchor, gauge, emit } = load(db);
        const n = 2 + Math.floor(rnd() * 20);
        const base = 1000 + Math.floor(rnd() * 1000);
        const calls = [];
        for (let k = 0; k < n; k++) calls.push(anchor.saveChecksumPg(base + k, `t${base + k}`));
        await drive(db, calls, pick);
        const ctx = `${name} seed ${seed} n ${n}`;
        expect({ ctx, row: db.row }).toEqual({ ctx, row: { count: base + n - 1, tailHash: `t${base + n - 1}` } });
        expect({ ctx, mono: monotonic(db.history) }).toEqual({ ctx, mono: true });
        expect({ ctx, f: failures(emit).length, z: zeroed(gauge) }).toEqual({ ctx, f: 0, z: false });
      }
    }
  });

  test('N03-06 callers out of order (26654 issued before 26653): the newer anchor is kept, the stale one is classified, not reported', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    // oldest-first: 26654 commits, then 26653 reaches the guard (pre-fix: both race; this order is the refusal)
    await drive(db, [anchor.saveChecksumPg(26654, 'b'), anchor.saveChecksumPg(26653, 'a')], OLDEST_FIRST);
    expect(db.row).toEqual({ count: 26654, tailHash: 'b' });
    expect(failures(emit)).toHaveLength(0);
    expect(zeroed(gauge)).toBe(false);
    expect(monotonic(db.history)).toBe(true);
  });

  test('N03-07 at most one anchor write is in flight; a burst of 200 increasing writes coalesces and every caller resolves', async () => {
    const db = makeDb(); const { anchor } = load(db);
    const calls = []; for (let k = 1; k <= 200; k++) calls.push(anchor.saveChecksumPg(k, `t${k}`));
    let maxInFlight = 0;
    await drive(db, calls, (n) => { maxInFlight = Math.max(maxInFlight, n); return 0; });
    expect(maxInFlight).toBe(1);
    expect(db.issued.length).toBeLessThan(200);
    expect(db.issued[db.issued.length - 1]).toBe(200);
    expect(db.row.count).toBe(200);
    expect(anchor.getBackendStatus().pgWritesCoalesced).toBe(200 - db.issued.length);
  });

  // ── Genuine failures keep the existing behaviour: WARN AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED, gauge 0, status false ──

  test('N03-08 a connection failure is still a failure (WARN, gauge 0, lastPgWriteOk false)', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    db.failNext = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:5432'), { code: 'ECONNREFUSED' });
    await drive(db, [anchor.saveChecksumPg(5, 'x')], OLDEST_FIRST);
    expect(failures(emit)).toHaveLength(1);
    expect(gauge.set).toHaveBeenLastCalledWith({}, 0);
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(false);
  });

  test('N03-09 a forward-only refusal against an anchor this process never wrote (another writer / rollback) is a failure', async () => {
    const db = makeDb({ seed: { count: 30000, tailHash: 'other' } }); const { anchor, gauge, emit } = load(db);
    await drive(db, [anchor.saveChecksumPg(26654, 'b')], OLDEST_FIRST);
    expect(db.row).toEqual({ count: 30000, tailHash: 'other' });
    expect(failures(emit)).toHaveLength(1);
    expect(gauge.set).toHaveBeenLastCalledWith({}, 0);
    expect(anchor.getBackendStatus().pgStaleWritesRefused).toBe(0);
  });

  test('N03-10 the same count with a different tail hash (a fork) is a failure, even after this process wrote that count', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await drive(db, [anchor.saveChecksumPg(26654, 'b')], OLDEST_FIRST);
    await drive(db, [anchor.saveChecksumPg(26654, 'FORK')], OLDEST_FIRST);
    expect(db.row).toEqual({ count: 26654, tailHash: 'b' });
    expect(failures(emit)).toHaveLength(1);
    expect(gauge.set).toHaveBeenLastCalledWith({}, 0);
  });

  test('N03-11 any other 42501 (e.g. a revoked grant) is a failure', async () => {
    const db = makeDb(); const { anchor, gauge, emit } = load(db);
    await drive(db, [anchor.saveChecksumPg(10, 'a')], OLDEST_FIRST);
    db.failNext = Object.assign(new Error('permission denied for table audit_checksum_anchor'), { code: '42501' });
    await drive(db, [anchor.saveChecksumPg(9, 'z')], OLDEST_FIRST);
    expect(failures(emit)).toHaveLength(1);
    expect(gauge.set).toHaveBeenLastCalledWith({}, 0);
  });

  test('N03-12 a failure does not stop later writes: the next write is issued and recovers the gauge', async () => {
    const db = makeDb(); const { anchor, gauge } = load(db);
    db.failNext = Object.assign(new Error('Connection terminated unexpectedly'), {});
    await drive(db, [anchor.saveChecksumPg(1, 'a')], OLDEST_FIRST);
    await drive(db, [anchor.saveChecksumPg(2, 'b')], OLDEST_FIRST);
    expect(db.row).toEqual({ count: 2, tailHash: 'b' });
    expect(gauge.set).toHaveBeenLastCalledWith({}, 1);
  });

  test('N03-13 PG disabled: no query, no queue, resolves', async () => {
    const db = makeDb(); const { anchor } = load(db, { pgEnabled: false });
    await expect(anchor.saveChecksumPg(1, 'a')).resolves.toBeUndefined();
    expect(db.query).not.toHaveBeenCalled();
  });
});
