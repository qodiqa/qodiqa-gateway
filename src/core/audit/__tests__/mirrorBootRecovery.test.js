'use strict';

/**
 * (owner D7 = B) — boot recovery of a PostgreSQL mirror that is BEHIND the authoritative file chain,
 * before the fail-closed consistency check. Unit level, with an in-memory mirror that enforces the same rules as
 * pg-audit-backend insertMirrorRow (parent must exist or be GENESIS; ON CONFLICT (hash) DO NOTHING).
 * The real-PostgreSQL counterpart is test/integration/mirrorBootRecovery.integration.test.js.
 *
 *   MR-01 disabled: switch off / PG disabled / distributed mode → nothing read, nothing written
 *   MR-02 in sync → no write
 * MR-03 PG behind → exactly the missing entries replayed, in chain order, each with
 *         its evidence step; re-verified tail == file tail
 *   MR-04 idempotent: a second run replays nothing; an entry already present is counted, not re-inserted
 *   MR-05 PG tail not in the file chain (PG ahead / fork / tampering) → NOT repaired, nothing written
 *   MR-06 empty mirror → NOT repaired (operator decision), nothing written
 *   MR-07 PostgreSQL down at boot (tail read fails) → FAILED, nothing written
 *   MR-08 an insert fails mid-replay → FAILED, replay stops at that entry (no later entry written out of order)
 *   MR-09 PG's tail older than the in-memory window → found by the streamed page scan, replayed in order
 *   MR-10 the mirror's tail after replay != file tail → FAILED (never reported as recovered)
 * Redis-independence is proven against real dependencies in the integration test (Redis pointed at a dead port).
 */

const crypto = require('crypto');
const { recoverMirrorBeforeBootCheck, OUTCOME } = require('../mirrorBootRecovery');

function chain(n) {
  const out = []; let prev = 'GENESIS';
  for (let i = 0; i < n; i++) { const hash = crypto.createHash('sha256').update(`e${i}`).digest('hex'); out.push({ hash, prevHash: prev, artifactId: `a${i}`, i }); prev = hash; }
  return out;
}

function rig({ entries, pgCount, windowSize = 1000, pgDown = false, failInsertAt = null, tailOverride = null, pgRows = null } = {}) {
  const pg = pgRows ? pgRows.slice() : entries.slice(0, pgCount).map((e) => e.hash);
  const inserted = []; const evidence = [];
  const has = (h) => pg.includes(h);
  const backend = {
    getChainTail: jest.fn(async () => {
      if (pgDown) throw new Error('connect ECONNREFUSED 127.0.0.1:5432');
      if (tailOverride) return tailOverride;
      return pg.length ? { hash: pg[pg.length - 1], seq: pg.length } : null;
    }),
    insertMirrorRow: jest.fn(async (tx, e) => {
      if (failInsertAt !== null && inserted.length === failInsertAt) throw Object.assign(new Error('Connection terminated'), { code: '08006' });
      if (has(e.hash)) return { inserted: false, alreadyPresent: true };
      if (e.prevHash !== 'GENESIS' && !has(e.prevHash)) throw Object.assign(new Error('AUDIT_MIRROR_PARENT_MISSING'), { code: 'AUDIT_MIRROR_PARENT_MISSING' });
      pg.push(e.hash); inserted.push(e.i);
      return { inserted: true, alreadyPresent: false };
    }),
    recordEvidenceForEntry: jest.fn(async (e) => { evidence.push(e.i); }),
  };
  const n = entries.length;
  const winStart = Math.max(0, n - windowSize);
  const auditLog = {
    ORDERING_MODE: 'single-node',
    WINDOW_SIZE: windowSize,
    memorySnapshot: () => ({ modernCount: n }),
    getAuditTailHash: () => (n ? entries[n - 1].hash : 'GENESIS'),
    getChainStart: () => ({ startCount: 0 }),
    getModernEntryAt: jest.fn(async (p) => (p >= winStart && p < n ? entries[p] : null)),
    forEachModernChainPage: jest.fn(async (onPage) => { for (let i = 0; i < n; i += 7) await onPage(entries.slice(i, i + 7)); return n; }),
  };
  const pool = { isEnabled: () => true, withTransaction: jest.fn(async (fn) => fn({ query: jest.fn() })) };
  const emit = jest.fn();
  const run = (env = { QODIQA_PG_ENABLED: 'true' }) => recoverMirrorBeforeBootCheck({ _env: env, _auditLog: auditLog, _pgAuditBackend: backend, _pgPool: pool, _emit: emit });
  return { pg, inserted, evidence, backend, auditLog, pool, emit, run };
}

describe('mirrorBootRecovery', () => {
  test('MR-01 disabled: switch off, PG disabled, or distributed mode → nothing read or written', async () => {
    const r = rig({ entries: chain(5), pgCount: 3 });
    expect((await r.run({ QODIQA_PG_ENABLED: 'true', QODIQA_AUDIT_MIRROR_BOOT_RECOVERY: 'off' })).outcome).toBe(OUTCOME.DISABLED);
    expect((await r.run({ QODIQA_PG_ENABLED: 'false' })).outcome).toBe(OUTCOME.DISABLED);
    r.auditLog.ORDERING_MODE = 'distributed';
    expect((await r.run()).outcome).toBe(OUTCOME.DISABLED);
    expect(r.backend.getChainTail).not.toHaveBeenCalled();
    expect(r.backend.insertMirrorRow).not.toHaveBeenCalled();
  });

  test('MR-02 in sync → no write', async () => {
    const r = rig({ entries: chain(5), pgCount: 5 });
    const out = await r.run();
    expect(out).toMatchObject({ outcome: OUTCOME.IN_SYNC, replayed: 0 });
    expect(r.backend.insertMirrorRow).not.toHaveBeenCalled();
  });

  test.each([['one entry fsynced, not mirrored', 20, 19], ['an outage backlog', 300, 160]])(
    'MR-03 %s → exactly the missing entries replayed in chain order, with evidence; tail re-verified', async (_label, n, k) => {
      const entries = chain(n);
      const r = rig({ entries, pgCount: k });
      const out = await r.run();
      expect(out).toMatchObject({ outcome: OUTCOME.RECOVERED, replayed: n - k, alreadyPresent: 0, pgTailAfter: entries[n - 1].hash });
      expect(r.inserted).toEqual(entries.slice(k).map((e) => e.i));
      expect(r.evidence).toEqual(entries.slice(k).map((e) => e.i));
      expect(r.pg).toEqual(entries.map((e) => e.hash));
    });

  test('MR-04 idempotent: a second run replays nothing; a row already present is skipped, not re-inserted', async () => {
    const entries = chain(12);
    const r = rig({ entries, pgCount: 8 });
    expect((await r.run()).replayed).toBe(4);
    const second = await r.run();
    expect(second).toMatchObject({ outcome: OUTCOME.IN_SYNC, replayed: 0 });
    expect(r.pg).toEqual(entries.map((e) => e.hash));
    // a concurrent writer (e.g. the recovery-queue worker) already mirrored one of the missing rows
    const r2 = rig({ entries, pgCount: 8 });
    r2.backend.insertMirrorRow.mockImplementationOnce(async () => { r2.pg.push(entries[8].hash); return { inserted: false, alreadyPresent: true }; });
    const out = await r2.run();
    expect(out).toMatchObject({ outcome: OUTCOME.RECOVERED, replayed: 3, alreadyPresent: 1 });
    expect(new Set(r2.pg).size).toBe(r2.pg.length);                    // no duplicate
  });

  test('MR-05 PG tail not in the file chain (PG ahead / fork / tampering) → not repaired, nothing written', async () => {
    const entries = chain(6);
    const foreign = crypto.createHash('sha256').update('foreign').digest('hex');
    const r = rig({ entries, pgRows: [...entries.slice(0, 3).map((e) => e.hash), foreign] });
    const out = await r.run();
    expect(out.outcome).toBe(OUTCOME.NOT_A_PREFIX);
    expect(r.backend.insertMirrorRow).not.toHaveBeenCalled();
    expect(r.emit).toHaveBeenCalledWith('ERROR', 'AUDIT_MIRROR_BOOT_RECOVERY', expect.objectContaining({ outcome: OUTCOME.NOT_A_PREFIX }));
  });

  test('MR-06 empty mirror → not repaired (operator decision), nothing written', async () => {
    const r = rig({ entries: chain(4), pgCount: 0 });
    expect((await r.run()).outcome).toBe(OUTCOME.PG_EMPTY);
    expect(r.backend.insertMirrorRow).not.toHaveBeenCalled();
  });

  test('MR-07 PostgreSQL down at boot → FAILED, nothing written', async () => {
    const r = rig({ entries: chain(4), pgCount: 2, pgDown: true });
    const out = await r.run();
    expect(out).toMatchObject({ outcome: OUTCOME.FAILED, stage: 'read_pg_tail', replayed: 0 });
    expect(r.backend.insertMirrorRow).not.toHaveBeenCalled();
  });

  test('MR-08 an insert fails mid-replay → FAILED; replay stops there, no later entry is written', async () => {
    const entries = chain(10);
    const r = rig({ entries, pgCount: 4, failInsertAt: 2 });
    const out = await r.run();
    expect(out).toMatchObject({ outcome: OUTCOME.FAILED, stage: 'insert', replayed: 2, code: '08006' });
    expect(r.inserted).toEqual([4, 5]);
    expect(r.pg).toEqual(entries.slice(0, 6).map((e) => e.hash));      // still an exact prefix
  });

  test('MR-09 PG tail older than the in-memory window → streamed page scan, replayed in order', async () => {
    const entries = chain(50);
    const r = rig({ entries, pgCount: 10, windowSize: 20 });
    const out = await r.run();
    expect(out).toMatchObject({ outcome: OUTCOME.RECOVERED, replayed: 40 });
    expect(r.auditLog.forEachModernChainPage).toHaveBeenCalled();
    expect(r.pg).toEqual(entries.map((e) => e.hash));
  });

  test('MR-10 the tail after replay != file tail → FAILED, never "recovered"', async () => {
    const entries = chain(6);
    const r = rig({ entries, pgCount: 3 });
    let calls = 0;
    r.backend.getChainTail.mockImplementation(async () => (++calls === 1 ? { hash: entries[2].hash, seq: 3 } : { hash: entries[4].hash, seq: 5 }));
    const out = await r.run();
    expect(out).toMatchObject({ outcome: OUTCOME.FAILED, stage: 'reverify_pg_tail' });
  });
});
