'use strict';

/**
 * R1 / (2026-10-09, adapted;
 * the flag is OPT-IN — QODIQA_TRANSPARENCY_GROUP_COMMIT must be the literal 'true', default OFF):
 * transparency group commit in registrar.register() — unit level, against a fake transaction that models the
 * transparency_log_head row lock, savepoints, commit and rollback. The real-PostgreSQL counterpart is
 *.
 *
 *   GC-U1 registrations that queue behind a held head lock are committed as ONE batch: one lock, one head update,
 *         one transaction, in exact arrival order, each leaf chained on the previous one
 *   GC-U2 byte-identity: the same registrations produce the same entry hashes, previous-hash links and signatures
 *         with group commit ON (concurrent) and OFF (legacy, sequential)
 *   GC-U3 per-entry isolation: one entry's INSERT failure rolls back only its savepoint; that caller gets the original
 *         error, every other caller is persisted, and the chain skips the failed entry
 * GC-U4 head-lock failure: every caller of the batch fails closed with the ORIGINAL error, each gets the
 *         legacy TRANSPARENCY_PREV_HASH_LOOKUP_FAILED + sequence-break signal, nothing is persisted
 *   GC-U5 commit failure: every caller fails closed, nothing is persisted, the head does not move
 *   GC-U6 a signing failure for one entry fails only that entry (fail closed), the rest are persisted
 *   GC-U7 a batch of one issues exactly the legacy statement sequence (no SAVEPOINT)
 *   GC-U8 QODIQA_TRANSPARENCY_GROUP_COMMIT=false restores one transaction per registration (legacy path)
 *   GC-U9 an ON CONFLICT no-op entry is persisted:false, signals a partial append, and does not move the head
 */

const crypto = require('crypto');

function setup({ groupCommit = true } = {}) {
  jest.resetModules();
  if (groupCommit) process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT = 'true';
  else delete process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT;

  const db = { committed: [], head: { tail_hash: null, tail_id: '0' }, nextId: 1, txCount: 0, txLogs: [],
    failLock: null, failCommit: null, failInsertFor: new Map(), conflictFor: new Set(), failSignAtCall: 0, signError: null };
  let lockTail = Promise.resolve();
  const acquire = () => { let rel; const p = new Promise((r) => { rel = r; }); const prev = lockTail; lockTail = prev.then(() => p); return prev.then(() => rel); };
  db.holdLock = acquire;

  jest.doMock('../../../infra/postgres/pool', () => ({
    isEnabled: () => true,
    withTransaction: jest.fn(async (fn) => {
      db.txCount++;
      const tx = { log: [], staged: [], sp: [], headUpd: null, release: null };
      tx.query = async (sql, params) => {
        const s = String(sql).trim();
        tx.log.push(s.replace(/\s+/g, ' ').slice(0, 40));
        if (/FOR UPDATE/.test(s)) { tx.release = await acquire(); if (db.failLock) throw db.failLock; return { rows: [{ ...db.head }] }; }
        if (/^SAVEPOINT/.test(s)) { tx.sp.push({ staged: tx.staged.length, headUpd: tx.headUpd }); return { rows: [] }; }
        if (/^ROLLBACK TO SAVEPOINT/.test(s)) { const top = tx.sp[tx.sp.length - 1]; tx.staged.length = top.staged; tx.headUpd = top.headUpd; return { rows: [] }; }
        if (/^RELEASE SAVEPOINT/.test(s)) { tx.sp.pop(); return { rows: [] }; }
        if (/^UPDATE transparency_log_head/.test(s)) { tx.headUpd = { tail_hash: params[0], tail_id: String(params[1]) }; return { rows: [] }; }
        return { rows: [] };
      };
      db.txLogs.push(tx.log);
      try {
        const r = await fn(tx);
        if (db.failCommit) throw db.failCommit;
        db.committed.push(...tx.staged);
        if (tx.headUpd) db.head = tx.headUpd;
        return r;
      } finally { if (tx.release) tx.release(); }
    }),
  }));
  jest.doMock('../logStore', () => ({
    lockTransparencyLogHead: async (tx) => (await tx.query('SELECT tail_hash, tail_id FROM transparency_log_head FOR UPDATE')).rows[0],
    appendEntry: async (record, { tx }) => {
      await tx.query('INSERT INTO transparency_log_entries');
      if (db.failInsertFor.has(record.transparencyId)) throw db.failInsertFor.get(record.transparencyId);
      if (db.conflictFor.has(record.transparencyId)) return null;
      const row = { id: String(db.nextId++), transparency_id: record.transparencyId, created_at: record.createdAt };
      tx.staged.push({ ...record, id: row.id });
      return row;
    },
    // multi-row INSERT (fast path): one statement — any failing row fails the statement; a conflict row is skipped
    appendEntries: async (records, { tx }) => {
      await tx.query('INSERT MULTI (fast path)');
      db.multiInserts = (db.multiInserts || 0) + 1;
      for (const r of records) if (db.failInsertFor.has(r.transparencyId)) throw db.failInsertFor.get(r.transparencyId);
      const rows = [];
      for (const r of records) {
        if (db.conflictFor.has(r.transparencyId)) continue;
        const row = { id: String(db.nextId++), transparency_id: r.transparencyId, created_at: r.createdAt, entry_hash: r.entryHash };
        tx.staged.push({ ...r, id: row.id });
        rows.push(row);
      }
      return rows.reverse(); // RETURNING order is not guaranteed — the registrar must match by entry_hash
    },
  }));
  jest.doMock('../transparencySigner', () => ({
    getTransparencySigner: () => ({
      getActiveKeyInfo: () => ({ keyId: 'tr-test:key_v1' }),
      sign: async (buf) => {
        const hex = buf.toString('hex');
        db.signCalls = (db.signCalls || 0) + 1;
        if (db.failSignAtCall === db.signCalls) throw db.signError;
        return { signature: crypto.createHash('sha256').update('sig|' + hex).digest('base64'), keyId: 'tr-test:key_v1', keyVersion: 1 };
      },
    }),
  }));
  const gap = { detectSequenceBreak: jest.fn(() => Promise.resolve()), detectPartialAppend: jest.fn(() => Promise.resolve()) };
  jest.doMock('../../transparencyGap', () => gap);
  jest.doMock('../../../infra/postgres/tenantContext', () => ({ setLocal: jest.fn((tx, t) => tx.query('SELECT set_config($1)', [t])), clearLocal: jest.fn((tx) => tx.query('SELECT set_config(clear)')) }));
  jest.doMock('../merkleCheckpoints', () => ({}));
  const emit = jest.fn();
  jest.doMock('../../../../services/logger', () => ({ emit }));
  const registrar = require('../registrar');
  const pool = require('../../../infra/postgres/pool');
  return { registrar, db, gap, emit, pool };
}

afterEach(() => { delete process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT; jest.resetModules(); });

const reg = (i, extra = {}) => ({ entryType: 'AUDIT', artifactId: `a-${i}`, payload: { i }, registeredBy: 'gc-test',
  transparencyId: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, ...extra });
const flush = () => new Promise((r) => setImmediate(r));
const chainOk = (rows, startPrev = null) => {
  let prev = startPrev;
  for (const r of rows) { if (r.previousEntryHash !== prev) return false; prev = r.entryHash; }
  return true;
};

describe('registrar — transparency group commit', () => {
  test('GC-U1 queued registrations commit as one batch, in arrival order, chained, one head update', async () => {
    const { registrar, db } = setup();
    const release = await db.holdLock();
    const first = registrar.register(reg(1));
    await flush();
    const rest = [2, 3, 4, 5, 6].map((i) => registrar.register(reg(i)));
    await flush();
    release();
    const out = await Promise.all([first, ...rest]);
    expect(out.every((o) => o.persisted === true)).toBe(true);
    expect(db.committed.map((r) => r.transparencyId)).toEqual([1, 2, 3, 4, 5, 6].map((i) => reg(i).transparencyId));
    expect(chainOk(db.committed)).toBe(true);
    expect(db.head).toEqual({ tail_hash: db.committed[5].entryHash, tail_id: db.committed[5].id });
    expect(db.txCount).toBe(2);
    const batchLog = db.txLogs[1];
    expect(batchLog.filter((s) => /^SELECT tail_hash, tail_id FROM/.test(s))).toHaveLength(1); // log lines are truncated to 40 chars
    expect(batchLog.filter((s) => /^UPDATE transparency_log_head/.test(s))).toHaveLength(1);
    expect(registrar.groupCommitStats()).toMatchObject({ enabled: true, batches: 2, entries: 6, maxBatch: 5, fastBatches: 1, fastFallbacks: 0 });
    expect(batchLog.filter((s) => /^INSERT MULTI/.test(s))).toHaveLength(1);
    out.forEach((o, i) => { expect(o.entryHash).toBe(db.committed[i].entryHash); expect(o.row.id).toBe(db.committed[i].id); });
  });

  test('GC-U2 entry hashes, previous-hash links and signatures are identical to the legacy path', async () => {
    const ids = [1, 2, 3, 4, 5, 6, 7];
    const a = setup({ groupCommit: true });
    const release = await a.db.holdLock();
    const ps = ids.map((i) => a.registrar.register(reg(i)));
    await flush(); release();
    await Promise.all(ps);
    const grouped = a.db.committed.map((r) => [r.transparencyId, r.previousEntryHash, r.entryHash, r.signature]);

    const b = setup({ groupCommit: false });
    for (const i of ids) await b.registrar.register(reg(i));
    const legacy = b.db.committed.map((r) => [r.transparencyId, r.previousEntryHash, r.entryHash, r.signature]);
    expect(grouped).toEqual(legacy);
    expect(b.db.txCount).toBe(ids.length);
  });

  test('GC-U3 one failing INSERT fails only its own caller; the chain skips it; others persisted', async () => {
    const { registrar, db } = setup();
    const dup = Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505' });
    db.failInsertFor.set(reg(3).transparencyId, dup);
    const release = await db.holdLock();
    const first = registrar.register(reg(1));
    await flush();
    const rest = [2, 3, 4, 5].map((i) => registrar.register(reg(i)).then((v) => ({ v }), (e) => ({ e })));
    await flush(); release();
    await first;
    const res = await Promise.all(rest);
    expect(res[1].e).toBe(dup);
    expect([res[0], res[2], res[3]].every((r) => r.v && r.v.persisted === true)).toBe(true);
    expect(db.committed.map((r) => r.transparencyId)).toEqual([1, 2, 4, 5].map((i) => reg(i).transparencyId));
    expect(chainOk(db.committed)).toBe(true);
    expect(db.head.tail_hash).toBe(db.committed[3].entryHash);
    expect(db.txLogs[1].some((s) => /^ROLLBACK TO SAVEPOINT/.test(s))).toBe(true);
    expect(registrar.groupCommitStats()).toMatchObject({ fastFallbacks: 1, fastBatches: 0 });
  });

  test('GC-U4 head-lock failure fails every caller closed with the original error, with the legacy signals', async () => {
    const { registrar, db, gap, emit } = setup();
    const timeout = Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
    db.failLock = timeout;
    const res = await Promise.all([1, 2, 3].map((i) => registrar.register(reg(i)).then((v) => ({ v }), (e) => ({ e }))));
    for (const r of res) expect(r.e).toBe(timeout);
    expect(db.committed).toEqual([]);
    expect(db.head.tail_hash).toBeNull();
    expect(gap.detectSequenceBreak).toHaveBeenCalledTimes(3);
    expect(emit.mock.calls.filter((c) => c[1] === 'TRANSPARENCY_PREV_HASH_LOOKUP_FAILED')).toHaveLength(3);
  });

  test('GC-U5 commit failure fails every caller closed; nothing persisted; head unchanged', async () => {
    const { registrar, db } = setup();
    const release = await db.holdLock();
    const first = registrar.register(reg(1)).then((v) => ({ v }), (e) => ({ e }));
    await flush();
    const rest = [2, 3, 4].map((i) => registrar.register(reg(i)).then((v) => ({ v }), (e) => ({ e })));
    await flush();
    const lost = Object.assign(new Error('Connection terminated unexpectedly'), { code: '08006' });
    db.failCommit = lost;
    release();
    const res = await Promise.all([first, ...rest]);
    for (const r of res) expect(r.e).toBe(lost);
    expect(db.committed).toEqual([]);
    expect(db.head.tail_hash).toBeNull();
  });

  test('GC-U6 a signing failure fails only that entry; the rest of the batch is persisted and chained', async () => {
    const { registrar, db } = setup();
    // signatures are produced in chain order: call 1 = entry 1 (alone), calls 2..4 = the batch [2, 3, 4]
    db.failSignAtCall = 3;
    db.signError = new Error('transparency signing failed');
    const release = await db.holdLock();
    const first = registrar.register(reg(1));
    await flush();
    const rest = [2, 3, 4].map((i) => registrar.register(reg(i)).then((v) => ({ v }), (e) => ({ e })));
    await flush(); release();
    await first;
    const res = await Promise.all(rest);
    expect(res[1].e).toBe(db.signError);
    expect(res[0].v.persisted).toBe(true);
    expect(res[2].v.persisted).toBe(true);
    expect(db.committed.map((r) => r.transparencyId)).toEqual([1, 2, 4].map((i) => reg(i).transparencyId));
    expect(chainOk(db.committed)).toBe(true);
  });

  test('GC-U7 a batch of one issues exactly the legacy statement sequence (no SAVEPOINT)', async () => {
    const a = setup({ groupCommit: true });
    await a.registrar.register(reg(1, { tenantId: 'tenant-a' }));
    const b = setup({ groupCommit: false });
    await b.registrar.register(reg(1, { tenantId: 'tenant-a' }));
    expect(a.db.txLogs).toEqual(b.db.txLogs);
    expect(a.db.txLogs[0].some((s) => /SAVEPOINT/.test(s))).toBe(false);
  });

  test('GC-U0 default (flag unset) and any non-literal value keep group commit OFF', () => {
    for (const v of [undefined, 'false', 'TRUE', '1', 'yes', ' true']) {
      jest.resetModules();
      if (v === undefined) delete process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT; else process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT = v;
      jest.doMock('../../../infra/postgres/pool', () => ({ isEnabled: () => true }));
      expect(require('../registrar').groupCommitStats().enabled).toBe(false);
    }
  });

  test('GC-U10 batches are bounded by QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH, in order, chained across batches', async () => {
    process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH = '3';
    try {
      const { registrar, db } = setup();
      const release = await db.holdLock();
      const first = registrar.register(reg(1));
      await flush();
      const rest = [2, 3, 4, 5, 6, 7, 8].map((i) => registrar.register(reg(i)));
      await flush(); release();
      await Promise.all([first, ...rest]);
      expect(db.committed.map((r) => r.transparencyId)).toEqual([1, 2, 3, 4, 5, 6, 7, 8].map((i) => reg(i).transparencyId));
      expect(chainOk(db.committed)).toBe(true);
      expect(db.txCount).toBe(4); // [1] [2,3,4] [5,6,7] [8]
      expect(registrar.groupCommitStats()).toMatchObject({ maxBatchEntries: 3, maxBatch: 3, batches: 4, entries: 8 });
    } finally { delete process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT_MAX_BATCH; }
  });

  test('GC-U11 fast path splits the batch into tenant runs (RLS RETURNING visibility); NULL leaves ride any run', async () => {
    const { registrar, db } = setup();
    const release = await db.holdLock();
    const first = registrar.register(reg(1));
    await flush();
    const rest = [registrar.register(reg(2, { tenantId: 'tenant-a' })), registrar.register(reg(3)),
      registrar.register(reg(4, { tenantId: 'tenant-b' })), registrar.register(reg(5))];
    await flush(); release();
    await Promise.all([first, ...rest]);
    const log = db.txLogs[1];
    expect(log.filter((s) => /^INSERT MULTI/.test(s))).toHaveLength(2); // [2,3] [4,5]
    expect(log.filter((s) => /set_config\(\$1/.test(s))).toHaveLength(2);
    expect(db.committed.map((r) => r.transparencyId)).toEqual([1, 2, 3, 4, 5].map((i) => reg(i).transparencyId));
    expect(chainOk(db.committed)).toBe(true);
  });

  test('GC-U11b per-leaf fallback clears a tenant context before a NULL-tenant leaf', async () => {
    const { registrar, db } = setup();
    const dup = Object.assign(new Error('dup'), { code: '23505' });
    db.failInsertFor.set(reg(4).transparencyId, dup); // forces the per-leaf path for this batch
    const release = await db.holdLock();
    const first = registrar.register(reg(1));
    await flush();
    const rest = [registrar.register(reg(2, { tenantId: 'tenant-a' })), registrar.register(reg(3)), registrar.register(reg(4)).catch((e) => e)];
    await flush(); release();
    const out = await Promise.all([first, ...rest]);
    expect(out[3]).toBe(dup);
    const log = db.txLogs[1];
    const lastMulti = log.map((s, i) => (/MULTI/.test(s) ? i : -1)).filter((i) => i >= 0).pop();
    const tail = log.slice(lastMulti + 1);
    const iSet = tail.findIndex((s) => /set_config\(\$1/.test(s));
    const iClear = tail.findIndex((s) => /set_config\(clear/.test(s));
    expect(iSet).toBeGreaterThan(-1);
    expect(iClear).toBeGreaterThan(iSet);
    expect(chainOk(db.committed)).toBe(true);
  });

  test('GC-U12 a caller never resolves before its batch COMMIT returned', async () => {
    const { registrar, db, pool } = setup();
    let committed = false;
    const orig = pool.withTransaction.getMockImplementation();
    pool.withTransaction.mockImplementation(async (fn) => { const r = await orig(fn); committed = true; return r; });
    const seen = [];
    const release = await db.holdLock();
    const first = registrar.register(reg(1)).then(() => seen.push(committed));
    await flush();
    const rest = [2, 3].map((i) => registrar.register(reg(i)).then(() => seen.push(committed)));
    await flush(); release();
    await Promise.all([first, ...rest]);
    expect(seen).toEqual([true, true, true]);
  });

  test('GC-U8 QODIQA_TRANSPARENCY_GROUP_COMMIT unset: one transaction per registration, never a SAVEPOINT', async () => {
    const { registrar, db } = setup({ groupCommit: false });
    const release = await db.holdLock();
    const ps = [1, 2, 3, 4].map((i) => registrar.register(reg(i)));
    await flush(); release();
    await Promise.all(ps);
    expect(db.txCount).toBe(4);
    expect(db.txLogs.flat().some((s) => /SAVEPOINT/.test(s))).toBe(false);
    expect(chainOk(db.committed)).toBe(true);
    expect(registrar.groupCommitStats()).toMatchObject({ enabled: false, batches: 0 });
  });

  test('GC-U9 an ON CONFLICT no-op is persisted:false, signals a partial append, and does not move the head', async () => {
    const { registrar, db, gap } = setup();
    db.conflictFor.add(reg(3).transparencyId);
    const release = await db.holdLock();
    const first = registrar.register(reg(1));
    await flush();
    const rest = [2, 3, 4].map((i) => registrar.register(reg(i)));
    await flush(); release();
    await first;
    const res = await Promise.all(rest);
    expect(res.map((r) => r.persisted)).toEqual([true, false, true]);
    expect(gap.detectPartialAppend).toHaveBeenCalledTimes(1);
    expect(db.committed.map((r) => r.transparencyId)).toEqual([1, 2, 4].map((i) => reg(i).transparencyId));
    expect(chainOk(db.committed)).toBe(true);
    expect(db.head.tail_hash).toBe(db.committed[2].entryHash);
    expect(registrar.groupCommitStats().fastFallbacks).toBe(1); // a conflict invalidates the fast path's chain
  });
});
