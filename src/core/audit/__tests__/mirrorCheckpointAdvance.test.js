'use strict';

/**
 * — runtime advancement of the startup mirror checkpoint
 * (mirrorConsistencyCheck.advanceMirrorCheckpoint). Invariants I-1..I-10:
 *
 *
 * 12,000 valid chained entries (production entryBuilder) in an in-memory "file" and an in-memory audit_chain (seq =
 * position + 1); signed checkpoints every 1,000 entries with a confirmed pgSeq; boot-written mirror checkpoint at 1,000;
 * pages of 5,000, so ranges cross page boundaries.
 *
 *   AV-1  consistent → advances in bounded runs to the newest signed checkpoint, rows tagged runtime-mirror-advance;
 *         the next boot's fast path then verifies only the remainder (I-1, I-2, I-10)
 *   AV-2  a PG row's canonical changed inside the range → refused, nothing written, ERROR; the boot still sees the range
 *         and its fast path rejects it (I-4)
 *   AV-3  a FILE entry's canonical changed without re-hashing → refused (FILE_RANGE_INVALID)
 *   AV-4  the same artifactId on both sides of a page boundary (validly re-hashed on both stores) → refused
 *   AV-5  latest checkpoint inconsistent (hash wrong in PG / beyond the file / hash wrong in the file) → nothing written,
 *         ERROR, advancement stays stopped for the process even after the data looks fine again (I-3)
 *   AV-6  a PG row deleted from the PREFIX (before the checkpoint) → the range count check refuses (PG_COUNT_MISMATCH)
 *   AV-7  no checkpoint at all → verified from GENESIS, bounded (recovery: missing)
 *   AV-8  target signature FALSE → refused; key unavailable → proceeds, recorded as 'unverifiable' (T5)
 *   AV-9  target row missing / different in PG → refused, nothing written
 *   AV-10 benign states write nothing: disabled, distributed, PG off, rebased chain, lock held, no target (I-5, I-8, I-9)
 *   AV-11 backlog larger than one run → WARN AUDIT_MIRROR_CHECKPOINT_BACKLOG, each run bounded (recovery: stale)
 */

const crypto = require('crypto');
const auditLog = require('../audit-log');
const eb = require('../entryBuilder');
const mc = require('../mirrorConsistencyCheck');

const N = 12_000;
const CP = 1_000;
const EVERY = 1_000;

function buildChain({ duplicateAt = null } = {}) {
  const entries = []; let prev = 'GENESIS'; let dupId = null;
  for (let i = 0; i < N; i++) {
    let artifactId = crypto.randomUUID();
    if (duplicateAt && i === duplicateAt[0]) dupId = artifactId;
    if (duplicateAt && i === duplicateAt[1]) artifactId = dupId;
    const e = eb.buildEntry(eb.normalizeFields({ artifactId, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: eb.EMPTY_OUTPUT_HASH,
      signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't' }), prev);
    entries.push(e); prev = e.hash;
  }
  return entries;
}

function world(fileEntries, pgRows, { checkpoint = 'boot', signed = null, start = { startCount: 0 }, lock = true } = {}) {
  const checkpoints = [];
  if (checkpoint === 'boot') checkpoints.push({ chainLength: CP, hash: fileEntries[CP - 1].hash, seq: CP, createdBy: 'startup-mirror-check' });
  else if (checkpoint) checkpoints.push(checkpoint);
  const signedList = signed || [];
  if (!signed) for (let n = EVERY; n <= fileEntries.length; n += EVERY) signedList.push({ payload: { checkpointId: `cp-${n}`, chainLength: n, headHash: fileEntries[n - 1].hash, pgSeq: n } });
  const events = [];
  const _auditLog = {
    ORDERING_MODE: 'single-node',
    createChainWalker: auditLog.createChainWalker,
    getChainStats: () => ({ modernLength: fileEntries.length }),
    getChainStart: () => start,
    async getModernEntryAt(pos) { return fileEntries[pos] || null; },
    async getModernChainSlice(from) { return fileEntries.slice(from); },
    locateModernCursor(pos) { return pos >= 0 && pos < fileEntries.length ? { m: pos, o: pos } : null; },
    async getModernChainPage({ cursor, limit }) {
      const from = cursor && Number.isInteger(cursor.m) ? cursor.m : 0;
      const entries = fileEntries.slice(from, from + limit);
      const next = from + entries.length;
      return { entries, startPos: from, nextCursor: next < fileEntries.length ? { m: next, o: next } : null };
    },
  };
  const _pgAuditBackend = {
    async getLatestAuditCheckpoint() { return checkpoints.reduce((m, c) => (!m || c.chainLength > m.chainLength ? c : m), null); },
    async insertAuditCheckpoint(c) { if (!checkpoints.some((x) => x.chainLength === c.chainLength)) checkpoints.push(c); },
    async fetchRowBySeq(seq) { const r = pgRows.find((x) => x.seq === seq); return r ? r.hash : null; },
    async fetchChainBatch(from, n) { const i = pgRows.findIndex((x) => x.seq > from); return i < 0 ? [] : pgRows.slice(i, i + n); },
    async countChainRows() { return pgRows.length; },
    async countChainRowsThroughSeq(seq) { return pgRows.filter((r) => r.seq <= seq).length; },
    async findSignedCheckpointForAdvance(after, max) {
      const c = signedList.filter((s) => s.payload.chainLength > after && s.payload.chainLength <= max && Number.isInteger(s.payload.pgSeq));
      return c.length ? c[c.length - 1] : null;
    },
  };
  const _pgPool = { isEnabled: () => true, withTransaction: async (fn) => fn({ query: async () => ({ rows: [{ acquired: lock }] }) }) };
  const _emit = (level, event, data) => events.push({ level, event, data });
  const run = (o = {}) => mc.advanceMirrorCheckpoint({ _env: {}, _pgPool, _pgAuditBackend, _auditLog, _emit, maxEntries: 5000, ...o });
  const boot = () => mc._checkpointFastPath({ _auditLog, _pgAuditBackend, fileCount: fileEntries.length, start: null });
  return { run, boot, checkpoints, events, _pgAuditBackend };
}
const asRows = (entries) => entries.map((e, i) => ({ ...e, seq: i + 1 }));
const written = (w) => w.checkpoints.filter((c) => c.createdBy === 'runtime-mirror-advance');

beforeEach(() => mc._resetAdvanceStateForTests());

describe('runtime mirror-checkpoint advancement', () => {
  const base = buildChain();

  test('AV-1 consistent: bounded runs reach the newest signed checkpoint; the boot then checks only the remainder', async () => {
    const w = world(base, asRows(base));
    const r1 = await w.run();
    expect(r1).toMatchObject({ advanced: true, from: CP, to: 6000, entries: 5000, toSeq: 6000, startLocate: 'newline' });
    const r2 = await w.run();
    expect(r2).toMatchObject({ advanced: true, from: 6000, to: 11000, startLocate: 'hint' });
    const r3 = await w.run();
    expect(r3).toMatchObject({ advanced: true, from: 11000, to: 12000, entries: 1000 });
    expect(await w.run()).toMatchObject({ skipped: true, reason: 'NOTHING_TO_VERIFY' });
    expect(written(w).map((c) => c.chainLength)).toEqual([6000, 11000, 12000]);
    expect(written(w).every((c) => c.hash === base[c.chainLength - 1].hash && c.seq === c.chainLength)).toBe(true);
    expect(w.events.filter((e) => e.event === 'AUDIT_MIRROR_CHECKPOINT_ADVANCED')).toHaveLength(3);
    const boot = await w.boot();
    expect(boot).toMatchObject({ ok: true, checkpointLength: 12000, suffixChecked: 0 });
  });

  test('AV-2 a tampered PG row inside the range → refused, nothing written; the boot still rejects the range', async () => {
    const rows = asRows(base);
    rows[3000] = { ...rows[3000], canonical: rows[3000].canonical.replace('"ALLOW"', '"BLOCK"') };
    const w = world(base, rows);
    const r = await w.run();
    expect(r).toMatchObject({ advanced: false, refused: true });
    expect(['PG_RANGE_INVALID', 'RANGE_DIVERGENCE']).toContain(r.reason);
    expect(written(w)).toHaveLength(0);
    expect(w.events.find((e) => e.event === 'AUDIT_MIRROR_CHECKPOINT_ADVANCE_REFUSED').level).toBe('ERROR');
    expect((await w.boot()).ok).toBe(false);   // the range stays in the boot's fail-closed check
  });

  test('AV-3 a FILE entry changed without re-hashing → refused (FILE_RANGE_INVALID)', async () => {
    const file = base.slice();
    file[4321] = { ...file[4321], canonical: file[4321].canonical.replace('"ALLOW"', '"BLOCK"') };
    const w = world(file, asRows(base));
    const r = await w.run();
    expect(r).toMatchObject({ refused: true, reason: 'FILE_RANGE_INVALID' });
    expect(written(w)).toHaveLength(0);
  });

  test('AV-4 the same artifactId across a page boundary (validly re-hashed on both stores) → refused', async () => {
    const dup = buildChain({ duplicateAt: [CP + 4998, CP + 5002] });
    const w = world(dup, asRows(dup));
    const r1 = await w.run({ maxEntries: 10_000 });
    expect(r1).toMatchObject({ refused: true });
    expect(['PG_RANGE_INVALID', 'FILE_RANGE_INVALID']).toContain(r1.reason);
    expect(r1.detail).toBe('AUDIT_DUPLICATE_ENTRY');
    expect(written(w)).toHaveLength(0);
  });

  test('AV-5 an inconsistent latest checkpoint is never superseded, and advancement stays stopped', async () => {
    const wrongPg = world(base, asRows(base), { checkpoint: { chainLength: CP, hash: 'e'.repeat(64), seq: CP, createdBy: 'startup-mirror-check' } });
    expect(await wrongPg.run()).toMatchObject({ inconsistent: true, reason: 'PG_CHECKPOINT_HASH_MISMATCH' });
    expect(written(wrongPg)).toHaveLength(0);
    // sticky: a perfectly consistent world in the same process is still not advanced
    const fine = world(base, asRows(base));
    expect(await fine.run()).toMatchObject({ skipped: true, reason: 'STOPPED_INCONSISTENT' });
    expect(written(fine)).toHaveLength(0);
    expect(fine.events.some((e) => e.event === 'AUDIT_MIRROR_CHECKPOINT_INCONSISTENT' && e.level === 'ERROR')).toBe(true);

    mc._resetAdvanceStateForTests();
    const beyond = world(base, asRows(base), { checkpoint: { chainLength: N + 5, hash: base[N - 1].hash, seq: N, createdBy: 'x' } });
    expect(await beyond.run()).toMatchObject({ inconsistent: true, reason: 'CHECKPOINT_BEYOND_FILE' });

    mc._resetAdvanceStateForTests();
    const file = base.slice(); file[CP - 1] = { ...file[CP - 1], hash: 'd'.repeat(64) };
    const wrongFile = world(file, asRows(base), { checkpoint: { chainLength: CP, hash: base[CP - 1].hash, seq: CP, createdBy: 'startup-mirror-check' } });
    expect(await wrongFile.run()).toMatchObject({ inconsistent: true, reason: 'FILE_CHECKPOINT_HASH_MISMATCH' });
    expect(written(wrongFile)).toHaveLength(0);
  });

  test('AV-6 a PG row deleted from the prefix is caught by the range count check', async () => {
    const rows = asRows(base).filter((r) => r.seq !== 500);
    const w = world(base, rows);
    expect(await w.run()).toMatchObject({ refused: true, reason: 'PG_COUNT_MISMATCH', pgRowsThroughSeq: 5999 });
    expect(written(w)).toHaveLength(0);
  });

  test('AV-7 no checkpoint: verified from GENESIS in bounded runs', async () => {
    const w = world(base, asRows(base), { checkpoint: null });
    expect(await w.run()).toMatchObject({ advanced: true, from: 0, to: 5000, startLocate: 'genesis' });
    expect(await w.run()).toMatchObject({ advanced: true, from: 5000, to: 10000 });
    expect((await w.boot())).toMatchObject({ ok: true, checkpointLength: 10000, suffixChecked: 2000 });
  });

  test('AV-8 target signature: FALSE refuses, key unavailable proceeds as unverifiable', async () => {
    const w = world(base, asRows(base));
    expect(await w.run({ _checkpointVerify: () => ({ ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' }) }))
      .toMatchObject({ refused: true, reason: 'TARGET_SIGNATURE_INVALID' });
    expect(written(w)).toHaveLength(0);
    expect(await w.run({ _checkpointVerify: () => ({ ok: false, reason: 'CHECKPOINT_KEY_UNAVAILABLE: kid' }) }))
      .toMatchObject({ advanced: true, signatureChecked: 'unverifiable' });
    expect(await w.run({ _checkpointVerify: () => ({ ok: true }) })).toMatchObject({ advanced: true, signatureChecked: 'valid' });
  });

  test('AV-9 target row missing or different in PG → refused', async () => {
    const w = world(base, asRows(base).filter((r) => r.seq !== 6000));
    expect(await w.run()).toMatchObject({ refused: true, reason: 'TARGET_PG_HASH_MISMATCH' });
    expect(written(w)).toHaveLength(0);
    mc._resetAdvanceStateForTests();
    const signed = [{ payload: { checkpointId: 'x', chainLength: 6000, headHash: 'c'.repeat(64), pgSeq: 6000 } }];
    const w2 = world(base, asRows(base), { signed });
    expect(await w2.run()).toMatchObject({ refused: true, reason: 'TARGET_PG_HASH_MISMATCH' });
  });

  test('AV-10 benign states write nothing', async () => {
    const w = world(base, asRows(base));
    expect(await w.run({ _env: { QODIQA_AUDIT_MIRROR_CHECKPOINT_ADVANCE: 'false' } })).toMatchObject({ skipped: true, reason: 'DISABLED' });
    expect(await w.run({ _env: { QODIQA_AUDIT_ORDERING_MODE: 'distributed' } })).toMatchObject({ skipped: true, reason: 'DISTRIBUTED_MODE' });
    expect(await w.run({ _pgPool: { isEnabled: () => false } })).toMatchObject({ skipped: true, reason: 'PG_DISABLED' });
    expect(await world(base, asRows(base), { start: { startCount: 500 } }).run()).toMatchObject({ skipped: true, reason: 'REBASED_CHAIN' });
    expect(await world(base, asRows(base), { lock: false }).run()).toMatchObject({ skipped: true, reason: 'LOCK_NOT_ACQUIRED' });
    expect(await world(base, asRows(base), { signed: [] }).run()).toMatchObject({ skipped: true, reason: 'NO_TARGET' });
    expect(written(w)).toHaveLength(0);
  });

  test('AV-11 a backlog larger than one run is reported and consumed in bounded runs', async () => {
    const w = world(base, asRows(base));
    const r = await w.run({ maxEntries: 2000 });
    expect(r).toMatchObject({ advanced: true, from: CP, to: 3000, entries: 2000, backlog: N - 3000 });
    expect(w.events.some((e) => e.event === 'AUDIT_MIRROR_CHECKPOINT_BACKLOG' && e.level === 'WARN')).toBe(true);
  });
});
