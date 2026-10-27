'use strict';

/**
 * WAL crash-replay — Tests (CHAIN-7 remediation).
 *
 * audit-log.js's append() is write-ahead-logged for crash safety
 * (audit-log.js:583-596): write WAL -> append LOG -> fsync -> update checksum
 * -> delete WAL. If the process dies between "write WAL" and "delete WAL",
 * the next startup's loadFromDisk() IIFE (audit-log.js:229-253) replays the
 * WAL entry into the log before validating the chain. That logic was
 * previously unexercised by any automated test (CHAIN-7) — this suite
 * simulates a real interrupted write (not a reimplementation of the replay
 * logic) by making the LOG_PATH commit step of a real append() call fail
 * *after* its WAL write has already landed on disk, then re-requiring the
 * real module fresh (a genuine process-restart-equivalent) to exercise the
 * actual replay branch.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');

function tmpAuditLogPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-wal-replay-'));
  return path.join(dir, 'audit.log');
}

function entryFields(overrides = {}) {
  return {
    artifactId: crypto.randomUUID(),
    inputHash: 'a'.repeat(64),
    decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature: 's'.repeat(64),
    requestHash: 'r'.repeat(64),
    policyHash: 'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

describe('WAL crash-replay (CHAIN-7)', () => {
  let prevAuditLogEnv;
  let logPath;
  let walPath;

  beforeEach(async () => {
    prevAuditLogEnv = process.env.QODIQA_AUDIT_LOG;
    logPath = tmpAuditLogPath();
    walPath = logPath + '.wal';
    process.env.QODIQA_AUDIT_LOG = logPath;
    jest.resetModules();
  });

  afterEach(async () => {
    jest.restoreAllMocks();
    if (prevAuditLogEnv === undefined) delete process.env.QODIQA_AUDIT_LOG;
    else process.env.QODIQA_AUDIT_LOG = prevAuditLogEnv;
    jest.resetModules();
  });

  test('an entry left in the WAL by a simulated crash is replayed into the log on the next module load, and the chain validates', async () => {
    // 1. Real startup, real first append — establishes a genuine committed
    //    entry #1 (chain must not be empty for this to be a meaningful test
    //    of hash-chain continuation across the crash).
    const auditLog1 = require('../audit-log.js');
    const entry1 = await auditLog1.append(entryFields());
    expect(auditLog1.getChainLength()).toBe(1);
    // S33 approved on-disk contract: the WAL is absent OR EMPTY while the writer runs (with WAL
    // reuse, one empty — i.e. invalidated — WAL file is kept between batches); absent after recovery and a clean stop.
    expect(!fs.existsSync(walPath) || fs.statSync(walPath).size === 0).toBe(true);

    // 2. Simulate a crash: the WAL write for entry #2 completes (real disk
    //    write, real hash/prevHash chaining against entry #1's real tail
    //    hash), but the subsequent LOG_PATH commit never happens — exactly
    //    "process dies between WAL write and log commit". This uses the
    //    REAL append() code path (audit-log.js:583-596), only interrupting
    //    it at the point a real crash would.
    // a real crash never ANSWERS the caller, so the log append is made to hang (the process is frozen there)
    // rather than reject — a REJECTED append is a failed batch (crash point B') whose WAL is invalidated and must
    // never be replayed (see the B' tests below).
    const appendFileSpy = jest.spyOn(fs.promises, 'appendFile')
      .mockImplementationOnce(() => new Promise(() => {}));

    const fields2 = entryFields();
    let settled = false;
    auditLog1.append(fields2).then(() => { settled = true; }, () => { settled = true; });
    // wait for entry #2's WAL write to land (S33: the reused WAL already exists, empty, so "exists" alone no longer
    // means "written" — wait for it to be non-empty)
    for (let i = 0; i < 50 && !(fs.existsSync(walPath) && fs.statSync(walPath).size > 0); i++) await new Promise((res) => setTimeout(res, 10));
    await new Promise((res) => setTimeout(res, 20));
    expect(settled).toBe(false); // the caller was never answered
    appendFileSpy.mockRestore();

    // Sanity-check the interrupted state actually looks like a real crash:
    // WAL present with the uncommitted entry, LOG_PATH still only has entry #1.
    expect(fs.existsSync(walPath)).toBe(true);
    const walEntry = JSON.parse(fs.readFileSync(walPath, 'utf8').trim());
    expect(walEntry.artifactId).toBe(fields2.artifactId);
    expect(walEntry.prevHash).toBe(entry1.hash);
    const committedLinesBeforeRestart = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    expect(committedLinesBeforeRestart).toHaveLength(1);

    // 3. Simulate a process restart: fresh require() of the real module runs
    //    loadFromDisk()'s WAL-recovery branch (audit-log.js:229-253) for real.
    jest.resetModules();
    const auditLog2 = require('../audit-log.js');

    // The WAL entry must have been replayed into the committed log and the
    // WAL file cleared — the actual replay code path, not a re-derivation.
    expect(fs.existsSync(walPath)).toBe(false);
    expect(auditLog2.getChainLength()).toBe(2);

    const replayed = await auditLog2.getArtifactById(fields2.artifactId);
    expect(replayed).toBeDefined();
    expect(replayed.hash).toBe(walEntry.hash);
    expect(replayed.prevHash).toBe(entry1.hash);

    // The recovered chain must pass full integrity verification — proving
    // the replayed entry is not just present but correctly hash-linked.
    const integrity = auditLog2.validateChainIntegrity();
    expect(integrity.chainValid).toBe(true);
    expect(integrity.tamperingDetected).toBe(false);

    // A third, ordinary append after recovery must continue the chain
    // correctly from the replayed entry's hash (proves the in-memory tail
    // state after replay is genuinely usable, not just disk-consistent).
    const entry3 = await auditLog2.append(entryFields());
    expect(entry3.prevHash).toBe(walEntry.hash);
    expect(auditLog2.getChainLength()).toBe(3);
  });

  test('a WAL entry that was ALREADY committed before the crash (crash happened after log write but before WAL delete) is not double-appended', async () => {
    const auditLog1 = require('../audit-log.js');
    const entry1 = await auditLog1.append(entryFields());
    expect(auditLog1.getChainLength()).toBe(1);

    // Simulate the narrower crash window: WAL write done, LOG_PATH append
    // done and fsynced, but the process died before unlinking the WAL file.
    // Construct this directly (rather than mocking fs.promises.unlink to
    // fail mid real append(), which would also be valid but this is the
    // more direct way to pin the exact on-disk state under test) — the WAL
    // file's content for this scenario is simply "the entry that's already
    // the log's tail".
    fs.writeFileSync(walPath, JSON.stringify(entry1) + '\n', 'utf8');

    jest.resetModules();
    const auditLog2 = require('../audit-log.js');

    // Must NOT be double-appended — chain length stays 1, WAL still cleared.
    expect(fs.existsSync(walPath)).toBe(false);
    expect(auditLog2.getChainLength()).toBe(1);
    const integrity = auditLog2.validateChainIntegrity();
    expect(integrity.chainValid).toBe(true);
  });

  // ── group commit ──────────
  const buildNext = (prevHash, overrides) => {
    const eb = require('../entryBuilder');
    return eb.buildEntry(eb.normalizeFields(entryFields(overrides)), prevHash);
  };
  const quarantined = () => (fs.existsSync(logPath + '.quarantine') ? fs.readdirSync(logPath + '.quarantine') : []);
  const artifactCount = (id) => fs.readFileSync(logPath, 'utf8').split('\n').filter((l) => l.includes(id)).length;

  test("B': a batch that fails after its WAL (log append rejects) is invalidated, never replayed; its retry commits once", async () => {
    const auditLog1 = require('../audit-log.js');
    await auditLog1.append(entryFields());
    const spy = jest.spyOn(fs.promises, 'appendFile').mockImplementationOnce(() => Promise.reject(Object.assign(new Error('EIO: injected'), { code: 'EIO' })));
    const fields2 = entryFields();
    await expect(auditLog1.append(fields2)).rejects.toThrow('EIO: injected');
    spy.mockRestore();
    // invalidated BEFORE the caller got the error: the WAL is empty (or gone)
    expect(!fs.existsSync(walPath) || fs.readFileSync(walPath, 'utf8') === '').toBe(true);
    jest.resetModules();
    const auditLog2 = require('../audit-log.js');
    expect(auditLog2.getChainLength()).toBe(1);                  // not replayed
    expect(auditLog2.getStorageReport().recovery.walReplayed).toBe(0);
    await auditLog2.append(fields2);                              // the caller's retry
    expect(artifactCount(fields2.artifactId)).toBe(1);            // exactly once
    expect(auditLog2.validateChainIntegrity().chainValid).toBe(true);
  });

  test("B': part of the batch reached the log before the failure → those bytes are quarantined and removed", async () => {
    const auditLog1 = require('../audit-log.js');
    await auditLog1.append(entryFields());
    const sizeBefore = fs.statSync(logPath).size;
    const realAppend = fs.promises.appendFile;
    const spy = jest.spyOn(fs.promises, 'appendFile').mockImplementationOnce(async (p, data) => {
      await realAppend(p, String(data).slice(0, 40), 'utf8');       // a partial write lands…
      throw Object.assign(new Error('ENOSPC: injected'), { code: 'ENOSPC' }); // …then the write fails
    });
    const fields2 = entryFields();
    await expect(auditLog1.append(fields2)).rejects.toThrow('ENOSPC: injected');
    spy.mockRestore();
    expect(fs.statSync(logPath).size).toBe(sizeBefore);            // restored to the pre-batch length
    expect(quarantined().some((q) => q.includes('failed-batch-log-tail'))).toBe(true);
    jest.resetModules();
    const auditLog2 = require('../audit-log.js');
    expect(auditLog2.getChainLength()).toBe(1);
    expect(artifactCount(fields2.artifactId)).toBe(0);
    expect(auditLog2.validateChainIntegrity().chainValid).toBe(true);
  });

  test('C: a torn last log line that is a prefix of the next WAL entry is quarantined, repaired and reported', async () => {
    const auditLog1 = require('../audit-log.js');
    const e1 = await auditLog1.append(entryFields());
    const e2 = buildNext(e1.hash);
    const line2 = JSON.stringify(e2) + '\n';
    fs.writeFileSync(walPath, line2, 'utf8');
    fs.appendFileSync(logPath, line2.slice(0, 57), 'utf8');         // the crash cut the log line
    jest.resetModules();
    const auditLog2 = require('../audit-log.js');
    expect(auditLog2.getChainLength()).toBe(2);
    const rep = auditLog2.getStorageReport().recovery;
    expect(rep.tornTailRepaired).toMatchObject({ bytes: 57, walEntryHash: e2.hash });
    expect(quarantined().some((q) => q.includes('torn-log-tail'))).toBe(true);
    expect(auditLog2.validateChainIntegrity().chainValid).toBe(true);
  });

  test('C: a torn last log line that is NOT a prefix of the WAL entry fails boot closed', async () => {
    const auditLog1 = require('../audit-log.js');
    const e1 = await auditLog1.append(entryFields());
    fs.writeFileSync(walPath, JSON.stringify(buildNext(e1.hash)) + '\n', 'utf8');
    fs.appendFileSync(logPath, '{"tampered":', 'utf8');
    jest.resetModules();
    expect(() => require('../audit-log.js')).toThrow(/AUDIT_INTEGRITY_VIOLATION/);
  });

  test('A: a torn WAL (no final newline) is discarded and quarantined; the log is unchanged', async () => {
    const auditLog1 = require('../audit-log.js');
    const e1 = await auditLog1.append(entryFields());
    const logBefore = fs.readFileSync(logPath, 'utf8');
    fs.writeFileSync(walPath, JSON.stringify(buildNext(e1.hash)).slice(0, 80), 'utf8');
    jest.resetModules();
    const auditLog2 = require('../audit-log.js');
    expect(fs.readFileSync(logPath, 'utf8')).toBe(logBefore);
    expect(auditLog2.getChainLength()).toBe(1);
    expect(auditLog2.getStorageReport().recovery.walTornDiscarded).toBe(true);
    expect(quarantined().some((q) => q.includes('torn-wal'))).toBe(true);
  });

  test('B/D: a multi-entry WAL batch whose first entries already reached the log replays only the rest', async () => {
    const auditLog1 = require('../audit-log.js');
    const e1 = await auditLog1.append(entryFields());
    const e2 = buildNext(e1.hash); const e3 = buildNext(e2.hash); const e4 = buildNext(e3.hash);
    fs.writeFileSync(walPath, [e2, e3, e4].map((e) => JSON.stringify(e) + '\n').join(''), 'utf8');
    fs.appendFileSync(logPath, JSON.stringify(e2) + '\n', 'utf8');   // the first entry of the batch had landed
    jest.resetModules();
    const auditLog2 = require('../audit-log.js');
    expect(auditLog2.getChainLength()).toBe(4);
    expect(auditLog2.getStorageReport().recovery).toMatchObject({ walEntries: 3, walAlreadyCommitted: 1, walReplayed: 2 });
    expect(artifactCount(e2.artifactId)).toBe(1);
    expect(auditLog2.validateChainIntegrity().chainValid).toBe(true);
  });

  test('a WAL batch that does not continue the log fails boot closed', async () => {
    const auditLog1 = require('../audit-log.js');
    await auditLog1.append(entryFields());
    fs.writeFileSync(walPath, JSON.stringify(buildNext('f'.repeat(64))) + '\n', 'utf8');
    jest.resetModules();
    expect(() => require('../audit-log.js')).toThrow(/AUDIT_INTEGRITY_VIOLATION/);
  });

  test('QODIQA_AUDIT_GROUP_COMMIT=false (rollback switch) keeps the per-entry path and says so', async () => {
    const saved = process.env.QODIQA_AUDIT_GROUP_COMMIT;
    process.env.QODIQA_AUDIT_GROUP_COMMIT = 'false';
    try {
      jest.resetModules();
      const auditLog1 = require('../audit-log.js');
      expect(auditLog1.getStorageReport().groupCommit).toBe(false);
      await auditLog1.append(entryFields());
      await auditLog1.append(entryFields());
      expect(auditLog1.groupCommitStats().batches).toBe(0);
      expect(auditLog1.validateChainIntegrity().chainValid).toBe(true);
    } finally {
      if (saved === undefined) delete process.env.QODIQA_AUDIT_GROUP_COMMIT; else process.env.QODIQA_AUDIT_GROUP_COMMIT = saved;
    }
  });

  test('concurrent appends are committed in batches, in FIFO order, each chained on the previous', async () => {
    const auditLog1 = require('../audit-log.js');
    const fields = Array.from({ length: 40 }, () => entryFields());
    const entries = await Promise.all(fields.map((f) => auditLog1.append(f)));
    for (let i = 1; i < entries.length; i++) expect(entries[i].prevHash).toBe(entries[i - 1].hash);
    expect(entries.map((e) => e.artifactId)).toEqual(fields.map((f) => f.artifactId));
    const st = auditLog1.groupCommitStats();
    expect(st.entries).toBe(40);
    expect(st.batches).toBeLessThan(40);                          // batched
    expect(auditLog1.validateChainIntegrity().chainValid).toBe(true);
  });

  test('a duplicate inside the same batch is rejected, the rest of the batch commits', async () => {
    const auditLog1 = require('../audit-log.js');
    const f = entryFields();
    const [a, b, c] = await Promise.allSettled([auditLog1.append(f), auditLog1.append({ ...f }), auditLog1.append(entryFields())]);
    expect(a.status).toBe('fulfilled');
    expect(b.status).toBe('rejected');
    expect(String(b.reason.message)).toMatch(/already_executed/);
    expect(c.status).toBe('fulfilled');
    expect(c.value.prevHash).toBe(a.value.hash);
  });
});
