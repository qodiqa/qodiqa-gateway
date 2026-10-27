'use strict';

/**
 * Startup Audit-Chain / PostgreSQL Mirror Consistency Check
 *
 * MC-01  Distributed mode short-circuits: no PG/audit-log calls, no exit
 * MC-02  Single-node mode, PG disabled: skipped, INFO emitted, no exit
 * MC-03  Valid matching chain: passes, INFO emitted, no exit
 * MC-04  Truncated local file (file behind PG): FATAL + exit(1)
 * MC-05  Deleted tail entries (file shorter, tail differs): FATAL + exit(1)
 * MC-06  Replaced chain tail (same count, tail hash differs): FATAL + exit(1)
 * MC-07  Mismatched chain hash / divergent lineage (head differs): FATAL + exit(1)
 * MC-08  Mismatched sequence number (PG ahead of file): FATAL + exit(1), multiple mismatch fields
 * MC-09  Corrupted terminal record in PG mirror (PG's own walk invalid): FATAL + exit(1)
 * MC-10  Empty chain handling: both sides empty passes cleanly
 * MC-11  PostgreSQL unavailable during verification: FATAL + exit(1)
 * MC-12  Regression: mismatch never emits the success INFO record
 * MC-13  Successful startup after consistency is restored (fail then pass)
 * MC-14  FATAL records are written directly to stderr, bypassing injected emit
 * MC-15  Regression: skip paths (distributed / PG disabled) never call _exit
 *
 * remediation — _reorderByHashChain (RB-01..07): the PG-side internal
 * chain-validity re-check (MC-09 above) walks loadChainFromPg()'s seq-ordered
 * rows positionally, the same seq-vs-logical-order assumption
 * crossValidateRecords() used to make (see CV-08 above) — RB-01..07 cover
 * the reorder helper that now runs before that walk.
 */

const { verifyMirrorConsistency } = require('../mirrorConsistencyCheck');

// ── Helpers ───────────────────────────────────────────────────────────────────

function capturedStderr(fn) {
  const chunks = [];
  const orig = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk) => { chunks.push(chunk); return true; };
  return fn().finally(() => { process.stderr.write = orig; }).then((result) => ({
    result,
    stderr: chunks.join(''),
  }));
}

function fakeChainStats({ modernLength, headHash, tailHash }) {
  return { chainLength: modernLength, modernLength, headHash, tailHash };
}

describe('mirrorConsistencyCheck', () => {

  test('MC-01 distributed mode short-circuits without touching PG or audit-log', async () => {
    const exit            = jest.fn();
    const emitFn           = jest.fn();
    const pgPool           = { isEnabled: jest.fn() };
    const pgAuditBackend   = { loadChainFromPg: jest.fn() };
    const auditLog         = { getChainStats: jest.fn(), verifyAuditChainDetailed: jest.fn() };

    const ok = await verifyMirrorConsistency({
      _env: { QODIQA_AUDIT_ORDERING_MODE: 'distributed' },
      _pgPool: pgPool,
      _pgAuditBackend: pgAuditBackend,
      _auditLog: auditLog,
      _exit: exit,
      _emit: emitFn,
    });

    expect(ok).toBe(true);
    expect(exit).not.toHaveBeenCalled();
    expect(pgPool.isEnabled).not.toHaveBeenCalled();
    expect(pgAuditBackend.loadChainFromPg).not.toHaveBeenCalled();
    expect(auditLog.getChainStats).not.toHaveBeenCalled();
  });

  test('MC-02 single-node mode with PG disabled is skipped and logs INFO', async () => {
    const exit  = jest.fn();
    const emitFn = jest.fn();
    const pgPool = { isEnabled: () => false };
    const pgAuditBackend = { loadChainFromPg: jest.fn() };
    const auditLog = { getChainStats: jest.fn(), verifyAuditChainDetailed: jest.fn() };

    const ok = await verifyMirrorConsistency({
      _env: {},
      _pgPool: pgPool,
      _pgAuditBackend: pgAuditBackend,
      _auditLog: auditLog,
      _exit: exit,
      _emit: emitFn,
    });

    expect(ok).toBe(true);
    expect(exit).not.toHaveBeenCalled();
    expect(pgAuditBackend.loadChainFromPg).not.toHaveBeenCalled();
    expect(emitFn).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CHECK_SKIPPED', expect.any(Object));
  });

  test('MC-03 valid matching chain passes and logs the consistency-verified INFO record', async () => {
    const exit   = jest.fn();
    const emitFn = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgRows = [{ hash: 'h3' }]; // opaque — the mocked walk below decides validity
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue(pgRows) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 3, headHash: 'h1', tailHash: 'h3' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 3, head: 'h1', tail: 'h3', tamperingDetected: false,
      }),
    };

    const ok = await verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: emitFn,
    });

    expect(ok).toBe(true);
    expect(exit).not.toHaveBeenCalled();
    expect(auditLog.verifyAuditChainDetailed).toHaveBeenCalledWith(pgRows);
    expect(emitFn).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', { entryCount: 3, tailHash: 'h3' });
  });

  test('MC-04 truncated local file (file behind PG) triggers FATAL + exit(1)', async () => {
    const exit   = jest.fn();
    const emitFn = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([{}]) };
    const auditLog = {
      // File chain was truncated to 2 entries; PG still has all 5.
      getChainStats: () => fakeChainStats({ modernLength: 2, headHash: 'h1', tailHash: 'h2' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 5, head: 'h1', tail: 'h5', tamperingDetected: false,
      }),
    };

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: emitFn,
    }));

    expect(result).toBe(false);
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.severity).toBe('FATAL');
    expect(record.eventType).toBe('AUDIT_MIRROR_CONSISTENCY_VIOLATION');
    expect(record.mismatches).toEqual(expect.arrayContaining([
      { field: 'entryCount', file: 2, pg: 5 },
      { field: 'tailHash', file: 'h2', pg: 'h5' },
    ]));
  });

  test('MC-05 deleted tail entries triggers FATAL + exit(1)', async () => {
    const exit   = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([{}]) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 8, headHash: 'h1', tailHash: 'h8' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 10, head: 'h1', tail: 'h10', tamperingDetected: false,
      }),
    };

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: jest.fn(),
    }));

    expect(result).toBe(false);
    expect(exit).toHaveBeenCalledWith(1);
    expect(JSON.parse(stderr.trim()).eventType).toBe('AUDIT_MIRROR_CONSISTENCY_VIOLATION');
  });

  test('MC-06 replaced chain tail (same count, tail hash differs) triggers FATAL + exit(1)', async () => {
    const exit   = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([{}]) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 4, headHash: 'h1', tailHash: 'REPLACED_TAIL' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 4, head: 'h1', tail: 'h4', tamperingDetected: false,
      }),
    };

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: jest.fn(),
    }));

    expect(result).toBe(false);
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.eventType).toBe('AUDIT_MIRROR_CONSISTENCY_VIOLATION');
    // Count matches — only the tail hash diverges.
    expect(record.mismatches).toEqual([{ field: 'tailHash', file: 'REPLACED_TAIL', pg: 'h4' }]);
  });

  test('MC-07 mismatched chain hash / divergent lineage (head differs) triggers FATAL + exit(1)', async () => {
    const exit   = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([{}]) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 2, headHash: 'DIFFERENT_GENESIS', tailHash: 'h2' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 2, head: 'h1', tail: 'h2', tamperingDetected: false,
      }),
    };

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: jest.fn(),
    }));

    expect(result).toBe(false);
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.mismatches).toEqual([{ field: 'headHash', file: 'DIFFERENT_GENESIS', pg: 'h1' }]);
  });

  test('MC-08 mismatched sequence number (PG ahead of file) reports multiple mismatch fields', async () => {
    const exit   = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([{}]) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 3, headHash: 'h1', tailHash: 'h3' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 7, head: 'h1', tail: 'h7', tamperingDetected: false,
      }),
    };

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: jest.fn(),
    }));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.fileEntryCount).toBe(3);
    expect(record.pgEntryCount).toBe(7);
    expect(record.mismatches).toEqual(expect.arrayContaining([
      { field: 'entryCount', file: 3, pg: 7 },
      { field: 'tailHash', file: 'h3', pg: 'h7' },
    ]));
  });

  test('MC-09 corrupted terminal record in the PG mirror triggers FATAL + exit(1) without comparing counts', async () => {
    const exit   = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([{}, {}, {}]) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 3, headHash: 'h1', tailHash: 'h3' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: false, reason: 'AUDIT_CHAIN_TAMPERED', entriesVerified: 2, head: 'h1', tail: 'h2', tamperingDetected: true,
      }),
    };

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: jest.fn(),
    }));

    expect(result).toBe(false);
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.eventType).toBe('AUDIT_MIRROR_PG_CHAIN_INVALID');
    expect(record.validationReason).toBe('AUDIT_CHAIN_TAMPERED');
    // Must fail before ever reaching the count/head/tail comparison.
    expect(record.mismatches).toBeUndefined();
  });

  test('MC-10 empty chain on both sides passes cleanly', async () => {
    const exit   = jest.fn();
    const emitFn = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([]) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 0, headHash: null, tailHash: 'GENESIS' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 0, head: null, tail: null, tamperingDetected: false,
      }),
    };

    const ok = await verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: emitFn,
    });

    expect(ok).toBe(true);
    expect(exit).not.toHaveBeenCalled();
    expect(emitFn).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', { entryCount: 0, tailHash: null });
  });

  test('MC-11 PostgreSQL unavailable during verification triggers FATAL + exit(1)', async () => {
    const exit   = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockRejectedValue(new Error('connection terminated')) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 3, headHash: 'h1', tailHash: 'h3' }),
      verifyAuditChainDetailed: jest.fn(),
    };

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: jest.fn(),
    }));

    expect(result).toBe(false);
    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.eventType).toBe('AUDIT_MIRROR_PG_UNREACHABLE');
    expect(record.error).toBe('connection terminated');
    expect(auditLog.verifyAuditChainDetailed).not.toHaveBeenCalled();
  });

  test('MC-12 regression: a mismatch never emits the success INFO record', async () => {
    const emitFn = jest.fn();
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockResolvedValue([{}]) };
    const auditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 1, headHash: 'h1', tailHash: 'h1' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 2, head: 'h1', tail: 'h2', tamperingDetected: false,
      }),
    };

    await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: jest.fn(), _emit: emitFn,
    }));

    expect(emitFn).not.toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', expect.anything());
  });

  test('MC-13 successful startup after consistency is restored', async () => {
    const pgPool = { isEnabled: () => true };
    const emitFn = jest.fn();

    // First boot: file has 2 entries, PG confirms 5 — refuse to start.
    const brokenAuditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 2, headHash: 'h1', tailHash: 'h2' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 5, head: 'h1', tail: 'h5', tamperingDetected: false,
      }),
    };
    const exit1 = jest.fn();
    const { result: firstResult } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool,
      _pgAuditBackend: { loadChainFromPg: jest.fn().mockResolvedValue([{}]) },
      _auditLog: brokenAuditLog, _exit: exit1, _emit: emitFn,
    }));
    expect(firstResult).toBe(false);
    expect(exit1).toHaveBeenCalledWith(1);

    // Operator reconciles the mirror (e.g. backfill) — now both sides agree.
    const fixedAuditLog = {
      getChainStats: () => fakeChainStats({ modernLength: 5, headHash: 'h1', tailHash: 'h5' }),
      verifyAuditChainDetailed: jest.fn().mockReturnValue({
        valid: true, reason: null, entriesVerified: 5, head: 'h1', tail: 'h5', tamperingDetected: false,
      }),
    };
    const exit2 = jest.fn();
    const secondResult = await verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool,
      _pgAuditBackend: { loadChainFromPg: jest.fn().mockResolvedValue([{}]) },
      _auditLog: fixedAuditLog, _exit: exit2, _emit: emitFn,
    });
    expect(secondResult).toBe(true);
    expect(exit2).not.toHaveBeenCalled();
    expect(emitFn).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', { entryCount: 5, tailHash: 'h5' });
  });

  test('MC-14 FATAL records are written directly to stderr, independent of the injected emit function', async () => {
    const exit  = jest.fn();
    const emitFn = jest.fn(() => { throw new Error('logger pipeline is down too'); });
    const pgPool = { isEnabled: () => true };
    const pgAuditBackend = { loadChainFromPg: jest.fn().mockRejectedValue(new Error('ECONNREFUSED')) };
    const auditLog = { getChainStats: () => fakeChainStats({ modernLength: 1, headHash: 'h1', tailHash: 'h1' }) };

    const { stderr } = await capturedStderr(() => verifyMirrorConsistency({
      _env: {}, _pgPool: pgPool, _pgAuditBackend: pgAuditBackend, _auditLog: auditLog, _exit: exit, _emit: emitFn,
    }));

    expect(exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.severity).toBe('FATAL');
    expect(record.ref).toBe('docs/protocol/AUDIT-SCHEMA-V8.md');
  });

  test('MC-15 regression: skip paths never call _exit', async () => {
    const exitA = jest.fn();
    await verifyMirrorConsistency({
      _env: { QODIQA_AUDIT_ORDERING_MODE: 'distributed' },
      _pgPool: { isEnabled: jest.fn() },
      _pgAuditBackend: { loadChainFromPg: jest.fn() },
      _auditLog: { getChainStats: jest.fn(), verifyAuditChainDetailed: jest.fn() },
      _exit: exitA, _emit: jest.fn(),
    });
    expect(exitA).not.toHaveBeenCalled();

    const exitB = jest.fn();
    await verifyMirrorConsistency({
      _env: {},
      _pgPool: { isEnabled: () => false },
      _pgAuditBackend: { loadChainFromPg: jest.fn() },
      _auditLog: { getChainStats: jest.fn(), verifyAuditChainDetailed: jest.fn() },
      _exit: exitB, _emit: jest.fn(),
    });
    expect(exitB).not.toHaveBeenCalled();
  });
});

// ── CHAIN-4 — full record-level cross-validation ─────────────────────────────
//
// (above) proved that a count/head/tail summary comparison is
// cryptographically sufficient to *detect* any divergence between the file
// chain and the PG mirror. CHAIN-4 adds a full positional record-by-record
// walk purely to *diagnose* a detected divergence — reporting the first
// diverging sequence number, both sides' hash/previousHash at that position,
// and the last record both stores still agree on — plus independent
// duplicate-hash detection and a documented, explicit-opt-in recovery mode.
//
//   CV-01  Perfectly matching large histories: success, correct records-checked
//   CV-02  Missing PostgreSQL record (file ahead): MISSING_IN_PG at the exact sequence
//   CV-03  Missing filesystem record (PG ahead): MISSING_IN_FILE at the exact sequence
//   CV-04  Different record hash mid-chain: HASH_MISMATCH at the exact sequence
//   CV-05  Different previousHash mid-chain: PREV_HASH_MISMATCH at the exact sequence
//   CV-06  Different chain head (tail record differs): lastCommonRecord is the prior record
//   CV-07  Different genesis record: GENESIS_MISMATCH, lastCommonRecord is null
//   CV-08  Different ordering (swapped records): mismatch at the swapped sequence
//   CV-09  Duplicate PostgreSQL record: reported in duplicateHashesInPg
//   CV-10  Duplicate filesystem record: reported in duplicateHashesInFile
//   CV-11  Truncated filesystem chain: MISSING_IN_FILE at the truncation point
//   CV-12  Truncated PostgreSQL chain: MISSING_IN_PG at the truncation point
//   CV-13  Corrupted filesystem record: AUDIT_MIRROR_FILE_CHAIN_INVALID, FATAL + exit(1)
//   CV-14  Corrupted PostgreSQL record: AUDIT_MIRROR_PG_CHAIN_INVALID, FATAL + exit(1)
//   CV-15  Large audit history (tens of thousands of records): correctness + performance
//   CV-16  Startup performance under a realistic production-sized audit log
//   CV-17  Recovery mode: divergence logged at WARN, startup proceeds, no exit
//   CV-18  Recovery mode never engages when there is no divergence to recover from
//   CV-19  Metrics emitted correctly on success
//   CV-20  Metrics emitted correctly on failure (records-checked set, last-verified NOT set)
//   CV-21  Detailed diagnostics include every required operator-facing field
//   CV-22  Regression: fallback to summary-only comparison when getModernChain() is absent

describe('CHAIN-4 — full record-level cross-validation', () => {

  function capturedStderr(fn) {
    const chunks = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => { chunks.push(chunk); return true; };
    return fn().finally(() => { process.stderr.write = orig; }).then((result) => ({
      result,
      stderr: chunks.join(''),
    }));
  }

  function makeEntry(i) {
    return {
      hash:       `h${i}`,
      prevHash:   i === 0 ? 'GENESIS' : `h${i - 1}`,
      canonical:  `canonical-${i}`,
      artifactId: `artifact-${i}`,
    };
  }

  function makeChain(n) {
    return Array.from({ length: n }, (_, i) => makeEntry(i));
  }

  function statsFor(entries) {
    return {
      chainLength:  entries.length,
      modernLength: entries.length,
      headHash:     entries.length ? entries[0].hash : null,
      tailHash:     entries.length ? entries[entries.length - 1].hash : 'GENESIS',
    };
  }

  // Simplified stand-in for audit-log.js's real _walkChain: valid unless an
  // entry was explicitly marked corrupted by a test. Does not itself enforce
  // hash/prevHash linkage — that's exactly the job of _crossValidateRecords,
  // which these tests exercise directly.
  function detailFor(entries) {
    if (!Array.isArray(entries)) {
      return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
    }
    const corruptedIdx = entries.findIndex(e => e && e.__corrupted);
    if (corruptedIdx !== -1) {
      return {
        valid: false, reason: 'AUDIT_CHAIN_TAMPERED',
        entriesVerified: corruptedIdx,
        head: entries[0]?.hash ?? null,
        tail: corruptedIdx > 0 ? entries[corruptedIdx - 1].hash : null,
        tamperingDetected: true,
      };
    }
    if (entries.length === 0) return { valid: true, reason: null, entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
    return {
      valid: true, reason: null,
      entriesVerified: entries.length,
      head: entries[0].hash,
      tail: entries[entries.length - 1].hash,
      tamperingDetected: false,
    };
  }

  function buildDeps({ fileEntries, pgEntries, extra = {} }) {
    return {
      _env: {},
      _pgPool: { isEnabled: () => true },
      _pgAuditBackend: { loadChainFromPg: jest.fn().mockResolvedValue(pgEntries) },
      _auditLog: {
        getChainStats:            () => statsFor(fileEntries),
        getModernChain:           () => fileEntries,
        verifyAuditChainDetailed: jest.fn(detailFor),
      },
      _exit: jest.fn(),
      _emit: jest.fn(),
      ...extra,
    };
  }

  test('CV-01 perfectly matching histories pass and report full records checked', async () => {
    const fileEntries = makeChain(200);
    const pgEntries    = makeChain(200);
    const deps = buildDeps({ fileEntries, pgEntries });

    const ok = await verifyMirrorConsistency(deps);

    expect(ok).toBe(true);
    expect(deps._exit).not.toHaveBeenCalled();
    expect(deps._emit).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', expect.any(Object));
  });

  test('CV-02 missing PostgreSQL record (file ahead) reports MISSING_IN_PG at the exact sequence', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = fileEntries.slice(0, 48).map(e => ({ ...e }));
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    expect(deps._exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.eventType).toBe('AUDIT_MIRROR_CONSISTENCY_VIOLATION');
    expect(record.firstMismatchSequence).toBe(48);
    expect(record.mismatchReason).toBe('MISSING_IN_PG');
    expect(record.lastCommonRecord).toEqual({ sequence: 47, hash: 'h47' });
  });

  test('CV-03 missing filesystem record (PG ahead) reports MISSING_IN_FILE at the exact sequence', async () => {
    const pgEntries    = makeChain(50);
    const fileEntries  = pgEntries.slice(0, 48).map(e => ({ ...e }));
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.firstMismatchSequence).toBe(48);
    expect(record.mismatchReason).toBe('MISSING_IN_FILE');
  });

  test('CV-04 different record hash mid-chain reports HASH_MISMATCH at the exact sequence', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50).map((e, i) => i === 25 ? { ...e, hash: 'TAMPERED_HASH_25' } : e);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.firstMismatchSequence).toBe(25);
    expect(record.mismatchReason).toBe('HASH_MISMATCH');
    expect(record.fileHash).toBe('h25');
    expect(record.pgHash).toBe('TAMPERED_HASH_25');
    expect(record.lastCommonRecord).toEqual({ sequence: 24, hash: 'h24' });
  });

  test('CV-05 different previousHash mid-chain reports PREV_HASH_MISMATCH at the exact sequence', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50).map((e, i) => i === 25 ? { ...e, prevHash: 'WRONG_PREV_HASH' } : e);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.firstMismatchSequence).toBe(25);
    expect(record.mismatchReason).toBe('PREV_HASH_MISMATCH');
    expect(record.expectedPrevHash).toBe('h24');
    expect(record.actualPrevHash).toBe('WRONG_PREV_HASH');
  });

  test('CV-06 different chain head (tail record differs) reports lastCommonRecord as the prior record', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50).map((e, i) => i === 49 ? { ...e, hash: 'DIFFERENT_TAIL', prevHash: e.prevHash } : e);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.firstMismatchSequence).toBe(49);
    expect(record.mismatchReason).toBe('HASH_MISMATCH');
    expect(record.lastCommonRecord).toEqual({ sequence: 48, hash: 'h48' });
  });

  test('CV-07 different genesis record reports GENESIS_MISMATCH with no lastCommonRecord', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50).map((e, i) => i === 0 ? { ...e, hash: 'DIFFERENT_GENESIS' } : e);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.firstMismatchSequence).toBe(0);
    expect(record.mismatchReason).toBe('GENESIS_MISMATCH');
    expect(record.lastCommonRecord).toBeNull();
  });

  test('CV-08 PG rows in a different order than the file (same content, same hash-chain linkage) is NOT a mismatch', async () => {
    // Pre-F26 this asserted the OPPOSITE — that swapped array positions
    // reported HASH_MISMATCH — because the old comparison was purely
    // positional (fileEntries[i] vs. pgEntries[i]). That was the bug
    // fixed: ordinary concurrent fire-and-forget dual-writes can legitimately
    // land two records in PostgreSQL in a different order than the file's
    // own true logical order, with zero real divergence — each record's own
    // hash/prevHash/canonical is completely unchanged, only its position in
    // the PG row array differs. Live-reproduced under real load
    // Session 3. The correct,
    // content-addressed comparison must treat this as clean, not as a false
    // PG_MIRROR_HASH_MISMATCH — including via this module's own FATAL
    // startup gate, which used to false-positive on exactly this shape.
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50);
    [pgEntries[10], pgEntries[11]] = [pgEntries[11], pgEntries[10]];
    const deps = buildDeps({ fileEntries, pgEntries });

    const ok = await verifyMirrorConsistency(deps);

    expect(ok).toBe(true);
    expect(deps._exit).not.toHaveBeenCalled();
    expect(deps._emit).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', expect.any(Object));
  });

  test('CV-09 duplicate PostgreSQL record is reported in duplicateHashesInPg', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50);
    pgEntries[20] = { ...pgEntries[19] };
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.duplicateHashesInPg).toEqual(['h19']);
  });

  test('CV-10 duplicate filesystem record is reported in duplicateHashesInFile', async () => {
    const fileEntries = makeChain(50);
    fileEntries[20] = { ...fileEntries[19] };
    const pgEntries  = makeChain(50);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.duplicateHashesInFile).toEqual(['h19']);
  });

  test('CV-11 truncated filesystem chain reports MISSING_IN_FILE at the truncation point', async () => {
    const pgEntries   = makeChain(50);
    const fileEntries = makeChain(30);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.mismatchReason).toBe('MISSING_IN_FILE');
    expect(record.firstMismatchSequence).toBe(30);
    expect(record.fileChainLength).toBe(30);
    expect(record.pgChainLength).toBe(50);
  });

  test('CV-12 truncated PostgreSQL chain reports MISSING_IN_PG at the truncation point', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(30);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    const record = JSON.parse(stderr.trim());
    expect(record.mismatchReason).toBe('MISSING_IN_PG');
    expect(record.firstMismatchSequence).toBe(30);
  });

  test('CV-13 corrupted filesystem record triggers AUDIT_MIRROR_FILE_CHAIN_INVALID, FATAL + exit(1)', async () => {
    const fileEntries = makeChain(50);
    fileEntries[10].__corrupted = true;
    const pgEntries = makeChain(50);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    expect(deps._exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.eventType).toBe('AUDIT_MIRROR_FILE_CHAIN_INVALID');
    expect(record.validationReason).toBe('AUDIT_CHAIN_TAMPERED');
    // Must fail before ever reaching the positional cross-validation.
    expect(record.mismatches).toBeUndefined();
  });

  test('CV-14 corrupted PostgreSQL record triggers AUDIT_MIRROR_PG_CHAIN_INVALID, FATAL + exit(1)', async () => {
    const fileEntries = makeChain(50);
    const pgEntries = makeChain(50);
    pgEntries[10].__corrupted = true;
    const deps = buildDeps({ fileEntries, pgEntries });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(false);
    expect(deps._exit).toHaveBeenCalledWith(1);
    const record = JSON.parse(stderr.trim());
    expect(record.eventType).toBe('AUDIT_MIRROR_PG_CHAIN_INVALID');
  });

  test('CV-15 large audit history (tens of thousands of records) verifies correctly', async () => {
    const N = 40000;
    const fileEntries = makeChain(N);
    const pgEntries    = makeChain(N);
    const deps = buildDeps({ fileEntries, pgEntries });

    const ok = await verifyMirrorConsistency(deps);

    expect(ok).toBe(true);
    expect(deps._exit).not.toHaveBeenCalled();
  });

  test('CV-16 startup cross-check completes quickly under a realistic production-sized audit log', async () => {
    const N = 40000;
    const fileEntries = makeChain(N);
    const pgEntries    = makeChain(N);
    const deps = buildDeps({ fileEntries, pgEntries });

    const startedAt = Date.now();
    await verifyMirrorConsistency(deps);
    const elapsedMs = Date.now() - startedAt;

    // Generous ceiling for CI variance — a single O(n) in-memory pass over
    // 40k records should complete in well under a second on any real hardware.
    expect(elapsedMs).toBeLessThan(5000);
  });

  test('CV-17 recovery mode logs the divergence at WARN and allows startup to proceed', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50).map((e, i) => i === 25 ? { ...e, hash: 'TAMPERED' } : e);
    const deps = buildDeps({
      fileEntries, pgEntries,
      extra: { _env: { QODIQA_AUDIT_MIRROR_RECOVERY_MODE: 'true' } },
    });

    const { result, stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(result).toBe(true);
    expect(deps._exit).not.toHaveBeenCalled();
    const record = JSON.parse(stderr.trim());
    expect(record.severity).toBe('WARN');
    expect(record.eventType).toBe('AUDIT_MIRROR_RECOVERY_MODE_ENGAGED');
    expect(record.recoveryMode).toBe(true);
    expect(record.firstMismatchSequence).toBe(25);
    expect(record.action).toMatch(/no automatic reconciliation/i);
  });

  test('CV-18 recovery mode never engages when there is no divergence to recover from', async () => {
    const fileEntries = makeChain(50);
    const pgEntries    = makeChain(50);
    const deps = buildDeps({
      fileEntries, pgEntries,
      extra: { _env: { QODIQA_AUDIT_MIRROR_RECOVERY_MODE: 'true' } },
    });

    const ok = await verifyMirrorConsistency(deps);

    expect(ok).toBe(true);
    expect(deps._exit).not.toHaveBeenCalled();
    expect(deps._emit).toHaveBeenCalledWith('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', expect.any(Object));
  });

  function fakeMetrics() {
    return {
      auditCrosscheckSuccessTotal:        { inc: jest.fn() },
      auditCrosscheckFailureTotal:        { inc: jest.fn() },
      auditCrosscheckDurationSeconds:     { observe: jest.fn() },
      auditCrosscheckRecordsChecked:      { set: jest.fn() },
      auditCrosscheckLastVerifiedTimestamp: { set: jest.fn() },
    };
  }

  test('CV-19 metrics are emitted correctly on a successful cross-check', async () => {
    const fileEntries = makeChain(30);
    const pgEntries    = makeChain(30);
    const metrics = fakeMetrics();
    const deps = buildDeps({ fileEntries, pgEntries, extra: { _metrics: metrics } });

    await verifyMirrorConsistency(deps);

    expect(metrics.auditCrosscheckSuccessTotal.inc).toHaveBeenCalledWith({});
    expect(metrics.auditCrosscheckFailureTotal.inc).not.toHaveBeenCalled();
    expect(metrics.auditCrosscheckDurationSeconds.observe).toHaveBeenCalledWith({}, expect.any(Number));
    expect(metrics.auditCrosscheckRecordsChecked.set).toHaveBeenCalledWith({}, 30);
    expect(metrics.auditCrosscheckLastVerifiedTimestamp.set).toHaveBeenCalledWith({}, expect.any(Number));
  });

  test('CV-20 metrics are emitted correctly on a failed cross-check (last-verified timestamp untouched)', async () => {
    const fileEntries = makeChain(30);
    const pgEntries    = makeChain(30).map((e, i) => i === 5 ? { ...e, hash: 'X' } : e);
    const metrics = fakeMetrics();
    const deps = buildDeps({ fileEntries, pgEntries, extra: { _metrics: metrics } });

    await capturedStderr(() => verifyMirrorConsistency(deps));

    expect(metrics.auditCrosscheckFailureTotal.inc).toHaveBeenCalledWith({ reason: 'DIVERGENCE' });
    expect(metrics.auditCrosscheckSuccessTotal.inc).not.toHaveBeenCalled();
    expect(metrics.auditCrosscheckRecordsChecked.set).toHaveBeenCalledWith({}, 6);
    expect(metrics.auditCrosscheckLastVerifiedTimestamp.set).not.toHaveBeenCalled();
  });

  test('CV-21 diagnostics record includes every required operator-facing field on mismatch', async () => {
    const fileEntries = makeChain(20);
    const pgEntries    = makeChain(20).map((e, i) => i === 8 ? { ...e, hash: 'BAD' } : e);
    const deps = buildDeps({ fileEntries, pgEntries });

    const { stderr } = await capturedStderr(() => verifyMirrorConsistency(deps));
    const record = JSON.parse(stderr.trim());

    for (const field of [
      'firstMismatchSequence', 'fileHash', 'pgHash', 'expectedPrevHash', 'actualPrevHash',
      'fileChainLength', 'pgChainLength', 'lastCommonRecord', 'divergencePoint',
      'mismatchReason', 'duplicateHashesInFile', 'duplicateHashesInPg', 'action', 'ref',
    ]) {
      expect(record).toHaveProperty(field);
    }
  });

  test('CV-22 regression: falls back to summary-only comparison when getModernChain() is unavailable', async () => {
    const fileEntries = makeChain(10);
    const pgEntries    = makeChain(10);
    const auditLog = {
      getChainStats:            () => statsFor(fileEntries),
      verifyAuditChainDetailed: jest.fn(detailFor),
      // Deliberately no getModernChain() — simulates an older/minimal
      // audit-log module stand-in. The check must still work via the
      // count/head/tail summary path rather than throwing.
    };
    const ok = await verifyMirrorConsistency({
      _env: {}, _pgPool: { isEnabled: () => true },
      _pgAuditBackend: { loadChainFromPg: jest.fn().mockResolvedValue(pgEntries) },
      _auditLog: auditLog, _exit: jest.fn(), _emit: jest.fn(),
    });

    expect(ok).toBe(true);
  });
});

describe('_reorderByHashChain', () => {
  const { _reorderByHashChain } = require('../mirrorConsistencyCheck');

  function row(i) {
    return { hash: `h${i}`, prevHash: i === 0 ? 'GENESIS' : `h${i - 1}` };
  }

  test('RB-01 already-ordered rows are returned in the same logical order', () => {
    const rows = [row(0), row(1), row(2), row(3)];
    expect(_reorderByHashChain(rows)).toEqual(rows);
  });

  test('RB-02 reordered rows (real seq-vs-logical-order shape) are reconstructed into true order', () => {
    const [r0, r1, r2, r3, r4, r5] = [row(0), row(1), row(2), row(3), row(4), row(5)];
    // Same shape crossValidateRecords()'s own comment documents: two
    // adjacent records land in seq-insertion order swapped relative to true
    // logical order — everything else stays a perfectly intact hash chain.
    const scrambled = [r0, r1, r2, r3, r5, r4];
    expect(_reorderByHashChain(scrambled)).toEqual([r0, r1, r2, r3, r4, r5]);
  });

  test('RB-03 fully reversed rows are reconstructed into true order', () => {
    const rows = [row(0), row(1), row(2), row(3), row(4)];
    const reversed = [...rows].reverse();
    expect(_reorderByHashChain(reversed)).toEqual(rows);
  });

  test('RB-04 a genuinely missing row (not just reordered) falls back to the original order unchanged', () => {
    // row(3) never arrived — row(4)'s own prevHash ('h3') has no match, so a
    // single linear chain cannot be reconstructed. Falling back preserves
    // the earlier detection behavior (verifyAuditChainDetailed's own
    // positional walk still correctly reports this as broken).
    const rows = [row(0), row(1), row(2), row(4)];
    expect(_reorderByHashChain(rows)).toBe(rows);
  });

  test('RB-05 a duplicate prevHash (branch, not a simple linear chain) falls back to the original order unchanged', () => {
    const branch = { hash: 'hX', prevHash: 'h1' }; // same predecessor as row(2)
    const rows = [row(0), row(1), row(2), branch];
    expect(_reorderByHashChain(rows)).toBe(rows);
  });

  test('RB-06 empty and single-row inputs are handled without error', () => {
    expect(_reorderByHashChain([])).toEqual([]);
    expect(_reorderByHashChain([row(0)])).toEqual([row(0)]);
  });

  test('RB-07 malformed rows (missing prevHash) fall back to the original order unchanged', () => {
    const rows = [row(0), {}, row(1)];
    expect(_reorderByHashChain(rows)).toBe(rows);
  });
});
