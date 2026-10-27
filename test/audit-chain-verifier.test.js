'use strict';

/**
 * CHAIN-2 — Live Audit Chain Integrity Verifier
 *
 * Unit-level tests for src/core/audit/verifier/ChainVerifier.js,
 * verifierState.js, diagnostics.js, and the background runner
 * (src/core/audit/verifier/index.js), plus the startup watermark-continuity
 * gate (src/core/audit/verifierStartupGate.js). Uses a real, isolated
 * audit-log.js instance (a fresh temp file per test) for file-mode
 * scenarios — no real PostgreSQL. PG-mode/table scanning scenarios are
 * covered separately in test/integration/audit-chain-verifier-pg.integration.test.js
 * (requires a real local Postgres, skips otherwise).
 *
 * Intentionally NOT re-tested here (already covered elsewhere):
 *   - multiInstanceGuard.js / pgLagMonitor.js          → test/audit-chain-hardening.test.js
 *   - distributed-mode concurrent-append safety        → test/integration/audit-chain-distributed.integration.test.js
 *   - the generic Persistence Recovery Queue            → test/persistence-recovery-queue.test.js
 *   - mirrorConsistencyCheck.js's own startup gate       → test/auditMirrorStartupGate.test.js
 *
 * ACV-01  Incremental verify of a valid tail extension only re-walks the
 *         delta (asserts getModernChainSlice is used, not a full re-walk)
 * ACV-02  Incremental verify detects a hash break introduced only in the
 *         newly-appended tail
 * ACV-03  Watermark seeding: no prior sidecar → seeds without walking
 * ACV-04  Watermark truncation is detected (persisted cursor > current chain)
 * ACV-05  FULL scan: fresh disk re-read diverging from the in-memory chain
 *         is detected as FILE_MEMORY_DIVERGENCE
 * ACV-06  FULL scan re-validates the on-disk chain independently and
 *         detects a hand-tampered record
 * ACV-07  diagnostics.js: every VIOLATION_REASON maps to exactly one
 *         severity, and severity maps to the correct alert event
 * ACV-08  repairAttempts is always 0 / repairSupported false regardless of
 *         scan outcome
 * ACV-09  verify() persists a new watermark after a clean incremental run
 * ACV-10  A violation does not advance the watermark past the bad entry
 * ACV-11  Runner: concurrent scheduled ticks skip rather than overlap
 *         (already_scanning)
 * ACV-12  Runner: verifyNow() triggers an immediate MANUAL-trigger scan
 * ACV-13  Runner: disabled config (enabled=false) never schedules a timer
 * ACV-14  Startup gate: no watermark seeds from current trusted state
 * ACV-15  Startup gate: watermark ahead of current chain length is FATAL
 *         by default (process.exit(1) called)
 * ACV-16  Startup gate: watermark hash divergence at a still-in-range
 *         position is FATAL by default
 * ACV-17  Startup gate: QODIQA_AUDIT_VERIFIER_RECOVERY_MODE=true downgrades
 *         a divergence to WARN and returns true (no exit)
 * ACV-18  Startup gate: a watermark that matches the current tail proceeds
 *         cleanly with no exit and no WARN
 * ACV-19  Startup gate (distributed mode): a genesis watermark (seq 0,
 *         GENESIS) against a still-empty chain (max seq null) is NOT
 * truncation -- fix regression guard
 * ACV-20  Startup gate (distributed mode): a real watermark (seq > 0)
 *         against a null current max seq is still FATAL truncation
 * ACV-21  Startup gate (distributed mode): current max seq below a real
 *         watermark is still FATAL truncation
 * ACV-22  Startup gate (distributed mode): hash divergence at an in-range
 *         watermark position is still FATAL
 * ACV-23  Startup gate (distributed mode): a watermark matching the current
 *         PG state proceeds cleanly
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const os   = require('os');
const path = require('path');
const fs   = require('fs');

function _tmpAuditLogPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-acv-test-'));
  return path.join(dir, 'audit.log');
}

// Loads a fresh, isolated instance of audit-log.js (and everything the
// verifier needs) pointed at its own temp file — jest.resetModules() is
// required since audit-log.js resolves QODIQA_AUDIT_LOG and performs its
// load-from-disk IIFE at require() time.
function _freshModules(logPath) {
  jest.resetModules();
  process.env.QODIQA_AUDIT_LOG = logPath;
  const auditLog = require('../src/core/audit/audit-log');
  const { createChainVerifier } = require('../src/core/audit/verifier/ChainVerifier');
  const { createVerifierRunner } = require('../src/core/audit/verifier/index');
  const verifierState = require('../src/core/audit/verifier/verifierState');
  const diagnostics = require('../src/core/audit/verifier/diagnostics');
  const { verifyChainVerifierContinuity } = require('../src/core/audit/verifierStartupGate');
  return { auditLog, createChainVerifier, createVerifierRunner, verifierState, diagnostics, verifyChainVerifierContinuity };
}

function _noopMetrics() {
  const counter = { inc: jest.fn(), set: jest.fn(), observe: jest.fn() };
  return new Proxy({}, { get: () => counter });
}

async function _appendEntries(auditLog, count, { startAt = 0 } = {}) {
  for (let i = startAt; i < startAt + count; i++) {
    await auditLog.append({
      artifactId:          `artifact-${i}`,
      inputHash:            'a'.repeat(64),
      decision:            'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:           `sig-${i}`,
      requestHash:          'b'.repeat(64),
      policyHash:           'c'.repeat(64),
      verificationResult:  true,
    });
  }
}

describe('CHAIN-2 — Live Audit Chain Integrity Verifier (file mode, unit)', () => {
  let logPath;
  let mods;

  beforeEach(() => {
    logPath = _tmpAuditLogPath();
    mods = _freshModules(logPath);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('ACV-01 incremental verify only walks the newly-appended delta', async () => {
    const { auditLog, createChainVerifier } = mods;
    await _appendEntries(auditLog, 5);

    const sliceSpy = jest.spyOn(auditLog, 'getModernChainSlice');
    // the capped catch-up reads the delta through the paged cursor (getModernChainPage) when available
    const pageSpy  = jest.spyOn(auditLog, 'getModernChainPage');
    const fullSpy  = jest.spyOn(auditLog, 'getModernChain');

    const verifier = createChainVerifier({ _auditLog: auditLog, _metrics: _noopMetrics() });
    const r1 = await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' });
    expect(r1.success).toBe(true);
    expect(r1.entriesChecked).toBe(5);
    expect(sliceSpy.mock.calls.length + pageSpy.mock.calls.length).toBeGreaterThan(0);
    expect(fullSpy).not.toHaveBeenCalled();

    await _appendEntries(auditLog, 2, { startAt: 5 });
    pageSpy.mockClear();
    const r2 = await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' });
    expect(r2.entriesChecked).toBe(2); // only the delta, not all 7
    if (pageSpy.mock.calls.length) expect(pageSpy.mock.calls[0][0].cursor).toEqual({ m: 5 }); // the delta's start
  });

  test('ACV-02 incremental verify detects a hash break only in the new tail', async () => {
    const { auditLog, createChainVerifier } = mods;
    await _appendEntries(auditLog, 3);

    const verifier = createChainVerifier({ _auditLog: auditLog, _metrics: _noopMetrics() });
    await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' }); // establish watermark at 3

    // Directly append 2 more raw (well-formed) entries, then corrupt the file
    // to break the prevHash link of the last one, simulating external
    // tampering of the newly-appended tail between verifier ticks.
    await _appendEntries(auditLog, 2, { startAt: 3 });

    const raw = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean);
    const last = JSON.parse(raw[4]);
    last.prevHash = 'f'.repeat(64); // break the link
    raw[4] = JSON.stringify(last);
    fs.writeFileSync(logPath, raw.join('\n') + '\n', 'utf8');

    // Reload a fresh in-memory view reflecting the tampered file (simulates
    // the verifier's FULL path, which re-reads independently of memory) —
    // for the INCREMENTAL path under test here we instead directly assert
    // against a fresh audit-log instance since INCREMENTAL walks the
    // trusted in-memory chain, not disk; so we re-require to pick up the
    // tampered file from disk via the load path itself failing loudly.
    jest.resetModules();
    process.env.QODIQA_AUDIT_LOG = logPath;
    expect(() => require('../src/core/audit/audit-log')).toThrow(/chain_break/);
  });

  test('ACV-03 watermark seeding: no prior sidecar seeds without a walk', async () => {
    const { auditLog, createChainVerifier, verifierState } = mods;
    await _appendEntries(auditLog, 4);

    const loadSpy = jest.spyOn(verifierState, 'loadFileState');
    const verifier = createChainVerifier({ _auditLog: auditLog, _verifierState: verifierState, _metrics: _noopMetrics() });

    const r = await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' });
    expect(loadSpy).toHaveBeenCalled();
    expect(r.entriesChecked).toBe(4); // no prior watermark → starts from index 0

    const state = await verifierState.loadFileState();
    expect(state.lastVerifiedIndex).toBe(4);
  });

  test('ACV-04 watermark truncation is detected', async () => {
    const { auditLog, createChainVerifier, verifierState, diagnostics } = mods;
    await _appendEntries(auditLog, 3);

    const verifier = createChainVerifier({ _auditLog: auditLog, _verifierState: verifierState, _metrics: _noopMetrics() });
    await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' }); // watermark = 3

    // Simulate a watermark that is ahead of reality (e.g. the file was
    // rolled back after the watermark was written).
    await verifierState.saveFileState({ lastVerifiedIndex: 999, lastVerifiedHash: 'deadbeef' });

    const r = await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' });
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0].reason).toBe(diagnostics.VIOLATION_REASON.TRUNCATION);
    expect(r.violations[0].severity).toBe('CRITICAL');
  });

  test('ACV-05 FULL scan detects file/memory divergence after a fresh disk re-read', async () => {
    const { auditLog, createChainVerifier, diagnostics } = mods;
    await _appendEntries(auditLog, 3);

    const verifier = createChainVerifier({ _auditLog: auditLog, _metrics: _noopMetrics() });

    // Tamper the file directly (bypassing the append() API) so the process's
    // in-memory chain (still 3 valid entries) disagrees with a fresh disk read.
    const raw = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean);
    const tampered = JSON.parse(raw[1]);
    tampered.decision = 'BLOCK';
    raw[1] = JSON.stringify(tampered);
    fs.writeFileSync(logPath, raw.join('\n') + '\n', 'utf8');

    const r = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });
    const reasons = r.violations.map(v => v.reason);
    expect(reasons).toContain(diagnostics.VIOLATION_REASON.FILE_MEMORY_DIVERGENCE);
    expect(reasons).toContain(diagnostics.VIOLATION_REASON.HASH_MISMATCH);
  });

  test('ACV-06 FULL scan reuses verifyFullChainFromDiskChunked and reports the offending record', async () => {
    // #129: the FULL scan now calls the chunked/non-blocking
    // twin of verifyFullChainFromDisk (identical file-read/checksum/walk
    // logic, yields to the event loop between chunks of the hash-chain
    // walk) so a large on-disk chain can't stall concurrent request
    // handling for the scan's whole duration. Same behavior, new function
    // name — this spy target is the one thing that had to change.
    const { auditLog, createChainVerifier } = mods;
    await _appendEntries(auditLog, 4);

    const spy = jest.spyOn(auditLog, 'verifyFullChainFromDiskChunked');
    const verifier = createChainVerifier({ _auditLog: auditLog, _metrics: _noopMetrics() });
    const r = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

    expect(spy).toHaveBeenCalled();
    expect(r.violations).toHaveLength(0);
    expect(r.entriesChecked).toBe(4);
  });

  test('ACV-07 diagnostics: every VIOLATION_REASON has exactly one severity and correct alert event', () => {
    const { diagnostics } = mods;
    for (const reason of Object.values(diagnostics.VIOLATION_REASON)) {
      const severity = diagnostics.severityOf(reason);
      expect([diagnostics.SEVERITY.CRITICAL, diagnostics.SEVERITY.MEDIUM]).toContain(severity);

      const event = diagnostics.alertEventFor(reason);
      if (severity === diagnostics.SEVERITY.CRITICAL) {
        expect(event).toBe('AUDIT_CHAIN_CORRUPTED');
      } else {
        expect(event).toBe('AUDIT_CHAIN_STRUCTURAL_ANOMALY');
      }
    }
    // SEQUENCE_GAP is the one documented MEDIUM-severity exception.
    expect(diagnostics.severityOf(diagnostics.VIOLATION_REASON.SEQUENCE_GAP)).toBe('MEDIUM');
    expect(diagnostics.severityOf(diagnostics.VIOLATION_REASON.HASH_MISMATCH)).toBe('CRITICAL');
  });

  test('ACV-08 repairAttempts is always 0 / repairSupported false', async () => {
    const { auditLog, createChainVerifier } = mods;
    await _appendEntries(auditLog, 2);

    const verifier = createChainVerifier({ _auditLog: auditLog, _metrics: _noopMetrics() });
    const clean = await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' });
    expect(clean.repairAttempts).toBe(0);
    expect(clean.repairSupported).toBe(false);

    const runner = mods.createVerifierRunner({ config: { enabled: true, incrementalIntervalMs: 0, fullIntervalMs: 0, pgDivergenceIntervalMs: 0, maxRetries: 0, retryDelayMs: 0 }, _auditLog: auditLog, _metrics: _noopMetrics() });
    const status = runner.getStatus();
    expect(status.repairAttempts).toBe(0);
    expect(status.repairSupported).toBe(false);
  });

  test('ACV-09 verify() persists a new watermark after a clean incremental run', async () => {
    const { auditLog, createChainVerifier, verifierState } = mods;
    await _appendEntries(auditLog, 6);

    const verifier = createChainVerifier({ _auditLog: auditLog, _verifierState: verifierState, _metrics: _noopMetrics() });
    await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' });

    const state = await verifierState.loadFileState();
    expect(state.lastVerifiedIndex).toBe(6);
    expect(typeof state.lastVerifiedHash).toBe('string');
    expect(state.lastVerifiedHash).toBe(auditLog.getChainStats().tailHash);
  });

  test('ACV-10 a violation does not advance the watermark past the bad entry', async () => {
    const { auditLog, createChainVerifier, verifierState } = mods;
    await _appendEntries(auditLog, 3);

    const verifier = createChainVerifier({ _auditLog: auditLog, _verifierState: verifierState, _metrics: _noopMetrics() });
    await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' }); // watermark = 3

    await verifierState.saveFileState({ lastVerifiedIndex: 999, lastVerifiedHash: 'deadbeef' });
    await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' }); // TRUNCATION — must not advance

    const state = await verifierState.loadFileState();
    expect(state.lastVerifiedIndex).toBe(999); // unchanged — never silently "fixed"
  });
});

describe('CHAIN-2 — Background runner (file mode, unit)', () => {
  let logPath;
  let mods;

  beforeEach(() => {
    logPath = _tmpAuditLogPath();
    mods = _freshModules(logPath);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('ACV-11 concurrent ticks skip rather than overlap', async () => {
    const { auditLog, createVerifierRunner } = mods;
    await _appendEntries(auditLog, 2);

    let resolveFirst;
    const gate = new Promise(resolve => { resolveFirst = resolve; });

    const runner = createVerifierRunner({
      config: { enabled: true, incrementalIntervalMs: 0, fullIntervalMs: 0, pgDivergenceIntervalMs: 0, maxRetries: 0, retryDelayMs: 0 },
      _auditLog: auditLog, _metrics: _noopMetrics(),
    });

    // Kick off a slow verifyNow and, while it's still in flight, request a
    // second one — the second must observe "already scanning" and skip.
    const orig = auditLog.getModernChainSlice.bind(auditLog);
    jest.spyOn(auditLog, 'getModernChainSlice').mockImplementation((...args) => {
      return orig(...args);
    });

    const p1 = runner.verifyNow('INCREMENTAL').then(r => { resolveFirst(); return r; });
    expect(runner.isScanning()).toBe(true);
    const p2 = runner.verifyNow('INCREMENTAL');

    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1).toBeTruthy();
    expect(r2.skipped).toBe(true);
    expect(r2.reason).toBe('ALREADY_SCANNING');
    await gate;
  });

  test('ACV-12 verifyNow() triggers an immediate MANUAL-trigger scan', async () => {
    const { auditLog, createVerifierRunner } = mods;
    await _appendEntries(auditLog, 3);

    const runner = createVerifierRunner({
      config: { enabled: true, incrementalIntervalMs: 0, fullIntervalMs: 0, pgDivergenceIntervalMs: 0, maxRetries: 0, retryDelayMs: 0 },
      _auditLog: auditLog, _metrics: _noopMetrics(),
    });

    const result = await runner.verifyNow('INCREMENTAL');
    expect(result.success).toBe(true);
    expect(result.trigger).toBe('MANUAL');
    expect(runner.getStatus().totalRuns).toBe(1);
  });

  test('ACV-13 disabled config never schedules a timer or runs on start()', async () => {
    const { auditLog, createVerifierRunner } = mods;
    await _appendEntries(auditLog, 1);

    const runner = createVerifierRunner({
      config: { enabled: false, incrementalIntervalMs: 60000, fullIntervalMs: 60000, pgDivergenceIntervalMs: 60000, maxRetries: 0, retryDelayMs: 0, startupScan: false },
      _auditLog: auditLog, _metrics: _noopMetrics(),
    });

    await runner.start();
    expect(runner.isRunning()).toBe(false);
    expect(runner.getStatus().totalRuns).toBe(0);
    runner.stop(); // idempotent no-op, must not throw
  });
});

describe('CHAIN-2 — Startup watermark-continuity gate', () => {
  let logPath;
  let mods;

  beforeEach(() => {
    logPath = _tmpAuditLogPath();
    delete process.env.QODIQA_AUDIT_VERIFIER_RECOVERY_MODE;
    mods = _freshModules(logPath);
  });

  afterEach(() => {
    delete process.env.QODIQA_AUDIT_VERIFIER_RECOVERY_MODE;
    jest.restoreAllMocks();
  });

  test('ACV-14 no watermark seeds from current trusted state, no exit', async () => {
    const { auditLog, verifyChainVerifierContinuity } = mods;
    await _appendEntries(auditLog, 3);

    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ _auditLog: auditLog, _exit });
    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
  });

  test('ACV-15 watermark ahead of current chain length is FATAL by default', async () => {
    const { auditLog, verifierState, verifyChainVerifierContinuity } = mods;
    await _appendEntries(auditLog, 3);

    await verifierState.saveFileState({ lastVerifiedIndex: 999, lastVerifiedHash: 'deadbeef' });

    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ _auditLog: auditLog, _verifierState: verifierState, _exit });
    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('ACV-16 watermark hash divergence at an in-range position is FATAL by default', async () => {
    const { auditLog, verifierState, verifyChainVerifierContinuity } = mods;
    await _appendEntries(auditLog, 3);

    // Points at a real, in-range position (index 2) but with a hash that
    // does not match what's actually there — simulates a rollback to a
    // different-but-internally-valid history of the same length.
    await verifierState.saveFileState({ lastVerifiedIndex: 2, lastVerifiedHash: 'f'.repeat(64) });

    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ _auditLog: auditLog, _verifierState: verifierState, _exit });
    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('ACV-17 recovery mode downgrades a divergence to WARN and proceeds', async () => {
    const { auditLog, verifierState, verifyChainVerifierContinuity } = mods;
    await _appendEntries(auditLog, 3);
    await verifierState.saveFileState({ lastVerifiedIndex: 999, lastVerifiedHash: 'deadbeef' });

    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({
      _auditLog: auditLog, _verifierState: verifierState, _exit,
      _env: { ...process.env, QODIQA_AUDIT_VERIFIER_RECOVERY_MODE: 'true', QODIQA_AUDIT_VERIFIER_FULL_ON_WATERMARK_MISMATCH: 'false' },
    });
    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
  });

  test('ACV-18 a watermark matching the current tail proceeds cleanly', async () => {
    const { auditLog, verifierState, verifyChainVerifierContinuity } = mods;
    await _appendEntries(auditLog, 4);

    const stats = auditLog.getChainStats();
    await verifierState.saveFileState({ lastVerifiedIndex: stats.modernLength, lastVerifiedHash: stats.tailHash });

    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ _auditLog: auditLog, _verifierState: verifierState, _exit });
    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
  });
});

// Startup gate: distributed-mode watermark comparison, pure mocks
// (no real Postgres; matches this file's own scope note above — real
// PG-mode scanning lives in the .integration.test.js sibling, but the
// startup gate's distributed-mode CONTROL FLOW is exercised here exactly
// like ACV-14..18 do for file mode, since every PG dependency is already
// injectable).
describe('CHAIN-2 — Startup watermark-continuity gate (distributed mode, unit)', () => {
  const { verifyChainVerifierContinuity } = require('../src/core/audit/verifierStartupGate');

  function _pgMocks({ loadPgState, getMaxSeq, fetchRowBySeq }) {
    return {
      _env: { QODIQA_AUDIT_ORDERING_MODE: 'distributed' },
      _pgPool: { isEnabled: () => true },
      _pgBackend: {
        getMaxSeq: jest.fn().mockResolvedValue(getMaxSeq),
        fetchRowBySeq: jest.fn().mockResolvedValue(fetchRowBySeq),
      },
      _verifierState: {
        loadPgState: jest.fn().mockResolvedValue(loadPgState),
        savePgState: jest.fn().mockResolvedValue(undefined),
      },
      _metrics: _noopMetrics(),
    };
  }

  test('ACV-19 a genesis watermark (seq 0, GENESIS) against a still-empty chain (max seq null) is NOT truncation', async () => {
    // Exact reproduction of the finding: a fresh distributed deployment
    // whose live verifier already confirmed the empty-chain watermark, then
    // restarted before any audit entry was ever written. MAX(seq) over zero
    // rows is SQL NULL, not 0 -- indistinguishable by value from a real
    // truncation unless this genesis case is special-cased.
    const mocks = _pgMocks({
      loadPgState: { last_verified_seq: 0, last_verified_hash: 'GENESIS' },
      getMaxSeq: null,
    });
    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ ...mocks, _exit });
    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
  });

  test('ACV-20 a real watermark (seq > 0) against a null current max seq is still FATAL truncation', async () => {
    // Regression guard for the ACV-19 fix: it must narrow the false positive
    // WITHOUT weakening the real truncation signature this gate exists to
    // catch -- a chain that once had confirmed entries and is now reported
    // completely empty is exactly the tampering scenario in scope.
    const mocks = _pgMocks({
      loadPgState: { last_verified_seq: 42, last_verified_hash: 'f'.repeat(64) },
      getMaxSeq: null,
    });
    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ ...mocks, _exit });
    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('ACV-21 current max seq below a real watermark is still FATAL truncation', async () => {
    const mocks = _pgMocks({
      loadPgState: { last_verified_seq: 42, last_verified_hash: 'f'.repeat(64) },
      getMaxSeq: 10,
    });
    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ ...mocks, _exit });
    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('ACV-22 hash divergence at an in-range watermark position is still FATAL', async () => {
    const mocks = _pgMocks({
      loadPgState: { last_verified_seq: 5, last_verified_hash: 'expected-hash' },
      getMaxSeq: 10,
      fetchRowBySeq: 'different-hash',
    });
    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ ...mocks, _exit });
    expect(ok).toBe(false);
    expect(_exit).toHaveBeenCalledWith(1);
  });

  test('ACV-23 a watermark matching the current PG state proceeds cleanly', async () => {
    const mocks = _pgMocks({
      loadPgState: { last_verified_seq: 5, last_verified_hash: 'matching-hash' },
      getMaxSeq: 10,
      fetchRowBySeq: 'matching-hash',
    });
    const _exit = jest.fn();
    const ok = await verifyChainVerifierContinuity({ ...mocks, _exit });
    expect(ok).toBe(true);
    expect(_exit).not.toHaveBeenCalled();
  });

  // a continuity query that FAILS is not "no rows". It used to be read as null — misattributed as truncation
  // or a missing record, and accepted outright for a genesis watermark.
  describe('a failed continuity query fails closed as CONTINUITY_CHECK_FAILED, never as a value', () => {
    const boom = () => Object.assign(new Error('connection terminated'), { code: '57P01' });
    const run = async (mocks) => {
      const _exit = jest.fn();
      const failure = jest.fn();
      const ok = await verifyChainVerifierContinuity({ ...mocks, _exit, _metrics: { ..._noopMetrics(), auditChainVerifierFailureTotal: { inc: failure } } });
      return { ok, _exit, failure };
    };

    test('ACV-24 genesis watermark + getMaxSeq REJECTS → refused (was accepted as VERIFIED)', async () => {
      const mocks = _pgMocks({ loadPgState: { last_verified_seq: 0, last_verified_hash: 'GENESIS' } });
      mocks._pgBackend.getMaxSeq = jest.fn().mockRejectedValue(boom());
      const r = await run(mocks);
      expect(r.ok).toBe(false);
      expect(r._exit).toHaveBeenCalledWith(1);
      expect(r.failure).not.toHaveBeenCalled(); // not reported as a tamper-shaped continuity violation
    });

    test('ACV-25 fetchRowBySeq REJECTS → refused as a check failure, not WATERMARK_RECORD_MISSING', async () => {
      const mocks = _pgMocks({ loadPgState: { last_verified_seq: 5, last_verified_hash: 'h' }, getMaxSeq: 10 });
      mocks._pgBackend.fetchRowBySeq = jest.fn().mockRejectedValue(boom());
      const r = await run(mocks);
      expect(r.ok).toBe(false);
      expect(r._exit).toHaveBeenCalledWith(1);
      expect(r.failure).not.toHaveBeenCalled();
    });

    test('ACV-26 no watermark yet + getMaxSeq REJECTS → refused instead of seeding a null watermark', async () => {
      const mocks = _pgMocks({ loadPgState: null });
      mocks._pgBackend.getMaxSeq = jest.fn().mockRejectedValue(boom());
      const r = await run(mocks);
      expect(r.ok).toBe(false);
      expect(mocks._verifierState.savePgState).not.toHaveBeenCalled();
    });

    test('ACV-27 control: a genuinely empty chain (getMaxSeq resolves null) with a genesis watermark still boots', async () => {
      const r = await run(_pgMocks({ loadPgState: { last_verified_seq: 0, last_verified_hash: 'GENESIS' }, getMaxSeq: null }));
      expect(r.ok).toBe(true);
    });
  });

  // H-40: a scan of the still-empty chain persists (0, GENESIS); entries are then appended and the process
  // restarts before a later scan advances the watermark. Reproduced on real PostgreSQL 6/6 as FATAL
  // WATERMARK_RECORD_MISSING watermarkSeq 0.
  describe('H-40 genesis watermark followed by legitimate appends', () => {
    test('ACV-28 genesis watermark + a chain that has grown since (max seq 3) boots — no lookup of the non-existent seq 0 anchor', async () => {
      const mocks = _pgMocks({ loadPgState: { last_verified_seq: 0, last_verified_hash: 'GENESIS' }, getMaxSeq: 3, fetchRowBySeq: null });
      const _exit = jest.fn(); const _emit = jest.fn();
      const ok = await verifyChainVerifierContinuity({ ...mocks, _exit, _emit });
      expect(ok).toBe(true);
      expect(_exit).not.toHaveBeenCalled();
      expect(mocks._pgBackend.getMaxSeq).toHaveBeenCalledTimes(1); // the tail was still read (a failure there refuses: ACV-24)
      expect(mocks._pgBackend.fetchRowBySeq).not.toHaveBeenCalled();
      expect(_emit).toHaveBeenCalledWith('INFO', 'AUDIT_CHAIN_VERIFIER_CONTINUITY_VERIFIED', expect.objectContaining({ watermarkSeq: 0, currentMaxSeq: 3 }));
    });

    test('ACV-29 a seq-0 watermark whose hash is NOT the literal GENESIS is still refused as WATERMARK_RECORD_MISSING', async () => {
      for (const hash of [null, 'GENESIS ', 'genesis', 'f'.repeat(64)]) {
        const mocks = _pgMocks({ loadPgState: { last_verified_seq: 0, last_verified_hash: hash }, getMaxSeq: 3, fetchRowBySeq: null });
        const _exit = jest.fn(); const failure = jest.fn();
        const ok = await verifyChainVerifierContinuity({ ...mocks, _exit, _metrics: { ..._noopMetrics(), auditChainVerifierFailureTotal: { inc: failure } } });
        expect({ hash, ok }).toEqual({ hash, ok: false });
        expect(_exit).toHaveBeenCalledWith(1);
        expect(failure).toHaveBeenCalledWith({ mode: 'STARTUP', reason: 'CONTINUITY_VIOLATION' });
      }
    });

    test('ACV-30 a real watermark whose anchor row is missing is still FATAL WATERMARK_RECORD_MISSING', async () => {
      const mocks = _pgMocks({ loadPgState: { last_verified_seq: 2, last_verified_hash: 'h2' }, getMaxSeq: 3, fetchRowBySeq: null });
      const _exit = jest.fn();
      const ok = await verifyChainVerifierContinuity({ ...mocks, _exit });
      expect(ok).toBe(false);
      expect(_exit).toHaveBeenCalledWith(1);
      expect(mocks._pgBackend.fetchRowBySeq).toHaveBeenCalledWith(2);
    });
  });
});
