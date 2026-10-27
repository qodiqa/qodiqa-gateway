'use strict';

/**
 * appendMandatory() — bounded-retry, fail-closed audit append — Tests
 *
 * Regression suite for the "Audit/Evidence Pipeline Fail-Closed Remediation":
 * appendMandatory() wraps the synchronous, throw-on-first-failure append()
 * with bounded retry for transient filesystem failures, while validation/
 * duplicate/replay errors still fail immediately (retrying them would waste
 * the retry budget on a condition that can never change).
 *
 * AM-01…04  Retryable failure: retried, succeeds within budget
 * AM-05…08  Retryable failure: budget exhausted → AUDIT_PERSISTENCE_FAILED
 * AM-09…13  Non-retryable failures (validation/duplicate/replay) never retried
 * AM-14…16  Configuration overrides (opts.maxRetries / opts.retryDelayMs)
 * AM-17…20  Metrics (retries counter, failure counter, stage labels)
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

// S33: this suite injects transient I/O failures through fs.promises.writeFile — the WAL write call site of the
// create/unlink-per-batch WAL path, i.e. the QODIQA_AUDIT_WAL_REUSE=false rollback path, which it is pinned to. The
// retry/fail-closed contract on the default reused-WAL path (failures on the held handle's write) is covered by
// walReuse.test.js (WR-AM-*).
const _prevWalReuse = process.env.QODIQA_AUDIT_WAL_REUSE;
process.env.QODIQA_AUDIT_WAL_REUSE = 'false';
afterAll(() => { if (_prevWalReuse === undefined) delete process.env.QODIQA_AUDIT_WAL_REUSE; else process.env.QODIQA_AUDIT_WAL_REUSE = _prevWalReuse; });

const fs     = require('fs');
const crypto = require('crypto');

// jest.mock('fs') automocks every fs.* function but does NOT create an
// fs.promises object at all (it stays undefined) — append()'s I/O is now
// entirely via fs.promises.*, so without this the module-scope `const fsp =
// fs.promises;` in audit-log.js would be undefined and every append() would
// reject with "Cannot read properties of undefined". Installed once, before
// audit-log.js is required below, exactly as CORE loadFromDisk needs it.
fs.promises = {
  writeFile:  jest.fn().mockResolvedValue(undefined),
  appendFile: jest.fn().mockResolvedValue(undefined),
  open:       jest.fn().mockResolvedValue({
    sync:  jest.fn().mockResolvedValue(undefined),
    close: jest.fn().mockResolvedValue(undefined),
    // S33: the reused WAL is written/truncated through its held FileHandle (real fs.promises FileHandle API)
    write:    jest.fn().mockImplementation((buf, off, len) => Promise.resolve({ bytesWritten: len, buffer: buf })),
    truncate: jest.fn().mockResolvedValue(undefined),
  }),
  rename:    jest.fn().mockResolvedValue(undefined),
  copyFile:  jest.fn().mockResolvedValue(undefined),
  unlink:    jest.fn().mockResolvedValue(undefined),
};

// Required ONCE at module scope (not per-test via jest.resetModules()) — this
// module holds an in-process chain, and re-requiring it fresh with
// resetModules() would decouple this file's `fs` reference from the one
// audit-log.js actually calls internally (resetModules() gives every fresh
// require('fs') a brand new automock instance). Every test uses a unique
// artifactId/nonce so entries never collide across the shared chain.
const auditLog = require('../audit-log');
const metrics  = require('../../../observability/metrics');

function uuid() { return crypto.randomUUID(); }

function allowParams(overrides = {}) {
  return {
    artifactId:         uuid(),
    inputHash:          'a'.repeat(64),
    decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:          's'.repeat(64),
    requestHash:        'r'.repeat(64),
    policyHash:         'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

beforeEach(() => {
  // Reset only what tests configure per-case — never resetModules()/resetAllMocks()
  // here, since that would strip pg-audit-backend's resolved-value mock and
  // decouple audit-log.js's internal `fs` reference from this file's, causing
  // every subsequent fs.promises.writeFile mockImplementation to silently no-op.
  // mockReset() (not mockClear()) is important: it also drops any
  // mockImplementation/mockImplementationOnce left over from the previous
  // test, reverting the mock to a bare jest.fn() — which resolves `undefined`
  // when awaited, i.e. "success", exactly like the old default no-op
  // fs.promises.writeFile mock did.
  fs.promises.writeFile.mockReset();
  metrics.auditAppendRetriesTotal.inc.mockRestore?.();
  metrics.auditAppendFailedTotal.inc.mockRestore?.();
  jest.spyOn(metrics.auditAppendRetriesTotal, 'inc');
  jest.spyOn(metrics.auditAppendFailedTotal, 'inc');
});

// Makes the very first fs.promises.writeFile call in the current test reject,
// then falls back to the real mock behavior (a no-op resolving to undefined)
// for every subsequent call — i.e. one transient failure, then success.
// _appendOne's WAL-write step (and _saveChecksumAsync's tmp-file write) are
// the only two call sites of fs.promises.writeFile, matching the old
// fs.promises.writeFile call sites exactly, so the call-count assertions below are
// unchanged from before this file was retargeted.
function _throwOnceOnWriteFileSync(message = 'EBUSY: resource busy or locked') {
  fs.promises.writeFile.mockImplementationOnce(() => {
    const err = new Error(message);
    err.code  = 'EBUSY';
    throw err;
  });
}

function _alwaysThrowOnWriteFileSync(message = 'ENOSPC: no space left on device') {
  fs.promises.writeFile.mockImplementation(() => {
    const err = new Error(message);
    err.code  = 'ENOSPC';
    throw err;
  });
}

// ═════════════════════════════════════════════════════════════════════════════
// AM-01…04  Retryable failure: retried, succeeds within budget
// ═════════════════════════════════════════════════════════════════════════════

describe('Retryable failure recovers within the retry budget', () => {
  test('AM-01: one transient failure then success returns the committed entry', async () => {
    _throwOnceOnWriteFileSync();
    const result = await auditLog.appendMandatory(allowParams(), { retryDelayMs: 1 });
    expect(result).toBeDefined();
    expect(result.decision).toBe('ALLOW');
  });

  test('AM-02: fs.promises.writeFile is called more than once when the first attempt fails', async () => {
    _throwOnceOnWriteFileSync();
    const callsBefore = fs.promises.writeFile.mock.calls.length;
    await auditLog.appendMandatory(allowParams(), { retryDelayMs: 1 });
    expect(fs.promises.writeFile.mock.calls.length).toBeGreaterThan(callsBefore + 1);
  });

  test('AM-03: the committed entry is indistinguishable from a first-try success', async () => {
    _throwOnceOnWriteFileSync();
    const result = await auditLog.appendMandatory(allowParams(), { retryDelayMs: 1 });
    expect(typeof result.hash).toBe('string');
    expect(result.hash).toHaveLength(64);
  });

  test('AM-04: two transient failures within a 3-attempt budget still succeeds', async () => {
    fs.promises.writeFile
      .mockImplementationOnce(() => { throw Object.assign(new Error('EBUSY'), { code: 'EBUSY' }); })
      .mockImplementationOnce(() => { throw Object.assign(new Error('EBUSY'), { code: 'EBUSY' }); });
    const result = await auditLog.appendMandatory(allowParams(), { maxRetries: 3, retryDelayMs: 1 });
    expect(result).toBeDefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AM-05…08  Retryable failure: budget exhausted → AUDIT_PERSISTENCE_FAILED
// ═════════════════════════════════════════════════════════════════════════════

describe('Retryable failure exhausting the retry budget fails closed', () => {
  test('AM-05: persistent fs failure throws AUDIT_PERSISTENCE_FAILED', async () => {
    _alwaysThrowOnWriteFileSync();
    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 2, retryDelayMs: 1 }))
      .rejects.toThrow(/AUDIT_PERSISTENCE_FAILED/);
  });

  test('AM-06: the thrown error carries code AUDIT_PERSISTENCE_FAILED', async () => {
    _alwaysThrowOnWriteFileSync();
    try {
      await auditLog.appendMandatory(allowParams(), { maxRetries: 2, retryDelayMs: 1 });
      throw new Error('should not reach here');
    } catch (err) {
      expect(err.code).toBe('AUDIT_PERSISTENCE_FAILED');
    }
  });

  test('AM-07: the thrown error preserves the original error as .cause', async () => {
    _alwaysThrowOnWriteFileSync('ENOSPC: disk full');
    try {
      await auditLog.appendMandatory(allowParams(), { maxRetries: 2, retryDelayMs: 1 });
      throw new Error('should not reach here');
    } catch (err) {
      expect(err.cause).toBeDefined();
      expect(err.cause.message).toMatch(/ENOSPC/);
    }
  });

  test('AM-08: .attempts reports maxRetries + 1 total attempts made', async () => {
    _alwaysThrowOnWriteFileSync();
    try {
      await auditLog.appendMandatory(allowParams(), { maxRetries: 2, retryDelayMs: 1 });
      throw new Error('should not reach here');
    } catch (err) {
      expect(err.attempts).toBe(3);
    }
  });

  // #9: ENOSPC exhaustion additionally emits a distinct AUDIT_DISK_FULL
  // event, alongside (not instead of) the existing AUDIT_PERSISTENCE_FAILED throw.
  test('AM-08b: ENOSPC exhaustion emits AUDIT_DISK_FULL at CRITICAL, in addition to throwing', async () => {
    const { emit } = require('../../../../services/logger');
    emit.mockClear();
    _alwaysThrowOnWriteFileSync(); // defaults to err.code = 'ENOSPC'

    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 2, retryDelayMs: 1, stage: 'ALLOW' }))
      .rejects.toThrow(/AUDIT_PERSISTENCE_FAILED/);

    expect(emit).toHaveBeenCalledWith('CRITICAL', 'AUDIT_DISK_FULL', { stage: 'ALLOW', attempts: 3 });
  });

  // and it is counted, so QodiqaAuditDiskFull can alert without a log pipeline.
  test('AM-08d: ENOSPC exhaustion increments qodiqa_audit_disk_full_total{stage}; EIO does not', async () => {
    const inc = jest.spyOn(metrics.auditDiskFullTotal, 'inc');
    _alwaysThrowOnWriteFileSync();
    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 1, retryDelayMs: 1, stage: 'ALLOW' })).rejects.toThrow(/AUDIT_PERSISTENCE_FAILED/);
    expect(inc).toHaveBeenCalledWith({ stage: 'ALLOW' });
    inc.mockClear();
    fs.promises.writeFile.mockImplementation(() => { const err = new Error('EIO: i/o error'); err.code = 'EIO'; throw err; });
    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 1, retryDelayMs: 1 })).rejects.toThrow(/AUDIT_PERSISTENCE_FAILED/);
    expect(inc).not.toHaveBeenCalled();
    inc.mockRestore();
  });

  test('AM-08c: a non-ENOSPC retryable failure does NOT emit AUDIT_DISK_FULL', async () => {
    const { emit } = require('../../../../services/logger');
    emit.mockClear();
    fs.promises.writeFile.mockImplementation(() => {
      const err = new Error('EIO: i/o error');
      err.code  = 'EIO';
      throw err;
    });

    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 1, retryDelayMs: 1 }))
      .rejects.toThrow(/AUDIT_PERSISTENCE_FAILED/);

    expect(emit).not.toHaveBeenCalledWith('CRITICAL', 'AUDIT_DISK_FULL', expect.any(Object));
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AM-09…13  Non-retryable failures are never retried
// ═════════════════════════════════════════════════════════════════════════════

describe('Non-retryable (validation/duplicate/replay) errors fail immediately, no retry', () => {
  test('AM-09: invalid decision throws immediately without touching the filesystem', async () => {
    const writeCallsBefore = fs.promises.writeFile.mock.calls.length;
    await expect(auditLog.appendMandatory({ decision: 'MAYBE' }, { maxRetries: 5, retryDelayMs: 1 }))
      .rejects.toThrow(/invalid_decision/);
    expect(fs.promises.writeFile.mock.calls.length).toBe(writeCallsBefore);
  });

  test('AM-10: already_executed (duplicate artifactId) is not retried', async () => {
    const params = allowParams();
    await auditLog.appendMandatory(params, { retryDelayMs: 1 }); // first: succeeds
    const writeCallsBefore = fs.promises.writeFile.mock.calls.length;
    await expect(auditLog.appendMandatory(params, { maxRetries: 5, retryDelayMs: 1 }))
      .rejects.toThrow(/already_executed/);
    // No WAL-write retry attempts for a duplicate — it fails before any fs call.
    expect(fs.promises.writeFile.mock.calls.length).toBe(writeCallsBefore);
  });

  test('AM-11: replay_detected (duplicate nonce) is not retried', async () => {
    const nonce = uuid();
    await auditLog.appendMandatory(allowParams({ nonce }), { retryDelayMs: 1 });
    await expect(auditLog.appendMandatory(allowParams({ nonce }), { maxRetries: 5, retryDelayMs: 1 }))
      .rejects.toThrow(/replay_detected/);
  });

  test('AM-12: non-retryable errors do not increment the retry metric', async () => {
    await expect(auditLog.appendMandatory({ decision: 'MAYBE' }, { maxRetries: 5, retryDelayMs: 1 }))
      .rejects.toThrow();
    expect(metrics.auditAppendRetriesTotal.inc).not.toHaveBeenCalled();
  });

  test('AM-13: non-retryable errors do not increment the exhausted-failure metric', async () => {
    await expect(auditLog.appendMandatory({ decision: 'MAYBE' }, { maxRetries: 5, retryDelayMs: 1 }))
      .rejects.toThrow();
    expect(metrics.auditAppendFailedTotal.inc).not.toHaveBeenCalled();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AM-14…16  Configuration overrides
// ═════════════════════════════════════════════════════════════════════════════

describe('Configuration overrides', () => {
  test('AM-14: maxRetries: 0 means exactly one attempt, no retries', async () => {
    _alwaysThrowOnWriteFileSync();
    const writeCallsBefore = fs.promises.writeFile.mock.calls.length;
    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 0, retryDelayMs: 1 }))
      .rejects.toThrow(/AUDIT_PERSISTENCE_FAILED/);
    // Exactly one WAL-write attempt (retryDelayMs skipped since attempt === maxRetries immediately).
    expect(fs.promises.writeFile.mock.calls.length).toBe(writeCallsBefore + 1);
  });

  test('AM-15: a higher maxRetries allows recovery from more transient failures', async () => {
    fs.promises.writeFile
      .mockImplementationOnce(() => { throw Object.assign(new Error('x'), { code: 'EBUSY' }); })
      .mockImplementationOnce(() => { throw Object.assign(new Error('x'), { code: 'EBUSY' }); })
      .mockImplementationOnce(() => { throw Object.assign(new Error('x'), { code: 'EBUSY' }); });
    const result = await auditLog.appendMandatory(allowParams(), { maxRetries: 4, retryDelayMs: 1 });
    expect(result).toBeDefined();
  });

  test('AM-16: retryDelayMs is honored between attempts', async () => {
    _throwOnceOnWriteFileSync();
    const start = Date.now();
    await auditLog.appendMandatory(allowParams(), { maxRetries: 2, retryDelayMs: 200 });
    expect(Date.now() - start).toBeGreaterThanOrEqual(190);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// AM-17…20  Metrics
// ═════════════════════════════════════════════════════════════════════════════

describe('Metrics', () => {
  test('AM-17: a successful first attempt increments neither retry nor failure metrics', async () => {
    await auditLog.appendMandatory(allowParams(), { retryDelayMs: 1 });
    expect(metrics.auditAppendRetriesTotal.inc).not.toHaveBeenCalled();
    expect(metrics.auditAppendFailedTotal.inc).not.toHaveBeenCalled();
  });

  test('AM-18: each retry attempt increments the retries counter with the stage label', async () => {
    _throwOnceOnWriteFileSync();
    await auditLog.appendMandatory(allowParams(), { retryDelayMs: 1, stage: 'ALLOW' });
    expect(metrics.auditAppendRetriesTotal.inc).toHaveBeenCalledWith({ stage: 'ALLOW' });
  });

  test('AM-19: exhausting retries increments the failure counter with the stage label', async () => {
    _alwaysThrowOnWriteFileSync();
    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 1, retryDelayMs: 1, stage: 'BLOCK' }))
      .rejects.toThrow();
    expect(metrics.auditAppendFailedTotal.inc).toHaveBeenCalledWith({ stage: 'BLOCK' });
  });

  test('AM-20: stage defaults to UNKNOWN when not supplied', async () => {
    _alwaysThrowOnWriteFileSync();
    await expect(auditLog.appendMandatory(allowParams(), { maxRetries: 0, retryDelayMs: 1 }))
      .rejects.toThrow();
    expect(metrics.auditAppendFailedTotal.inc).toHaveBeenCalledWith({ stage: 'UNKNOWN' });
  });
});
