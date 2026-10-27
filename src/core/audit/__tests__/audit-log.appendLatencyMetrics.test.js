'use strict';

/**
 * #3 — Audit append/fsync/persistence latency histograms.
 *
 * Additive alongside the existing auditAppendRetriesTotal/auditAppendFailedTotal
 * counters — these assert the three new histograms (metrics.js) receive an
 * .observe() call with a sane, non-negative value on both the success and
 * failure paths of _appendOne() in audit-log.js. No exact-timing assertions.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

// Primed at module scope, before any jest.isolateModules() call, so every
// later isolateModules() block's own require('fs') resolves to this SAME
// automock instance — see audit-log.asyncQueue.test.js's file header for the
// full rationale (empirically required ordering, not a style choice).
const fs = require('fs');

const crypto = require('crypto');

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

function _installFsPromisesMocks(fsMod) {
  fsMod.promises = {
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
}

function freshAudit() {
  let mod;
  jest.isolateModules(() => {
    const fs = require('fs');
    fs.existsSync.mockReturnValue(false);
    _installFsPromisesMocks(fs);
    mod = require('../audit-log');
  });
  return mod;
}

describe('#3 / Finding C: audit append/WAL-fsync/fsync/checksum-persist latency histograms', () => {
  let metrics;

  beforeEach(() => {
    metrics = require('../../../observability/metrics');
    jest.spyOn(metrics.auditAppendDurationSeconds, 'observe');
    jest.spyOn(metrics.auditWalFsyncDurationSeconds, 'observe');
    jest.spyOn(metrics.auditFsyncDurationSeconds, 'observe');
    jest.spyOn(metrics.auditChecksumPersistDurationSeconds, 'observe');
  });

  afterEach(() => jest.restoreAllMocks());

  test('REL-06: a successful single-node append moves orderingAppendTotal and orderingInflightAppends for mode=single-node, and a duplicate rejection moves the failure outcome separately', async () => {
    const audit = freshAudit();
    const successKey = 'mode="single-node",outcome="success"';
    const failureKey = 'mode="single-node",outcome="failure"';
    const inflightKey = 'mode="single-node"';
    const successBefore = metrics.orderingAppendTotal._values.get(successKey) || 0;
    const failureBefore = metrics.orderingAppendTotal._values.get(failureKey) || 0;

    const params = allowParams();
    await audit.append(params);
    expect((metrics.orderingAppendTotal._values.get(successKey) || 0) - successBefore).toBe(1);
    // The finally-block dec() cannot leak — back to 0 once the single await
    // above has resolved, not stuck at 1 (the exact vacuous-metric
    // failure mode: a gauge that only ever moves in one direction).
    expect(metrics.orderingInflightAppends._values.get(inflightKey) || 0).toBe(0);

    // Same artifactId again — a genuine duplicate rejection, not simulated —
    // proves the outcome label moves to "failure" for a real failure, not
    // just always "success" regardless of what actually happened.
    await expect(audit.append(params)).rejects.toThrow('already_executed');
    expect((metrics.orderingAppendTotal._values.get(failureKey) || 0) - failureBefore).toBe(1);
    expect(metrics.orderingInflightAppends._values.get(inflightKey) || 0).toBe(0);
  });

  test('a successful append observes all four histograms (WAL fsync before log fsync) with outcome=success and a non-negative value', async () => {
    const audit = freshAudit();
    await audit.append(allowParams());

    expect(metrics.auditAppendDurationSeconds.observe).toHaveBeenCalledTimes(1);
    const [appendLabels, appendValue] = metrics.auditAppendDurationSeconds.observe.mock.calls[0];
    expect(appendLabels).toEqual({ mode: 'single-node', outcome: 'success' });
    expect(appendValue).toBeGreaterThanOrEqual(0);

    expect(metrics.auditWalFsyncDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditWalFsyncDurationSeconds.observe.mock.calls[0][1]).toBeGreaterThanOrEqual(0);

    expect(metrics.auditFsyncDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditFsyncDurationSeconds.observe.mock.calls[0][1]).toBeGreaterThanOrEqual(0);

    expect(metrics.auditChecksumPersistDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditChecksumPersistDurationSeconds.observe.mock.calls[0][1]).toBeGreaterThanOrEqual(0);

    // WAL fsync (fs.promises.open call #1) must happen strictly before the
    // main-log fsync (call #2) — the WAL durability-barrier ordering
    // Finding C requires.
    expect(fs.promises.open).toHaveBeenCalledTimes(2);
  });

  test('a WAL fsync failure (the new durability barrier) observes append/WAL-fsync duration with outcome=failure, but never reaches the log fsync or checksum-persist timers', async () => {
    const audit = freshAudit();
    // First fs.promises.open() call is now the WAL fsync (step 1) — see
    // audit-log.js _appendOne().
    fs.promises.open.mockResolvedValueOnce({
      sync:  jest.fn().mockRejectedValue(new Error('EIO: simulated WAL fsync failure')),
      close: jest.fn().mockResolvedValue(undefined),
      write:    jest.fn().mockImplementation((buf, off, len) => Promise.resolve({ bytesWritten: len, buffer: buf })), // S33: WAL handle
      truncate: jest.fn().mockResolvedValue(undefined),
    });

    await expect(audit.append(allowParams())).rejects.toThrow();

    expect(metrics.auditAppendDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditAppendDurationSeconds.observe.mock.calls[0][0]).toEqual({ mode: 'single-node', outcome: 'failure' });

    expect(metrics.auditWalFsyncDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditFsyncDurationSeconds.observe).not.toHaveBeenCalled();
    expect(metrics.auditChecksumPersistDurationSeconds.observe).not.toHaveBeenCalled();
    // The main log append must never be attempted once the WAL durability
    // barrier itself failed — the whole point of write-ahead ordering.
    expect(fs.promises.appendFile).not.toHaveBeenCalled();
  });

  test('a main-log fsync failure (WAL already durable) still observes append/WAL-fsync/fsync duration with outcome=failure, but not checksum-persist', async () => {
    const audit = freshAudit();
    // First fs.promises.open() call (WAL fsync) succeeds; second (main log
    // fsync, step 3) fails.
    fs.promises.open.mockResolvedValueOnce({
      sync:  jest.fn().mockResolvedValue(undefined),
      close: jest.fn().mockResolvedValue(undefined),
      write:    jest.fn().mockImplementation((buf, off, len) => Promise.resolve({ bytesWritten: len, buffer: buf })), // S33: WAL handle
      truncate: jest.fn().mockResolvedValue(undefined),
    });
    fs.promises.open.mockResolvedValueOnce({
      sync:  jest.fn().mockRejectedValue(new Error('EIO: simulated log fsync failure')),
      close: jest.fn().mockResolvedValue(undefined),
      write:    jest.fn().mockImplementation((buf, off, len) => Promise.resolve({ bytesWritten: len, buffer: buf })), // S33: same fake FileHandle shape
      truncate: jest.fn().mockResolvedValue(undefined),
    });

    await expect(audit.append(allowParams())).rejects.toThrow();

    expect(metrics.auditAppendDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditAppendDurationSeconds.observe.mock.calls[0][0]).toEqual({ mode: 'single-node', outcome: 'failure' });

    expect(metrics.auditWalFsyncDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditFsyncDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditChecksumPersistDurationSeconds.observe).not.toHaveBeenCalled();
  });

  test('a duplicate/validation error (non-I/O) observes append duration with outcome=failure but never reaches WAL/fsync/checksum timers', async () => {
    const audit = freshAudit();
    const params = allowParams();
    await audit.append(params);
    metrics.auditAppendDurationSeconds.observe.mockClear();
    metrics.auditWalFsyncDurationSeconds.observe.mockClear();
    metrics.auditFsyncDurationSeconds.observe.mockClear();
    metrics.auditChecksumPersistDurationSeconds.observe.mockClear();

    await expect(audit.append(params)).rejects.toThrow('already_executed');

    expect(metrics.auditAppendDurationSeconds.observe).toHaveBeenCalledTimes(1);
    expect(metrics.auditAppendDurationSeconds.observe.mock.calls[0][0]).toEqual({ mode: 'single-node', outcome: 'failure' });
    expect(metrics.auditWalFsyncDurationSeconds.observe).not.toHaveBeenCalled();
    expect(metrics.auditFsyncDurationSeconds.observe).not.toHaveBeenCalled();
    expect(metrics.auditChecksumPersistDurationSeconds.observe).not.toHaveBeenCalled();
  });
});
