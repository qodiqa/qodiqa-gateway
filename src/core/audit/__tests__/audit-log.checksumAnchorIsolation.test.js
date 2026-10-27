'use strict';

/**
 * #2 (finding #109) — verifyChecksumAnchorIsolation().
 *
 * The whole point of the isolated PG anchor is that it can be validated
 * independently of the audit-log filesystem. These tests mock
 * ./checksumAnchor entirely (not fs) so the isolation check's comparison
 * logic can be exercised without any real file I/O — proving the function
 * itself makes no fs.* calls, matching its own header comment.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../observability/metrics', () => ({
  auditChecksumAnchorMismatchTotal: { inc: jest.fn() },
  auditAppendDurationSeconds:       { observe: jest.fn() },
  auditWalFsyncDurationSeconds:     { observe: jest.fn() },
  auditFsyncDurationSeconds:        { observe: jest.fn() },
  auditChecksumPersistDurationSeconds: { observe: jest.fn() },
  orderingAppendTotal:              { inc: jest.fn() },
  orderingInflightAppends:          { inc: jest.fn(), dec: jest.fn() },
}));

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

/** Loads a fresh audit-log instance with ./checksumAnchor mocked. */
function freshAudit({ loadChecksumPgImpl } = {}) {
  let mod;
  let checksumAnchorMock;
  jest.isolateModules(() => {
    const fs = require('fs');
    fs.existsSync.mockReturnValue(false);
    _installFsPromisesMocks(fs);

    checksumAnchorMock = {
      resolveFileAnchorPath: jest.fn((logPath) => logPath + '.sum'),
      loadChecksum:          jest.fn(() => null),
      saveChecksum:           jest.fn(),
      saveChecksumFileAsync:  jest.fn().mockResolvedValue(undefined),
      saveChecksumPg:         jest.fn().mockResolvedValue(undefined),
      loadChecksumPg:         jest.fn(loadChecksumPgImpl ?? (() => Promise.resolve(null))),
      getBackendStatus:       jest.fn(() => ({ pgEnabled: false, lastPgWriteAt: null, lastPgWriteOk: null })),
    };
    jest.doMock('../checksumAnchor', () => checksumAnchorMock);

    mod = require('../audit-log');
  });
  return { audit: mod, checksumAnchorMock };
}

describe('verifyChecksumAnchorIsolation()', () => {
  beforeEach(() => jest.clearAllMocks());

  test('applicable:false when the PG anchor has no row (PG disabled or fresh install)', async () => {
    const { audit } = freshAudit({ loadChecksumPgImpl: () => Promise.resolve(null) });

    const result = await audit.verifyChecksumAnchorIsolation();

    expect(result).toEqual({ applicable: false, reason: 'PG_ANCHOR_UNAVAILABLE', valid: null });
  });

  test('valid:true when the PG anchor count/hash matches the in-memory chain tail', async () => {
    const { audit, checksumAnchorMock } = freshAudit();
    const e1 = await audit.append(allowParams());

    checksumAnchorMock.loadChecksumPg.mockResolvedValue({ count: 1, tailHash: e1.hash });

    const result = await audit.verifyChecksumAnchorIsolation();

    expect(result.applicable).toBe(true);
    expect(result.valid).toBe(true);
    expect(result.reason).toBeNull();
    expect(result.memoryCount).toBe(1);
    expect(result.memoryTailHash).toBe(e1.hash);
  });

  test('valid:false (PG_ANCHOR_HASH_MISMATCH) when counts match but tail hashes differ', async () => {
    const { audit, checksumAnchorMock } = freshAudit();
    await audit.append(allowParams());

    checksumAnchorMock.loadChecksumPg.mockResolvedValue({ count: 1, tailHash: 'not-the-real-hash' });

    const result = await audit.verifyChecksumAnchorIsolation();

    expect(result.applicable).toBe(true);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('PG_ANCHOR_HASH_MISMATCH');
  });

  test('valid:false (PG_ANCHOR_AHEAD_OF_MEMORY) when the PG anchor count exceeds the in-memory chain length', async () => {
    const { audit, checksumAnchorMock } = freshAudit();
    await audit.append(allowParams());

    checksumAnchorMock.loadChecksumPg.mockResolvedValue({ count: 5, tailHash: 'anything' });

    const result = await audit.verifyChecksumAnchorIsolation();

    expect(result.applicable).toBe(true);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('PG_ANCHOR_AHEAD_OF_MEMORY');
  });

  test('a mismatch increments the auditChecksumAnchorMismatchTotal counter', async () => {
    const { audit, checksumAnchorMock } = freshAudit();
    await audit.append(allowParams());
    checksumAnchorMock.loadChecksumPg.mockResolvedValue({ count: 1, tailHash: 'wrong' });
    const metrics = require('../../../observability/metrics');

    await audit.verifyChecksumAnchorIsolation();

    expect(metrics.auditChecksumAnchorMismatchTotal.inc).toHaveBeenCalledTimes(1);
  });

  test('a valid match does not increment the mismatch counter', async () => {
    const { audit, checksumAnchorMock } = freshAudit();
    const e1 = await audit.append(allowParams());
    checksumAnchorMock.loadChecksumPg.mockResolvedValue({ count: 1, tailHash: e1.hash });
    const metrics = require('../../../observability/metrics');

    await audit.verifyChecksumAnchorIsolation();

    expect(metrics.auditChecksumAnchorMismatchTotal.inc).not.toHaveBeenCalled();
  });

  test('an empty chain (GENESIS) with a matching empty PG anchor is valid', async () => {
    const { audit, checksumAnchorMock } = freshAudit({
      loadChecksumPgImpl: () => Promise.resolve({ count: 0, tailHash: null }),
    });

    const result = await audit.verifyChecksumAnchorIsolation();

    expect(result.valid).toBe(true);
    expect(result.memoryCount).toBe(0);
    expect(result.memoryTailHash).toBeNull();
  });

  test('every successful append dual-writes to the PG anchor (fire-and-forget, not awaited by the append itself)', async () => {
    const { audit, checksumAnchorMock } = freshAudit();

    const entry = await audit.append(allowParams());

    // the file anchor now also carries the v2 lifetime-counter block
    // (totalCount/modernCount/allow/block/replay/headHash/byteLength) — the
    // original three arguments are unchanged; the PG anchor keeps its
    // original two-argument shape (fixed schema).
    expect(checksumAnchorMock.saveChecksumFileAsync).toHaveBeenCalledWith(
      expect.any(String), 1, entry.hash,
      expect.objectContaining({ totalCount: 1, modernCount: 1, allowCount: 1, blockCount: 0, headHash: entry.hash }),
    );
    expect(checksumAnchorMock.saveChecksumPg).toHaveBeenCalledWith(1, entry.hash);
  });
});
