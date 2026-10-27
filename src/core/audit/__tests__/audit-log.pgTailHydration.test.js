'use strict';

/**
 * FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION — single-node startup
 * hydration of _tailHash from PostgreSQL's true last row.
 *
 * The fresh-process-against-populated-DB scenario reproduced live (disposable
 * DB, two real processes, see FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION-
 * REPORT.md) becomes PGH-01 below: a fresh (empty-file) process must hydrate
 * _tailHash from pg-audit-backend.getChainTail() before its first append,
 * instead of unconditionally re-claiming 'GENESIS' against a table that may
 * already hold a committed chain from a prior process lifetime.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry:   jest.fn().mockResolvedValue(undefined),
  getChainTail:   jest.fn().mockResolvedValue(null),
  setKeyInfoResolver: jest.fn(),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../observability/metrics', () => ({
  auditPgHydrationFailedTotal:         { inc: jest.fn() },
  auditChecksumAnchorMismatchTotal:    { inc: jest.fn() },
  auditAppendDurationSeconds:          { observe: jest.fn() },
  auditWalFsyncDurationSeconds:        { observe: jest.fn() },
  auditFsyncDurationSeconds:           { observe: jest.fn() },
  auditChecksumPersistDurationSeconds: { observe: jest.fn() },
  orderingAppendTotal:                 { inc: jest.fn() },
  orderingInflightAppends:             { inc: jest.fn(), dec: jest.fn() },
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

/** Loads a fresh audit-log instance with pg-audit-backend.getChainTail mocked. */
function freshAudit({ getChainTailImpl } = {}) {
  let mod;
  let pgAuditBackendMock;
  jest.isolateModules(() => {
    const fs = require('fs');
    fs.existsSync.mockReturnValue(false); // fresh process: no on-disk audit.log
    _installFsPromisesMocks(fs);

    jest.doMock('../checksumAnchor', () => ({
      resolveFileAnchorPath: jest.fn((logPath) => logPath + '.sum'),
      loadChecksum:          jest.fn(() => null),
      saveChecksum:           jest.fn(),
      saveChecksumFileAsync:  jest.fn().mockResolvedValue(undefined),
      saveChecksumPg:         jest.fn().mockResolvedValue(undefined),
      loadChecksumPg:         jest.fn(() => Promise.resolve(null)),
      getBackendStatus:       jest.fn(() => ({ pgEnabled: false, lastPgWriteAt: null, lastPgWriteOk: null })),
    }));

    pgAuditBackendMock = require('../../../infra/postgres/pg-audit-backend');
    pgAuditBackendMock.getChainTail = jest.fn(getChainTailImpl ?? (() => Promise.resolve(null)));

    mod = require('../audit-log');
  });
  return { audit: mod, pgAuditBackend: pgAuditBackendMock };
}

describe('FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION — PG tail hydration', () => {
  beforeEach(() => jest.clearAllMocks());

  test('PGH-01 fresh process (empty file) hydrates prevHash from PG\'s true last row instead of GENESIS — the repro scenario', async () => {
    const priorHash = 'f'.repeat(64);
    const { audit, pgAuditBackend } = freshAudit({
      getChainTailImpl: () => Promise.resolve({ hash: priorHash, seq: 159 }),
    });

    const entry = await audit.append(allowParams());

    expect(pgAuditBackend.getChainTail).toHaveBeenCalledTimes(1);
    expect(entry.prevHash).toBe(priorHash);
    expect(entry.prevHash).not.toBe('GENESIS');
  });

  test('PGH-02 genuinely empty PG table (getChainTail resolves null) leaves the first entry at GENESIS, no error', async () => {
    const { audit, pgAuditBackend } = freshAudit({ getChainTailImpl: () => Promise.resolve(null) });
    const logger  = require('../../../../services/logger');
    const metrics = require('../../../observability/metrics');

    const entry = await audit.append(allowParams());

    expect(pgAuditBackend.getChainTail).toHaveBeenCalledTimes(1);
    expect(entry.prevHash).toBe('GENESIS');
    expect(metrics.auditPgHydrationFailedTotal.inc).not.toHaveBeenCalled();
    expect(logger.emit).not.toHaveBeenCalledWith('ERROR', 'AUDIT_PG_HYDRATION_FAILED', expect.anything());
  });

  test('PGH-03 hydration failure (PG unreachable) falls back to GENESIS, but never silently — ERROR logged + counter incremented', async () => {
    const pgError = Object.assign(new Error('connection terminated'), { code: 'ECONNRESET' });
    const { audit } = freshAudit({ getChainTailImpl: () => Promise.reject(pgError) });
    const logger  = require('../../../../services/logger');
    const metrics = require('../../../observability/metrics');

    const entry = await audit.append(allowParams());

    expect(entry.prevHash).toBe('GENESIS'); // same fallback behavior as before the fix
    expect(metrics.auditPgHydrationFailedTotal.inc).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith('ERROR', 'AUDIT_PG_HYDRATION_FAILED', expect.objectContaining({
      error: 'connection terminated',
      code:  'ECONNRESET',
    }));
  });

  test('PGH-04 hydration is attempted at most once per process (memoized) — second append never re-queries PG', async () => {
    const priorHash = 'e'.repeat(64);
    const { audit, pgAuditBackend } = freshAudit({
      getChainTailImpl: () => Promise.resolve({ hash: priorHash, seq: 1 }),
    });

    const e1 = await audit.append(allowParams());
    const e2 = await audit.append(allowParams());

    expect(pgAuditBackend.getChainTail).toHaveBeenCalledTimes(1);
    expect(e1.prevHash).toBe(priorHash);
    expect(e2.prevHash).toBe(e1.hash); // second entry chains off the first, in-process, as normal
  });

  test('PGH-05 once _tailHash has already advanced in-process, a later append never re-queries PG even though the guard condition is re-checked', async () => {
    const { audit, pgAuditBackend } = freshAudit({ getChainTailImpl: () => Promise.resolve(null) });

    await audit.append(allowParams()); // first append: hydration runs once, PG empty, stays GENESIS
    await audit.append(allowParams()); // second append: _tailHash is no longer GENESIS either way

    expect(pgAuditBackend.getChainTail).toHaveBeenCalledTimes(1);
  });
});
