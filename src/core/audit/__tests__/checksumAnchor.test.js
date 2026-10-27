'use strict';

/**
 * #2 (finding #109) — checksum anchor isolation.
 *
 * Covers both backends in isolation:
 *   - File anchor: loadChecksum/saveChecksum/saveChecksumFileAsync — same
 *     I/O audit-log.js always did, now just extracted here. resolveFileAnchorPath
 *     env-override vs. co-located default.
 *   - PG anchor: saveChecksumPg/loadChecksumPg — best-effort, isolated
 *     failure domain, no-op when PG disabled, never throws on PG failure.
 */

const ORIGINAL_ENV_ANCHOR_PATH = process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH;

afterEach(() => {
  jest.resetModules();
  jest.restoreAllMocks();
  if (ORIGINAL_ENV_ANCHOR_PATH === undefined) delete process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH;
  else process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH = ORIGINAL_ENV_ANCHOR_PATH;
});

describe('checksumAnchor — resolveFileAnchorPath', () => {
  test('defaults to the co-located <logPath>.sum path when the env override is unset', () => {
    delete process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH;
    jest.resetModules();
    const checksumAnchor = require('../checksumAnchor');

    expect(checksumAnchor.resolveFileAnchorPath('/data/audit.log')).toBe('/data/audit.log.sum');
  });

  test('uses QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH when set, ignoring the log path entirely', () => {
    process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH = '/separate-volume/anchor.sum';
    jest.resetModules();
    const checksumAnchor = require('../checksumAnchor');

    expect(checksumAnchor.resolveFileAnchorPath('/data/audit.log')).toBe('/separate-volume/anchor.sum');
  });
});

describe('checksumAnchor — file anchor (fs mocked)', () => {
  function loadModule() {
    jest.resetModules();
    jest.doMock('fs');
    const fs = require('fs');
    fs.promises = {
      writeFile: jest.fn().mockResolvedValue(undefined),
      rename:    jest.fn().mockResolvedValue(undefined),
      copyFile:  jest.fn().mockResolvedValue(undefined),
      unlink:    jest.fn().mockResolvedValue(undefined),
    };
    const checksumAnchor = require('../checksumAnchor');
    return { checksumAnchor, fs };
  }

  test('loadChecksum returns null when the file does not exist', () => {
    const { checksumAnchor, fs } = loadModule();
    fs.existsSync.mockReturnValue(false);

    expect(checksumAnchor.loadChecksum('/data/audit.log.sum')).toBeNull();
  });

  test('loadChecksum parses and returns the stored {count, tailHash}', () => {
    const { checksumAnchor, fs } = loadModule();
    fs.existsSync.mockReturnValue(true);
    fs.readFileSync.mockReturnValue(JSON.stringify({ count: 5, tailHash: 'abc123' }));

    expect(checksumAnchor.loadChecksum('/data/audit.log.sum')).toEqual({ count: 5, tailHash: 'abc123' });
  });

  test('saveChecksum writes via tmp-file-then-rename', () => {
    const { checksumAnchor, fs } = loadModule();

    checksumAnchor.saveChecksum('/data/audit.log.sum', 3, 'deadbeef');

    expect(fs.writeFileSync).toHaveBeenCalledWith(
      '/data/audit.log.sum.tmp', JSON.stringify({ count: 3, tailHash: 'deadbeef' }), 'utf8',
    );
    expect(fs.renameSync).toHaveBeenCalledWith('/data/audit.log.sum.tmp', '/data/audit.log.sum');
  });

  test('saveChecksum falls back to copy+unlink if rename fails (cross-device)', () => {
    const { checksumAnchor, fs } = loadModule();
    fs.renameSync.mockImplementation(() => { throw new Error('EXDEV'); });

    checksumAnchor.saveChecksum('/data/audit.log.sum', 3, 'deadbeef');

    expect(fs.copyFileSync).toHaveBeenCalledWith('/data/audit.log.sum.tmp', '/data/audit.log.sum');
    expect(fs.unlinkSync).toHaveBeenCalledWith('/data/audit.log.sum.tmp');
  });

  test('saveChecksumFileAsync writes via fsp tmp-file-then-rename', async () => {
    const { checksumAnchor, fs } = loadModule();

    await checksumAnchor.saveChecksumFileAsync('/data/audit.log.sum', 7, 'cafef00d');

    expect(fs.promises.writeFile).toHaveBeenCalledWith(
      '/data/audit.log.sum.tmp', JSON.stringify({ count: 7, tailHash: 'cafef00d' }), 'utf8',
    );
    expect(fs.promises.rename).toHaveBeenCalledWith('/data/audit.log.sum.tmp', '/data/audit.log.sum');
  });
});

describe('checksumAnchor — PG anchor', () => {
  function loadModule({ pgEnabled = true, queryImpl } = {}) {
    jest.resetModules();
    const mockQuery = jest.fn(queryImpl ?? (() => Promise.resolve({ rows: [] })));
    jest.doMock('../../../infra/postgres/pool', () => ({
      isEnabled: jest.fn(() => pgEnabled),
      query: mockQuery,
    }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
    jest.doMock('../../../observability/metrics', () => ({
      auditChecksumAnchorBackend: { set: jest.fn() },
      auditChecksumAnchorLastWriteTimestamp: { set: jest.fn() },
    }));
    const checksumAnchor = require('../checksumAnchor');
    const pgPool = require('../../../infra/postgres/pool');
    const metrics = require('../../../observability/metrics');
    return { checksumAnchor, mockQuery, pgPool, metrics };
  }

  test('saveChecksumPg is a no-op when PG is disabled — no query issued', async () => {
    const { checksumAnchor, mockQuery } = loadModule({ pgEnabled: false });

    await checksumAnchor.saveChecksumPg(3, 'abc');

    expect(mockQuery).not.toHaveBeenCalled();
  });

  test('saveChecksumPg upserts {count, tailHash} and updates metrics on success', async () => {
    const { checksumAnchor, mockQuery, metrics } = loadModule();

    await checksumAnchor.saveChecksumPg(3, 'abc');

    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO audit_checksum_anchor'),
      [3, 'abc'],
      'audit_checksum_anchor_upsert',
    );
    expect(metrics.auditChecksumAnchorBackend.set).toHaveBeenCalledWith({}, 1);
  });

  test('saveChecksumPg never throws when the PG write fails, and records backend=0', async () => {
    const { checksumAnchor, metrics } = loadModule({
      queryImpl: () => Promise.reject(new Error('connection refused')),
    });

    await expect(checksumAnchor.saveChecksumPg(3, 'abc')).resolves.toBeUndefined();
    expect(metrics.auditChecksumAnchorBackend.set).toHaveBeenCalledWith({}, 0);
  });

  test('loadChecksumPg returns null when PG is disabled', async () => {
    const { checksumAnchor, mockQuery } = loadModule({ pgEnabled: false });

    await expect(checksumAnchor.loadChecksumPg()).resolves.toBeNull();
    expect(mockQuery).not.toHaveBeenCalled();
  });

  test('loadChecksumPg returns null when the table has no row yet', async () => {
    const { checksumAnchor } = loadModule({ queryImpl: () => Promise.resolve({ rows: [] }) });

    await expect(checksumAnchor.loadChecksumPg()).resolves.toBeNull();
  });

  test('loadChecksumPg returns {count, tailHash} from the anchor row', async () => {
    const { checksumAnchor } = loadModule({
      queryImpl: () => Promise.resolve({ rows: [{ count: '9', tail_hash: 'ffee00' }] }),
    });

    await expect(checksumAnchor.loadChecksumPg()).resolves.toEqual({ count: 9, tailHash: 'ffee00' });
  });

  test('loadChecksumPg returns null (not throw) when the query fails', async () => {
    const { checksumAnchor } = loadModule({
      queryImpl: () => Promise.reject(new Error('timeout')),
    });

    await expect(checksumAnchor.loadChecksumPg()).resolves.toBeNull();
  });

  test('getBackendStatus reflects pgEnabled and the last write outcome', async () => {
    const { checksumAnchor } = loadModule({ pgEnabled: true });

    await checksumAnchor.saveChecksumPg(1, 'a');
    const status = checksumAnchor.getBackendStatus();

    expect(status.pgEnabled).toBe(true);
    expect(status.lastPgWriteOk).toBe(true);
    expect(status.lastPgWriteAt).toEqual(expect.any(String));
  });
});
