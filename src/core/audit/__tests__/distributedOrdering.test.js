'use strict';

/**
 * distributedOrdering.js — SCAL-11 Unit Tests
 *
 * DO-01  Happy path: locks audit_chain_head, inserts, updates head, commits —
 *        under READ COMMITTED isolation (not the pool default REPEATABLE READ)
 * DO-02  Missing audit_chain_head seed row throws AUDIT_CHAIN_HEAD_MISSING
 * DO-03  23505 on artifact_id constraint -> already_executed error
 * DO-04  23505 on nonce constraint -> replay_detected error
 * DO-05  23505 on prev_hash constraint -> AUDIT_CHAIN_CONCURRENT_CONFLICT (retryable)
 * DO-06  Field validation (entryBuilder.normalizeFields) runs before any PG call
 * DO-07  A non-23505 PG error (e.g. connection failure) passes through untranslated
 * DO-08 a head at a HIGHER schema version refuses the append (invalid_schema_downgrade), nothing is written
 * DO-09 the head update writes the new entry's schema version (v8 over a v7 head advances it); an equal version is fine
 * DO-10 a head version that is not a non-negative integer fails closed
 *
 * Strategy: mirrors src/infra/postgres/__tests__/pool.isolation.test.js —
 * jest.resetModules() + jest.doMock('pg', ...) loads a fresh pool.js backed
 * by a fake pg.Pool, so no real database connection is needed.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
function validFields(overrides = {}) {
  return {
    artifactId: 'artifact-1',
    inputHash:  'a'.repeat(64),
    decision:   'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:  'sig',
    requestHash: 'b'.repeat(64),
    policyHash:  'c'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

function pgUniqueViolation(constraint) {
  const e = new Error(`duplicate key value violates unique constraint "${constraint}"`);
  e.code = '23505';
  e.constraint = constraint;
  return e;
}

describe('SCAL-11 — distributedOrdering.appendEntry', () => {
  let mockClientQuery;
  let mockClientRelease;

  function loadModules() {
    process.env.QODIQA_PG_ENABLED = 'true';
    const pool = require('../../../infra/postgres/pool');
    pool.initialize();
    const distributedOrdering = require('../distributedOrdering');
    return { pool, distributedOrdering };
  }

  beforeEach(() => {
    jest.resetModules();

    mockClientRelease = jest.fn();
    mockClientQuery    = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });

    const client = { query: mockClientQuery, release: mockClientRelease };
    jest.doMock('pg', () => ({
      Pool: jest.fn().mockImplementation(() => ({
        connect:      jest.fn().mockResolvedValue(client),
        on:           jest.fn(),
        end:          jest.fn().mockResolvedValue(),
        waitingCount: 0,
        options:      { max: 10 },
      })),
    }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
  });

  afterEach(() => {
    delete process.env.QODIQA_PG_ENABLED;
  });

  test('DO-01 happy path: locks head under READ COMMITTED, inserts, updates head, commits', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) {
        return { rows: [{ tail_hash: 'GENESIS', tail_seq: '0', tail_schema_version: 0 }] };
      }
      return { rows: [], rowCount: 0 };
    });

    const { distributedOrdering } = loadModules();
    const entry = await distributedOrdering.appendEntry(validFields());

    const sqls = mockClientQuery.mock.calls.map(c => c[0]);
    expect(sqls[0]).toBe('BEGIN ISOLATION LEVEL READ COMMITTED');
    expect(sqls.some(s => s.includes('FROM audit_chain_head FOR UPDATE'))).toBe(true);
    expect(sqls.some(s => s.includes('INSERT INTO audit_chain'))).toBe(true);
    expect(sqls.some(s => s.includes('UPDATE audit_chain_head'))).toBe(true);
    expect(sqls).toContain('COMMIT');

    expect(entry.prevHash).toBe('GENESIS');
    expect(entry.artifactId).toBe('artifact-1');
    expect(typeof entry.hash).toBe('string');
    expect(entry.hash).toHaveLength(64);

    // UPDATE audit_chain_head must advance tail_seq from 0 to 1 and set
    // tail_hash to the newly computed entry hash.
    const updateCall = mockClientQuery.mock.calls.find(c => c[0].includes('UPDATE audit_chain_head'));
    expect(updateCall[1]).toEqual([entry.hash, '1', entry.schemaVersion]);   // the head also carries the entry's schema version
  });

  test('DO-02 missing audit_chain_head seed row throws AUDIT_CHAIN_HEAD_MISSING', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) return { rows: [] };
      return { rows: [], rowCount: 0 };
    });

    const { distributedOrdering } = loadModules();
    await expect(distributedOrdering.appendEntry(validFields()))
      .rejects.toThrow(/AUDIT_CHAIN_HEAD_MISSING/);
  });

  test('DO-03 23505 on artifact_id constraint translates to already_executed', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) {
        return { rows: [{ tail_hash: 'GENESIS', tail_seq: '0', tail_schema_version: 0 }] };
      }
      if (sql.includes('INSERT INTO audit_chain')) {
        throw pgUniqueViolation('idx_audit_chain_artifact_id');
      }
      return { rows: [], rowCount: 0 };
    });

    const { distributedOrdering } = loadModules();
    await expect(distributedOrdering.appendEntry(validFields()))
      .rejects.toThrow('already_executed: artifactId already in audit log');
  });

  test('DO-04 23505 on nonce constraint translates to replay_detected', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) {
        return { rows: [{ tail_hash: 'GENESIS', tail_seq: '0', tail_schema_version: 0 }] };
      }
      if (sql.includes('INSERT INTO audit_chain')) {
        throw pgUniqueViolation('idx_audit_chain_nonce');
      }
      return { rows: [], rowCount: 0 };
    });

    const { distributedOrdering } = loadModules();
    await expect(distributedOrdering.appendEntry(validFields({ nonce: 'nonce-1' })))
      .rejects.toThrow('replay_detected: nonce already used');
  });

  test('DO-05 23505 on prev_hash constraint translates to a retryable AUDIT_CHAIN_CONCURRENT_CONFLICT error (no invalid_*/already_executed/replay_detected prefix)', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) {
        return { rows: [{ tail_hash: 'GENESIS', tail_seq: '0', tail_schema_version: 0 }] };
      }
      if (sql.includes('INSERT INTO audit_chain')) {
        throw pgUniqueViolation('idx_audit_chain_prev_hash_unique');
      }
      return { rows: [], rowCount: 0 };
    });

    const { distributedOrdering } = loadModules();
    await expect(distributedOrdering.appendEntry(validFields()))
      .rejects.toThrow('AUDIT_CHAIN_CONCURRENT_CONFLICT');
  });

  test('DO-06 field validation runs before any PG call', async () => {
    const { distributedOrdering } = loadModules();
    await expect(distributedOrdering.appendEntry(validFields({ decision: 'MAYBE' })))
      .rejects.toThrow('invalid_decision');
    expect(mockClientQuery).not.toHaveBeenCalled();
  });

  test('DO-07 a non-23505 PG error passes through untranslated', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) {
        const e = new Error('connection terminated unexpectedly');
        e.code = 'ECONNRESET';
        throw e;
      }
      return { rows: [], rowCount: 0 };
    });

    const { distributedOrdering } = loadModules();
    await expect(distributedOrdering.appendEntry(validFields()))
      .rejects.toThrow('connection terminated unexpectedly');
  });

  test('DO-08 a head at a higher schema version refuses the append: invalid_schema_downgrade, no INSERT, no head UPDATE', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) return { rows: [{ tail_hash: 'f'.repeat(64), tail_seq: '41', tail_schema_version: 8 }] };
      return { rows: [], rowCount: 0 };
    });
    const { distributedOrdering } = loadModules();
    const err = await distributedOrdering.appendEntry(validFields()).then(() => null, (e) => e);   // v7 entry (QODIQA_AUDIT_SCHEMA_V8 off)
    expect(err).toBeTruthy();
    expect(err.message).toMatch(/^invalid_schema_downgrade: the chain head is schema v8 and this writer would append v7/);
    expect(err.code).toBe('AUDIT_SCHEMA_DOWNGRADE_REFUSED');
    const sqls = mockClientQuery.mock.calls.map((c) => c[0]);
    expect(sqls.some((q) => q.includes('INSERT INTO audit_chain'))).toBe(false);
    expect(sqls.some((q) => q.includes('UPDATE audit_chain_head'))).toBe(false);
    expect(sqls).toContain('ROLLBACK');
  });

  test('DO-09 the head update writes the schema version of the new entry; an equal version is accepted', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) return { rows: [{ tail_hash: 'GENESIS', tail_seq: '0', tail_schema_version: 7 }] };
      return { rows: [], rowCount: 0 };
    });
    const { distributedOrdering } = loadModules();
    const entry = await distributedOrdering.appendEntry(validFields());
    expect(entry.schemaVersion).toBe(7);
    const up = mockClientQuery.mock.calls.find((c) => c[0].includes('UPDATE audit_chain_head'));
    expect(up[0]).toContain("tail_schema_version = $3");
    expect(up[1]).toEqual([entry.hash, '1', 7]);
  });

  test.each([[-1], [undefined], ['x'], [1.5]])('DO-10 a head version %p that is not a non-negative integer fails closed', async (bad) => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql.includes('FROM audit_chain_head FOR UPDATE')) return { rows: [{ tail_hash: 'GENESIS', tail_seq: '0', tail_schema_version: bad }] };
      return { rows: [], rowCount: 0 };
    });
    const { distributedOrdering } = loadModules();
    await expect(distributedOrdering.appendEntry(validFields())).rejects.toThrow(/AUDIT_CHAIN_HEAD_VERSION_INVALID/);
    expect(mockClientQuery.mock.calls.some((c) => c[0].includes('INSERT INTO audit_chain'))).toBe(false);
  });
});
