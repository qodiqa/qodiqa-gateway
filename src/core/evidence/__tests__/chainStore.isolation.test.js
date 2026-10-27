'use strict';

/**
 * Evidence Chain Store Transaction Isolation Tests — Component #18
 *
 * CS-TX-01  Locks the evidence_chain_head pointer row (SELECT tail_hash ...
 *           FOR UPDATE) under READ COMMITTED, no advisory lock — see
 *           FINDING-EVIDENCE-CHAIN-FORK-RACE-REPORT.md for why (supersedes
 *           the advisory-lock approach from FINDING-EVIDENCE-CHAIN-RECORDS-
 *           PERMISSION-REPORT.md)
 * CS-TX-02  previousEvidenceHash is taken from the pointer row, and the
 *           pointer is advanced to the new evidence_hash/id after INSERT
 * CS-TX-03  DB errors are absorbed — never propagated to caller
 * CS-TX-04  Does nothing when PG is disabled
 */

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockTxQuery = jest.fn();

const mockPool = {
  _enabled:   false,
  lastTxOpts: null,
  isEnabled:       function () { return this._enabled; },
  query:           jest.fn(),
  withTransaction: async function (fn, opts) {
    if (!this._enabled) throw new Error('PG pool not initialized');
    this.lastTxOpts = opts;
    return fn({ query: mockTxQuery });
  },
};

jest.mock('../../../infra/postgres/pool', () => mockPool);

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

jest.mock('../../../observability/metrics', () => ({
  evidenceChainRecordsTotal:         { inc: jest.fn() },
  evidenceChainPersistFailuresTotal: { inc: jest.fn() },
}));

jest.mock('../chain', () => ({
  buildEvidenceRecord: jest.fn().mockReturnValue({
    evidenceId:           'ev-001',
    artifactId:           'art-001',
    artifactHash:         'a'.repeat(64),
    policyId:             'POLICY_SET',
    policyVersion:        null,
    policyHash:           'p'.repeat(64),
    keyId:                null,
    keyVersion:           null,
    keyFingerprint:       null,
    auditRecordId:        'rec-001',
    auditRecordHash:      'r'.repeat(64),
    previousEvidenceHash: null,
    evidenceHash:         'e'.repeat(64),
    decision:             'ALLOWED',
    tenantId:             null,
    createdAt:            new Date(),
  }),
}));

// ── Load module under test ────────────────────────────────────────────────────

const chainStore = require('../chainStore');
const chain      = require('../chain');

// ── Helpers ───────────────────────────────────────────────────────────────────

const AUDIT_ENTRY = {
  artifactId:    'art-001',
  decision:      'ALLOWED',
  hash:          'a'.repeat(64),
  prevHash:      null,
  timestamp:     new Date().toISOString(),
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('CS-TX-01 … CS-TX-04: chainStore.recordEvidenceFromAuditEntry', () => {
  beforeEach(() => {
    mockTxQuery.mockReset();
    mockPool._enabled = false;
    mockPool.lastTxOpts = null;
    chain.buildEvidenceRecord.mockClear();
  });

  test('CS-TX-01 locks evidence_chain_head (FOR UPDATE), no advisory lock, under READ COMMITTED', async () => {
    mockPool._enabled = true;

    const capturedSqls = [];
    mockTxQuery.mockImplementation((sql) => {
      capturedSqls.push(sql);
      if (sql.includes('INSERT INTO evidence_chain_records')) {
        return { rows: [{ id: 1 }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    });

    await chainStore.recordEvidenceFromAuditEntry(AUDIT_ENTRY, null, {});

    const headLockSql = capturedSqls.find(s => s.includes('FROM evidence_chain_head'));
    expect(headLockSql).toBeDefined();
    expect(headLockSql).toMatch(/FOR UPDATE/);
    expect(capturedSqls.some(s => s.includes('pg_advisory_xact_lock'))).toBe(false);
    expect(mockPool.lastTxOpts).toEqual({ isolationLevel: 'READ COMMITTED' });
  });

  test('CS-TX-02 passes the previous evidence hash from the pointer row to buildEvidenceRecord, then advances the pointer', async () => {
    mockPool._enabled = true;

    const prevHash = 'f'.repeat(64);
    mockTxQuery
      .mockResolvedValueOnce({ rows: [{ tail_hash: prevHash }] })  // evidence_chain_head lock
      .mockResolvedValueOnce({ rows: [] })                          // no existing row for this artifact
      .mockResolvedValueOnce({ rows: [{ id: 42 }], rowCount: 1 })  // INSERT ... RETURNING id
      .mockResolvedValueOnce({ rows: [], rowCount: 1 });           // UPDATE evidence_chain_head

    await chainStore.recordEvidenceFromAuditEntry(AUDIT_ENTRY, null, {});

    expect(chain.buildEvidenceRecord).toHaveBeenCalledWith(
      AUDIT_ENTRY,
      null,
      expect.objectContaining({ previousEvidenceHash: prevHash }),
    );
    expect(mockTxQuery).toHaveBeenNthCalledWith(
      4, // head lock, existence check, INSERT, then the pointer UPDATE
      expect.stringContaining('UPDATE evidence_chain_head'),
      ['e'.repeat(64), 42],
    );
  });

  test('CS-TX-03 absorbs DB errors and does not propagate them', async () => {
    mockPool._enabled = true;

    mockTxQuery.mockRejectedValue(new Error('connection lost'));

    await expect(
      chainStore.recordEvidenceFromAuditEntry(AUDIT_ENTRY, null, {})
    ).resolves.toBeUndefined();
  });

  test('CS-TX-04 returns immediately when PG is disabled', async () => {
    mockPool._enabled = false;

    await chainStore.recordEvidenceFromAuditEntry(AUDIT_ENTRY, null, {});

    expect(mockTxQuery).not.toHaveBeenCalled();
    expect(mockPool.query).not.toHaveBeenCalled();
  });
});
