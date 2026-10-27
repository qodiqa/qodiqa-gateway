'use strict';

/**
 * phase 9 — pg-audit-backend.persistEntries() (batched single-node mirror), unit level.
 *
 *   PE-01  a contiguous same-tenant batch: ONE guard query, ONE mirror transaction with every INSERT in chain order,
 *          ONE batched evidence call; the per-entry evidence path is not used
 *   PE-02  the batch transaction fails → every entry goes through the unchanged per-entry path (its own guard,
 *          transaction and evidence), so per-entry recovery-queue semantics apply
 *   PE-03  the batched evidence write fails → per-entry evidence for every entry (mirror rows not rewritten)
 *   PE-04  mixed tenants → consecutive same-tenant runs, each with its own guard + transaction, tenant set once per run
 *   PE-05  a non-contiguous batch never uses the batch path
 *   PE-06  PostgreSQL disabled → complete no-op
 */

const mockSystemQuery = jest.fn();
jest.mock('../rolePools', () => ({ system: { query: (...a) => mockSystemQuery(...a) }, reporting: { query: jest.fn() } }));
const mockTx = { calls: [] };
jest.mock('../pool', () => ({
  isEnabled: jest.fn(() => true),
  query: jest.fn(),
  withTransaction: jest.fn(async (fn) => { const tx = { query: jest.fn(async (sql, params) => { mockTx.calls.push({ sql, params }); return { rows: [] }; }) }; return fn(tx); }),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../core/persistenceRecovery', () => ({ enqueue: jest.fn().mockResolvedValue({}), OPERATION_TYPES: { AUDIT_CHAIN_PG_SAVE: 'A', EVIDENCE_CHAIN_SAVE: 'E' } }));
const mockBatch = jest.fn().mockResolvedValue(1);
const mockSingle = jest.fn().mockResolvedValue(undefined);
jest.mock('../../../core/evidence/chainStore', () => ({
  recordEvidenceFromAuditEntry: jest.fn(),
  _recordEvidenceFromAuditEntryOrThrow: (...a) => mockSingle(...a),
  _recordEvidenceBatchOrThrow: (...a) => mockBatch(...a),
}));

const pgPool = require('../pool');
const backend = require('../pg-audit-backend');

const chain = (n, tenantOf = () => null) => {
  const out = []; let prev = 'GENESIS';
  for (let i = 0; i < n; i++) {
    const hash = String(i + 1).padStart(64, '0');
    out.push({ hash, prevHash: prev, canonical: '{}', artifactId: `a${i}`, decision: 'ALLOW', timestamp: new Date().toISOString(), highResTime: '1',
      inputHash: 'i'.repeat(64), signature: 's', requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true, tenantId: tenantOf(i) });
    prev = hash;
  }
  return out;
};
const inserts = () => mockTx.calls.filter((c) => /INSERT INTO audit_chain/.test(c.sql)).map((c) => c.params[0]);
const guardCalls = (re) => mockSystemQuery.mock.calls.filter(([sql]) => re.test(sql)).length;

beforeEach(() => {
  jest.clearAllMocks(); mockTx.calls = [];
  pgPool.isEnabled.mockReturnValue(true);
  mockSystemQuery.mockImplementation(async (sql) => (/AS present/.test(sql) ? { rows: [{ parent_ok: true, present: [] }] } : { rows: [{ parent_ok: true, self_exists: false }] }));
  mockBatch.mockResolvedValue(1); mockSingle.mockResolvedValue(undefined);
});

test('PE-01 contiguous batch: one guard, one transaction, inserts in chain order, one batched evidence call', async () => {
  const es = chain(5);
  await backend.persistEntries(es);
  expect(guardCalls(/AS present/)).toBe(1);
  expect(guardCalls(/self_exists/)).toBe(0);
  expect(pgPool.withTransaction).toHaveBeenCalledTimes(1);
  expect(inserts()).toEqual(es.map((e) => e.hash));
  expect(mockBatch).toHaveBeenCalledTimes(1);
  expect(mockBatch.mock.calls[0][0].map((x) => x.auditEntry.hash)).toEqual(es.map((e) => e.hash));
  expect(mockSingle).not.toHaveBeenCalled();
});

test('PE-02 a failing batch transaction falls back to the per-entry path for every entry', async () => {
  const es = chain(3);
  pgPool.withTransaction.mockImplementationOnce(async () => { throw Object.assign(new Error('connection reset'), { code: 'ECONNRESET' }); });
  await backend.persistEntries(es);
  expect(guardCalls(/self_exists/)).toBe(3);                  // each entry's own guard
  expect(inserts()).toEqual(es.map((e) => e.hash));            // committed only by the per-entry transactions
  expect(mockSingle).toHaveBeenCalledTimes(3);                 // per-entry evidence
  expect(mockBatch).not.toHaveBeenCalled();
});

test('PE-03 a failing batched evidence write falls back to per-entry evidence only', async () => {
  const es = chain(4);
  mockBatch.mockRejectedValueOnce(new Error('evidence head lock timeout'));
  await backend.persistEntries(es);
  expect(inserts()).toEqual(es.map((e) => e.hash));            // mirror rows written once, by the batch
  expect(mockSingle.mock.calls.map((c) => c[0].hash)).toEqual(es.map((e) => e.hash));
});

test('PE-04 mixed tenants are written as consecutive same-tenant runs', async () => {
  const tenants = [null, null, 'ta', 'ta', null, 'tb'];
  const es = chain(6, (i) => tenants[i]);
  await backend.persistEntries(es);
  // runs: [0,1] null, [2,3] ta, [4] null (single → per-entry path), [5] tb (single → per-entry path)
  expect(guardCalls(/AS present/)).toBe(2);
  expect(guardCalls(/self_exists/)).toBe(2);
  expect(inserts()).toEqual(es.map((e) => e.hash));
  expect(mockBatch.mock.calls.map((c) => c[0].length)).toEqual([2, 2]);
});

test('PE-05 a non-contiguous batch never takes the batch path', async () => {
  const es = chain(4); const gapped = [es[0], es[2], es[3]];
  await backend.persistEntries(gapped);
  expect(guardCalls(/AS present/)).toBe(0);
  expect(guardCalls(/self_exists/)).toBe(3);
  expect(mockBatch).not.toHaveBeenCalled();
});

test('PE-06 PostgreSQL disabled → no-op', async () => {
  pgPool.isEnabled.mockReturnValue(false);
  await backend.persistEntries(chain(3));
  expect(mockSystemQuery).not.toHaveBeenCalled(); expect(pgPool.withTransaction).not.toHaveBeenCalled();
});
