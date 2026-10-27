'use strict';

/**
 * pg-audit-backend.recordEvidenceForEntry(), the
 * evidence step shared by single-node persistEntry() and the distributed post-commit
 * call. Same doubles as pg-audit-backend.recovery.test.js.
 *
 *   RE-01  success → writer called with the entry and resolved key info; nothing queued
 *   RE-02  retryable failure → EVIDENCE_CHAIN_SAVE queued with { auditEntry, keyInfo, opts }
 * RE-03 non-retryable failure → queued too (worker DLQs it after one
 *          replay attempt), nothing thrown
 *   RE-04  PG disabled → complete no-op
 *   RE-05  persistEntry() still runs the evidence step after its INSERT (single-node unchanged)
 *   RE-06  an enqueue failure is still absorbed (never throws to the audit path)
 */

// the transaction double answers insertMirrorRow()'s parent guard
// (migration 058) with 'parent committed, row not present' and forwards every
// other statement to the same query mock — see pg-audit-backend.recovery.test.js.
// cross-tenant DEFINER reads now go through rolePools (qodiqa_system / qodiqa_reporting);
// the forwarder sends them to the same mocked pool and records which pool served each call.
jest.mock('../rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../pool'), {
  // The mirror parent/self guard used to run on the transaction mock below; it
  // now runs as qodiqa_system and is answered the same way (parent present).
  intercept: (sql) => (/qodiqa_audit_chain_hash_exists/.test(sql) ? { rows: [{ parent_ok: true, self_exists: false }] } : undefined),
}));
jest.mock('../pool', () => {
  const query = jest.fn();
  const txQuery = (sql, ...rest) => (/qodiqa_audit_chain_hash_exists/.test(sql)
    ? Promise.resolve({ rows: [{ parent_ok: true, self_exists: false }] })
    : query(sql, ...rest));
  return { isEnabled: jest.fn(() => true), query, withTransaction: jest.fn((fn) => fn({ query: txQuery })) };
});
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const mockEnqueue = jest.fn().mockResolvedValue({});
jest.mock('../../../core/persistenceRecovery', () => ({
  enqueue: (...args) => mockEnqueue(...args),
  OPERATION_TYPES: { AUDIT_CHAIN_PG_SAVE: 'AUDIT_CHAIN_PG_SAVE', EVIDENCE_CHAIN_SAVE: 'EVIDENCE_CHAIN_SAVE' },
}));

const mockRecordOrThrow = jest.fn().mockResolvedValue(undefined);
jest.mock('../../../core/evidence/chainStore', () => ({
  recordEvidenceFromAuditEntry: jest.fn(),
  _recordEvidenceFromAuditEntryOrThrow: (...args) => mockRecordOrThrow(...args),
}));

const pgPool = require('../pool');
const backend = require('../pg-audit-backend');

const KEY = { publicKeyB64: 'AAAA', version: 1 };
const entry = () => ({ artifactId: 'h134-re', hash: 'a'.repeat(64), prevHash: 'GENESIS', canonical: '{}', decision: 'ALLOW',
  timestamp: new Date().toISOString(), highResTime: '1', tenantId: null, publicKeyId: 'tenant-a:key_v1', schemaVersion: 6 });

beforeEach(() => {
  mockEnqueue.mockClear(); mockRecordOrThrow.mockReset().mockResolvedValue(undefined);
  pgPool.isEnabled.mockReturnValue(true); pgPool.query.mockReset().mockResolvedValue({ rows: [] });
  backend.setKeyInfoResolver(async () => KEY);
});

test('RE-01 success → writer called with the entry and the resolved key info; nothing queued', async () => {
  const e = entry();
  await backend.recordEvidenceForEntry(e);
  expect(mockRecordOrThrow).toHaveBeenCalledWith(e, KEY, null);
  expect(mockEnqueue).not.toHaveBeenCalled();
});

test('RE-02 retryable failure → EVIDENCE_CHAIN_SAVE queued with the committed entry for deterministic replay', async () => {
  const err = Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
  mockRecordOrThrow.mockRejectedValueOnce(err);
  const e = entry();
  await expect(backend.recordEvidenceForEntry(e)).resolves.toBeUndefined();
  expect(mockEnqueue).toHaveBeenCalledWith('EVIDENCE_CHAIN_SAVE', { auditEntry: e, keyInfo: KEY, opts: null }, err);
});

// inverted. a non-retryable failure was only logged and
// the committed audit entry was left with no evidence row and no durable
// record of the loss; it is now queued like a retryable one.
test('RE-03 non-retryable failure → queued, nothing thrown', async () => {
  const err = Object.assign(new Error('permission denied for table evidence_chain_records'), { code: '42501' });
  mockRecordOrThrow.mockRejectedValueOnce(err);
  const e = entry();
  await expect(backend.recordEvidenceForEntry(e)).resolves.toBeUndefined();
  expect(mockEnqueue).toHaveBeenCalledWith('EVIDENCE_CHAIN_SAVE', { auditEntry: e, keyInfo: KEY, opts: null }, err);
});

test('RE-04 PG disabled → complete no-op', async () => {
  pgPool.isEnabled.mockReturnValue(false);
  await backend.recordEvidenceForEntry(entry());
  expect(mockRecordOrThrow).not.toHaveBeenCalled();
  expect(mockEnqueue).not.toHaveBeenCalled();
});

test('RE-05 persistEntry() still runs the evidence step after its audit_chain INSERT (single-node unchanged)', async () => {
  const e = entry();
  await backend.persistEntry(e);
  expect(pgPool.query.mock.calls.some(c => /INSERT INTO audit_chain/.test(c[0]))).toBe(true);
  expect(mockRecordOrThrow).toHaveBeenCalledWith(e, KEY, null);
});

test('RE-06 an enqueue failure is absorbed — never throws to the audit path', async () => {
  mockRecordOrThrow.mockRejectedValueOnce(Object.assign(new Error('Connection terminated'), { code: '08006' }));
  mockEnqueue.mockRejectedValueOnce(new Error('queue down'));
  await expect(backend.recordEvidenceForEntry(entry())).resolves.toBeUndefined();
});
