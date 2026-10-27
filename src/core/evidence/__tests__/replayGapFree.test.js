'use strict';

/**
 * — chainStore._recordEvidenceFromAuditEntryOrThrow is a gap-free
 * idempotent writer: under the evidence_chain_head lock, an artifact that already has its
 * evidence row returns WITHOUT an INSERT (a no-op `INSERT ... ON CONFLICT DO NOTHING`
 * still consumes a BIGSERIAL id). Statement-level contract with a scripted transaction;
 * the real-PostgreSQL proof is test/integration/distributedEvidenceLedger.integration.test.js.
 *
 *   RG-01  first write: head lock → tenant context → existence check → INSERT → head advanced
 *   RG-02  replay (row exists): no INSERT, no head update, resolves
 *   RG-03  the existence check runs after the head lock and after the tenant context
 *   RG-04  a NULL-tenant entry sets no tenant context and is still checked before insert
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const mockCalls = [];
let mockExisting = [];
jest.mock('../../../infra/postgres/pool', () => ({
  isEnabled: () => true,
  withTransaction: jest.fn(async (fn) => fn({
    query: jest.fn(async (sql, params) => {
      mockCalls.push({ sql: sql.replace(/\s+/g, ' ').trim(), params });
      if (/FROM evidence_chain_head FOR UPDATE/.test(sql)) return { rows: [{ tail_hash: 'f'.repeat(64) }] };
      if (/SELECT id FROM evidence_chain_records WHERE artifact_id/.test(sql)) return { rows: mockExisting };
      if (/INSERT INTO evidence_chain_records/.test(sql)) return { rows: [{ id: 7 }] };
      return { rows: [] };
    }),
  })),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const chainStore = require('../chainStore');
const { buildEntry, normalizeFields } = require('../../audit/entryBuilder');

const entry = (tenantId = 'tenant-a') => buildEntry(normalizeFields({
  artifactId: 'h134-rg', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig', nonce: 'n-rg',
  requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId,
  publicKeyId: tenantId ? `${tenantId}:key_v1` : undefined,
}), 'GENESIS');
const kinds = () => mockCalls.map(c =>
  /evidence_chain_head FOR UPDATE/.test(c.sql) ? 'HEAD_LOCK'
    : /set_config\('qodiqa.tenant_id'/.test(c.sql) ? 'TENANT'
      : /SELECT id FROM evidence_chain_records WHERE artifact_id/.test(c.sql) ? 'EXISTS?'
        : /INSERT INTO evidence_chain_records/.test(c.sql) ? 'INSERT'
          : /UPDATE evidence_chain_head/.test(c.sql) ? 'HEAD_UPDATE' : c.sql);

beforeEach(() => { mockCalls.length = 0; mockExisting = []; });

test('RG-01 first write: head lock → tenant context → existence check → INSERT → head advanced', async () => {
  await chainStore._recordEvidenceFromAuditEntryOrThrow(entry(), null, null);
  expect(kinds()).toEqual(['HEAD_LOCK', 'TENANT', 'EXISTS?', 'INSERT', 'HEAD_UPDATE']);
  expect(mockCalls[2].params).toEqual(['h134-rg']);
});

test('RG-02 replay of an artifact that already has its row: no INSERT, no head update, resolves', async () => {
  mockExisting = [{ id: 3 }];
  await expect(chainStore._recordEvidenceFromAuditEntryOrThrow(entry(), null, null)).resolves.toBeUndefined();
  expect(kinds()).toEqual(['HEAD_LOCK', 'TENANT', 'EXISTS?']);
});

test('RG-03 the existence check runs after the head lock and the tenant context (RLS-scoped read)', async () => {
  mockExisting = [{ id: 3 }];
  await chainStore._recordEvidenceFromAuditEntryOrThrow(entry('tenant-b'), null, null);
  const k = kinds();
  expect(k.indexOf('EXISTS?')).toBeGreaterThan(k.indexOf('HEAD_LOCK'));
  expect(k.indexOf('EXISTS?')).toBeGreaterThan(k.indexOf('TENANT'));
  expect(mockCalls[k.indexOf('TENANT')].params).toEqual(['tenant-b']);
});

test('RG-04 a NULL-tenant entry sets no tenant context and is still checked before any insert', async () => {
  await chainStore._recordEvidenceFromAuditEntryOrThrow(entry(null), null, null);
  expect(kinds()).toEqual(['HEAD_LOCK', 'EXISTS?', 'INSERT', 'HEAD_UPDATE']);
});
