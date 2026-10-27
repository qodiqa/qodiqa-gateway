'use strict';

/**
 * recoveryManager.js — AUDIT_CHAIN_PG_SAVE / EVIDENCE_CHAIN_SAVE retry handlers
 *
 * These are the handlers the background worker invokes when retrying a
 * queued audit/evidence PG write that failed on its first attempt (see
 * pg-audit-backend.recovery.test.js for the enqueue side of this).
 *
 * RH-01…04  AUDIT_CHAIN_PG_SAVE handler
 * RH-05…08  EVIDENCE_CHAIN_SAVE handler
 */

// the AUDIT_CHAIN_PG_SAVE handler now runs its INSERT inside
// pgPool.withTransaction() (tenant context + INSERT in one transaction, the
// same construct pg-audit-backend.js persistEntry() uses) — the double routes
// the transaction's query() through the same `query` mock, so every existing
// assertion on pgPool.query still observes the real INSERT.
// cross-tenant DEFINER reads now go through rolePools (qodiqa_system / qodiqa_reporting);
// the forwarder sends them to the same mocked pool and records which pool served each call.
const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('../../../infra/postgres/rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../../../infra/postgres/pool')));
jest.mock('../../../infra/postgres/pool', () => {
  const query = jest.fn();
  return {
    isEnabled:       jest.fn(() => true),
    query,
    withTransaction: jest.fn(async (fn) => fn({ query })),
  };
});
jest.mock('../../evidence/chainStore', () => ({
  _recordEvidenceFromAuditEntryOrThrow: jest.fn(),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const pgPool          = require('../../../infra/postgres/pool');
const chainStore      = require('../../evidence/chainStore');
const recoveryManager = require('../recoveryManager');

const { AUDIT_CHAIN_PG_SAVE, EVIDENCE_CHAIN_SAVE } = recoveryManager.OPERATION_TYPES;

function makeAuditEntry(overrides = {}) {
  return {
    hash: 'h'.repeat(64), prevHash: 'GENESIS', canonical: '{}',
    artifactId: 'art-1', decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, timestamp: new Date().toISOString(),
    highResTime: '123', inputHash: 'i'.repeat(64), signature: 's'.repeat(64),
    requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64),
    verificationResult: true, nonce: null, tenantId: null, executionContext: null,
    ...overrides,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  pgPool.isEnabled.mockReturnValue(true);
});

// the handler now runs pg-audit-backend.js insertMirrorRow(), which
// first asks (migration 058) whether the row's parent is committed and whether
// the row itself already exists, then INSERTs. This routes the double's answers
// by statement so the tests below still observe the real INSERT.
function guardSays({ parentOk = true, selfExists = false } = {}) {
  pgPool.query.mockImplementation(async (sql) => (
    /qodiqa_audit_chain_hash_exists/.test(sql)
      ? { rows: [{ parent_ok: parentOk, self_exists: selfExists }] }
      : { rows: [] }
  ));
}
const insertCalls = () => pgPool.query.mock.calls.filter(([sql]) => /INSERT INTO audit_chain/.test(sql));

// ═════════════════════════════════════════════════════════════════════════════
// RH-01…04  AUDIT_CHAIN_PG_SAVE handler
// ═════════════════════════════════════════════════════════════════════════════

describe('AUDIT_CHAIN_PG_SAVE retry handler', () => {
  test('RH-01: reports success and issues the audit_chain INSERT when the retry succeeds', async () => {
    guardSays();
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    const result  = await handler({ payload: makeAuditEntry() });
    expect(result.success).toBe(true);
    expect(pgPool.query).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO audit_chain'),
      expect.any(Array),
      'recovery_audit_chain_insert',
    );
  });

  test('RH-02: reports failure (not a thrown exception) when PG is still unreachable', async () => {
    pgPool.query.mockRejectedValueOnce(Object.assign(new Error('still down'), { code: 'ECONNREFUSED' }));
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    const result  = await handler({ payload: makeAuditEntry() });
    expect(result.success).toBe(false);
  });

  test('RH-03: reports PG-disabled as a failure without attempting the query', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    const result  = await handler({ payload: makeAuditEntry() });
    expect(result.success).toBe(false);
    expect(pgPool.query).not.toHaveBeenCalled();
  });

  test('RH-04: the INSERT uses ON CONFLICT (hash) DO NOTHING, so a re-delivered retry is idempotent', async () => {
    guardSays();
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    await handler({ payload: makeAuditEntry() });
    expect(insertCalls()).toHaveLength(1);
    expect(insertCalls()[0][0]).toMatch(/ON CONFLICT \(hash\) DO NOTHING/);
  });

  // the parent guard — a replay can never land out of chain order.
  test('RH-09: a replay whose parent is not committed yet is a RETRYABLE failure and issues no INSERT', async () => {
    guardSays({ parentOk: false });
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    const result = await handler({ payload: makeAuditEntry({ prevHash: 'a'.repeat(64) }) });
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/AUDIT_MIRROR_PARENT_MISSING/);
    expect(result.error).not.toMatch(/non-retryable/);
    expect(insertCalls()).toHaveLength(0);
  });

  test('RH-10: a replay of a row that is already present succeeds idempotently without an INSERT', async () => {
    guardSays({ selfExists: true });
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    const result = await handler({ payload: makeAuditEntry() });
    expect(result.success).toBe(true);
    expect(insertCalls()).toHaveLength(0);
  });

  test('RH-11: the guard is asked about the entry\'s parent and the entry itself', async () => {
    guardSays();
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    await handler({ payload: makeAuditEntry({ prevHash: 'b'.repeat(64) }) });
    const guardCall = pgPool.query.mock.calls.find(([sql]) => /qodiqa_audit_chain_hash_exists/.test(sql));
    expect(guardCall[1]).toEqual(['b'.repeat(64), 'h'.repeat(64)]);
  });

  // the two properties whose absence made recovered rows unverifiable
  // (missing hash-protected columns) or rejected (no RLS tenant context).
  // test/integration/auditChainCircuitOpenRecovery.integration.test.js ACOR-03/04 prove
  // the same against real PostgreSQL.
  test('RH-04b: a tenant-scoped entry sets qodiqa.tenant_id in the same transaction first, and the INSERT binds all 43 audit_chain columns (v7: +5 and mirror_encoding, migration 075; audit v8: +10, migration 083)', async () => {
    guardSays();
    const handler = recoveryManager._builtinHandlers[AUDIT_CHAIN_PG_SAVE];
    const result = await handler({ payload: makeAuditEntry({
      tenantId: 'tenant-a', publicKeyId: 'tenant-a:key_v1', schemaVersion: 6,
      consentProvenance: { consentId: 'c1' }, policyDecision: { decision: 'EXECUTE' },
      callerContext: { callerId: 'x' }, provider: 'local', model: 'm', stage: 'PROVIDER_EXECUTION',
      reason: null, semantic: { score: 0.1 }, tokenUsage: { totalTokens: 8 }, responseId: 'r1',
    }) });
    expect(result.success).toBe(true);
    expect(pgPool.withTransaction).toHaveBeenCalledTimes(1);
    expect(pgPool.query.mock.calls[0][0]).toMatch(/set_config\('qodiqa\.tenant_id'/);
    expect(pgPool.query.mock.calls[0][1]).toEqual(['tenant-a']);
    const [sql, params] = insertCalls()[0];
    expect(sql).toMatch(/INSERT INTO audit_chain/);
    expect(params).toHaveLength(43);
    expect(params.slice(15)).toEqual([
      'tenant-a:key_v1', 6, '{"consentId":"c1"}', '{"decision":"EXECUTE"}', '{"callerId":"x"}',
      'local', 'm', 'PROVIDER_EXECUTION', null, '{"score":0.1}', '{"totalTokens":8}', 'r1',
      // v7 columns (entry_type, output_hash, request_id, organization_id, executing_provider): each binds the
      // entry's own value or NULL (absent ≡ null); this synthetic fixture carries only outputHash.
      null, W7_EMPTY_OUTPUT_HASH, null, null, null,
      // (R-F2): mirror_encoding = 1 — every per-field value went through P (these ASCII values are unchanged by it)
      1,
      // audit v8 (migration 083): ten columns, all NULL for a schemaVersion-6 entry
      null, null, null, null, null, null, null, null, null, null,
    ]);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RH-05…08  EVIDENCE_CHAIN_SAVE handler
// ═════════════════════════════════════════════════════════════════════════════

describe('EVIDENCE_CHAIN_SAVE retry handler', () => {
  test('RH-05: reports success and calls the throwing evidence-record function when the retry succeeds', async () => {
    chainStore._recordEvidenceFromAuditEntryOrThrow.mockResolvedValueOnce(undefined);
    const handler = recoveryManager._builtinHandlers[EVIDENCE_CHAIN_SAVE];
    const auditEntry = makeAuditEntry();
    const result = await handler({ payload: { auditEntry, keyInfo: null, opts: null } });
    expect(result.success).toBe(true);
    expect(chainStore._recordEvidenceFromAuditEntryOrThrow).toHaveBeenCalledWith(auditEntry, null, null);
  });

  test('RH-06: reports failure when the retry also fails', async () => {
    chainStore._recordEvidenceFromAuditEntryOrThrow.mockRejectedValueOnce(
      Object.assign(new Error('still down'), { code: 'ETIMEDOUT' }),
    );
    const handler = recoveryManager._builtinHandlers[EVIDENCE_CHAIN_SAVE];
    const result = await handler({ payload: { auditEntry: makeAuditEntry(), keyInfo: null, opts: null } });
    expect(result.success).toBe(false);
  });

  test('RH-07: reports PG-disabled as a failure without attempting the write', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    const handler = recoveryManager._builtinHandlers[EVIDENCE_CHAIN_SAVE];
    const result = await handler({ payload: { auditEntry: makeAuditEntry(), keyInfo: null, opts: null } });
    expect(result.success).toBe(false);
    expect(chainStore._recordEvidenceFromAuditEntryOrThrow).not.toHaveBeenCalled();
  });

  test('RH-08: the original keyInfo captured at enqueue time is passed through to the retry', async () => {
    chainStore._recordEvidenceFromAuditEntryOrThrow.mockResolvedValueOnce(undefined);
    const handler = recoveryManager._builtinHandlers[EVIDENCE_CHAIN_SAVE];
    const keyInfo = { pubDer: Buffer.from('x'), status: 'active' };
    await handler({ payload: { auditEntry: makeAuditEntry(), keyInfo, opts: { policyId: 'POL-1' } } });
    expect(chainStore._recordEvidenceFromAuditEntryOrThrow).toHaveBeenCalledWith(
      expect.any(Object), keyInfo, { policyId: 'POL-1' },
    );
  });
});
