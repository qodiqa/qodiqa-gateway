'use strict';

/**
 * pg-audit-backend.js — Persistence Recovery Queue wiring — Tests
 *
 * Regression suite for the "Audit/Evidence Pipeline Fail-Closed Remediation":
 * persistEntry() used to swallow every PostgreSQL dual-write failure (both
 * the audit_chain INSERT and the evidence-chain-record generation it
 * triggers) with a bare `.catch(() => {})` / nested try/catch — a retryable
 * outage (connection drop, pool exhaustion) meant the PG copy and its
 * evidence chain record were silently and permanently lost, with no retry
 * and no trace beyond a single ERROR log line.
 *
 * PAB-01…05  Retryable audit_chain failure → durably queued (AUDIT_CHAIN_PG_SAVE)
 * PAB-06…08  Non-retryable audit_chain failure → NOT queued (would retry forever pointlessly)
 * PAB-09…13  Retryable evidence-chain failure → durably queued (EVIDENCE_CHAIN_SAVE)
 * PAB-14…16 Non-retryable evidence-chain failure → queued
 * PAB-17…18  PG disabled → persistEntry() is a complete no-op
 */

// FINDING-PG-TENANT-CONTEXT-WRITE-PATH: persistEntry() now wraps its INSERT
// in pgPool.withTransaction() (to set tenant context before writing — see
// pg-audit-backend.js) instead of calling pgPool.query() directly. Routing
// the mocked withTransaction's tx.query through this SAME `query` jest.fn()
// means every existing test's pgPool.query.mockResolvedValueOnce/
// mockRejectedValueOnce(...) setup and pgPool.query.mock.calls assertions
// keep working unchanged — no individual test body edited. Safe here
// because no test in this file overrides tenantId away from makeEntry()'s
// default `null`, so setLocal()'s extra set_config call is never issued and
// never consumes a queued mock value meant for the INSERT.
// persistEntry() now runs pg-audit-backend.js insertMirrorRow(),
// which first asks (migration 058) whether the row's parent is committed and
// whether the row already exists. The transaction double answers ONLY that
// guard statement ("parent committed, row not present yet") and forwards every
// other statement to the same `query` mock — so each test's queued
// mockResolvedValueOnce/mockRejectedValueOnce still reaches the INSERT, exactly
// as before. The guard's own behaviour (parent missing → retryable, already
// present → idempotent) is covered in auditEvidenceHandlers.test.js RH-09..11.
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
  return {
    isEnabled: jest.fn(() => true),
    query,
    withTransaction: jest.fn((fn) => fn({ query: txQuery })),
  };
});
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const mockEnqueue = jest.fn().mockResolvedValue({});
jest.mock('../../../core/persistenceRecovery', () => ({
  enqueue: (...args) => mockEnqueue(...args),
  OPERATION_TYPES: {
    AUDIT_CHAIN_PG_SAVE: 'AUDIT_CHAIN_PG_SAVE',
    EVIDENCE_CHAIN_SAVE: 'EVIDENCE_CHAIN_SAVE',
  },
}));

const mockRecordOrThrow = jest.fn().mockResolvedValue(undefined);
jest.mock('../../../core/evidence/chainStore', () => ({
  recordEvidenceFromAuditEntry: jest.fn(),
  _recordEvidenceFromAuditEntryOrThrow: (...args) => mockRecordOrThrow(...args),
}));

jest.mock('../../../../services/artifact/keyManager', () => ({
  getVerificationKey: jest.fn().mockResolvedValue(null),
}));

const pgPool = require('../pool');
const pgAuditBackend = require('../pg-audit-backend');
const metrics = require('../../../observability/metrics');
const keyManager = require('../../../../services/artifact/keyManager');

// pg-audit-backend.js (Infrastructure) no longer requires keyManager.js
// (Services) directly — it exposes setKeyInfoResolver() as a dependency-
// injection point instead, wired in production by src/core/audit/audit-log.js
// at module load. Mirror that wiring here so this unit test's mocked
// keyManager.getVerificationKey is still the function persistEntry() calls.
pgAuditBackend.setKeyInfoResolver(keyManager.getVerificationKey);

function makeEntry(overrides = {}) {
  return {
    hash: 'h'.repeat(64), prevHash: 'GENESIS', canonical: '{}',
    artifactId: 'art-1', decision: 'ALLOW', timestamp: new Date().toISOString(),
    highResTime: '123', inputHash: 'i'.repeat(64), signature: 's'.repeat(64),
    requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64),
    verificationResult: true, nonce: null, tenantId: null, executionContext: null,
    ...overrides,
  };
}

function retryableError(code = 'ECONNREFUSED') {
  return Object.assign(new Error('connection refused'), { code });
}
function nonRetryableError(code = '23505') {
  return Object.assign(new Error('duplicate key value violates unique constraint'), { code });
}

beforeEach(() => {
  jest.clearAllMocks();
  pgPool.isEnabled.mockReturnValue(true);
  mockEnqueue.mockResolvedValue({});
  mockRecordOrThrow.mockResolvedValue(undefined);
  jest.spyOn(metrics.auditPgRecoveryQueuedTotal, 'inc');
});
afterEach(() => {
  metrics.auditPgRecoveryQueuedTotal.inc.mockRestore();
});

// ═════════════════════════════════════════════════════════════════════════════
// PAB-01…05  Retryable audit_chain failure → durably queued
// ═════════════════════════════════════════════════════════════════════════════

describe('Retryable audit_chain PG failure is durably queued', () => {
  test('PAB-01: a connection-refused error on the audit_chain INSERT enqueues AUDIT_CHAIN_PG_SAVE', async () => {
    pgPool.query.mockRejectedValueOnce(retryableError('ECONNREFUSED'));
    const entry = makeEntry();
    await pgAuditBackend.persistEntry(entry);
    expect(mockEnqueue).toHaveBeenCalledWith('AUDIT_CHAIN_PG_SAVE', entry, expect.any(Error));
  });

  test('PAB-02: a pool-exhaustion-style PG error code (53300) is also queued', async () => {
    pgPool.query.mockRejectedValueOnce(retryableError('53300'));
    await pgAuditBackend.persistEntry(makeEntry());
    expect(mockEnqueue).toHaveBeenCalledWith('AUDIT_CHAIN_PG_SAVE', expect.any(Object), expect.any(Error));
  });

  test('PAB-03: persistEntry never throws even when the PG write and the enqueue both fail', async () => {
    pgPool.query.mockRejectedValueOnce(retryableError());
    mockEnqueue.mockRejectedValueOnce(new Error('redis also down'));
    await expect(pgAuditBackend.persistEntry(makeEntry())).resolves.toBeUndefined();
  });

  test('PAB-04: the recovery-queued metric increments with the AUDIT_CHAIN_PG_SAVE label', async () => {
    pgPool.query.mockRejectedValueOnce(retryableError());
    await pgAuditBackend.persistEntry(makeEntry());
    expect(metrics.auditPgRecoveryQueuedTotal.inc).toHaveBeenCalledWith({ operationType: 'AUDIT_CHAIN_PG_SAVE' });
  });

  test('PAB-05: a successful audit_chain INSERT never enqueues anything', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    await pgAuditBackend.persistEntry(makeEntry());
    expect(mockEnqueue).not.toHaveBeenCalledWith('AUDIT_CHAIN_PG_SAVE', expect.anything(), expect.anything());
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// PAB-06…08  Non-retryable audit_chain failure → NOT queued
// ═════════════════════════════════════════════════════════════════════════════

describe('Non-retryable audit_chain PG failure is not queued', () => {
  test('PAB-06: a unique-violation (23505) is not enqueued — it would never succeed on retry', async () => {
    pgPool.query.mockRejectedValueOnce(nonRetryableError('23505'));
    await pgAuditBackend.persistEntry(makeEntry());
    expect(mockEnqueue).not.toHaveBeenCalledWith('AUDIT_CHAIN_PG_SAVE', expect.anything(), expect.anything());
  });

  test('PAB-07: a syntax error (42601) is not enqueued', async () => {
    pgPool.query.mockRejectedValueOnce(nonRetryableError('42601'));
    await pgAuditBackend.persistEntry(makeEntry());
    expect(mockEnqueue).not.toHaveBeenCalledWith('AUDIT_CHAIN_PG_SAVE', expect.anything(), expect.anything());
  });

  test('PAB-08: persistEntry still resolves normally for a non-retryable error', async () => {
    pgPool.query.mockRejectedValueOnce(nonRetryableError());
    await expect(pgAuditBackend.persistEntry(makeEntry())).resolves.toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// PAB-09…13  Retryable evidence-chain failure → durably queued
// ═════════════════════════════════════════════════════════════════════════════

describe('Retryable evidence-chain failure is durably queued', () => {
  test('PAB-09: a connection failure in evidence-chain generation enqueues EVIDENCE_CHAIN_SAVE', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] }); // audit_chain insert succeeds
    mockRecordOrThrow.mockRejectedValueOnce(retryableError('ECONNRESET'));
    const entry = makeEntry();
    await pgAuditBackend.persistEntry(entry);
    expect(mockEnqueue).toHaveBeenCalledWith(
      'EVIDENCE_CHAIN_SAVE',
      expect.objectContaining({ auditEntry: entry }),
      expect.any(Error),
    );
  });

  test('PAB-10: the queued payload carries the same entry the caller supplied', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    mockRecordOrThrow.mockRejectedValueOnce(retryableError());
    const entry = makeEntry({ artifactId: 'specific-artifact-id' });
    await pgAuditBackend.persistEntry(entry);
    const call = mockEnqueue.mock.calls.find(c => c[0] === 'EVIDENCE_CHAIN_SAVE');
    expect(call[1].auditEntry.artifactId).toBe('specific-artifact-id');
  });

  test('PAB-11: the recovery-queued metric increments with the EVIDENCE_CHAIN_SAVE label', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    mockRecordOrThrow.mockRejectedValueOnce(retryableError());
    await pgAuditBackend.persistEntry(makeEntry());
    expect(metrics.auditPgRecoveryQueuedTotal.inc).toHaveBeenCalledWith({ operationType: 'EVIDENCE_CHAIN_SAVE' });
  });

  test('PAB-12: an audit_chain failure AND an evidence-chain failure in the same call both get queued independently', async () => {
    pgPool.query.mockRejectedValueOnce(retryableError('ECONNREFUSED'));
    mockRecordOrThrow.mockRejectedValueOnce(retryableError('ETIMEDOUT'));
    await pgAuditBackend.persistEntry(makeEntry());
    expect(mockEnqueue).toHaveBeenCalledWith('AUDIT_CHAIN_PG_SAVE', expect.anything(), expect.anything());
    expect(mockEnqueue).toHaveBeenCalledWith('EVIDENCE_CHAIN_SAVE', expect.anything(), expect.anything());
  });

  test('PAB-13: persistEntry never throws even when evidence-chain generation fails', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    mockRecordOrThrow.mockRejectedValueOnce(retryableError());
    await expect(pgAuditBackend.persistEntry(makeEntry())).resolves.toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// PAB-14…16 Non-retryable evidence-chain failure → queued
//
// Inverted in these pinned the defect (a committed audit entry left
// with no evidence row and only a log line). The queued replay is safe for a
// unique-violation because the evidence writer is idempotent (an
// artifact that already has its row is success); a deterministic failure is
// moved to the DLQ after one replay attempt (worker.js).
// ═════════════════════════════════════════════════════════════════════════════

describe('Non-retryable evidence-chain failure is queued', () => {
  test('PAB-14: a unique-violation on evidence_chain_records is enqueued', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    mockRecordOrThrow.mockRejectedValueOnce(nonRetryableError('23505'));
    await pgAuditBackend.persistEntry(makeEntry());
    expect(mockEnqueue).toHaveBeenCalledWith('EVIDENCE_CHAIN_SAVE', expect.anything(), expect.anything());
  });

  test('PAB-15: a data exception (22xxx class) is enqueued', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    mockRecordOrThrow.mockRejectedValueOnce(nonRetryableError('22001'));
    await pgAuditBackend.persistEntry(makeEntry());
    expect(mockEnqueue).toHaveBeenCalledWith('EVIDENCE_CHAIN_SAVE', expect.anything(), expect.anything());
  });

  test('PAB-16: persistEntry still resolves normally for a non-retryable evidence error', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    mockRecordOrThrow.mockRejectedValueOnce(nonRetryableError());
    await expect(pgAuditBackend.persistEntry(makeEntry())).resolves.toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// PAB-19…21 executionContext.publicKeyId → key lookup wiring
//
// publicKeyId was computed during every execution but never written
// into the audit entry's executionContext (fixed in aiChat.js / streamEnforcer.js),
// which meant this key lookup here — the link between the audit entry and the
// keyInfo that chainStore.buildEvidenceRecord() uses to compute
// key_fingerprint — never fired for a real production entry. These tests
// pin the pg-audit-backend side of that wiring: given an entry that DOES
// carry executionContext.publicKeyId, the verification key is looked up and
// handed to the evidence-chain writer; given one that doesn't (e.g. a BLOCK
// recorded before any key was resolved), it is legitimately skipped.
// ═════════════════════════════════════════════════════════════════════════════

describe('executionContext.publicKeyId drives the verification-key lookup', () => {
  test('PAB-19: an entry with executionContext.publicKeyId looks up that exact key', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    const entry = makeEntry({ executionContext: { stage: 'PROVIDER_EXECUTION', publicKeyId: 'default:key_v1' } });
    await pgAuditBackend.persistEntry(entry);
    expect(keyManager.getVerificationKey).toHaveBeenCalledWith('default:key_v1');
  });

  test('PAB-20: the resolved keyInfo is passed through to the evidence-chain writer', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    const keyInfo = { publicKeyB64: 'b64key', status: 'active' };
    keyManager.getVerificationKey.mockResolvedValueOnce(keyInfo);
    const entry = makeEntry({ executionContext: { stage: 'PROVIDER_EXECUTION', publicKeyId: 'default:key_v1' } });
    await pgAuditBackend.persistEntry(entry);
    expect(mockRecordOrThrow).toHaveBeenCalledWith(entry, keyInfo, null);
  });

  test('PAB-21: an entry without executionContext.publicKeyId never looks up a key, and keyInfo passed through is null', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    const entry = makeEntry({ executionContext: { stage: 'VALIDATION', reason: 'INVALID_SIGNATURE' } });
    await pgAuditBackend.persistEntry(entry);
    expect(keyManager.getVerificationKey).not.toHaveBeenCalled();
    expect(mockRecordOrThrow).toHaveBeenCalledWith(entry, null, null);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// PAB-22…25 public_key_id/schema_version persisted + key lookup
// prefers the new durable, hash-protected top-level field
// ═════════════════════════════════════════════════════════════════════════════

describe('remediation: publicKeyId/schemaVersion persisted to PG', () => {
  test('PAB-22: the audit_chain INSERT is called with entry.publicKeyId and entry.schemaVersion as parameters', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    const entry = makeEntry({ publicKeyId: 'tenant-a:key_v1', schemaVersion: 2 });
    await pgAuditBackend.persistEntry(entry);
    const [, params] = pgPool.query.mock.calls[0];
    expect(params).toContain('tenant-a:key_v1');
    expect(params).toContain(2);
  });

  test('PAB-23: an entry with no publicKeyId/schemaVersion persists null / legacy default 1', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    const entry = makeEntry(); // no publicKeyId, no schemaVersion
    await pgAuditBackend.persistEntry(entry);
    const [, params] = pgPool.query.mock.calls[0];
    expect(params).toContain(null);
    expect(params).toContain(1);
  });

  test('PAB-24: the key lookup prefers the new top-level publicKeyId over the legacy executionContext copy', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    const entry = makeEntry({
      publicKeyId: 'new-field-key',
      executionContext: { stage: 'PROVIDER_EXECUTION', publicKeyId: 'legacy-field-key' },
    });
    await pgAuditBackend.persistEntry(entry);
    expect(keyManager.getVerificationKey).toHaveBeenCalledWith('new-field-key');
  });

  test('PAB-25: the key lookup still falls back to executionContext.publicKeyId for legacy entries missing the top-level field', async () => {
    pgPool.query.mockResolvedValueOnce({ rows: [] });
    const entry = makeEntry({
      executionContext: { stage: 'PROVIDER_EXECUTION', publicKeyId: 'legacy-only-key' },
    });
    await pgAuditBackend.persistEntry(entry);
    expect(keyManager.getVerificationKey).toHaveBeenCalledWith('legacy-only-key');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// PAB-17…18  PG disabled → complete no-op
// ═════════════════════════════════════════════════════════════════════════════

describe('PG disabled', () => {
  test('PAB-17: persistEntry does nothing at all when pgPool.isEnabled() is false', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    await pgAuditBackend.persistEntry(makeEntry());
    expect(pgPool.query).not.toHaveBeenCalled();
    expect(mockRecordOrThrow).not.toHaveBeenCalled();
    expect(mockEnqueue).not.toHaveBeenCalled();
  });

  test('PAB-18: persistEntry resolves cleanly when PG is disabled', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    await expect(pgAuditBackend.persistEntry(makeEntry())).resolves.toBeUndefined();
  });
});
