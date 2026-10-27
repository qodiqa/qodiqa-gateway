'use strict';

/**
 * audit-log rejects, before any write, a
 * policyDecision.policyId the evidence ledger cannot represent (policy_id VARCHAR(256)).
 * The real PostgreSQL proof is test/integration/policyIdBound.integration.test.js.
 *
 *   PU-01  distributed: 256 characters accepted; 257 rejected (invalid_policyDecision) and
 *          the ordering transaction (distributedOrdering.appendEntry) is never started
 *   PU-02  the bound counts characters (code points), as PostgreSQL VARCHAR does:
 *          256 astral characters (512 UTF-16 units) accepted; 257 rejected
 *   PU-03  null / absent policyDecision and a null or non-string policyId are unchanged
 *   PU-04  appendMandatory: deterministic, not retried
 *   PU-05  single-node: the rejection happens before the WAL / log write (file unchanged)
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs = require('fs');

const committed = (fields) => Object.freeze({ ...fields, hash: 'a'.repeat(64), prevHash: 'GENESIS', canonical: '{}', timestamp: new Date().toISOString(), highResTime: '1', schemaVersion: 6 });
let seq = 0;
const FIELDS = (policyDecision) => {
  seq += 1; const id = `h136-unit-${seq}`;
  return { artifactId: id, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
    verificationResult: true, nonce: `n-${id}`, tenantId: 'tenant-a', publicKeyId: 'tenant-a:key_v1', ...(policyDecision !== undefined ? { policyDecision } : {}) };
};
const pd = (policyId) => ({ policyId, policyVersion: 1, policyRuleHash: null, engineVersion: 'x', evaluatedAt: null, evaluationPath: [] });

function loadDistributed(appendEntry) {
  jest.resetModules();
  process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
  jest.doMock('../distributedOrdering', () => ({ appendEntry }));
  jest.doMock('../../../infra/postgres/pg-audit-backend', () => ({ setKeyInfoResolver: jest.fn(), persistEntry: jest.fn(), recordEvidenceForEntry: jest.fn().mockResolvedValue(undefined) }));
  return require('../audit-log');
}

describe('policyId bound — distributed branch', () => {
  const ORIGINAL = process.env.QODIQA_AUDIT_ORDERING_MODE;
  afterEach(() => {
    if (ORIGINAL === undefined) delete process.env.QODIQA_AUDIT_ORDERING_MODE; else process.env.QODIQA_AUDIT_ORDERING_MODE = ORIGINAL;
    jest.dontMock('../distributedOrdering'); jest.dontMock('../../../infra/postgres/pg-audit-backend');
  });

  test('PU-01 256 characters accepted; 257 rejected before the ordering transaction starts', async () => {
    const appendEntry = jest.fn(async (f) => committed(f));
    const auditLog = loadDistributed(appendEntry);
    await expect(auditLog.append(FIELDS(pd('p'.repeat(256))))).resolves.toBeDefined();
    expect(appendEntry).toHaveBeenCalledTimes(1);
    await expect(auditLog.append(FIELDS(pd('p'.repeat(257))))).rejects.toThrow(/^invalid_policyDecision: policyId exceeds the evidence ledger limit of 256 characters$/);
    expect(appendEntry).toHaveBeenCalledTimes(1);
  });

  test('PU-02 counts characters (code points), not UTF-16 units', async () => {
    const appendEntry = jest.fn(async (f) => committed(f));
    const auditLog = loadDistributed(appendEntry);
    const astral = '\u{1F600}';
    expect(astral.repeat(256).length).toBe(512);
    await expect(auditLog.append(FIELDS(pd(astral.repeat(256))))).resolves.toBeDefined();
    await expect(auditLog.append(FIELDS(pd(astral.repeat(257))))).rejects.toThrow(/^invalid_policyDecision/);
    expect(appendEntry).toHaveBeenCalledTimes(1);
  });

  test.each([
    ['no policyDecision', undefined],
    ['policyDecision null', null],
    ['policyId null', pd(null)],
    ['numeric policyId', pd(12345)],
  ])('PU-03 %s is unchanged', async (_n, decision) => {
    const appendEntry = jest.fn(async (f) => committed(f));
    const auditLog = loadDistributed(appendEntry);
    await expect(auditLog.append(FIELDS(decision))).resolves.toBeDefined();
    expect(appendEntry).toHaveBeenCalledTimes(1);
  });

  test('PU-04 appendMandatory: the rejection is deterministic and not retried', async () => {
    const appendEntry = jest.fn(async (f) => committed(f));
    const auditLog = loadDistributed(appendEntry);
    await expect(auditLog.appendMandatory(FIELDS(pd('p'.repeat(300))), { stage: 'ALLOW', maxRetries: 3, retryDelayMs: 1 })).rejects.toThrow(/^invalid_policyDecision/);
    expect(appendEntry).not.toHaveBeenCalled();
  });
});

describe('policyId bound — single-node branch', () => {
  test('PU-05 the rejection happens before the WAL / audit.log write', async () => {
    jest.resetModules();
    delete process.env.QODIQA_AUDIT_ORDERING_MODE;
    jest.doMock('../../../infra/postgres/pg-audit-backend', () => ({ setKeyInfoResolver: jest.fn(), persistEntry: jest.fn().mockResolvedValue(undefined) }));
    const auditLog = require('../audit-log');
    expect(auditLog.ORDERING_MODE).toBe('single-node');
    const logPath = process.env.QODIQA_AUDIT_LOG;
    const size = () => (fs.existsSync(logPath) ? fs.statSync(logPath).size : 0);
    const before = size(); const len0 = auditLog.getChainLength();
    await expect(auditLog.append(FIELDS(pd('p'.repeat(257))))).rejects.toThrow(/^invalid_policyDecision/);
    expect(size()).toBe(before);
    expect(auditLog.getChainLength()).toBe(len0);
    await expect(auditLog.append(FIELDS(pd('p'.repeat(256))))).resolves.toBeDefined();
    expect(auditLog.getChainLength()).toBe(len0 + 1);
    jest.dontMock('../../../infra/postgres/pg-audit-backend');
  });
});
