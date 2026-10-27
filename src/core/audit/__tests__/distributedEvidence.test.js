'use strict';

/**
 * audit-log.js distributed branch schedules the
 * evidence-chain record AFTER the distributed audit commit, best-effort, NOT awaited.
 *
 * distributedOrdering.appendEntry() (the committed audit transaction) and
 * pg-audit-backend (the evidence step) are doubles here; the real PostgreSQL path
 * is covered by test/integration/distributedEvidenceLedger.integration.test.js.
 *
 *   DE-01  evidence step called exactly once, with the committed entry, after commit
 *   DE-02  append() does not wait for the evidence step (A1, not A2)
 *   DE-03  an evidence-step rejection never fails append()
 *   DE-04  a failed audit commit schedules no evidence step
 *   DE-05  a pg-audit-backend double without the export still appends (typeof guard)
 *   DE-06  the distributed branch never calls persistEntry() (no second audit_chain write)
 */

// audit-log.js requires ./distributedOrdering lazily (at append time), so the doubles
// must live in the module registry that is current when append() runs — a fresh
// registry per test (resetModules), not an isolateModules scope that has already exited.
const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
function loadDistributed({ appendEntry, backend }) {
  jest.resetModules();
  process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
  jest.doMock('../distributedOrdering', () => ({ appendEntry }));
  jest.doMock('../../../infra/postgres/pg-audit-backend', () => backend);
  return require('../audit-log');
}

const committed = (fields) => Object.freeze({
  ...fields, hash: 'a'.repeat(64), prevHash: 'GENESIS', canonical: '{}', timestamp: new Date().toISOString(), highResTime: '1', schemaVersion: 6,
});
const FIELDS = {
  artifactId: 'h134-unit-1', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig', requestHash: 'b'.repeat(64),
  policyHash: 'c'.repeat(64), verificationResult: true, nonce: 'n-h134-unit-1', tenantId: 'tenant-a', publicKeyId: 'tenant-a:key_v1',
};

describe('A1 — distributed append schedules the evidence step post-commit', () => {
  const ORIGINAL = process.env.QODIQA_AUDIT_ORDERING_MODE;
  afterEach(() => {
    if (ORIGINAL === undefined) delete process.env.QODIQA_AUDIT_ORDERING_MODE; else process.env.QODIQA_AUDIT_ORDERING_MODE = ORIGINAL;
    jest.dontMock('../distributedOrdering');
    jest.dontMock('../../../infra/postgres/pg-audit-backend');
  });

  function backendDouble(recordEvidenceForEntry) {
    return { setKeyInfoResolver: jest.fn(), persistEntry: jest.fn().mockResolvedValue(undefined), recordEvidenceForEntry };
  }

  test('DE-01 evidence step called exactly once with the committed entry, only after appendEntry() resolved', async () => {
    const order = [];
    const appendEntry = jest.fn(async (f) => { order.push('commit'); return committed(f); });
    const record = jest.fn(async () => { order.push('evidence'); });
    const auditLog = loadDistributed({ appendEntry, backend: backendDouble(record) });
    expect(auditLog.ORDERING_MODE).toBe('distributed');
    const entry = await auditLog.append(FIELDS);
    expect(record).toHaveBeenCalledTimes(1);
    expect(record.mock.calls[0][0]).toBe(entry);
    expect(order).toEqual(['commit', 'evidence']);
  });

  test('DE-02 append() resolves while the evidence step is still pending (not awaited)', async () => {
    const appendEntry = jest.fn(async (f) => committed(f));
    let started = false;
    const record = jest.fn(() => { started = true; return new Promise(() => {}); }); // never settles
    const auditLog = loadDistributed({ appendEntry, backend: backendDouble(record) });
    const entry = await auditLog.append(FIELDS);
    expect(entry.hash).toBe('a'.repeat(64));
    expect(started).toBe(true);
  });

  test('DE-03 an evidence-step rejection never fails append()', async () => {
    const appendEntry = jest.fn(async (f) => committed(f));
    const record = jest.fn().mockRejectedValue(Object.assign(new Error('boom'), { code: '08006' }));
    const auditLog = loadDistributed({ appendEntry, backend: backendDouble(record) });
    await expect(auditLog.append(FIELDS)).resolves.toEqual(expect.objectContaining({ artifactId: 'h134-unit-1' }));
    await new Promise(r => setImmediate(r)); // the rejection is absorbed, not unhandled
    expect(record).toHaveBeenCalledTimes(1);
  });

  test('DE-04 a failed audit commit schedules no evidence step and still propagates', async () => {
    const appendEntry = jest.fn().mockRejectedValue(new Error('already_executed: artifactId already in audit log'));
    const record = jest.fn().mockResolvedValue(undefined);
    const auditLog = loadDistributed({ appendEntry, backend: backendDouble(record) });
    await expect(auditLog.append(FIELDS)).rejects.toThrow(/already_executed/);
    expect(record).not.toHaveBeenCalled();
  });

  test('DE-05 a pg-audit-backend double without recordEvidenceForEntry still appends', async () => {
    const appendEntry = jest.fn(async (f) => committed(f));
    const auditLog = loadDistributed({ appendEntry, backend: { setKeyInfoResolver: jest.fn(), persistEntry: jest.fn() } });
    await expect(auditLog.append(FIELDS)).resolves.toEqual(expect.objectContaining({ artifactId: 'h134-unit-1' }));
  });

  test('DE-06 the distributed branch never calls persistEntry() (no second audit_chain write)', async () => {
    const appendEntry = jest.fn(async (f) => committed(f));
    const backend = backendDouble(jest.fn().mockResolvedValue(undefined));
    const auditLog = loadDistributed({ appendEntry, backend });
    await auditLog.append(FIELDS);
    expect(backend.persistEntry).not.toHaveBeenCalled();
  });
});
