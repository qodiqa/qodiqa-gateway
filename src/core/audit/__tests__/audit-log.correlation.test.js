'use strict';

/**
 * remediation — requestId/traceId correlation fields on audit chain
 * entries.
 *
 * Root cause: the audit chain (this file / entryBuilder.js) and the
 * operational log stream (services/logger.js) evolved as two genuinely
 * different systems — one a signed, hash-chained compliance record whose
 * field set is fixed by QODIQA-PROTOCOL-SPEC.md §11.3, the other a general
 * activity stream for SIEM/observability — and never shared a correlation
 * envelope. The audit chain had no requestId field at all (only a one-way
 * requestHash) and no traceId, so a SOC analyst could not join an audit
 * chain entry to the operational events from the same request without
 * bespoke mapping.
 *
 * This suite proves the fix: requestId/traceId are carried through as
 * additive, NOT hash-protected fields (same pattern as tenantId/
 * organizationId) — so correlation improves without altering the
 * cryptographic hash formula, breaking existing signed entries, or touching
 * the external SDK/verifier contract. See SIEM-3-REMEDIATION-REPORT.md.
 *
 * CR-01..CR-03: requestId/traceId are recorded when supplied, omitted when
 *               not (consistent with tenantId's existing null-omission
 *               behaviour).
 * CR-04..CR-05: neither field participates in the protected hash — adding,
 *               removing, or changing either leaves the hash unchanged, and
 *               a legacy entry with neither field still verifies.
 *
 * audit schema v7 CHANGES this contract for requestId
 * only: on v7 entries requestId is a HASHED core field (it is the link between an INTENT / STREAM_OPENED entry and
 * its DECISION), so it is always present (null when not supplied — absent ≡ null) and rewriting it at rest IS
 * tampering. traceId keeps the contract unchanged (unhashed, omitted when absent). CR-02..CR-05 assert the v7
 * contract in both directions; pre-v7 entries keep their original field sets (hashFieldsFor()).
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');

function uuid() { return crypto.randomUUID(); }

function allowParams(overrides = {}) {
  return {
    artifactId:         uuid(),
    inputHash:          'a'.repeat(64),
    decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:          's'.repeat(64),
    requestHash:        'r'.repeat(64),
    policyHash:         'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

function _installFsPromisesMocks(fsMod) {
  fsMod.promises = {
    writeFile:  jest.fn().mockResolvedValue(undefined),
    appendFile: jest.fn().mockResolvedValue(undefined),
    open:       jest.fn().mockResolvedValue({
      sync:  jest.fn().mockResolvedValue(undefined),
      close: jest.fn().mockResolvedValue(undefined),
      // S33: the reused WAL is written/truncated through its held FileHandle (real fs.promises FileHandle API)
      write:    jest.fn().mockImplementation((buf, off, len) => Promise.resolve({ bytesWritten: len, buffer: buf })),
      truncate: jest.fn().mockResolvedValue(undefined),
    }),
    rename:    jest.fn().mockResolvedValue(undefined),
    copyFile:  jest.fn().mockResolvedValue(undefined),
    unlink:    jest.fn().mockResolvedValue(undefined),
  };
}

function freshAudit() {
  let mod;
  jest.isolateModules(() => {
    const fs = require('fs');
    fs.existsSync.mockReturnValue(false);
    _installFsPromisesMocks(fs);
    mod = require('../audit-log');
  });
  return mod;
}

describe('CR-01..CR-03: requestId/traceId are recorded when supplied', () => {
  test('CR-01 append() stamps requestId and traceId on the entry when both are given', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams({ requestId: 'req-123', traceId: 'a'.repeat(32) }));
    expect(e.requestId).toBe('req-123');
    expect(e.traceId).toBe('a'.repeat(32));
  });

  test('CR-02 append() with neither field: v7 records requestId as null (hashed core field), omits traceId', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams());
    expect(e.schemaVersion).toBe(7);
    expect(e.requestId).toBeNull();
    expect('traceId' in e).toBe(false);
  });

  test('CR-03 requestId may be supplied without traceId (tracing disabled) and vice versa', async () => {
    const audit = freshAudit();
    const withRequestOnly = await audit.append(allowParams({ requestId: 'req-only' }));
    expect(withRequestOnly.requestId).toBe('req-only');
    expect('traceId' in withRequestOnly).toBe(false);

    const audit2 = freshAudit();
    const withTraceOnly = await audit2.append(allowParams({ traceId: 'b'.repeat(32) }));
    expect(withTraceOnly.traceId).toBe('b'.repeat(32));
    expect(withTraceOnly.requestId).toBeNull();   // v7: hashed core field, absent ≡ null
  });
});

describe('CR-04..CR-05: traceId is NOT hash-protected; requestId IS from v7 on', () => {
  test('CR-04 identical core fields: a different traceId keeps the hash, a different requestId changes it (v7)', async () => {
    // timestamp is itself a hash-protected core field (generated inside
    // buildEntry() at append() time) — freeze the clock so the only thing
    // that differs between e1/e2 is requestId/traceId, isolating exactly
    // the variable this test is about.
    jest.useFakeTimers({ now: new Date('2024-06-01T00:00:00.000Z') });
    try {
      const sharedFields = {
        artifactId:  'fixed-artifact-id-cr04',
        inputHash:   'a'.repeat(64),
        requestHash: 'r'.repeat(64),
        policyHash:  'p'.repeat(64),
        signature:   's'.repeat(64),
        verificationResult: true,
        decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      };
      const a1 = freshAudit();
      const e1 = await a1.append({ ...sharedFields, requestId: 'req-A', traceId: 'a'.repeat(32) });
      const a2 = freshAudit();
      const e2 = await a2.append({ ...sharedFields, requestId: 'req-A', traceId: 'b'.repeat(32) });
      expect(e1.hash).toBe(e2.hash);
      const a3 = freshAudit();
      const e3 = await a3.append({ ...sharedFields, requestId: 'req-B', traceId: 'a'.repeat(32) });
      expect(e3.hash).not.toBe(e1.hash);
    } finally {
      jest.useRealTimers();
    }
  });

  test('CR-05 rewriting traceId at rest is not tampering; rewriting requestId at rest IS (v7 hashed)', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams({ requestId: 'req-original', traceId: 'a'.repeat(32) }));
    const traceRewritten = { ...e, traceId: 'b'.repeat(32) };
    const ok = audit.verifyAuditChainDetailed([traceRewritten]);
    expect(ok.valid).toBe(true);
    expect(ok.tamperingDetected).toBe(false);
    const requestRewritten = { ...e, requestId: 'req-rewritten' };
    const bad = audit.verifyAuditChainDetailed([requestRewritten]);
    expect(bad.valid).toBe(false);
    expect(bad.tamperingDetected).toBe(true);
  });
});
