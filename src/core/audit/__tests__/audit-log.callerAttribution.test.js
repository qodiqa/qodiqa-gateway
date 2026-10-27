'use strict';

/**
 * remediation — durable, hash-protected CALLER attribution.
 *
 * Root cause (master-findings-
 * register.md reconfirming TRUST-1/COMP-15): the audit chain only
 * ever recorded publicKeyId — the shared tenant signing key — as attribution
 * for a decision. Two different authenticated callers signing under the same
 * tenant key produced cryptographically identical, indistinguishable audit
 * entries. This suite proves the fix at the audit-log.js layer, mirroring
 * audit-log.keyAttribution.test.js's KA-* structure for the earlier,
 * analogous fix:
 *
 * CA-01…CA-04: new entries carry callerContext as part of the protected hash
 *              (schemaVersion 4) — durable and tamper-evident, not just
 *              present.
 * CA-05…CA-07: legacy (schemaVersion < 4, or schemaVersion 4 with no
 *              callerContext — pre-NONREP-1 artifact) entries continue to
 *              load and verify exactly as before.
 *
 * NOTE (PERF-10): see audit-log.keyAttribution.test.js's file header — every
 * append() is awaited; freshAudit() installs fs.promises mocks up front.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
// v7 (R-12 / R-14): callerContext.callerId is pseudonymized on append, which needs PostgreSQL in production
// (fail-closed without it). This suite has no database, so it opts in to the EXPLICIT test-only pseudonym stand-in.
jest.mock('../../dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
const { expectedPseudonym: w7Pseudonym } = require('../../../../test/helpers/subjectPseudonymMock');

const crypto = require('crypto');
const { sortedJSON, domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');

function uuid() { return crypto.randomUUID(); }

const SAMPLE_CALLER_CONTEXT = Object.freeze({
  callerId: 'identity-caller-a', callerName: 'ci-runner', environment: 'test', credentialType: 'api-key',
});

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

// Hand-builds a legacy (schemaVersion 3 / pre-NONREP-1) entry exactly as the
// OLD append() produced: no callerContext field at all, hashed only over the
// 13 CORE_HASH_FIELDS_V3.
function buildV3Entry({ artifactId, prevHash, timestamp }) {
  const coreFields = {
    artifactId,
    consentProvenance:  null,
    decision:           'ALLOW',
    inputHash:          'a'.repeat(64),
    policyDecision:     null,
    policyHash:         'p'.repeat(64),
    prevHash,
    publicKeyId:        'tenant-a:key_v1',
    requestHash:        'r'.repeat(64),
    schemaVersion:      3,
    signature:          's'.repeat(64),
    timestamp,
    verificationResult: true,
  };
  const canonical = sortedJSON(coreFields);
  const hash      = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex');
  return { ...coreFields, highResTime: '1', canonical, hash };
}

describe('CA-01…CA-04: new entries hash-protect callerContext', () => {
  test('CA-01 append() stamps the current schema version and the given callerContext — callerId pseudonymized (R-12/R-13)', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams({ callerContext: SAMPLE_CALLER_CONTEXT }));
    expect(e.schemaVersion).toBe(audit.CURRENT_SCHEMA_VERSION);
    expect(e.schemaVersion).toBe(7);
    expect(e.callerContext).toEqual({ ...SAMPLE_CALLER_CONTEXT, callerId: w7Pseudonym(null, SAMPLE_CALLER_CONTEXT.callerId) });
    expect(JSON.stringify(e)).not.toContain(SAMPLE_CALLER_CONTEXT.callerId);   // no raw identifier anywhere in the entry
  });

  test('CA-02 append() with no callerContext stores null (not a placeholder) and still produces a valid hash', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams());
    expect(e.callerContext).toBeNull();
    expect(typeof e.hash).toBe('string');
    expect(e.hash).toHaveLength(64);
    expect(audit.verifyAuditChainDetailed([e]).valid).toBe(true);
  });

  test('CA-03 callerContext participates in the protected hash — differing only in caller yields a different hash', async () => {
    const sharedFields = {
      artifactId: 'fixed-artifact-id-ca03',
      inputHash: 'a'.repeat(64), requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64),
      signature: 's'.repeat(64), verificationResult: true, decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      publicKeyId: 'tenant-a:key_v1',
    };
    const audit = freshAudit();
    const eA = await audit.append({ ...sharedFields, callerContext: { ...SAMPLE_CALLER_CONTEXT, callerId: 'caller-A' } });
    const audit2 = freshAudit();
    const eB = await audit2.append({ ...sharedFields, callerContext: { ...SAMPLE_CALLER_CONTEXT, callerId: 'caller-B' } });
    expect(eA.hash).not.toBe(eB.hash);
  });

  test('CA-04 recorded callerContext on an entry is hash-protected, not just present — tampering is detected', async () => {
    const audit = freshAudit();
    await audit.append(allowParams({ callerContext: SAMPLE_CALLER_CONTEXT }));
    const [entry] = await audit.getAuditChain();
    const tampered = { ...entry, callerContext: { ...entry.callerContext, callerId: 'someone-else-entirely' } };
    const result = audit.verifyAuditChainDetailed([tampered]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
    expect(result.tamperingDetected).toBe(true);
  });
});

describe('CA-05…CA-07: legacy (pre-NONREP-1) entries load and verify unchanged', () => {
  test('CA-05 a hand-built schemaVersion 3 entry with no callerContext field hashes under the 13-field formula and verifies correctly', async () => {
    const audit = freshAudit();
    const entry = buildV3Entry({ artifactId: 'legacy-' + uuid(), prevHash: 'GENESIS', timestamp: new Date().toISOString() });
    expect(Object.keys(JSON.parse(entry.canonical))).toHaveLength(13);
    expect(audit.verifyAuditChainDetailed([entry]).valid).toBe(true);
  });

  test('CA-06 a hand-built legacy (schemaVersion 3) entry and a new (schemaVersion 4) entry each verify correctly under their own formula in the same batch', async () => {
    // verifyAuditChainDetailed dispatches per-entry on schemaVersion (see
    // entryBuilder.hashFieldsFor) — this proves a schemaVersion 3 entry with
    // no callerContext is not incorrectly evaluated against the 14-field V4
    // formula (which would spuriously fail it as tampered).
    const legacy = buildV3Entry({ artifactId: 'legacy-' + uuid(), prevHash: 'GENESIS', timestamp: new Date().toISOString() });
    const audit  = freshAudit();
    const modern = await audit.append(allowParams({ callerContext: SAMPLE_CALLER_CONTEXT }));
    expect(audit.verifyAuditChainDetailed([legacy]).valid).toBe(true);
    expect(audit.verifyAuditChainDetailed([modern]).valid).toBe(true);
  });

  test('CA-07 CORE_HASH_FIELDS_V3 (legacy) and CORE_HASH_FIELDS_V4 (legacy) are both exported and V4 strictly extends V3 by callerContext', async () => {
    const audit = freshAudit();
    expect(audit.CORE_HASH_FIELDS_V3).toBeDefined();
    expect(audit.CORE_HASH_FIELDS_V4).toEqual([...audit.CORE_HASH_FIELDS_V3, 'callerContext']);
    // moved CURRENT_SCHEMA_VERSION to 5 (CORE_HASH_FIELDS_V5 = V4 +
    // provider + model), and moved it again to 6 (CORE_HASH_FIELDS_V6
    // = V5 + stage/reason/semantic/tokenUsage/responseId) — V4 remains a
    // supported legacy formula forever.
    expect(audit.CURRENT_SCHEMA_VERSION).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)
  });
});
