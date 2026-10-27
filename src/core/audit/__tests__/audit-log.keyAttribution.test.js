'use strict';

/**
 * remediation — durable, hash-protected key attribution.
 *
 * Root cause: the
 * signing key that authorized a decision was never recorded as a protected,
 * hash-chained field on the audit chain entry — only as an unprotected
 * sub-field of the optional `executionContext` blob, and only on some code
 * paths. This suite proves the fix at the audit-log.js layer:
 *
 * KA-01…KA-04: new entries carry publicKeyId as part of the protected hash
 *              (schemaVersion 2) — it is durable and tamper-evident, not
 *              just present.
 * KA-05…KA-08: legacy (schemaVersion 1, pre-fix) entries — with no
 *              publicKeyId field at all — continue to load and verify
 *              exactly as before. Historical evidence remains readable.
 *
 * NOTE (PERF-10): append() is asynchronous (fs.promises I/O behind a
 * module-level write queue), so every `.append(...)` call is awaited. See
 * audit-chain-hash-conformance.test.js's file header for the full rationale
 * on why freshAudit() installs fs.promises.* mocks before requiring
 * audit-log.js (jest.mock('fs') automocks fs.*Sync but leaves fs.promises
 * undefined).
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const { sortedJSON, domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');

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

// Hand-builds a legacy (schemaVersion 1 / pre-NONREP-2-fix) entry exactly as
// the OLD append() produced: no publicKeyId, no schemaVersion field at all,
// hashed only over the original 9 CORE_HASH_FIELDS_V1.
function buildLegacyEntry({ artifactId, prevHash, timestamp, includeLegacyExecutionContextKey = false }) {
  const coreFields = {
    artifactId,
    decision:            'ALLOW',
    inputHash:           'a'.repeat(64),
    policyHash:          'p'.repeat(64),
    prevHash,
    requestHash:         'r'.repeat(64),
    signature:           's'.repeat(64),
    timestamp,
    verificationResult:  true,
  };
  const canonical = sortedJSON(coreFields);
  const hash      = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex');
  return {
    ...coreFields,
    highResTime: '1',
    ...(includeLegacyExecutionContextKey
      ? { executionContext: { stage: 'PROVIDER_EXECUTION', publicKeyId: 'legacy-tenant:key_v1' } }
      : {}),
    canonical,
    hash,
  };
}

// ── KA-01…KA-04: new entries — durable, tamper-evident attribution ───────────

describe('KA-01…KA-04: new entries hash-protect publicKeyId', () => {
  test('KA-01 append() stamps the current schema version and the given publicKeyId on the entry', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams({ publicKeyId: 'tenant-a:key_v1' }));
    // TRACE-2 bumped CURRENT_SCHEMA_VERSION 2 -> 3; publicKeyId protection
    // (this test's subject) is unaffected — still hash-protected on V2+.
    expect(e.schemaVersion).toBe(audit.CURRENT_SCHEMA_VERSION);
    expect(e.publicKeyId).toBe('tenant-a:key_v1');
  });

  test('KA-02 append() with no publicKeyId stores null (not a placeholder string) and still produces a valid hash', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams());
    expect(e.publicKeyId).toBeNull();
    expect(e.schemaVersion).toBe(audit.CURRENT_SCHEMA_VERSION);
    expect(typeof e.hash).toBe('string');
    expect(e.hash).toHaveLength(64);
    expect(audit.verifyAuditChainDetailed([e]).valid).toBe(true);
  });

  test('KA-03 publicKeyId participates in the protected hash — differing only in key yields a different hash', async () => {
    const sharedFields = {
      artifactId:  'fixed-artifact-id-ka03',
      inputHash:   'a'.repeat(64),
      requestHash: 'r'.repeat(64),
      policyHash:  'p'.repeat(64),
      signature:   's'.repeat(64),
      verificationResult: true,
      decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    };
    const a1 = freshAudit();
    const e1 = await a1.append({ ...sharedFields, publicKeyId: 'key-A' });
    const a2 = freshAudit();
    const e2 = await a2.append({ ...sharedFields, publicKeyId: 'key-B' });
    expect(e1.hash).not.toBe(e2.hash);
  });

  test('KA-04 tampering with publicKeyId after the fact is detected as chain tampering', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams({ publicKeyId: 'key-A' }));
    // Simulate an attacker rewriting only the key attribution field at rest.
    const tampered = { ...e, publicKeyId: 'key-B' };
    const result = audit.verifyAuditChainDetailed([tampered]);
    expect(result.valid).toBe(false);
    expect(result.tamperingDetected).toBe(true);
    expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
  });

  test('KA-04b stripping schemaVersion back down to look like a legacy entry also breaks verification', async () => {
    const audit = freshAudit();
    const e = await audit.append(allowParams({ publicKeyId: 'key-A' }));
    const { schemaVersion: _drop, ...downgraded } = e;
    const result = audit.verifyAuditChainDetailed([downgraded]);
    expect(result.valid).toBe(false);
    expect(result.tamperingDetected).toBe(true);
  });
});

// ── KA-05…KA-08: legacy entries remain readable and verifiable ───────────────

describe('KA-05…KA-08: legacy (schemaVersion 1) entries remain fully readable', () => {
  test('KA-05 a hand-built legacy entry (no publicKeyId/schemaVersion fields) verifies successfully', async () => {
    const audit = freshAudit();
    const legacy = buildLegacyEntry({
      artifactId: uuid(),
      prevHash:   'GENESIS',
      timestamp:  new Date().toISOString(),
    });
    const result = audit.verifyAuditChainDetailed([legacy]);
    expect(result.valid).toBe(true);
    expect(result.tamperingDetected).toBe(false);
  });

  test('KA-06 a legacy entry carrying only the old unprotected executionContext.publicKeyId still verifies (that field was never hashed, so its presence is compatible)', async () => {
    const audit = freshAudit();
    const legacy = buildLegacyEntry({
      artifactId: uuid(),
      prevHash:   'GENESIS',
      timestamp:  new Date().toISOString(),
      includeLegacyExecutionContextKey: true,
    });
    const result = audit.verifyAuditChainDetailed([legacy]);
    expect(result.valid).toBe(true);
  });

  test('KA-07 loading a mixed legacy-then-new-schema chain from disk at startup succeeds end to end', async () => {
    const legacyId = uuid();
    const legacy = buildLegacyEntry({
      artifactId: legacyId,
      prevHash:   'GENESIS',
      timestamp:  new Date().toISOString(),
    });

    // Build the v2 entry's core fields/hash exactly as the fixed append()
    // would, chained onto the legacy entry's hash.
    const newId = uuid();
    const v2CoreFields = {
      artifactId:  newId,
      decision:    'ALLOW',
      inputHash:   'a'.repeat(64),
      policyHash:  'p'.repeat(64),
      prevHash:    legacy.hash,
      publicKeyId: 'tenant-a:key_v1',
      requestHash: 'r'.repeat(64),
      schemaVersion: 2,
      signature:   's'.repeat(64),
      timestamp:   new Date().toISOString(),
      verificationResult: true,
    };
    const v2Canonical = sortedJSON(v2CoreFields);
    const v2Hash       = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, v2Canonical).toString('hex');
    const v2Entry = { ...v2CoreFields, highResTime: '2', canonical: v2Canonical, hash: v2Hash };

    const fileContent = [JSON.stringify(legacy), JSON.stringify(v2Entry)].join('\n') + '\n';

    let audit;
    jest.isolateModules(() => {
      const fs = require('fs');
      fs.existsSync.mockImplementation((p) => String(p).endsWith('audit.log'));
      fs.readFileSync.mockImplementation((p) => {
        if (String(p).endsWith('audit.log')) return fileContent;
        return '';
      });
      // streamed boot reads via stat/open/readSync (fixed-buffer
      // chunks) instead of one readFileSync — mock the fd surface over the
      // same fileContent so the loader sees the identical bytes.
      const bootBuf = Buffer.from(fileContent, 'utf8');
      fs.statSync.mockImplementation((p) => ({ size: String(p).endsWith('audit.log') ? bootBuf.length : 0 }));
      fs.openSync.mockReturnValue(42);
      fs.closeSync.mockImplementation(() => {});
      fs.readSync.mockImplementation((fd, target, offset, length, position) => {
        const n = Math.max(0, Math.min(length, bootBuf.length - position));
        if (n > 0) bootBuf.copy(target, offset, position, position + n);
        return n;
      });
      _installFsPromisesMocks(fs);
      audit = require('../audit-log');
    });

    expect(audit.getChainLength()).toBe(2);
    expect(audit.verifyAuditChain()).toBe(true);
    expect((await audit.getArtifactById(legacyId)).publicKeyId).toBeUndefined();
    expect((await audit.getArtifactById(newId)).publicKeyId).toBe('tenant-a:key_v1');
  });

  test('KA-08 CORE_HASH_FIELDS_V1 (legacy) and CORE_HASH_FIELDS_V2 (current) are both exported and V2 strictly extends V1 by publicKeyId + schemaVersion', async () => {
    const audit = freshAudit();
    expect(audit.CORE_HASH_FIELDS_V1).toEqual([
      'artifactId', 'decision', 'inputHash', 'policyHash',
      'prevHash', 'requestHash', 'signature', 'timestamp', 'verificationResult',
    ]);
    for (const f of audit.CORE_HASH_FIELDS_V1) {
      expect(audit.CORE_HASH_FIELDS_V2).toContain(f);
    }
    expect(audit.CORE_HASH_FIELDS_V2).toContain('publicKeyId');
    expect(audit.CORE_HASH_FIELDS_V2).toContain('schemaVersion');
    // TRACE-2 bumped the live schema to 3 (CORE_HASH_FIELDS_V3 = V2 +
    // consentProvenance + policyDecision), bumped it again to 4
    // (CORE_HASH_FIELDS_V4 = V3 + callerContext), bumped it again
    // to 5 (CORE_HASH_FIELDS_V5 = V4 + provider + model), and bumped
    // it again to 6 (CORE_HASH_FIELDS_V6 = V5 + stage/reason/semantic/
    // tokenUsage/responseId, see entryBuilder.js) — V1/V2 remain exactly as
    // asserted above for historical entries.
    expect(audit.CURRENT_SCHEMA_VERSION).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)
  });
});
