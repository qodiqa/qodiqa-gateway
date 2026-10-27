'use strict';

/**
 * Audit Chain Hash Conformance — QODIQA-PROTOCOL-SPEC.md §11.1/§11.3/§11.4
 *
 * Regression suite for the audit-chain hash defect fixed in Phase "Audit Chain
 * Hash Remediation": entry.hash previously used sha256Hex(canonical) (no domain
 * separation) over a field set that leaked highResTime and the OPTIONAL fields
 * (tenantId, organizationId, nonce, executionContext) into the hash input.
 *
 * Updated for remediation (
 *): schemaVersion 2 entries hash 11 fields, not 9 —
 * `publicKeyId` (the signature-verified signing key) and `schemaVersion`
 * itself were added to the protected set so key attribution is
 * durable/tamper-evident, not just present in the unprotected
 * `executionContext` blob.
 *
 * Updated again for TRACE-2 remediation (consent-record + policy-rule
 * provenance linkage): schemaVersion 3 entries hash 13 fields —
 * `consentProvenance` and `policyDecision` were added to the protected set
 * (see src/core/audit/entryBuilder.js CORE_HASH_FIELDS_V3) so the immutable
 * consent record and matched policy rule that authorized a decision are
 * cryptographically bound to it, not just correlatable via a separate,
 * unsigned lookup. Both are present-but-null when not applicable (e.g. a
 * VALIDATION-stage BLOCK that never reached policy evaluation).
 *
 * Updated again for remediation (caller-attribution — audit/
 * part-04-transparency-audit-chain.md, master-findings-register.md
 *): every entry produced by the current append() is now
 * schemaVersion 4 and hashes 14 fields — `callerContext` (the authenticated
 * caller identity /sign bound into the artifact's payload) was added to the
 * protected set (CORE_HASH_FIELDS_V4) so non-repudiation evidence proves
 * WHICH authenticated caller requested a signature, not merely which shared
 * tenant key produced it. Present-but-null for an artifact signed before
 * this remediation shipped. Legacy on-disk entries (schemaVersion 1, 9
 * fields; schemaVersion 2, 11 fields; schemaVersion 3, 13 fields; schemaVersion
 * 4, 14 fields) continue to hash under their original formulas forever — see
 * CHC-18/CHC-19/CHC-20/CHC-21/CHC-24/CHC-25/CHC-28.
 *
 * Updated again for remediation (provider/model excluded from the
 * protected hash): schemaVersion 5 entries hash 16 fields -- `provider` and
 * `model` (the AI provider/model identity that executed, or would have
 * executed, this request) were added to the protected set
 * (CORE_HASH_FIELDS_V5) so that execution-changing metadata cannot be
 * silently rewritten after the fact without invalidating the chain hash.
 * Present-but-null when no provider had been selected yet (the common case
 * for a BLOCK). See CHC-27/CHC-28/CHC-29.
 *
 * Updated again for remediation (approved option A, 2026-09-10:
 * residual executionContext fields excluded from the protected hash): every
 * entry produced by the current append() is now schemaVersion 6 and hashes
 * 21 fields -- `stage`, `reason`, `semantic`, `tokenUsage`, `responseId`
 * (the decision-pipeline stage, stated BLOCK reason, semantic-classifier
 * evidence, provider token accounting, and linked provider response id)
 * were added to the protected set (CORE_HASH_FIELDS_V6), closing the
 * residual gap
 * documented: an attacker with in-place write access to audit.log/
 * audit_chain could previously alter these fields without invalidating the
 * chain hash. Present-but-null wherever not applicable (e.g. `reason` on an
 * ALLOW entry). See CHC-30/CHC-31/CHC-32a/CHC-32b.
 *
 * Updated again for audit schema v7: every entry produced by
 * the current append() is now schemaVersion 7 and hashes 28 fields — V6 plus `entryType`, `outputHash`,
 * `tenantId`, `requestId`, `organizationId`, the whole `executionContext` and `executingProvider`. CHC-06 /
 * CHC-07 therefore assert the v7 contract: tenantId/organizationId/executionContext ARE hashed now (rewriting them is
 * tampering); nonce and traceId stay outside the hash. Earlier versions keep their formulas forever (CHC-19..CHC-31).
 * callerContext/consentProvenance identities are pseudonymized on append (R-12); this suite has no database, so it
 * opts in to the explicit test-only pseudonym stand-in (test/helpers/subjectPseudonymMock.js).
 *
 * Spec formula under test (schemaVersion 6; schemaVersion 7 adds the seven fields above):
 *   coreFields = { artifactId, callerContext, consentProvenance, decision,
 *                  inputHash, model, policyDecision, policyHash, prevHash,
 *                  provider, publicKeyId, reason, requestHash, schemaVersion,
 *                  semantic, signature, stage, timestamp, tokenUsage,
 *                  responseId, verificationResult }
 *   canonical  = CanonicalSerialize(coreFields)
 *   hash       = LowercaseHex(SHA-256(UTF8("QODIQA::AUDIT::V1") || canonical))
 *
 * schemaVersion 5 formula (historical entries only):
 *   coreFields = { artifactId, callerContext, consentProvenance, decision,
 *                  inputHash, model, policyDecision, policyHash, prevHash,
 *                  provider, publicKeyId, requestHash, schemaVersion,
 *                  signature, timestamp, verificationResult }
 *
 * schemaVersion 2 formula (historical entries only):
 *   coreFields = { artifactId, decision, inputHash, policyHash, prevHash,
 *                  publicKeyId, requestHash, schemaVersion, signature,
 *                  timestamp, verificationResult }
 *
 * Legacy formula (schemaVersion 1, historical entries only):
 *   coreFields = { artifactId, decision, inputHash, policyHash, prevHash,
 *                  requestHash, signature, timestamp, verificationResult }
 *
 * NOTE (PERF-10): append() is asynchronous — its durable disk I/O now runs via
 * fs.promises instead of blocking fs.*Sync calls, serialized through a
 * module-level write queue. Every `.append(...)` call below is awaited so the
 * entry is fully committed to the in-memory chain/indexes (and its returned
 * value is the actual entry object, not a pending Promise) before assertions
 * run. jest.mock('fs') automocks every fs.* function but does NOT create an
 * fs.promises object — it stays undefined — so freshAudit() installs
 * fs.promises.* mocks (resolving immediately) before requiring audit-log,
 * otherwise the module-scope `const fsp = fs.promises;` in audit-log.js would
 * be undefined and every append() would reject.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));

const crypto = require('crypto');
const sortedJSON = require('../../../utils/stableStringify');

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

// Installs fs.promises.* mocks that resolve immediately — see file header note.
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

// Independent re-implementation of §11.3's formula using raw crypto — does NOT
// call domainSeparatedHash, so this cross-checks the actual byte-level formula
// rather than merely confirming audit-log.js agrees with its own dependency.
//
// Version-aware: an entry
// with schemaVersion === 6 (everything append() produces today) hashes the
// 21-field set including stage/reason/semantic/tokenUsage/responseId;
// schemaVersion === 5 hashes 16 fields including provider/model;
// schemaVersion === 4 hashes 14 fields including callerContext;
// schemaVersion === 3 hashes 13 fields including consentProvenance/
// policyDecision; schemaVersion === 2 hashes 11 fields (adds publicKeyId +
// schemaVersion over the legacy set); an entry with no schemaVersion field at
// all (legacy, hand-built to simulate pre-remediation on-disk data) hashes
// the original 9-field set — matching audit-log.js's own version-gated
// _hashFieldsFor().
function expectedHash(entry) {
  const v = entry.schemaVersion;
  const isV2orAbove = v === 2 || v === 3 || v === 4 || v === 5 || v === 6 || v === 7;
  const isV3orAbove  = v === 3 || v === 4 || v === 5 || v === 6 || v === 7;
  const isV4orAbove   = v === 4 || v === 5 || v === 6 || v === 7;
  const isV5orAbove   = v === 5 || v === 6 || v === 7;
  const isV6          = v === 6 || v === 7;   // "V6 fields": present from v6 on
  const isV7          = v === 7;
  const coreFields = {
    // v7: absent ≡ null (the canonical rule), stated explicitly here
    ...(isV7 ? {
      entryType: entry.entryType ?? null, outputHash: entry.outputHash ?? null, tenantId: entry.tenantId ?? null,
      requestId: entry.requestId ?? null, organizationId: entry.organizationId ?? null,
      executionContext: entry.executionContext ?? null, executingProvider: entry.executingProvider ?? null,
    } : {}),
    artifactId:          entry.artifactId,
    ...(isV4orAbove ? { callerContext: entry.callerContext } : {}),
    ...(isV3orAbove ? { consentProvenance: entry.consentProvenance } : {}),
    decision:            entry.decision,
    inputHash:           entry.inputHash,
    ...(isV5orAbove ? { model: entry.model } : {}),
    ...(isV3orAbove ? { policyDecision: entry.policyDecision } : {}),
    policyHash:          entry.policyHash,
    prevHash:            entry.prevHash,
    ...(isV5orAbove ? { provider: entry.provider } : {}),
    ...(isV2orAbove ? { publicKeyId: entry.publicKeyId } : {}),
    ...(isV6 ? { reason: entry.reason } : {}),
    requestHash:         entry.requestHash,
    ...(isV2orAbove ? { schemaVersion: entry.schemaVersion } : {}),
    ...(isV6 ? { semantic: entry.semantic } : {}),
    signature:           entry.signature,
    ...(isV6 ? { stage: entry.stage } : {}),
    timestamp:           entry.timestamp,
    ...(isV6 ? { tokenUsage: entry.tokenUsage } : {}),
    ...(isV6 ? { responseId: entry.responseId } : {}),
    verificationResult:  entry.verificationResult,
  };
  const canonical = sortedJSON(coreFields);
  return crypto.createHash('sha256')
    .update('QODIQA::AUDIT::V1', 'utf8')
    .update(canonical, 'utf8')
    .digest('hex');
}

describe('Audit Chain Hash Conformance — §11.3 Chain Hash Computation', () => {

  test('CHC-01 entry.hash matches the independently-computed spec formula', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams());
    expect(entry.hash).toBe(expectedHash(entry));
  });

  test('CHC-02 entry.canonical is CanonicalSerialize of exactly the 28 core fields (sorted keys, no extras) — v7', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams({ tenantId: 'tenant-A', nonce: 'n-1' }));
    const parsed = JSON.parse(entry.canonical);
    expect(Object.keys(parsed).sort()).toEqual([
      'artifactId', 'callerContext', 'consentProvenance', 'decision', 'inputHash', 'model', 'policyDecision', 'policyHash',
      'prevHash', 'provider', 'publicKeyId', 'reason', 'requestHash', 'responseId', 'schemaVersion',
      'semantic', 'signature', 'stage', 'timestamp', 'tokenUsage', 'verificationResult',
      'entryType', 'outputHash', 'tenantId', 'requestId', 'organizationId', 'executionContext', 'executingProvider',
    ].sort());
  });

  test('CHC-03 hash is domain-separated: differs from a plain (non-domain-separated) SHA-256 of the same canonical', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams());
    const plainSha256 = crypto.createHash('sha256').update(entry.canonical, 'utf8').digest('hex');
    expect(entry.hash).not.toBe(plainSha256);
  });

  test('CHC-04 genesis entry has prevHash === "GENESIS"', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams());
    expect(entry.prevHash).toBe('GENESIS');
    expect(entry.hash).toBe(expectedHash(entry));
  });

  test('CHC-05 highResTime is stored on the entry but excluded from the hash', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams());
    expect(typeof entry.highResTime).toBe('string');
    expect(entry.canonical).not.toMatch(/highResTime/);
  });

  test('CHC-06 v7: tenantId, organizationId and executionContext are IN the hash; nonce and traceId stay out', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams({
      tenantId:         'tenant-A',
      organizationId:   'org-1',
      nonce:            'nonce-xyz',
      traceId:          'f'.repeat(32),
      executionContext: { stage: 'TEST' },
    }));
    const parsed = JSON.parse(entry.canonical);
    expect(parsed).toMatchObject({ tenantId: 'tenant-A', organizationId: 'org-1', executionContext: { stage: 'TEST' } });
    for (const key of ['nonce', 'traceId', 'highResTime']) expect(entry.canonical).not.toMatch(new RegExp(key));
    expect(entry.hash).toBe(expectedHash(entry));
  });

  test('CHC-07 v7: mutating an out-of-hash field (nonce) does not break verification; mutating tenantId or executionContext does', async () => {
    const audit = freshAudit();
    await audit.append(allowParams({ tenantId: 'tenant-A', nonce: 'nonce-1', executionContext: { stage: 'TEST' } }));
    const [entry] = await audit.getAuditChain();
    expect(audit.verifyAuditChainDetailed([{ ...entry, nonce: 'nonce-2' }]).valid).toBe(true);
    for (const tampered of [{ ...entry, tenantId: 'tenant-B' }, { ...entry, executionContext: { stage: 'FORGED' } }]) {
      const result = audit.verifyAuditChainDetailed([tampered]);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
    }
  });

  for (const field of ['artifactId', 'decision', 'inputHash', 'policyHash', 'requestHash', 'signature', 'timestamp']) {
    test(`CHC-08 tampering with core field "${field}" is detected as AUDIT_CHAIN_TAMPERED`, async () => {
      const audit = freshAudit();
      await audit.append(allowParams());
      const [entry] = await audit.getAuditChain();
      const tampered = { ...entry, [field]: 'TAMPERED-VALUE' };
      const result = audit.verifyAuditChainDetailed([tampered]);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
      expect(result.tamperingDetected).toBe(true);
    });
  }

  test('CHC-09 tampering with verificationResult is detected as AUDIT_CHAIN_TAMPERED', async () => {
    const audit = freshAudit();
    await audit.append(allowParams());
    const [entry] = await audit.getAuditChain();
    const tampered = { ...entry, verificationResult: !entry.verificationResult };
    const result = audit.verifyAuditChainDetailed([tampered]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
  });

  test('CHC-10 modified prevHash on a non-first entry is detected as AUDIT_CHAIN_BROKEN', async () => {
    const audit = freshAudit();
    await audit.append(allowParams());
    await audit.append(allowParams());
    const chain = await audit.getAuditChain();
    chain[1] = { ...chain[1], prevHash: '0'.repeat(64) };
    const result = audit.verifyAuditChainDetailed(chain);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('AUDIT_CHAIN_BROKEN');
  });

  test('CHC-11 large chain (200 entries) verifies cleanly end to end', async () => {
    const audit = freshAudit();
    // Sequential awaits (not Promise.all) — each entry's prevHash must chain
    // off the previously COMMITTED entry, in order.
    for (let i = 0; i < 200; i++) await audit.append(allowParams());
    const result = audit.verifyAuditChainDetailed();
    expect(result.valid).toBe(true);
    expect(result.entriesVerified).toBe(200);
  });

  test('CHC-12 tampering with an entry in the middle of a large chain is caught at that entry', async () => {
    const audit = freshAudit();
    for (let i = 0; i < 50; i++) await audit.append(allowParams());
    const chain = await audit.getAuditChain();
    chain[25] = { ...chain[25], decision: chain[25].decision === 'ALLOW' ? 'BLOCK' : 'ALLOW' };
    const result = audit.verifyAuditChainDetailed(chain);
    expect(result.valid).toBe(false);
    expect(result.entriesVerified).toBe(25); // entries 0..24 verified fine before the break
  });

  test('CHC-13 Unicode field values hash deterministically and verify correctly', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams({ artifactId: 'artifact-héllo-🚀-' + uuid() }));
    expect(entry.hash).toBe(expectedHash(entry));
    const result = audit.verifyAuditChainDetailed([entry]);
    expect(result.valid).toBe(true);
  });

  test('CHC-14 BLOCK entries with UNAVAILABLE sentinel fields hash deterministically and verify', async () => {
    const audit = freshAudit();
    const entry = await audit.append({ artifactId: uuid(), decision: 'BLOCK' });
    expect(entry.inputHash).toBe('UNAVAILABLE');
    expect(entry.signature).toBe('UNAVAILABLE');
    expect(entry.requestHash).toBe('UNAVAILABLE');
    expect(entry.policyHash).toBe('UNAVAILABLE');
    expect(entry.hash).toBe(expectedHash(entry));
    expect(audit.verifyAuditChainDetailed([entry]).valid).toBe(true);
  });

  test('CHC-15 hash computation is deterministic for identical core fields', async () => {
    const fixedEntry = {
      artifactId: 'fixed-id', decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, inputHash: 'a'.repeat(64),
      policyHash: 'p'.repeat(64), prevHash: 'GENESIS', requestHash: 'r'.repeat(64),
      signature: 's'.repeat(64), timestamp: '2026-01-01T00:00:00.000Z',
      verificationResult: true,
    };
    expect(expectedHash(fixedEntry)).toBe(expectedHash({ ...fixedEntry }));
  });

  test('CHC-16 the current (schemaVersion 6) hash field set is exactly 21 fields — 16 plus stage/reason/semantic/tokenUsage/responseId', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams());
    const parsed = JSON.parse(entry.canonical);
    expect(Object.keys(parsed)).toHaveLength(28);   // the live entry is v7 (V6's 21 + 7)
    expect(audit.CORE_HASH_FIELDS_V6).toHaveLength(21);
    expect(audit.CORE_HASH_FIELDS_V7).toEqual([...audit.CORE_HASH_FIELDS_V6, 'entryType', 'outputHash', 'tenantId', 'requestId', 'organizationId', 'executionContext', 'executingProvider']);
    expect(entry.schemaVersion).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)
  });

  test('CHC-17 chain integrity verification at startup (validateChainIntegrity) reflects hash conformance', async () => {
    const audit = freshAudit();
    await audit.append(allowParams());
    await audit.append(allowParams());
    const report = audit.validateChainIntegrity();
    expect(report.chainValid).toBe(true);
    expect(report.tamperingDetected).toBe(false);
  });

  // ── backward compatibility: legacy (schemaVersion 1) entries ────────
  // continue to hash under the original 9-field formula forever, so
  // historical evidence written before this remediation remains verifiable.

  test('CHC-18 CORE_HASH_FIELDS_V1 (legacy) is exactly the original 9 fields named in §11.3 — no more, no fewer', async () => {
    const audit = freshAudit();
    expect(audit.CORE_HASH_FIELDS_V1).toEqual([
      'artifactId', 'decision', 'inputHash', 'policyHash',
      'prevHash', 'requestHash', 'signature', 'timestamp', 'verificationResult',
    ]);
    expect(audit.CORE_HASH_FIELDS_V1).toHaveLength(9);
  });

  test('CHC-19 a hand-built legacy entry with no schemaVersion field hashes under the original 9-field formula and verifies correctly', async () => {
    const audit = freshAudit();
    const legacyEntry = {
      artifactId: 'legacy-' + uuid(), decision: 'ALLOW', inputHash: 'a'.repeat(64),
      policyHash: 'p'.repeat(64), prevHash: 'GENESIS', requestHash: 'r'.repeat(64),
      signature: 's'.repeat(64), timestamp: new Date().toISOString(),
      verificationResult: true,
    };
    const canonical = sortedJSON(legacyEntry);
    const hash = crypto.createHash('sha256').update('QODIQA::AUDIT::V1', 'utf8').update(canonical, 'utf8').digest('hex');
    const frozen = { ...legacyEntry, highResTime: '1', canonical, hash };

    expect(Object.keys(JSON.parse(frozen.canonical))).toHaveLength(9);
    expect(frozen.hash).toBe(expectedHash(frozen));
    expect(audit.verifyAuditChainDetailed([frozen]).valid).toBe(true);
  });

  // ── TRACE-2: consentProvenance + policyDecision are hash-protected ─────────

  test('CHC-20 CORE_HASH_FIELDS_V3 strictly extends V2 by consentProvenance + policyDecision', async () => {
    const audit = freshAudit();
    expect(audit.CORE_HASH_FIELDS_V3).toEqual([...audit.CORE_HASH_FIELDS_V2, 'consentProvenance', 'policyDecision']);
  });

  test('CHC-21 a hand-built schemaVersion 2 entry with no consentProvenance/policyDecision fields hashes under the 11-field formula and verifies correctly — backward compatibility', async () => {
    const audit = freshAudit();
    const v2Entry = {
      artifactId: 'v2-' + uuid(), decision: 'ALLOW', inputHash: 'a'.repeat(64),
      policyHash: 'p'.repeat(64), prevHash: 'GENESIS', publicKeyId: 'tenant-a:key_v1',
      requestHash: 'r'.repeat(64), schemaVersion: 2,
      signature: 's'.repeat(64), timestamp: new Date().toISOString(),
      verificationResult: true,
    };
    const canonical = sortedJSON(v2Entry);
    const hash = crypto.createHash('sha256').update('QODIQA::AUDIT::V1', 'utf8').update(canonical, 'utf8').digest('hex');
    const frozen = { ...v2Entry, highResTime: '1', canonical, hash };

    expect(Object.keys(JSON.parse(frozen.canonical))).toHaveLength(11);
    expect(frozen.hash).toBe(expectedHash(frozen));
    expect(audit.verifyAuditChainDetailed([frozen]).valid).toBe(true);
  });

  test('CHC-22 consentProvenance and policyDecision are carried on schemaVersion 3 entries as immutable objects (present-but-null when not applicable)', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams());
    expect(entry).toHaveProperty('consentProvenance', null);
    expect(entry).toHaveProperty('policyDecision', null);
  });

  test('CHC-23 tampering with consentProvenance or policyDecision on a schemaVersion 3 entry is detected as AUDIT_CHAIN_TAMPERED', async () => {
    const audit = freshAudit();
    const consentProvenance = { consentId: 'c-1', consentVersion: 1, revocationStatus: 'ACTIVE' };
    const policyDecision    = { policyId: 'POL-001', policyVersion: 1, engineVersion: '1.0.0' };
    const entry = await audit.append(allowParams({ consentProvenance, policyDecision }));
    expect(entry.hash).toBe(expectedHash(entry));

    for (const field of ['consentProvenance', 'policyDecision']) {
      const tampered = { ...entry, [field]: { ...entry[field], tampered: true } };
      const result = audit.verifyAuditChainDetailed([tampered]);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
    }
  });

  // ── callerContext is hash-protected ───────────────────────────────

  test('CHC-24 CORE_HASH_FIELDS_V4 strictly extends V3 by callerContext', async () => {
    const audit = freshAudit();
    expect(audit.CORE_HASH_FIELDS_V4).toEqual([...audit.CORE_HASH_FIELDS_V3, 'callerContext']);
  });

  test('CHC-25 a hand-built schemaVersion 3 entry with no callerContext field hashes under the 13-field formula and verifies correctly — backward compatibility', async () => {
    const audit = freshAudit();
    const v3Entry = {
      artifactId: 'v3-' + uuid(), decision: 'ALLOW', inputHash: 'a'.repeat(64),
      policyHash: 'p'.repeat(64), prevHash: 'GENESIS', publicKeyId: 'tenant-a:key_v1',
      requestHash: 'r'.repeat(64), schemaVersion: 3,
      signature: 's'.repeat(64), timestamp: new Date().toISOString(),
      verificationResult: true, consentProvenance: null, policyDecision: null,
    };
    const canonical = sortedJSON(v3Entry);
    const hash = crypto.createHash('sha256').update('QODIQA::AUDIT::V1', 'utf8').update(canonical, 'utf8').digest('hex');
    const frozen = { ...v3Entry, highResTime: '1', canonical, hash };

    expect(Object.keys(JSON.parse(frozen.canonical))).toHaveLength(13);
    expect(frozen.hash).toBe(expectedHash(frozen));
    expect(audit.verifyAuditChainDetailed([frozen]).valid).toBe(true);
  });

  test('CHC-26 callerContext is carried on schemaVersion 4 entries as an immutable object (present-but-null when the artifact predates)', async () => {
    const audit = freshAudit();
    const nullEntry = await audit.append(allowParams());
    expect(nullEntry).toHaveProperty('callerContext', null);
  });

  test('CHC-26b tampering with callerContext on a schemaVersion 4 entry is detected as AUDIT_CHAIN_TAMPERED', async () => {
    const callerContext = { callerId: 'identity-1', callerName: 'ci-runner', environment: 'production', credentialType: 'api-key' };
    const audit = freshAudit();
    const entry = await audit.append(allowParams({ callerContext }));
    // v7 (R-12/R-13): the stored callerId is the subject pseudonym, never the raw identifier
    expect(entry.callerContext).toEqual({ ...callerContext, callerId: require('../../../../test/helpers/subjectPseudonymMock').expectedPseudonym(null, callerContext.callerId) });
    expect(entry.hash).toBe(expectedHash(entry));

    const tampered = { ...entry, callerContext: { ...entry.callerContext, callerId: 'someone-else' } };
    const result = audit.verifyAuditChainDetailed([tampered]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
  });

  // ── provider/model are hash-protected ───────────────────────────────

  test('CHC-27 CORE_HASH_FIELDS_V5 strictly extends V4 by provider + model (superseded as CURRENT_SCHEMA_VERSION/V6 — see CHC-30)', async () => {
    const audit = freshAudit();
    expect(audit.CORE_HASH_FIELDS_V5).toEqual([...audit.CORE_HASH_FIELDS_V4, 'provider', 'model']);
  });

  test('CHC-28 a hand-built schemaVersion 4 entry with no provider/model fields hashes under the 14-field formula and verifies correctly — backward compatibility', async () => {
    const audit = freshAudit();
    const v4Entry = {
      artifactId: 'v4-' + uuid(), decision: 'ALLOW', inputHash: 'a'.repeat(64),
      policyHash: 'p'.repeat(64), prevHash: 'GENESIS', publicKeyId: 'tenant-a:key_v1',
      requestHash: 'r'.repeat(64), schemaVersion: 4,
      signature: 's'.repeat(64), timestamp: new Date().toISOString(),
      verificationResult: true, consentProvenance: null, policyDecision: null, callerContext: null,
    };
    const canonical = sortedJSON(v4Entry);
    const hash = crypto.createHash('sha256').update('QODIQA::AUDIT::V1', 'utf8').update(canonical, 'utf8').digest('hex');
    const frozen = { ...v4Entry, highResTime: '1', canonical, hash };

    expect(Object.keys(JSON.parse(frozen.canonical))).toHaveLength(14);
    expect(frozen.hash).toBe(expectedHash(frozen));
    expect(audit.verifyAuditChainDetailed([frozen]).valid).toBe(true);
  });

  test('CHC-29a provider/model are present-but-null on a schemaVersion 5 entry when no provider was selected', async () => {
    const audit = freshAudit();
    const nullEntry = await audit.append(allowParams());
    expect(nullEntry).toHaveProperty('provider', null);
    expect(nullEntry).toHaveProperty('model', null);
  });

  test('CHC-29b tampering with provider/model on a schemaVersion 5 entry is detected as AUDIT_CHAIN_TAMPERED', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams({ provider: 'anthropic', model: 'claude-3-opus-20240229' }));
    expect(entry.provider).toBe('anthropic');
    expect(entry.model).toBe('claude-3-opus-20240229');
    expect(entry.hash).toBe(expectedHash(entry));

    for (const field of ['provider', 'model']) {
      const tampered = { ...entry, [field]: 'TAMPERED-VALUE' };
      const result = audit.verifyAuditChainDetailed([tampered]);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
    }
  });

  // ── stage/reason/semantic/tokenUsage/responseId are hash-protected ──

  test('CHC-30 CORE_HASH_FIELDS_V6 strictly extends V5 by stage + reason + semantic + tokenUsage + responseId, and is the live CURRENT_SCHEMA_VERSION', async () => {
    const audit = freshAudit();
    expect(audit.CORE_HASH_FIELDS_V6).toEqual([
      ...audit.CORE_HASH_FIELDS_V5, 'stage', 'reason', 'semantic', 'tokenUsage', 'responseId',
    ]);
    expect(audit.CURRENT_SCHEMA_VERSION).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)
  });

  test('CHC-31 a hand-built schemaVersion 5 entry with no stage/reason/semantic/tokenUsage/responseId fields hashes under the 16-field formula and verifies correctly — backward compatibility', async () => {
    const audit = freshAudit();
    const v5Entry = {
      artifactId: 'v5-' + uuid(), decision: 'ALLOW', inputHash: 'a'.repeat(64),
      policyHash: 'p'.repeat(64), prevHash: 'GENESIS', publicKeyId: 'tenant-a:key_v1',
      requestHash: 'r'.repeat(64), schemaVersion: 5,
      signature: 's'.repeat(64), timestamp: new Date().toISOString(),
      verificationResult: true, consentProvenance: null, policyDecision: null, callerContext: null,
      provider: 'anthropic', model: 'claude-3-opus-20240229',
    };
    const canonical = sortedJSON(v5Entry);
    const hash = crypto.createHash('sha256').update('QODIQA::AUDIT::V1', 'utf8').update(canonical, 'utf8').digest('hex');
    const frozen = { ...v5Entry, highResTime: '1', canonical, hash };

    expect(Object.keys(JSON.parse(frozen.canonical))).toHaveLength(16);
    expect(frozen.hash).toBe(expectedHash(frozen));
    expect(audit.verifyAuditChainDetailed([frozen]).valid).toBe(true);
  });

  test('CHC-32a stage/reason/semantic/tokenUsage/responseId are present-but-null on a schemaVersion 6 ALLOW entry when not applicable (reason is BLOCK-only)', async () => {
    const audit = freshAudit();
    const nullEntry = await audit.append(allowParams());
    expect(nullEntry).toHaveProperty('stage', null);
    expect(nullEntry).toHaveProperty('reason', null);
    expect(nullEntry).toHaveProperty('semantic', null);
    expect(nullEntry).toHaveProperty('tokenUsage', null);
    expect(nullEntry).toHaveProperty('responseId', null);
  });

  test('CHC-32b tampering with stage/reason/semantic/tokenUsage/responseId on a schemaVersion 6 entry is detected as AUDIT_CHAIN_TAMPERED', async () => {
    const audit = freshAudit();
    const entry = await audit.append(allowParams({
      stage: 'PROVIDER_EXECUTION',
      reason: 'SEMANTIC_BLOCK',
      semantic: { family: 'literal', score: 0.9 },
      tokenUsage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 },
      responseId: 'resp-123',
    }));
    expect(entry.stage).toBe('PROVIDER_EXECUTION');
    expect(entry.reason).toBe('SEMANTIC_BLOCK');
    expect(entry.semantic).toEqual({ family: 'literal', score: 0.9 });
    expect(entry.tokenUsage).toEqual({ inputTokens: 10, outputTokens: 5, totalTokens: 15 });
    expect(entry.responseId).toBe('resp-123');
    expect(entry.hash).toBe(expectedHash(entry));

    for (const field of ['stage', 'reason', 'responseId']) {
      const tampered = { ...entry, [field]: 'TAMPERED-VALUE' };
      const result = audit.verifyAuditChainDetailed([tampered]);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
    }
    for (const field of ['semantic', 'tokenUsage']) {
      const tampered = { ...entry, [field]: { ...entry[field], tampered: true } };
      const result = audit.verifyAuditChainDetailed([tampered]);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('AUDIT_CHAIN_TAMPERED');
    }
  });

});
