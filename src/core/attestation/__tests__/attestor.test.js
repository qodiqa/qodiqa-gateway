'use strict';

/**
 * QODIQA Attestation API Tests — Component #24
 *
 * AT-01  … AT-15   generateAttestation — decision mapping and result structure
 * AT-16  … AT-30   generateAttestation — transparency, persistence, metrics
 * AT-31  … AT-45   verifyEvidencePackage — integrity and chain lookup
 * AT-46  … AT-60   verifyChain — per-record and range verification
 * AT-61  … AT-75   attestationStore — PG-disabled path
 * AT-76  … AT-95   attestationStore — PG-enabled path (mocked)
 * AT-96  … AT-110  RBAC permissions matrix
 */

const { createHash, randomUUID } = require('crypto');
const { canonicalHash } = require('../../../../services/utils/evidencePackage');

// ── Mock pgPool ────────────────────────────────────────────────────────────────

const mockPool = {
  _enabled: false,
  isEnabled: function () { return this._enabled; },
  query:     jest.fn(),
};
jest.mock('../../../infra/postgres/pool', () => mockPool);

// ── Mock logger ────────────────────────────────────────────────────────────────

jest.mock('../../../../services/logger', () => ({
  emit:                 jest.fn(),
  allowed:              jest.fn(),
  blocked:              jest.fn(),
  eventBus:             { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

// ── Mock validateArtifact ──────────────────────────────────────────────────────

const mockValidateArtifact = jest.fn();
jest.mock('../../../validation/validateArtifact', () => ({
  validateArtifact: mockValidateArtifact,
}));

// ── Mock metrics ───────────────────────────────────────────────────────────────

jest.mock('../../../observability/metrics', () => ({
  attestationsTotal:                    { inc: jest.fn() },
  attestationFailuresTotal:             { inc: jest.fn() },
  attestationPersistFailuresTotal:      { inc: jest.fn() },
  attestationEvidenceVerificationsTotal: { inc: jest.fn() },
  attestationChainVerificationsTotal:   { inc: jest.fn() },
}));

// ── Mock registrar ─────────────────────────────────────────────────────────────

const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({
  register: mockRegister,
}));

// ── Mock chainStore ────────────────────────────────────────────────────────────

const mockVerifyEvidence    = jest.fn();
const mockVerifyChainRange  = jest.fn();
const mockGetByArtifactId   = jest.fn();
// H132-D: verifyChain reads each VALID record's tenant (single-tenant request
// integrity). Default: every record belongs to the same tenant.
const mockGetByEvidenceId   = jest.fn(async () => ({ tenant_id: 'tenant-a' }));
jest.mock('../../../core/evidence/chainStore', () => ({
  verifyEvidence:    mockVerifyEvidence,
  verifyChainRange:  mockVerifyChainRange,
  getByArtifactId:   mockGetByArtifactId,
  getByEvidenceId:   mockGetByEvidenceId,
}));

// ── Mock attestationStore ──────────────────────────────────────────────────────

const mockRecordAttestation   = jest.fn();
const mockGetByAttestationId  = jest.fn();
const mockGetByFingerprint    = jest.fn();
const mockListAttestations    = jest.fn();
const mockAggregateStats      = jest.fn();
jest.mock('../attestationStore', () => ({
  recordAttestation:   mockRecordAttestation,
  getByAttestationId:  mockGetByAttestationId,
  getByFingerprint:    mockGetByFingerprint,
  listAttestations:    mockListAttestations,
  aggregateStats:      mockAggregateStats,
}));

// ── Load modules ───────────────────────────────────────────────────────────────

const attestor        = require('../attestor');
const attestationStore = require('../attestationStore');
const realAttestationStore = jest.requireActual('../attestationStore');
const { PERMISSIONS } = require('../../rbac/roles');
const metrics         = require('../../../observability/metrics');

// ── Helpers ────────────────────────────────────────────────────────────────────

const EXECUTE  = { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', details: {} };
const BLOCK_SIG = { decision: 'BLOCK', reason: 'INVALID_SIGNATURE', details: { issue: 'Ed25519 signature is invalid' } };

function makeArtifact(overrides = {}) {
  return {
    payload:     { action: 'test', requestId: randomUUID() },
    timestamp:   Date.now(),
    expiry:      Date.now() + 60_000,
    publicKeyId: 'default:key_v1',
    signature:   Buffer.from('fake-sig').toString('base64'),
    ...overrides,
  };
}

function buildEvidencePackage(overrides = {}) {
  const content = {
    packageType:       'QODIQA::PORTAL_EVIDENCE::V1',
    schemaVersion:     '1.0',
    verificationId:    randomUUID(),
    overallResult:     'VERIFIED',
    failedCheck:       null,
    failureReason:     null,
    warnings:          [],
    checksPerformed:   [],
    artifactFingerprint: 'a'.repeat(64),
    artifactPublicKeyId: 'default:key_v1',
    artifactTimestampMs: Date.now(),
    artifactExpiryMs:    Date.now() + 60_000,
    artifactId:          'art-001',
    transparencyId:      null,
    submittedBy:         'external',
    submissionIp:        null,
    durationMs:          10,
    verifiedAt:          new Date().toISOString(),
    ...overrides,
  };
  const packageHash = canonicalHash(content);
  return {
    ...content,
    packageId:   createHash('sha256').update(`${content.verificationId}:PORTAL_EVIDENCE`, 'utf8').digest('hex'),
    generatedAt: new Date().toISOString(),
    packageHash,
  };
}

// ── Setup ──────────────────────────────────────────────────────────────────────

beforeEach(() => {
  jest.clearAllMocks();
  mockPool._enabled = false;
  mockRegister.mockResolvedValue({ transparencyId: 'trans-001' });
  mockRecordAttestation.mockResolvedValue({ attestation_id: 'stub' });
  mockGetByFingerprint.mockResolvedValue(null);
  mockGetByArtifactId.mockResolvedValue(null);
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-01…AT-15  generateAttestation — decision mapping and result structure
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-01…AT-15  generateAttestation — decision mapping and result structure', () => {
  test('AT-01  EXECUTE → ATTESTED', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.attestationDecision).toBe('ATTESTED');
  });

  test('AT-02  BLOCK (INVALID_SIGNATURE) → NOT_ATTESTED', async () => {
    mockValidateArtifact.mockReturnValue(BLOCK_SIG);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-03  EXECUTE + replay fingerprint → ATTESTED_WITH_WARNINGS', async () => {
    mockPool._enabled = true;
    mockValidateArtifact.mockReturnValue(EXECUTE);
    mockGetByFingerprint.mockResolvedValue({ attestation_id: randomUUID(), attestation_decision: 'ATTESTED' });
    mockGetByArtifactId.mockResolvedValue({ id: 'ev-001' });
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.attestationDecision).toBe('ATTESTED_WITH_WARNINGS');
  });

  test('AT-04  result contains attestationId as UUID', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.attestationId).toMatch(/^[0-9a-f-]{36}$/);
  });

  test('AT-05  result contains attestationType ARTIFACT_VERIFICATION', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.attestationType).toBe('ARTIFACT_VERIFICATION');
  });

  test('AT-06  result contains version 1.0', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.version).toBe('1.0');
  });

  test('AT-07  result contains generatedAt ISO string', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(() => new Date(r.generatedAt)).not.toThrow();
    expect(r.generatedAt).toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  test('AT-08  verificationResult.overallResult is VERIFIED for EXECUTE', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.verificationResult.overallResult).toBe('VERIFIED');
  });

  test('AT-09  verificationResult.failedCheck is SIGNATURE for tampered artifact', async () => {
    mockValidateArtifact.mockReturnValue(BLOCK_SIG);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.verificationResult.failedCheck).toBe('SIGNATURE');
    expect(r.verificationResult.overallResult).toBe('FAILED');
  });

  test('AT-10  cryptographicResult contains signatureVerification with Ed25519 algorithm', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.cryptographicResult.signatureVerification.algorithm).toBe('Ed25519');
    expect(r.cryptographicResult.signatureVerification.status).toBe('PASS');
  });

  test('AT-11  complianceResult.conformanceStatus is CONFORMS for EXECUTE', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.complianceResult.conformanceStatus).toBe('CONFORMS');
  });

  test('AT-12  complianceResult.conformanceStatus is DOES_NOT_CONFORM for BLOCK', async () => {
    mockValidateArtifact.mockReturnValue(BLOCK_SIG);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.complianceResult.conformanceStatus).toBe('DOES_NOT_CONFORM');
  });

  test('AT-13  evidencePackage.packageHash is a 64-char hex string', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.evidencePackage.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('AT-14  metadata.durationMs is a non-negative number', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(typeof r.metadata.durationMs).toBe('number');
    expect(r.metadata.durationMs).toBeGreaterThanOrEqual(0);
  });

  test('AT-15  verificationResult.checks contains all 8 checks for EXECUTE', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    const checkNames = r.verificationResult.checks.map(c => c.check);
    expect(checkNames).toContain('SCHEMA');
    expect(checkNames).toContain('SIGNATURE');
    expect(checkNames).toContain('REPLAY_CHECK');
    expect(checkNames).toContain('EVIDENCE_CHAIN');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-16…AT-30  generateAttestation — transparency, persistence, metrics
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-16…AT-30  generateAttestation — transparency, persistence, metrics', () => {
  test('AT-16  registrar.register is called with entryType VERIFICATION', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    await attestor.generateAttestation(makeArtifact());
    expect(mockRegister).toHaveBeenCalledWith(
      expect.objectContaining({ entryType: 'VERIFICATION', registeredBy: 'attestation' }),
    );
  });

  test('AT-17  transparencyId from registrar is returned in result', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    mockRegister.mockResolvedValue({ transparencyId: 'trans-xyz' });
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.transparencyReferences.transparencyId).toBe('trans-xyz');
  });

  test('AT-18  transparencyId is null when registrar throws', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    mockRegister.mockRejectedValue(new Error('signing failed'));
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.transparencyReferences.transparencyId).toBeNull();
  });

  test('AT-19  recordAttestation is called with correct attestationDecision', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    await attestor.generateAttestation(makeArtifact());
    await new Promise(r => setImmediate(r));
    expect(mockRecordAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ attestationDecision: 'ATTESTED' }),
    );
  });

  test('AT-20  recordAttestation is called with transparencyId from registrar', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    mockRegister.mockResolvedValue({ transparencyId: 'trans-abc' });
    await attestor.generateAttestation(makeArtifact());
    await new Promise(r => setImmediate(r));
    expect(mockRecordAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ transparencyId: 'trans-abc' }),
    );
  });

  test('AT-21  recordAttestation is called with evidencePackageHash', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    await attestor.generateAttestation(makeArtifact());
    await new Promise(r => setImmediate(r));
    expect(mockRecordAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ evidencePackageHash: expect.stringMatching(/^[0-9a-f]{64}$/) }),
    );
  });

  test('AT-22  requestedBy and requestIp are passed to recordAttestation', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    await attestor.generateAttestation(makeArtifact(), { requestedBy: 'auditor-1', requestIp: '10.0.0.1' });
    await new Promise(r => setImmediate(r));
    expect(mockRecordAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ requestedBy: 'auditor-1', requestIp: '10.0.0.1' }),
    );
  });

  test('AT-23  attestationsTotal metric is incremented with correct decision', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    await attestor.generateAttestation(makeArtifact());
    expect(metrics.attestationsTotal.inc).toHaveBeenCalledWith({ decision: 'ATTESTED' });
  });

  test('AT-24  attestationFailuresTotal is incremented for NOT_ATTESTED', async () => {
    mockValidateArtifact.mockReturnValue(BLOCK_SIG);
    await attestor.generateAttestation(makeArtifact());
    expect(metrics.attestationFailuresTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ failed_check: 'SIGNATURE' }),
    );
  });

  test('AT-25  attestationFailuresTotal is NOT incremented for ATTESTED', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    await attestor.generateAttestation(makeArtifact());
    expect(metrics.attestationFailuresTotal.inc).not.toHaveBeenCalled();
  });

  test('AT-26  attestationPersistFailuresTotal incremented when recordAttestation throws', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    mockRecordAttestation.mockRejectedValue(new Error('pg down'));
    await attestor.generateAttestation(makeArtifact());
    await new Promise(r => setImmediate(r));
    expect(metrics.attestationPersistFailuresTotal.inc).toHaveBeenCalled();
  });

  test('AT-27  chainResult.chainPresent is false when no evidence record (PG disabled)', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.chainResult.chainPresent).toBe(false);
  });

  test('AT-28  chainResult.chainPresent is true when evidence record found', async () => {
    mockPool._enabled = true;
    mockValidateArtifact.mockReturnValue(EXECUTE);
    mockGetByArtifactId.mockResolvedValue({ evidence_id: 'ev-001', artifact_id: 'art-001', evidence_hash: 'hash', decision: 'ALLOW' });
    mockGetByFingerprint.mockResolvedValue(null);
    const r = await attestor.generateAttestation(makeArtifact());
    expect(r.chainResult.chainPresent).toBe(true);
  });

  // evidence is correlated only to an artifact that passed core
  // validation — otherwise a caller could put a known requestId into an
  // unsigned artifact and read that execution's evidence back (reproduced live).
  test('AT-28b an artifact failing core validation never exposes a correlated evidence record', async () => {
    mockPool._enabled = true;
    mockValidateArtifact.mockReturnValue(BLOCK_SIG);
    mockGetByArtifactId.mockResolvedValue({ evidence_id: 'ev-victim', artifact_id: 'art-victim', evidence_hash: 'hash', decision: 'ALLOW' });
    mockGetByFingerprint.mockResolvedValue(null);
    // carries both identifiers so the lookup runs whichever key the code uses
    const r = await attestor.generateAttestation(makeArtifact({ payload: { action: 'test', requestId: 'art-victim', artifactId: 'art-victim' } }));
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.chainResult).toEqual({ chainPresent: false, evidenceId: null, artifactId: null, chainHash: null, chainDecision: null });
    expect(JSON.stringify(r)).not.toContain('ev-victim');
  });

  // the lookup is keyed on the artifact's own signed payload.requestId.
  test('AT-28c evidence lookup uses payload.requestId and ignores a claimed payload.artifactId', async () => {
    mockPool._enabled = true;
    mockValidateArtifact.mockReturnValue(EXECUTE);
    mockGetByArtifactId.mockResolvedValue(null);
    mockGetByFingerprint.mockResolvedValue(null);
    const art = makeArtifact({ payload: { action: 'test', requestId: 'own-req', artifactId: 'victim-req' } });
    await attestor.generateAttestation(art);
    expect(mockGetByArtifactId).toHaveBeenCalledWith('own-req');
    expect(mockGetByArtifactId).not.toHaveBeenCalledWith('victim-req');
  });

  test('AT-29  DECISION_MAP maps all three portal results', () => {
    expect(attestor._DECISION_MAP['VERIFIED']).toBe('ATTESTED');
    expect(attestor._DECISION_MAP['VERIFIED_WITH_WARNINGS']).toBe('ATTESTED_WITH_WARNINGS');
    expect(attestor._DECISION_MAP['FAILED']).toBe('NOT_ATTESTED');
  });

  test('AT-30  each generateAttestation call produces a unique attestationId', async () => {
    mockValidateArtifact.mockReturnValue(EXECUTE);
    const r1 = await attestor.generateAttestation(makeArtifact());
    const r2 = await attestor.generateAttestation(makeArtifact());
    expect(r1.attestationId).not.toBe(r2.attestationId);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-31…AT-45  verifyEvidencePackage — integrity
// ─────────────────────────────────────────────────────────────────────────────

// H129-A (design decision, Option B): a "valid package" is one genuinely bound to
// an existing original — the package the system issues for that stored record.
const portal = require('../../verification/portal');
function sampleOriginalRecord(overrides = {}) {
  return {
    attestation_id:         randomUUID(),
    attestation_type:       'ARTIFACT_VERIFICATION',
    attestation_decision:   'ATTESTED',
    artifact_fingerprint:   'a'.repeat(64),
    artifact_public_key_id: 'default:key_v1',
    artifact_timestamp_ms:  1790000000000,
    artifact_expiry_ms:     1790000060000,
    artifact_id:            'art-001',
    verification_result:    { overallResult: 'VERIFIED' },
    checks_performed:       [{ check: 'SIGNATURE', result: 'PASS' }],
    failed_check:           null,
    failure_reason:         null,
    warnings:               [],
    transparency_id:        null,
    requested_by:           'external',
    request_ip:             null,
    duration_ms:            10,
    generated_at:           new Date('2026-09-25T00:00:00.000Z'),
    ...overrides,
  };
}
function withOriginal(record) {
  mockPool._enabled = true;
  mockGetByAttestationId.mockResolvedValue(record);
  return portal.assembleEvidencePackageFromAttestationRecord(record);
}
function resealed(pkg, changes) {
  const { packageId, generatedAt, packageHash, ...content } = { ...pkg, ...changes };
  return { ...content, packageId, generatedAt, packageHash: canonicalHash(content) };
}

describe('AT-31…AT-45  verifyEvidencePackage — integrity', () => {
  // H129-A: previously built a self-hashed package with NO original and expected
  // ATTESTED — the fail-open itself. Now a genuine package bound to its original.
  test('AT-31  valid (genuine, original-bound) package returns valid=true and ATTESTED', async () => {
    const pkg = withOriginal(sampleOriginalRecord());
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.valid).toBe(true);
    expect(r.attestationDecision).toBe('ATTESTED');
    expect(r.chainVerification.contentBound).toBe(true);
  });

  test('AT-32  tampered packageHash returns valid=false and NOT_ATTESTED', async () => {
    const pkg = buildEvidencePackage();
    pkg.packageHash = 'a'.repeat(64); // corrupt the hash
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.valid).toBe(false);
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-33  tampered content (overallResult changed) returns valid=false', async () => {
    const pkg = buildEvidencePackage({ overallResult: 'VERIFIED' });
    pkg.overallResult = 'ATTESTED'; // tamper content
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.valid).toBe(false);
  });

  test('AT-34  integrityVerification contains computedHash and providedHash', async () => {
    const pkg = buildEvidencePackage();
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.integrityVerification.computedHash).toBeDefined();
    expect(r.integrityVerification.providedHash).toBeDefined();
    expect(r.integrityVerification.match).toBe(true);
  });

  test('AT-35  integrityVerification.algorithm is SHA-256/stableStringify', async () => {
    const pkg = buildEvidencePackage();
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.integrityVerification.algorithm).toBe('SHA-256/stableStringify');
  });

  test('AT-36  attestationType is EVIDENCE_VERIFICATION', async () => {
    const pkg = buildEvidencePackage();
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.attestationType).toBe('EVIDENCE_VERIFICATION');
  });

  test('AT-37  attestationId is a UUID', async () => {
    const pkg = buildEvidencePackage();
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.attestationId).toMatch(/^[0-9a-f-]{36}$/);
  });

  test('AT-38  null package returns valid=false with failureReason', async () => {
    const r = await attestor.verifyEvidencePackage(null);
    expect(r.valid).toBe(false);
    expect(r.failureReason).toMatch(/non-null object/);
  });

  test('AT-39  wrong packageType returns valid=false with unsupported reason', async () => {
    const r = await attestor.verifyEvidencePackage({ packageType: 'WRONG::TYPE' });
    expect(r.valid).toBe(false);
    expect(r.failureReason).toMatch(/Unsupported package type/);
  });

  test('AT-40  array input returns valid=false', async () => {
    const r = await attestor.verifyEvidencePackage([]);
    expect(r.valid).toBe(false);
  });

  test('AT-41  registrar.register is called for evidence verification', async () => {
    const pkg = buildEvidencePackage();
    await attestor.verifyEvidencePackage(pkg);
    expect(mockRegister).toHaveBeenCalledWith(
      expect.objectContaining({
        entryType:    'VERIFICATION',
        registeredBy: 'attestation',
      }),
    );
  });

  test('AT-42  attestationEvidenceVerificationsTotal metric incremented for VALID', async () => {
    const pkg = withOriginal(sampleOriginalRecord()); // H129-A: VALID requires an original-bound package
    await attestor.verifyEvidencePackage(pkg);
    expect(metrics.attestationEvidenceVerificationsTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'VALID' }),
    );
  });

  test('AT-43  attestationEvidenceVerificationsTotal metric incremented for INVALID on tamper', async () => {
    const pkg = buildEvidencePackage();
    pkg.packageHash = 'b'.repeat(64);
    await attestor.verifyEvidencePackage(pkg);
    expect(metrics.attestationEvidenceVerificationsTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'INVALID' }),
    );
  });

  test('AT-44  verificationId from package is in chainVerification', async () => {
    const pkg = buildEvidencePackage({ verificationId: '33333333-3333-3333-3333-333333333333' });
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(r.chainVerification.verificationId).toBe('33333333-3333-3333-3333-333333333333');
  });

  test('AT-45  durationMs is present and non-negative', async () => {
    const pkg = buildEvidencePackage();
    const r = await attestor.verifyEvidencePackage(pkg);
    expect(typeof r.durationMs).toBe('number');
    expect(r.durationMs).toBeGreaterThanOrEqual(0);
  });

  // withOriginal()/mockRejectedValue set implementations that clearAllMocks keeps.
  afterEach(() => { mockGetByAttestationId.mockReset(); });

  // ── H129-A — package must be bound to its stored original (design decision, Option B) ──
  // Each NOT_ATTESTED case below was ATTESTED before H129-A (real-PG matrix:
  //).
  const expectRejected = (r, failedCheck) => {
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.valid).toBe(false);
    expect(mockRecordAttestation).toHaveBeenCalledWith(expect.objectContaining({ attestationDecision: 'NOT_ATTESTED', failedCheck }));
    expect(metrics.attestationEvidenceVerificationsTotal.inc).toHaveBeenCalledWith(expect.objectContaining({ result: 'INVALID' }));
  };

  test('AT-H129A-01  self-consistent package with no original (the former AT-31 scenario) → NOT_ATTESTED, ORIGINAL_NOT_FOUND', async () => {
    const r = await attestor.verifyEvidencePackage(buildEvidencePackage());
    expect(r.integrityVerification.match).toBe(true);
    expect(r.chainVerification.originalFound).toBe(false);
    expectRejected(r, 'ORIGINAL_NOT_FOUND');
  });

  test('AT-H129A-02  fabricated, self-hashed content citing an existing original id → NOT_ATTESTED, ORIGINAL_BINDING', async () => {
    const rec = sampleOriginalRecord();
    withOriginal(rec);
    const r = await attestor.verifyEvidencePackage(buildEvidencePackage({ verificationId: rec.attestation_id }));
    expect(r.integrityVerification.match).toBe(true);
    expect(r.chainVerification).toEqual(expect.objectContaining({ originalFound: true, contentBound: false }));
    expectRejected(r, 'ORIGINAL_BINDING');
  });

  test.each([
    ['decision changed', { overallResult: 'FAILED' }],
    ['checks changed', { checksPerformed: [{ check: 'FORGED', result: 'PASS' }] }],
    ['tenant key changed', { artifactPublicKeyId: 'other-tenant:key_v1' }],
    ['artifact re-pointed', { artifactId: 'another-execution' }],
  ])('AT-H129A-03  genuine package %s and re-sealed → NOT_ATTESTED, ORIGINAL_BINDING', async (_n, change) => {
    const pkg = withOriginal(sampleOriginalRecord());
    const r = await attestor.verifyEvidencePackage(resealed(pkg, change));
    expect(r.integrityVerification.match).toBe(true);
    expectRejected(r, 'ORIGINAL_BINDING');
  });

  test('AT-H129A-04  genuine package re-pointed at a different existing original → NOT_ATTESTED', async () => {
    const pkg = portal.assembleEvidencePackageFromAttestationRecord(sampleOriginalRecord());
    const other = sampleOriginalRecord({ artifact_id: 'art-002' });
    withOriginal(other);
    const r = await attestor.verifyEvidencePackage(resealed(pkg, { verificationId: other.attestation_id }));
    expectRejected(r, 'ORIGINAL_BINDING');
  });

  test('AT-H129A-05  original lookup failure → NOT_ATTESTED (fail-closed)', async () => {
    const pkg = withOriginal(sampleOriginalRecord());
    mockGetByAttestationId.mockRejectedValue(new Error('db down'));
    const r = await attestor.verifyEvidencePackage(pkg);
    expectRejected(r, 'ORIGINAL_NOT_FOUND');
  });

  test('AT-H129A-06  the authoritative hash is never returned for a mismatching package', async () => {
    const rec = sampleOriginalRecord();
    const authoritative = withOriginal(rec).packageHash;
    const r = await attestor.verifyEvidencePackage(buildEvidencePackage({ verificationId: rec.attestation_id }));
    expect(JSON.stringify(r)).not.toContain(authoritative);
  });

  test('AT-H129A-07  a bound package still fails on a bad self-hash first (INTEGRITY)', async () => {
    const pkg = withOriginal(sampleOriginalRecord());
    const r = await attestor.verifyEvidencePackage({ ...pkg, packageHash: 'f'.repeat(64) });
    expectRejected(r, 'INTEGRITY');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-46…AT-60  verifyChain — per-record and range verification
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-46…AT-60  verifyChain — per-record and range verification', () => {
  const validEvidenceResult = {
    result:        'VALID',
    failedStep:    null,
    failureReason: null,
    stepsPassed:   ['STEP_1', 'STEP_2'],
    stepsFailed:   [],
    durationMs:    5,
  };

  const invalidEvidenceResult = {
    result:        'INVALID',
    failedStep:    'STEP_3',
    failureReason: 'Hash mismatch',
    stepsPassed:   ['STEP_1'],
    stepsFailed:   ['STEP_3'],
    durationMs:    3,
  };

  test('AT-46  single valid evidenceId → ATTESTED', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001'] });
    expect(r.attestationDecision).toBe('ATTESTED');
  });

  test('AT-47  single invalid evidenceId → NOT_ATTESTED', async () => {
    mockVerifyEvidence.mockResolvedValue(invalidEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-002'] });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-48  mixed results (one invalid) → NOT_ATTESTED', async () => {
    mockVerifyEvidence
      .mockResolvedValueOnce(validEvidenceResult)
      .mockResolvedValueOnce(invalidEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001', 'ev-002'] });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-49  all valid evidenceIds → ATTESTED', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001', 'ev-002', 'ev-003'] });
    expect(r.attestationDecision).toBe('ATTESTED');
  });

  // (design decision, Option A): a range is a continuity check only — its
  // records never receive a per-record VALID verdict — so it can no longer
  // attest on its own. Previously pinned ATTESTED; inverted to the approved value.
  test('AT-50 range with valid continuity result → NOT_ATTESTED', async () => {
    mockVerifyChainRange.mockResolvedValue({ valid: true, checkedCount: 100, failureId: null });
    const r = await attestor.verifyChain({ range: { startId: 1, endId: 100 } });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.chainIntegrity.rangeResult).toEqual(expect.objectContaining({ valid: true, checkedCount: 100 }));
  });

  test('AT-51  range with invalid result → NOT_ATTESTED', async () => {
    mockVerifyChainRange.mockResolvedValue({ valid: false, checkedCount: 50, failureId: 42, failureDetail: 'break' });
    const r = await attestor.verifyChain({ range: { startId: 1, endId: 100 } });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-52  attestationType is CHAIN_VERIFICATION', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001'] });
    expect(r.attestationType).toBe('CHAIN_VERIFICATION');
  });

  test('AT-53  chainIntegrity.perRecordResults includes result per evidenceId', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001', 'ev-002'] });
    expect(r.chainIntegrity.perRecordResults).toHaveLength(2);
    expect(r.chainIntegrity.perRecordResults[0].evidenceId).toBe('ev-001');
  });

  // zero records verified is not a positive verification. Previously
  // pinned ATTESTED ("no checks run"); inverted to the approved value.
  test('AT-54 verifyChain without evidenceIds or range → NOT_ATTESTED', async () => {
    const r = await attestor.verifyChain({});
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.chainIntegrity.perRecordResults).toHaveLength(0);
  });

  test('AT-55  evidenceIds capped at 50 entries', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const ids = Array.from({ length: 60 }, (_, i) => `ev-${i}`);
    await attestor.verifyChain({ evidenceIds: ids });
    expect(mockVerifyEvidence).toHaveBeenCalledTimes(50);
  });

  test('AT-56  chainStore.verifyEvidence error → NOT_ATTESTED for that record', async () => {
    mockVerifyEvidence.mockRejectedValue(new Error('db error'));
    const r = await attestor.verifyChain({ evidenceIds: ['ev-fail'] });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.chainIntegrity.perRecordResults[0].result).toBe('ERROR');
  });

  test('AT-57  attestationChainVerificationsTotal metric incremented VALID', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    await attestor.verifyChain({ evidenceIds: ['ev-001'] });
    expect(metrics.attestationChainVerificationsTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'VALID' }),
    );
  });

  test('AT-58  attestationChainVerificationsTotal metric incremented INVALID', async () => {
    mockVerifyEvidence.mockResolvedValue(invalidEvidenceResult);
    await attestor.verifyChain({ evidenceIds: ['ev-001'] });
    expect(metrics.attestationChainVerificationsTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'INVALID' }),
    );
  });

  test('AT-59  registrar.register is called for chain verification', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    await attestor.verifyChain({ evidenceIds: ['ev-001'] });
    expect(mockRegister).toHaveBeenCalledWith(
      expect.objectContaining({ entryType: 'VERIFICATION', registeredBy: 'attestation' }),
    );
  });

  test('AT-60  verificationPath.evidenceIdsChecked matches input', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001', 'ev-002'] });
    expect(r.verificationPath.evidenceIdsChecked).toEqual(['ev-001', 'ev-002']);
  });

  // ── ATTESTED iff every requested record is VALID (design decision, Option A) ──
  // Every case below was ATTESTED (reproduced on a real server path:
  //).
  const errorNotFound = { result: 'ERROR', failedStep: null, failureReason: 'Evidence record not found: x', stepsPassed: [], stepsFailed: [], durationMs: 1 };
  const partial       = { result: 'PARTIAL', failedStep: null, failureReason: null, stepsPassed: [], stepsFailed: [], durationMs: 1 };

  test.each([
    ['returned ERROR (unknown evidence id)', [errorNotFound]],
    ['PARTIAL', [partial]],
    ['VALID + returned ERROR', [validEvidenceResult, errorNotFound]],
    ['VALID + PARTIAL', [validEvidenceResult, partial]],
    ['an unrecognised result value', [{ ...validEvidenceResult, result: 'OK' }]],
    ['a result with no status at all', [{ stepsPassed: [], stepsFailed: [] }]],
  ])('AT-H128-01  %s → NOT_ATTESTED, stored and reported the same', async (_n, results) => {
    for (const res of results) mockVerifyEvidence.mockResolvedValueOnce(res);
    const r = await attestor.verifyChain({ evidenceIds: results.map((_, i) => `ev-${i}`) });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.chainIntegrity.valid).toBe(false);
    expect(mockRecordAttestation).toHaveBeenCalledWith(expect.objectContaining({
      attestationDecision: 'NOT_ATTESTED', failedCheck: 'CHAIN_INTEGRITY',
    }));
    // no record is silently discarded
    expect(r.chainIntegrity.perRecordResults).toHaveLength(results.length);
  });

  test('AT-H128-02  more than 50 requested ids → NOT_ATTESTED (unverified records cannot be attested)', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: Array.from({ length: 51 }, (_, i) => `ev-${i}`) });
    expect(mockVerifyEvidence).toHaveBeenCalledTimes(50);
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-H128-03  valid ids plus a range (valid continuity, or zero records) → NOT_ATTESTED, range still reported', async () => {
    for (const rangeRes of [{ valid: true, checkedCount: 10, failureId: null }, { valid: true, checkedCount: 0, failureId: null }]) {
      mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
      mockVerifyChainRange.mockResolvedValue(rangeRes);
      const r = await attestor.verifyChain({ evidenceIds: ['ev-001'], range: { startId: 1, endId: 10 } });
      expect(r.attestationDecision).toBe('NOT_ATTESTED');
      expect(r.chainIntegrity.rangeResult.checkedCount).toBe(rangeRes.checkedCount);
    }
  });

  test('AT-H128-04  range-only with zero records (e.g. PG disabled or empty range) → NOT_ATTESTED', async () => {
    mockVerifyChainRange.mockResolvedValue({ valid: true, checkedCount: 0, failureId: null, failureDetail: 'PG not enabled' });
    const r = await attestor.verifyChain({ range: { startId: 1, endId: 5 } });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-H128-05  every requested record VALID (1..50) → ATTESTED — the only path to ATTESTED', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: Array.from({ length: 50 }, (_, i) => `ev-${i}`) });
    expect(r.attestationDecision).toBe('ATTESTED');
    expect(r.chainIntegrity.valid).toBe(true);
    expect(mockRecordAttestation).toHaveBeenCalledWith(expect.objectContaining({ attestationDecision: 'ATTESTED', failedCheck: null }));
  });

  // ── H132-D — request integrity: duplicate / cross-tenant ids, generic errors ──
  test('AT-H132-01  duplicate evidenceIds → NOT_ATTESTED, each record verified once (no inflated count)', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001', 'ev-001', 'ev-001'] });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.chainIntegrity.requestIntegrity.duplicateIds).toBe(true);
    expect(mockVerifyEvidence).toHaveBeenCalledTimes(1);
    expect(r.chainIntegrity.perRecordResults).toHaveLength(1);
  });

  test('AT-H132-02  VALID records of two tenants → NOT_ATTESTED (cross-tenant set)', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    mockGetByEvidenceId.mockResolvedValueOnce({ tenant_id: 'tenant-a' }).mockResolvedValueOnce({ tenant_id: 'tenant-b' });
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001', 'ev-002'] });
    expect(r.attestationDecision).toBe('NOT_ATTESTED');
    expect(r.chainIntegrity.requestIntegrity.crossTenant).toBe(true);
  });

  test('AT-H132-03  tenant context: a record outside expectedTenantIds → NOT_ATTESTED; inside → ATTESTED', async () => {
    mockVerifyEvidence.mockResolvedValue(validEvidenceResult);
    const out = await attestor.verifyChain({ evidenceIds: ['ev-001'] }, { expectedTenantIds: ['tenant-b'] });
    expect(out.attestationDecision).toBe('NOT_ATTESTED');
    const inside = await attestor.verifyChain({ evidenceIds: ['ev-001'] }, { expectedTenantIds: ['tenant-a'] });
    expect(inside.attestationDecision).toBe('ATTESTED');
  });

  test('AT-H132-04  verifyEvidence / verifyChainRange throwing → generic text, never the raw driver message', async () => {
    mockVerifyEvidence.mockRejectedValue(new Error('invalid input syntax for type uuid: "x"'));
    mockVerifyChainRange.mockRejectedValue(new Error('value "1e+20" is out of range for type bigint'));
    const r = await attestor.verifyChain({ evidenceIds: ['ev-001'], range: { startId: 1, endId: 5 } });
    expect(JSON.stringify(r)).not.toMatch(/syntax for type|out of range for type/);
    expect(r.chainIntegrity.rangeResult).toEqual(expect.objectContaining({ valid: false, complete: false, failureDetail: 'Range verification failed' }));
  });

  test('AT-H132-05  a single expected tenant is passed to the range verifier', async () => {
    mockVerifyChainRange.mockResolvedValue({ valid: false, complete: true, checkedCount: 0 });
    await attestor.verifyChain({ range: { startId: 1, endId: 5 } }, { expectedTenantIds: ['tenant-a'] });
    expect(mockVerifyChainRange).toHaveBeenCalledWith(expect.objectContaining({ tenantId: 'tenant-a' }));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-61…AT-75  attestationStore — PG-disabled path
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-61…AT-75  attestationStore — PG-disabled path', () => {
  beforeEach(() => {
    mockPool._enabled = false;
    mockPool.query.mockReset();
  });

  test('AT-61  recordAttestation returns null when PG disabled', async () => {
    const r = await realAttestationStore.recordAttestation({ attestationId: randomUUID(), attestationDecision: 'ATTESTED', artifactFingerprint: 'a'.repeat(64) });
    expect(r).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('AT-62  getByAttestationId returns null when PG disabled', async () => {
    const r = await realAttestationStore.getByAttestationId(randomUUID());
    expect(r).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('AT-63  getByFingerprint returns null when PG disabled', async () => {
    const r = await realAttestationStore.getByFingerprint('a'.repeat(64));
    expect(r).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('AT-64  listAttestations returns empty when PG disabled', async () => {
    const r = await realAttestationStore.listAttestations();
    expect(r.attestations).toHaveLength(0);
    expect(r.total).toBe(0);
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('AT-65  listAttestations preserves page and pageSize', async () => {
    const r = await realAttestationStore.listAttestations({ page: 2, pageSize: 20 });
    expect(r.page).toBe(2);
    expect(r.pageSize).toBe(20);
  });

  test('AT-66  aggregateStats returns null when PG disabled', async () => {
    const r = await realAttestationStore.aggregateStats();
    expect(r).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-76…AT-95  attestationStore — PG-enabled path (mocked pool)
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-76…AT-95  attestationStore — PG-enabled path', () => {
  const sampleRow = {
    id:                     1,
    attestation_id:         randomUUID(),
    attestation_type:       'ARTIFACT_VERIFICATION',
    version:                '1.0',
    artifact_fingerprint:   'b'.repeat(64),
    artifact_public_key_id: 'default:key_v1',
    artifact_timestamp_ms:  1700000000000,
    artifact_expiry_ms:     1700003600000,
    artifact_id:            'art-001',
    attestation_decision:   'ATTESTED',
    verification_result:    '{}',
    cryptographic_result:   '{}',
    compliance_result:      '{}',
    chain_result:           '{}',
    checks_performed:       '[]',
    warnings:               '[]',
    failed_check:           null,
    failure_reason:         null,
    transparency_id:        null,
    evidence_package_hash:  null,
    requested_by:           'external',
    request_ip:             null,
    duration_ms:            15,
    generated_at:           new Date().toISOString(),
  };

  beforeEach(() => {
    mockPool._enabled = true;
    mockPool.query.mockReset();
  });

  test('AT-76  recordAttestation issues INSERT with RETURNING', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });
    await realAttestationStore.recordAttestation({
      attestationId:       randomUUID(),
      attestationDecision: 'ATTESTED',
      artifactFingerprint: 'c'.repeat(64),
    });
    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('INSERT INTO attestations');
    expect(sql).toContain('RETURNING');
  });

  test('AT-77  recordAttestation serializes verificationResult as JSON string', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });
    const vr = { overallResult: 'VERIFIED', checks: [] };
    await realAttestationStore.recordAttestation({
      attestationId:       randomUUID(),
      attestationDecision: 'ATTESTED',
      artifactFingerprint: 'd'.repeat(64),
      verificationResult:  vr,
    });
    const [, params] = mockPool.query.mock.calls[0];
    const serialised = params.find(p => typeof p === 'string' && p.includes('VERIFIED'));
    expect(serialised).toBe(JSON.stringify(vr));
  });

  test('AT-78  getByAttestationId queries by UUID', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });
    const id = randomUUID();
    await realAttestationStore.getByAttestationId(id);
    const [sql, params] = mockPool.query.mock.calls[0];
    expect(sql).toContain('attestation_id');
    expect(params[0]).toBe(id);
  });

  test('AT-79  getByAttestationId returns null for no rows', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const r = await realAttestationStore.getByAttestationId(randomUUID());
    expect(r).toBeNull();
  });

  test('AT-80  getByFingerprint filters ARTIFACT_VERIFICATION type', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleRow] });
    await realAttestationStore.getByFingerprint('e'.repeat(64));
    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('ARTIFACT_VERIFICATION');
    expect(sql).toContain('DESC');
  });

  test('AT-81  listAttestations runs data + count queries', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [sampleRow] })
      .mockResolvedValueOnce({ rows: [{ total: '1' }] });
    const r = await realAttestationStore.listAttestations();
    expect(mockPool.query).toHaveBeenCalledTimes(2);
    expect(r.attestations).toHaveLength(1);
    expect(r.total).toBe(1);
  });

  test('AT-82  listAttestations filters by attestationDecision', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });
    await realAttestationStore.listAttestations({ attestationDecision: 'NOT_ATTESTED' });
    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('attestation_decision');
  });

  test('AT-83  listAttestations filters by attestationType', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });
    await realAttestationStore.listAttestations({ attestationType: 'CHAIN_VERIFICATION' });
    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('attestation_type');
  });

  test('AT-84  listAttestations caps pageSize at 500', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });
    const r = await realAttestationStore.listAttestations({ pageSize: 9999 });
    expect(r.pageSize).toBe(500);
  });

  test('AT-85  listAttestations uses DESC by default', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });
    await realAttestationStore.listAttestations();
    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('DESC');
  });

  test('AT-86  listAttestations uses ASC when sortOrder=asc', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });
    await realAttestationStore.listAttestations({ sortOrder: 'asc' });
    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('ASC');
  });

  test('AT-87  aggregateStats queries attestations table', async () => {
    const statsRow = {
      total: '50', attested_count: '40', warnings_count: '5', not_attested_count: '5',
      artifact_verifications: '45', evidence_verifications: '3', chain_verifications: '2',
      schema_failures: '1', signature_failures: '3', expiry_failures: '1',
      first_attestation: null, last_attestation: null, table_size: '8 kB',
    };
    mockPool.query.mockResolvedValue({ rows: [statsRow] });
    const r = await realAttestationStore.aggregateStats();
    const [sql] = mockPool.query.mock.calls[0];
    expect(sql).toContain('attestations');
    expect(r.total).toBe(50);
    expect(r.attestedCount).toBe(40);
    expect(r.notAttestedCount).toBe(5);
  });

  test('AT-88  aggregateStats returns zero-values when no rows', async () => {
    mockPool.query.mockResolvedValue({ rows: [{}] });
    const r = await realAttestationStore.aggregateStats();
    expect(r.total).toBe(0);
    expect(r.attestedCount).toBe(0);
  });

  test('AT-89  listAttestations correct offset for page 3 pageSize 10', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '0' }] });
    await realAttestationStore.listAttestations({ page: 3, pageSize: 10 });
    const [, params] = mockPool.query.mock.calls[0];
    expect(params).toContain(10);  // pageSize
    expect(params).toContain(20);  // offset = (3-1)*10
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-96…AT-110  RBAC permissions matrix
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-96…AT-110  RBAC permissions matrix', () => {
  test('AT-96  READ_ATTESTATIONS is defined in PERMISSIONS', () => {
    expect(PERMISSIONS.READ_ATTESTATIONS).toBeDefined();
  });

  test('AT-97  EXPORT_ATTESTATIONS is defined in PERMISSIONS', () => {
    expect(PERMISSIONS.EXPORT_ATTESTATIONS).toBeDefined();
  });

  test('AT-98  MANAGE_ATTESTATIONS is defined in PERMISSIONS', () => {
    expect(PERMISSIONS.MANAGE_ATTESTATIONS).toBeDefined();
  });

  test('AT-99  admin can READ_ATTESTATIONS', () => {
    expect(PERMISSIONS.READ_ATTESTATIONS).toContain('admin');
  });

  test('AT-100  auditor can READ_ATTESTATIONS', () => {
    expect(PERMISSIONS.READ_ATTESTATIONS).toContain('auditor');
  });

  test('AT-101  compliance can READ_ATTESTATIONS', () => {
    expect(PERMISSIONS.READ_ATTESTATIONS).toContain('compliance');
  });

  test('AT-102  operator cannot READ_ATTESTATIONS', () => {
    expect(PERMISSIONS.READ_ATTESTATIONS).not.toContain('operator');
  });

  test('AT-103  viewer cannot READ_ATTESTATIONS', () => {
    expect(PERMISSIONS.READ_ATTESTATIONS).not.toContain('viewer');
  });

  test('AT-104  admin can EXPORT_ATTESTATIONS', () => {
    expect(PERMISSIONS.EXPORT_ATTESTATIONS).toContain('admin');
  });

  test('AT-105  auditor can EXPORT_ATTESTATIONS', () => {
    expect(PERMISSIONS.EXPORT_ATTESTATIONS).toContain('auditor');
  });

  test('AT-106  compliance can EXPORT_ATTESTATIONS', () => {
    expect(PERMISSIONS.EXPORT_ATTESTATIONS).toContain('compliance');
  });

  test('AT-107  only admin can MANAGE_ATTESTATIONS', () => {
    expect(PERMISSIONS.MANAGE_ATTESTATIONS).toContain('admin');
    expect(PERMISSIONS.MANAGE_ATTESTATIONS).not.toContain('auditor');
    expect(PERMISSIONS.MANAGE_ATTESTATIONS).not.toContain('compliance');
    expect(PERMISSIONS.MANAGE_ATTESTATIONS).not.toContain('operator');
    expect(PERMISSIONS.MANAGE_ATTESTATIONS).not.toContain('viewer');
  });

  test('AT-108  ATTESTATION_VERSION is 1.0', () => {
    expect(attestor.ATTESTATION_VERSION).toBe('1.0');
  });

  test('AT-109  _DECISION_MAP is frozen', () => {
    expect(Object.isFrozen(attestor._DECISION_MAP)).toBe(true);
  });

  test('AT-110  DECISION_MAP contains exactly 3 entries', () => {
    expect(Object.keys(attestor._DECISION_MAP)).toHaveLength(3);
  });
});
