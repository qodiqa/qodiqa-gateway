'use strict';

/**
 * Attestation API — Integration & End-to-End Tests (Component #24)
 *
 * Tests real route execution against mocked external dependencies (DB,
 * transparency log, evidence chain, attestation store).  The core
 * attestation logic in attestor.js, portal.js, and validateArtifact()
 * run unmodified.
 *
 * AT-IT-01…AT-IT-08   POST /v1/attestation/verify — successful (ATTESTED)
 * AT-IT-09…AT-IT-13   POST /v1/attestation/verify — tampered → NOT_ATTESTED
 * AT-IT-14…AT-IT-17   POST /v1/attestation/verify — replay → ATTESTED_WITH_WARNINGS
 * AT-IT-18…AT-IT-20   POST /v1/attestation/verify — bad input
 * AT-IT-21…AT-IT-24   POST /v1/attestation/evidence/verify — valid package
 * AT-IT-25…AT-IT-28   POST /v1/attestation/evidence/verify — tampered / bad input
 * AT-IT-29…AT-IT-32   POST /v1/attestation/chain/verify — evidenceIds
 * AT-IT-33…AT-IT-36   POST /v1/attestation/chain/verify — range + limits
 * AT-IT-37…AT-IT-41   GET  /v1/attestation/:id — found, not found, invalid UUID
 * AT-IT-42…AT-IT-46   GET  /v1/attestation/:id/export — JSON and PDF
 * AT-IT-47…AT-IT-50   GET  /v1/attestation/:id/evidence
 * AT-IT-51…AT-IT-53   GET  /v1/attestation/:id/summary
 * AT-IT-54…AT-IT-57   GET  /v1/attestation/admin/history and stats
 * AT-IT-E2E-A-01…05   E2E Scenario A: valid artifact → full ATTESTED workflow
 * AT-IT-E2E-B-01…04   E2E Scenario B: tampered artifact → NOT_ATTESTED
 * AT-IT-E2E-C-01…04   E2E Scenario C: replay → ATTESTED_WITH_WARNINGS
 */

// ── Mocks (must precede all requires) ─────────────────────────────────────────

const mockPool = {
  _enabled: true,
  isEnabled: function () { return this._enabled; },
  query:     jest.fn(),
};
jest.mock('../../../infra/postgres/pool', () => mockPool);

const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({
  register: mockRegister,
}));

const mockVerifyEvidence   = jest.fn();
const mockVerifyChainRange = jest.fn();
const mockGetByArtifactId  = jest.fn();
jest.mock('../../../core/evidence/chainStore', () => ({
  verifyEvidence:   mockVerifyEvidence,
  verifyChainRange: mockVerifyChainRange,
  getByArtifactId:  mockGetByArtifactId,
  // H132-D: verifyChain reads each VALID record's tenant (single-tenant set).
  getByEvidenceId:  jest.fn(async () => ({ tenant_id: 'tenant-a' })),
}));

const mockRecordAttestation  = jest.fn();
const mockGetByAttestationId = jest.fn();
const mockGetByFingerprint   = jest.fn();
const mockListAttestations   = jest.fn();
const mockAggregateStats     = jest.fn();
jest.mock('../../../core/attestation/attestationStore', () => ({
  recordAttestation:  mockRecordAttestation,
  getByAttestationId: mockGetByAttestationId,
  getByFingerprint:   mockGetByFingerprint,
  listAttestations:   mockListAttestations,
  aggregateStats:     mockAggregateStats,
}));

// portalStore is accessed dynamically inside verifyEvidencePackage
jest.mock('../../../core/verification/portalStore', () => ({
  getByVerificationId: jest.fn().mockResolvedValue(null),
  recordVerification:  jest.fn().mockResolvedValue({ verification_id: 'stub' }),
  getByFingerprint:    jest.fn().mockResolvedValue(null),
  listVerifications:   jest.fn(),
  aggregateStats:      jest.fn(),
}));

jest.mock('../../../../services/logger', () => ({
  emit:                 jest.fn(),
  allowed:              jest.fn(),
  blocked:              jest.fn(),
  eventBus:             { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

jest.mock('../../../observability/metrics', () => ({
  attestationsTotal:                     { inc: jest.fn() },
  attestationFailuresTotal:              { inc: jest.fn() },
  attestationPersistFailuresTotal:       { inc: jest.fn() },
  attestationEvidenceVerificationsTotal: { inc: jest.fn() },
  attestationChainVerificationsTotal:    { inc: jest.fn() },
  portalVerificationsTotal:              { inc: jest.fn() },
  portalVerificationFailuresTotal:       { inc: jest.fn() },
  portalPersistFailuresTotal:            { inc: jest.fn() },
}));

// ── Module imports (after mocks) ──────────────────────────────────────────────

const request  = require('supertest');
const express  = require('express');
const { createHash, randomUUID } = require('crypto');
const { canonicalHash } = require('../../../../services/utils/evidencePackage');

const { createAttestationPublicRouter, createAttestationAdminRouter } = require('../attestation');
const { getActiveKey }  = require('../../../../services/artifact/keyStore');
const { signArtifact }  = require('../../../validation/signArtifact');

// ── Fixtures ──────────────────────────────────────────────────────────────────

let KEY;

beforeAll(() => {
  KEY = getActiveKey('default');
});

beforeEach(() => {
  jest.clearAllMocks();
  mockPool._enabled = true;

  // Default: no replay, evidence chain record present (so EVIDENCE_CHAIN check passes)
  mockGetByFingerprint.mockResolvedValue(null);
  mockGetByArtifactId.mockResolvedValue({ id: 'ev-record-001', artifact_id: 'art-001' });

  // Default: transparency registration succeeds
  mockRegister.mockResolvedValue({ transparencyId: 'trans-uuid-001' });

  // Default: attestation persistence succeeds
  mockRecordAttestation.mockResolvedValue({ attestation_id: 'stub-id' });

  // Default: GET lookups return null (tests override per case)
  mockGetByAttestationId.mockResolvedValue(null);
  mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
  mockAggregateStats.mockResolvedValue(null);

  // Default: chainStore calls return VALID
  mockVerifyEvidence.mockResolvedValue({ result: 'VALID', checks: [] });
  mockVerifyChainRange.mockResolvedValue({ valid: true, checkedCount: 5 });
});

// ── App factories ─────────────────────────────────────────────────────────────

// (D7 → B): public verifications persist only for an authenticated caller
// holding the write permission (optionalAuth → ctx.adminStack(...) in src/app.js).
// These suites test the PERSISTED flow, so the stand-in resolves an operator the
// way that stack would; the anonymous, ephemeral flow has its own tests
// (src/api/routes/__tests__/publicVerifyEphemeral.test.js).
const AUTHED = Object.freeze({ optionalAuth: (req, _res, next) => {
  req.rbacUser = req.rbacUser || Object.freeze({ id: 'op-1', username: 'op', role: 'admin', enabled: true });
  next();
} });

function makePublicApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  app.use('/v1/attestation', createAttestationPublicRouter(AUTHED));
  return app;
}

function makeAdminApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  app.use('/v1/attestation', createAttestationAdminRouter({
    requirePermission: () => (_r, _s, n) => n(),
  }));
  return app;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeValidArtifact(payloadOverrides = {}) {
  const now = Date.now();
  return signArtifact(
    {
      payload:     { action: 'test', requestId: randomUUID(), ...payloadOverrides },
      timestamp:   now,
      expiry:      now + 60_000,
      publicKeyId: KEY.keyId,
    },
    KEY.privDer,
  );
}

function buildEvidencePackage(overrides = {}) {
  const content = {
    packageType:         'QODIQA::PORTAL_EVIDENCE::V1',
    schemaVersion:       '1.0',
    verificationId:      randomUUID(),
    overallResult:       'VERIFIED',
    failedCheck:         null,
    failureReason:       null,
    warnings:            [],
    checksPerformed:     [],
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
    packageId:   createHash('sha256')
      .update(`${content.verificationId}:PORTAL_EVIDENCE`, 'utf8')
      .digest('hex'),
    generatedAt: new Date().toISOString(),
    packageHash,
  };
}

function makeSampleRecord(attestationId, overrides = {}) {
  return {
    id:                     1,
    attestation_id:         attestationId || randomUUID(),
    attestation_type:       'ARTIFACT_VERIFICATION',
    version:                '1.0',
    artifact_fingerprint:   'a'.repeat(64),
    artifact_public_key_id: KEY.keyId,
    artifact_timestamp_ms:  Date.now(),
    artifact_expiry_ms:     Date.now() + 60_000,
    artifact_id:            'art-001',
    attestation_decision:   'ATTESTED',
    verification_result:    { overallResult: 'VERIFIED', failedCheck: null, failureReason: null, warnings: [], checks: [] },
    cryptographic_result:   { signatureVerification: { status: 'PASS', algorithm: 'Ed25519' } },
    compliance_result:      { conformanceStatus: 'CONFORMS', policyCompliance: { status: 'COMPLIANT' } },
    chain_result:           { chainPresent: false },
    checks_performed:       [],
    warnings:               [],
    failed_check:           null,
    failure_reason:         null,
    transparency_id:        'trans-uuid-001',
    evidence_package_hash:  'e'.repeat(64),
    requested_by:           'external',
    request_ip:             null,
    duration_ms:            15,
    // a real `TIMESTAMPTZ` column comes back from the pg driver as a
    // native Date, not a string — `.toISOString()` here would silently mask
    // exactly the bug this fixture needs to catch (see AT-IT-47b below).
    generated_at:           new Date(),
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-01…AT-IT-08  POST /v1/attestation/verify — successful (ATTESTED)
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-01…AT-IT-08  POST /v1/attestation/verify — successful verification', () => {
  test('AT-IT-01  returns 200 with ATTESTED decision for a valid signed artifact', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
  });

  test('AT-IT-02  response includes apiVersion=v1', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.body.data.apiVersion).toBe('v1');
  });

  test('AT-IT-03  response attestationId is a valid UUID', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.body.data.attestation.attestationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  test('AT-IT-04  response includes attestationType=ARTIFACT_VERIFICATION', async () => {
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(res.body.data.attestation.attestationType).toBe('ARTIFACT_VERIFICATION');
  });

  test('AT-IT-05  verificationResult.overallResult is VERIFIED', async () => {
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(res.body.data.attestation.verificationResult.overallResult).toBe('VERIFIED');
  });

  test('AT-IT-06  transparency registration is called', async () => {
    await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(mockRegister).toHaveBeenCalledWith(
      expect.objectContaining({ entryType: 'VERIFICATION', registeredBy: 'attestation' }),
    );
  });

  test('AT-IT-07  accepts { artifact: <obj> } envelope format', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send({ artifact });
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
  });

  test('AT-IT-08  transparencyReferences.transparencyId is populated from registrar', async () => {
    mockRegister.mockResolvedValue({ transparencyId: 'trans-test-xyz' });
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(res.body.data.attestation.transparencyReferences.transparencyId).toBe('trans-test-xyz');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-09…AT-IT-13  POST /v1/attestation/verify — tampered → NOT_ATTESTED
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-09…AT-IT-13  POST /v1/attestation/verify — tampered → NOT_ATTESTED', () => {
  test('AT-IT-09  returns 200 with NOT_ATTESTED for invalid signature', async () => {
    const artifact = { ...makeValidArtifact(), signature: Buffer.from('bad-sig').toString('base64') };
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-IT-10  verificationResult.overallResult is FAILED for tampered artifact', async () => {
    const artifact = { ...makeValidArtifact(), signature: 'badsig' };
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.body.data.attestation.verificationResult.overallResult).toBe('FAILED');
  });

  test('AT-IT-11  failedCheck is populated for a failed verification', async () => {
    const artifact = { ...makeValidArtifact(), signature: 'badsig' };
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.body.data.attestation.verificationResult.failedCheck).toBeTruthy();
  });

  test('AT-IT-12  complianceResult.conformanceStatus is DOES_NOT_CONFORM', async () => {
    const artifact = { ...makeValidArtifact(), signature: 'badsig' };
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.body.data.attestation.complianceResult.conformanceStatus).toBe('DOES_NOT_CONFORM');
  });

  test('AT-IT-13  expired artifact yields NOT_ATTESTED', async () => {
    const now = Date.now();
    const artifact = signArtifact(
      { payload: { action: 'test', requestId: randomUUID() }, timestamp: now - 120_000, expiry: now - 60_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-14…AT-IT-17  POST /v1/attestation/verify — replay → ATTESTED_WITH_WARNINGS
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-14…AT-IT-17  POST /v1/attestation/verify — replay detection', () => {
  test('AT-IT-14  fingerprint seen → ATTESTED_WITH_WARNINGS', async () => {
    mockGetByFingerprint.mockResolvedValue({ attestation_id: randomUUID(), attestation_decision: 'ATTESTED' });
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED_WITH_WARNINGS');
  });

  test('AT-IT-15  overallResult is VERIFIED_WITH_WARNINGS on replay', async () => {
    mockGetByFingerprint.mockResolvedValue({ attestation_id: randomUUID(), attestation_decision: 'ATTESTED' });
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(res.body.data.attestation.verificationResult.overallResult).toBe('VERIFIED_WITH_WARNINGS');
  });

  test('AT-IT-16  replay check is still WARN (not FAIL) so status is 200', async () => {
    mockGetByFingerprint.mockResolvedValue({ attestation_id: randomUUID(), attestation_decision: 'ATTESTED' });
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
  });

  test('AT-IT-17  no replay when PG is disabled (getByFingerprint not called)', async () => {
    mockPool._enabled = false;
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(makeValidArtifact());
    expect(mockGetByFingerprint).not.toHaveBeenCalled();
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-18…AT-IT-20  POST /v1/attestation/verify — bad input
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-18…AT-IT-20  POST /v1/attestation/verify — bad input', () => {
  test('AT-IT-18  JSON null body returns 400 (express strict parser rejects it)', async () => {
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .set('Content-Type', 'application/json')
      .send('null');
    expect(res.status).toBe(400);
  });

  test('AT-IT-19  array body returns 400', async () => {
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send([{ payload: {}, signature: 'x' }]);
    expect(res.status).toBe(400);
  });

  test('AT-IT-20  empty object body still runs (no crash) and returns 200', async () => {
    const res = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send({});
    // Empty object is not null/array — passes input guard, runs checks, returns result
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-21…AT-IT-24  POST /v1/attestation/evidence/verify — valid package
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-21…AT-IT-24  POST /v1/attestation/evidence/verify — valid package', () => {
  // H129-A (design decision, Option B): a valid package is the one the system
  // issues for an existing original (previously: any self-hashed package, with
  // no original at all — the fail-open itself).
  const genuinePackage = () => {
    const rec = makeSampleRecord(randomUUID());
    mockGetByAttestationId.mockResolvedValue(rec);
    return require('../../../core/verification/portal').assembleEvidencePackageFromAttestationRecord(rec);
  };

  test('AT-IT-21  returns 200 ATTESTED for a valid (genuine, original-bound) package', async () => {
    const pkg = genuinePackage();
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .send({ evidencePackage: pkg });
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
    expect(res.body.data.attestation.valid).toBe(true);
  });

  test('AT-IT-22  integrityVerification.match is true for valid package', async () => {
    const pkg = buildEvidencePackage();
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .send({ evidencePackage: pkg });
    expect(res.body.data.attestation.integrityVerification.match).toBe(true);
  });

  test('AT-IT-23  accepts raw package body (without evidencePackage wrapper)', async () => {
    const pkg = genuinePackage();
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .send(pkg);
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.valid).toBe(true);
  });

  test('AT-IT-24  attestationType is EVIDENCE_VERIFICATION', async () => {
    const pkg = buildEvidencePackage();
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .send({ evidencePackage: pkg });
    expect(res.body.data.attestation.attestationType).toBe('EVIDENCE_VERIFICATION');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-25…AT-IT-28  POST /v1/attestation/evidence/verify — tampered / bad input
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-25…AT-IT-28  POST /v1/attestation/evidence/verify — tampered package', () => {
  test('AT-IT-25  tampered package hash → NOT_ATTESTED, valid=false', async () => {
    const pkg = buildEvidencePackage();
    // Mutate a field AFTER building (hash now mismatches)
    pkg.overallResult = 'FAILED';
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .send({ evidencePackage: pkg });
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
    expect(res.body.data.attestation.valid).toBe(false);
    expect(res.body.data.attestation.integrityVerification.match).toBe(false);
  });

  test('AT-IT-26  wrong packageType → 200 with valid=false', async () => {
    const pkg = buildEvidencePackage();
    pkg.packageType = 'QODIQA::WRONG::V1';
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .send({ evidencePackage: pkg });
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.valid).toBe(false);
  });

  test('AT-IT-27  JSON null body returns 400 (express strict parser rejects it)', async () => {
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .set('Content-Type', 'application/json')
      .send('null');
    expect(res.status).toBe(400);
  });

  test('AT-IT-28  array body returns 400', async () => {
    const res = await request(makePublicApp())
      .post('/v1/attestation/evidence/verify')
      .send([{ packageType: 'QODIQA::PORTAL_EVIDENCE::V1' }]);
    expect(res.status).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// (NF-2): POST /chain/verify is no longer public — it lives on the admin
// router behind MANAGE_ATTESTATIONS. These suites mirror src/app.js: public
// router, then the admin router behind an authentication stand-in (role header)
// and the REAL requirePermission.
function makeChainVerifyApp() {
  const roles = require('../../../core/rbac/roles');
  const { createRequirePermission } = require('../../../middleware/rbac');
  const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  app.use('/v1/attestation', createAttestationPublicRouter(AUTHED));
  app.use('/v1/attestation', (req, res, next) => {
    const role = req.headers['x-test-operator-role'];
    if (!role) return res.status(401).json({ error: { code: 'UNAUTHORIZED' } });
    req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role, enabled: true });
    return next();
  }, createAttestationAdminRouter({ requirePermission }));
  return app;
}
const CHAIN_ADMIN = { 'x-test-operator-role': 'admin' };

describe('AT-IT-28b POST /v1/attestation/chain/verify requires authentication + MANAGE_ATTESTATIONS', () => {
  const body = { evidenceIds: ['00000000-0000-4000-8000-000000000001'] };
  test('anonymous → 401, nothing verified or written', async () => {
    const res = await request(makeChainVerifyApp()).post('/v1/attestation/chain/verify').send(body);
    expect(res.status).toBe(401);
    expect(mockVerifyEvidence).not.toHaveBeenCalled();
  });
  test('an operator without MANAGE_ATTESTATIONS (auditor) → 403', async () => {
    const res = await request(makeChainVerifyApp()).post('/v1/attestation/chain/verify').set({ 'x-test-operator-role': 'auditor' }).send(body);
    expect(res.status).toBe(403);
    expect(mockVerifyEvidence).not.toHaveBeenCalled();
  });
  test('the public router alone no longer serves it (404)', async () => {
    const res = await request(makePublicApp()).post('/v1/attestation/chain/verify').send(body);
    expect(res.status).toBe(404);
  });
});

// AT-IT-29…AT-IT-32  POST /v1/attestation/chain/verify — evidenceIds
// ─────────────────────────────────────────────────────────────────────────────

// H132-D: evidenceIds are UUIDs at the route (schema), so fixtures use UUIDs.
describe('AT-IT-29…AT-IT-32  POST /v1/attestation/chain/verify — evidenceIds', () => {
  test('AT-IT-29  returns 200 ATTESTED when all evidence records are VALID', async () => {
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({ evidenceIds: ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002'] });
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
    expect(res.body.data.attestation.chainIntegrity.valid).toBe(true);
  });

  test('AT-IT-30  INVALID evidence record → NOT_ATTESTED', async () => {
    mockVerifyEvidence.mockResolvedValue({ result: 'INVALID', checks: [], failureReason: 'hash mismatch' });
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({ evidenceIds: ['00000000-0000-4000-8000-000000000001'] });
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
    expect(res.body.data.attestation.chainIntegrity.valid).toBe(false);
  });

  test('AT-IT-31  perRecordResults contains one entry per evidenceId', async () => {
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({ evidenceIds: ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000003'] });
    expect(res.body.data.attestation.chainIntegrity.perRecordResults).toHaveLength(3);
  });

  test('AT-IT-32  missing body → 400', async () => {
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-33…AT-IT-36  POST /v1/attestation/chain/verify — range + limits
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-33…AT-IT-36  POST /v1/attestation/chain/verify — range + limits', () => {
  // (design decision, Option A): a range-only request runs the continuity
  // check but can never attest — its records never receive a per-record VALID
  // verdict. The decision assertion (previously ATTESTED) is inverted to the
  // approved value; the call assertion this test exists for is unchanged.
  test('AT-IT-33 range input calls verifyChainRange', async () => {
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({ range: { startId: 1, endId: 10 } });
    expect(res.status).toBe(200);
    expect(mockVerifyChainRange).toHaveBeenCalled();
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-IT-34  evidenceIds > 50 → 400', async () => {
    const ids = Array.from({ length: 51 }, (_, i) => `ev-${i}`);
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({ evidenceIds: ids });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });

  test('AT-IT-35  invalid range → NOT_ATTESTED when chainStore throws', async () => {
    mockVerifyChainRange.mockRejectedValue(new Error('range not found'));
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({ range: { startId: 999, endId: 1000 } });
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-IT-36  attestationType is CHAIN_VERIFICATION', async () => {
    const res = await request(makeChainVerifyApp())
      .post('/v1/attestation/chain/verify').set(CHAIN_ADMIN)
      .send({ evidenceIds: ['00000000-0000-4000-8000-000000000001'] });
    expect(res.body.data.attestation.attestationType).toBe('CHAIN_VERIFICATION');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-37…AT-IT-41  GET /v1/attestation/:id — fetch by attestationId
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-37…AT-IT-41  GET /v1/attestation/:id', () => {
  test('AT-IT-37  returns 200 with attestation when found', async () => {
    const id     = randomUUID();
    const record = makeSampleRecord(id);
    mockGetByAttestationId.mockResolvedValue(record);
    const res = await request(makePublicApp())
      .get(`/v1/attestation/${id}`);
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestation_id).toBe(id);
  });

  test('AT-IT-38  returns 404 when attestation not found', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(null);
    const res = await request(makePublicApp())
      .get(`/v1/attestation/${id}`);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('AT-IT-39  returns 400 for non-UUID attestationId', async () => {
    const res = await request(makePublicApp())
      .get('/v1/attestation/not-a-uuid');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });

  test('AT-IT-40  response includes apiVersion=v1', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makePublicApp())
      .get(`/v1/attestation/${id}`);
    expect(res.body.data.apiVersion).toBe('v1');
  });

  test('AT-IT-41  response status is success', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makePublicApp())
      .get(`/v1/attestation/${id}`);
    expect(res.body.status).toBe('success');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-42…AT-IT-46  GET /v1/attestation/:id/export — JSON and PDF
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-42…AT-IT-46  GET /v1/attestation/:id/export', () => {
  test('AT-IT-42  JSON export returns 200 with attestation record', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/export`);
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestation_id).toBe(id);
  });

  test('AT-IT-43  PDF export returns 200 with Content-Type application/pdf', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/export?format=pdf`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/pdf/);
  }, 10_000);

  test('AT-IT-44  PDF export body starts with PDF magic bytes', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/export?format=pdf`)
      .buffer(true)
      .parse((response, callback) => {
        const chunks = [];
        response.on('data', c => chunks.push(c));
        response.on('end', () => callback(null, Buffer.concat(chunks)));
      });
    expect(res.body.slice(0, 4).toString()).toBe('%PDF');
  }, 10_000);

  test('AT-IT-45  export 404 when not found', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(null);
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/export`);
    expect(res.status).toBe(404);
  });

  test('AT-IT-46  export 400 for non-UUID id', async () => {
    const res = await request(makeAdminApp())
      .get('/v1/attestation/bad-id/export');
    expect(res.status).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-47…AT-IT-50  GET /v1/attestation/:id/evidence
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-47…AT-IT-50  GET /v1/attestation/:id/evidence', () => {
  test('AT-IT-47  returns 200 with evidencePackage', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/evidence`);
    expect(res.status).toBe(200);
    expect(res.body.data.evidencePackage).toBeDefined();
  });

  test('AT-IT-48  evidencePackage.packageType is QODIQA::PORTAL_EVIDENCE::V1', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/evidence`);
    expect(res.body.data.evidencePackage.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
  });

  test('AT-IT-49  evidence endpoint returns 404 when record not found', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(null);
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/evidence`);
    expect(res.status).toBe(404);
  });

  test('AT-IT-50  evidencePackage includes packageHash (SHA-256 hex)', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/evidence`);
    expect(res.body.data.evidencePackage.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });

  // GET /:id/evidence threw an uncaught 500 —
  // "stableStringify: cannot serialize a non-plain-object value (Date)" —
  // because `generated_at` (a real TIMESTAMPTZ column, a native Date via the
  // pg driver, not the string the old fixture used) reached canonicalHash()
  // unconverted. Reproduced live against a real server before fixing; see
  //.

  test('AT-IT-47a a null-artifact_id attestation returns 200, not 500', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, { artifact_id: null }));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/evidence`);
    expect(res.status).toBe(200);
    expect(res.body.data.evidencePackage.artifactId).toBeNull();
  });

  test('AT-IT-47b the generated_at Date is serialized as an ISO string, no crash regardless of artifact_id', async () => {
    const id = randomUUID();
    // artifact_id is non-null here (the "happy path" linkage case) — proves
    // the fix isn't specific to null linkage, since the real bug never was.
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, { artifact_id: 'art-002' }));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/evidence`);
    expect(res.status).toBe(200);
    expect(res.body.data.evidencePackage.artifactId).toBe('art-002');
    expect(typeof res.body.data.evidencePackage.verifiedAt).toBe('string');
    expect(res.body.data.evidencePackage.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test('AT-IT-47c a real evidence-chain linkage still returns its evidence correctly', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, {
      artifact_id: 'art-linked-001',
      chain_result: { chainPresent: true, evidenceId: 'ev-001', artifactId: 'art-linked-001' },
    }));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/evidence`);
    expect(res.status).toBe(200);
    expect(res.body.data.evidencePackage.artifactId).toBe('art-linked-001');
    expect(res.body.data.evidencePackage.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
    expect(res.body.data.evidencePackage.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-51…AT-IT-53  GET /v1/attestation/:id/summary
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-51…AT-IT-53  GET /v1/attestation/:id/summary', () => {
  test('AT-IT-51  returns 200 with summary for found record', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/summary`);
    expect(res.status).toBe(200);
    expect(res.body.data.summary.attestationId).toBe(id);
    expect(res.body.data.summary.attestationDecision).toBe('ATTESTED');
  });

  test('AT-IT-52  summary includes cryptographicReferences.algorithm=Ed25519', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id));
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/summary`);
    expect(res.body.data.summary.cryptographicReferences.algorithm).toBe('Ed25519');
  });

  test('AT-IT-53  summary returns 404 when record not found', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(null);
    const res = await request(makeAdminApp())
      .get(`/v1/attestation/${id}/summary`);
    expect(res.status).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-54…AT-IT-57  GET admin/history and admin/stats
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-54…AT-IT-57  admin/history and admin/stats', () => {
  test('AT-IT-54  GET /admin/history returns 200 with attestations array', async () => {
    mockListAttestations.mockResolvedValue({
      attestations: [makeSampleRecord(randomUUID())],
      total: 1,
      page: 1,
      pageSize: 50,
    });
    const res = await request(makeAdminApp())
      .get('/v1/attestation/admin/history');
    expect(res.status).toBe(200);
    expect(res.body.data.attestations).toHaveLength(1);
    expect(res.body.data.total).toBe(1);
  });

  test('AT-IT-55  GET /admin/history forwards query filters', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
    await request(makeAdminApp())
      .get('/v1/attestation/admin/history?attestationDecision=ATTESTED&pageSize=10');
    expect(mockListAttestations).toHaveBeenCalledWith(
      expect.objectContaining({ attestationDecision: 'ATTESTED', pageSize: 10 }),
    );
  });

  test('AT-IT-56  GET /admin/stats returns 200 with stats', async () => {
    mockAggregateStats.mockResolvedValue({
      total: 100, attestedCount: 80, warningsCount: 10, notAttestedCount: 10,
      artifactVerifications: 90, evidenceVerifications: 5, chainVerifications: 5,
    });
    const res = await request(makeAdminApp())
      .get('/v1/attestation/admin/stats');
    expect(res.status).toBe(200);
    expect(res.body.data.stats.total).toBe(100);
    expect(res.body.data.pgEnabled).toBe(true);
  });

  test('AT-IT-57  GET /admin/stats returns zero counts when PG disabled (stats=null)', async () => {
    mockAggregateStats.mockResolvedValue(null);
    const res = await request(makeAdminApp())
      .get('/v1/attestation/admin/stats');
    expect(res.status).toBe(200);
    expect(res.body.data.pgEnabled).toBe(false);
    expect(res.body.data.stats.total).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// E2E Scenario A — Full artifact attestation workflow (ATTESTED)
// ─────────────────────────────────────────────────────────────────────────────

describe('E2E Scenario A — valid artifact → ATTESTED full workflow', () => {
  let capturedAttestationId;
  let capturedTransparencyArgs;
  let capturedPersistArgs;
  let capturedResponse;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockPool._enabled = true;
    mockGetByFingerprint.mockResolvedValue(null);
    mockGetByArtifactId.mockResolvedValue({ id: 'ev-chain-001', artifact_id: 'art-001' });
    mockRegister.mockResolvedValue({ transparencyId: 'trans-e2e-a' });
    mockRecordAttestation.mockResolvedValue({ attestation_id: 'persist-e2e-a' });

    const artifact = makeValidArtifact({ artifactId: 'art-001' });

    capturedResponse = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);

    // Capture mock call state immediately before outer beforeEach clears it
    capturedTransparencyArgs = mockRegister.mock.calls[0]?.[0] ?? null;
    capturedPersistArgs      = mockRecordAttestation.mock.calls[0]?.[0] ?? null;
    capturedAttestationId    = capturedResponse.body?.data?.attestation?.attestationId ?? null;
  });

  test('AT-IT-E2E-A-01  response status is 200 ATTESTED', () => {
    expect(capturedResponse.status).toBe(200);
    expect(capturedResponse.body.data.attestation.attestationDecision).toBe('ATTESTED');
  });

  test('AT-IT-E2E-A-02  transparencyId from registrar is reflected in response', () => {
    expect(capturedResponse.body.data.attestation.transparencyReferences.transparencyId)
      .toBe('trans-e2e-a');
  });

  test('AT-IT-E2E-A-03  transparency registrar received VERIFICATION entryType', () => {
    expect(capturedTransparencyArgs?.entryType).toBe('VERIFICATION');
    expect(capturedTransparencyArgs?.registeredBy).toBe('attestation');
  });

  test('AT-IT-E2E-A-04  persistence record carries ATTESTED decision', async () => {
    // Fire-and-forget: allow microtask queue to flush
    await Promise.resolve();
    const args = mockRecordAttestation.mock.calls[0]?.[0] ?? capturedPersistArgs;
    expect(args?.attestationDecision).toBe('ATTESTED');
    expect(args?.attestationType).toBe('ARTIFACT_VERIFICATION');
  });

  test('AT-IT-E2E-A-05  evidencePackage.packageHash is a 64-char hex string', () => {
    expect(capturedResponse.body.data.attestation.evidencePackage.packageHash)
      .toMatch(/^[0-9a-f]{64}$/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// E2E Scenario B — Tampered artifact → NOT_ATTESTED
// ─────────────────────────────────────────────────────────────────────────────

describe('E2E Scenario B — tampered artifact → NOT_ATTESTED', () => {
  let capturedResponse;
  let capturedPersistArgs;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockPool._enabled = true;
    mockGetByFingerprint.mockResolvedValue(null);
    mockRegister.mockResolvedValue({ transparencyId: 'trans-e2e-b' });
    mockRecordAttestation.mockResolvedValue({ attestation_id: 'persist-e2e-b' });

    const artifact = { ...makeValidArtifact(), signature: 'tampered-signature-xyz' };

    capturedResponse = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);

    await Promise.resolve(); // flush fire-and-forget
    capturedPersistArgs = mockRecordAttestation.mock.calls[0]?.[0] ?? null;
  });

  test('AT-IT-E2E-B-01  response is 200 NOT_ATTESTED', () => {
    expect(capturedResponse.status).toBe(200);
    expect(capturedResponse.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('AT-IT-E2E-B-02  verificationResult.failedCheck is populated', () => {
    expect(capturedResponse.body.data.attestation.verificationResult.failedCheck).toBeTruthy();
  });

  test('AT-IT-E2E-B-03  complianceResult.conformanceStatus is DOES_NOT_CONFORM', () => {
    expect(capturedResponse.body.data.attestation.complianceResult.conformanceStatus)
      .toBe('DOES_NOT_CONFORM');
  });

  test('AT-IT-E2E-B-04  persistence record carries NOT_ATTESTED decision', () => {
    expect(capturedPersistArgs?.attestationDecision).toBe('NOT_ATTESTED');
    expect(capturedPersistArgs?.failedCheck).toBeTruthy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// E2E Scenario C — Replay detection → ATTESTED_WITH_WARNINGS
// ─────────────────────────────────────────────────────────────────────────────

describe('E2E Scenario C — replay submission → ATTESTED_WITH_WARNINGS', () => {
  let capturedResponse;
  let capturedPersistArgs;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockPool._enabled = true;
    // Simulate fingerprint previously seen
    mockGetByFingerprint.mockResolvedValue({
      attestation_id:       randomUUID(),
      attestation_decision: 'ATTESTED',
    });
    mockRegister.mockResolvedValue({ transparencyId: 'trans-e2e-c' });
    mockRecordAttestation.mockResolvedValue({ attestation_id: 'persist-e2e-c' });

    const artifact = makeValidArtifact();

    capturedResponse = await request(makePublicApp())
      .post('/v1/attestation/verify')
      .send(artifact);

    await Promise.resolve(); // flush fire-and-forget
    capturedPersistArgs = mockRecordAttestation.mock.calls[0]?.[0] ?? null;
  });

  test('AT-IT-E2E-C-01  response is 200 ATTESTED_WITH_WARNINGS', () => {
    expect(capturedResponse.status).toBe(200);
    expect(capturedResponse.body.data.attestation.attestationDecision).toBe('ATTESTED_WITH_WARNINGS');
  });

  test('AT-IT-E2E-C-02  verificationResult.overallResult is VERIFIED_WITH_WARNINGS', () => {
    expect(capturedResponse.body.data.attestation.verificationResult.overallResult)
      .toBe('VERIFIED_WITH_WARNINGS');
  });

  test('AT-IT-E2E-C-03  verificationResult.warnings is non-empty', () => {
    expect(capturedResponse.body.data.attestation.verificationResult.warnings.length).toBeGreaterThan(0);
  });

  test('AT-IT-E2E-C-04  persistence record carries ATTESTED_WITH_WARNINGS decision', () => {
    expect(capturedPersistArgs?.attestationDecision).toBe('ATTESTED_WITH_WARNINGS');
  });
});

// ── public evidence correlation (security boundary) ─────────────────────
// POST /v1/attestation/verify is unauthenticated and the evidence lookup reads
// across tenants, so the key MUST be the artifact's own signed payload.requestId
// (QODIQA-PROTOCOL-SPEC §10.11/§12.1) and the response must never carry another
// execution's evidence. Reproduced live before the fix: an unexecuted artifact
// claiming another execution's id was ATTESTED with that execution's evidence,
// and an invalid artifact still disclosed it.
// payloads carry the signing key's own tenant ('default') — /sign never produces any other, and
// validateArtifact now rejects a payload tenant that differs from the key's.
describe('AT-IT-H126  POST /v1/attestation/verify — evidence correlation boundary', () => {
  const VICTIM = { evidence_id: 'ev-victim-h126', artifact_id: 'victim-req', evidence_hash: 'victimhash', decision: 'ALLOW', tenant_id: 'default' };
  const noVictim = (res) => expect(JSON.stringify(res.body)).not.toMatch(/ev-victim-h126|victimhash/);
  const post = (artifact) => request(makePublicApp()).post('/v1/attestation/verify').send({ artifact });

  test('AT-IT-H126-01  a legitimate artifact is ATTESTED with its own evidence, looked up by payload.requestId', async () => {
    const own = randomUUID();
    mockGetByArtifactId.mockImplementation(async (id) => (id === own ? { evidence_id: 'ev-own', artifact_id: own, evidence_hash: 'ownhash', decision: 'ALLOW', tenant_id: 'default' } : null));
    const res = await post(makeValidArtifact({ requestId: own, tenantId: 'default' }));
    expect(mockGetByArtifactId).toHaveBeenCalledWith(own);
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
    expect(res.body.data.attestation.chainResult).toMatchObject({ chainPresent: true, evidenceId: 'ev-own', artifactId: own });
  });

  test('AT-IT-H126-02  a caller-supplied payload.artifactId cannot redirect the lookup to another execution', async () => {
    const own = randomUUID();
    mockGetByArtifactId.mockImplementation(async (id) => (id === 'victim-req' ? VICTIM : null));
    const res = await post(makeValidArtifact({ requestId: own, tenantId: 'default', artifactId: 'victim-req' }));
    expect(mockGetByArtifactId).toHaveBeenCalledWith(own);
    expect(mockGetByArtifactId).not.toHaveBeenCalledWith('victim-req');
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED_WITH_WARNINGS');
    expect(res.body.data.attestation.chainResult.chainPresent).toBe(false);
    noVictim(res);
  });

  test('AT-IT-H126-03  a record belonging to another tenant is rejected', async () => {
    const own = randomUUID();
    mockGetByArtifactId.mockImplementation(async () => ({ ...VICTIM, artifact_id: own, tenant_id: 't-b' }));
    // artifactId also set, so the lookup runs whichever key the code uses
    const res = await post(makeValidArtifact({ requestId: own, tenantId: 'default', artifactId: own }));
    expect(res.body.data.attestation.chainResult.chainPresent).toBe(false);
    noVictim(res);
  });

  test('AT-IT-H126-04  a signed artifact with no requestId performs no lookup and exposes nothing', async () => {
    mockGetByArtifactId.mockImplementation(async () => VICTIM);
    const now = Date.now();
    const art = signArtifact({ payload: { action: 'test', artifactId: 'victim-req', tenantId: 'default' }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId }, KEY.privDer);
    const res = await post(art);
    expect(mockGetByArtifactId).not.toHaveBeenCalled();
    expect(res.body.data.attestation.chainResult.chainPresent).toBe(false);
    noVictim(res);
  });

  test('AT-IT-H126-05  a malformed (non-string) requestId performs no lookup and exposes nothing', async () => {
    mockGetByArtifactId.mockImplementation(async () => VICTIM);
    const res = await post(makeValidArtifact({ requestId: 42, tenantId: 'default', artifactId: 'victim-req' }));
    expect(mockGetByArtifactId).not.toHaveBeenCalled();
    expect(res.body.data.attestation.chainResult.chainPresent).toBe(false);
    noVictim(res);
  });

  test('AT-IT-H126-06  a tampered artifact pointing at another execution is NOT_ATTESTED and discloses nothing', async () => {
    mockGetByArtifactId.mockImplementation(async (id) => (id === 'victim-req' ? VICTIM : null));
    const art = makeValidArtifact({ tenantId: 'default' });
    art.payload.requestId = 'victim-req'; // unsigned edit -> signature invalid
    art.payload.artifactId = 'victim-req'; // so the lookup runs whichever key the code uses
    const res = await post(art);
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
    expect(res.body.data.attestation.chainResult.chainPresent).toBe(false);
    noVictim(res);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AT-IT-H129  historical (pre-binding) evidence-package attestations are FLAGGED
// at retrieval — never rewritten (H129-A, owner-selected retrieval-time flag).
// Discriminator: records written by the bound verifier store
// compliance_result.contentBound; the pre-fix verifier never did.
// ─────────────────────────────────────────────────────────────────────────────

describe('AT-IT-H129  retrieval-time flag for pre-binding package attestations', () => {
  const preFix = (id) => makeSampleRecord(id, {
    attestation_type: 'EVIDENCE_VERIFICATION', attestation_decision: 'ATTESTED',
    compliance_result: { originalFound: false, originalResult: null, verificationId: null },
  });
  const postFix = (id) => makeSampleRecord(id, {
    attestation_type: 'EVIDENCE_VERIFICATION', attestation_decision: 'ATTESTED',
    compliance_result: { originalFound: true, originalResult: 'ATTESTED', verificationId: randomUUID(), contentBound: true },
  });
  const ADVISORY = 'EVIDENCE_PACKAGE_NOT_BOUND_TO_ORIGINAL';

  test('AT-IT-H129-01  public GET flags a pre-binding ATTESTED package attestation; stored decision is returned unchanged', async () => {
    const id = randomUUID(); const rec = preFix(id);
    mockGetByAttestationId.mockResolvedValue(rec);
    const res = await request(makePublicApp()).get(`/v1/attestation/${id}`);
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestation_decision).toBe('ATTESTED');
    expect(res.body.data.attestation.integrityAdvisory).toEqual(expect.objectContaining({ code: ADVISORY, storedDecisionUnchanged: true }));
    expect(rec.integrityAdvisory).toBeUndefined();          // the stored row object is not mutated
    expect(mockRecordAttestation).not.toHaveBeenCalled();  // nothing is re-persisted
  });

  test.each([
    ['a bound (post-fix) package attestation', (id) => postFix(id)],
    ['a pre-fix NOT_ATTESTED package attestation', (id) => ({ ...preFix(id), attestation_decision: 'NOT_ATTESTED' })],
    ['an artifact attestation', (id) => makeSampleRecord(id)],
  ])('AT-IT-H129-02  no flag for %s', async (_n, make) => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(make(id));
    const res = await request(makePublicApp()).get(`/v1/attestation/${id}`);
    expect(res.body.data.attestation.integrityAdvisory).toBeUndefined();
  });

  test('AT-IT-H129-03  admin export (JSON), summary and history carry the same flag', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(preFix(id));
    const exp = await request(makeAdminApp()).get(`/v1/attestation/${id}/export`);
    expect(exp.body.data.attestation.integrityAdvisory.code).toBe(ADVISORY);
    const sum = await request(makeAdminApp()).get(`/v1/attestation/${id}/summary`);
    expect(sum.body.data.summary.integrityAdvisory.code).toBe(ADVISORY);
    mockListAttestations.mockResolvedValue({ attestations: [preFix(randomUUID()), postFix(randomUUID())], total: 2, page: 1, pageSize: 50 });
    const hist = await request(makeAdminApp()).get('/v1/attestation/admin/history');
    const flags = hist.body.data.attestations.map(a => (a.integrityAdvisory ? a.integrityAdvisory.code : null));
    expect(flags).toEqual([ADVISORY, null]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// H130-AT-IT-01…H130-AT-IT-07: the
// requester / verifier address (attestations.request_ip) is INTERNAL AUDIT DATA —
// persisted, served to READ/EXPORT_ATTESTATIONS operators, never public.
// ─────────────────────────────────────────────────────────────────────────────

describe('H130-AT-IT  requester/verifier address: internal audit data, never public', () => {
  const H130_IP   = '203.0.113.10'; // RFC 5737 TEST-NET-3 — synthetic
  const UNRELATED = { Authorization: 'Bearer sk_h130_unrelated_tenant_credential' };
  const roles = require('../../../core/rbac/roles');
  const { createRequirePermission } = require('../../../middleware/rbac');
  const portal = require('../../../core/verification/portal');

  // Mirrors src/app.js: public router, then the admin router behind the admin
  // stack (authentication stood in by a role header; REAL requirePermission).
  function makeComposedApp() {
    const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
    app.use('/v1/attestation', createAttestationPublicRouter(AUTHED));
    app.use('/v1/attestation', (req, res, next) => {
      const role = req.headers['x-test-operator-role'];
      if (!role) return res.status(401).json({ error: { code: 'UNAUTHORIZED' } });
      req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role, enabled: true });
      return next();
    }, createAttestationAdminRouter({ requirePermission }));
    return app;
  }
  const AUDITOR = { 'x-test-operator-role': roles.ROLES.AUDITOR };
  const stripIdAndTime = ({ packageId, generatedAt, ...c }) => c;

  test('H130-AT-IT-01  public GET /:id omits request_ip; the rest of the row is intact; unrelated credential sees the same', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, { request_ip: H130_IP }));
    const anon = await request(makeComposedApp()).get(`/v1/attestation/${id}`);
    expect(anon.status).toBe(200);
    expect(anon.body.data.attestation).not.toHaveProperty('request_ip');
    expect(anon.body.data.attestation.attestation_id).toBe(id);
    expect(anon.body.data.attestation.attestation_decision).toBe('ATTESTED');
    expect(anon.text).not.toContain(H130_IP);
    const other = await request(makeComposedApp()).get(`/v1/attestation/${id}`).set(UNRELATED);
    expect(other.body.data).toEqual(anon.body.data);
  });

  test('H130-AT-IT-02  a third-party verifier address is withheld publicly, and the H129-A historical advisory still attaches', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, {
      attestation_type: 'EVIDENCE_VERIFICATION', compliance_result: { originalFound: false }, request_ip: H130_IP,
    }));
    const res = await request(makeComposedApp()).get(`/v1/attestation/${id}`);
    expect(res.status).toBe(200);
    expect(res.body.data.attestation).not.toHaveProperty('request_ip');
    expect(res.body.data.attestation.integrityAdvisory.code).toBe('EVIDENCE_PACKAGE_NOT_BOUND_TO_ORIGINAL');
    expect(res.text).not.toContain(H130_IP);
  });

  test('H130-AT-IT-03  public verification still ATTESTS a genuine package that carries an address, and echoes no address', async () => {
    const rec = makeSampleRecord(randomUUID(), { request_ip: H130_IP });
    mockGetByAttestationId.mockResolvedValue(rec);
    const pkg = portal.assembleEvidencePackageFromAttestationRecord(rec);
    expect(pkg.submissionIp).toBe(H130_IP);
    const res = await request(makeComposedApp()).post('/v1/attestation/evidence/verify').send({ evidencePackage: pkg });
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
    expect(res.body.data.attestation.valid).toBe(true);
    expect(res.text).not.toContain(H130_IP);
    const verifierIp = mockRecordAttestation.mock.calls[0][0].requestIp;
    expect(typeof verifierIp).toBe('string');
    expect(res.text).not.toContain(verifierIp);
  });

  test('H130-AT-IT-04  a genuine package with its address redacted is NOT attested (hash contract unchanged)', async () => {
    const rec = makeSampleRecord(randomUUID(), { request_ip: H130_IP });
    mockGetByAttestationId.mockResolvedValue(rec);
    const { packageHash: _h, ...rest } = portal.assembleEvidencePackageFromAttestationRecord(rec);
    const redacted = { ...rest, submissionIp: null };
    const res = await request(makeComposedApp()).post('/v1/attestation/evidence/verify')
      .send({ evidencePackage: { ...redacted, packageHash: canonicalHash(stripIdAndTime(redacted)) } });
    expect(res.status).toBe(200);
    expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
  });

  test('H130-AT-IT-05  POST /verify and /chain/verify persist the caller address internally but never return it', async () => {
    const a = await request(makeComposedApp()).post('/v1/attestation/verify').send({ artifact: makeValidArtifact() });
    expect(a.status).toBe(200);
    const ipA = mockRecordAttestation.mock.calls[0][0].requestIp;
    expect(typeof ipA).toBe('string');
    expect(a.text).not.toContain(ipA);
    // (NF-2): chain verify is operator-only now (MANAGE_ATTESTATIONS → admin).
    const c = await request(makeComposedApp()).post('/v1/attestation/chain/verify').set({ 'x-test-operator-role': roles.ROLES.ADMIN }).send({ evidenceIds: ['00000000-0000-4000-8000-000000000001'] });
    expect(c.status).toBe(200);
    const ipC = mockRecordAttestation.mock.calls[1][0].requestIp;
    expect(typeof ipC).toBe('string');
    expect(c.text).not.toContain(ipC);
  });

  test('H130-AT-IT-06  internal audit views keep the address: export (JSON), evidence package, history', async () => {
    const id = randomUUID();
    const rec = makeSampleRecord(id, { request_ip: H130_IP });
    mockGetByAttestationId.mockResolvedValue(rec);
    mockListAttestations.mockResolvedValue({ attestations: [rec], total: 1, page: 1, pageSize: 50 });
    const exp = await request(makeComposedApp()).get(`/v1/attestation/${id}/export`).set(AUDITOR);
    expect(exp.status).toBe(200);
    expect(exp.body.data.attestation.request_ip).toBe(H130_IP);
    const ev = await request(makeComposedApp()).get(`/v1/attestation/${id}/evidence`).set(AUDITOR);
    expect(ev.status).toBe(200);
    expect(ev.body.data.evidencePackage.submissionIp).toBe(H130_IP);
    const hist = await request(makeComposedApp()).get('/v1/attestation/admin/history').set(AUDITOR);
    expect(hist.status).toBe(200);
    expect(hist.body.data.attestations[0].request_ip).toBe(H130_IP);
  });

  test('H130-AT-IT-07  internal views are refused without operator authentication (401) or with an unpermitted role (403)', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, { request_ip: H130_IP }));
    for (const path of [`/v1/attestation/${id}/export`, `/v1/attestation/${id}/evidence`, '/v1/attestation/admin/history']) {
      const anon = await request(makeComposedApp()).get(path).set(UNRELATED);
      expect(anon.status).toBe(401);
      expect(anon.text).not.toContain(H130_IP);
      const viewer = await request(makeComposedApp()).get(path).set({ 'x-test-operator-role': roles.ROLES.VIEWER });
      expect(viewer.status).toBe(403);
      expect(viewer.text).not.toContain(H130_IP);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// H131-AT-IT-01…H131-AT-IT-03 GET /v1/attestation/:id/export?format=pdf
// with the value shapes PostgreSQL actually returns (BIGINT timestamps as
// strings). `lateWrites` records any write attempted on an already-ended
// response — the operation that previously terminated the process.
// ─────────────────────────────────────────────────────────────────────────────

describe('H131-AT-IT  attestation export PDF is process-safe with PostgreSQL value shapes', () => {
  const http = require('http');
  const zlib = require('zlib');
  const PG_TS = '1790000000000';
  const PG_EX = '1790000600000';
  let lateWrites;
  let writeSpy;

  beforeEach(() => {
    lateWrites = 0;
    const origWrite = http.ServerResponse.prototype.write;
    writeSpy = jest.spyOn(http.ServerResponse.prototype, 'write').mockImplementation(function (...args) {
      if (this.writableEnded) { lateWrites += 1; return false; }
      return origWrite.apply(this, args);
    });
  });
  afterEach(() => { writeSpy.mockRestore(); });

  const settle = () => new Promise(r => setTimeout(r, 150));
  const binary = (res, cb) => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => cb(null, Buffer.concat(c))); };
  const pdfText = (buf) => {
    const s = buf.toString('latin1'); let out = ''; let i = 0;
    while ((i = s.indexOf('stream', i)) !== -1) {
      let st = i + 6; if (s[st] === '\r') st++; if (s[st] === '\n') st++;
      const en = s.indexOf('endstream', st); if (en === -1) break;
      let b = Buffer.from(s.slice(st, en), 'latin1'); try { b = zlib.inflateSync(b); } catch { /* raw */ }
      for (const blk of b.toString('latin1').split('ET')) {
        let line = '';
        for (const m of blk.matchAll(/<([0-9a-fA-F]+)>|\(((?:\\.|[^\\)])*)\)/g)) line += m[1] ? Buffer.from(m[1], 'hex').toString('latin1') : m[2];
        if (line) out += line + '\n';
      }
      i = en + 9;
    }
    return out.replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z(?=\s+\S\s+Page)/g, '<GENERATED>');
  };

  test('H131-AT-IT-01  string BIGINT timestamps: valid PDF, twice, correct values, no write-after-end, server keeps serving', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, { artifact_timestamp_ms: PG_TS, artifact_expiry_ms: PG_EX }));
    const app = makeAdminApp();
    for (let i = 0; i < 2; i++) {
      const res = await request(app).get(`/v1/attestation/${id}/export?format=pdf`).buffer(true).parse(binary);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.body.slice(0, 5).toString('latin1')).toBe('%PDF-');
      expect(res.body.slice(-8).toString('latin1')).toContain('%%EOF');
      const text = pdfText(res.body);
      expect(text).toContain('Timestamp:      2026-09-21T14:13:20.000Z');
      expect(text).toContain('Expiry:         2026-09-21T14:23:20.000Z');
      await settle();
      const health = await request(app).get(`/v1/attestation/${id}/export`);
      expect(health.status).toBe(200);
    }
    expect(lateWrites).toBe(0);
  });

  test('H131-AT-IT-02  output unchanged: string, number and Date inputs render identical page text', async () => {
    const id = randomUUID();
    const base = makeSampleRecord(id, { generated_at: new Date('2026-09-25T00:00:00.000Z') });
    const render = async (ts, ex) => {
      mockGetByAttestationId.mockResolvedValue({ ...base, artifact_timestamp_ms: ts, artifact_expiry_ms: ex });
      const res = await request(makeAdminApp()).get(`/v1/attestation/${id}/export?format=pdf`).buffer(true).parse(binary);
      expect(res.status).toBe(200);
      return pdfText(res.body);
    };
    const asNumber = await render(Number(PG_TS), Number(PG_EX));
    expect(await render(PG_TS, PG_EX)).toBe(asNumber);
    expect(await render(new Date(Number(PG_TS)), new Date(Number(PG_EX)))).toBe(asNumber);
    expect(await render(null, null)).toContain('Timestamp:      N/A');
  });

  test('H131-AT-IT-03  malformed timestamp: controlled, sanitized 500 JSON — no PDF bytes, no stack, no write-after-end; next request succeeds', async () => {
    const id = randomUUID();
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, { artifact_expiry_ms: 'not-a-timestamp' }));
    const app = makeAdminApp();
    for (let i = 0; i < 2; i++) {
      const res = await request(app).get(`/v1/attestation/${id}/export?format=pdf`);
      expect(res.status).toBe(500);
      expect(res.headers['content-type']).toMatch(/^application\/json/);
      expect(res.headers['content-disposition']).toBeUndefined();
      expect(res.body.error.code).toBe('INTERNAL_ERROR');
      expect(res.body.error.message).toBe('An unexpected error occurred');
      expect(res.text).not.toMatch(/RangeError|stack|epoch|at _stream|\.js:\d+/);
      await settle();
    }
    expect(lateWrites).toBe(0);
    mockGetByAttestationId.mockResolvedValue(makeSampleRecord(id, { artifact_timestamp_ms: PG_TS, artifact_expiry_ms: PG_EX }));
    const ok = await request(app).get(`/v1/attestation/${id}/export?format=pdf`).buffer(true).parse(binary);
    expect(ok.status).toBe(200);
    expect(ok.body.slice(0, 5).toString('latin1')).toBe('%PDF-');
  });
});
