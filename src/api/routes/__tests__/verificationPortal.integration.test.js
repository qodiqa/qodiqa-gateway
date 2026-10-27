'use strict';

/**
 * Public Verification Portal — Integration & End-to-End Tests (Component #23)
 *
 * Tests real route execution against mocked external dependencies (DB,
 * transparency log, evidence chain).  The core verification logic in portal.js
 * and validateArtifact() run unmodified.
 *
 * VP-IT-01…VP-IT-08   POST /portal/verify — successful verification
 * VP-IT-09…VP-IT-14   POST /portal/verify — failed verification (tampered sig)
 * VP-IT-15…VP-IT-19   POST /portal/verify — replay detection (VERIFIED_WITH_WARNINGS)
 * VP-IT-20…VP-IT-23   GET  /portal/result/:id — result retrieval
 * VP-IT-24…VP-IT-28   GET  /portal/report/:id — JSON report download
 * VP-IT-29…VP-IT-32   GET  /portal/report/:id?format=pdf — PDF report download
 * VP-IT-33…VP-IT-37 GET /portal/evidence/:id — evidence package download (internal
 *                      audit data — RBAC READ_VERIFICATION_PORTAL; fetched as an auditor)
 * H130-VP-IT-01…H130-VP-IT-09 public/internal IP disclosure boundary (internal
 *                      audit data — RBAC READ_VERIFICATION_PORTAL; fetched as an auditor)
 * H130-VP-IT-01…10 public/internal IP disclosure boundary
 * VP-IT-38…VP-IT-45   E2E Scenario A: valid artifact → full workflow
 * VP-IT-46…VP-IT-52   E2E Scenario B: tampered artifact → FAILED + audit
 * VP-IT-53…VP-IT-60   E2E Scenario C: replay submission → VERIFIED_WITH_WARNINGS
 */

// ── Mocks (must precede all requires) ─────────────────────────────────────────

const mockQuery     = jest.fn();
const mockPool = {
  _enabled: true,
  isEnabled: function () { return this._enabled; },
  query:     mockQuery,
};
jest.mock('../../../infra/postgres/pool', () => mockPool);

const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({
  register: mockRegister,
}));

const mockGetByArtifactId = jest.fn();
jest.mock('../../../core/evidence/chainStore', () => ({
  getByArtifactId: mockGetByArtifactId,
}));

const mockRecordVerification  = jest.fn();
const mockGetByVerificationId = jest.fn();
const mockGetByFingerprint    = jest.fn();
jest.mock('../../../core/verification/portalStore', () => ({
  recordVerification:  mockRecordVerification,
  getByVerificationId: mockGetByVerificationId,
  getByFingerprint:    mockGetByFingerprint,
  listVerifications:   jest.fn(),
  aggregateStats:      jest.fn(),
}));

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({
  emit:                mockEmit,
  allowed:             jest.fn(),
  blocked:             jest.fn(),
  eventBus:            { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

jest.mock('../../../observability/metrics', () => ({
  portalVerificationsTotal:       { inc: jest.fn() },
  portalVerificationFailuresTotal: { inc: jest.fn() },
  portalPersistFailuresTotal:     { inc: jest.fn() },
}));

// ── Module imports (after mocks) ──────────────────────────────────────────────

const request  = require('supertest');
const express  = require('express');
const { randomUUID } = require('crypto');

const { createVerificationPortalPublicRouter, createVerificationPortalAdminRouter } = require('../verificationPortal');
const { createRequirePermission } = require('../../../middleware/rbac');
const roles             = require('../../../core/rbac/roles');
const { getActiveKey }  = require('../../../../services/artifact/keyStore');
const { signArtifact }  = require('../../../validation/signArtifact');
const metrics           = require('../../../observability/metrics');

// ── Fixtures ──────────────────────────────────────────────────────────────────

let KEY;

beforeAll(() => {
  KEY = getActiveKey('default');
});

beforeEach(() => {
  jest.clearAllMocks();
  mockPool._enabled = true;

  // Default: no prior record (no replay); artifact found in evidence chain
  mockGetByFingerprint.mockResolvedValue(null);
  mockGetByArtifactId.mockResolvedValue({ id: 'ev-record-001', artifact_id: 'art-001' });

  // Default: transparency registration succeeds
  mockRegister.mockResolvedValue({ transparencyId: 'trans-uuid-001' });

  // Default: recordVerification returns a stub row
  mockRecordVerification.mockResolvedValue({ verification_id: 'stub-id' });

  // Default: getByVerificationId returns null (callers override per test)
  mockGetByVerificationId.mockResolvedValue(null);
});

// mirrors src/app.js — at both /portal and /v1/portal, the public router,
// then the admin router behind the admin stack. Authentication (opsAuth +
// rbacResolve) is stood in by a header carrying the operator role; authorization
// is the REAL rbac.createRequirePermission over the REAL roles table.
const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
function testOperatorAuth(req, res, next) {
  const role = req.headers['x-test-operator-role'];
  if (!role) return res.status(401).json({ error: { code: 'UNAUTHORIZED' } });
  req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role, enabled: true });
  return next();
}
const AUDITOR = { 'x-test-operator-role': roles.ROLES.AUDITOR };

// (D7 → B): public verifications persist only for an authenticated caller
// holding the write permission (optionalAuth → ctx.adminStack(...) in src/app.js).
// These suites test the PERSISTED flow, so the stand-in resolves an operator the
// way that stack would; the anonymous, ephemeral flow has its own tests
// (src/api/routes/__tests__/publicVerifyEphemeral.test.js).
const AUTHED = Object.freeze({ optionalAuth: (req, _res, next) => {
  req.rbacUser = req.rbacUser || Object.freeze({ id: 'op-1', username: 'op', role: 'admin', enabled: true });
  next();
} });

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  const pub = createVerificationPortalPublicRouter(AUTHED);
  const adm = createVerificationPortalAdminRouter({ requirePermission });
  for (const base of ['/portal', '/v1/portal']) {
    app.use(base, pub);
    app.use(base, testOperatorAuth, adm);
  }
  return app;
}

function makeValidArtifact(payloadOverrides = {}) {
  const now    = Date.now();
  const expiry = now + 60_000;
  return signArtifact(
    {
      payload:     { action: 'test', requestId: randomUUID(), ...payloadOverrides },
      timestamp:   now,
      expiry,
      publicKeyId: KEY.keyId,
    },
    KEY.privDer,
  );
}

function makeStoredRecord(verificationId, overrides = {}) {
  return {
    verification_id:       verificationId,
    artifact_fingerprint:  'a'.repeat(64),
    artifact_public_key_id: KEY.keyId,
    artifact_timestamp_ms:  Date.now(),
    artifact_expiry_ms:     Date.now() + 60_000,
    artifact_id:           'art-001',
    overall_result:        'VERIFIED',
    checks_performed:      [{ check: 'SCHEMA', result: 'PASS' }],
    failed_check:          null,
    failure_reason:        null,
    warnings:              [],
    transparency_id:       'trans-uuid-001',
    submitted_by:          'public',
    submission_ip:         '127.0.0.1',
    duration_ms:           12,
    // twin: a real `TIMESTAMPTZ` column comes back from the pg driver
    // as a native Date, not a string — `.toISOString()` here would silently
    // mask exactly the bug this fixture needs to catch (see the
    // VP-IT-33…37 block's regression tests below).
    verified_at:           new Date(),
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-01…VP-IT-08  POST /portal/verify — successful verification
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-01…VP-IT-08  POST /portal/verify — successful verification', () => {
  test('VP-IT-01  returns 200 with VERIFIED result for a valid signed artifact', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.overallResult).toBe('VERIFIED');
  });

  test('VP-IT-02  response includes verificationId (UUID)', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    expect(res.body.data.verificationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  test('VP-IT-03  response includes checks array with all 8 checks', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    const checkNames = res.body.data.checks.map(c => c.check);
    expect(checkNames).toEqual([
      'SCHEMA', 'KEY_VALID', 'TIMESTAMP', 'NOT_EXPIRED',
      'SIGNATURE', 'CLOCK_SKEW', 'REPLAY_CHECK', 'EVIDENCE_CHAIN',
    ]);
  });

  test('VP-IT-04  all core checks are PASS for a valid artifact', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    const coreChecks = res.body.data.checks.filter(c =>
      ['SCHEMA', 'KEY_VALID', 'TIMESTAMP', 'NOT_EXPIRED', 'SIGNATURE', 'CLOCK_SKEW'].includes(c.check),
    );
    expect(coreChecks.every(c => c.result === 'PASS')).toBe(true);
  });

  test('VP-IT-05  transparency log is registered before persistence', async () => {
    const callOrder = [];
    mockRegister.mockImplementation(async () => {
      callOrder.push('register');
      return { transparencyId: 'trans-abc' };
    });
    mockRecordVerification.mockImplementation(async () => {
      callOrder.push('persist');
      return { verification_id: 'stub' };
    });

    const artifact = makeValidArtifact();
    await request(makeApp()).post('/portal/verify').send(artifact);

    // Give the fire-and-forget persist a tick to fire
    await new Promise(r => setImmediate(r));

    expect(callOrder[0]).toBe('register');
    expect(callOrder[1]).toBe('persist');
  });

  test('VP-IT-06  transparencyId from registrar is passed to recordVerification', async () => {
    mockRegister.mockResolvedValue({ transparencyId: 'confirmed-trans-id' });

    const artifact = makeValidArtifact();
    await request(makeApp()).post('/portal/verify').send(artifact);
    await new Promise(r => setImmediate(r));

    expect(mockRecordVerification).toHaveBeenCalledWith(
      expect.objectContaining({ transparencyId: 'confirmed-trans-id' }),
    );
  });

  test('VP-IT-07  durationMs is present and numeric in response', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    expect(typeof res.body.data.durationMs).toBe('number');
    expect(res.body.data.durationMs).toBeGreaterThanOrEqual(0);
  });

  test('VP-IT-08  warnings array is empty for a clean verification', async () => {
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    expect(res.body.data.warnings).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-09…VP-IT-14  POST /portal/verify — failed verification
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-09…VP-IT-14  POST /portal/verify — failed verification', () => {
  function makeTamperedArtifact() {
    const art = makeValidArtifact();
    // Corrupt the signature — still valid base64 length but wrong bytes
    const badSig = Buffer.from('x'.repeat(64)).toString('base64');
    return { ...art, signature: badSig };
  }

  test('VP-IT-09  returns 200 with FAILED result for invalid signature', async () => {
    const res = await request(makeApp()).post('/portal/verify').send(makeTamperedArtifact());
    expect(res.status).toBe(200);
    expect(res.body.data.overallResult).toBe('FAILED');
  });

  test('VP-IT-10  failedCheck is SIGNATURE for tampered artifact', async () => {
    const res = await request(makeApp()).post('/portal/verify').send(makeTamperedArtifact());
    expect(res.body.data.failedCheck).toBe('SIGNATURE');
  });

  test('VP-IT-11  SIGNATURE check result is FAIL', async () => {
    const res = await request(makeApp()).post('/portal/verify').send(makeTamperedArtifact());
    const sigCheck = res.body.data.checks.find(c => c.check === 'SIGNATURE');
    expect(sigCheck.result).toBe('FAIL');
  });

  test('VP-IT-12  checks after SIGNATURE are SKIP', async () => {
    const res = await request(makeApp()).post('/portal/verify').send(makeTamperedArtifact());
    const afterSig = res.body.data.checks.filter(c =>
      ['CLOCK_SKEW', 'REPLAY_CHECK', 'EVIDENCE_CHAIN'].includes(c.check),
    );
    expect(afterSig.every(c => c.result === 'SKIP')).toBe(true);
  });

  test('VP-IT-13  audit event PORTAL_VERIFICATION_COMPLETE is emitted with FAILED', async () => {
    await request(makeApp()).post('/portal/verify').send(makeTamperedArtifact());
    expect(mockEmit).toHaveBeenCalledWith(
      'INFO', 'PORTAL_VERIFICATION_COMPLETE',
      expect.objectContaining({ overallResult: 'FAILED', failedCheck: 'SIGNATURE' }),
    );
  });

  test('VP-IT-14  portalVerificationFailuresTotal metric is incremented', async () => {
    await request(makeApp()).post('/portal/verify').send(makeTamperedArtifact());
    expect(metrics.portalVerificationFailuresTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ failed_check: 'SIGNATURE' }),
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-15…VP-IT-19  POST /portal/verify — replay detection
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-15…VP-IT-19  POST /portal/verify — replay detection', () => {
  test('VP-IT-15  REPLAY_CHECK is WARN when fingerprint was seen before', async () => {
    mockGetByFingerprint.mockResolvedValue({
      verification_id: randomUUID(),
      overall_result:  'VERIFIED',
      verified_at:     new Date().toISOString(),
    });

    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    expect(res.status).toBe(200);

    const replayCheck = res.body.data.checks.find(c => c.check === 'REPLAY_CHECK');
    expect(replayCheck.result).toBe('WARN');
  });

  test('VP-IT-16  overall result is VERIFIED_WITH_WARNINGS on replay', async () => {
    mockGetByFingerprint.mockResolvedValue({ verification_id: randomUUID() });
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    expect(res.body.data.overallResult).toBe('VERIFIED_WITH_WARNINGS');
  });

  test('VP-IT-17  warnings array contains REPLAY_CHECK entry', async () => {
    mockGetByFingerprint.mockResolvedValue({ verification_id: randomUUID() });
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    const replayWarn = res.body.data.warnings.find(w => w.check === 'REPLAY_CHECK');
    expect(replayWarn).toBeDefined();
    expect(replayWarn.reason).toMatch(/previously submitted/i);
  });

  test('VP-IT-18  REPLAY_CHECK is PASS when fingerprint is new', async () => {
    mockGetByFingerprint.mockResolvedValue(null);
    const artifact = makeValidArtifact();
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    const replayCheck = res.body.data.checks.find(c => c.check === 'REPLAY_CHECK');
    expect(replayCheck.result).toBe('PASS');
  });

  test('VP-IT-19  EVIDENCE_CHAIN is WARN when artifact not in chain', async () => {
    mockGetByArtifactId.mockResolvedValue(null); // override: artifact NOT in chain
    const artifact = makeValidArtifact({ artifactId: 'unknown-art-id' });
    const res = await request(makeApp()).post('/portal/verify').send(artifact);
    const ecCheck = res.body.data.checks.find(c => c.check === 'EVIDENCE_CHAIN');
    expect(ecCheck.result).toBe('WARN');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-20…VP-IT-23  GET /portal/result/:id
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-20…VP-IT-23  GET /portal/result/:id', () => {
  test('VP-IT-20  returns 200 with verification record when found', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));

    const res = await request(makeApp()).get(`/portal/result/${vid}`);
    expect(res.status).toBe(200);
    expect(res.body.data.verification.verification_id).toBe(vid);
  });

  test('VP-IT-21  returns 404 when verification not found', async () => {
    mockGetByVerificationId.mockResolvedValue(null);
    const res = await request(makeApp()).get(`/portal/result/${randomUUID()}`);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('VP-IT-22  returns 400 for invalid UUID', async () => {
    const res = await request(makeApp()).get('/portal/result/not-a-uuid');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });

  test('VP-IT-23  pgPool not queried when id is invalid', async () => {
    await request(makeApp()).get('/portal/result/bad-id');
    expect(mockGetByVerificationId).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-24…VP-IT-28  GET /portal/report/:id — JSON
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-24…VP-IT-28  GET /portal/report/:id — JSON', () => {
  test('VP-IT-24  returns 200 with JSON report', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp()).get(`/portal/report/${vid}`);
    expect(res.status).toBe(200);
    expect(res.body.data.report).toBeDefined();
  });

  test('VP-IT-25  report contains verificationId and overallResult', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { overall_result: 'VERIFIED' }));
    const res = await request(makeApp()).get(`/portal/report/${vid}`);
    expect(res.body.data.report.verificationId).toBe(vid);
    expect(res.body.data.report.overallResult).toBe('VERIFIED');
  });

  test('VP-IT-26  report contains checks and warnings arrays', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp()).get(`/portal/report/${vid}`);
    expect(Array.isArray(res.body.data.report.checksPerformed)).toBe(true);
    expect(Array.isArray(res.body.data.report.warnings)).toBe(true);
  });

  test('VP-IT-27  returns 404 when report record not found', async () => {
    mockGetByVerificationId.mockResolvedValue(null);
    const res = await request(makeApp()).get(`/portal/report/${randomUUID()}`);
    expect(res.status).toBe(404);
  });

  test('VP-IT-28  returns 400 for invalid UUID', async () => {
    const res = await request(makeApp()).get('/portal/report/not-a-uuid');
    expect(res.status).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-29…VP-IT-32  GET /portal/report/:id?format=pdf
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-29…VP-IT-32  GET /portal/report/:id?format=pdf', () => {
  test('VP-IT-29  returns 200 with application/pdf content-type', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp()).get(`/portal/report/${vid}?format=pdf`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/pdf/);
  }, 10_000);

  test('VP-IT-30  PDF has Content-Disposition attachment header', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp()).get(`/portal/report/${vid}?format=pdf`);
    expect(res.headers['content-disposition']).toMatch(/attachment/);
    expect(res.headers['content-disposition']).toMatch(new RegExp(vid));
  }, 10_000);

  test('VP-IT-31  PDF response starts with %PDF magic bytes', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp())
      .get(`/portal/report/${vid}?format=pdf`)
      .buffer(true)
      .parse((res, callback) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      });
    expect(res.body.slice(0, 4).toString()).toBe('%PDF');
  }, 10_000);

  test('VP-IT-32  PDF returns 404 when record not found', async () => {
    mockGetByVerificationId.mockResolvedValue(null);
    const res = await request(makeApp()).get(`/portal/report/${randomUUID()}?format=pdf`);
    expect(res.status).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-33…VP-IT-37  GET /portal/evidence/:id
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-33…VP-IT-37  GET /portal/evidence/:id', () => {
  test('VP-IT-33  returns 200 with evidence package', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set(AUDITOR);
    expect(res.status).toBe(200);
    expect(res.body.data.evidencePackage).toBeDefined();
  });

  test('VP-IT-34  evidence package has packageType QODIQA::PORTAL_EVIDENCE::V1', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set(AUDITOR);
    expect(res.body.data.evidencePackage.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
  });

  test('VP-IT-35  evidence package contains verificationId and overallResult', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { overall_result: 'FAILED' }));
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set(AUDITOR);
    expect(res.body.data.evidencePackage.verificationId).toBe(vid);
    expect(res.body.data.evidencePackage.overallResult).toBe('FAILED');
  });

  test('VP-IT-36  evidence package includes a 64-char hex packageHash', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid));
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set(AUDITOR);
    expect(res.body.data.evidencePackage.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('VP-IT-37  returns 404 when evidence record not found', async () => {
    mockGetByVerificationId.mockResolvedValue(null);
    const res = await request(makeApp()).get(`/portal/evidence/${randomUUID()}`).set(AUDITOR);
    expect(res.status).toBe(404);
  });

  // twin: the identical uncaught 500 as
  // src/api/routes/attestation.js's own /:id/evidence route — "stableStringify:
  // cannot serialize a non-plain-object value (Date)" — because `verified_at`
  // (a real TIMESTAMPTZ column, a native Date via the pg driver, not the
  // string the old fixture used) reached canonicalHash() unconverted.
  // Reproduced live against a real server before fixing; see
  //.

  test('VP-IT-33a a null-artifact_id verification returns 200, not 500', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { artifact_id: null }));
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set(AUDITOR);
    expect(res.status).toBe(200);
    expect(res.body.data.evidencePackage.artifactId).toBeNull();
  });

  test('VP-IT-33b the verified_at Date is serialized as an ISO string, no crash regardless of artifact_id', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { artifact_id: 'art-002' }));
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set(AUDITOR);
    expect(res.status).toBe(200);
    expect(res.body.data.evidencePackage.artifactId).toBe('art-002');
    expect(typeof res.body.data.evidencePackage.verifiedAt).toBe('string');
    expect(res.body.data.evidencePackage.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-38…VP-IT-45  E2E Scenario A: valid artifact → full workflow
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-38…VP-IT-45  E2E Scenario A: valid artifact → full workflow', () => {
  let app;
  let verificationId;
  let storedRecord;
  // Captured during beforeAll before jest.clearAllMocks() can erase them
  let capturedRegisterArgs;
  let capturedPersistArgs;

  beforeAll(async () => {
    // Reset mocks fresh for this scenario (outer beforeEach hasn't run yet)
    jest.clearAllMocks();
    mockGetByFingerprint.mockResolvedValue(null);
    mockGetByArtifactId.mockResolvedValue({ id: 'ev-001' });
    mockRegister.mockImplementation(async args => {
      capturedRegisterArgs = args;
      return { transparencyId: 'trans-uuid-001' };
    });
    mockRecordVerification.mockImplementation(async args => {
      capturedPersistArgs = args;
      return { verification_id: 'stub' };
    });

    app = makeApp();
    const artifact = makeValidArtifact();

    const res = await request(app).post('/portal/verify').send(artifact);
    expect(res.status).toBe(200);
    verificationId = res.body.data.verificationId;

    // Wait for fire-and-forget persistence to settle
    await new Promise(r => setImmediate(r));

    storedRecord = makeStoredRecord(verificationId, {
      overall_result:   res.body.data.overallResult,
      checks_performed: res.body.data.checks,
      warnings:         res.body.data.warnings,
      failed_check:     res.body.data.failedCheck,
      failure_reason:   res.body.data.failureReason,
      transparency_id:  'trans-uuid-001',
    });
  });

  // Re-apply getByVerificationId after outer beforeEach clears all mocks
  beforeEach(() => {
    if (storedRecord) mockGetByVerificationId.mockResolvedValue(storedRecord);
  });

  test('VP-IT-38  Scenario A: verification returns VERIFIED', () => {
    expect(storedRecord.overall_result).toBe('VERIFIED');
  });

  test('VP-IT-39  Scenario A: transparency log was registered', () => {
    expect(capturedRegisterArgs).toEqual(expect.objectContaining({
      entryType:    'VERIFICATION',
      registeredBy: 'portal',
    }));
  });

  test('VP-IT-40  Scenario A: persistence received the resolved transparencyId', () => {
    expect(capturedPersistArgs).toEqual(expect.objectContaining({
      verificationId,
      transparencyId: 'trans-uuid-001',
      overallResult:  'VERIFIED',
    }));
  });

  test('VP-IT-41  Scenario A: GET /result/:id returns the stored record', async () => {
    const res = await request(app).get(`/portal/result/${verificationId}`);
    expect(res.status).toBe(200);
    expect(res.body.data.verification.verification_id).toBe(verificationId);
  });

  test('VP-IT-42  Scenario A: GET /evidence/:id returns a valid evidence package', async () => {
    const res = await request(app).get(`/portal/evidence/${verificationId}`).set(AUDITOR);
    expect(res.status).toBe(200);
    const pkg = res.body.data.evidencePackage;
    expect(pkg.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
    expect(pkg.verificationId).toBe(verificationId);
    expect(pkg.overallResult).toBe('VERIFIED');
    expect(pkg.transparencyId).toBe('trans-uuid-001');
  });

  test('VP-IT-43  Scenario A: evidence package packageHash is a valid SHA-256', async () => {
    const res = await request(app).get(`/portal/evidence/${verificationId}`).set(AUDITOR);
    expect(res.body.data.evidencePackage.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('VP-IT-44  Scenario A: GET /report/:id returns the structured report', async () => {
    const res = await request(app).get(`/portal/report/${verificationId}`);
    expect(res.status).toBe(200);
    expect(res.body.data.report.verificationId).toBe(verificationId);
    expect(res.body.data.report.overallResult).toBe('VERIFIED');
  });

  test('VP-IT-45  Scenario A: GET /report/:id?format=pdf returns a PDF', async () => {
    const res = await request(app).get(`/portal/report/${verificationId}?format=pdf`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/pdf/);
  }, 10_000);
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-46…VP-IT-52  E2E Scenario B: tampered artifact → FAILED + audit
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-46…VP-IT-52  E2E Scenario B: tampered artifact → FAILED + audit', () => {
  let result;
  let capturedEmitCalls;
  let capturedRegisterArgs;
  let capturedMetricInc;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockGetByFingerprint.mockResolvedValue(null);
    mockGetByArtifactId.mockResolvedValue({ id: 'ev-001' });
    mockRegister.mockImplementation(async args => {
      capturedRegisterArgs = args;
      return { transparencyId: 'trans-b' };
    });
    mockRecordVerification.mockResolvedValue({ verification_id: 'stub' });

    const app      = makeApp();
    const artifact = makeValidArtifact();
    const tampered = {
      ...artifact,
      signature: Buffer.from('tampered'.padEnd(64, 'x')).toString('base64'),
    };

    const res = await request(app).post('/portal/verify').send(tampered);
    result = res.body.data;

    // Capture emitted events and metrics before clearAllMocks fires
    capturedEmitCalls  = mockEmit.mock.calls.slice();
    capturedMetricInc  = metrics.portalVerificationFailuresTotal.inc.mock.calls.slice();
  });

  test('VP-IT-46  Scenario B: overall result is FAILED', () => {
    expect(result.overallResult).toBe('FAILED');
  });

  test('VP-IT-47  Scenario B: failedCheck is SIGNATURE', () => {
    expect(result.failedCheck).toBe('SIGNATURE');
  });

  test('VP-IT-48  Scenario B: SIGNATURE check result is FAIL', () => {
    const sig = result.checks.find(c => c.check === 'SIGNATURE');
    expect(sig.result).toBe('FAIL');
  });

  test('VP-IT-49  Scenario B: advisory checks are SKIP', () => {
    const advisory = result.checks.filter(c =>
      ['REPLAY_CHECK', 'EVIDENCE_CHAIN'].includes(c.check),
    );
    expect(advisory.every(c => c.result === 'SKIP')).toBe(true);
  });

  test('VP-IT-50  Scenario B: PORTAL_VERIFICATION_COMPLETE audit event is emitted', () => {
    const hit = capturedEmitCalls.find(
      c => c[1] === 'PORTAL_VERIFICATION_COMPLETE' && c[2]?.overallResult === 'FAILED',
    );
    expect(hit).toBeDefined();
  });

  test('VP-IT-51  Scenario B: failure metric is incremented with SIGNATURE', () => {
    const hit = capturedMetricInc.find(c => c[0]?.failed_check === 'SIGNATURE');
    expect(hit).toBeDefined();
  });

  test('VP-IT-52  Scenario B: transparency is still registered even for failures', () => {
    expect(capturedRegisterArgs).toEqual(expect.objectContaining({
      entryType: 'VERIFICATION',
      payload:   expect.objectContaining({ overallResult: 'FAILED' }),
    }));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// VP-IT-53…VP-IT-60  E2E Scenario C: replay → VERIFIED_WITH_WARNINGS
// ─────────────────────────────────────────────────────────────────────────────

describe('VP-IT-53…VP-IT-60  E2E Scenario C: replay → VERIFIED_WITH_WARNINGS', () => {
  let firstResult;
  let replayResult;
  let capturedRegisterCount;
  let capturedCompleteEvents;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockGetByArtifactId.mockResolvedValue({ id: 'ev-001' });
    mockRegister.mockResolvedValue({ transparencyId: 'trans-c' });
    mockRecordVerification.mockResolvedValue({ verification_id: 'stub' });

    const app      = makeApp();
    const artifact = makeValidArtifact();

    // First submission: fingerprint not seen
    mockGetByFingerprint.mockResolvedValueOnce(null);
    const first = await request(app).post('/portal/verify').send(artifact);
    firstResult = first.body.data;

    // Second submission (replay): fingerprint was seen
    mockGetByFingerprint.mockResolvedValueOnce({
      verification_id: firstResult.verificationId,
      overall_result:  'VERIFIED',
      verified_at:     new Date().toISOString(),
    });
    const replay = await request(app).post('/portal/verify').send(artifact);
    replayResult = replay.body.data;

    capturedRegisterCount  = mockRegister.mock.calls.length;
    capturedCompleteEvents = mockEmit.mock.calls
      .filter(c => c[1] === 'PORTAL_VERIFICATION_COMPLETE')
      .map(c => c[2]);
  });

  test('VP-IT-53  Scenario C: first submission result is VERIFIED', () => {
    expect(firstResult.overallResult).toBe('VERIFIED');
  });

  test('VP-IT-54  Scenario C: replay submission result is VERIFIED_WITH_WARNINGS', () => {
    expect(replayResult.overallResult).toBe('VERIFIED_WITH_WARNINGS');
  });

  test('VP-IT-55  Scenario C: replay REPLAY_CHECK result is WARN', () => {
    const rc = replayResult.checks.find(c => c.check === 'REPLAY_CHECK');
    expect(rc.result).toBe('WARN');
  });

  test('VP-IT-56  Scenario C: replay warnings array contains REPLAY_CHECK', () => {
    expect(replayResult.warnings.some(w => w.check === 'REPLAY_CHECK')).toBe(true);
  });

  test('VP-IT-57  Scenario C: first submission REPLAY_CHECK is PASS', () => {
    const rc = firstResult.checks.find(c => c.check === 'REPLAY_CHECK');
    expect(rc.result).toBe('PASS');
  });

  test('VP-IT-58  Scenario C: two verificationIds are distinct', () => {
    expect(firstResult.verificationId).not.toBe(replayResult.verificationId);
  });

  test('VP-IT-59  Scenario C: both submissions called registrar.register', () => {
    expect(capturedRegisterCount).toBe(2);
  });

  test('VP-IT-60  Scenario C: audit events reflect both VERIFIED and VERIFIED_WITH_WARNINGS', () => {
    expect(capturedCompleteEvents.length).toBe(2);
    const results = capturedCompleteEvents.map(e => e.overallResult);
    expect(results).toContain('VERIFIED');
    expect(results).toContain('VERIFIED_WITH_WARNINGS');
  });
});

// ── the evidence lookup is keyed on the signed payload.requestId ────────
// Reproduced live before the fix: an unexecuted artifact embedding another
// execution's id as payload.artifactId was reported VERIFIED (and ATTESTED
// with that execution's evidence), while a genuine executed artifact was
// never found. The ledger only matches the artifact's OWN requestId.
describe('VP-IT-H126  POST /portal/verify — evidence correlation key', () => {
  test('VP-IT-H126-01  queries by the artifact\'s own payload.requestId, never a claimed payload.artifactId', async () => {
    const ownId = randomUUID();
    const victimId = randomUUID();
    mockGetByArtifactId.mockImplementation(async (id) => (id === victimId ? { id: 'ev-victim', artifact_id: victimId } : null));
    const res = await request(makeApp()).post('/portal/verify').send(makeValidArtifact({ requestId: ownId, artifactId: victimId }));
    expect(mockGetByArtifactId).toHaveBeenCalledWith(ownId);
    expect(mockGetByArtifactId).not.toHaveBeenCalledWith(victimId);
    expect(res.body.data.checks.find(c => c.check === 'EVIDENCE_CHAIN').result).toBe('WARN');
    expect(res.body.data.overallResult).toBe('VERIFIED_WITH_WARNINGS');
  });

  test('VP-IT-H126-02  a genuine artifact whose own requestId is in the ledger verifies cleanly', async () => {
    const ownId = randomUUID();
    mockGetByArtifactId.mockImplementation(async (id) => (id === ownId ? { id: 'ev-own', artifact_id: ownId } : null));
    const res = await request(makeApp()).post('/portal/verify').send(makeValidArtifact({ requestId: ownId }));
    expect(res.body.data.checks.find(c => c.check === 'EVIDENCE_CHAIN').result).toBe('PASS');
    expect(res.body.data.overallResult).toBe('VERIFIED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// H130-VP-IT-01…H130-VP-IT-09: the
// submitter address is INTERNAL AUDIT DATA. It is persisted and served to
// READ_VERIFICATION_PORTAL operators, never in a public response; the V1
// evidence package (and its hash) is unchanged but is no longer anonymous.
// ─────────────────────────────────────────────────────────────────────────────

const H130_IP   = '203.0.113.10'; // RFC 5737 TEST-NET-3 — synthetic, never a real address
const UNRELATED = { Authorization: 'Bearer sk_h130_unrelated_tenant_credential' };

describe('H130-VP-IT  submitter address: internal audit data, never public', () => {
  const portal = require('../../../core/verification/portal');
  const portalStoreMock = require('../../../core/verification/portalStore');
  const { canonicalHash } = require('../../../../services/utils/evidencePackage');

  test('H130-VP-IT-01  public GET /result/:id (both mounts) omits submission_ip; the rest of the row is intact', async () => {
    const vid = randomUUID();
    const rec = makeStoredRecord(vid, { submission_ip: H130_IP });
    mockGetByVerificationId.mockResolvedValue(rec);
    for (const base of ['/portal', '/v1/portal']) {
      const res = await request(makeApp()).get(`${base}/result/${vid}`);
      expect(res.status).toBe(200);
      const v = res.body.data.verification;
      expect(v).not.toHaveProperty('submission_ip');
      expect(v.verification_id).toBe(vid);
      expect(v.submitted_by).toBe('public');
      expect(v.overall_result).toBe(rec.overall_result);
      expect(res.text).not.toContain(H130_IP);
    }
  });

  test('H130-VP-IT-02  GET /evidence/:id (both mounts) is not served anonymously — 401, no package, no address', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { submission_ip: H130_IP }));
    for (const base of ['/portal', '/v1/portal']) {
      const res = await request(makeApp()).get(`${base}/evidence/${vid}`);
      expect(res.status).toBe(401);
      expect(res.text).not.toContain(H130_IP);
      expect(res.text).not.toContain('evidencePackage');
    }
    expect(mockGetByVerificationId).not.toHaveBeenCalled();
  });

  test('H130-VP-IT-03  cross-tenant behaviour unchanged: an unrelated credential gets the identical public view, and no package', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { submission_ip: H130_IP }));
    const anon  = await request(makeApp()).get(`/v1/portal/result/${vid}`);
    const other = await request(makeApp()).get(`/v1/portal/result/${vid}`).set(UNRELATED);
    expect(other.status).toBe(200);
    expect(other.body.data).toEqual(anon.body.data);
    expect(other.text).not.toContain(H130_IP);
    const ev = await request(makeApp()).get(`/v1/portal/evidence/${vid}`).set(UNRELATED);
    expect(ev.status).toBe(401);
    expect(ev.text).not.toContain(H130_IP);
  });

  test('H130-VP-IT-04  an operator role without READ_VERIFICATION_PORTAL is refused the package (403)', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { submission_ip: H130_IP }));
    expect(roles.PERMISSIONS.READ_VERIFICATION_PORTAL).not.toContain(roles.ROLES.VIEWER);
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set({ 'x-test-operator-role': roles.ROLES.VIEWER });
    expect(res.status).toBe(403);
    expect(res.text).not.toContain(H130_IP);
  });

  test('H130-VP-IT-05  internal audit view: every READ_VERIFICATION_PORTAL role receives the package WITH the address', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { submission_ip: H130_IP }));
    for (const role of roles.PERMISSIONS.READ_VERIFICATION_PORTAL) {
      for (const base of ['/portal', '/v1/portal']) {
        const res = await request(makeApp()).get(`${base}/evidence/${vid}`).set({ 'x-test-operator-role': role });
        expect(res.status).toBe(200);
        expect(res.body.data.evidencePackage.submissionIp).toBe(H130_IP);
      }
    }
  });

  test('H130-VP-IT-06  the internally served package is the unchanged V1 package: same content as the shared assembler, hash recomputes', async () => {
    const vid = randomUUID();
    const rec = makeStoredRecord(vid, { submission_ip: H130_IP, verified_at: new Date('2026-09-25T00:00:00.000Z') });
    mockGetByVerificationId.mockResolvedValue(rec);
    const res = await request(makeApp()).get(`/portal/evidence/${vid}`).set(AUDITOR);
    const { packageId: _pi, generatedAt: _ga, ...got } = res.body.data.evidencePackage;
    const { packageId: _xi, generatedAt: _xa, ...exp } = portal.assembleEvidencePackageFromPortalRecord(rec);
    expect(got).toEqual(exp);
    expect(got.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
    const { packageHash, ...content } = got;
    expect(canonicalHash(content)).toBe(packageHash);
  });

  test('H130-VP-IT-07  public GET /report/:id (JSON, both mounts) carries no address', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { submission_ip: H130_IP }));
    for (const base of ['/portal', '/v1/portal']) {
      const res = await request(makeApp()).get(`${base}/report/${vid}`);
      expect(res.status).toBe(200);
      expect(res.text).not.toContain(H130_IP);
    }
  });

  test('H130-VP-IT-08  POST /verify persists the caller address internally but never returns it', async () => {
    const res = await request(makeApp()).post('/v1/portal/verify').send(makeValidArtifact());
    expect(res.status).toBe(200);
    const persisted = mockRecordVerification.mock.calls[0][0].submissionIp;
    expect(typeof persisted).toBe('string');
    expect(persisted.length).toBeGreaterThan(0);
    expect(res.text).not.toContain(persisted);
  });

  test('H130-VP-IT-09  admin history (internal audit view) still carries submission_ip; anonymous is refused', async () => {
    const rec = makeStoredRecord(randomUUID(), { submission_ip: H130_IP });
    portalStoreMock.listVerifications.mockResolvedValue({ verifications: [rec], total: 1, page: 1, pageSize: 50 });
    const anon = await request(makeApp()).get('/portal/admin/history');
    expect(anon.status).toBe(401);
    const res = await request(makeApp()).get('/portal/admin/history').set(AUDITOR);
    expect(res.status).toBe(200);
    expect(res.body.data.verifications[0].submission_ip).toBe(H130_IP);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// H131-VP-IT-01…H131-VP-IT-04 GET /portal/report/:id?format=pdf with the
// value shapes PostgreSQL actually returns (BIGINT artifact_timestamp_ms /
// artifact_expiry_ms arrive as strings). Previously: RangeError after
// doc.pipe(res) -> 500 -> pdfkit wrote into the ended response
// (ERR_STREAM_WRITE_AFTER_END) -> process exit. `lateWrites` records any write
// attempted on an already-ended response — the exact process-fatal operation.
// ─────────────────────────────────────────────────────────────────────────────

describe('H131-VP-IT  portal PDF is process-safe with PostgreSQL value shapes', () => {
  const http = require('http');
  const zlib = require('zlib');
  const PG_TS = '1790000000000'; // BIGINT as returned by the pg driver
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

  test('H131-VP-IT-01  string BIGINT timestamps: valid PDF, twice, correct values, no write-after-end, server keeps serving', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { artifact_timestamp_ms: PG_TS, artifact_expiry_ms: PG_EX }));
    const app = makeApp();
    for (let i = 0; i < 2; i++) {
      const res = await request(app).get(`/portal/report/${vid}?format=pdf`).buffer(true).parse(binary);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.body.slice(0, 5).toString('latin1')).toBe('%PDF-');
      expect(res.body.slice(-8).toString('latin1')).toContain('%%EOF');
      const text = pdfText(res.body);
      expect(text).toContain('Timestamp:      2026-09-21T14:13:20.000Z');
      expect(text).toContain('Expiry:         2026-09-21T14:23:20.000Z');
      await settle();
      const health = await request(app).get(`/portal/report/${vid}`);
      expect(health.status).toBe(200);
    }
    expect(lateWrites).toBe(0);
  });

  test('H131-VP-IT-02  output unchanged: string, number and Date inputs render identical page text', async () => {
    const vid = randomUUID();
    const base = makeStoredRecord(vid, { verified_at: new Date('2026-09-25T00:00:00.000Z') });
    const render = async (ts, ex) => {
      mockGetByVerificationId.mockResolvedValue({ ...base, artifact_timestamp_ms: ts, artifact_expiry_ms: ex });
      const res = await request(makeApp()).get(`/portal/report/${vid}?format=pdf`).buffer(true).parse(binary);
      expect(res.status).toBe(200);
      return pdfText(res.body);
    };
    const asNumber = await render(Number(PG_TS), Number(PG_EX));
    expect(await render(PG_TS, PG_EX)).toBe(asNumber);
    expect(await render(new Date(Number(PG_TS)), new Date(Number(PG_EX)))).toBe(asNumber);
    expect(await render(null, null)).toContain('Timestamp:      N/A');
  });

  test('H131-VP-IT-03  malformed timestamp: controlled, sanitized 500 JSON — no PDF bytes, no stack, no write-after-end; next request succeeds', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { artifact_timestamp_ms: 'not-a-timestamp' }));
    const app = makeApp();
    for (let i = 0; i < 2; i++) {
      const res = await request(app).get(`/portal/report/${vid}?format=pdf`);
      expect(res.status).toBe(500);
      expect(res.headers['content-type']).toMatch(/^application\/json/);
      expect(res.headers['content-disposition']).toBeUndefined();
      expect(res.body.error.code).toBe('INTERNAL_ERROR');
      expect(res.body.error.message).toBe('An unexpected error occurred');
      expect(res.text).not.toMatch(/RangeError|stack|epoch|at _stream|\.js:\d+/);
      await settle();
    }
    expect(lateWrites).toBe(0);
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { artifact_timestamp_ms: PG_TS, artifact_expiry_ms: PG_EX }));
    const ok = await request(app).get(`/portal/report/${vid}?format=pdf`).buffer(true).parse(binary);
    expect(ok.status).toBe(200);
    expect(ok.body.slice(0, 5).toString('latin1')).toBe('%PDF-');
  });

  test('H131-VP-IT-04  the /v1/portal alias behaves identically', async () => {
    const vid = randomUUID();
    mockGetByVerificationId.mockResolvedValue(makeStoredRecord(vid, { artifact_timestamp_ms: PG_TS, artifact_expiry_ms: PG_EX }));
    const res = await request(makeApp()).get(`/v1/portal/report/${vid}?format=pdf`).buffer(true).parse(binary);
    expect(res.status).toBe(200);
    expect(res.body.slice(0, 5).toString('latin1')).toBe('%PDF-');
    await settle();
    expect(lateWrites).toBe(0);
  });
});
