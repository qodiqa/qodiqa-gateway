'use strict';

/**
 * Integration + E2E tests for Component #25 — Certification Runtime API
 *
 * CI-01..CI-15  POST /v1/certification/evaluate — public endpoint
 * CI-16..CI-25  GET  /v1/certification/:certificationId — retrieve record
 * CI-26..CI-31  GET  /v1/certification/:certificationId/summary
 * CI-32..CI-40  GET  /v1/certification/admin/history
 * CI-41..CI-47  GET  /v1/certification/admin/stats
 * CI-48..CI-56  GET  /v1/certification/:certificationId/report
 * CI-57..CI-63  GET  /v1/certification/:certificationId/evidence
 * CI-64..CI-68  GET  /v1/certification/:certificationId/export
 * CI-69..CI-75  E2E Scenario A — CERTIFIED_PREMIUM (perfect submission)
 * CI-76..CI-81  E2E Scenario B — NOT_CERTIFIED (critical failure)
 * CI-82..CI-87  E2E Scenario C — CERTIFIED_PLUS range (warnings only)
 */

const express    = require('express');
const supertest  = require('supertest');

// ── Mock all external dependencies ────────────────────────────────────────────

jest.mock('../../../core/certification/evaluationEngine');
jest.mock('../../../core/certification/certificationStore');
jest.mock('../../../infra/postgres/pool', () => ({
  isEnabled: jest.fn().mockReturnValue(false),
  query:     jest.fn(),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../observability/metrics', () => ({
  certificationsTotal:              { inc: jest.fn() },
  certificationFailuresTotal:       { inc: jest.fn() },
  certificationPersistFailuresTotal:{ inc: jest.fn() },
}));

// portalStore is required deep inside attestor.verifyEvidencePackage
jest.mock('../../../core/verification/portalStore', () => ({
  getByVerificationId: jest.fn().mockResolvedValue(null),
  recordVerification:  jest.fn().mockResolvedValue({ verification_id: 'stub' }),
  listVerifications:   jest.fn().mockResolvedValue({ verifications: [], total: 0 }),
  aggregateStats:      jest.fn().mockResolvedValue(null),
}));

const evaluationEngine   = require('../../../core/certification/evaluationEngine');
const certificationStore = require('../../../core/certification/certificationStore');

const { createCertificationPublicRouter, createCertificationAdminRouter } = require('../certification');

// ── Mock function aliases ─────────────────────────────────────────────────────

const mockEvaluate                 = evaluationEngine.evaluate;
const mockAssembleCertEvidence     = evaluationEngine.assembleCertificationEvidence;
const mockGetById                  = certificationStore.getByCertificationId;
const mockListCertifications       = certificationStore.listCertifications;
const mockAggregateStats           = certificationStore.aggregateStats;

// ── App factories ─────────────────────────────────────────────────────────────

// POST /evaluate lives on the admin router (authenticated + RBAC)
//. This app mounts both routers exactly as src/app.js does — public
// first, admin second behind the admin stack — with the admin stack stood in
// by an authenticated operator, so the evaluate tests below keep exercising the
// real handler. The unauthenticated 401 is proven on the real app
//.
function makePublicApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  app.use('/v1/certification', createCertificationPublicRouter());
  app.use('/v1/certification', (req, _res, next) => {
    req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role: 'admin', enabled: true });
    next();
  }, createCertificationAdminRouter({ requirePermission: () => (_r, _s, n) => n() }));
  return app;
}

function makeAdminApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  app.use('/v1/certification', createCertificationAdminRouter({
    requirePermission: () => (_r, _s, n) => n(),
  }));
  return app;
}

// ── Canonical test data ───────────────────────────────────────────────────────

const VALID_UUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const INVALID_UUID = 'not-a-uuid';

const PERFECT_CERTIFICATION = {
  certificationId:       VALID_UUID,
  certificationLevel:    'CERTIFIED_PREMIUM',
  certificationDecision: 'CERTIFIED',
  version:               '1.0',
  generatedAt:           '2026-06-22T00:00:00.000Z',
  score:                 100,
  scoreBreakdown: {
    verificationControls: { score: 40, max: 40 },
    operationalControls:  { score: 35, max: 35 },
    complianceControls:   { score: 25, max: 25 },
    totalScore:           100,
  },
  criticalControlFailures: [],
  passedControls:          [{ control: 'artifactVerification', score: 15, max: 15, detail: 'ok' }],
  failedControls:          [],
  attestationReferences:   [{ attestationId: 'att-001', attestationDecision: 'ATTESTED' }],
  evidenceReferences:      [{ attestationId: 'ev-att-001', valid: true }],
  verificationReferences: {
    artifactVerifications: 1,
    evidenceVerifications: 1,
    chainVerificationRun:  true,
    chainDecision:         'ATTESTED',
  },
  evidencePackage: { packageHash: 'a'.repeat(64), packageId: 'b'.repeat(64), packageType: 'QODIQA::CERTIFICATION_EVIDENCE::V1' },
  transparencyReferences: { transparencyId: 'trans-001', registeredAt: '2026-06-22T00:00:00.000Z' },
  metadata: { artifactsEvaluated: 1, evidencePackagesVerified: 1, chainVerified: true, requestedBy: 'external', durationMs: 42 },
};

const NOT_CERTIFIED_RESULT = {
  ...PERFECT_CERTIFICATION,
  certificationId:       VALID_UUID,
  certificationLevel:    'NOT_CERTIFIED',
  certificationDecision: 'NOT_CERTIFIED',
  score:                 0,
  criticalControlFailures: [{ control: 'ARTIFACT_SUBMISSION', reason: 'No artifacts', severity: 'CRITICAL' }],
  passedControls:   [],
  failedControls:   [{ control: 'artifactVerification', score: 0, max: 15, detail: 'no artifacts' }],
};

const DB_RECORD = {
  id:                       1,
  certification_id:         VALID_UUID,
  certification_level:      'CERTIFIED_PREMIUM',
  certification_decision:   'CERTIFIED',
  score:                    100,
  score_breakdown:          PERFECT_CERTIFICATION.scoreBreakdown,
  critical_control_failures:[],
  passed_controls:          PERFECT_CERTIFICATION.passedControls,
  failed_controls:          [],
  evaluation_result:        {},
  attestation_references:   PERFECT_CERTIFICATION.attestationReferences,
  evidence_references:      PERFECT_CERTIFICATION.evidenceReferences,
  verification_references:  PERFECT_CERTIFICATION.verificationReferences,
  transparency_id:          'trans-001',
  evidence_package_hash:    'a'.repeat(64),
  artifacts_count:          1,
  evidence_packages_count:  1,
  requested_by:             'external',
  request_ip:               null,
  duration_ms:              42,
  generated_at:             '2026-06-22T00:00:00.000Z',
};

// ── beforeEach defaults ───────────────────────────────────────────────────────

beforeEach(() => {
  jest.clearAllMocks();
  mockEvaluate.mockResolvedValue(PERFECT_CERTIFICATION);
  mockAssembleCertEvidence.mockReturnValue({
    packageType:  'QODIQA::CERTIFICATION_EVIDENCE::V1',
    packageHash:  'a'.repeat(64),
    packageId:    'b'.repeat(64),
    generatedAt:  '2026-06-22T00:00:00.000Z',
    schemaVersion:'1.0',
    certificationId: VALID_UUID,
  });
  mockGetById.mockResolvedValue(null);
  mockListCertifications.mockResolvedValue({ certifications: [], total: 0, page: 1, pageSize: 50 });
  mockAggregateStats.mockResolvedValue(null);
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-01..CI-15  POST /v1/certification/evaluate
// ─────────────────────────────────────────────────────────────────────────────

describe('POST /v1/certification/evaluate', () => {
  test('CI-01 valid body with artifacts → 200 with certification result', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{ payload: 'test' }] });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.certification).toBeDefined();
    expect(res.body.data.certification.certificationLevel).toBe('CERTIFIED_PREMIUM');
  });

  test('CI-02 empty artifacts array → evaluate called, returns NOT_CERTIFIED', async () => {
    mockEvaluate.mockResolvedValue(NOT_CERTIFIED_RESULT);
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [] });

    expect(res.status).toBe(200);
    expect(res.body.data.certification.certificationLevel).toBe('NOT_CERTIFIED');
  });

  test('CI-03 artifacts array omitted → defaults to [] → evaluate called', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({});

    expect(res.status).toBe(200);
    expect(mockEvaluate).toHaveBeenCalledWith(
      expect.objectContaining({ artifacts: [] }),
      expect.any(Object),
    );
  });

  test('CI-04 artifacts > 50 → 400 INVALID_PARAM', async () => {
    const artifacts = Array.from({ length: 51 }, (_, i) => ({ id: i }));
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });

  test('CI-05 evidencePackages > 50 → 400 INVALID_PARAM', async () => {
    const evidencePackages = Array.from({ length: 51 }, (_, i) => ({ id: i }));
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}], evidencePackages });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });

  test('CI-06 artifacts is not array → 400', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: 'not-an-array' });

    expect(res.status).toBe(400);
  });

  test('CI-07 evidencePackages is not array → 400', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [], evidencePackages: 'bad' });

    expect(res.status).toBe(400);
  });

  test('CI-08 null body → 400', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .set('Content-Type', 'application/json')
      .send('null');

    expect(res.status).toBe(400);
  });

  test('CI-09 array body → 400', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send([{ artifacts: [] }]);

    expect(res.status).toBe(400);
  });

  test('CI-10 evaluationEngine throws → 500', async () => {
    mockEvaluate.mockRejectedValue(new Error('engine failure'));
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}] });

    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
  });

  test('CI-11 response contains apiVersion v1', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}] });

    expect(res.body.data.apiVersion).toBe('v1');
  });

  test('CI-12 evaluate called with evidencePackages and chain from body', async () => {
    await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({
        artifacts:        [{ id: 1 }],
        evidencePackages: [{ id: 2 }],
        chain:            { evidenceIds: ['ev-001'] },
      });

    expect(mockEvaluate).toHaveBeenCalledWith(
      expect.objectContaining({
        evidencePackages: [{ id: 2 }],
        chain:            { evidenceIds: ['ev-001'] },
      }),
      expect.any(Object),
    );
  });

  // inverted — a caller-chosen requestedBy is ignored; the record
  // names the authenticated operator.
  test('CI-13 options.requestedBy is ignored: evaluate records the authenticated identity', async () => {
    await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}], options: { requestedBy: 'ci-test-user' } });

    expect(mockEvaluate).toHaveBeenCalledWith(
      expect.any(Object),
      expect.objectContaining({ requestedBy: 'op' }),
    );
    expect(mockEvaluate).not.toHaveBeenCalledWith(expect.any(Object), expect.objectContaining({ requestedBy: 'ci-test-user' }));
  });

  test('CI-13b the public router alone no longer serves POST /evaluate', async () => {
    const app = express();
    app.use(express.json());
    app.use('/v1/certification', createCertificationPublicRouter());
    const res = await supertest(app).post('/v1/certification/evaluate').send({ artifacts: [{}] });
    expect(res.status).toBe(404);
    expect(mockEvaluate).not.toHaveBeenCalled();
  });

  test('CI-14 exactly 50 artifacts allowed → 200', async () => {
    const artifacts = Array.from({ length: 50 }, () => ({}));
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts });

    expect(res.status).toBe(200);
  });

  test('CI-15 result contains certification with certificationId', async () => {
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}] });

    expect(res.body.data.certification.certificationId).toBe(VALID_UUID);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-16..CI-25  GET /v1/certification/:certificationId
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /v1/certification/:certificationId', () => {
  test('CI-16 invalid UUID → 400', async () => {
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${INVALID_UUID}`);

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });

  test('CI-17 valid UUID not found → 404', async () => {
    mockGetById.mockResolvedValue(null);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}`);

    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('CI-18 valid UUID found → 200 with certification record', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}`);

    expect(res.status).toBe(200);
    expect(res.body.data.certification).toBeDefined();
    expect(res.body.data.certification.certification_id).toBe(VALID_UUID);
  });

  test('CI-19 store throws → 500', async () => {
    mockGetById.mockRejectedValue(new Error('db error'));
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}`);

    expect(res.status).toBe(500);
  });

  test('CI-20 /admin is NOT treated as a UUID → 400 from public router', async () => {
    const res = await supertest(makePublicApp())
      .get('/v1/certification/admin');

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-26..CI-31  GET /v1/certification/:certificationId/summary
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /v1/certification/:certificationId/summary', () => {
  test('CI-26 invalid UUID → 400', async () => {
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${INVALID_UUID}/summary`);

    expect(res.status).toBe(400);
  });

  test('CI-27 not found → 404', async () => {
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    expect(res.status).toBe(404);
  });

  test('CI-28 found → 200 with summary structure', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    expect(res.status).toBe(200);
    const summary = res.body.data.summary;
    expect(summary.certificationId).toBe(VALID_UUID);
    expect(summary.certificationLevel).toBe('CERTIFIED_PREMIUM');
    expect(summary.score).toBe(100);
  });

  test('CI-29 summary has scoreSummary, controlsSummary, verificationSummary', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    const summary = res.body.data.summary;
    expect(summary.scoreSummary).toBeDefined();
    expect(summary.controlsSummary).toBeDefined();
    expect(summary.verificationSummary).toBeDefined();
  });

  test('CI-30 summary includes evidenceReference and transparencyReference', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    const summary = res.body.data.summary;
    expect(summary.evidenceReference).toBeDefined();
    expect(summary.transparencyReference).toBeDefined();
    expect(summary.transparencyReference.transparencyId).toBe('trans-001');
  });

  test('CI-31 store throws → 500', async () => {
    mockGetById.mockRejectedValue(new Error('db error'));
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    expect(res.status).toBe(500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-32..CI-40  GET /v1/certification/admin/history
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /v1/certification/admin/history', () => {
  test('CI-32 returns 200 with paginated list', async () => {
    mockListCertifications.mockResolvedValue({
      certifications: [DB_RECORD],
      total:          1,
      page:           1,
      pageSize:       50,
    });

    const res = await supertest(makeAdminApp())
      .get('/v1/certification/admin/history');

    expect(res.status).toBe(200);
    expect(res.body.data.certifications).toHaveLength(1);
    expect(res.body.data.total).toBe(1);
  });

  test('CI-33 empty result → 200 with empty array', async () => {
    const res = await supertest(makeAdminApp())
      .get('/v1/certification/admin/history');

    expect(res.status).toBe(200);
    expect(res.body.data.certifications).toEqual([]);
  });

  test('CI-34 certificationLevel filter passed to store', async () => {
    await supertest(makeAdminApp())
      .get('/v1/certification/admin/history?certificationLevel=CERTIFIED_PREMIUM');

    expect(mockListCertifications).toHaveBeenCalledWith(
      expect.objectContaining({ certificationLevel: 'CERTIFIED_PREMIUM' }),
    );
  });

  test('CI-35 certificationDecision filter passed to store', async () => {
    await supertest(makeAdminApp())
      .get('/v1/certification/admin/history?certificationDecision=CERTIFIED');

    expect(mockListCertifications).toHaveBeenCalledWith(
      expect.objectContaining({ certificationDecision: 'CERTIFIED' }),
    );
  });

  test('CI-36 minScore and maxScore filters passed as numbers', async () => {
    await supertest(makeAdminApp())
      .get('/v1/certification/admin/history?minScore=60&maxScore=100');

    expect(mockListCertifications).toHaveBeenCalledWith(
      expect.objectContaining({ minScore: 60, maxScore: 100 }),
    );
  });

  test('CI-37 pagination params passed to store', async () => {
    await supertest(makeAdminApp())
      .get('/v1/certification/admin/history?page=2&pageSize=25&sortOrder=asc');

    expect(mockListCertifications).toHaveBeenCalledWith(
      expect.objectContaining({ page: 2, pageSize: 25, sortOrder: 'asc' }),
    );
  });

  test('CI-38 store throws → 500', async () => {
    mockListCertifications.mockRejectedValue(new Error('db error'));
    const res = await supertest(makeAdminApp())
      .get('/v1/certification/admin/history');

    expect(res.status).toBe(500);
  });

  test('CI-39 requestedBy filter passed to store', async () => {
    await supertest(makeAdminApp())
      .get('/v1/certification/admin/history?requestedBy=audit-team');

    expect(mockListCertifications).toHaveBeenCalledWith(
      expect.objectContaining({ requestedBy: 'audit-team' }),
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-41..CI-47  GET /v1/certification/admin/stats
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /v1/certification/admin/stats', () => {
  test('CI-41 PG disabled → 200 with zero-filled stats', async () => {
    mockAggregateStats.mockResolvedValue(null);
    const res = await supertest(makeAdminApp())
      .get('/v1/certification/admin/stats');

    expect(res.status).toBe(200);
    expect(res.body.data.pgEnabled).toBe(false);
    expect(res.body.data.stats.total).toBe(0);
  });

  test('CI-42 PG enabled → 200 with real stats', async () => {
    mockAggregateStats.mockResolvedValue({
      total: 5, premiumCount: 2, plusCount: 1, certifiedCount: 1, notCertifiedCount: 1,
      decisionCertified: 4, decisionNotCertified: 1,
      avgScore: 87.5, minScore: 40, maxScore: 100,
    });

    const res = await supertest(makeAdminApp())
      .get('/v1/certification/admin/stats');

    expect(res.status).toBe(200);
    expect(res.body.data.pgEnabled).toBe(true);
    expect(res.body.data.stats.total).toBe(5);
  });

  test('CI-43 response includes generatedAt', async () => {
    const res = await supertest(makeAdminApp())
      .get('/v1/certification/admin/stats');

    expect(res.body.data.generatedAt).toBeDefined();
  });

  test('CI-44 store throws → 500', async () => {
    mockAggregateStats.mockRejectedValue(new Error('db error'));
    const res = await supertest(makeAdminApp())
      .get('/v1/certification/admin/stats');

    expect(res.status).toBe(500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-48..CI-56  GET /v1/certification/:certificationId/report
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /v1/certification/:certificationId/report', () => {
  test('CI-48 invalid UUID → 400', async () => {
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${INVALID_UUID}/report`);

    expect(res.status).toBe(400);
  });

  test('CI-49 not found → 404', async () => {
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report`);

    expect(res.status).toBe(404);
  });

  test('CI-50 found JSON → 200 with report structure', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report`);

    expect(res.status).toBe(200);
    const report = res.body.data.report;
    expect(report.certificationMetadata).toBeDefined();
    expect(report.evaluationResults).toBeDefined();
    expect(report.verificationResults).toBeDefined();
    expect(report.complianceResults).toBeDefined();
    expect(report.evidenceReferences).toBeDefined();
    expect(report.requestMetadata).toBeDefined();
  });

  test('CI-51 report.certificationMetadata has correct fields', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report`);

    const meta = res.body.data.report.certificationMetadata;
    expect(meta.certificationId).toBe(VALID_UUID);
    expect(meta.certificationLevel).toBe('CERTIFIED_PREMIUM');
    expect(meta.certificationDecision).toBe('CERTIFIED');
  });

  test('CI-52 PDF format → 200 application/pdf', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report?format=pdf`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/pdf');
  });

  test('CI-53 PDF response has Content-Disposition with filename', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report?format=pdf`);

    expect(res.headers['content-disposition']).toContain('attachment');
    expect(res.headers['content-disposition']).toContain(VALID_UUID);
  });

  test('CI-54 store throws → 500', async () => {
    mockGetById.mockRejectedValue(new Error('db error'));
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report`);

    expect(res.status).toBe(500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-57..CI-63  GET /v1/certification/:certificationId/evidence
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /v1/certification/:certificationId/evidence', () => {
  test('CI-57 invalid UUID → 400', async () => {
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${INVALID_UUID}/evidence`);

    expect(res.status).toBe(400);
  });

  test('CI-58 not found → 404', async () => {
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/evidence`);

    expect(res.status).toBe(404);
  });

  test('CI-59 found → 200 with certificationEvidence', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/evidence`);

    expect(res.status).toBe(200);
    expect(res.body.data.certificationEvidence).toBeDefined();
    expect(res.body.data.certificationEvidence.packageType).toBe('QODIQA::CERTIFICATION_EVIDENCE::V1');
  });

  test('CI-60 assembleCertificationEvidence called with record fields', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/evidence`);

    expect(mockAssembleCertEvidence).toHaveBeenCalledWith(
      expect.objectContaining({ certificationId: VALID_UUID }),
    );
  });

  test('CI-61 evidence package has packageHash', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/evidence`);

    expect(res.body.data.certificationEvidence.packageHash).toBe('a'.repeat(64));
  });

  test('CI-62 store throws → 500', async () => {
    mockGetById.mockRejectedValue(new Error('db error'));
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/evidence`);

    expect(res.status).toBe(500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-64..CI-68  GET /v1/certification/:certificationId/export
// ─────────────────────────────────────────────────────────────────────────────

describe('GET /v1/certification/:certificationId/export', () => {
  test('CI-64 invalid UUID → 400', async () => {
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${INVALID_UUID}/export`);

    expect(res.status).toBe(400);
  });

  test('CI-65 not found → 404', async () => {
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/export`);

    expect(res.status).toBe(404);
  });

  test('CI-66 JSON export → 200 with full certification record', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/export`);

    expect(res.status).toBe(200);
    expect(res.body.data.certification.certification_id).toBe(VALID_UUID);
  });

  test('CI-67 PDF export → 200 application/pdf', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/export?format=pdf`);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('application/pdf');
  });

  test('CI-68 store throws → 500', async () => {
    mockGetById.mockRejectedValue(new Error('db error'));
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/export`);

    expect(res.status).toBe(500);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-69..CI-75  E2E Scenario A — CERTIFIED_PREMIUM (perfect submission)
// ─────────────────────────────────────────────────────────────────────────────

describe('E2E Scenario A: CERTIFIED_PREMIUM perfect submission', () => {
  let evalResult;
  let evalRes;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockEvaluate.mockResolvedValue(PERFECT_CERTIFICATION);
    mockGetById.mockResolvedValue(DB_RECORD);
    mockAssembleCertEvidence.mockReturnValue({
      packageType:   'QODIQA::CERTIFICATION_EVIDENCE::V1',
      packageHash:   'a'.repeat(64),
      packageId:     'b'.repeat(64),
      schemaVersion: '1.0',
      certificationId: VALID_UUID,
    });

    evalRes = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{ payload: 'test', signature: 'sig', timestamp: Date.now() }] });

    evalResult = evalRes.body.data.certification;
  });

  test('CI-69 evaluate returns 200', () => {
    expect(evalRes.status).toBe(200);
  });

  test('CI-70 certificationLevel is CERTIFIED_PREMIUM', () => {
    expect(evalResult.certificationLevel).toBe('CERTIFIED_PREMIUM');
  });

  test('CI-71 certificationDecision is CERTIFIED', () => {
    expect(evalResult.certificationDecision).toBe('CERTIFIED');
  });

  test('CI-72 score is 100', () => {
    expect(evalResult.score).toBe(100);
  });

  test('CI-73 no critical control failures', () => {
    expect(evalResult.criticalControlFailures).toHaveLength(0);
  });

  test('CI-74 retrieve record by certificationId → 200', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}`);

    expect(res.status).toBe(200);
    expect(res.body.data.certification.certification_level).toBe('CERTIFIED_PREMIUM');
  });

  test('CI-75 evidence endpoint returns QODIQA::CERTIFICATION_EVIDENCE::V1', async () => {
    mockGetById.mockResolvedValue(DB_RECORD);
    mockAssembleCertEvidence.mockReturnValue({
      packageType:   'QODIQA::CERTIFICATION_EVIDENCE::V1',
      packageHash:   'a'.repeat(64),
      packageId:     'b'.repeat(64),
      schemaVersion: '1.0',
      certificationId: VALID_UUID,
    });
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/evidence`);

    expect(res.status).toBe(200);
    expect(res.body.data.certificationEvidence.packageType).toBe('QODIQA::CERTIFICATION_EVIDENCE::V1');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-76..CI-81  E2E Scenario B — NOT_CERTIFIED (critical failure)
// ─────────────────────────────────────────────────────────────────────────────

describe('E2E Scenario B: NOT_CERTIFIED critical failure', () => {
  let evalResult;
  let evalRes;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockEvaluate.mockResolvedValue(NOT_CERTIFIED_RESULT);

    evalRes = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [] });

    evalResult = evalRes.body.data.certification;
  });

  test('CI-76 evaluate returns 200', () => {
    expect(evalRes.status).toBe(200);
  });

  test('CI-77 certificationLevel is NOT_CERTIFIED', () => {
    expect(evalResult.certificationLevel).toBe('NOT_CERTIFIED');
  });

  test('CI-78 certificationDecision is NOT_CERTIFIED', () => {
    expect(evalResult.certificationDecision).toBe('NOT_CERTIFIED');
  });

  test('CI-79 criticalControlFailures has ARTIFACT_SUBMISSION', () => {
    expect(evalResult.criticalControlFailures).toHaveLength(1);
    expect(evalResult.criticalControlFailures[0].control).toBe('ARTIFACT_SUBMISSION');
  });

  test('CI-80 score is 0', () => {
    expect(evalResult.score).toBe(0);
  });

  test('CI-81 failedControls is non-empty', () => {
    expect(evalResult.failedControls.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-82..CI-87  E2E Scenario C — CERTIFIED_PLUS range (warnings only)
// ─────────────────────────────────────────────────────────────────────────────

describe('E2E Scenario C: CERTIFIED_PLUS range with warnings', () => {
  const PLUS_RESULT = {
    ...PERFECT_CERTIFICATION,
    certificationLevel:    'CERTIFIED_PLUS',
    certificationDecision: 'CERTIFIED',
    score:                 85,
    criticalControlFailures: [],
    scoreBreakdown: {
      verificationControls: { score: 35, max: 40 },
      operationalControls:  { score: 25, max: 35 },
      complianceControls:   { score: 25, max: 25 },
      totalScore:           85,
    },
  };

  let evalResult;
  let evalRes;

  beforeAll(async () => {
    jest.clearAllMocks();
    mockEvaluate.mockResolvedValue(PLUS_RESULT);

    evalRes = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}] });

    evalResult = evalRes.body.data.certification;
  });

  test('CI-82 evaluate returns 200', () => {
    expect(evalRes.status).toBe(200);
  });

  test('CI-83 certificationLevel is CERTIFIED_PLUS', () => {
    expect(evalResult.certificationLevel).toBe('CERTIFIED_PLUS');
  });

  test('CI-84 certificationDecision is CERTIFIED (not NOT_CERTIFIED)', () => {
    expect(evalResult.certificationDecision).toBe('CERTIFIED');
  });

  test('CI-85 score is in 80–94 range', () => {
    expect(evalResult.score).toBeGreaterThanOrEqual(80);
    expect(evalResult.score).toBeLessThanOrEqual(94);
  });

  test('CI-86 no critical control failures', () => {
    expect(evalResult.criticalControlFailures).toHaveLength(0);
  });

  test('CI-87 scoreBreakdown totalScore matches score', () => {
    expect(evalResult.scoreBreakdown.totalScore).toBe(evalResult.score);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-88..CI-99  Component #21 — Certificate Expiry
// ─────────────────────────────────────────────────────────────────────────────

describe('Component #21: Certificate Expiry — evaluate response', () => {
  const CERTIFIED_WITH_EXPIRY = {
    ...PERFECT_CERTIFICATION,
    expiresAt: '2027-06-24T00:00:00.000Z',
    renewal:   'ELIGIBLE',
  };

  const NOT_CERTIFIED_WITH_EXPIRY = {
    ...NOT_CERTIFIED_RESULT,
    expiresAt: null,
    renewal:   'NOT_APPLICABLE',
  };

  test('CI-88 CERTIFIED result includes expiresAt (non-null ISO string)', async () => {
    mockEvaluate.mockResolvedValue(CERTIFIED_WITH_EXPIRY);
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}] });

    expect(res.status).toBe(200);
    const cert = res.body.data.certification;
    expect(cert.expiresAt).toBeDefined();
    expect(typeof cert.expiresAt).toBe('string');
    expect(new Date(cert.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  test('CI-89 CERTIFIED result has renewal = ELIGIBLE', async () => {
    mockEvaluate.mockResolvedValue(CERTIFIED_WITH_EXPIRY);
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}] });

    expect(res.body.data.certification.renewal).toBe('ELIGIBLE');
  });

  test('CI-90 NOT_CERTIFIED result has expiresAt = null', async () => {
    mockEvaluate.mockResolvedValue(NOT_CERTIFIED_WITH_EXPIRY);
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [] });

    expect(res.body.data.certification.expiresAt).toBeNull();
  });

  test('CI-91 NOT_CERTIFIED result has renewal = NOT_APPLICABLE', async () => {
    mockEvaluate.mockResolvedValue(NOT_CERTIFIED_WITH_EXPIRY);
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [] });

    expect(res.body.data.certification.renewal).toBe('NOT_APPLICABLE');
  });
});

describe('Component #21: Certificate Expiry — summary endpoint', () => {
  const ACTIVE_DB_RECORD = {
    ...DB_RECORD,
    expires_at: new Date(Date.now() + 365 * 86_400_000).toISOString(),
    renewal:    'ELIGIBLE',
  };

  const EXPIRED_DB_RECORD = {
    ...DB_RECORD,
    expires_at: new Date(Date.now() - 1000).toISOString(),
    renewal:    'ELIGIBLE',
  };

  const HISTORICAL_DB_RECORD = {
    ...DB_RECORD,
    expires_at: null,
    renewal:    null,
  };

  test('CI-92 active cert summary has lifecycle.validityStatus = ACTIVE', async () => {
    mockGetById.mockResolvedValue(ACTIVE_DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    expect(res.status).toBe(200);
    expect(res.body.data.summary.lifecycle.validityStatus).toBe('ACTIVE');
    expect(res.body.data.summary.lifecycle.renewal).toBe('ELIGIBLE');
    expect(res.body.data.summary.lifecycle.expiresAt).toBeDefined();
  });

  test('CI-93 expired cert summary has lifecycle.validityStatus = EXPIRED', async () => {
    mockGetById.mockResolvedValue(EXPIRED_DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    expect(res.status).toBe(200);
    expect(res.body.data.summary.lifecycle.validityStatus).toBe('EXPIRED');
  });

  test('CI-94 historical cert (null expires_at) has lifecycle.validityStatus = NOT_APPLICABLE', async () => {
    mockGetById.mockResolvedValue(HISTORICAL_DB_RECORD);
    const res = await supertest(makePublicApp())
      .get(`/v1/certification/${VALID_UUID}/summary`);

    expect(res.status).toBe(200);
    expect(res.body.data.summary.lifecycle.validityStatus).toBe('NOT_APPLICABLE');
    expect(res.body.data.summary.lifecycle.expiresAt).toBeNull();
    expect(res.body.data.summary.lifecycle.renewal).toBeNull();
  });
});

describe('Component #21: Certificate Expiry — report endpoint', () => {
  const ACTIVE_DB_RECORD = {
    ...DB_RECORD,
    expires_at: new Date(Date.now() + 365 * 86_400_000).toISOString(),
    renewal:    'ELIGIBLE',
  };

  test('CI-95 report certificationMetadata includes expiresAt', async () => {
    mockGetById.mockResolvedValue(ACTIVE_DB_RECORD);
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report`);

    expect(res.status).toBe(200);
    const meta = res.body.data.report.certificationMetadata;
    expect(meta.expiresAt).toBeDefined();
    expect(meta.renewal).toBe('ELIGIBLE');
    expect(meta.validityStatus).toBe('ACTIVE');
  });

  test('CI-96 report for historical record (null expires_at) still succeeds', async () => {
    mockGetById.mockResolvedValue({ ...DB_RECORD, expires_at: null, renewal: null });
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report`);

    expect(res.status).toBe(200);
    const meta = res.body.data.report.certificationMetadata;
    expect(meta.expiresAt).toBeNull();
    expect(meta.renewal).toBeNull();
    expect(meta.validityStatus).toBe('NOT_APPLICABLE');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CI-97..CI-99  Component #22 — Evidence Package Enforcement (API layer)
// ─────────────────────────────────────────────────────────────────────────────

describe('Component #22: Evidence package enforcement — API passthrough', () => {
  const MISSING_EVIDENCE_RESULT = {
    ...NOT_CERTIFIED_RESULT,
    certificationDecision:   'NOT_CERTIFIED',
    certificationLevel:      'NOT_CERTIFIED',
    criticalControlFailures: [{
      control:  'MISSING_EVIDENCE_PACKAGE',
      reason:   'No evidence packages submitted — at least one evidence package is required for certification',
      severity: 'CRITICAL',
    }],
  };

  test('CI-97 evaluate response includes MISSING_EVIDENCE_PACKAGE in criticalControlFailures', async () => {
    mockEvaluate.mockResolvedValue(MISSING_EVIDENCE_RESULT);
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}] });

    expect(res.status).toBe(200);
    expect(res.body.data.certification.certificationDecision).toBe('NOT_CERTIFIED');
    const failure = res.body.data.certification.criticalControlFailures
      .find(f => f.control === 'MISSING_EVIDENCE_PACKAGE');
    expect(failure).toBeDefined();
    expect(failure.severity).toBe('CRITICAL');
  });

  test('CI-98 report endpoint includes MISSING_EVIDENCE_PACKAGE in evaluationResults.criticalControlFailures', async () => {
    mockGetById.mockResolvedValue({
      ...DB_RECORD,
      certification_decision:    'NOT_CERTIFIED',
      certification_level:       'NOT_CERTIFIED',
      critical_control_failures: [{ control: 'MISSING_EVIDENCE_PACKAGE', severity: 'CRITICAL' }],
    });
    const res = await supertest(makeAdminApp())
      .get(`/v1/certification/${VALID_UUID}/report`);

    expect(res.status).toBe(200);
    const failures = res.body.data.report.evaluationResults.criticalControlFailures;
    expect(failures.find(f => f.control === 'MISSING_EVIDENCE_PACKAGE')).toBeDefined();
  });

  test('CI-99 score pass + evidence present → engine called with evidencePackages forwarded', async () => {
    mockEvaluate.mockResolvedValue(PERFECT_CERTIFICATION);
    const res = await supertest(makePublicApp())
      .post('/v1/certification/evaluate')
      .send({ artifacts: [{}], evidencePackages: [{ id: 'pkg-001' }] });

    expect(res.status).toBe(200);
    expect(mockEvaluate).toHaveBeenCalledWith(
      expect.objectContaining({ evidencePackages: [{ id: 'pkg-001' }] }),
      expect.any(Object),
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// H130-CI-01…H130-CI-05: the
// requester address (certifications.request_ip) is INTERNAL AUDIT DATA —
// persisted, served to READ/EXPORT_CERTIFICATIONS operators, never public.
// ─────────────────────────────────────────────────────────────────────────────

describe('H130-CI  requester address: internal audit data, never public', () => {
  const H130_IP   = '203.0.113.10'; // RFC 5737 TEST-NET-3 — synthetic
  const UNRELATED = { Authorization: 'Bearer sk_h130_unrelated_tenant_credential' };
  const roles = require('../../../core/rbac/roles');
  const { createRequirePermission } = require('../../../middleware/rbac');
  const RECORD = { ...DB_RECORD, request_ip: H130_IP };

  // Mirrors src/app.js: public router, then the admin router behind the admin
  // stack (authentication stood in by a role header; REAL requirePermission).
  function makeComposedApp() {
    const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
    app.use('/v1/certification', createCertificationPublicRouter());
    app.use('/v1/certification', (req, res, next) => {
      const role = req.headers['x-test-operator-role'];
      if (!role) return res.status(401).json({ error: { code: 'UNAUTHORIZED' } });
      req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role, enabled: true });
      return next();
    }, createCertificationAdminRouter({ requirePermission }));
    return app;
  }
  const AUDITOR = { 'x-test-operator-role': roles.ROLES.AUDITOR };

  test('H130-CI-01  public GET /:id omits request_ip; the rest of the row is intact; unrelated credential sees the same', async () => {
    mockGetById.mockResolvedValue(RECORD);
    const anon = await supertest(makeComposedApp()).get(`/v1/certification/${VALID_UUID}`);
    expect(anon.status).toBe(200);
    expect(anon.body.data.certification).not.toHaveProperty('request_ip');
    expect(anon.body.data.certification.certification_id).toBe(VALID_UUID);
    expect(anon.body.data.certification.certification_decision).toBe('CERTIFIED');
    expect(anon.text).not.toContain(H130_IP);
    const other = await supertest(makeComposedApp()).get(`/v1/certification/${VALID_UUID}`).set(UNRELATED);
    expect(other.body.data).toEqual(anon.body.data);
  });

  test('H130-CI-02  public GET /:id/summary carries no address', async () => {
    mockGetById.mockResolvedValue(RECORD);
    const res = await supertest(makeComposedApp()).get(`/v1/certification/${VALID_UUID}/summary`);
    expect(res.status).toBe(200);
    expect(res.text).not.toContain(H130_IP);
  });

  test('H130-CI-03  POST /evaluate hands the caller address to the engine (internal) but never returns it', async () => {
    // evaluate requires authentication + SUBMIT_BATCH_CERTIFICATION.
    const noAuth = await supertest(makeComposedApp()).post('/v1/certification/evaluate').send({ artifacts: [{ payload: 'test' }] });
    expect(noAuth.status).toBe(401);
    const viewer = await supertest(makeComposedApp()).post('/v1/certification/evaluate')
      .set({ 'x-test-operator-role': roles.ROLES.VIEWER }).send({ artifacts: [{ payload: 'test' }] });
    expect(viewer.status).toBe(403);
    expect(mockEvaluate).not.toHaveBeenCalled();
    const res = await supertest(makeComposedApp()).post('/v1/certification/evaluate')
      .set({ 'x-test-operator-role': roles.ROLES.OPERATOR }).send({ artifacts: [{ payload: 'test' }] });
    expect(res.status).toBe(200);
    expect(mockEvaluate.mock.calls[0][1].requestedBy).toBe('op');
    const ip = mockEvaluate.mock.calls[0][1].requestIp;
    expect(typeof ip).toBe('string');
    expect(res.text).not.toContain(ip);
  });

  test('H130-CI-04  internal audit views keep the address: report (JSON), export (JSON), history', async () => {
    mockGetById.mockResolvedValue(RECORD);
    mockListCertifications.mockResolvedValue({ certifications: [RECORD], total: 1, page: 1, pageSize: 50 });
    const rep = await supertest(makeComposedApp()).get(`/v1/certification/${VALID_UUID}/report`).set(AUDITOR);
    expect(rep.status).toBe(200);
    expect(rep.body.data.report.requestMetadata.requestIp).toBe(H130_IP);
    const exp = await supertest(makeComposedApp()).get(`/v1/certification/${VALID_UUID}/export`).set(AUDITOR);
    expect(exp.status).toBe(200);
    expect(exp.body.data.certification.request_ip).toBe(H130_IP);
    const hist = await supertest(makeComposedApp()).get('/v1/certification/admin/history').set(AUDITOR);
    expect(hist.status).toBe(200);
    expect(hist.body.data.certifications[0].request_ip).toBe(H130_IP);
  });

  test('H130-CI-05  internal views are refused without operator authentication (401) or with an unpermitted role (403)', async () => {
    mockGetById.mockResolvedValue(RECORD);
    mockListCertifications.mockResolvedValue({ certifications: [RECORD], total: 1, page: 1, pageSize: 50 });
    for (const path of [`/v1/certification/${VALID_UUID}/report`, `/v1/certification/${VALID_UUID}/export`, '/v1/certification/admin/history']) {
      const anon = await supertest(makeComposedApp()).get(path).set(UNRELATED);
      expect(anon.status).toBe(401);
      expect(anon.text).not.toContain(H130_IP);
      const viewer = await supertest(makeComposedApp()).get(path).set({ 'x-test-operator-role': roles.ROLES.VIEWER });
      expect(viewer.status).toBe(403);
      expect(viewer.text).not.toContain(H130_IP);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// H131-CI-01 regression guard: the certification PDF routes (not changed by
// and not affected by the crash) keep rendering with the value
// shapes PostgreSQL returns (TIMESTAMPTZ -> Date), twice, with no write after end.
// ─────────────────────────────────────────────────────────────────────────────

describe('H131-CI  certification PDF behaviour unchanged', () => {
  const http = require('http');
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
  const binary = (res, cb) => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => cb(null, Buffer.concat(c))); };

  test('H131-CI-01  report and export PDFs render twice each with PostgreSQL-shaped timestamps', async () => {
    mockGetById.mockResolvedValue({ ...DB_RECORD, generated_at: new Date('2026-09-25T00:00:00.000Z'), expires_at: new Date('2027-09-25T00:00:00.000Z') });
    const app = makeAdminApp();
    for (const path of [`/v1/certification/${VALID_UUID}/report?format=pdf`, `/v1/certification/${VALID_UUID}/export?format=pdf`]) {
      for (let i = 0; i < 2; i++) {
        const res = await supertest(app).get(path).buffer(true).parse(binary);
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toBe('application/pdf');
        expect(res.body.slice(0, 5).toString('latin1')).toBe('%PDF-');
        expect(res.body.slice(-8).toString('latin1')).toContain('%%EOF');
      }
    }
    await new Promise(r => setTimeout(r, 150));
    expect(lateWrites).toBe(0);
  });
});
