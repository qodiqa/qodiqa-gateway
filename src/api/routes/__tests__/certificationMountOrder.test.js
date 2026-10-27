'use strict';

/**
 * src/app.js mount-order regression coverage.
 *
 * /v1/certification used to mount the ADMIN router first, on the theory
 * that this was needed to stop the public router's /:certificationId from
 * swallowing /admin/history and /admin/stats. That theory was wrong —
 * Express's path-to-regexp requires an exact segment-count match, so a
 * bare /:certificationId (one segment) never matches a two-segment path
 * like /admin/history regardless of mount order (verified directly against
 * a standalone Express instance before the fix landed). The actual effect
 * of admin-first was far worse than the swallowing it was meant to
 * prevent: ctx.adminStack()'s auth middleware is unconditional for the
 * whole mounted prefix, and the admin router's own trailing catch-all
 * (METHOD_NOT_ALLOWED) never calls next() — together these made the
 * ENTIRE public certification API unreachable, authenticated or not (see
 * for the full live-witness record).
 *
 * Fixed by reordering the two mount blocks in src/app.js — public now
 * comes first, matching the identical pattern transparencyLog.js,
 * verificationPortal.js, and attestation.js already use. This suite
 * guards that order two ways: a static source-position check (fails
 * loudly with no Express boot required if anyone reorders the lines
 * back), and a live multi-mount topology test reproducing both routers
 * co-mounted in the app.js order, proving neither swallows the other.
 */

const fs      = require('fs');
const path    = require('path');
const express = require('express');
const request = require('supertest');

jest.mock('../../../core/certification/evaluationEngine');
jest.mock('../../../core/certification/certificationStore');
jest.mock('../../../infra/postgres/pool', () => ({
  isEnabled: jest.fn().mockReturnValue(false),
  query:     jest.fn(),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../observability/metrics', () => ({
  certificationsTotal:               { inc: jest.fn() },
  certificationFailuresTotal:        { inc: jest.fn() },
  certificationPersistFailuresTotal: { inc: jest.fn() },
}));
jest.mock('../../../core/verification/portalStore', () => ({
  getByVerificationId: jest.fn().mockResolvedValue(null),
  recordVerification:  jest.fn().mockResolvedValue({ verification_id: 'stub' }),
  listVerifications:   jest.fn().mockResolvedValue({ verifications: [], total: 0 }),
  aggregateStats:      jest.fn().mockResolvedValue(null),
}));

const evaluationEngine   = require('../../../core/certification/evaluationEngine');
const certificationStore = require('../../../core/certification/certificationStore');
const { createCertificationPublicRouter, createCertificationAdminRouter } = require('../certification');

const VALID_UUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

describe('(static regression guard) — src/app.js mounts /v1/certification public before admin', () => {
  test('the public-router mount line appears before the admin-router mount line', () => {
    const appSrc = fs.readFileSync(path.join(__dirname, '../../../app.js'), 'utf8');

    const publicIdx = appSrc.indexOf("app.use('/v1/certification', createCertificationPublicRouter()");
    const adminIdx  = appSrc.indexOf("app.use('/v1/certification', ...ctx.adminStack(), _stepUpAdmin, createCertificationAdminRouter("); // + step-up

    expect(publicIdx).toBeGreaterThan(-1);
    expect(adminIdx).toBeGreaterThan(-1);
    expect(publicIdx).toBeLessThan(adminIdx);
  });
});

describe('(live multi-mount topology) — public and admin certification routers co-mounted in the fixed app.js order', () => {
  // Same order as the fixed src/app.js: public mounted before admin.
  // Swap these two app.use() calls and every "public reachable" test below
  // fails (401/405 instead of 200) — that is the regression this suite
  // exists to catch.
  function makeMultiMountApp({ authorized = true } = {}) {
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });

    app.use('/v1/certification', createCertificationPublicRouter());

    const requirePermission = () => (req, res, next) => {
      if (!authorized) return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Missing authentication credentials' });
      next();
    };
    app.use('/v1/certification', createCertificationAdminRouter({ requirePermission }));

    return app;
  }

  beforeEach(() => jest.clearAllMocks());

  test('POST /v1/certification/evaluate reaches the public handler (public not swallowed by admin auth)', async () => {
    const app = makeMultiMountApp();
    evaluationEngine.evaluate.mockResolvedValue({
      certificationId: VALID_UUID, certificationLevel: 'CERTIFIED_PREMIUM',
      certificationDecision: 'CERTIFIED', version: '1.0',
    });

    const res = await request(app).post('/v1/certification/evaluate').send({ artifactId: 'a1', results: [] });

    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(405);
  });

  test('GET /v1/certification/:certificationId reaches the public handler, not the admin auth gate', async () => {
    const app = makeMultiMountApp({ authorized: false }); // admin auth would reject if reached
    certificationStore.getByCertificationId.mockResolvedValue({
      certification_id: VALID_UUID, certification_level: 'CERTIFIED_PREMIUM',
    });

    const res = await request(app).get(`/v1/certification/${VALID_UUID}`);

    // If the old bug were present, this would be 401 (admin auth, unauthorized)
    // or 405 (admin catch-all) even though this path belongs to the public router.
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(405);
  });

  test('GET /v1/certification/admin/history reaches the admin handler, not swallowed by the public /:certificationId route', async () => {
    const app = makeMultiMountApp();
    certificationStore.listCertifications.mockResolvedValue({ certifications: [], total: 0 });

    const res = await request(app).get('/v1/certification/admin/history');

    expect(res.status).not.toBe(404);
    expect(certificationStore.listCertifications).toHaveBeenCalledTimes(1);
  });

  test('GET /v1/certification/admin/history is rejected when unauthorized — admin auth still gates correctly with public mounted first', async () => {
    const app = makeMultiMountApp({ authorized: false });

    const res = await request(app).get('/v1/certification/admin/history');

    expect(res.status).toBe(401);
  });

  test('GET /v1/certification/:certificationId/report reaches the admin handler (two-segment admin route, not swallowed by public single-segment route)', async () => {
    const app = makeMultiMountApp();
    certificationStore.getByCertificationId.mockResolvedValue({ certification_id: VALID_UUID });
    evaluationEngine.assembleCertificationEvidence?.mockResolvedValue?.({});

    const res = await request(app).get(`/v1/certification/${VALID_UUID}/report`);

    // Reaching the admin handler at all (not a 404 from an unmatched public
    // fallthrough) is what this test locks in -- the specific 200 vs 500
    // shape of a real report depends on evidence-assembly mocks this suite
    // doesn't fully wire, which is not what's under test here.
    expect(res.status).not.toBe(404);
  });
});
