'use strict';

/**
 * operator "sign out everywhere" for a tenant-portal user:
 *   POST /v1/admin/tenants/:tenantId/portal-users/:portalUserId/revoke-sessions
 *
 * Uses the REAL tenantPortalUserStore (memory mode), the REAL portal session middleware and tokens, and the REAL
 * MFA step-up middleware + MFA module composed exactly as src/app.js composes the /v1/admin/tenants mount
 * (adminStack('MANAGE_USERS') → _stepUp = createMfaStepUp({ mfa }) → createTenantsAdminRouter()); the admin stack
 * itself is stood in for by a middleware that sets req.rbacUser (its own suites cover it). The live-app wiring is
 * proven separately: AR-07 asserts the committed OpenAPI marks this operation x-qodiqa-mfa-step-up, and
 * src/openapi/mfaStepUpScope.test.js MS-01 asserts the spec's step-up set equals the live app's.
 *
 *   AR-01 revoke → 200, version bumped; the user's outstanding portal token is refused on its next request
 *   AR-02 other users (same tenant and other tenant) keep working
 *   AR-03 a user of ANOTHER tenant → 404 (never acts across tenants), version unchanged
 *   AR-04 unknown user → 404; malformed ids → 400
 *   AR-05 MFA required: operator without MFA → 403 MFA_ENROLLMENT_REQUIRED; enrolled, no code → 401 MFA_REQUIRED;
 *         nothing revoked in either case
 *   AR-06 MFA required: enrolled operator with a valid code → 200 and the session is revoked
 *   AR-07 the committed OpenAPI declares the operation with x-qodiqa-mfa-step-up
 *   AR-08 the user is NOT disabled: a token at the new version works (re-login)
 */

jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

const express = require('express');
const request = require('supertest');

const SECRET = 'e'.repeat(64);

const portalUserStore = require('../../../../core/portal/tenantPortalUserStore');
const { createTenantsAdminRouter } = require('../tenants');
const { createMfaStepUp } = require('../../../../middleware/mfaStepUp');
const { createPortalSessionMiddleware } = require('../../../../middleware/portalAuth');
const { mintSessionToken, verifySessionToken } = require('../../../../../services/portal/portalSessionToken');
const rbacStore = require('../../../../core/rbac/store');
const mfa = require('../../../../core/rbac/mfa');

let seq = 0;
function portalUser(tenantId) {
  seq += 1;
  return portalUserStore.findOrCreateByIdpSubject({
    idpIssuer: 'https://idp.example.com', idpSubject: `dd095-admin-${process.pid}-${Date.now()}-${seq}`, tenantId, email: null,
  });
}
function tokenFor(rec) {
  return mintSessionToken({ portalUserId: rec.id, tenantId: rec.tenantId, role: rec.role, sessionVersion: portalUserStore.sessionVersionOf(rec) });
}

// The admin plane: stand-in for ctx.adminStack('MANAGE_USERS') + the real step-up + the real router (src/app.js order).
function adminApp(operator) {
  const a = express();
  a.use(express.json());
  a.use((req, _res, next) => { req.requestId = 'dd095-admin'; if (operator) req.rbacUser = operator; next(); });
  a.use('/v1/admin/tenants', createMfaStepUp({ mfa }), createTenantsAdminRouter());
  return a;
}
// The tenant portal's authenticated surface, minimal: the real session middleware in front of a probe.
function portalApp() {
  const a = express();
  a.get('/probe', createPortalSessionMiddleware({ verifySessionToken, getPortalUserById: portalUserStore.getById }), (_req, res) => res.json({ ok: true }));
  return a;
}
const probe = (token) => request(portalApp()).get('/probe').set('Authorization', `Bearer ${token}`);
const revokePath = (t, u) => `/v1/admin/tenants/${t}/portal-users/${u}/revoke-sessions`;

let opSeq = 0;
function operator() { opSeq += 1; const u = rbacStore.createUser({ username: `dd095-op-${opSeq}-${Date.now()}`, role: 'admin' }); return { id: u.id, username: u.username }; }
async function enrolledOperator() {
  const op = operator();
  const { secret } = mfa.beginEnrollment(op);
  const raw = mfa.base32Decode(secret);
  await mfa.confirmEnrollment(op, mfa.totp(raw, Date.now() - 60_000), undefined, Date.now() - 60_000);
  return { op, raw };
}

let savedSecret; let savedMfa;
beforeEach(() => {
  savedSecret = process.env.QODIQA_PORTAL_SESSION_SECRET; savedMfa = process.env.QODIQA_OPS_MFA_REQUIRED;
  process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;
  process.env.QODIQA_OPS_MFA_REQUIRED = 'false';
});
afterEach(() => {
  if (savedSecret === undefined) delete process.env.QODIQA_PORTAL_SESSION_SECRET; else process.env.QODIQA_PORTAL_SESSION_SECRET = savedSecret;
  if (savedMfa === undefined) delete process.env.QODIQA_OPS_MFA_REQUIRED; else process.env.QODIQA_OPS_MFA_REQUIRED = savedMfa;
});

describe('admin revoke-sessions route', () => {
  test('AR-01 revoke → 200, version bumped; the outstanding token is refused on its next request', async () => {
    const u = portalUser('acme');
    const token = tokenFor(u);
    expect((await probe(token)).status).toBe(200);
    const r = await request(adminApp(operator())).post(revokePath('acme', u.id));
    expect(r.status).toBe(200);
    expect(r.body.data.portalUserId).toBe(u.id);
    expect(r.body.data.sessionVersion).toBe(1);
    expect((await probe(token)).status).toBe(401);
  });

  test('AR-02 other users (same tenant, other tenant) are unaffected', async () => {
    const target = portalUser('acme'); const sameTenant = portalUser('acme'); const otherTenant = portalUser('globex');
    const tSame = tokenFor(sameTenant); const tOther = tokenFor(otherTenant);
    await request(adminApp(operator())).post(revokePath('acme', target.id)).expect(200);
    expect((await probe(tSame)).status).toBe(200);
    expect((await probe(tOther)).status).toBe(200);
  });

  test('AR-03 a user of ANOTHER tenant → 404, nothing revoked', async () => {
    const u = portalUser('globex');
    const token = tokenFor(u);
    const r = await request(adminApp(operator())).post(revokePath('acme', u.id));
    expect(r.status).toBe(404);
    expect(portalUserStore.sessionVersionOf(portalUserStore.getById(u.id))).toBe(0);
    expect((await probe(token)).status).toBe(200);
  });

  test('AR-04 unknown user → 404; malformed tenant / user ids → 400', async () => {
    const app = adminApp(operator());
    expect((await request(app).post(revokePath('acme', 'pu_does-not-exist'))).status).toBe(404);
    expect((await request(app).post(revokePath('bad!tenant', 'pu_x'))).status).toBe(400);
    expect((await request(app).post(revokePath('acme', 'x'.repeat(200)))).status).toBe(400);
  });

  test('AR-05 MFA required: no MFA → 403 MFA_ENROLLMENT_REQUIRED; enrolled without a code → 401 MFA_REQUIRED; nothing revoked', async () => {
    process.env.QODIQA_OPS_MFA_REQUIRED = 'true';
    const u = portalUser('acme');
    const token = tokenFor(u);
    const a = await request(adminApp(operator())).post(revokePath('acme', u.id));
    expect(a.status).toBe(403);
    expect(a.body.error.code).toBe('MFA_ENROLLMENT_REQUIRED');
    const { op } = await enrolledOperator();
    const b = await request(adminApp(op)).post(revokePath('acme', u.id));
    expect(b.status).toBe(401);
    expect(b.body.error.code).toBe('MFA_REQUIRED');
    expect(portalUserStore.sessionVersionOf(portalUserStore.getById(u.id))).toBe(0);
    expect((await probe(token)).status).toBe(200);
  });

  test('AR-06 MFA required: enrolled operator with a valid code → 200 and the session is revoked', async () => {
    process.env.QODIQA_OPS_MFA_REQUIRED = 'true';
    const u = portalUser('acme');
    const token = tokenFor(u);
    const { op, raw } = await enrolledOperator();
    const r = await request(adminApp(op)).post(revokePath('acme', u.id)).set('X-QODIQA-OTP', mfa.totp(raw, Date.now()));
    expect(r.status).toBe(200);
    expect((await probe(token)).status).toBe(401);
  });

  test('AR-07 the committed OpenAPI declares the operation with x-qodiqa-mfa-step-up', () => {
    const spec = require('../../../../../docs/api/openapi.json');
    const op = spec.paths['/v1/admin/tenants/{tenantId}/portal-users/{portalUserId}/revoke-sessions'];
    expect(op && op.post).toBeTruthy();
    expect(op.post['x-qodiqa-mfa-step-up']).toBeTruthy();
  });

  test('AR-08 the user is not disabled: a token minted at the new version (re-login) works', async () => {
    const u = portalUser('acme');
    await request(adminApp(operator())).post(revokePath('acme', u.id)).expect(200);
    const after = portalUserStore.getById(u.id);
    expect(after.enabled).toBe(true);
    expect((await probe(tokenFor(after))).status).toBe(200);
  });
});
