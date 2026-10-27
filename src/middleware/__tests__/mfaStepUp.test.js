'use strict';

/** the step-up middleware in front of privileged mutations. */

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));

const express = require('express');
const request = require('supertest');
const { emit } = require('../../../services/logger');
const store = require('../../core/rbac/store');
const mfa = require('../../core/rbac/mfa');
const { createMfaStepUp, GOVERNANCE_STEP_UP, RBAC_SELF_ENROLL } = require('../mfaStepUp');

let n = 0;
function user() { n += 1; const u = store.createUser({ username: `stepup-${n}-${Date.now()}`, role: 'admin' }); return { id: u.id, username: u.username }; }
function enrolled() {
  const u = user();
  const { secret } = mfa.beginEnrollment(u);
  const raw = mfa.base32Decode(secret);
  const { recoveryCodes } = mfa.confirmEnrollment(u, mfa.totp(raw, Date.now() - 60_000), undefined, Date.now() - 60_000);
  return { u, raw, recoveryCodes };
}
function app(rbacUser, opts) {
  const a = express();
  a.use((req, _res, next) => { if (rbacUser) req.rbacUser = rbacUser; next(); });
  a.all(/.*/, createMfaStepUp({ mfa, ...opts }), (_req, res) => res.json({ ok: true }));
  return a;
}

let saved;
beforeEach(() => { saved = process.env.QODIQA_OPS_MFA_REQUIRED; process.env.QODIQA_OPS_MFA_REQUIRED = 'true'; emit.mockClear(); });
afterEach(() => { process.env.QODIQA_OPS_MFA_REQUIRED = saved; });

test('reads never need a code', async () => {
  const u = user();
  for (const m of ['get', 'head', 'options']) expect((await request(app(u))[m]('/x')).status).toBe(200);
});

test('mutation by an operator without MFA → 403 MFA_ENROLLMENT_REQUIRED', async () => {
  const r = await request(app(user())).post('/x');
  expect(r.status).toBe(403); expect(JSON.stringify(r.body)).toContain('MFA_ENROLLMENT_REQUIRED');
  expect(emit.mock.calls.some((c) => c[1] === 'RBAC_MFA_STEP_UP_DENIED')).toBe(true);
});

test('mutation with no operator identity → 403', async () => {
  expect((await request(app(null)).delete('/x')).status).toBe(403);
});

test('enrolled, no code → 401 MFA_REQUIRED; wrong code → 401 MFA_INVALID; valid → passes', async () => {
  const { u, raw } = enrolled();
  const a = app(u);
  let r = await request(a).post('/x');
  expect(r.status).toBe(401); expect(JSON.stringify(r.body)).toContain('MFA_REQUIRED');
  r = await request(a).post('/x').set('X-QODIQA-OTP', '000000');
  expect(r.status).toBe(401); expect(JSON.stringify(r.body)).toContain('MFA_INVALID');
  r = await request(a).put('/x').set('X-QODIQA-OTP', mfa.totp(raw));
  expect(r.status).toBe(200);
  expect(emit.mock.calls.some((c) => c[1] === 'RBAC_MFA_STEP_UP_OK')).toBe(true);
});

test('a recovery code passes once', async () => {
  const { u, recoveryCodes } = enrolled();
  expect((await request(app(u)).patch('/x').set('X-QODIQA-OTP', recoveryCodes[0])).status).toBe(200);
  expect((await request(app(u)).patch('/x').set('X-QODIQA-OTP', recoveryCodes[0])).status).toBe(401);
});

test('5 wrong codes → 429 MFA_LOCKED with Retry-After, and a valid code is then refused', async () => {
  const { u, raw } = enrolled();
  const a = app(u);
  for (let i = 0; i < 4; i++) expect((await request(a).post('/x').set('X-QODIQA-OTP', '111111')).status).toBe(401);
  const fifth = await request(a).post('/x').set('X-QODIQA-OTP', '111111');
  expect(fifth.status).toBe(429); expect(Number(fifth.headers['retry-after'])).toBeGreaterThan(0);
  expect((await request(a).post('/x').set('X-QODIQA-OTP', mfa.totp(raw))).status).toBe(429);
});

test('QODIQA_OPS_MFA_REQUIRED=false disables the requirement', async () => {
  process.env.QODIQA_OPS_MFA_REQUIRED = 'false';
  expect((await request(app(user())).post('/x')).status).toBe(200);
});

test('the `when` predicate scopes the step-up (governance / rbac self-enrol)', async () => {
  const u = user();
  const gov = app(u, { when: (req) => GOVERNANCE_STEP_UP.test(req.path) });
  expect((await request(gov).post('/p1/submit')).status).toBe(200);
  for (const p of ['/p1/approve', '/p1/publish', '/p1/schedule', '/emergency/activate', '/emergency/e1/retro-approve', '/p1/rollback/approve']) {
    expect((await request(gov).post(p)).status).toBe(403);
  }
  const rbac = app(u, { when: (req) => !RBAC_SELF_ENROLL.test(req.path) });
  expect((await request(rbac).post('/me/mfa/enroll')).status).toBe(200);
  expect((await request(rbac).post('/me/mfa/confirm')).status).toBe(200);
  expect((await request(rbac).post('/users/x/api-key')).status).toBe(403);
  expect((await request(rbac).delete('/users/x/mfa')).status).toBe(403);
});

// admin-plane mounts gate every mutation except the approved exemption registry.
describe('admin-plane step-up predicate', () => {
  const { STEP_UP_EXEMPTIONS, isStepUpExempt, adminPlaneStepUpWhen } = require('../mfaStepUp');

  function mounted(rbacUser, mount) {
    const a = express();
    a.use((req, _res, next) => { if (rbacUser) req.rbacUser = rbacUser; next(); });
    a.use(mount, createMfaStepUp({ mfa, when: adminPlaneStepUpWhen }), (_req, res) => res.json({ ok: true }));
    return a;
  }

  test('every exemption has a method, a path and a reason; matching is exact, case-sensitive, one segment per {param}', () => {
    expect(STEP_UP_EXEMPTIONS.length).toBeGreaterThan(0);
    for (const e of STEP_UP_EXEMPTIONS) {
      expect(e.op).toMatch(/^(post|put|patch|delete) \/\S+$/);
      expect(e.reason.length).toBeGreaterThan(10);
    }
    expect(isStepUpExempt('POST', '/consent/verify')).toBe(true);
    expect(isStepUpExempt('post', '/consent/verify/')).toBe(true);
    expect(isStepUpExempt('POST', '/evidence-chain/records/abc/verify')).toBe(true);
    expect(isStepUpExempt('POST', '/evidence-chain/records/a/b/verify')).toBe(false); // {param} is one segment
    expect(isStepUpExempt('DELETE', '/consent/verify')).toBe(false);                  // method-specific
    expect(isStepUpExempt('POST', '/CONSENT/VERIFY')).toBe(false);                    // case-sensitive: fails closed
    expect(isStepUpExempt('POST', '/consent/verify-all')).toBe(false);                // anchored
    expect(isStepUpExempt('POST', '/x/consent/verify')).toBe(false);
    expect(isStepUpExempt('POST', '/consent/x/revoke')).toBe(false);
  });

  test('a mounted admin-plane step-up gates mutations, passes exemptions (via baseUrl + path) and reads', async () => {
    const u = user();
    const consent = mounted(u, '/consent');
    expect((await request(consent).post('/consent/c1/revoke')).status).toBe(403);
    expect((await request(consent).delete('/consent/actor/a1')).status).toBe(403);
    expect((await request(consent).post('/consent')).status).toBe(403);
    expect((await request(consent).post('/consent/verify')).status).toBe(200);
    expect((await request(consent).get('/consent/c1')).status).toBe(200);
    const store = mounted(u, '/audit-store');
    expect((await request(store).post('/audit-store/retention/apply')).status).toBe(403);
    expect((await request(store).delete('/audit-store/retention/holds/h1')).status).toBe(403);
    const gov = mounted(u, '/v1/policy/governance');
    for (const p of ['/draft', '/p1/submit', '/p1/review', '/p1/reject', '/p1/withdraw', '/rollback', '/emergency/sweep-expired', '/p1/approve']) {
      expect((await request(gov).post(`/v1/policy/governance${p}`)).status).toBe(403);
    }
    // an exempt path under a DIFFERENT mount is not exempt there
    expect((await request(mounted(u, '/compliance')).post('/compliance/verify')).status).toBe(403);
    expect((await request(mounted(u, '/compliance')).post('/compliance/report/verify')).status).toBe(200);
  });

  test('enrolled operator: a gated admin-plane mutation needs the code, then passes', async () => {
    const { u, raw } = enrolled();
    const a = mounted(u, '/transparency');
    const r = await request(a).post('/transparency/admin/roots/generate');
    expect(r.status).toBe(401); expect(JSON.stringify(r.body)).toContain('MFA_REQUIRED');
    expect((await request(a).post('/transparency/admin/roots/generate').set('X-QODIQA-OTP', mfa.totp(raw))).status).toBe(200);
  });
});
