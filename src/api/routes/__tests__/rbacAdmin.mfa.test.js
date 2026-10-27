'use strict';

/**
 * /rbac MFA endpoints and the safe projections.
 * The mount-level step-up is tested in src/middleware/__tests__/mfaStepUp.test.js
 * and its presence on every S1 mutation in scripts/security/__tests__/routeGuardRegistry.test.js.
 */

const request = require('supertest');
const express = require('express');
const store = require('../../../core/rbac/store');
const mfa = require('../../../core/rbac/mfa');
const createRbacAdminRouter = require('../rbacAdmin');

function app(user) {
  const a = express();
  a.use(express.json());
  a.use((req, _res, next) => { req.requestId = 'r'; if (user) req.rbacUser = user; next(); });
  a.use('/rbac', createRbacAdminRouter({ store, customRoleStore: { listRoles: () => [] }, requirePermission: () => (_q, _s, n) => n() }));
  return a;
}
let n = 0;
const mk = () => { n += 1; const u = store.createUser({ username: `rbac-mfa-${n}-${Date.now()}`, role: 'admin' }); return { id: u.id, username: u.username, role: 'admin' }; };

test('enrol → confirm → status; secret and codes only in the one-time responses', async () => {
  const u = mk(); const a = app(u);
  const e = await request(a).post('/rbac/me/mfa/enroll');
  expect(e.status).toBe(201);
  expect(e.headers['cache-control']).toBe('no-store');
  const secret = e.body.data.secret;
  expect(e.body.data.otpauthUri).toContain('otpauth://totp/');
  const c = await request(a).post('/rbac/me/mfa/confirm').send({ code: mfa.totp(mfa.base32Decode(secret)) });
  expect(c.status).toBe(200);
  expect(c.body.data.recoveryCodes).toHaveLength(10);
  const s = await request(a).get('/rbac/me/mfa');
  expect(s.body.data).toMatchObject({ enrolled: true, remainingRecoveryCodes: 10 });
  expect(JSON.stringify(s.body)).not.toContain(secret);
  const list = await request(a).get(`/rbac/users/${u.id}`);
  expect(list.body.data.user.mfaEnabled).toBe(true);
  expect(JSON.stringify(list.body)).not.toContain(secret);
  expect(list.body.data.user).not.toHaveProperty('mfa');
});

test('confirm with a wrong code → 401; enrol again once enrolled → 409', async () => {
  const u = mk(); const a = app(u);
  const { body } = await request(a).post('/rbac/me/mfa/enroll');
  expect((await request(a).post('/rbac/me/mfa/confirm').send({ code: '000000' })).status).toBe(401);
  await request(a).post('/rbac/me/mfa/confirm').send({ code: mfa.totp(mfa.base32Decode(body.data.secret)) });
  expect((await request(a).post('/rbac/me/mfa/enroll')).status).toBe(409);
});

test('admin reset clears a SUBORDINATE user’s MFA', async () => {
  // the target must hold strictly fewer permissions than the caller.
  n += 1; const t = store.createUser({ username: `rbac-mfa-op-${n}-${Date.now()}`, role: 'operator' });
  const target = { id: t.id, username: t.username, role: 'operator' }; const admin = mk();
  const { secret } = mfa.beginEnrollment(target);
  mfa.confirmEnrollment(target, mfa.totp(mfa.base32Decode(secret)));
  const r = await request(app(admin)).delete(`/rbac/users/${target.id}/mfa`);
  expect(r.status).toBe(200);
  expect(mfa.status(target.id).enrolled).toBe(false);
  expect((await request(app(admin)).delete('/rbac/users/nope/mfa')).status).toBe(404);
});

test('an admin cannot reset a PEER admin’s MFA (403 PEER_CREDENTIAL_FORBIDDEN, MFA untouched)', async () => {
  const target = mk(); const admin = mk();
  const { secret } = mfa.beginEnrollment(target);
  mfa.confirmEnrollment(target, mfa.totp(mfa.base32Decode(secret)));
  const r = await request(app(admin)).delete(`/rbac/users/${target.id}/mfa`);
  expect([r.status, r.body.error.code]).toEqual([403, 'PEER_CREDENTIAL_FORBIDDEN']);
  expect(mfa.status(target.id).enrolled).toBe(true);
});

test('no operator identity (shared ops token) → 403 on self-service MFA', async () => {
  expect((await request(app(null)).post('/rbac/me/mfa/enroll')).status).toBe(403);
});

test('API-key issue returns expiry + previous-key grace (D5); the user view shows the expiry', async () => {
  const u = mk(); const a = app(u);
  const first = await request(a).post(`/rbac/users/${u.id}/api-key`);
  expect(first.status).toBe(201);
  expect(first.body.data.expiresAt).toBeTruthy();
  expect(first.body.data.previousKeyGraceUntil).toBeNull();
  const second = await request(a).post(`/rbac/users/${u.id}/api-key`);
  expect(second.body.data.previousKeyGraceUntil).toBeTruthy();
  const view = await request(a).get(`/rbac/users/${u.id}`);
  expect(view.body.data.user.apiKeyExpiresAt).toBe(second.body.data.expiresAt);
});
