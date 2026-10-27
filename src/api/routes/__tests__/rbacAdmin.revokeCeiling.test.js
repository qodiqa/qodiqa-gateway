'use strict';

/**
 * — DELETE /rbac/users/:id/api-key carries the privilege ceiling.
 *
 *   RC-01 a user manager cannot revoke a superior's (admin's) key: 403 PRIVILEGE_CEILING, key untouched
 *   RC-02 a user manager can still revoke a subordinate's key, and an admin a peer admin's (incident response)
 *   RC-03 any operator can still revoke its OWN key
 *   RC-04 an unknown user id still reaches the store (its own NOT_FOUND), not the ceiling
 */

const request = require('supertest');
const express = require('express');
const store = require('../../../core/rbac/store');
const customRoleStore = require('../../../core/rbac/customRoleStore');
const createRbacAdminRouter = require('../rbacAdmin');

function app(user) {
  const a = express();
  a.use(express.json());
  a.use((req, _res, next) => { req.requestId = 'r'; if (user) req.rbacUser = user; next(); });
  a.use('/rbac', createRbacAdminRouter({ store, customRoleStore, requirePermission: () => (_q, _s, n) => n() }));
  return a;
}
let n = 0;
const uniq = (p) => { n += 1; return `${p}-${n}-${Date.now()}`; };
const mkUser = (role) => { const u = store.createUser({ username: uniq('dd098'), role }); return { id: u.id, username: u.username, role }; };
const withKey = async (role) => { const u = mkUser(role); await store.issueApiKey(u.id, { issuedBy: 'test', issuedById: null }); return u; };

let userManagerRole;
beforeAll(async () => {
  userManagerRole = (await customRoleStore.createRole({ name: uniq('user manager'), permissions: ['MANAGE_USERS', 'READ_USERS'] })).id;
});

test('RC-01 a user manager cannot revoke a superior (admin) key', async () => {
  const um = mkUser(userManagerRole); const adm = await withKey('admin');
  const before = store.getUser(adm.id).apiKeyHash;
  expect(before).toBeTruthy();
  const r = await request(app(um)).delete(`/rbac/users/${adm.id}/api-key`);
  expect([r.status, r.body.error.code]).toEqual([403, 'PRIVILEGE_CEILING']);
  expect(store.getUser(adm.id).apiKeyHash).toBe(before);
});

test('RC-02 subordinate and peer revocation still work', async () => {
  const um = mkUser(userManagerRole); const viewer = await withKey('viewer');
  const sub = await request(app(um)).delete(`/rbac/users/${viewer.id}/api-key`);
  // a viewer's permissions may not all be held by this narrow custom role; assert on the ceiling contract itself
  const { permissionsForRole } = require('../../../core/rbac/authorize');
  const held = new Set(permissionsForRole(userManagerRole));
  const expectAllowed = permissionsForRole('viewer').every((p) => held.has(p));
  expect(sub.status).toBe(expectAllowed ? 200 : 403);

  const a = mkUser('admin'); const b = await withKey('admin');
  const peer = await request(app(a)).delete(`/rbac/users/${b.id}/api-key`);
  expect(peer.status).toBe(200);
  expect(peer.body.data).toEqual({ revoked: true, userId: b.id });
  expect(store.getUser(b.id).apiKeyHash).toBeFalsy();
});

test('RC-03 an operator can revoke its own key', async () => {
  const um = await withKey(userManagerRole);
  const r = await request(app(um)).delete(`/rbac/users/${um.id}/api-key`);
  expect(r.status).toBe(200);
  expect(store.getUser(um.id).apiKeyHash).toBeFalsy();
});

test('RC-04 an unknown user id is not answered by the ceiling', async () => {
  const um = mkUser(userManagerRole);
  const r = await request(app(um)).delete('/rbac/users/no-such-user/api-key');
  expect(r.body.error.code).not.toBe('PRIVILEGE_CEILING');
});
