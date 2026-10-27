'use strict';

/**
 * — /rbac privilege ceiling and dual control.
 *
 * nobody grants what they do not hold: custom-role creation/update, user creation, role assignment and
 *          deleting/modifying a superior are refused (403 PRIVILEGE_CEILING); nobody changes their own role.
 * an API key / MFA reset for ANOTHER operator is issued over HTTP only when that operator's permissions are a
 *          strict subset of the caller's (403 PEER_CREDENTIAL_FORBIDDEN otherwise); self-rotation stays allowed;
 *          the issuer's id is recorded on the target (apiKeyIssuedById) and the creator's id (createdById).
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
const mkUser = (role) => { const u = store.createUser({ username: uniq('sec'), role }); return { id: u.id, username: u.username, role }; };

let userManagerRole;
beforeAll(async () => {
  userManagerRole = (await customRoleStore.createRole({ name: uniq('user manager'), permissions: ['MANAGE_USERS', 'READ_USERS'] })).id;
});

describe('privilege ceiling', () => {
  test('a user manager cannot create an admin, assign admin, or escalate itself', async () => {
    const um = mkUser(userManagerRole);
    const c = await request(app(um)).post('/rbac/users').send({ username: uniq('x'), role: 'admin' });
    expect([c.status, c.body.error.code]).toEqual([403, 'PRIVILEGE_CEILING']);
    const self = await request(app(um)).patch(`/rbac/users/${um.id}`).send({ role: 'admin' });
    expect([self.status, self.body.error.code]).toEqual([403, 'SELF_ROLE_CHANGE']);
    expect(store.getUser(um.id).role).toBe(userManagerRole);
    const v = mkUser('viewer');
    const up = await request(app(um)).patch(`/rbac/users/${v.id}`).send({ role: 'admin' });
    expect([up.status, up.body.error.code]).toEqual([403, 'PRIVILEGE_CEILING']);
    expect(store.getUser(v.id).role).toBe('viewer');
  });

  test('a user manager cannot mint a custom role carrying permissions it lacks, nor widen one', async () => {
    const um = mkUser(userManagerRole);
    const c = await request(app(um)).post('/rbac/roles').send({ name: uniq('keys'), permissions: ['MANAGE_KEYS'] });
    expect([c.status, c.body.error.code]).toEqual([403, 'PRIVILEGE_CEILING']);
    const u = await request(app(um)).patch(`/rbac/roles/${userManagerRole}`).send({ permissions: ['MANAGE_USERS', 'READ_USERS', 'MANAGE_KEYS'] });
    expect([u.status, u.body.error.code]).toEqual([403, 'PRIVILEGE_CEILING']);
  });

  test('a user manager cannot modify or delete a superior (admin)', async () => {
    const um = mkUser(userManagerRole); const adm = mkUser('admin');
    expect((await request(app(um)).patch(`/rbac/users/${adm.id}`).send({ enabled: false })).status).toBe(403);
    expect((await request(app(um)).delete(`/rbac/users/${adm.id}`)).status).toBe(403);
    expect(store.getUser(adm.id).enabled).toBe(true);
  });

  test('an admin (holding everything) still creates users of any built-in role; unknown permissions still 422', async () => {
    const adm = mkUser('admin');
    const c = await request(app(adm)).post('/rbac/users').send({ username: uniq('op'), role: 'operator' });
    expect(c.status).toBe(201);
    expect(store.getUser(c.body.data.user.id).createdById).toBe(adm.id);
    const bad = await request(app(adm)).post('/rbac/roles').send({ name: uniq('bad'), permissions: ['NOT_A_REAL_PERMISSION'] });
    expect([bad.status, bad.body.error.code]).toEqual([422, 'UNKNOWN_PERMISSION']);
  });
});

describe('dual control on credentials', () => {
  test('an admin cannot mint an API key for a peer admin; can for a subordinate; can rotate its own', async () => {
    const a = mkUser('admin'); const b = mkUser('admin'); const op = mkUser('operator');
    const peer = await request(app(a)).post(`/rbac/users/${b.id}/api-key`);
    expect([peer.status, peer.body.error.code]).toEqual([403, 'PEER_CREDENTIAL_FORBIDDEN']);
    expect(peer.body.error.message).toMatch(/rbac-bootstrap-key\.js --user/);
    expect(store.getUser(b.id).apiKeyHash).toBeFalsy();
    const sub = await request(app(a)).post(`/rbac/users/${op.id}/api-key`);
    expect(sub.status).toBe(201);
    expect(store.getUser(op.id).apiKeyIssuedById).toBe(a.id);
    const own = await request(app(a)).post(`/rbac/users/${a.id}/api-key`);
    expect(own.status).toBe(201);
    expect(store.getUser(a.id).apiKeyIssuedById).toBe(null);
  });

  // (PROBE-SEC01-B): the author keys a subordinate, then — holding that key — self-rotates AS the
  // subordinate. The rotation must not clear the record of who knows the key.
  test('a self-rotation inherits the previous issuer (no laundering of an author-issued key)', async () => {
    const a = mkUser('admin'); const op = mkUser('operator');
    expect((await request(app(a)).post(`/rbac/users/${op.id}/api-key`)).status).toBe(201);
    expect(store.getUser(op.id).apiKeyIssuedById).toBe(a.id);
    const issuerLabel = store.getUser(op.id).apiKeyIssuedBy;
    const launder = await request(app(op)).post(`/rbac/users/${op.id}/api-key`); // acting AS the subordinate
    expect(launder.status).toBe(201);
    expect(store.getUser(op.id).apiKeyIssuedById).toBe(a.id);
    expect(store.getUser(op.id).apiKeyIssuedBy).toBe(issuerLabel); // the label stays with the id
  });

  // no other administrative path clears provisioning provenance either.
  test('a role change and an MFA self-reset keep createdById / apiKeyIssuedById', async () => {
    const a = mkUser('admin'); const op = mkUser('operator');
    expect((await request(app(a)).post(`/rbac/users/${op.id}/api-key`)).status).toBe(201);
    const before = store.getUser(op.id);
    await request(app(a)).put(`/rbac/users/${op.id}`).send({ role: 'viewer' });
    await request(app(op)).delete(`/rbac/users/${op.id}/mfa`);
    const after = store.getUser(op.id);
    expect([after.createdById, after.apiKeyIssuedById, after.apiKeyIssuedBy]).toEqual([before.createdById, a.id, before.apiKeyIssuedBy]);
  });

  test('a user manager cannot mint a key for an auditor (not a strict subset of its own permissions)', async () => {
    const um = mkUser(userManagerRole); const aud = mkUser('auditor');
    expect((await request(app(um)).post(`/rbac/users/${aud.id}/api-key`)).status).toBe(403);
  });
});

describe('account self-protection', () => {
  test('an admin cannot disable or delete their own account; the record is unchanged', async () => {
    const me = mkUser('admin');
    mkUser('admin'); // another admin exists, so this is self-protection, not the last-admin rule
    const dis = await request(app(me)).patch(`/rbac/users/${me.id}`).send({ enabled: false });
    expect([dis.status, dis.body.error.code]).toEqual([403, 'SELF_DISABLE']);
    const del = await request(app(me)).delete(`/rbac/users/${me.id}`);
    expect([del.status, del.body.error.code]).toEqual([403, 'SELF_DELETE']);
    expect(store.getUser(me.id)).toMatchObject({ enabled: true, role: 'admin' });
  });

  test('control: another admin can disable and delete that account; self-rename still works', async () => {
    const target = mkUser('admin');
    const other = mkUser('admin');
    const ren = await request(app(target)).patch(`/rbac/users/${target.id}`).send({ username: uniq('renamed') });
    expect(ren.status).toBe(200);
    const dis = await request(app(other)).patch(`/rbac/users/${target.id}`).send({ enabled: false });
    expect(dis.status).toBe(200);
    expect(store.getUser(target.id).enabled).toBe(false);
    const del = await request(app(other)).delete(`/rbac/users/${target.id}`);
    expect(del.status).toBe(200);
    expect(store.getUser(target.id)).toBeNull();
  });
});
