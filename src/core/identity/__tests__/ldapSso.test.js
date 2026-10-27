'use strict';

/**
 * LDAP / Active Directory sign-in through the real router, a fake directory and the real RBAC store: link, disabled user, lockout, generic refusals, session token accepted
 * by the operator federation (same token path as SAML), public-route limits.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');
const express = require('express');

jest.mock('../../../../services/logger', () => { const a = jest.requireActual('../../../../services/logger'); return { ...a, emit: jest.fn() }; });

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-ldap-sso-'));
process.env.QODIQA_MAC_KEYS_PATH = path.join(dir, 'mac-keys.json');
process.env.QODIQA_KEYS_PATH = path.join(dir, 'keys.json');
process.env.QODIQA_KEY_ENCRYPTION_KEY = 'a'.repeat(64);
process.env.QODIQA_RBAC_STORE_PATH = path.join(dir, 'rbac.json');
process.env.QODIQA_LDAP_CONFIG_PATH = path.join(dir, 'ldap.json');
process.env.LDAP_SVC_PASSWORD = 'svc-secret-for-tests';
fs.writeFileSync(process.env.QODIQA_LDAP_CONFIG_PATH, JSON.stringify({ providers: [{ id: 'corp', url: 'ldaps://dir.example.test:636', baseDn: 'dc=example,dc=test', bindDn: 'cn=svc,dc=example,dc=test', bindPasswordEnv: 'LDAP_SVC_PASSWORD' }] }));

const ext = require('../extensionPoint');
const ldapService = require('../ldapService');
const operatorFederation = require('../operatorFederation');
const rbacStore = require('../../rbac/store');
const { createLdapAuthRouter } = require('../../../api/routes/ldapAuth');
const { createLimiter } = require('../../../api/routes/samlAuth');

const USERS = { carol: { dn: 'uid=carol,dc=example,dc=test', password: 'right-password', uuid: 'uuid-carol' }, dave: { dn: 'uid=dave,dc=example,dc=test', password: 'dave-pw', uuid: 'uuid-dave' } };
function factory() {
  return {
    async bind(dn, pw) { if (dn === 'cn=svc,dc=example,dc=test' ? pw === process.env.LDAP_SVC_PASSWORD : Object.values(USERS).some((u) => u.dn === dn && u.password === pw)) return; const e = new Error('bad'); e.name = 'InvalidCredentialsError'; throw e; },
    async search(base, o) { const m = /uid=([^)]*)\)\)$/.exec(o.filter); const u = m && USERS[m[1]]; return { searchEntries: u ? [{ dn: u.dn, entryUUID: u.uuid }] : [] }; },
    async unbind() {},
  };
}

let app;
beforeAll(async () => {
  expect(ext.get()).toBeTruthy();
  ldapService._reset(); ldapService._loadWith(process.env, factory);
  await rbacStore.createUser({ username: 'ldap-carol', role: 'admin', externalIdentity: { issuer: 'ldap:corp', subject: 'uuid-carol' } });
  await rbacStore.createUser({ username: 'ldap-dave', role: 'viewer', externalIdentity: { issuer: 'ldap:corp', subject: 'uuid-dave' } });
  app = express();
  app.use('/auth/ldap', createLdapAuthRouter({ limiter: createLimiter({ max: 1000 }) }));
  const fed = operatorFederation.create(rbacStore);
  app.get('/admin/whoami', async (req, res) => {
    const t = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!fed || !fed.accepts(t)) return res.status(401).json({});
    const r = await fed.resolve(t);
    return r.ok ? res.json({ id: r.operator.id, role: r.operator.role, via: r.via }) : res.status(401).json({ reason: r.reason });
  });
});
afterAll(() => { ldapService._reset(); });

const login = (body) => request(app).post('/auth/ldap/login').send(body);

describe('ldap sign-in', () => {
  test('LS-01 a linked user with the right password gets a session token the operator federation accepts; no group/role is read from the directory', async () => {
    const r = await login({ provider: 'corp', username: 'carol', password: 'right-password' });
    expect(r.status).toBe(200);
    expect(r.body.data).toMatchObject({ tokenType: 'Bearer', assured: false, user: { username: 'ldap-carol', role: 'admin' } });
    expect(r.headers['cache-control']).toMatch(/no-store/);
    const who = await request(app).get('/admin/whoami').set('Authorization', `Bearer ${r.body.data.token}`);
    expect(who.body).toMatchObject({ role: 'admin', via: 'session' });
  });

  test('LS-02 wrong password, unknown user, empty password, wrong shapes: the same generic 401 / 400 and no token', async () => {
    for (const body of [{ provider: 'corp', username: 'carol', password: 'nope' }, { provider: 'corp', username: 'ghost', password: 'x' }, { provider: 'corp', username: 'carol', password: '' }]) {
      const r = await login(body); expect(r.status).toBe(401); expect(r.body.error.code).toBe('AUTHENTICATION_FAILED'); expect((r.body.data || {}).token).toBeUndefined();
    }
    expect((await login({ provider: 'corp', username: 'carol' })).status).toBe(400);
    expect((await login({ provider: 'corp', username: ['carol'], password: 'x' })).status).toBe(400);
    expect((await request(app).post('/auth/ldap/login').send('[]')).status).toBe(400);
    expect((await login({ provider: 'unknown', username: 'carol', password: 'right-password' })).status).toBe(404);
  });

  test('LS-03 a directory user that is not linked, or whose account is disabled, gets nothing (no automatic account creation)', async () => {
    USERS.erin = { dn: 'uid=erin,dc=example,dc=test', password: 'erin-pw', uuid: 'uuid-erin' };
    expect((await login({ provider: 'corp', username: 'erin', password: 'erin-pw' })).status).toBe(401);
    expect(rbacStore.resolveByExternalIdentity('ldap:corp', 'uuid-erin')).toBeNull();
    const d = await rbacStore.getUserByUsername('ldap-dave');
    await rbacStore.updateUser(d.id, { enabled: false });
    expect((await login({ provider: 'corp', username: 'dave', password: 'dave-pw' })).status).toBe(401);
    await rbacStore.updateUser(d.id, { enabled: true });
    expect((await login({ provider: 'corp', username: 'dave', password: 'dave-pw' })).status).toBe(200);
  });

  test('LS-04 disabling or unlinking the user ends an existing session at once', async () => {
    const t = (await login({ provider: 'corp', username: 'dave', password: 'dave-pw' })).body.data.token;
    expect((await request(app).get('/admin/whoami').set('Authorization', `Bearer ${t}`)).status).toBe(200);
    const d = await rbacStore.getUserByUsername('ldap-dave');
    await rbacStore.updateUser(d.id, { externalIdentity: { issuer: 'ldap:corp', subject: 'uuid-other' } });
    expect((await request(app).get('/admin/whoami').set('Authorization', `Bearer ${t}`)).status).toBe(401);
    await rbacStore.updateUser(d.id, { externalIdentity: { issuer: 'ldap:corp', subject: 'uuid-dave' } });
  });

  test('LS-05 five failures lock the (provider, username) pair for the window, even for the right password; another user is unaffected; success resets', async () => {
    const now = Date.now();
    for (let i = 0; i < ldapService.MAX_FAILURES; i++) expect((await ldapService.login('corp', 'carol', 'bad', { rbacStore, now })).ok).toBe(false);
    expect((await ldapService.login('corp', 'carol', 'right-password', { rbacStore, now: now + 1000 })).reason).toBe('LDAP_LOCKED');
    expect((await ldapService.login('corp', 'dave', 'dave-pw', { rbacStore, now: now + 1000 })).ok).toBe(true);
    expect((await ldapService.login('corp', 'carol', 'right-password', { rbacStore, now: now + ldapService.LOCK_WINDOW_MS + 5000 })).ok).toBe(true);
  });

  test('LS-06 a directory outage is 503 and does not count toward the lockout; the router limiter answers 429', async () => {
    ldapService._reset(); ldapService._loadWith(process.env, () => ({ async bind() { throw new Error('ECONNREFUSED'); }, async unbind() {} }));
    const r = await login({ provider: 'corp', username: 'carol', password: 'right-password' });
    expect(r.status).toBe(503); expect(r.headers['retry-after']).toBeDefined();
    ldapService._reset(); ldapService._loadWith(process.env, factory);
    const limited = express(); limited.use('/auth/ldap', createLdapAuthRouter({ limiter: createLimiter({ max: 3 }) }));
    const codes = []; for (let i = 0; i < 5; i++) codes.push((await request(limited).post('/auth/ldap/login').send({ provider: 'corp', username: 'x', password: 'y' })).status);
    expect(codes.slice(0, 3)).not.toContain(429); expect(codes.slice(3)).toEqual([429, 429]);
  });

  test('LS-07 LDAP off (no config path) means no provider: 404', async () => {
    const saved = process.env.QODIQA_LDAP_CONFIG_PATH; delete process.env.QODIQA_LDAP_CONFIG_PATH;
    try { ldapService._reset(); expect(ldapService.isEnabled()).toBe(false); expect((await login({ provider: 'corp', username: 'carol', password: 'right-password' })).status).toBe(404); }
    finally { process.env.QODIQA_LDAP_CONFIG_PATH = saved; ldapService._reset(); ldapService._loadWith(process.env, factory); }
  });
  test('LS-08 the lockout counter is one per account: case, compatibility forms and spacing do not give a fresh budget (F10V-01)', async () => {
    const now = Date.now();
    for (let i = 0; i < ldapService.MAX_FAILURES; i++) await ldapService.login('corp', 'dave', 'bad', { rbacStore, now });
    for (const alias of ['DAVE', 'Dave', 'ｄａｖｅ', ' dave', 'dave ']) expect((await ldapService.login('corp', alias, 'dave-pw', { rbacStore, now: now + 1000 })).reason).toBe('LDAP_LOCKED');
    expect((await ldapService.login('corp', 'dave', 'dave-pw', { rbacStore, now: now + ldapService.LOCK_WINDOW_MS + 5000 })).ok).toBe(true);
  });
});
