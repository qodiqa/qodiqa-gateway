'use strict';

const fs   = require('fs');
const os   = require('os');
const path = require('path');

function freshStore() {
  jest.resetModules();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-portal-user-store-'));
  process.env.QODIQA_PORTAL_USER_STORE_PATH = path.join(dir, 'tenant-portal-users.json');
  return require('../tenantPortalUserStore');
}

afterEach(() => {
  delete process.env.QODIQA_PORTAL_USER_STORE_PATH;
});

describe('tenantPortalUserStore — JIT provisioning', () => {
  test('first login for a new (issuer, subject, tenant) creates a record with role=tenant, enabled=true', () => {
    const store = freshStore();
    const rec = store.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-123', tenantId: 'acme', email: 'a@acme.example',
    });
    expect(rec.id).toMatch(/^pu_/);
    expect(rec.tenantId).toBe('acme');
    expect(rec.role).toBe('tenant');
    expect(rec.enabled).toBe(true);
    expect(rec.email).toBe('a@acme.example');
    expect(Object.isFrozen(rec)).toBe(true);
  });

  test('second login for the SAME (issuer, subject, tenant) returns the SAME id and updates lastLoginAt', async () => {
    const store = freshStore();
    const first = store.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-123', tenantId: 'acme', email: 'a@acme.example',
    });
    await new Promise((r) => setTimeout(r, 5));
    const second = store.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-123', tenantId: 'acme', email: 'a@acme.example',
    });
    expect(second.id).toBe(first.id);
    expect(second.createdAt).toBe(first.createdAt);
    expect(new Date(second.lastLoginAt).getTime()).toBeGreaterThanOrEqual(new Date(first.lastLoginAt).getTime());
  });

  test('the SAME idpSubject logging into a DIFFERENT tenant creates a SEPARATE record', () => {
    const store = freshStore();
    const forAcme = store.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-123', tenantId: 'acme', email: null,
    });
    const forGlobex = store.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-123', tenantId: 'globex', email: null,
    });
    expect(forAcme.id).not.toBe(forGlobex.id);
    expect(forAcme.tenantId).toBe('acme');
    expect(forGlobex.tenantId).toBe('globex');
  });

  test('persists across a fresh require() of the module (durable, not just in-memory)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-portal-user-store-'));
    process.env.QODIQA_PORTAL_USER_STORE_PATH = path.join(dir, 'tenant-portal-users.json');

    jest.resetModules();
    const store1 = require('../tenantPortalUserStore');
    const created = store1.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-999', tenantId: 'acme', email: null,
    });

    jest.resetModules();
    const store2 = require('../tenantPortalUserStore');
    const fetched = store2.getById(created.id);
    expect(fetched).not.toBeNull();
    expect(fetched.id).toBe(created.id);
  });

  test('rejects invalid input', () => {
    const store = freshStore();
    expect(() => store.findOrCreateByIdpSubject({ idpIssuer: '', idpSubject: 'x', tenantId: 'acme' })).toThrow(TypeError);
    expect(() => store.findOrCreateByIdpSubject({ idpIssuer: 'https://idp', idpSubject: '', tenantId: 'acme' })).toThrow(TypeError);
    expect(() => store.findOrCreateByIdpSubject({ idpIssuer: 'https://idp', idpSubject: 'x', tenantId: 'not valid!' })).toThrow(TypeError);
  });

  test('getById returns null for an unknown id', () => {
    const store = freshStore();
    expect(store.getById('pu_does-not-exist')).toBeNull();
  });

  test('setEnabled(false) disables a user; subsequent getById reflects it', () => {
    const store = freshStore();
    const rec = store.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-1', tenantId: 'acme', email: null,
    });
    expect(store.setEnabled(rec.id, false)).toBe(true);
    expect(store.getById(rec.id).enabled).toBe(false);
    expect(store.setEnabled('pu_unknown', false)).toBe(false);
  });

  test('a corrupt store file self-heals to an empty store rather than throwing', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-portal-user-store-'));
    const p = path.join(dir, 'tenant-portal-users.json');
    fs.writeFileSync(p, '{not valid json', 'utf8');
    process.env.QODIQA_PORTAL_USER_STORE_PATH = p;
    jest.resetModules();
    const store = require('../tenantPortalUserStore');
    expect(store.getById('anything')).toBeNull();
    // Store remains usable — a fresh record can still be created.
    const rec = store.findOrCreateByIdpSubject({
      idpIssuer: 'https://idp.example.com', idpSubject: 'user-1', tenantId: 'acme', email: null,
    });
    expect(rec.id).toMatch(/^pu_/);
  });
});

// ── session version ───────────────────────────────────────────
describe('tenantPortalUserStore — session revocation', () => {
  // The control-plane snapshot is process-wide (collection.js), so every test uses its own IdP subject.
  let seq = 0;
  function newUser(store, sub = `user-sv-${process.pid}-${Date.now()}-${++seq}`) {
    return store.findOrCreateByIdpSubject({ idpIssuer: 'https://idp.example.com', idpSubject: sub, tenantId: 'acme', email: null });
  }

  test('DD095-S1 a new / never-revoked record reads as session version 0 (no field written)', () => {
    const store = freshStore();
    const rec = newUser(store);
    expect(store.sessionVersionOf(rec)).toBe(0);
    expect(store.sessionVersionOf(null)).toBe(0);
    expect(store.sessionVersionOf({ sessionVersion: -3 })).toBe(0);
  });

  test('DD095-S2 revokeSessions increments the version and records when/why; enabled is unchanged', () => {
    const store = freshStore();
    const rec = newUser(store);
    const r1 = store.revokeSessions(rec.id, { reason: 'admin_revoke' });
    expect(r1.sessionVersion).toBe(1);
    expect(r1.sessionsRevokedReason).toBe('admin_revoke');
    expect(typeof r1.sessionsRevokedAt).toBe('string');
    expect(r1.enabled).toBe(true);
    expect(store.revokeSessions(rec.id, { reason: 'self_logout' }).sessionVersion).toBe(2);
    expect(store.sessionVersionOf(store.getById(rec.id))).toBe(2);
  });

  test('DD095-S3 revokeSessions on another user leaves this user untouched', () => {
    const store = freshStore();
    const a = newUser(store, 'user-a');
    const b = newUser(store, 'user-b');
    store.revokeSessions(a.id);
    expect(store.sessionVersionOf(store.getById(b.id))).toBe(0);
  });

  test('DD095-S4 unknown user -> null; unknown reason -> TypeError', () => {
    const store = freshStore();
    expect(store.revokeSessions('pu_unknown')).toBeNull();
    const rec = newUser(store);
    expect(() => store.revokeSessions(rec.id, { reason: 'whatever' })).toThrow(TypeError);
  });

  test('DD095-S5 disabling bumps the version, so a later RE-ENABLE does not resurrect old sessions', () => {
    const store = freshStore();
    const rec = newUser(store);
    store.setEnabled(rec.id, false);
    expect(store.sessionVersionOf(store.getById(rec.id))).toBe(1);
    store.setEnabled(rec.id, true);
    const after = store.getById(rec.id);
    expect(after.enabled).toBe(true);
    expect(store.sessionVersionOf(after)).toBe(1); // a token minted at 0 stays dead
  });

  test('DD095-S6 a later login (findOrCreate, email change) preserves the session version', () => {
    const store = freshStore();
    const sub = `user-sv6-${Date.now()}`;
    const rec = newUser(store, sub);
    store.revokeSessions(rec.id);
    const again = store.findOrCreateByIdpSubject({ idpIssuer: 'https://idp.example.com', idpSubject: sub, tenantId: 'acme', email: 'new@acme.example' });
    expect(again.id).toBe(rec.id);
    expect(store.sessionVersionOf(again)).toBe(1);
  });
});
