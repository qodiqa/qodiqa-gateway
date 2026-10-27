'use strict';

/**
 * single sign-on for operators and second-factor assurance for non-operator identities.
 *   SS-01  an OIDC bearer token authenticates an operator linked to it (role from the RBAC user); refusals
 *   SS-02  MFA step-up: an IdP-vouched recent second factor replaces the TOTP; anything less leaves the TOTP rule in force
 *   SS-03  the RBAC store: link validation, uniqueness, unlink, no cross-account resolution
 *   SS-04  tenant portal: assurance function (amr / acr / auth_time age), fail closed
 *   SS-05  signing identities with requireAssurance: refused without the provider's assurance
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

jest.mock('../safeFetch', () => ({ fetchJson: jest.fn(), checkUrl: jest.fn(), IdpFetchError: class IdpFetchError extends Error {} }));
jest.mock('../../../../services/logger', () => { const a = jest.requireActual('../../../../services/logger'); return { ...a, emit: jest.fn() }; });

const ISS = 'https://idp.example.com/realm';
const AUD = 'qodiqa-api';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-sso-'));
const cfgPath = path.join(dir, 'oidc.json');
fs.writeFileSync(cfgPath, JSON.stringify({ providers: [{ id: 'main', issuer: ISS, audience: [AUD], jwksUri: 'https://idp.example.com/realm/jwks', assurance: { amr: ['mfa', 'otp'], acr: ['urn:strong'], maxAuthAgeSec: 300 } }] }));
process.env.QODIQA_OIDC_CONFIG_PATH = cfgPath;
process.env.QODIQA_CLIENT_ID = 'default';
process.env.OPENAI_API_KEY = require('../../../../test/helpers/providerFixtureKeys').PROVIDER_FIXTURE_KEYS.openai;
process.env.QODIQA_OPS_MFA_REQUIRED = 'true';

const request = require('supertest');
const express = require('express');
const { fetchJson } = require('../safeFetch');
const oidcService = require('../oidcService');
const rbacStore = require('../../rbac/store');
const mfa = require('../../rbac/mfa');
const { createOpsAuthMiddleware } = require('../../../middleware/opsAuth');
const { createMfaStepUp } = require('../../../middleware/mfaStepUp');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const signingStore = require('../../signing/signingIdentityStore');
const createSignRouter = require('../../../api/routes/sign');
const attachClientIp = require('../../../../middleware/clientIp');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const assurance = require('../assurance');
const { createUserSchema, updateUserSchema } = require('../../../validation/schemas/rbac.schema');

const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...kp.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }] };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const nowSec = () => Math.floor(Date.now() / 1000);
function mint(claims = {}) {
  const h = b64({ alg: 'RS256', typ: 'JWT', kid: 'k1' }); const p = b64({ iss: ISS, aud: AUD, sub: 'op-1', exp: nowSec() + 600, iat: nowSec() - 5, ...claims });
  return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), kp.privateKey).toString('base64url')}`;
}

let admin; let viewer;
function opsApp() {
  oidcService._reset();
  const a = express(); a.use(express.json()); a.use(attachClientIp);
  a.use(createOpsAuthMiddleware({}, rbacStore, undefined, { federation: oidcService.operatorFederation(rbacStore) }));
  a.get('/whoami', (req, res) => res.json({ id: req.rbacUser.id, role: req.rbacUser.role, method: req.operatorAuthMethod, sso: req.operatorSso || null }));
  a.post('/change', createMfaStepUp({ mfa }), (req, res) => res.json({ changed: true }));
  return a;
}
const get = (a, token) => request(a).get('/whoami').set('Authorization', `Bearer ${token}`);
const post = (a, token) => request(a).post('/change').set('Authorization', `Bearer ${token}`).send({});

beforeAll(async () => {
  rbacStore._reset && rbacStore._reset();
  admin = await rbacStore.createUser({ username: 'sso-admin', role: 'admin', externalIdentity: { issuer: ISS, subject: 'op-1' } });
  viewer = await rbacStore.createUser({ username: 'sso-viewer', role: 'viewer', externalIdentity: { issuer: ISS, subject: 'op-2' } });
});
beforeEach(() => { fetchJson.mockReset().mockResolvedValue(jwks); });

describe('operator single sign-on', () => {
  test('SS-01 a linked operator authenticates with a bearer token; role comes from the RBAC user', async () => {
    const a = opsApp();
    expect((await get(a, mint())).body).toMatchObject({ id: admin.id, role: 'admin', method: 'oidc', sso: { providerId: 'main', assured: false } });
    expect((await get(a, mint({ sub: 'op-2' }))).body).toMatchObject({ id: viewer.id, role: 'viewer' });
    for (const [token, status] of [[mint({ sub: 'nobody' }), 401], [mint({ exp: nowSec() - 1000 }), 401], [mint({ aud: 'x' }), 401], [mint({ iss: 'https://evil.example.com' }), 401], ['ok_' + 'a'.repeat(64), 401]]) {
      expect((await get(a, token)).status).toBe(status);
    }
    await rbacStore.updateUser(viewer.id, { enabled: false });
    expect((await get(a, mint({ sub: 'op-2' }))).status).toBe(401);
    await rbacStore.updateUser(viewer.id, { enabled: true });
    fetchJson.mockReset().mockRejectedValue(new Error('down'));
    const down = await get(opsApp(), mint());
    expect(down.status).toBe(503); expect(down.body.error ? down.body.error.code : down.body.code).toBe('AUTH_BACKEND_UNAVAILABLE');
  });

  test('SS-02 step-up: a recent IdP-vouched second factor is accepted, anything less leaves the TOTP rule in force', async () => {
    const a = opsApp();
    const strong = mint({ amr: ['pwd', 'mfa'], auth_time: nowSec() - 30 });
    expect((await get(a, strong)).body.sso.assured).toBe(true);
    expect((await post(a, strong)).status).toBe(200);
    expect((await post(a, mint({ acr: 'urn:strong', auth_time: nowSec() - 30 }))).status).toBe(200);
    for (const weak of [mint(), mint({ amr: ['pwd'], auth_time: nowSec() - 30 }), mint({ amr: ['mfa'] }), mint({ amr: ['mfa'], auth_time: nowSec() - 4000 }), mint({ amr: ['mfa'], auth_time: nowSec() + 4000 }), mint({ acr: 'urn:weak', auth_time: nowSec() })]) {
      const r = await post(a, weak);
      expect(r.status).toBe(403); expect(r.body.error ? r.body.error.code : r.body.code).toBe('MFA_ENROLLMENT_REQUIRED');         // no TOTP enrolled: the normal rule applies
    }
  });
});

describe('RBAC store link', () => {
  test('SS-03', async () => {
    const bad = async (ext, code) => expect(Promise.resolve().then(() => rbacStore.createUser({ username: `u${Math.random().toString(36).slice(2, 8)}`, role: 'viewer', externalIdentity: ext }))).rejects.toMatchObject({ code });
    await bad({ issuer: ISS, subject: 'op-1' }, 'EXTERNAL_IDENTITY_EXISTS');
    await bad({ issuer: 'ftp://x', subject: 's' }, 'INVALID_EXTERNAL_IDENTITY'); await bad({ issuer: ISS, subject: '' }, 'INVALID_EXTERNAL_IDENTITY'); await bad({ issuer: ISS }, 'INVALID_EXTERNAL_IDENTITY'); await bad('x', 'INVALID_EXTERNAL_IDENTITY');
    expect(rbacStore.resolveByExternalIdentity(ISS, 'op-1').id).toBe(admin.id);
    expect(rbacStore.resolveByExternalIdentity(ISS, 'OP-1')).toBeNull(); expect(rbacStore.resolveByExternalIdentity(`${ISS}/`, 'op-1')).toBeNull(); expect(rbacStore.resolveByExternalIdentity(ISS, 7)).toBeNull();
    await expect(Promise.resolve().then(() => rbacStore.updateUser(viewer.id, { externalIdentity: { issuer: ISS, subject: 'op-1' } }))).rejects.toMatchObject({ code: 'EXTERNAL_IDENTITY_EXISTS' });
    await rbacStore.updateUser(viewer.id, { externalIdentity: null });
    expect(rbacStore.resolveByExternalIdentity(ISS, 'op-2')).toBeNull();
    await rbacStore.updateUser(viewer.id, { externalIdentity: { issuer: ISS, subject: 'op-2' } });
    expect(rbacStore.resolveByExternalIdentity(ISS, 'op-2').id).toBe(viewer.id);
    expect(createUserSchema.safeParse({ username: 'a', role: 'viewer', externalIdentity: { issuer: ISS, subject: 's' } }).success).toBe(true);
    expect(updateUserSchema.safeParse({ externalIdentity: null }).success).toBe(true);
    expect(updateUserSchema.safeParse({}).success).toBe(false);
  });
});

describe('portal assurance', () => {
  test('SS-04', () => {
    const env = {}; const now = Date.now(); const t = Math.floor(now / 1000);
    expect(assurance.required(env)).toBe(false); expect(assurance.required({ QODIQA_PORTAL_REQUIRE_MFA: 'true' })).toBe(true);
    expect(assurance.portalAssured({ amr: ['pwd', 'otp'], auth_time: t - 10 }, env, now)).toBe(true);
    expect(assurance.portalAssured({ amr: ['hwk'], auth_time: t - 10 }, env, now)).toBe(true);
    expect(assurance.portalAssured({ amr: ['pwd'], auth_time: t - 10 }, env, now)).toBe(false);
    expect(assurance.portalAssured({ amr: ['mfa'] }, env, now)).toBe(false);                                   // no auth_time
    expect(assurance.portalAssured({ amr: ['mfa'], auth_time: t - 2000 }, env, now)).toBe(false);              // older than the default 900 s
    expect(assurance.portalAssured({ amr: ['mfa'], auth_time: t - 2000 }, { QODIQA_PORTAL_MFA_MAX_AGE_SEC: '3600' }, now)).toBe(true);
    expect(assurance.portalAssured({ acr: 'urn:x', auth_time: t }, { QODIQA_PORTAL_MFA_ACR: 'urn:x,urn:y' }, now)).toBe(true);
    expect(assurance.portalAssured({ amr: 'mfa', auth_time: t }, env, now)).toBe(false);                        // amr must be a list
    expect(assurance.portalAssured(null, env, now)).toBe(false);
    const ext = require('../extensionPoint'); ext._set(null);
    try { expect(assurance.portalAssured({ amr: ['mfa'], auth_time: t }, env, now)).toBe(false); } finally { ext._set(undefined); }         // module absent: fail closed
  });
});

describe('signing identity requireAssurance', () => {
  test('SS-05', async () => {
    provisionTestSigningIdentity({ tenantId: 'default' });
    const strict = await signingStore.createSigningIdentity({ name: 'strict-oidc', tenantId: 'default', environment: 'test', permissions: ['SIGN_ARTIFACT'], credentialType: 'oidc', externalIdentity: { issuer: ISS, subject: 'strict' }, requireAssurance: true, createdBy: 'JEST' });
    await expect(Promise.resolve().then(() => signingStore.createSigningIdentity({ name: 'bad-assur', tenantId: 'default', environment: 'test', permissions: ['SIGN_ARTIFACT'], requireAssurance: true, createdBy: 'JEST' }))).rejects.toMatchObject({ code: 'INVALID_REQUIRE_ASSURANCE' });
    expect(strict.requireAssurance).toBe(true);
    oidcService._reset();
    const a = express(); a.use(attachClientIp); a.use(express.json());
    a.use('/sign', createSignRouter(() => validateAndPrepare({ policies: [{ id: 'P', type: 'REQUIRE_CONSENT', priority: 1, enabled: true, config: { requireValidArtifact: true } }] })));
    const body = { request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4o-mini' } }, payload: { provider: 'openai' } };
    const sign = (t) => request(a).post('/sign').set('Authorization', `Bearer ${t}`).send(body);
    expect((await sign(mint({ sub: 'strict' }))).status).toBe(403);                                           // valid token, no assurance
    expect((await sign(mint({ sub: 'strict', amr: ['mfa'], auth_time: nowSec() - 10 }))).status).toBe(200);
    await signingStore.updateSigningIdentity(strict.id, { requireAssurance: false });
    expect((await sign(mint({ sub: 'strict' }))).status).toBe(200);
  });
});
