'use strict';

/**
 * an OIDC bearer token authenticates POST /sign through the REAL sign router, the REAL signing-identity store and the REAL enterprise verifier
 * (only the network fetch of the JWKS is replaced).
 *   OS-01  a linked subject signs; the artifact's callerContext says credentialType oidc
 *   OS-02  refusals: unlinked subject, wrong audience, expired, alg none, HS256 confusion, unknown issuer, tampered, disabled / revoked / permission-less identity
 *   OS-03  the IdP being unreachable is 503 (not a credential failure); API keys keep working next to OIDC
 *   OS-04  the store: oidc identity needs externalIdentity, no API key for it, no duplicate link; the admin schema agrees
 *   OS-05  configuration errors surface at boot, not at the first request
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

jest.mock('../safeFetch', () => ({ fetchJson: jest.fn(), checkUrl: jest.fn(), IdpFetchError: class IdpFetchError extends Error {} }));
jest.mock('../../../../services/logger', () => { const a = jest.requireActual('../../../../services/logger'); return { ...a, emit: jest.fn() }; });

const ISS = 'https://idp.example.com/realm';
const AUD = 'qodiqa-api';
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-oidc-'));
const cfgPath = path.join(dir, 'oidc.json');
fs.writeFileSync(cfgPath, JSON.stringify({ providers: [{ id: 'main', issuer: ISS, audience: [AUD], jwksUri: 'https://idp.example.com/realm/jwks' }] }));
process.env.QODIQA_OIDC_CONFIG_PATH = cfgPath;
process.env.QODIQA_CLIENT_ID = 'default';
process.env.OPENAI_API_KEY = require('../../../../test/helpers/providerFixtureKeys').PROVIDER_FIXTURE_KEYS.openai;

const request = require('supertest');
const express = require('express');
const { fetchJson } = require('../safeFetch');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const store = require('../../signing/signingIdentityStore');
const createSignRouter = require('../../../api/routes/sign');
const attachClientIp = require('../../../../middleware/clientIp');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const oidcService = require('../oidcService');
const { createSigningIdentitySchema } = require('../../../validation/schemas/signingIdentity.schema');

const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const kp2 = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...kp.publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }] };
const b64 = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
function mint({ claims = {}, header = {}, key = kp, alg = 'RS256', sign } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const h = b64({ alg, typ: 'JWT', kid: 'k1', ...header });
  const p = b64({ iss: ISS, aud: AUD, sub: 'alice', exp: now + 600, iat: now - 5, ...claims });
  const sig = sign ? sign(`${h}.${p}`) : crypto.sign('sha256', Buffer.from(`${h}.${p}`), key.privateKey);
  return `${h}.${p}.${sig.toString('base64url')}`;
}

const { apiKey: API_KEY } = provisionTestSigningIdentity({ tenantId: 'default' });
const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
let identity;

function app() {
  oidcService._reset();
  const a = express(); a.use(attachClientIp); a.use(express.json());
  a.use('/sign', createSignRouter(() => POLICIES));
  return a;
}
const body = { request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4o-mini' } }, payload: { provider: 'openai' } };
const sign = (a, token) => request(a).post('/sign').set('Authorization', `Bearer ${token}`).send(body);

beforeAll(async () => {
  identity = await store.createSigningIdentity({ name: 'alice-oidc', tenantId: 'default', environment: 'test', permissions: ['SIGN_ARTIFACT'], credentialType: 'oidc', externalIdentity: { issuer: ISS, subject: 'alice' }, createdBy: 'JEST' });
});
beforeEach(() => { fetchJson.mockReset().mockResolvedValue(jwks); });

describe('OIDC on /sign', () => {
  test('OS-01 a linked subject signs; the evidence names the credential type', async () => {
    const res = await sign(app(), mint());
    expect(res.status).toBe(200);
    const payload = res.body.artifact.payload;
    expect(payload.callerContext).toMatchObject({ callerId: identity.id, credentialType: 'oidc' });
    expect(res.body.artifact.signature).toBeTruthy();
  });

  test('OS-02 refusals', async () => {
    const a = app();
    const refused = async (token, status = 401) => { const r = await sign(a, token); expect({ status: r.status, reason: r.body.reason }).toEqual({ status, reason: status === 401 ? 'UNAUTHORIZED' : 'FORBIDDEN' }); expect(r.body.artifact).toBeUndefined(); };
    await refused(mint({ claims: { sub: 'mallory' } }));                                                      // valid token, subject not linked: being known to the IdP grants nothing
    await refused(mint({ claims: { aud: 'someone-else' } }));
    await refused(mint({ claims: { exp: Math.floor(Date.now() / 1000) - 1000 } }));
    await refused(mint({ claims: { iss: 'https://evil.example.com' } }));
    await refused(mint({ key: kp2 }));                                                                         // signed by another key
    await refused(`${b64({ alg: 'none', typ: 'JWT' })}.${b64({ iss: ISS, aud: AUD, sub: 'alice', exp: 9999999999 })}.`);
    await refused(`${b64({ alg: 'none', typ: 'JWT' })}.${b64({ iss: ISS, aud: AUD, sub: 'alice', exp: 9999999999 })}.AAAA`);
    const pem = kp.publicKey.export({ type: 'spki', format: 'pem' });
    await refused(mint({ alg: 'HS256', sign: (input) => crypto.createHmac('sha256', pem).update(input).digest() }));
    const good = mint(); const [h, p, s] = good.split('.');
    await refused(`${h}.${b64({ iss: ISS, aud: AUD, sub: 'alice', exp: 9999999999 })}.${s}`);                 // payload swapped
    await store.updateSigningIdentity(identity.id, { enabled: false });
    await refused(good, 403);
    await store.updateSigningIdentity(identity.id, { enabled: true });
  });

  test('OS-02b a permission-less or revoked oidc identity is refused (403) exactly like an API-key one', async () => {
    const other = await store.createSigningIdentity({ name: 'bob-oidc', tenantId: 'default', environment: 'test', permissions: ['SIGN_ARTIFACT'], credentialType: 'oidc', externalIdentity: { issuer: ISS, subject: 'bob' }, createdBy: 'JEST' });
    const a = app();
    expect((await sign(a, mint({ claims: { sub: 'bob' } }))).status).toBe(200);
    await store.revokeSigningKey(other.id, { revokedBy: 'JEST', reason: 'test' });
    const r = await sign(a, mint({ claims: { sub: 'bob' } }));
    expect(r.status).toBe(403);
  });

  test('OS-03 the IdP being unreachable is 503, and API keys work beside OIDC', async () => {
    fetchJson.mockReset().mockRejectedValue(new Error('idp down'));
    const down = await sign(app(), mint({ claims: { sub: 'alice' } }));
    expect(down.status).toBe(503); expect(down.body.reason).toBe('AUTH_BACKEND_UNAVAILABLE'); expect(down.headers['retry-after']).toBeDefined();
    expect((await sign(app(), API_KEY)).status).toBe(200);
    expect((await sign(app(), 'sk_' + 'f'.repeat(64))).status).toBe(401);
  });
});

describe('store and schema', () => {
  test('OS-04', async () => {
    const mk = (over) => store.createSigningIdentity({ name: `x-${Math.random().toString(36).slice(2, 8)}`, tenantId: 'default', environment: 'test', permissions: ['SIGN_ARTIFACT'], createdBy: 'JEST', ...over });
    await expect(Promise.resolve().then(() => mk({ credentialType: 'oidc' }))).rejects.toMatchObject({ code: 'INVALID_EXTERNAL_IDENTITY' });
    await expect(Promise.resolve().then(() => mk({ externalIdentity: { issuer: ISS, subject: 'z' } }))).rejects.toMatchObject({ code: 'INVALID_EXTERNAL_IDENTITY' });                      // api-key identity with a link
    for (const bad of [{ issuer: 'http://x.example.com', subject: 's' }, { issuer: ISS, subject: '' }, { issuer: ISS, subject: 'x'.repeat(256) }, { issuer: ISS }, { issuer: ISS, subject: 's', extra: 1 }, 'str']) {
      await expect(Promise.resolve().then(() => mk({ credentialType: 'oidc', externalIdentity: bad }))).rejects.toMatchObject({ code: 'INVALID_EXTERNAL_IDENTITY' });
    }
    await expect(Promise.resolve().then(() => mk({ credentialType: 'oidc', externalIdentity: { issuer: ISS, subject: 'alice' } }))).rejects.toMatchObject({ code: 'EXTERNAL_IDENTITY_EXISTS' });
    expect(() => store.issueSigningKey(identity.id)).toThrow(/no API key/);
    expect(store.resolveByExternalIdentity(ISS, 'alice').id).toBe(identity.id);
    expect(store.resolveByExternalIdentity(ISS, 'ALICE')).toBeNull(); expect(store.resolveByExternalIdentity(`${ISS}/`, 'alice')).toBeNull(); expect(store.resolveByExternalIdentity(ISS, 5)).toBeNull();
    const ok = createSigningIdentitySchema.safeParse({ name: 'n', tenantId: 't', environment: 'test', permissions: ['SIGN_ARTIFACT'], credentialType: 'oidc', externalIdentity: { issuer: ISS, subject: 's' } });
    expect(ok.success).toBe(true);
    expect(createSigningIdentitySchema.safeParse({ name: 'n', tenantId: 't', environment: 'test', permissions: ['SIGN_ARTIFACT'], credentialType: 'oidc' }).success).toBe(false);
    expect(createSigningIdentitySchema.safeParse({ name: 'n', tenantId: 't', environment: 'test', permissions: ['SIGN_ARTIFACT'], externalIdentity: { issuer: ISS, subject: 's' } }).success).toBe(false);
  });
});

describe('configuration', () => {
  test('OS-05 a bad file or provider fails at boot; no config means federation off', () => {
    const keep = process.env.QODIQA_OIDC_CONFIG_PATH;
    try {
      oidcService._reset(); process.env.QODIQA_OIDC_CONFIG_PATH = path.join(dir, 'missing.json');
      expect(() => oidcService.assertConfigured()).toThrow(/cannot be read/);
      const bad = path.join(dir, 'bad.json'); fs.writeFileSync(bad, JSON.stringify({ providers: [{ id: 'x', issuer: 'http://insecure.example.com', audience: ['a'], jwksUri: 'https://x/y' }] }));
      oidcService._reset(); process.env.QODIQA_OIDC_CONFIG_PATH = bad;
      expect(() => oidcService.assertConfigured()).toThrow(/https/);
      oidcService._reset(); delete process.env.QODIQA_OIDC_CONFIG_PATH;
      expect(oidcService.isEnabled()).toBe(false); expect(oidcService.federation(store)).toBeNull();
      // plain http is accepted only with the explicit development opt-in, and never in production
      const dev = path.join(dir, 'dev.json'); fs.writeFileSync(dev, JSON.stringify({ providers: [{ id: 'dev', issuer: 'http://localhost:8080/realms/t', audience: ['a'], jwksUri: 'http://localhost:8080/certs' }] }));
      oidcService._reset(); process.env.QODIQA_OIDC_CONFIG_PATH = dev;
      expect(() => oidcService.assertConfigured()).toThrow();
      process.env.QODIQA_OIDC_ALLOW_INSECURE = 'true'; oidcService._reset(); expect(() => oidcService.assertConfigured()).not.toThrow();
      process.env.NODE_ENV = 'production'; oidcService._reset(); expect(() => oidcService.assertConfigured()).toThrow();
    } finally { process.env.NODE_ENV = 'test'; delete process.env.QODIQA_OIDC_ALLOW_INSECURE; process.env.QODIQA_OIDC_CONFIG_PATH = keep; oidcService._reset(); }
  });
});
