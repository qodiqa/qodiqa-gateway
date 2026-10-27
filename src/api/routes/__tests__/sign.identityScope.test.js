'use strict';
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys');

/**
 * POST /sign:
 * one canonical route resolver: allowedProviders and the provider-enabled
 *          checks run for EVERY path the router maps to the AI handler (aliases,
 *          trailing slash, case, encodings, dot segments, backslashes);
 * (D2) auth-failure bucket: repeated bad signing keys → 429;
 * (D5) an expired signing key is refused (401 API_KEY_EXPIRED); an
 *          expiring one works and is flagged (X-QODIQA-Key-Expires).
 */

const request = require('supertest');
const express = require('express');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const PROVIDER_ENV_KEYS = ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL'];
const { apiKey: RESTRICTED } = provisionTestSigningIdentity({ tenantId: 'default', allowedProviders: ['openai'] });

function loadApp({ lockout } = {}) {
  jest.resetModules();
  for (const k of PROVIDER_ENV_KEYS) delete process.env[k];
  process.env.OPENAI_API_KEY = PROVIDER_FIXTURE_KEYS.openai;
  process.env.ANTHROPIC_API_KEY = PROVIDER_FIXTURE_KEYS.anthropic;
  process.env.QODIQA_CLIENT_ID = 'default';
  const createSignRouter = require('../sign');
  const { validateAndPrepare } = require('../../../../services/policy/loader');
  const policies = validateAndPrepare({ policies: [{ id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
  let _authLockout;
  if (lockout) {
    const { createAuthLockout } = require('../../../core/authLockout');
    const { MemoryStorage } = require('../../../core/authLockout/storage');
    _authLockout = createAuthLockout({
      authLockoutEnabled: true, authLockoutMaxFailures: 3, authLockoutFailureWindowMs: 60_000, authLockoutDurationMs: 300_000,
      authLockoutBackoffMinMs: 0, authLockoutBackoffMaxMs: 0, authLockoutCredentialHashBytes: 16,
    }, { _storage: new MemoryStorage(), namespace: 'sign' });
  }
  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => policies, { _authLockout }));
  return app;
}
const sign = (app, token, path, provider) => request(app).post('/sign').set('Authorization', `Bearer ${token}`)
  .send({ request: { method: 'POST', path, body: { prompt: 'hi' } }, payload: provider ? { provider } : undefined });

afterAll(() => { for (const k of PROVIDER_ENV_KEYS) delete process.env[k]; });

describe('provider scope on every AI alias', () => {
  const ALIASES = ['/ai/chat', '/v1/ai/chat', '/ai/chat/stream', '/v1/ai/chat/stream', '/ai/chat/', '/AI/Chat', '/V1/Ai/Chat/Stream',
    '/%61i/chat', '/ai%2Fchat', '/%2561i/chat', '/x/../ai/chat', '/ai/./chat', '\\ai\\chat', '//ai//chat'];

  test.each(ALIASES)('%s: a provider outside allowedProviders → 403 SCOPE_PROVIDER_DENIED', async (p) => {
    const r = await sign(loadApp(), RESTRICTED, p, 'anthropic');
    expect(r.status).toBe(403);
    expect(r.body.reason).toBe('SCOPE_PROVIDER_DENIED');
  });

  test.each(['/ai/chat', '/V1/AI/CHAT/', '/%61i/chat'])('%s: an allowed provider signs', async (p) => {
    const r = await sign(loadApp(), RESTRICTED, p, 'openai');
    expect(r.status).toBe(200);
  });

  test.each(['/AI/Chat', '/v1/ai/chat/'])('%s: an unknown provider is refused (provider checks run)', async (p) => {
    const r = await sign(loadApp(), RESTRICTED, p, 'not-a-real-provider');
    expect(r.status).toBe(400);
    expect(r.body.reason).toBe('PROVIDER_NOT_SUPPORTED');
  });

  test('an undecodable path is treated as the AI route', async () => {
    const r = await sign(loadApp(), RESTRICTED, '/ai/chat%E0%A4%A', 'anthropic');
    expect(r.status).toBe(403);
  });

  test('a non-AI path is unaffected (generic signing)', async () => {
    const r = await sign(loadApp(), RESTRICTED, '/orders/create', undefined);
    expect(r.status).toBe(200);
  });
});

describe('(D2) — /sign auth-failure bucket', () => {
  test('bad keys: 401 up to the threshold, then 429 AUTH_LOCKED_OUT (valid key from the locked source too)', async () => {
    const app = loadApp({ lockout: true });
    for (let i = 0; i < 3; i++) expect((await sign(app, `sk_bad_${i}`, '/orders/create')).status).toBe(401);
    const locked = await sign(app, 'sk_bad_x', '/orders/create');
    expect(locked.status).toBe(429);
    expect(JSON.stringify(locked.body)).toContain('AUTH_LOCKED_OUT');
    expect((await sign(app, RESTRICTED, '/orders/create')).status).toBe(429);
  });

  test('a success resets nothing it should not: a valid key before the threshold still signs', async () => {
    const app = loadApp({ lockout: true });
    for (let i = 0; i < 2; i++) await sign(app, `sk_bad_${i}`, '/orders/create');
    expect((await sign(app, RESTRICTED, '/orders/create')).status).toBe(200);
  });
});

describe('(D5) — signing-key expiry', () => {
  const DAY = 86_400_000;
  let nowSpy;
  afterEach(() => { if (nowSpy) nowSpy.mockRestore(); nowSpy = null; });

  test('an expiring key (≤14 d left) works and is flagged', async () => {
    const app = loadApp();
    const real = Date.now();
    nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => real + 80 * DAY);
    const r = await sign(app, RESTRICTED, '/orders/create');
    expect(r.status).toBe(200);
    expect(r.headers['x-qodiqa-key-expires']).toBeTruthy();
  });

  test('an expired key → 401 API_KEY_EXPIRED', async () => {
    const app = loadApp();
    const real = Date.now();
    nowSpy = jest.spyOn(Date, 'now').mockImplementation(() => real + 91 * DAY);
    const r = await sign(app, RESTRICTED, '/orders/create');
    expect(r.status).toBe(401);
    expect(JSON.stringify(r.body)).toContain('API_KEY_EXPIRED');
  });
});
