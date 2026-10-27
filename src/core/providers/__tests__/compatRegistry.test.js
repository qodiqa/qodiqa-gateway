'use strict';

/**
 * dynamic registry of OpenAI-compatible providers.
 *   CR-01  validation (id, https public host, apiKeyEnv shape, models, bounds, unknown fields)
 *   CR-02  register / update / disable / enable, no delete, revision, never a key in a record or a response
 *   CR-03  tamper: a record changed without the MAC key is not callable and is escalated
 *   CR-04  integration: config.js, router (list/enabled/dispatch/model allowlist/missing key), failover name, streaming
 *   CR-05  admin API: permissions, validation errors, no key echoed
 */

jest.mock('../../../../services/logger', () => { const a = jest.requireActual('../../../../services/logger'); return { ...a, emit: jest.fn() }; });

const created = [];
jest.mock('openai', () => ({
  OpenAI: class FakeOpenAI {
    constructor(opts) { this.opts = opts; created.push(opts); this.chat = { completions: { create: async (payload) => {
      if (payload.stream) return (async function* gen() { yield { choices: [{ delta: { content: 'he' } }] }; yield { choices: [{ delta: { content: 'llo' }, finish_reason: 'stop' }] }; })();
      return { id: 'c1', model: payload.model, choices: [{ message: { content: `echo:${payload.model}` } }], usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 } };
    } } }; }
  },
  AzureOpenAI: class {},
}));

const express = require('express');
const supertest = require('supertest');
const registry = require('../compatRegistry');
const config = require('../../../../services/providers/config');
const router = require('../../../../services/providers/router');
const { routeStreamingProviderCall: routeProviderStream } = require('../../../../services/providers/router.stream');
const { createProvidersAdminRouter } = require('../../../api/routes/admin/providers');
const macKeyring = require('../../security/macKeyring');

const OP = 'tester';
const GOOD = { id: 'acme', baseUrl: 'https://llm.acme.example.com/v1', apiKeyEnv: 'COMPAT_KEY_ACME', models: ['m-small', 'm-large'], defaultModel: 'm-small' };
const meta = { requestId: 'r' };
const body = (model) => ({ model, messages: [{ role: 'user', content: 'hi' }] });

beforeAll(() => { process.env.COMPAT_KEY_ACME = 'secret-key-value-123'; process.env.COMPAT_KEY_ACME_HOSTS = 'llm.acme.example.com'; process.env.COMPAT_KEY_VENDOR_HOSTS = '*.vendor.example.org'; });
afterAll(() => { delete process.env.COMPAT_KEY_ACME; delete process.env.COMPAT_KEY_ACME_HOSTS; delete process.env.COMPAT_KEY_VENDOR_HOSTS; });

describe('validation', () => {
  const bad = (spec, code) => { try { registry.validateSpec(spec); } catch (e) { expect(e.code).toBe(code); return; } throw new Error(`expected ${code}`); };
  test('CR-01 refusals', () => {
    bad({ ...GOOD, id: 'Bad_Id' }, 'INVALID_ID'); bad({ ...GOOD, id: 'a' }, 'INVALID_ID'); bad({ ...GOOD, id: '1abc' }, 'INVALID_ID');
    for (const u of ['http://llm.acme.example.com/v1', 'https://169.254.169.254/v1', 'https://localhost/v1', 'https://10.0.0.5/v1', 'https://[::1]/v1', 'https://user:pw@llm.acme.example.com/v1',
      'https://llm.acme.example.com/v1?x=1', 'https://nodots/v1', 'ftp://x.example.com', 'not a url']) bad({ ...GOOD, baseUrl: u }, /^(INVALID_BASE_URL|BASE_URL_REFUSED)$/.test('') ? '' : (['not a url', 'https://user:pw@llm.acme.example.com/v1', 'https://llm.acme.example.com/v1?x=1'].includes(u) ? 'INVALID_BASE_URL' : 'BASE_URL_REFUSED'));
    for (const k of ['DATABASE_PASSWORD', 'compat_key_x', 'COMPAT_KEY_', 'COMPAT_KEY_a-b', 'QODIQA_PG_PASSWORD']) bad({ ...GOOD, apiKeyEnv: k }, 'INVALID_API_KEY_ENV');
    bad({ ...GOOD, models: 'x' }, 'INVALID_MODELS'); bad({ ...GOOD, models: [' padded'] }, 'INVALID_MODELS'); bad({ ...GOOD, defaultModel: 'not-in-list' }, 'DEFAULT_MODEL_NOT_ALLOWED');
    bad({ ...GOOD, timeoutMs: 10 }, 'INVALID_TIMEOUT'); bad({ ...GOOD, maxTokens: 99999 }, 'INVALID_MAX_TOKENS'); bad({ ...GOOD, extra: 1 }, 'UNKNOWN_FIELD'); bad({ ...GOOD, enabled: 'yes' }, 'INVALID_ENABLED');
    bad(null, 'INVALID_PROVIDER'); bad([], 'INVALID_PROVIDER');
  });
  test('CR-01b the base URL is normalised and a plain-http local destination needs the explicit non-production opt-in', () => {
    expect(registry.validateSpec({ ...GOOD, baseUrl: 'https://llm.acme.example.com/v1///' }).baseUrl).toBe('https://llm.acme.example.com/v1');
    process.env.QODIQA_COMPAT_ALLOW_LOCAL = 'true';
    try {
      expect(registry.validateSpec({ ...GOOD, baseUrl: 'http://127.0.0.1:8000/v1' }).baseUrl).toBe('http://127.0.0.1:8000/v1');
      expect(() => registry.validateSpec({ ...GOOD, baseUrl: 'http://169.254.169.254/v1' })).toThrow(/outbound policy/);
      process.env.NODE_ENV = 'production';
      expect(() => registry.validateSpec({ ...GOOD, baseUrl: 'http://127.0.0.1:8000/v1' })).toThrow(/outbound policy/);
    } finally { process.env.NODE_ENV = 'test'; delete process.env.QODIQA_COMPAT_ALLOW_LOCAL; }
  });
});

describe('lifecycle', () => {
  test('CR-02', async () => {
    const v = await registry.register(GOOD, OP);
    expect(v).toMatchObject({ id: 'acme', name: 'compat-acme', enabled: true, revision: 1, keyConfigured: true, apiKeyEnv: 'COMPAT_KEY_ACME', models: ['m-small', 'm-large'] });
    expect(JSON.stringify(v)).not.toContain('secret-key-value-123');
    await expect(registry.register(GOOD, OP)).rejects.toMatchObject({ code: 'PROVIDER_EXISTS', status: 409 });
    await expect(registry.register({ ...GOOD, id: 'other' }, '')).rejects.toMatchObject({ code: 'OPERATOR_REQUIRED' });
    const u = await registry.update('acme', { timeoutMs: 5000, maxTokens: 256, failoverProvider: 'openai' }, OP);
    expect(u).toMatchObject({ revision: 2, timeoutMs: 5000, maxTokens: 256, failoverProvider: 'openai' }); expect(u.configHash).not.toBe(v.configHash);
    await expect(registry.update('acme', { id: 'other' }, OP)).rejects.toMatchObject({ code: 'ID_IMMUTABLE' });
    await expect(registry.update('nope', { timeoutMs: 5000 }, OP)).rejects.toMatchObject({ code: 'PROVIDER_NOT_FOUND', status: 404 });
    expect((await registry.setEnabled('acme', false, OP)).enabled).toBe(false);
    expect(registry.resolve('compat-acme')).toBeNull();
    expect((await registry.setEnabled('acme', true, OP)).revision).toBe(4);
    expect(registry.resolve('compat-acme')).not.toBeNull();
    expect(registry.list().map((p) => p.id)).toContain('acme'); expect(registry.get('nope')).toBeNull();
    expect(registry.remove).toBeUndefined();                                    // there is no deletion
  });
});

describe('integrity', () => {
  test('CR-03 a record changed without the MAC key is not callable and is escalated', async () => {
    const { emit } = require('../../../../services/logger');
    await registry.register({ ...GOOD, id: 'tamper', models: [], defaultModel: undefined }, OP);
    expect(registry.resolve('compat-tamper')).not.toBeNull();
    const rec = registry._col.get('tamper');
    registry._col._s.records.set('tamper', { ...rec, baseUrl: 'https://evil.example.com/v1' });          // a database writer without the key
    emit.mockClear();
    expect(registry.resolve('compat-tamper')).toBeNull();
    expect(registry.configFor('compat-tamper').enabled).toBe(false);
    expect(emit.mock.calls.some((c) => c[1] === 'PROVIDER_REGISTRY_RECORD_TAMPERED')).toBe(true);
    registry._col._s.records.set('tamper', { ...rec, mac: undefined });
    expect(registry.resolve('compat-tamper')).toBeNull();
    registry._col._s.records.set('tamper', rec);
    expect(registry.resolve('compat-tamper')).not.toBeNull();
    expect(macKeyring.PURPOSES.PROVIDER_REGISTRY).toBe('qodiqa-provider-registry-v1');
  });
});

describe('integration with the provider layer', () => {
  beforeAll(async () => { if (!registry.get('acme')) await registry.register(GOOD, OP); });
  test('CR-04 config, listing, dispatch, allowlist, missing key', async () => {
    const cfg = config.getProviderConfig('compat-acme');
    expect(cfg).toMatchObject({ enabled: true, baseUrl: 'https://llm.acme.example.com/v1', defaultModel: 'm-small', dynamic: true });
    expect(cfg.allowedModels.has('m-large')).toBe(true);
    expect(config.resolveDefaultModel('compat-acme')).toBe('m-small');
    expect(config.getEnabledProviders()).toContain('compat-acme'); expect(router.listProviders()).toContain('compat-acme'); expect(router.listEnabledProviders()).toContain('compat-acme');
    expect(config.getProviderConfig('compat-nope')).toBeNull(); expect(config.getProviderConfig('compat-')).toBeNull(); expect(config.getProviderConfig('compatx')).toBeNull();

    created.length = 0;
    const out = await router.routeProviderCall('compat-acme', body('m-large'), meta);
    expect(out).toMatchObject({ output: 'echo:m-large', provider: 'compat-acme', tokenUsage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 } });
    expect(created[0]).toMatchObject({ apiKey: 'secret-key-value-123', baseURL: 'https://llm.acme.example.com/v1', maxRetries: 0, timeout: 5000 });
    expect(created[0].fetch.guardedAgent).toBeInstanceOf(require('http').Agent);   // openai >= 5 has no httpAgent option - the SSRF-guarded agent rides on the client's fetch

    await expect(router.routeProviderCall('compat-acme', body('not-listed'), meta)).rejects.toMatchObject({ code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    await expect(router.routeProviderCall('compat-unknown', body('m'), meta)).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });

    const keep = process.env.COMPAT_KEY_ACME; delete process.env.COMPAT_KEY_ACME;
    try {
      expect(config.getProviderConfig('compat-acme').enabled).toBe(false); expect(router.listEnabledProviders()).not.toContain('compat-acme');
      await expect(router.routeProviderCall('compat-acme', body('m-small'), meta)).rejects.toMatchObject({ code: 'PROVIDER_NOT_CONFIGURED' });
    } finally { process.env.COMPAT_KEY_ACME = keep; }

    await registry.setEnabled('acme', false, OP);
    await expect(router.routeProviderCall('compat-acme', body('m-small'), meta)).rejects.toMatchObject({ code: 'PROVIDER_NOT_CONFIGURED' });
    await registry.setEnabled('acme', true, OP);
  });
  test('CR-04b a key change creates a new client (the next call uses the new key)', async () => {
    created.length = 0;
    await router.routeProviderCall('compat-acme', body('m-small'), meta);
    process.env.COMPAT_KEY_ACME = 'rotated-key-value-456';
    await router.routeProviderCall('compat-acme', body('m-small'), meta);
    expect(created.map((c) => c.apiKey)).toEqual(['secret-key-value-123', 'rotated-key-value-456']);
    process.env.COMPAT_KEY_ACME = 'secret-key-value-123';
  });
  test('CR-04c streaming: native stream through the same guarded client; deltas arrive and the terminal chunk is required', async () => {
    const chunks = [];
    for await (const c of routeProviderStream('compat-acme', body('m-small'), meta)) chunks.push(c.delta);
    expect(chunks.join('')).toBe('hello');
  });
});

describe('admin API', () => {
  const app = express(); app.use(express.json()); app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'admin1', role: 'admin' }; next(); });
  app.use('/v1/admin/providers', createProvidersAdminRouter({ requirePermission: (p) => (req, res, next) => (req.headers['x-deny'] === p ? res.status(403).json({ denied: p }) : next()) }));
  test('CR-05', async () => {
    const make = { id: 'viaapi', baseUrl: 'https://api.vendor.example.org/v1', apiKeyEnv: 'COMPAT_KEY_VENDOR', models: ['x1'] };
    const created1 = await supertest(app).post('/v1/admin/providers').send(make);
    expect(created1.status).toBe(201); expect(created1.body.data.provider).toMatchObject({ id: 'viaapi', name: 'compat-viaapi', keyConfigured: false });
    expect(JSON.stringify(created1.body)).not.toMatch(/secret/i);
    expect((await supertest(app).post('/v1/admin/providers').send(make)).status).toBe(409);
    const badUrl = await supertest(app).post('/v1/admin/providers').send({ ...make, id: 'badone', baseUrl: 'https://169.254.169.254/' });
    expect(badUrl.status).toBe(400); expect(badUrl.body.error.code).toBe('BASE_URL_REFUSED');
    expect((await supertest(app).get('/v1/admin/providers')).body.data.providers.map((p) => p.id)).toContain('viaapi');
    expect((await supertest(app).get('/v1/admin/providers/viaapi')).body.data.provider.id).toBe('viaapi');
    expect((await supertest(app).get('/v1/admin/providers/nope')).status).toBe(404);
    expect((await supertest(app).put('/v1/admin/providers/viaapi').send({ maxTokens: 128 })).body.data.provider.maxTokens).toBe(128);
    expect((await supertest(app).post('/v1/admin/providers/viaapi/disable')).body.data.provider.enabled).toBe(false);
    expect((await supertest(app).post('/v1/admin/providers/viaapi/enable')).body.data.provider.enabled).toBe(true);
    expect((await supertest(app).delete('/v1/admin/providers/viaapi')).status).toBe(404);              // no DELETE route
    expect((await supertest(app).post('/v1/admin/providers').set('x-deny', 'MANAGE_PROVIDERS').send({ ...make, id: 'denied' })).status).toBe(403);
    expect((await supertest(app).get('/v1/admin/providers').set('x-deny', 'READ_PROVIDERS')).status).toBe(403);
  });
});
