'use strict';

/**
 * repairs - regression tests for what the independent provider verification found.
 *   RP-01  the timeout covers headers AND body; a stalled stream hits the idle deadline; counters and breaker see it
 *   RP-02  a 200 with an unusable body is PROVIDER_INVALID_RESPONSE, sent once, never failed over
 *   RP-03  provider-reported usage and output are bounded
 *   RP-04  strict public mode: a public name that resolves to loopback / private / documentation space is refused
 *   RP-05  the registry: destination judged again at use, ports, non-public names, key bound to hosts, invisible characters
 *   RP-06  routing: a model change on the SAME provider is re-authorised; one currency per rule; "fastest" ignores failures
 *   RP-07  SigV4 path normalisation; bedrock answer without a text block
 *   RP-08  SDK redirects are not followed
 */

jest.mock('../../logger', () => { const a = jest.requireActual('../../logger'); return { ...a, emit: jest.fn() }; });

Object.assign(process.env, {
  BEDROCK_REGION: 'us-east-1', BEDROCK_ACCESS_KEY_ID: ['AK', 'IA'].join('') + 'IOSFODNN7ABCDEFG', BEDROCK_SECRET_ACCESS_KEY: 'wJalr' + 'XUtnFEMI/K7MDENG+bPxRfiCY' + 'z'.repeat(10), BEDROCK_TIMEOUT_MS: '300',
  AZURE_OPENAI_ENDPOINT: 'https://myres.openai.azure.com', AZURE_OPENAI_API_KEY: 'a1'.repeat(16), AZURE_OPENAI_TIMEOUT_MS: '300',
});

const dns = require('dns');
const http = require('http');
const bedrock = require('../bedrock');
const azure = require('../azure');
const base = require('../baseAdapter');
const router = require('../router');
const providerLoad = require('../providerLoad');
const providerHealth = require('../providerHealth');
const ssrf = require('../ssrf');
const sigv4 = require('../sigv4');
const { buildResponse } = require('../normalize');
const registry = require('../../../src/core/providers/compatRegistry');
const routingStage = require('../../../src/core/routing/routingStage');
const routingEval = require('../../policy/evaluators/routing');

const msgs = [{ role: 'user', content: 'hi' }];
const BMODEL = 'amazon.nova-pro-v1:0';
const stalledBody = () => new ReadableStream({ start() { /* never closes */ } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('timeouts and answers', () => {
  afterEach(() => { providerLoad.resetAll(); providerHealth.resetAll(); jest.restoreAllMocks(); });

  test('RP-01 headers then silence, and a body that stalls: PROVIDER_TIMEOUT within the configured time; in-flight returns to 0; health sees it', async () => {
    for (const mk of [() => new Response(stalledBody(), { status: 200, headers: { 'content-type': 'application/json' } }), () => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"a":')); } }), { status: 200 })]) {
      const spy = jest.spyOn(global, 'fetch').mockImplementation(async (_u, init) => { const r = mk(); init.signal.addEventListener('abort', () => {}); return r; });
      const t0 = Date.now();
      const e = await router.routeProviderCall('bedrock', { model: BMODEL, messages: msgs }, { requestId: 'r' }).catch((x) => x);
      spy.mockRestore();
      expect(e.code).toBe('PROVIDER_TIMEOUT'); expect(Date.now() - t0).toBeLessThan(3000); expect(providerLoad.get('bedrock')).toBe(0);
    }
    expect(providerHealth.snapshot('bedrock').timeoutRate).toBeGreaterThan(0);
  }, 20000);

  test('RP-01b azure (SDK): a body that never ends is cut by the call deadline too', async () => {
    azure._setFetch(async () => new Response(stalledBody(), { status: 200, headers: { 'content-type': 'application/json' } }));
    const t0 = Date.now();
    const e = await azure.callAzure({ model: 'dep', messages: msgs }, {}).catch((x) => x);
    expect(e.code).toBe('PROVIDER_TIMEOUT'); expect(Date.now() - t0).toBeLessThan(3000);
  }, 20000);

  test('RP-01c a stream with no first chunk, and one that stalls after a chunk, hits the idle deadline; a steady stream is not cut', async () => {
    const run = async (gen) => {
      const out = []; let err = null;
      try { for await (const c of base.runProviderStream({ name: 'bedrock', transport: base.TRANSPORTS.fetch, validate: {}, transformRequest: () => ({}), execute: gen, parseChunk: (c) => c.d }, { model: BMODEL, messages: msgs }, {})) out.push(c.delta); } catch (e) { err = e; }
      return { out, err };
    };
    const hang = () => new Promise(() => {});
    const a = await run(async function* g() { await hang(); });
    expect(a.err.code).toBe('PROVIDER_TIMEOUT');
    const b = await run(async function* g() { yield { d: 'x' }; await hang(); });
    expect(b.out).toEqual(['x']); expect(b.err.code).toBe('PROVIDER_TIMEOUT'); expect(b.err.providerMayHaveExecuted).toBe(true);
    const c = await run(async function* g() { for (let i = 0; i < 6; i++) { await sleep(120); yield { d: String(i) }; } });       // 720 ms in total, never idle for 300 ms
    expect(c.err).toBeNull(); expect(c.out).toHaveLength(6);
  }, 20000);

  test('RP-02 a 200 with an unusable body is sent ONCE and is PROVIDER_INVALID_RESPONSE (also through the router: no failover)', async () => {
    for (const body of ['not json at all', 'null', '', '{"truncated":', '[]']) {
      const spy = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(body, { status: 200, headers: { 'content-type': 'application/json' } }));
      const e = await router.routeProviderCall('bedrock', { model: BMODEL, messages: msgs }, { requestId: 'r' }).catch((x) => x);
      const calls = spy.mock.calls.length; spy.mockRestore();
      expect({ body, code: e.code, calls }).toEqual({ body, code: 'PROVIDER_INVALID_RESPONSE', calls: 1 });
    }
    let n = 0; azure._setFetch(async () => { n++; return new Response('<html>oops</html>', { status: 200, headers: { 'content-type': 'application/json' } }); });
    const e = await azure.callAzure({ model: 'dep', messages: msgs }, {}).catch((x) => x);
    expect(e.code).toBe('PROVIDER_INVALID_RESPONSE'); expect(n).toBe(1);
    // a body over the cap is refused while it is read
    const big = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(1024 * 1024)); c.enqueue(new Uint8Array(1024 * 1024)); c.close(); } }), { status: 200 }));
    await expect(base.fetchJSON('https://x.example.com/', {}, 5000, undefined, { maxBytes: 1024 * 1024 })).rejects.toMatchObject({ code: 'PROVIDER_INVALID_RESPONSE' });
    big.mockRestore();
  }, 20000);

  test('RP-03 usage and output are bounded', () => {
    const r = buildResponse({ output: 'ok', tokenUsage: { inputTokens: 1e308, outputTokens: '5', totalTokens: -1 } });
    expect(r.tokenUsage).toEqual({ inputTokens: null, outputTokens: null, totalTokens: null });
    expect(buildResponse({ output: 'ok', tokenUsage: { inputTokens: 12, outputTokens: 3.4, totalTokens: 1e9 } }).tokenUsage).toEqual({ inputTokens: 12, outputTokens: 3, totalTokens: 1e9 });
    expect(buildResponse({ output: 'ok', tokenUsage: { inputTokens: 1e9 + 1, outputTokens: NaN, totalTokens: Infinity } }).tokenUsage).toEqual({ inputTokens: null, outputTokens: null, totalTokens: null });
    expect(() => buildResponse({ output: 'a\u0000b' })).toThrow(/PROVIDER_INVALID_RESPONSE/);
    expect(() => buildResponse({ output: 'x'.repeat(4 * 1024 * 1024 + 1) })).toThrow(/PROVIDER_INVALID_RESPONSE/);
    expect(buildResponse({ output: '' }).output).toBe('');
  });
});

describe('strict public mode', () => {
  test('RP-04 a public name that resolves to loopback, private or documentation space is refused, even for the named host', async () => {
    const env = { PROVIDER_GUARD_STRICT_PUBLIC: 'true', LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS: 'true' };
    const lookup = ssrf.createGuardedLookup(env, { trustedHost: 'llm.vendor.example.com' });
    const resolveTo = (addr) => new Promise((resolve) => {
      const spy = jest.spyOn(dns, 'lookup').mockImplementation((_h, _o, cb) => cb(null, [{ address: addr, family: addr.includes(':') ? 6 : 4 }]));
      lookup('llm.vendor.example.com', { all: true }, (err, res) => { spy.mockRestore(); resolve({ err, res }); });
    });
    for (const a of ['127.0.0.1', '::1', '::ffff:127.0.0.1', '10.0.0.5', '192.168.1.1', '169.254.169.254', '192.0.2.7', '198.51.100.9', '203.0.113.5', '2001:db8::5', 'fec0::1', 'fd00::1']) {
      const r = await resolveTo(a); expect({ a, code: r.err && r.err.code }).toEqual({ a, code: 'SSRF_BLOCKED_RESOLVED_ADDRESS' });
    }
    expect((await resolveTo('93.184.216.34')).err).toBeNull();
    // the self-hosted default is unchanged: the operator-named host may be loopback
    const lax = ssrf.createGuardedLookup({}, { trustedHost: 'localhost' });
    const spy = jest.spyOn(dns, 'lookup').mockImplementation((_h, _o, cb) => cb(null, [{ address: '127.0.0.1', family: 4 }]));
    await new Promise((resolve) => lax('localhost', { all: true }, (err) => { expect(err).toBeNull(); resolve(); }));
    spy.mockRestore();
  });
});

describe('dynamic registry', () => {
  const OP = 'tester';
  const GOOD = { id: 'strict', baseUrl: 'https://llm.vendor.example.com/v1', models: ['m1'] };
  test('RP-05', async () => {
    process.env.COMPAT_KEY_STRICT = 'k-value-123456'; process.env.COMPAT_KEY_STRICT_HOSTS = 'llm.vendor.example.com';
    const bad = async (spec, code) => expect(registry.register({ ...GOOD, id: `x${Math.random().toString(36).slice(2, 7)}`, ...spec }, OP)).rejects.toMatchObject({ code });
    for (const u of ['https://localtest.me/v1', 'https://svc.internal/v1', 'https://printer.local/v1', 'https://localhost.localdomain/v1', 'https://10.0.0.1.nip.io/v1', 'https://host.cluster.local/v1', 'https://nodots/v1']) await bad({ baseUrl: u }, 'BASE_URL_REFUSED');
    await bad({ baseUrl: 'https://llm.vendor.example.com:8443/v1' }, 'BASE_URL_REFUSED');                      // only 443
    await bad({ models: ['m‮evil'] }, 'INVALID_MODELS'); await bad({ displayName: 'a​b' }, 'INVALID_DISPLAY_NAME');
    await bad({ apiKeyEnv: 'COMPAT_KEY_STRICT', baseUrl: 'https://other.vendor.example.com/v1' }, 'KEY_HOST_NOT_ALLOWED');       // the key is bound to llm.vendor.example.com
    const rec = await registry.register({ ...GOOD, apiKeyEnv: 'COMPAT_KEY_STRICT' }, OP);
    expect(rec.enabled).toBe(true); expect(registry.resolve('compat-strict')).not.toBeNull();
    await expect(registry.update('strict', { baseUrl: 'https://evil.example.org/v1' }, OP)).rejects.toMatchObject({ code: 'KEY_HOST_NOT_ALLOWED' });   // a PUT cannot aim the key elsewhere
    expect(registry.keyAllowedFor('COMPAT_KEY_STRICT', 'llm.vendor.example.com')).toBe(true);
    process.env.COMPAT_KEY_STRICT_HOSTS = '*.vendor.example.com'; expect(registry.keyAllowedFor('COMPAT_KEY_STRICT', 'a.vendor.example.com')).toBe(true); expect(registry.keyAllowedFor('COMPAT_KEY_STRICT', 'vendor.example.com')).toBe(false); expect(registry.keyAllowedFor('COMPAT_KEY_STRICT', 'evilvendor.example.com')).toBe(false);
    delete process.env.COMPAT_KEY_STRICT_HOSTS; expect(registry.resolve('compat-strict')).toBeNull();            // no HOSTS list: the key is not usable
    process.env.COMPAT_KEY_STRICT_HOSTS = 'llm.vendor.example.com';
    // a stored plain-http / loopback record is not callable once the policy no longer permits it
    process.env.QODIQA_COMPAT_ALLOW_LOCAL = 'true';
    const local = await registry.register({ id: 'localdev', baseUrl: 'http://127.0.0.1:8000/v1' }, OP);
    expect(local.enabled).toBe(true); expect(registry.resolve('compat-localdev')).not.toBeNull();
    delete process.env.QODIQA_COMPAT_ALLOW_LOCAL;
    expect(registry.resolve('compat-localdev')).toBeNull(); expect(registry.configFor('compat-localdev').enabled).toBe(false); expect(registry.enabledNames()).not.toContain('compat-localdev');
    process.env.QODIQA_COMPAT_ALLOW_LOCAL = 'true'; process.env.NODE_ENV = 'production';
    try { expect(registry.resolve('compat-localdev')).toBeNull(); } finally { process.env.NODE_ENV = 'test'; delete process.env.QODIQA_COMPAT_ALLOW_LOCAL; }
    delete process.env.COMPAT_KEY_STRICT; delete process.env.COMPAT_KEY_STRICT_HOSTS;
  });
});

describe('routing', () => {
  test('RP-06 a model change on the same provider is re-authorised; one currency; fastest ignores failures', async () => {
    process.env.OPENAI_API_KEY = require('../../../test/helpers/providerFixtureKeys').PROVIDER_FIXTURE_KEYS.openai;
    jest.resetModules();
    const stage = require('../../../src/core/routing/routingStage');
    const rule = { id: 'R', type: 'ROUTING', priority: 1, enabled: true, config: { routingFormat: 1, strategy: 'ordered', modelMode: 'override', candidates: [{ provider: 'openai', model: 'gpt-4' }] } };
    const seen = [];
    const run = async (auth) => stage.resolve({ policies: [{ ...rule, config: { ...rule.config, _when: null } }], requestedProvider: 'openai', body: { model: 'gpt-3.5-turbo' }, attributes: {}, context: {}, authorize: async (t, i) => { seen.push([t, i]); return auth; } });
    const allowed = await run({ ok: true }); expect(seen).toEqual([['openai', { model: 'gpt-4' }]]); expect(allowed.model).toBe('gpt-4');
    const denied = await run({ ok: false, reason: 'ABAC_NO_GPT4' }); expect(denied.routed.fallback).toBe(true); expect(denied.routed.skipped).toEqual([{ provider: 'openai', reason: 'ABAC_NO_GPT4' }]);
    seen.length = 0; await stage.resolve({ policies: [{ ...rule, config: { ...rule.config, modelMode: 'fill', _when: null } }], requestedProvider: 'openai', body: { model: 'gpt-3.5-turbo' }, attributes: {}, context: {}, authorize: async (t, i) => { seen.push(i); return { ok: true }; } });
    expect(seen).toEqual([]);                                          // same provider, same model: nothing new to authorise
    expect(() => routingEval.validate({ routingFormat: 1, strategy: 'cheapest', candidates: [{ provider: 'openai' }], pricing: { openai: { currency: 'USD', inputPerMillionMicros: 1, outputPerMillionMicros: 1 }, local: { currency: 'EUR', inputPerMillionMicros: 1, outputPerMillionMicros: 1 } } })).toThrow(/one currency/);
    const health = require('../providerHealth'); health.resetAll();
    for (let i = 0; i < 4; i++) health.recordOutcome('anthropic', { ok: false, latencyMs: 1 });
    health.recordOutcome('openai', { ok: true, latencyMs: 900 });
    expect(health.snapshot('anthropic').successSamples).toBe(0); expect(health.snapshot('openai').successLatencyMs).toBe(900);
    void routingStage;
  });
});

describe('signing and answers', () => {
  test('RP-07 SigV4 collapses redundant slashes and dot segments for non-S3 services; a bedrock answer without a text block is invalid', async () => {
    const sign = (path) => sigv4.sign({ method: 'POST', url: `https://bedrock-runtime.us-east-1.amazonaws.com${path}`, body: '{}', region: 'us-east-1', service: 'bedrock', accessKeyId: process.env.BEDROCK_ACCESS_KEY_ID, secretAccessKey: process.env.BEDROCK_SECRET_ACCESS_KEY, now: new Date(Date.UTC(2026, 0, 1)) });
    expect(sign('/model//x/./y/../z').canonicalRequest.split('\n')[1]).toBe('/model/x/z');
    expect(sign('/model/x/').canonicalRequest.split('\n')[1]).toBe('/model/x/');
    expect(sign('//a///b').signature).toBe(sign('/a/b').signature);
    const spy = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ output: { message: { content: [{ toolUse: {} }] } }, usage: {} }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const e = await bedrock.callBedrock({ model: BMODEL, messages: msgs }, {}).catch((x) => x); spy.mockRestore();
    expect(e.code).toBe('PROVIDER_INVALID_RESPONSE');
  });
});

describe('redirects', () => {
  test('RP-08 the SDK fetch does not follow a redirect (the target is never contacted, credentials never travel)', async () => {
    let targetHits = 0; let targetAuth = null;
    const target = http.createServer((req, res) => { targetHits++; targetAuth = req.headers['api-key'] || req.headers.authorization || null; res.end('{}'); });
    await new Promise((r) => target.listen(0, '127.0.0.1', r));
    const origin = http.createServer((req, res) => { res.statusCode = 307; res.setHeader('location', `http://127.0.0.1:${target.address().port}/steal`); res.end(); });
    await new Promise((r) => origin.listen(0, '127.0.0.1', r));
    try {
      const res = await base.noRedirectFetch(`http://127.0.0.1:${origin.address().port}/x`, { method: 'POST', headers: { 'api-key': 'secret-value' }, body: '{}' });
      expect(res.status).toBe(307); expect(targetHits).toBe(0); expect(targetAuth).toBeNull();
    } finally { origin.close(); target.close(); }
  });
});

describe('verification round 2', () => {
  test('RP-09 a node-fetch invalid-json FetchError (empty/truncated 200) is PROVIDER_INVALID_RESPONSE', () => {
    const e = new Error('invalid json response body at http://x reason: Unexpected end of JSON input'); e.name = 'FetchError'; e.type = 'invalid-json';
    expect(base.classifyTransportError(e, base.TRANSPORTS.sdk)).toBe('PROVIDER_INVALID_RESPONSE');
  });
  test('RP-10 a byModel price cannot carry another currency than its provider', () => {
    const routing = require('../../policy/evaluators/routing');
    const cfg = (byModel) => ({ routingFormat: 1, strategy: 'cheapest', candidates: [{ provider: 'openai' }], pricing: { openai: { currency: 'USD', inputPerMillionMicros: 1, outputPerMillionMicros: 1, byModel } } });
    let msg = null; try { routing.validate(cfg({ m: { currency: 'JPY', inputPerMillionMicros: 1, outputPerMillionMicros: 1 } })); } catch (e) { msg = e.message; }
    expect(msg).toMatch(/currency/);
  });
});

describe('verification round 3', () => {
  test('RP-11 a 200 body that fails at the transport layer (bad gzip, cut chunked body) is PROVIDER_INVALID_RESPONSE', () => {
    for (const code of ['Z_DATA_ERROR', 'ERR_STREAM_PREMATURE_CLOSE']) {
      const e = new Error('Invalid response body while trying to fetch http://x: boom'); e.name = 'FetchError'; e.type = 'system'; e.code = code;
      expect(base.classifyTransportError(e, base.TRANSPORTS.sdk)).toBe('PROVIDER_INVALID_RESPONSE');
    }
    const refused = new Error('connect ECONNREFUSED'); refused.name = 'FetchError'; refused.type = 'system'; refused.code = 'ECONNREFUSED';
    expect(base.classifyTransportError(refused, base.TRANSPORTS.sdk)).not.toBe('PROVIDER_INVALID_RESPONSE');
  });
  test('RP-12 a BUDGET byModel price cannot carry a currency (or any other member)', () => {
    const budget = require('../../policy/evaluators/budget');
    const cfg = (v) => ({ budgetFormat: 1, limits: { costMicros: 1000 }, period: 'day', scope: 'tenant', pricing: { currency: 'USD', inputPerMillionMicros: 1, outputPerMillionMicros: 1, byModel: { m: v } } });
    let msg = null; try { budget.validate(cfg({ currency: 'JPY', inputPerMillionMicros: 1, outputPerMillionMicros: 1 })); } catch (e) { msg = e.message; }
    expect(msg).toMatch(/currency|only/);
  });
});
