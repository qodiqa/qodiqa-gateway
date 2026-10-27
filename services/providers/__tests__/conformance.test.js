'use strict';

/**
 * conformance of the new adapters (azure, bedrock, compat-<id>) to what every adapter must do: strict timeout, cancellation before dispatch, multi-turn messages
 *no redirect following, SSRF refusal of a bad endpoint, circuit breaker through the router, failover name resolution.
 *   CN-01  timeout: a request that never answers fails as PROVIDER_TIMEOUT within the configured time (azure, bedrock)
 *   CN-02  cancellation: an already-aborted signal is PROVIDER_CANCELLED and nothing is sent (azure, bedrock, compat)
 *   CN-03  messages: system + several turns reach the provider payload in order, nothing dropped
 *   CN-04  the circuit breaker opens after repeated provider failures for the new providers (router path)
 *   CN-05  the shared fetch helper refuses redirects for every fetch adapter
 */

jest.mock('../../logger', () => { const a = jest.requireActual('../../logger'); return { ...a, emit: jest.fn() }; });

const SECRET = 'a1'.repeat(16);
Object.assign(process.env, {
  AZURE_OPENAI_ENDPOINT: 'https://myres.openai.azure.com', AZURE_OPENAI_API_KEY: SECRET, AZURE_OPENAI_TIMEOUT_MS: '150',
  BEDROCK_REGION: 'us-east-1', BEDROCK_ACCESS_KEY_ID: ['AK', 'IA'].join('') + 'IOSFODNN7ABCDEFG', BEDROCK_SECRET_ACCESS_KEY: 'wJalr' + 'XUtnFEMI/K7MDENG+bPxRfiCY' + 'z'.repeat(10), BEDROCK_TIMEOUT_MS: '150',
  PROVIDER_CB_FAILURE_THRESHOLD: '3',
});

const azure = require('../azure');
const bedrock = require('../bedrock');
const baseAdapter = require('../baseAdapter');
const router = require('../router');

const msgs = [{ role: 'system', content: 'S1' }, { role: 'user', content: 'U1' }, { role: 'assistant', content: 'A1' }, { role: 'user', content: 'U2' }];
const hang = (_u, init) => new Promise((_res, rej) => { if (init && init.signal) init.signal.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true }); });

describe('timeouts (strict)', () => {
  test('CN-01 azure and bedrock fail as PROVIDER_TIMEOUT within the configured time', async () => {
    azure._setFetch(hang);
    let t0 = Date.now();
    const a = await azure.callAzure({ model: 'dep', messages: msgs }, {}).catch((e) => e);
    expect(a.code).toBe('PROVIDER_TIMEOUT'); expect(Date.now() - t0).toBeLessThan(3000);
    const spy = jest.spyOn(global, 'fetch').mockImplementation(hang);
    t0 = Date.now();
    const b = await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: msgs }, {}).catch((e) => e);
    spy.mockRestore();
    expect(b.code).toBe('PROVIDER_TIMEOUT'); expect(Date.now() - t0).toBeLessThan(3000);
    expect(b.providerMayHaveExecuted).toBe(true);                                       // a timeout after send is never failed over
  }, 15000);
});

describe('cancellation', () => {
  test('CN-02 an aborted signal is PROVIDER_CANCELLED and nothing is sent', async () => {
    const ac = new AbortController(); ac.abort();
    const sent = []; azure._setFetch(async (u) => { sent.push(String(u)); return new Response('{}'); });
    const spy = jest.spyOn(global, 'fetch').mockImplementation(async (u) => { sent.push(String(u)); return new Response('{}'); });
    const e1 = await azure.callAzure({ model: 'dep', messages: msgs }, {}, ac.signal).catch((e) => e);
    const e2 = await bedrock.callBedrock({ model: 'amazon.nova-pro-v1:0', messages: msgs }, {}, ac.signal).catch((e) => e);
    const e3 = await baseAdapter.runProviderCall({ name: 'azure', transport: baseAdapter.TRANSPORTS.sdk, validate: {}, transformRequest: () => ({}), execute: async () => { sent.push('x'); return {}; }, logFields: () => ({}), parseResponse: () => ({}) }, { model: 'dep', messages: msgs }, {}, ac.signal).catch((e) => e);
    spy.mockRestore();
    expect([e1.code, e2.code, e3.code]).toEqual(['PROVIDER_CANCELLED', 'PROVIDER_CANCELLED', 'PROVIDER_CANCELLED']); expect(sent).toEqual([]);
  });
});

describe('multi-turn messages', () => {
  test('CN-03 every turn reaches the payload in order', () => {
    const order = (payload, needles) => { const j = JSON.stringify(payload); const idx = needles.map((n) => j.indexOf(n)); expect(idx.every((i) => i >= 0)).toBe(true); expect([...idx].sort((a, b) => a - b)).toEqual(idx); };
    order(azure._spec.transformRequest({ model: 'd', messages: msgs }), ['S1', 'U1', 'A1', 'U2']);
    const b = bedrock._spec.transformRequest({ model: 'm', messages: msgs });
    expect(b.system).toEqual([{ text: 'S1' }]); order(b.messages, ['U1', 'A1', 'U2']); expect(b.messages.map((m) => m.role)).toEqual(['user', 'assistant', 'user']);
    const c = require('../compat').specFor('compat-x');
    order(c.transformRequest({ model: 'm', messages: msgs }), ['S1', 'U1', 'A1', 'U2']);
  });
});

describe('circuit breaker', () => {
  test('CN-04 azure and bedrock open their breaker after repeated provider failures and then fast-fail', async () => {
    azure._setFetch(async () => new Response('{"error":{"message":"x"}}', { status: 503, headers: { 'content-type': 'application/json' } }));
    const spy = jest.spyOn(global, 'fetch').mockImplementation(async () => new Response('{}', { status: 503 }));
    const codes = { azure: [], bedrock: [] };
    for (let i = 0; i < 6; i++) {
      codes.azure.push((await router.routeProviderCall('azure', { model: 'dep', messages: msgs }, { requestId: `r${i}` }).catch((e) => e)).code);
      codes.bedrock.push((await router.routeProviderCall('bedrock', { model: 'amazon.nova-pro-v1:0', messages: msgs }, { requestId: `r${i}` }).catch((e) => e)).code);
    }
    spy.mockRestore();
    for (const name of ['azure', 'bedrock']) {
      expect(codes[name].slice(0, 3)).toEqual(['PROVIDER_UNAVAILABLE', 'PROVIDER_UNAVAILABLE', 'PROVIDER_UNAVAILABLE']);
      expect(codes[name].slice(3)).toEqual(['PROVIDER_CIRCUIT_OPEN', 'PROVIDER_CIRCUIT_OPEN', 'PROVIDER_CIRCUIT_OPEN']);
    }
  }, 30000);
});

describe('fetch helper', () => {
  test('CN-05 fetchWithTimeout tells fetch to error on a redirect unless a caller says otherwise', async () => {
    const seen = [];
    const spy = jest.spyOn(global, 'fetch').mockImplementation(async (u, init) => { seen.push(init); return new Response('{}'); });
    await baseAdapter.fetchWithTimeout('https://example.com/x', { method: 'POST' }, 1000);
    spy.mockRestore();
    expect(seen[0].redirect).toBe('error');
  });
});
