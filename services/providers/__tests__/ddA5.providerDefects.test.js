'use strict';

/**
 * Due-diligence cluster A5 — provider adapter defects.
 *
 *
 * MOCKED TRANSPORTS ONLY: `global.fetch` is a jest mock and the native stream handlers that are not under test are
 * jest doubles. No real provider is contacted — no credential exists on this machine. Provider keys come from the
 * shared format-valid fake fixture set (test/helpers/providerFixtureKeys.js).
 *
 * Each test loads a FRESH module graph (jest.resetModules) under its own env, so config.js / the circuit-breaker
 * registry / providerHealth start clean and the real router + real adapter + real breaker are exercised together.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));

const { PROVIDER_FIXTURE_KEYS } = require('../../../test/helpers/providerFixtureKeys');

const ENV_KEYS = [
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL',
  'PROVIDER_FAILOVER_OPENAI', 'PROVIDER_FAILOVER_ANTHROPIC', 'PROVIDER_FAILOVER_GEMINI', 'PROVIDER_FAILOVER_LOCAL',
  'PROVIDER_FAILOVER_LLAMA', 'PROVIDER_DEFAULT_MODEL_LOCAL', 'PROVIDER_RETRY_BASE_MS', 'PROVIDER_RETRY_JITTER',
  'PROVIDER_CB_FAILURE_THRESHOLD',
];
let savedEnv;
beforeEach(() => {
  savedEnv = {};
  for (const k of ENV_KEYS) { savedEnv[k] = process.env[k]; delete process.env[k]; }
  process.env.PROVIDER_RETRY_BASE_MS = '1';
  process.env.PROVIDER_RETRY_JITTER  = 'false';
  jest.resetModules();
});
afterEach(() => {
  for (const k of ENV_KEYS) { if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k]; }
  delete global.fetch;
  jest.dontMock('../local.stream');
  jest.dontMock('../llama.stream');
  jest.dontMock('../local');
});

const MSGS = [{ role: 'user', content: 'Hello' }];
const META = () => ({ requestId: 'req-a5', authorizeFailover: async () => ({ ok: true }) });

function httpResponse(status, body = {}) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}
async function drain(gen) { const out = []; for await (const c of gen) out.push(c); return out; }

// ── ───────────────────────────────────────────────────────────────────
describe('provider 4xx classification', () => {
  test.each([
    [400, 'PROVIDER_INVALID_REQUEST'], [404, 'PROVIDER_INVALID_REQUEST'], [405, 'PROVIDER_INVALID_REQUEST'],
    [409, 'PROVIDER_INVALID_REQUEST'], [410, 'PROVIDER_INVALID_REQUEST'], [413, 'PROVIDER_INVALID_REQUEST'],
    [415, 'PROVIDER_INVALID_REQUEST'], [422, 'PROVIDER_INVALID_REQUEST'],
    [401, 'PROVIDER_AUTH_FAILED'], [403, 'PROVIDER_AUTH_FAILED'],
    [408, 'PROVIDER_UNAVAILABLE'], [429, 'PROVIDER_RATE_LIMITED'],
    [500, 'PROVIDER_UNAVAILABLE'], [502, 'PROVIDER_UNAVAILABLE'], [503, 'PROVIDER_UNAVAILABLE'], [529, 'PROVIDER_UNAVAILABLE'],
  ])('HTTP %i → %s (every transport)', (status, code) => {
    const { classifyTransportError, TRANSPORTS } = require('../baseAdapter');
    for (const t of Object.values(TRANSPORTS)) {
      expect(classifyTransportError(Object.assign(new Error(`HTTP ${status}`), { status }), t)).toBe(code);
    }
  });

  test('a client-error code is neither retried nor treated as "may have executed"', () => {
    const { shouldRetry, mayHaveExecuted, isRetryable } = require('../baseAdapter');
    const e404 = Object.assign(new Error('HTTP 404'), { status: 404 });
    expect(isRetryable('PROVIDER_INVALID_REQUEST')).toBe(false);
    expect(shouldRetry('PROVIDER_INVALID_REQUEST', e404)).toBe(false);
    expect(mayHaveExecuted('PROVIDER_INVALID_REQUEST', e404)).toBe(false);
  });

  function geminiEnv({ failover = true } = {}) {
    process.env.GEMINI_API_KEY    = PROVIDER_FIXTURE_KEYS.gemini;
    process.env.ANTHROPIC_API_KEY = PROVIDER_FIXTURE_KEYS.anthropic;
    if (failover) process.env.PROVIDER_FAILOVER_GEMINI = 'anthropic';
  }
  function fetchByHost(geminiStatus) {
    const calls = { gemini: 0, anthropic: 0 };
    global.fetch = jest.fn(async (url) => {
      if (String(url).includes('generativelanguage.googleapis.com')) { calls.gemini++; return httpResponse(geminiStatus, { error: { code: geminiStatus } }); }
      if (String(url).includes('api.anthropic.com')) { calls.anthropic++; return httpResponse(200, {}); }
      throw new Error(`unexpected URL ${url}`);
    });
    return calls;
  }

  test.each([[404], [400], [405], [409], [401], [403]])(
    'real router + real gemini adapter: HTTP %i ×7 never opens the breaker, is never retried, never fails over', async (status) => {
      geminiEnv();
      const calls = fetchByHost(status);
      const { routeProviderCall } = require('../router');
      const { getCircuitBreaker } = require('../providerCircuitBreaker');
      const { CIRCUIT_BREAKER_CONFIG } = require('../circuitBreakerConfig');
      const expected = status === 401 || status === 403 ? 'PROVIDER_AUTH_FAILED' : 'PROVIDER_INVALID_REQUEST';
      for (let i = 0; i < 7; i++) {
        await expect(routeProviderCall('gemini', { model: 'gemini-1.5-flash', messages: MSGS }, META()))
          .rejects.toMatchObject({ code: expected });
      }
      expect(calls.gemini).toBe(7);    // one upstream call per request: no retry, no breaker fast-fail
      expect(calls.anthropic).toBe(0); // no failover
      expect(getCircuitBreaker('gemini', CIRCUIT_BREAKER_CONFIG).state).toBe('CLOSED');
    });

  test('control: HTTP 503 ×5 DOES open the breaker (server errors still count), 6th call fast-fails', async () => {
    geminiEnv({ failover: false });
    const calls = fetchByHost(503);
    const { routeProviderCall } = require('../router');
    for (let i = 0; i < 5; i++) {
      await expect(routeProviderCall('gemini', { model: 'gemini-1.5-flash', messages: MSGS }, META()))
        .rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
    }
    await expect(routeProviderCall('gemini', { model: 'gemini-1.5-flash', messages: MSGS }, META()))
      .rejects.toMatchObject({ code: 'PROVIDER_CIRCUIT_OPEN' });
    expect(calls.gemini).toBe(5); // RT-06: a 5xx is not retried — exactly one upstream call per request
  });

  test('streaming router + real anthropic.stream adapter: HTTP 404 ×6 never opens the breaker and never fails over', async () => {
    process.env.ANTHROPIC_API_KEY = PROVIDER_FIXTURE_KEYS.anthropic;
    process.env.GEMINI_API_KEY    = PROVIDER_FIXTURE_KEYS.gemini;
    process.env.PROVIDER_FAILOVER_ANTHROPIC = 'gemini';
    const calls = { anthropic: 0, gemini: 0 };
    global.fetch = jest.fn(async (url) => {
      if (String(url).includes('api.anthropic.com')) { calls.anthropic++; return { ok: false, status: 404, body: null }; }
      calls.gemini++; return httpResponse(200, {});
    });
    const { routeStreamingProviderCall } = require('../router.stream');
    const { getCircuitBreaker } = require('../providerCircuitBreaker');
    const { CIRCUIT_BREAKER_CONFIG } = require('../circuitBreakerConfig');
    for (let i = 0; i < 6; i++) {
      await expect(drain(routeStreamingProviderCall('anthropic', { model: 'claude-3-5-sonnet-20241022', messages: MSGS }, META())))
        .rejects.toMatchObject({ code: 'PROVIDER_INVALID_REQUEST' });
    }
    expect(calls.anthropic).toBe(6);
    expect(calls.gemini).toBe(0);
    expect(getCircuitBreaker('anthropic', CIRCUIT_BREAKER_CONFIG).state).toBe('CLOSED');
  });
});

// ── ───────────────────────────────────────────────────────────────────
describe('no streaming failover once output has been emitted', () => {
  test('adapter layer: an error AFTER the first yielded chunk is flagged providerMayHaveExecuted, whatever its class', async () => {
    const { runProviderStream, TRANSPORTS } = require('../baseAdapter');
    const mkSpec = (yieldFirst, err) => ({
      name: 'local', transport: TRANSPORTS.sdkStream, validate: {},
      transformRequest: (b) => b,
      async* execute() { if (yieldFirst) yield 'partial'; throw err; },
      parseChunk: (c) => c,
    });
    process.env.LOCAL_BASE_URL = 'http://127.0.0.1:9';
    // 429-shaped and bare-TypeError mid-stream errors: by error class alone these read as "not executed".
    for (const raw of [Object.assign(new Error('HTTP 429'), { status: 429 }), new TypeError('terminated')]) {
      const seen = [];
      const err = await (async () => { for await (const c of runProviderStream(mkSpec(true, raw), { model: 'm', messages: MSGS }, {})) seen.push(c); })().catch((e) => e);
      expect(seen).toEqual([{ delta: 'partial' }]);
      expect(err.providerMayHaveExecuted).toBe(true);
    }
    // Control: the same errors BEFORE any output keep their pre-existing (provably-unsent) classification.
    for (const raw of [Object.assign(new Error('HTTP 429'), { status: 429 }), new TypeError('fetch failed')]) {
      const err = await drain(runProviderStream(mkSpec(false, raw), { model: 'm', messages: MSGS }, {})).catch((e) => e);
      expect(err.providerMayHaveExecuted).toBeUndefined();
    }
  });

  function mockStreams(primaryImpl) {
    const failoverCalls = { n: 0 };
    jest.doMock('../local.stream', () => ({ callLocalStream: primaryImpl }));
    jest.doMock('../llama.stream', () => ({
      callLlamaStream: async function* () { failoverCalls.n++; yield { delta: 'FROM-FAILOVER' }; },
    }));
    process.env.LOCAL_BASE_URL = 'http://127.0.0.1:9/v1';
    process.env.LLAMA_BASE_URL = 'http://127.0.0.1:10/v1';
    process.env.PROVIDER_FAILOVER_LOCAL = 'llama';
    return failoverCalls;
  }
  const rateLimited = () => Object.assign(new Error('PROVIDER_RATE_LIMITED'), { code: 'PROVIDER_RATE_LIMITED' }); // no flag

  test('router layer: a retryable error after the primary emitted output does NOT start the failover provider', async () => {
    const failoverCalls = mockStreams(async function* () { yield { delta: 'partial' }; throw rateLimited(); });
    const { routeStreamingProviderCall } = require('../router.stream');
    const { emit } = require('../../logger');
    const seen = [];
    const err = await (async () => {
      for await (const c of routeStreamingProviderCall('local', { model: 'm', messages: MSGS }, META())) seen.push(c);
    })().catch((e) => e);
    expect(seen).toEqual([{ delta: 'partial' }]); // never spliced with failover output
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
    expect(err.providerMayHaveExecuted).toBe(true);
    expect(failoverCalls.n).toBe(0);
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_FAILOVER_SUPPRESSED', expect.objectContaining({ primaryProvider: 'local', code: 'PROVIDER_RATE_LIMITED' }));
    expect(emit).not.toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_FAILOVER', expect.anything());
  });

  test('control: the same retryable error BEFORE any output still fails over (pre-existing behaviour kept)', async () => {
    const failoverCalls = mockStreams(async function* () { throw rateLimited(); }); // eslint-disable-line require-yield
    const { routeStreamingProviderCall } = require('../router.stream');
    const chunks = await drain(routeStreamingProviderCall('local', { model: 'm', messages: MSGS }, META()));
    expect(chunks).toEqual([{ delta: 'FROM-FAILOVER' }]);
    expect(failoverCalls.n).toBe(1);
  });

  test('a consumer that stops early still closes the primary generator (for-await keeps yield* close semantics)', async () => {
    let finalized = false;
    mockStreams(async function* () { try { yield { delta: 'a' }; yield { delta: 'b' }; } finally { finalized = true; } });
    const { routeStreamingProviderCall } = require('../router.stream');
    for await (const c of routeStreamingProviderCall('local', { model: 'm', messages: MSGS }, META())) { expect(c).toEqual({ delta: 'a' }); break; }
    expect(finalized).toBe(true);
  });
});

// ── ───────────────────────────────────────────────────────────────────
describe('local provider never receives an OpenAI default model', () => {
  test('no PROVIDER_DEFAULT_MODEL_LOCAL: the route-resolved model is null and the router refuses BEFORE dispatch, naming the env var', async () => {
    process.env.LOCAL_BASE_URL = 'http://127.0.0.1:9/v1';
    const callLocal = jest.fn();
    jest.doMock('../local', () => ({ callLocal }));
    const { resolveDefaultModel } = require('../config');
    const { routeProviderCall } = require('../router');
    const { emit } = require('../../logger');
    const model = resolveDefaultModel('local');
    expect(model).toBeNull(); // never 'gpt-3.5-turbo'
    await expect(routeProviderCall('local', { model, messages: MSGS }, META())).rejects.toMatchObject({ code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    expect(callLocal).not.toHaveBeenCalled();
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_MODEL_MISSING', expect.objectContaining({ provider: 'local', envVar: 'PROVIDER_DEFAULT_MODEL_LOCAL' }));
  });

  test('streaming path: same refusal and warning, no handler invoked', async () => {
    process.env.LOCAL_BASE_URL = 'http://127.0.0.1:9/v1';
    const callLocalStream = jest.fn();
    jest.doMock('../local.stream', () => ({ callLocalStream }));
    const { routeStreamingProviderCall } = require('../router.stream');
    const { emit } = require('../../logger');
    await expect(drain(routeStreamingProviderCall('local', { model: null, messages: MSGS }, META())))
      .rejects.toMatchObject({ code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    expect(callLocalStream).not.toHaveBeenCalled();
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_MODEL_MISSING', expect.objectContaining({ envVar: 'PROVIDER_DEFAULT_MODEL_LOCAL' }));
  });

  test('PROVIDER_DEFAULT_MODEL_LOCAL set: that model is what the local handler receives', async () => {
    process.env.LOCAL_BASE_URL = 'http://127.0.0.1:9/v1';
    process.env.PROVIDER_DEFAULT_MODEL_LOCAL = 'qwen2.5:7b';
    const callLocal = jest.fn().mockResolvedValue({ output: 'ok' });
    jest.doMock('../local', () => ({ callLocal }));
    const { resolveDefaultModel } = require('../config');
    const { routeProviderCall } = require('../router');
    await routeProviderCall('local', { model: resolveDefaultModel('local'), messages: MSGS }, META());
    expect(callLocal.mock.calls[0][0].model).toBe('qwen2.5:7b');
  });

  test('a present-but-disallowed model does NOT emit PROVIDER_MODEL_MISSING (warning is specific to the missing case)', async () => {
    process.env.ANTHROPIC_API_KEY = PROVIDER_FIXTURE_KEYS.anthropic;
    const { routeProviderCall } = require('../router');
    const { emit } = require('../../logger');
    await expect(routeProviderCall('anthropic', { model: 'gpt-4', messages: MSGS }, META())).rejects.toMatchObject({ code: 'PROVIDER_MODEL_NOT_ALLOWED' });
    expect(emit).not.toHaveBeenCalledWith('WARN', 'PROVIDER_MODEL_MISSING', expect.anything());
  });
});
