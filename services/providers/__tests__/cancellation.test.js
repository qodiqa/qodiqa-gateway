'use strict';

/**
 * Finding 32 (2.3) remediation — cooperative cancellation regression suite.
 *
 * Proves, at the provider-adapter and router layer:
 *   1. Every provider adapter rejects immediately with PROVIDER_CANCELLED when
 *      given an already-aborted AbortSignal, WITHOUT attempting any network
 *      I/O (no wasted provider quota) and without needing valid credentials.
 *   2. The router (_dispatch) rejects with PROVIDER_CANCELLED before invoking
 *      the handler at all when the signal is already aborted — even for a
 *      completely unconfigured/unregistered provider — cancellation always
 *      wins the race against every other check.
 *   3. Cancellation is never classified as a retryable error and never
 *      triggers failover.
 *   4. An externally-issued AbortSignal that fires mid-flight reaches the
 *      outbound network call for both SDK-based (OpenAI-compatible) and
 *      fetch-based (Anthropic/Gemini) adapters.
 */

const https = require('https');

describe('provider adapters — pre-aborted signal short-circuits before any I/O', () => {
  afterEach(() => {
    jest.resetModules();
    delete process.env.OPENAI_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.GEMINI_API_KEY;
    delete process.env.MISTRAL_API_KEY;
    delete process.env.LLAMA_BASE_URL;
    delete process.env.LOCAL_BASE_URL;
    delete global.fetch;
  });

  function abortedSignal() {
    const ac = new AbortController();
    ac.abort('timeout');
    return ac.signal;
  }

  test('callOpenAI: PROVIDER_CANCELLED, no https.request call, no API key needed', async () => {
    const { callOpenAI } = require('../openai');
    const spy = jest.spyOn(https, 'request');
    const body = { model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }] };
    await expect(callOpenAI(body, {}, abortedSignal()))
      .rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('callMistral: PROVIDER_CANCELLED, no https.request call', async () => {
    const { callMistral } = require('../mistral');
    const spy = jest.spyOn(https, 'request');
    const body = { model: 'mistral-large-latest', messages: [{ role: 'user', content: 'hi' }] };
    await expect(callMistral(body, {}, abortedSignal()))
      .rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('callLlama: PROVIDER_CANCELLED, no https.request call', async () => {
    process.env.LLAMA_BASE_URL = 'https://api.groq.com/openai/v1';
    const { callLlama } = require('../llama');
    const spy = jest.spyOn(https, 'request');
    const body = { model: 'llama3.2', messages: [{ role: 'user', content: 'hi' }] };
    await expect(callLlama(body, {}, abortedSignal()))
      .rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('callLocal: PROVIDER_CANCELLED, no https.request call', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434';
    const { callLocal } = require('../local');
    const spy = jest.spyOn(https, 'request');
    const body = { model: 'llama3.2', messages: [{ role: 'user', content: 'hi' }] };
    await expect(callLocal(body, {}, abortedSignal()))
      .rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  test('callAnthropic: PROVIDER_CANCELLED, fetch never called', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    global.fetch = jest.fn();
    const { callAnthropic } = require('../anthropic');
    const body = { model: 'claude-3-5-sonnet-20241022', messages: [{ role: 'user', content: 'hi' }] };
    await expect(callAnthropic(body, {}, abortedSignal()))
      .rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('callGemini: PROVIDER_CANCELLED, fetch never called', async () => {
    process.env.GEMINI_API_KEY = 'test-key';
    global.fetch = jest.fn();
    const { callGemini } = require('../gemini');
    const body = { model: 'gemini-1.5-flash', messages: [{ role: 'user', content: 'hi' }] };
    await expect(callGemini(body, {}, abortedSignal()))
      .rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('cancellation is checked before model validation (no PROVIDER_MODEL_NOT_ALLOWED masking it)', async () => {
    const { callOpenAI } = require('../openai');
    const body = { model: 'not-a-real-model', messages: [{ role: 'user', content: 'hi' }] };
    await expect(callOpenAI(body, {}, abortedSignal()))
      .rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
  });
});

describe('router — cancellation takes priority over every other dispatch check', () => {
  jest.mock('../../logger', () => ({ emit: jest.fn() }));

  function abortedSignal() {
    const ac = new AbortController();
    ac.abort('timeout');
    return ac.signal;
  }

  test('_dispatch throws PROVIDER_CANCELLED before checking the registry, for an unregistered provider name', async () => {
    const { routeProviderCall } = require('../router');
    const err = await routeProviderCall('totally-unknown-provider', {}, {}, abortedSignal()).catch(e => e);
    expect(err.code).toBe('PROVIDER_CANCELLED');
  });

  test('PROVIDER_CANCELLED is not in the retryable set and never triggers failover', async () => {
    jest.resetModules();
    jest.doMock('../openai', () => ({ callOpenAI: jest.fn() }));
    jest.doMock('../anthropic', () => ({ callAnthropic: jest.fn() }));
    jest.doMock('../config', () => ({
      getProviderConfig: jest.fn(() => ({ enabled: true, failoverProvider: 'anthropic' })),
    }));

    const { routeProviderCall } = require('../router');
    const { callOpenAI }    = require('../openai');
    const { callAnthropic } = require('../anthropic');

    const err = await routeProviderCall('openai', {}, {}, abortedSignal()).catch(e => e);

    expect(err.code).toBe('PROVIDER_CANCELLED');
    expect(callOpenAI).not.toHaveBeenCalled();
    expect(callAnthropic).not.toHaveBeenCalled();

    jest.dontMock('../openai');
    jest.dontMock('../anthropic');
    jest.dontMock('../config');
    // dontMock() only stops FUTURE requires from using the mock factory — it
    // does not evict the already-cached mocked '../config' module (missing
    // allowedModels) from the registry. Without this, later tests in this
    // file that require adapters fresh (e.g. callAnthropic below) would
    // transitively pick up the stale mocked config via modelValidation.js
    // and fail model validation instead of exercising cancellation.
    jest.resetModules();
  });
});

describe('mid-flight abort reaches the outbound network call', () => {
  afterEach(() => {
    jest.resetModules();
    delete process.env.ANTHROPIC_API_KEY;
    delete global.fetch;
  });

  test('anthropic.js: the AbortSignal passed to fetch aborts when the caller signal aborts', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    const { callAnthropic } = require('../anthropic');

    let capturedSignal;
    global.fetch = jest.fn((url, options) => {
      capturedSignal = options.signal;
      return new Promise((resolve, reject) => {
        options.signal.addEventListener('abort', () => {
          const err = new Error('The operation was aborted');
          err.name  = 'AbortError';
          reject(err);
        });
      });
    });

    const ac = new AbortController();
    const body = { model: 'claude-3-5-sonnet-20241022', messages: [{ role: 'user', content: 'hi' }] };

    const callPromise = callAnthropic(body, {}, ac.signal);
    // Give the fetch mock a tick to register, then abort mid-flight.
    await new Promise(r => setImmediate(r));
    ac.abort('timeout');

    await expect(callPromise).rejects.toMatchObject({ code: 'PROVIDER_CANCELLED' });
    expect(capturedSignal.aborted).toBe(true);
  });

  test('openai.js: the caller signal is forwarded as the SDK call options', async () => {
    process.env.OPENAI_API_KEY = 'test-key';
    const mockCreate = jest.fn().mockResolvedValue({
      id: 'x', model: 'gpt-4o', choices: [{ message: { content: 'hi' } }], usage: {},
    });
    jest.doMock('openai', () => ({
      OpenAI: jest.fn().mockImplementation(() => ({
        chat: { completions: { create: mockCreate } },
      })),
    }));

    const { callOpenAI } = require('../openai');
    const ac = new AbortController();
    const body = { model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }] };

    await callOpenAI(body, {}, ac.signal);

    // the SDK now gets a signal DERIVED from the caller's and the call deadline - aborting the caller's signal must abort it
    expect(mockCreate).toHaveBeenCalledWith(
      expect.objectContaining({ model: 'gpt-4o' }),
      { signal: expect.any(AbortSignal) },
    );
    const passed = mockCreate.mock.calls[0][1].signal;
    expect(passed.aborted).toBe(false);
    ac.abort();
    expect(passed.aborted).toBe(true);

    jest.dontMock('openai');
    delete process.env.OPENAI_API_KEY;
  });
});
