'use strict';

/**
 * openai.js — dedicated execution-path coverage.
 *
 * openai.validation.test.js already covers the full pre-flight validation
 * surface (model allowlist, message structure, count/size limits, roles)
 * without an API key or SDK mock — its own header comment states it never
 * reaches _getClient(). This suite covers everything after that: the real
 * SDK call, response extraction/normalization, error classification, base
 * URL handling, and audit attribution — mirroring mistral.test.js's
 * conventions, since openai.js and mistral.js share the identical
 * createLazyClient()/TRANSPORTS.sdk shape.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('openai');

const { emit }   = require('../../logger');
const { OpenAI } = require('openai');
const { callOpenAI, _resetClient } = require('../openai');

const VALID_BODY = {
  model:    'gpt-4o',
  messages: [{ role: 'user', content: 'Hello OpenAI' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

const VALID_COMPLETION = {
  id:      'chatcmpl-001',
  model:   'gpt-4o',
  choices: [{ message: { role: 'assistant', content: 'Hello from OpenAI!' } }],
  usage:   { prompt_tokens: 5, completion_tokens: 10, total_tokens: 15 },
};

function setupMockClient(completion) {
  const mockCreate = jest.fn().mockResolvedValue(completion);
  OpenAI.mockImplementation(() => ({
    chat: { completions: { create: mockCreate } },
  }));
  return mockCreate;
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.OPENAI_API_KEY = 'sk-test-key';
  delete process.env.OPENAI_BASE_URL;
  _resetClient();
});

afterEach(() => {
  delete process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_BASE_URL;
  _resetClient();
});

// ── Successful execution ──────────────────────────────────────────────────────

describe('successful execution', () => {
  test('returns normalized ProviderResponse', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(result.output).toBe('Hello from OpenAI!');
    expect(result.provider).toBe('openai');
    expect(result.model).toBe('gpt-4o');
  });

  test('request is sent with the exact model and messages, unmodified', async () => {
    const mockCreate = setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    expect(mockCreate.mock.calls[0][0]).toEqual({ model: 'gpt-4o', messages: VALID_BODY.messages });
  });

  test('tokenUsage is populated from response usage', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(result.tokenUsage.inputTokens).toBe(5);
    expect(result.tokenUsage.outputTokens).toBe(10);
    expect(result.tokenUsage.totalTokens).toBe(15);
  });

  test('executionMetadata.responseId is set from response id', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(result.executionMetadata.responseId).toBe('chatcmpl-001');
  });

  test('executionMetadata.latencyMs is a non-negative number', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(typeof result.executionMetadata.latencyMs).toBe('number');
    expect(result.executionMetadata.latencyMs).toBeGreaterThanOrEqual(0);
  });

  test('result is frozen', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(Object.isFrozen(result)).toBe(true);
  });

  test('model falls back to ctx.model when the response omits its own model field', async () => {
    setupMockClient({ ...VALID_COMPLETION, model: undefined });
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(result.model).toBe('gpt-4o');
  });

  test('emits PROVIDER_REQUEST_VALIDATED and PROVIDER_EXECUTION_COMPLETE', async () => {
    setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_REQUEST_VALIDATED', expect.objectContaining({ provider: 'openai' }));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_EXECUTION_COMPLETE', expect.objectContaining({ provider: 'openai' }));
  });
});

// ── Base URL handling (SSRF protection contract) ──────────────────────────────

describe('base URL handling', () => {
  test('OpenAI client is constructed with the hardcoded canonical base URL', async () => {
    setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    const constructorCall = OpenAI.mock.calls[0][0];
    expect(constructorCall.baseURL).toBe('https://api.openai.com/v1');
  });

  test('OPENAI_BASE_URL is set but ignored — client still uses the canonical URL', async () => {
    process.env.OPENAI_BASE_URL = 'https://evil.example.com/v1';
    setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    const constructorCall = OpenAI.mock.calls[0][0];
    expect(constructorCall.baseURL).toBe('https://api.openai.com/v1');
  });

  test('emits PROVIDER_BASE_URL_OVERRIDE_IGNORED when OPENAI_BASE_URL is set', async () => {
    process.env.OPENAI_BASE_URL = 'https://evil.example.com/v1';
    setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_BASE_URL_OVERRIDE_IGNORED', expect.objectContaining({
      canonicalBaseUrl: 'https://api.openai.com/v1',
    }));
  });

  test('does not emit PROVIDER_BASE_URL_OVERRIDE_IGNORED when OPENAI_BASE_URL is not set', async () => {
    setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    expect(emit).not.toHaveBeenCalledWith('WARN', 'PROVIDER_BASE_URL_OVERRIDE_IGNORED', expect.anything());
  });
});

// ── Model allowlist (smoke check only — full surface in openai.validation.test.js) ──

describe('model allowlist wiring', () => {
  test('an allowed model reaches the real SDK call', async () => {
    const mockCreate = setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    expect(mockCreate).toHaveBeenCalledTimes(1);
  });

  test('an unlisted model never reaches the SDK client', async () => {
    const mockCreate = setupMockClient(VALID_COMPLETION);
    await callOpenAI({ ...VALID_BODY, model: 'not-a-real-model' }, VALID_META).catch(() => {});
    expect(mockCreate).not.toHaveBeenCalled();
  });
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('authentication', () => {
  test('throws PROVIDER_AUTH_FAILED when API key missing, without constructing a client', async () => {
    delete process.env.OPENAI_API_KEY;
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
    expect(OpenAI).not.toHaveBeenCalled();
  });
});

// ── Provider error propagation ────────────────────────────────────────────────

describe('provider error propagation', () => {
  test('HTTP 429 → PROVIDER_RATE_LIMITED after retries are exhausted', async () => {
    const create429 = jest.fn().mockRejectedValue(Object.assign(new Error('429'), { status: 429 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: create429 } } }));
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
    expect(create429).toHaveBeenCalledTimes(2); // MAX_RETRIES=1 -> 2 attempts total
  });

  test('HTTP 401 → PROVIDER_AUTH_FAILED', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('401'), { status: 401 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('network ECONNREFUSED → PROVIDER_UNAVAILABLE', async () => {
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('APIConnectionTimeoutError (by name) → PROVIDER_TIMEOUT', async () => {
    const timeoutErr = Object.assign(new Error('timed out'), { name: 'APIConnectionTimeoutError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(timeoutErr) } } }));
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_TIMEOUT');
  });

  test('AbortError is NOT treated as a timeout for the non-streaming sdk transport (unlike sdkStream)', async () => {
    // baseAdapter.js's TRANSPORTS.sdk.timeoutNames deliberately excludes
    // AbortError (only TRANSPORTS.sdkStream includes it) — pinning the
    // documented asymmetry from the caller side rather than assuming it.
    const abortErr = Object.assign(new Error('aborted'), { name: 'AbortError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(abortErr) } } }));
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).not.toBe('PROVIDER_TIMEOUT');
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('a client-disconnect signal already aborted before the call → PROVIDER_CANCELLED, no SDK call made', async () => {
    const mockCreate = setupMockClient(VALID_COMPLETION);
    const controller = new AbortController();
    controller.abort();
    const err = await callOpenAI(VALID_BODY, VALID_META, controller.signal).catch(e => e);
    expect(err.code).toBe('PROVIDER_CANCELLED');
    expect(mockCreate).not.toHaveBeenCalled();
  });

  test('emits PROVIDER_EXECUTION_FAILED with the classified code', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    await callOpenAI(VALID_BODY, VALID_META).catch(() => {});
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_EXECUTION_FAILED', expect.objectContaining({
      provider: 'openai', code: 'PROVIDER_UNAVAILABLE',
    }));
  });
});

// ── Response extraction / malformed responses ─────────────────────────────────

describe('response extraction', () => {
  test('malformed response (no choices) → PROVIDER_INVALID_RESPONSE', async () => {
    setupMockClient({ id: 'chatcmpl-x', choices: [] });
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });

  test('malformed response (message content is null) → PROVIDER_INVALID_RESPONSE', async () => {
    setupMockClient({ id: 'chatcmpl-x', choices: [{ message: { role: 'assistant', content: null } }] });
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });

  test('malformed response (no message key at all) → PROVIDER_INVALID_RESPONSE', async () => {
    setupMockClient({ id: 'chatcmpl-x', choices: [{}] });
    const err = await callOpenAI(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });

  test('an empty-string content is a valid response, not PROVIDER_INVALID_RESPONSE', async () => {
    // buildResponse() only rejects a non-string output — an empty string IS
    // a string, so this is a real, distinct pass-through case, not an
    // oversight. Confirmed against services/providers/normalize.js.
    setupMockClient({ id: 'chatcmpl-empty', choices: [{ message: { role: 'assistant', content: '' } }] });
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(result.output).toBe('');
  });

  test('tokenUsage fields are null when usage is absent from the response', async () => {
    setupMockClient({ id: 'chatcmpl-x', choices: [{ message: { role: 'assistant', content: 'ok' } }] });
    const result = await callOpenAI(VALID_BODY, VALID_META);
    expect(result.tokenUsage.inputTokens).toBeNull();
    expect(result.tokenUsage.outputTokens).toBeNull();
    expect(result.tokenUsage.totalTokens).toBeNull();
  });
});

// ── Audit attribution ─────────────────────────────────────────────────────────

describe('audit attribution', () => {
  test('PROVIDER_REQUEST_VALIDATED includes requestId/requestHash/policyHash', async () => {
    setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_REQUEST_VALIDATED', expect.objectContaining({
      requestId: 'req-001', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64),
    }));
  });

  test('PROVIDER_EXECUTION_COMPLETE includes requestHash/policyHash (completeLogIncludesHash)', async () => {
    setupMockClient(VALID_COMPLETION);
    await callOpenAI(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_EXECUTION_COMPLETE', expect.objectContaining({
      requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64),
    }));
  });
});
