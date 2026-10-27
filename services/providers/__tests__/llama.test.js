'use strict';

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('openai');

const { emit }   = require('../../logger');
const { OpenAI } = require('openai');

const VALID_BODY = {
  model:    'llama3.2',
  messages: [{ role: 'user', content: 'Hello Llama' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

const VALID_COMPLETION = {
  id:      'llama-resp-001',
  model:   'llama3.2',
  choices: [{ message: { role: 'assistant', content: 'Hello from Llama!' } }],
  usage:   { prompt_tokens: 8, completion_tokens: 12, total_tokens: 20 },
};

function setupMockClient(completion) {
  const mockCreate = jest.fn().mockResolvedValue(completion);
  OpenAI.mockImplementation(() => ({
    chat: { completions: { create: mockCreate } },
  }));
  return mockCreate;
}

function loadLlama(env = {}) {
  jest.resetModules();
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  const mod = require('../llama');
  for (const k of Object.keys(env)) delete process.env[k];
  return mod;
}

beforeEach(() => {
  jest.clearAllMocks();
});

afterEach(() => {
  delete process.env.LLAMA_BASE_URL;
  delete process.env.LLAMA_API_KEY;
});

// ── Successful execution ──────────────────────────────────────────────────────

describe('successful execution', () => {
  test('returns normalized ProviderResponse for cloud-hosted Llama', async () => {
    process.env.LLAMA_BASE_URL = 'https://api.groq.com/openai/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const result = await callLlama(VALID_BODY, VALID_META);
    expect(result.output).toBe('Hello from Llama!');
    expect(result.provider).toBe('llama');
    expect(result.model).toBe('llama3.2');
    _resetClient();
  });

  test('returns normalized ProviderResponse for self-hosted Llama', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const result = await callLlama(VALID_BODY, VALID_META);
    expect(result.output).toBe('Hello from Llama!');
    _resetClient();
  });

  test('tokenUsage is populated', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const result = await callLlama(VALID_BODY, VALID_META);
    expect(result.tokenUsage.inputTokens).toBe(8);
    expect(result.tokenUsage.outputTokens).toBe(12);
    expect(result.tokenUsage.totalTokens).toBe(20);
    _resetClient();
  });

  test('any non-empty model name is accepted', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    // Various Llama model names
    for (const model of ['llama3.2', 'llama-3.1-8b', 'meta-llama/Llama-3.2-3B-Instruct']) {
      jest.clearAllMocks();
      setupMockClient({ ...VALID_COMPLETION, model });
      const result = await callLlama({ ...VALID_BODY, model }, VALID_META);
      expect(result.output).toBeDefined();
    }
    _resetClient();
  });
});

// ── Payload validation ────────────────────────────────────────────────────────

describe('payload validation', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED when model is null', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const err = await callLlama({ ...VALID_BODY, model: null }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    _resetClient();
  });

  test('throws PROVIDER_INVALID_REQUEST for empty messages', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const err = await callLlama({ ...VALID_BODY, messages: [] }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
    _resetClient();
  });
});

// ── URL validation ────────────────────────────────────────────────────────────

describe('URL validation', () => {
  test('throws PROVIDER_CONFIG_INVALID for file:// URL', async () => {
    process.env.LLAMA_BASE_URL = 'file:///etc/passwd';
    OpenAI.mockImplementation(() => ({}));
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const err = await callLlama(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_CONFIG_INVALID');
    _resetClient();
  });

  test('accepts http://localhost endpoint', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    await expect(callLlama(VALID_BODY, VALID_META)).resolves.toBeDefined();
    _resetClient();
  });
});

// ── Failure scenarios ─────────────────────────────────────────────────────────

describe('failure scenarios', () => {
  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const err = await callLlama(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetClient();
  });

  test('ECONNREFUSED → PROVIDER_UNAVAILABLE', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const err = await callLlama(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetClient();
  });

  test('malformed response → PROVIDER_INVALID_RESPONSE', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockClient({ id: 'x', choices: [] });
    const { callLlama, _resetClient } = require('../llama');
    _resetClient();
    const err = await callLlama(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
    _resetClient();
  });
});

// RT-06: a provider that answered 5xx is not sent the completion twice.
describe('RT-06 non-idempotent retry policy', () => {
  test('HTTP 500 from the provider → exactly ONE call; ECONNREFUSED (no response) → retried', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    let m = require('../llama'); m._resetClient();
    expect((await m.callLlama(VALID_BODY, VALID_META).catch((e) => e)).code).toBe('PROVIDER_UNAVAILABLE');
    expect(createErr).toHaveBeenCalledTimes(1);
    const refused = jest.fn().mockRejectedValue(Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: refused } } }));
    m = require('../llama'); m._resetClient();
    await m.callLlama(VALID_BODY, VALID_META).catch((e) => e);
    expect(refused).toHaveBeenCalledTimes(2);
    m._resetClient();
  });
  // a connection RESET may come after delivery, so it is no longer retried; only failures that provably
  // never reached the provider are (refused connection, DNS, 429 refusal).
  test('shouldRetry: 429 yes; 5xx with a response no; reset no; refused/DNS yes', () => {
    const { shouldRetry, mayHaveExecuted } = require('../baseAdapter');
    expect(shouldRetry('PROVIDER_RATE_LIMITED', { status: 429 })).toBe(true);
    expect(shouldRetry('PROVIDER_UNAVAILABLE', { status: 503 })).toBe(false);
    expect(shouldRetry('PROVIDER_UNAVAILABLE', { code: 'ECONNRESET' })).toBe(false);
    expect(shouldRetry('PROVIDER_UNAVAILABLE', { code: 'ECONNREFUSED' })).toBe(true);
    expect(shouldRetry('PROVIDER_UNAVAILABLE', { code: 'ENOTFOUND' })).toBe(true);
    expect(shouldRetry('PROVIDER_TIMEOUT', {})).toBe(false);
    expect(mayHaveExecuted('PROVIDER_UNAVAILABLE', { status: 502 })).toBe(true);
    expect(mayHaveExecuted('PROVIDER_TIMEOUT', {})).toBe(true);
    expect(mayHaveExecuted('PROVIDER_UNAVAILABLE', { code: 'ECONNREFUSED' })).toBe(false);
    expect(mayHaveExecuted('PROVIDER_RATE_LIMITED', { status: 429 })).toBe(false);
  });
});
