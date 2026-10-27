'use strict';

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('openai');

const { emit }      = require('../../logger');
const { OpenAI }    = require('openai');
const { callMistral, _resetClient } = require('../mistral');

// ── Helpers ───────────────────────────────────────────────────────────────────

const VALID_BODY = {
  model:    'mistral-large-latest',
  messages: [{ role: 'user', content: 'Hello Mistral' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

const VALID_COMPLETION = {
  id:      'cmpl-001',
  model:   'mistral-large-latest',
  choices: [{ message: { role: 'assistant', content: 'Hello from Mistral!' } }],
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
  process.env.MISTRAL_API_KEY = 'ms-test-key';
  delete process.env.MISTRAL_BASE_URL;
  _resetClient();
});

afterEach(() => {
  delete process.env.MISTRAL_API_KEY;
  delete process.env.MISTRAL_BASE_URL;
  _resetClient();
});

// ── Successful execution ──────────────────────────────────────────────────────

describe('successful execution', () => {
  test('returns normalized ProviderResponse', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callMistral(VALID_BODY, VALID_META);
    expect(result.output).toBe('Hello from Mistral!');
    expect(result.provider).toBe('mistral');
    expect(result.model).toBe('mistral-large-latest');
  });

  test('tokenUsage is populated', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callMistral(VALID_BODY, VALID_META);
    expect(result.tokenUsage.inputTokens).toBe(5);
    expect(result.tokenUsage.outputTokens).toBe(10);
    expect(result.tokenUsage.totalTokens).toBe(15);
  });

  test('responseId is set from completion id', async () => {
    setupMockClient(VALID_COMPLETION);
    const result = await callMistral(VALID_BODY, VALID_META);
    expect(result.executionMetadata.responseId).toBe('cmpl-001');
  });

  test('OpenAI client is constructed with Mistral base URL', async () => {
    setupMockClient(VALID_COMPLETION);
    await callMistral(VALID_BODY, VALID_META);
    const constructorCall = OpenAI.mock.calls[0][0];
    expect(constructorCall.baseURL).toBe('https://api.mistral.ai/v1');
  });

  test('OpenAI client uses MISTRAL_BASE_URL when set', async () => {
    process.env.MISTRAL_BASE_URL = 'https://api.mistral.ai/v1';
    setupMockClient(VALID_COMPLETION);
    await callMistral(VALID_BODY, VALID_META);
    const constructorCall = OpenAI.mock.calls[0][0];
    expect(constructorCall.baseURL).toBe('https://api.mistral.ai/v1');
  });
});

// ── Model allowlist ───────────────────────────────────────────────────────────

describe('model allowlist', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED for gpt-4', async () => {
    const err = await callMistral({ ...VALID_BODY, model: 'gpt-4' }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('accepts mistral-small-latest', async () => {
    setupMockClient(VALID_COMPLETION);
    await expect(callMistral({ ...VALID_BODY, model: 'mistral-small-latest' }, VALID_META)).resolves.toBeDefined();
  });
});

// ── Payload validation ────────────────────────────────────────────────────────

describe('payload validation', () => {
  test('throws PROVIDER_INVALID_REQUEST for empty messages', async () => {
    const err = await callMistral({ ...VALID_BODY, messages: [] }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
  });

  test('throws PROVIDER_REQUEST_REJECTED for too many messages', async () => {
    const messages = Array.from({ length: 51 }, () => ({ role: 'user', content: 'x' }));
    const err = await callMistral({ ...VALID_BODY, messages }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_REQUEST_REJECTED');
  });
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('authentication', () => {
  test('throws PROVIDER_AUTH_FAILED when API key missing', async () => {
    delete process.env.MISTRAL_API_KEY;
    const err = await callMistral(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });
});

// ── Failure scenarios ─────────────────────────────────────────────────────────

describe('failure scenarios', () => {
  test('HTTP 429 → PROVIDER_RATE_LIMITED after retries', async () => {
    const create429 = jest.fn().mockRejectedValue(Object.assign(new Error('429'), { status: 429 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: create429 } } }));
    const err = await callMistral(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
  });

  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await callMistral(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('HTTP 401 → PROVIDER_AUTH_FAILED', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('401'), { status: 401 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await callMistral(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('network ECONNREFUSED → PROVIDER_UNAVAILABLE', async () => {
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const err = await callMistral(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('malformed response (no choices) → PROVIDER_INVALID_RESPONSE', async () => {
    setupMockClient({ id: 'cmpl-001', choices: [] });
    const err = await callMistral(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });

  test('emits PROVIDER_EXECUTION_FAILED on error', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    await callMistral(VALID_BODY, VALID_META).catch(() => {});
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_EXECUTION_FAILED', expect.objectContaining({
      provider: 'mistral',
    }));
  });
});
