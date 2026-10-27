'use strict';

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('openai');

const { emit }   = require('../../logger');
const { OpenAI } = require('openai');

const VALID_BODY = {
  model:    'llama3.2',
  messages: [{ role: 'user', content: 'Hello from local' }],
};

const VALID_META = {
  requestId:   'req-local-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

const VALID_COMPLETION = {
  id:      'local-resp-001',
  model:   'llama3.2',
  choices: [{ message: { role: 'assistant', content: 'Response from local model!' } }],
  usage:   { prompt_tokens: 3, completion_tokens: 8, total_tokens: 11 },
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
});

afterEach(() => {
  delete process.env.LOCAL_BASE_URL;
  delete process.env.LOCAL_API_KEY;
});

// ── Successful execution ──────────────────────────────────────────────────────

describe('successful execution', () => {
  test('returns normalized ProviderResponse for Ollama', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const result = await callLocal(VALID_BODY, VALID_META);
    expect(result.output).toBe('Response from local model!');
    expect(result.provider).toBe('local');
    expect(result.model).toBe('llama3.2');
    _resetClient();
  });

  test('accepts any non-empty model name', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    for (const model of ['llama3.2', 'phi3', 'mistral', 'deepseek-r1:7b']) {
      jest.clearAllMocks();
      setupMockClient({ ...VALID_COMPLETION, model });
      await expect(callLocal({ ...VALID_BODY, model }, VALID_META)).resolves.toBeDefined();
    }
    _resetClient();
  });

  test('uses LOCAL_API_KEY when set', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    process.env.LOCAL_API_KEY  = 'my-local-key';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    await callLocal(VALID_BODY, VALID_META);
    const constructorCall = OpenAI.mock.calls[0][0];
    expect(constructorCall.apiKey).toBe('my-local-key');
    _resetClient();
  });

  test('uses placeholder key when LOCAL_API_KEY not set', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    await callLocal(VALID_BODY, VALID_META);
    const constructorCall = OpenAI.mock.calls[0][0];
    expect(constructorCall.apiKey).toBe('local');
    _resetClient();
  });

  test('tokenUsage populated', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const result = await callLocal(VALID_BODY, VALID_META);
    expect(result.tokenUsage.inputTokens).toBe(3);
    expect(result.tokenUsage.outputTokens).toBe(8);
    _resetClient();
  });
});

// ── URL validation ────────────────────────────────────────────────────────────

describe('URL validation', () => {
  test('rejects file:// URL', async () => {
    process.env.LOCAL_BASE_URL = 'file:///etc/passwd';
    OpenAI.mockImplementation(() => ({}));
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const err = await callLocal(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_CONFIG_INVALID');
    _resetClient();
  });

  test('rejects ftp:// URL', async () => {
    process.env.LOCAL_BASE_URL = 'ftp://localhost/v1';
    OpenAI.mockImplementation(() => ({}));
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const err = await callLocal(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_CONFIG_INVALID');
    _resetClient();
  });

  test('accepts http://127.0.0.1 endpoint', async () => {
    process.env.LOCAL_BASE_URL = 'http://127.0.0.1:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    await expect(callLocal(VALID_BODY, VALID_META)).resolves.toBeDefined();
    _resetClient();
  });

  test('accepts https://private-server.local endpoint', async () => {
    process.env.LOCAL_BASE_URL = 'https://private-server.local/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    await expect(callLocal(VALID_BODY, VALID_META)).resolves.toBeDefined();
    _resetClient();
  });

  test('throws PROVIDER_CONFIG_INVALID when LOCAL_BASE_URL not set', async () => {
    delete process.env.LOCAL_BASE_URL;
    OpenAI.mockImplementation(() => ({}));
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const err = await callLocal(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_CONFIG_INVALID');
    _resetClient();
  });
});

// ── Payload validation ────────────────────────────────────────────────────────

describe('payload validation', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED for null model', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const err = await callLocal({ ...VALID_BODY, model: null }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    _resetClient();
  });

  test('throws PROVIDER_INVALID_REQUEST for empty messages', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const err = await callLocal({ ...VALID_BODY, messages: [] }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
    _resetClient();
  });
});

// ── Failure scenarios ─────────────────────────────────────────────────────────

describe('failure scenarios', () => {
  test('ECONNREFUSED → PROVIDER_UNAVAILABLE (Ollama not running)', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const err = await callLocal(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetClient();
  });

  test('malformed response → PROVIDER_INVALID_RESPONSE', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient({ id: 'x', choices: [{ message: { role: 'assistant', content: null } }] });
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    const err = await callLocal(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
    _resetClient();
  });
});

// ── Audit attribution ─────────────────────────────────────────────────────────

describe('audit attribution', () => {
  test('emits PROVIDER_EXECUTION_START with provider=local', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    await callLocal(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_EXECUTION_START', expect.objectContaining({
      provider: 'local',
    }));
    _resetClient();
  });

  test('emits LOCAL_PROVIDER_ENDPOINT_CONFIGURED on first client creation', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockClient(VALID_COMPLETION);
    const { callLocal, _resetClient } = require('../local');
    _resetClient();
    await callLocal(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'LOCAL_PROVIDER_ENDPOINT_CONFIGURED', expect.any(Object));
    _resetClient();
  });
});
