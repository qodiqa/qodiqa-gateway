'use strict';

jest.mock('../../logger', () => ({ emit: jest.fn() }));

const { emit }         = require('../../logger');
const { callAnthropic } = require('../anthropic');

// ── Helpers ───────────────────────────────────────────────────────────────────

const VALID_BODY = {
  model:    'claude-3-5-sonnet-20241022',
  messages: [{ role: 'user', content: 'Hello' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

function mockFetchOk(responseBody) {
  global.fetch = jest.fn().mockResolvedValueOnce({
    ok:     true,
    status: 200,
    json:   async () => responseBody,
  });
}

function mockFetchError(status) {
  global.fetch = jest.fn().mockResolvedValue({
    ok:     false,
    status,
    json:   async () => ({ error: { message: 'error' } }),
  });
}

function mockFetchNetworkError(code) {
  const err  = new Error('Network error');
  err.code   = code;
  global.fetch = jest.fn().mockRejectedValue(err);
}

const VALID_ANTHROPIC_RESPONSE = {
  id:    'msg_01abc',
  type:  'message',
  role:  'assistant',
  model: 'claude-3-5-sonnet-20241022',
  content: [{ type: 'text', text: 'Hello there!' }],
  usage: { input_tokens: 10, output_tokens: 20 },
};

beforeEach(() => {
  jest.clearAllMocks();
  process.env.ANTHROPIC_API_KEY = 'test-key';
});

afterEach(() => {
  delete process.env.ANTHROPIC_API_KEY;
  delete global.fetch;
});

// ── Successful execution ──────────────────────────────────────────────────────

describe('successful execution', () => {
  test('returns normalized ProviderResponse on success', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    const result = await callAnthropic(VALID_BODY, VALID_META);
    expect(result.output).toBe('Hello there!');
    expect(result.provider).toBe('anthropic');
    expect(result.model).toBe('claude-3-5-sonnet-20241022');
  });

  test('tokenUsage is populated from response usage', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    const result = await callAnthropic(VALID_BODY, VALID_META);
    expect(result.tokenUsage.inputTokens).toBe(10);
    expect(result.tokenUsage.outputTokens).toBe(20);
  });

  test('executionMetadata.responseId is set from response id', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    const result = await callAnthropic(VALID_BODY, VALID_META);
    expect(result.executionMetadata.responseId).toBe('msg_01abc');
  });

  test('executionMetadata.latencyMs is a positive number', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    const result = await callAnthropic(VALID_BODY, VALID_META);
    expect(typeof result.executionMetadata.latencyMs).toBe('number');
    expect(result.executionMetadata.latencyMs).toBeGreaterThanOrEqual(0);
  });

  test('result is frozen', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    const result = await callAnthropic(VALID_BODY, VALID_META);
    expect(Object.isFrozen(result)).toBe(true);
  });

  test('emits PROVIDER_REQUEST_VALIDATED and PROVIDER_EXECUTION_COMPLETE', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    await callAnthropic(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_REQUEST_VALIDATED', expect.objectContaining({ provider: 'anthropic' }));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_EXECUTION_COMPLETE', expect.objectContaining({ provider: 'anthropic' }));
  });

  test('handles system messages by extracting them', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    const bodyWithSystem = {
      ...VALID_BODY,
      messages: [
        { role: 'system', content: 'You are a helpful assistant.' },
        { role: 'user', content: 'Hello' },
      ],
    };
    await expect(callAnthropic(bodyWithSystem, VALID_META)).resolves.toBeDefined();
    // The fetch body should not contain 'system' role in messages array
    const callArgs = global.fetch.mock.calls[0];
    const fetchBody = JSON.parse(callArgs[1].body);
    expect(fetchBody.messages.every(m => m.role !== 'system')).toBe(true);
    expect(fetchBody.system).toBe('You are a helpful assistant.');
  });
});

// ── Model allowlist ───────────────────────────────────────────────────────────

describe('model allowlist', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED for unknown model', async () => {
    const err = await callAnthropic({ ...VALID_BODY, model: 'gpt-4' }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('throws PROVIDER_MODEL_NOT_ALLOWED when model is null', async () => {
    const err = await callAnthropic({ ...VALID_BODY, model: null }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('accepts all claude-3-5-sonnet-20241022 model', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    await expect(callAnthropic({ ...VALID_BODY, model: 'claude-3-5-sonnet-20241022' }, VALID_META)).resolves.toBeDefined();
  });

  test('no fetch call on model rejection', async () => {
    global.fetch = jest.fn();
    await callAnthropic({ ...VALID_BODY, model: 'bad-model' }, VALID_META).catch(() => {});
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

// ── Payload validation ────────────────────────────────────────────────────────

describe('payload validation', () => {
  test('throws PROVIDER_INVALID_REQUEST for empty messages', async () => {
    const err = await callAnthropic({ ...VALID_BODY, messages: [] }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
  });

  test('throws PROVIDER_INVALID_REQUEST for null body', async () => {
    const err = await callAnthropic(null, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('throws PROVIDER_REQUEST_REJECTED for too many messages', async () => {
    const messages = Array.from({ length: 51 }, (_, i) => ({ role: 'user', content: `msg${i}` }));
    const err = await callAnthropic({ ...VALID_BODY, messages }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_REQUEST_REJECTED');
  });

  test('throws PROVIDER_REQUEST_REJECTED for content exceeding limit', async () => {
    const messages = [{ role: 'user', content: 'x'.repeat(33_000) }];
    const err = await callAnthropic({ ...VALID_BODY, messages }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_REQUEST_REJECTED');
  });

  test('throws PROVIDER_INVALID_REQUEST for invalid role', async () => {
    const messages = [{ role: 'bot', content: 'hello' }];
    const err = await callAnthropic({ ...VALID_BODY, messages }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
  });

  test('throws PROVIDER_INVALID_REQUEST for system-only messages', async () => {
    const messages = [{ role: 'system', content: 'system only' }];
    const err = await callAnthropic({ ...VALID_BODY, messages }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
  });
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('authentication', () => {
  test('throws PROVIDER_AUTH_FAILED when API key missing', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    global.fetch = jest.fn();
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

// ── Failure scenarios ─────────────────────────────────────────────────────────

describe('failure scenarios', () => {
  test('HTTP 401 → PROVIDER_AUTH_FAILED', async () => {
    mockFetchError(401);
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('HTTP 403 → PROVIDER_AUTH_FAILED', async () => {
    mockFetchError(403);
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('HTTP 429 → PROVIDER_RATE_LIMITED', async () => {
    // Both attempts return 429 to exhaust retries
    global.fetch = jest.fn().mockResolvedValue({
      ok: false, status: 429, json: async () => ({}),
    });
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
  });

  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false, status: 500, json: async () => ({}),
    });
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('HTTP 400 → PROVIDER_INVALID_REQUEST', async () => {
    mockFetchError(400);
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
  });

  test('network error ECONNREFUSED → PROVIDER_UNAVAILABLE', async () => {
    mockFetchNetworkError('ECONNREFUSED');
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('AbortError (timeout) → PROVIDER_TIMEOUT', async () => {
    const abortErr = new Error('aborted');
    abortErr.name  = 'AbortError';
    global.fetch   = jest.fn().mockRejectedValue(abortErr);
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_TIMEOUT');
  });

  test('malformed response (no content array) → PROVIDER_INVALID_RESPONSE', async () => {
    mockFetchOk({ id: 'msg-001', content: [], model: 'claude-3-5-sonnet-20241022' });
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });

  test('malformed response (content is not array) → PROVIDER_INVALID_RESPONSE', async () => {
    mockFetchOk({ id: 'msg-001', content: 'not an array', model: 'claude-3-5-sonnet-20241022' });
    const err = await callAnthropic(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });

  test('emits PROVIDER_EXECUTION_FAILED on error', async () => {
    mockFetchError(500);
    await callAnthropic(VALID_BODY, VALID_META).catch(() => {});
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_EXECUTION_FAILED', expect.objectContaining({
      provider: 'anthropic', code: 'PROVIDER_UNAVAILABLE',
    }));
  });
});

// ── Audit attribution ─────────────────────────────────────────────────────────

describe('audit attribution', () => {
  test('PROVIDER_REQUEST_VALIDATED includes requestId', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    await callAnthropic(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_REQUEST_VALIDATED', expect.objectContaining({
      requestId: 'req-001',
    }));
  });

  test('PROVIDER_EXECUTION_COMPLETE includes policyHash', async () => {
    mockFetchOk(VALID_ANTHROPIC_RESPONSE);
    await callAnthropic(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_EXECUTION_COMPLETE', expect.objectContaining({
      policyHash: 'b'.repeat(64),
    }));
  });
});
