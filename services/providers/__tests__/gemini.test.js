'use strict';

jest.mock('../../logger', () => ({ emit: jest.fn() }));

const { emit }      = require('../../logger');
const { callGemini } = require('../gemini');

// ── Helpers ───────────────────────────────────────────────────────────────────

const VALID_BODY = {
  model:    'gemini-1.5-flash',
  messages: [{ role: 'user', content: 'Hello' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

const VALID_GEMINI_RESPONSE = {
  candidates: [{
    content: {
      parts: [{ text: 'Hello from Gemini!' }],
      role:  'model',
    },
    finishReason:  'STOP',
    safetyRatings: [],
  }],
  usageMetadata: {
    promptTokenCount:     10,
    candidatesTokenCount: 15,
    totalTokenCount:      25,
  },
};

function mockFetchOk(body) {
  global.fetch = jest.fn().mockResolvedValueOnce({
    ok: true, status: 200, json: async () => body,
  });
}

function mockFetchError(status) {
  global.fetch = jest.fn().mockResolvedValue({
    ok: false, status, json: async () => ({ error: { message: 'error' } }),
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.GEMINI_API_KEY = 'gm-test-key';
});

afterEach(() => {
  delete process.env.GEMINI_API_KEY;
  delete global.fetch;
});

// ── Successful execution ──────────────────────────────────────────────────────

describe('successful execution', () => {
  test('returns normalized ProviderResponse', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    const result = await callGemini(VALID_BODY, VALID_META);
    expect(result.output).toBe('Hello from Gemini!');
    expect(result.provider).toBe('gemini');
    expect(result.model).toBe('gemini-1.5-flash');
  });

  test('tokenUsage is populated from usageMetadata', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    const result = await callGemini(VALID_BODY, VALID_META);
    expect(result.tokenUsage.inputTokens).toBe(10);
    expect(result.tokenUsage.outputTokens).toBe(15);
    expect(result.tokenUsage.totalTokens).toBe(25);
  });

  test('responseId is null (Gemini does not return response ID)', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    const result = await callGemini(VALID_BODY, VALID_META);
    expect(result.executionMetadata.responseId).toBeNull();
  });

  // inverted from the pre-fix "API key is sent in query string" assertion — the key now
  // travels in Google's documented x-goog-api-key header and the URL carries no credential.
  test('API key is sent in the x-goog-api-key header, never in the URL (and not as Authorization)', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    await callGemini(VALID_BODY, VALID_META);
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).not.toContain('gm-test-key');
    expect(url).not.toMatch(/[?&]key=/);
    expect(url).toBe('https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent');
    expect(opts.headers['x-goog-api-key']).toBe('gm-test-key');
    expect(opts.headers?.authorization).toBeUndefined();
  });

  test('the API key never appears in any emitted log event, on success or failure', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    await callGemini(VALID_BODY, VALID_META);
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });
    await callGemini(VALID_BODY, VALID_META).catch(() => {});
    global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed'));
    await callGemini(VALID_BODY, VALID_META).catch(() => {});
    expect(emit.mock.calls.length).toBeGreaterThan(0);
    expect(JSON.stringify(emit.mock.calls)).not.toContain('gm-test-key');
  });

  test('model name is included in endpoint URL', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    await callGemini(VALID_BODY, VALID_META);
    const [url] = global.fetch.mock.calls[0];
    expect(url).toContain('gemini-1.5-flash');
  });

  test('messages are transformed to Gemini contents format', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    await callGemini(VALID_BODY, VALID_META);
    const [, opts] = global.fetch.mock.calls[0];
    const body = JSON.parse(opts.body);
    expect(body.contents).toBeDefined();
    expect(body.contents[0].role).toBe('user');
    expect(body.contents[0].parts[0].text).toBe('Hello');
  });

  test('assistant role is mapped to model role in Gemini format', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    const body = {
      ...VALID_BODY,
      messages: [
        { role: 'user',      content: 'Hello' },
        { role: 'assistant', content: 'Hi' },
      ],
    };
    await callGemini(body, VALID_META);
    const [, opts] = global.fetch.mock.calls[0];
    const fetchBody = JSON.parse(opts.body);
    expect(fetchBody.contents[1].role).toBe('model');
  });

  test('system messages are extracted to systemInstruction', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    const body = {
      ...VALID_BODY,
      messages: [
        { role: 'system', content: 'You are helpful.' },
        { role: 'user',   content: 'Hello' },
      ],
    };
    await callGemini(body, VALID_META);
    const [, opts] = global.fetch.mock.calls[0];
    const fetchBody = JSON.parse(opts.body);
    expect(fetchBody.systemInstruction).toBeDefined();
    expect(fetchBody.systemInstruction.parts[0].text).toBe('You are helpful.');
    // System message must not appear in contents
    expect(fetchBody.contents.every(c => c.role !== 'system')).toBe(true);
  });
});

// ── Model allowlist ───────────────────────────────────────────────────────────

describe('model allowlist', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED for unknown model', async () => {
    const err = await callGemini({ ...VALID_BODY, model: 'gpt-4' }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('accepts gemini-2.0-flash', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    await expect(callGemini({ ...VALID_BODY, model: 'gemini-2.0-flash' }, VALID_META)).resolves.toBeDefined();
  });
});

// ── Payload validation ────────────────────────────────────────────────────────

describe('payload validation', () => {
  test('throws PROVIDER_INVALID_REQUEST when no user message', async () => {
    const messages = [{ role: 'system', content: 'system only' }];
    const err = await callGemini({ ...VALID_BODY, messages }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
  });

  test('throws PROVIDER_REQUEST_REJECTED for too many messages', async () => {
    const messages = Array.from({ length: 51 }, () => ({ role: 'user', content: 'x' }));
    const err = await callGemini({ ...VALID_BODY, messages }, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_REQUEST_REJECTED');
  });
});

// ── Authentication ────────────────────────────────────────────────────────────

describe('authentication', () => {
  test('throws PROVIDER_AUTH_FAILED when GEMINI_API_KEY missing', async () => {
    delete process.env.GEMINI_API_KEY;
    global.fetch = jest.fn();
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

// ── Failure scenarios ─────────────────────────────────────────────────────────

describe('failure scenarios', () => {
  test('HTTP 401 → PROVIDER_AUTH_FAILED', async () => {
    mockFetchError(401);
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('HTTP 429 → PROVIDER_RATE_LIMITED (after retries)', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 429, json: async () => ({}) });
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
  });

  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('network error → PROVIDER_UNAVAILABLE', async () => {
    const netErr = new TypeError('Failed to fetch');
    global.fetch = jest.fn().mockRejectedValue(netErr);
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('AbortError → PROVIDER_TIMEOUT', async () => {
    const abortErr = new Error('aborted');
    abortErr.name  = 'AbortError';
    global.fetch   = jest.fn().mockRejectedValue(abortErr);
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_TIMEOUT');
  });

  test('empty candidates array → PROVIDER_INVALID_RESPONSE', async () => {
    mockFetchOk({ candidates: [], usageMetadata: {} });
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });

  test('missing candidates → PROVIDER_INVALID_RESPONSE', async () => {
    mockFetchOk({ usageMetadata: {} });
    const err = await callGemini(VALID_BODY, VALID_META).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_RESPONSE');
  });
});

// ── Audit attribution ─────────────────────────────────────────────────────────

describe('audit attribution', () => {
  test('PROVIDER_EXECUTION_START includes model and provider', async () => {
    mockFetchOk(VALID_GEMINI_RESPONSE);
    await callGemini(VALID_BODY, VALID_META);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_EXECUTION_START', expect.objectContaining({
      provider: 'gemini',
      model:    'gemini-1.5-flash',
    }));
  });
});
