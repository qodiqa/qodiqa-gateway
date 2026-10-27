'use strict';

/**
 * mistral.stream.js — native streaming adapter regression coverage.
 *
 * Mirrors mistral.test.js's (non-streaming) conventions exactly, adapted for
 * the streaming shape: `create()` resolves to an async-iterable stream of
 * `{ choices: [{ delta: { content } }] }` chunks instead of a single
 * completion object — matching the real `openai` SDK's own streaming
 * response shape, the same contract local.stream.js already relies on.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('openai');

const { emit }   = require('../../logger');
const { OpenAI } = require('openai');
const { callMistralStream, _resetStreamClient } = require('../mistral.stream');

const VALID_BODY = {
  model:    'mistral-large-latest',
  messages: [{ role: 'user', content: 'Hello Mistral' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

// A plain async generator satisfies `for await...of` / `yield*` — the same
// minimal shape the real OpenAI SDK's Stream class provides.
async function* chunksOf(...deltas) {
  for (const delta of deltas) {
    yield { choices: [{ delta: { content: delta } }] };
  }
  // every complete OpenAI-compatible stream ends with a chunk carrying a non-null finish_reason
  // (recorded-contract shape: final chunk has an empty delta and finish_reason 'stop'; [DONE] is consumed by the SDK).
  yield TERMINAL_CHUNK;
}

const TERMINAL_CHUNK = Object.freeze({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] });

function setupMockStream(asyncGen) {
  const mockCreate = jest.fn().mockResolvedValue(asyncGen);
  OpenAI.mockImplementation(() => ({
    chat: { completions: { create: mockCreate } },
  }));
  return mockCreate;
}

async function drain(gen) {
  const chunks = [];
  for await (const c of gen) chunks.push(c);
  return chunks;
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.MISTRAL_API_KEY = 'ms-test-key';
  delete process.env.MISTRAL_BASE_URL;
  _resetStreamClient();
});

afterEach(() => {
  delete process.env.MISTRAL_API_KEY;
  delete process.env.MISTRAL_BASE_URL;
  _resetStreamClient();
});

describe('successful streaming', () => {
  test('yields each delta in order', async () => {
    setupMockStream(chunksOf('Hello', ' from', ' Mistral!'));
    const chunks = await drain(callMistralStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'Hello' }, { delta: ' from' }, { delta: ' Mistral!' }]);
  });

  test('request is sent with stream: true', async () => {
    const mockCreate = setupMockStream(chunksOf('hi'));
    await drain(callMistralStream(VALID_BODY, VALID_META));
    expect(mockCreate.mock.calls[0][0].stream).toBe(true);
  });

  test('OpenAI client is constructed with the Mistral base URL', async () => {
    setupMockStream(chunksOf('hi'));
    await drain(callMistralStream(VALID_BODY, VALID_META));
    expect(OpenAI.mock.calls[0][0].baseURL).toBe('https://api.mistral.ai/v1');
  });

  test('emits PROVIDER_STREAM_START and PROVIDER_STREAM_COMPLETE', async () => {
    setupMockStream(chunksOf('hi'));
    await drain(callMistralStream(VALID_BODY, VALID_META));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_START', expect.objectContaining({ provider: 'mistral' }));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'mistral' }));
  });
});

describe('stream parsing — provider-specific chunk shape', () => {
  test('a chunk with no delta content is skipped, not yielded as an empty string', async () => {
    setupMockStream(chunksOf('start', '', 'end'));
    const chunks = await drain(callMistralStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'start' }, { delta: 'end' }]);
  });

  test('a chunk shaped without choices[0].delta.content at all is skipped safely', async () => {
    async function* mixed() {
      yield { choices: [{ delta: {} }] };          // no content key
      yield { choices: [{ delta: { content: 'ok' } }] };
      yield { choices: [] };                        // no choices at all
      yield TERMINAL_CHUNK; // fixture correction: a complete stream ends with finish_reason
    }
    setupMockStream(mixed());
    const chunks = await drain(callMistralStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'ok' }]);
  });

  // INVERTED from "an empty stream completes with zero deltas, not an error" — that asserted
  // the defect: a stream that ends without the terminal finish_reason is truncated, not an empty success.
  test('an empty stream (zero chunks, no finish_reason) is an incomplete stream — error, not success', async () => {
    async function* empty() {}
    setupMockStream(empty());
    await expect(drain(callMistralStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
  });
});

describe('model allowlist', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED for a non-Mistral model', async () => {
    const err = await drain(callMistralStream({ ...VALID_BODY, model: 'gpt-4' }, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('accepts mistral-small-latest', async () => {
    setupMockStream(chunksOf('ok'));
    await expect(drain(callMistralStream({ ...VALID_BODY, model: 'mistral-small-latest' }, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });
});

describe('authentication', () => {
  test('throws PROVIDER_AUTH_FAILED when API key missing', async () => {
    delete process.env.MISTRAL_API_KEY;
    const err = await drain(callMistralStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });
});

describe('provider error propagation', () => {
  test('HTTP 429 → PROVIDER_RATE_LIMITED', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('429'), { status: 429 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await drain(callMistralStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
  });

  test('HTTP 401 → PROVIDER_AUTH_FAILED', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('401'), { status: 401 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await drain(callMistralStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('network ECONNREFUSED → PROVIDER_UNAVAILABLE', async () => {
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const err = await drain(callMistralStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('a mid-stream throw is classified the same as an upfront rejection', async () => {
    async function* throwsMidStream() {
      yield { choices: [{ delta: { content: 'partial' } }] };
      const err = new Error('500'); err.status = 500;
      throw err;
    }
    setupMockStream(throwsMidStream());
    const err = await drain(callMistralStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('emits PROVIDER_EXECUTION_FAILED-equivalent WARN on error (PROVIDER_STREAM_START still fires first)', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    await drain(callMistralStream(VALID_BODY, VALID_META)).catch(() => {});
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_START', expect.objectContaining({ provider: 'mistral' }));
  });
});

// ── truncated streams must fail ──────────────
// RECORDED-CONTRACT FIXTURES (mocked openai SDK, no network): chunk shapes follow the OpenAI Chat Completions
// streaming contract ("chat.completion.chunk": choices[].finish_reason null until the final chunk).
describe('a stream that ends without finish_reason is truncated, never a success', () => {
  async function* truncated() {
    yield { choices: [{ index: 0, delta: { role: 'assistant', content: '' }, finish_reason: null }] };
    yield { choices: [{ index: 0, delta: { content: 'partial' }, finish_reason: null }] };
    // connection ends here: no finish_reason chunk (and no [DONE])
  }
  test('partial output is yielded, then the stream FAILS with PROVIDER_UNAVAILABLE (providerMayHaveExecuted)', async () => {
    
    setupMockStream(truncated());
    
    const seen = [];
    const err = await (async () => { for await (const ch of callMistralStream(VALID_BODY, VALID_META)) seen.push(ch); })().catch((e) => e);
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(err).toBeInstanceOf(Error);
    expect(err).toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_INCOMPLETE', expect.objectContaining({ provider: 'mistral', emittedOutput: true }));
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
  });

  test.each(['stop', 'length', 'content_filter', 'tool_calls'])('finish_reason %s is a terminal signal — stream completes', async (reason) => {
    
    async function* ended() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: reason }] };
    }
    setupMockStream(ended());
    
    await expect(drain(callMistralStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'mistral' }));
  });

  test('finish_reason on the same chunk as the last content (some servers do this) completes', async () => {
    
    async function* sameChunk() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: 'stop' }] }; }
    setupMockStream(sameChunk());
    
    await expect(drain(callMistralStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('a trailing usage-only chunk (choices: []) after the terminal chunk still completes', async () => {
    
    async function* withUsage() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] };
      yield { choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } };
    }
    setupMockStream(withUsage());
    
    await expect(drain(callMistralStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('an empty-string finish_reason is NOT terminal (fail closed)', async () => {
    
    async function* emptyReason() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: '' }] }; }
    setupMockStream(emptyReason());
    
    await expect(drain(callMistralStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
  });
});
