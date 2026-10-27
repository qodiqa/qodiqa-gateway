'use strict';

/**
 * openai.stream.js — dedicated adapter regression coverage.
 *
 * Mirrors mistral.stream.test.js's conventions exactly — openai.stream.js
 * and mistral.stream.js share the identical TRANSPORTS.sdkStream/
 * createLazyClient shape, differing only in base URL (hardcoded here, not
 * configurable) and model allowlist.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));
jest.mock('openai');

const { emit }   = require('../../logger');
const { OpenAI } = require('openai');
const { callOpenAIStream, _resetClient } = require('../openai.stream');

const VALID_BODY = {
  model:    'gpt-4o',
  messages: [{ role: 'user', content: 'Hello OpenAI' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

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
  process.env.OPENAI_API_KEY = 'sk-test-key';
  _resetClient();
});

afterEach(() => {
  delete process.env.OPENAI_API_KEY;
  _resetClient();
});

describe('successful streaming', () => {
  test('yields each delta in order', async () => {
    setupMockStream(chunksOf('Hello', ' from', ' OpenAI!'));
    const chunks = await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'Hello' }, { delta: ' from' }, { delta: ' OpenAI!' }]);
  });

  test('request is sent with stream: true', async () => {
    const mockCreate = setupMockStream(chunksOf('hi'));
    await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(mockCreate.mock.calls[0][0].stream).toBe(true);
  });

  test('request preserves model and messages unmodified', async () => {
    const mockCreate = setupMockStream(chunksOf('hi'));
    await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(mockCreate.mock.calls[0][0].model).toBe('gpt-4o');
    expect(mockCreate.mock.calls[0][0].messages).toEqual(VALID_BODY.messages);
  });

  test('OpenAI client is constructed with the canonical OpenAI base URL', async () => {
    setupMockStream(chunksOf('hi'));
    await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(OpenAI.mock.calls[0][0].baseURL).toBe('https://api.openai.com/v1');
  });

  test('emits PROVIDER_STREAM_START and PROVIDER_STREAM_COMPLETE', async () => {
    setupMockStream(chunksOf('hi'));
    await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_START', expect.objectContaining({ provider: 'openai' }));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'openai' }));
  });

  test('emits PROVIDER_STREAM_FIRST_CHUNK exactly once, on the first non-empty delta', async () => {
    setupMockStream(chunksOf('', 'first', 'second'));
    await drain(callOpenAIStream(VALID_BODY, VALID_META));
    const firstChunkCalls = emit.mock.calls.filter(([, event]) => event === 'PROVIDER_STREAM_FIRST_CHUNK');
    expect(firstChunkCalls).toHaveLength(1);
  });
});

describe('stream parsing — provider-specific chunk shape', () => {
  test('a chunk with no delta content is skipped, not yielded as an empty string', async () => {
    setupMockStream(chunksOf('start', '', 'end'));
    const chunks = await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'start' }, { delta: 'end' }]);
  });

  test('a chunk shaped without choices[0].delta.content at all is skipped safely', async () => {
    async function* mixed() {
      yield { choices: [{ delta: {} }] };          // no content key
      yield { choices: [{ delta: { content: 'ok' } }] };
      yield { choices: [] };                        // no choices at all
      yield {};                                      // no choices key at all
      yield TERMINAL_CHUNK; // fixture correction: a complete stream ends with finish_reason
    }
    setupMockStream(mixed());
    const chunks = await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'ok' }]);
  });

  test('a non-string delta (e.g. null) is skipped, not coerced', async () => {
    async function* nullDelta() {
      yield { choices: [{ delta: { content: null } }] };
      yield { choices: [{ delta: { content: 'ok' } }] };
      yield TERMINAL_CHUNK; // fixture correction: a complete stream ends with finish_reason
    }
    setupMockStream(nullDelta());
    const chunks = await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'ok' }]);
  });

  // INVERTED from "an empty stream completes with zero deltas, not an error" — that asserted
  // the defect: a stream that ends without the terminal finish_reason is truncated, not an empty success.
  test('an empty stream (zero chunks, no finish_reason) is an incomplete stream — error, not success', async () => {
    async function* empty() {}
    setupMockStream(empty());
    await expect(drain(callOpenAIStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
  });

  test('ordering is preserved across many chunks (not reordered or batched)', async () => {
    const deltas = Array.from({ length: 20 }, (_, i) => `t${i}`);
    setupMockStream(chunksOf(...deltas));
    const chunks = await drain(callOpenAIStream(VALID_BODY, VALID_META));
    expect(chunks.map((c) => c.delta)).toEqual(deltas);
  });
});

describe('model allowlist', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED for an unlisted model', async () => {
    const err = await drain(callOpenAIStream({ ...VALID_BODY, model: 'not-a-real-model' }, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });

  test('accepts gpt-3.5-turbo', async () => {
    setupMockStream(chunksOf('ok'));
    await expect(drain(callOpenAIStream({ ...VALID_BODY, model: 'gpt-3.5-turbo' }, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });
});

describe('payload validation', () => {
  test('throws PROVIDER_INVALID_REQUEST for empty messages', async () => {
    const err = await drain(callOpenAIStream({ ...VALID_BODY, messages: [] }, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
  });
});

describe('authentication', () => {
  test('throws PROVIDER_AUTH_FAILED when API key missing', async () => {
    delete process.env.OPENAI_API_KEY;
    const err = await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });
});

describe('provider error propagation', () => {
  test('HTTP 429 → PROVIDER_RATE_LIMITED', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('429'), { status: 429 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
  });

  test('HTTP 401 → PROVIDER_AUTH_FAILED', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('401'), { status: 401 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const err = await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('network ECONNREFUSED → PROVIDER_UNAVAILABLE', async () => {
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const err = await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  // baseAdapter.js's TRANSPORTS.sdkStream is documented as deliberately
  // treating AbortError as a timeout — an asymmetry vs. the non-streaming
  // `sdk` transport, which does not. This pins that adapter-specific
  // contract point rather than assuming it.
  test('AbortError → PROVIDER_TIMEOUT (sdkStream-specific: unlike the non-streaming sdk transport)', async () => {
    const abortErr = Object.assign(new Error('aborted'), { name: 'AbortError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(abortErr) } } }));
    const err = await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_TIMEOUT');
  });

  test('a mid-stream throw is classified the same as an upfront rejection', async () => {
    async function* throwsMidStream() {
      yield { choices: [{ delta: { content: 'partial' } }] };
      const err = new Error('500'); err.status = 500;
      throw err;
    }
    setupMockStream(throwsMidStream());
    const err = await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('chunks yielded before a mid-stream error are not lost, but the stream ultimately rejects', async () => {
    async function* throwsMidStream() {
      yield { choices: [{ delta: { content: 'partial' } }] };
      const err = new Error('500'); err.status = 500;
      throw err;
    }
    setupMockStream(throwsMidStream());
    const seen = [];
    const gen = callOpenAIStream(VALID_BODY, VALID_META);
    await expect((async () => {
      for await (const c of gen) seen.push(c);
    })()).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
    expect(seen).toEqual([{ delta: 'partial' }]);
  });

  test('emits no PROVIDER_STREAM_COMPLETE when the stream errors', async () => {
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    await drain(callOpenAIStream(VALID_BODY, VALID_META)).catch(() => {});
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_START', expect.objectContaining({ provider: 'openai' }));
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
    const err = await (async () => { for await (const ch of callOpenAIStream(VALID_BODY, VALID_META)) seen.push(ch); })().catch((e) => e);
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(err).toBeInstanceOf(Error);
    expect(err).toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_INCOMPLETE', expect.objectContaining({ provider: 'openai', emittedOutput: true }));
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
  });

  test.each(['stop', 'length', 'content_filter', 'tool_calls'])('finish_reason %s is a terminal signal — stream completes', async (reason) => {
    
    async function* ended() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: reason }] };
    }
    setupMockStream(ended());
    
    await expect(drain(callOpenAIStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'openai' }));
  });

  test('finish_reason on the same chunk as the last content (some servers do this) completes', async () => {
    
    async function* sameChunk() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: 'stop' }] }; }
    setupMockStream(sameChunk());
    
    await expect(drain(callOpenAIStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('a trailing usage-only chunk (choices: []) after the terminal chunk still completes', async () => {
    
    async function* withUsage() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] };
      yield { choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } };
    }
    setupMockStream(withUsage());
    
    await expect(drain(callOpenAIStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('an empty-string finish_reason is NOT terminal (fail closed)', async () => {
    
    async function* emptyReason() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: '' }] }; }
    setupMockStream(emptyReason());
    
    await expect(drain(callOpenAIStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
  });
});
