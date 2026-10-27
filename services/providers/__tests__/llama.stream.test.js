'use strict';

/**
 * llama.stream.js — native streaming adapter regression coverage.
 *
 * Mirrors llama.test.js's (non-streaming) conventions exactly, adapted for
 * the streaming shape: `create()` resolves to an async-iterable stream of
 * `{ choices: [{ delta: { content } }] }` chunks instead of a single
 * completion object.
 */

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
});

afterEach(() => {
  delete process.env.LLAMA_BASE_URL;
  delete process.env.LLAMA_API_KEY;
});

describe('successful streaming', () => {
  test('yields each delta in order (cloud-hosted Llama)', async () => {
    process.env.LLAMA_BASE_URL = 'https://api.groq.com/openai/v1';
    setupMockStream(chunksOf('Hello', ' from', ' Llama!'));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const chunks = await drain(callLlamaStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'Hello' }, { delta: ' from' }, { delta: ' Llama!' }]);
    _resetStreamClient();
  });

  test('yields each delta in order (self-hosted Llama)', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockStream(chunksOf('hi', ' there'));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const chunks = await drain(callLlamaStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'hi' }, { delta: ' there' }]);
    _resetStreamClient();
  });

  test('request is sent with stream: true', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const mockCreate = setupMockStream(chunksOf('hi'));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    await drain(callLlamaStream(VALID_BODY, VALID_META));
    expect(mockCreate.mock.calls[0][0].stream).toBe(true);
    _resetStreamClient();
  });

  test('any non-empty model name is accepted (deployment-specific allowlist)', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    for (const model of ['llama3.2', 'llama-3.1-8b', 'meta-llama/Llama-3.2-3B-Instruct']) {
      jest.clearAllMocks();
      // The lazy client is cached across calls (createLazyClient) — each
      // iteration needs a fresh client so it picks up this iteration's own
      // (single-use) async-generator mock instead of reusing an
      // already-exhausted one from the previous iteration.
      _resetStreamClient();
      setupMockStream(chunksOf('ok'));
      const chunks = await drain(callLlamaStream({ ...VALID_BODY, model }, VALID_META));
      expect(chunks).toEqual([{ delta: 'ok' }]);
    }
    _resetStreamClient();
  });

  test('emits PROVIDER_STREAM_START and PROVIDER_STREAM_COMPLETE', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockStream(chunksOf('hi'));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    await drain(callLlamaStream(VALID_BODY, VALID_META));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_START', expect.objectContaining({ provider: 'llama' }));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'llama' }));
    _resetStreamClient();
  });
});

describe('stream parsing — provider-specific chunk shape', () => {
  test('a chunk with no delta content is skipped', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockStream(chunksOf('start', '', 'end'));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const chunks = await drain(callLlamaStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'start' }, { delta: 'end' }]);
    _resetStreamClient();
  });

  // INVERTED from "an empty stream completes with zero deltas, not an error" — that asserted
  // the defect: a stream that ends without the terminal finish_reason is truncated, not an empty success.
  test('an empty stream (zero chunks, no finish_reason) is an incomplete stream — error, not success', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    async function* empty() {}
    setupMockStream(empty());
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    await expect(drain(callLlamaStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    _resetStreamClient();
  });
});

describe('payload validation', () => {
  test('throws PROVIDER_INVALID_REQUEST for empty messages', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const err = await drain(callLlamaStream({ ...VALID_BODY, messages: [] }, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
    _resetStreamClient();
  });
});

describe('URL validation', () => {
  test('throws PROVIDER_CONFIG_INVALID for file:// URL', async () => {
    process.env.LLAMA_BASE_URL = 'file:///etc/passwd';
    OpenAI.mockImplementation(() => ({}));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const err = await drain(callLlamaStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_CONFIG_INVALID');
    _resetStreamClient();
  });

  test('accepts http://localhost endpoint', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:11434/v1';
    setupMockStream(chunksOf('ok'));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    await expect(drain(callLlamaStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
    _resetStreamClient();
  });
});

describe('provider error propagation', () => {
  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const err = await drain(callLlamaStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetStreamClient();
  });

  test('ECONNREFUSED → PROVIDER_UNAVAILABLE', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const err = await drain(callLlamaStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetStreamClient();
  });

  test('a mid-stream throw is classified the same as an upfront rejection', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    async function* throwsMidStream() {
      yield { choices: [{ delta: { content: 'partial' } }] };
      const err = new Error('500'); err.status = 500;
      throw err;
    }
    setupMockStream(throwsMidStream());
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream');
    _resetStreamClient();
    const err = await drain(callLlamaStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetStreamClient();
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
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    setupMockStream(truncated());
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream'); _resetStreamClient();
    const seen = [];
    const err = await (async () => { for await (const ch of callLlamaStream(VALID_BODY, VALID_META)) seen.push(ch); })().catch((e) => e);
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(err).toBeInstanceOf(Error);
    expect(err).toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_INCOMPLETE', expect.objectContaining({ provider: 'llama', emittedOutput: true }));
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
  });

  test.each(['stop', 'length', 'content_filter', 'tool_calls'])('finish_reason %s is a terminal signal — stream completes', async (reason) => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    async function* ended() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: reason }] };
    }
    setupMockStream(ended());
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream'); _resetStreamClient();
    await expect(drain(callLlamaStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'llama' }));
  });

  test('finish_reason on the same chunk as the last content (some servers do this) completes', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    async function* sameChunk() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: 'stop' }] }; }
    setupMockStream(sameChunk());
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream'); _resetStreamClient();
    await expect(drain(callLlamaStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('a trailing usage-only chunk (choices: []) after the terminal chunk still completes', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    async function* withUsage() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] };
      yield { choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } };
    }
    setupMockStream(withUsage());
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream'); _resetStreamClient();
    await expect(drain(callLlamaStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('an empty-string finish_reason is NOT terminal (fail closed)', async () => {
    process.env.LLAMA_BASE_URL = 'http://localhost:8080/v1';
    async function* emptyReason() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: '' }] }; }
    setupMockStream(emptyReason());
    const { callLlamaStream, _resetStreamClient } = require('../llama.stream'); _resetStreamClient();
    await expect(drain(callLlamaStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
  });
});
