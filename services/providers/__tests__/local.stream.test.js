'use strict';

/**
 * local.stream.js — dedicated adapter regression coverage.
 *
 * Mirrors local.test.js's (non-streaming) conventions exactly, adapted for
 * the streaming shape: `create()` resolves to an async-iterable stream of
 * `{ choices: [{ delta: { content } }] }` chunks instead of a single
 * completion object — the same contract mistral.stream.js/llama.stream.js
 * already have dedicated tests for; this is the third and last
 * OpenAI-SDK-based adapter to gain direct coverage.
 */

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
  delete process.env.LOCAL_BASE_URL;
  delete process.env.LOCAL_API_KEY;
});

describe('successful streaming', () => {
  test('yields each delta in order (Ollama-shaped chunks)', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockStream(chunksOf('Hello', ' from', ' local!'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const chunks = await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'Hello' }, { delta: ' from' }, { delta: ' local!' }]);
    _resetStreamClient();
  });

  test('request is sent with stream: true', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const mockCreate = setupMockStream(chunksOf('hi'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(mockCreate.mock.calls[0][0].stream).toBe(true);
    _resetStreamClient();
  });

  test('accepts any non-empty model name (deployment-specific runtime)', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    for (const model of ['llama3.2', 'phi3', 'mistral', 'deepseek-r1:7b']) {
      jest.clearAllMocks();
      _resetStreamClient(); // fresh client per iteration —'s llama.stream.test.js note
      setupMockStream(chunksOf('ok'));
      const chunks = await drain(callLocalStream({ ...VALID_BODY, model }, VALID_META));
      expect(chunks).toEqual([{ delta: 'ok' }]);
    }
    _resetStreamClient();
  });

  test('uses LOCAL_API_KEY when set', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    process.env.LOCAL_API_KEY  = 'my-local-key';
    setupMockStream(chunksOf('hi'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(OpenAI.mock.calls[0][0].apiKey).toBe('my-local-key');
    _resetStreamClient();
  });

  test('uses placeholder key when LOCAL_API_KEY not set', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockStream(chunksOf('hi'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(OpenAI.mock.calls[0][0].apiKey).toBe('local');
    _resetStreamClient();
  });

  test('emits PROVIDER_STREAM_START and PROVIDER_STREAM_COMPLETE', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockStream(chunksOf('hi'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_START', expect.objectContaining({ provider: 'local' }));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'local' }));
    _resetStreamClient();
  });

  // Pins a real, current asymmetry (not a bug is fixing): local.js
  // (non-streaming) emits LOCAL_PROVIDER_ENDPOINT_CONFIGURED on first client
  // creation; local.stream.js does not. Documented here so a future change
  // to either file makes this asymmetry visible instead of silent.
  test('does NOT emit LOCAL_PROVIDER_ENDPOINT_CONFIGURED (unlike the non-streaming adapter)', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockStream(chunksOf('hi'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(emit).not.toHaveBeenCalledWith('INFO', 'LOCAL_PROVIDER_ENDPOINT_CONFIGURED', expect.anything());
    _resetStreamClient();
  });
});

describe('stream parsing — provider-specific chunk shape', () => {
  test('a chunk with no delta content is skipped', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockStream(chunksOf('start', '', 'end'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const chunks = await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'start' }, { delta: 'end' }]);
    _resetStreamClient();
  });

  test('a chunk shaped without choices[0].delta.content at all is skipped safely', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    async function* mixed() {
      yield { choices: [{ delta: {} }] };
      yield { choices: [{ delta: { content: 'ok' } }] };
      yield { choices: [] };
      yield TERMINAL_CHUNK; // fixture correction: a complete stream ends with finish_reason
    }
    setupMockStream(mixed());
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const chunks = await drain(callLocalStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'ok' }]);
    _resetStreamClient();
  });

  // INVERTED from "an empty stream completes with zero deltas, not an error" — that asserted
  // the defect: a stream that ends without the terminal finish_reason is truncated, not an empty success.
  test('an empty stream (zero chunks, no finish_reason) is an incomplete stream — error, not success', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    async function* empty() {}
    setupMockStream(empty());
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await expect(drain(callLocalStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    _resetStreamClient();
  });
});

describe('URL validation', () => {
  test('rejects file:// URL with PROVIDER_CONFIG_INVALID', async () => {
    process.env.LOCAL_BASE_URL = 'file:///etc/passwd';
    OpenAI.mockImplementation(() => ({}));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const err = await drain(callLocalStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_CONFIG_INVALID');
    _resetStreamClient();
  });

  test('throws PROVIDER_CONFIG_INVALID when LOCAL_BASE_URL not set', async () => {
    delete process.env.LOCAL_BASE_URL;
    OpenAI.mockImplementation(() => ({}));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const err = await drain(callLocalStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_CONFIG_INVALID');
    _resetStreamClient();
  });

  test('accepts http://127.0.0.1 endpoint', async () => {
    process.env.LOCAL_BASE_URL = 'http://127.0.0.1:11434/v1';
    setupMockStream(chunksOf('ok'));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await expect(drain(callLocalStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
    _resetStreamClient();
  });
});

describe('payload validation', () => {
  test('throws PROVIDER_MODEL_NOT_ALLOWED for null model', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const err = await drain(callLocalStream({ ...VALID_BODY, model: null }, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
    _resetStreamClient();
  });

  test('throws PROVIDER_INVALID_REQUEST for empty messages', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const err = await drain(callLocalStream({ ...VALID_BODY, messages: [] }, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
    _resetStreamClient();
  });
});

describe('provider error propagation', () => {
  test('ECONNREFUSED → PROVIDER_UNAVAILABLE (Ollama not running)', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const netErr = Object.assign(new Error('conn refused'), { code: 'ECONNREFUSED', name: 'APIConnectionError' });
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: jest.fn().mockRejectedValue(netErr) } } }));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const err = await drain(callLocalStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetStreamClient();
  });

  test('a mid-stream throw is classified the same as an upfront rejection', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    async function* throwsMidStream() {
      yield { choices: [{ delta: { content: 'partial' } }] };
      const err = new Error('500'); err.status = 500;
      throw err;
    }
    setupMockStream(throwsMidStream());
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    const err = await drain(callLocalStream(VALID_BODY, VALID_META)).catch(e => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
    _resetStreamClient();
  });

  test('emits no PROVIDER_STREAM_COMPLETE when the stream errors', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    const createErr = jest.fn().mockRejectedValue(Object.assign(new Error('500'), { status: 500 }));
    OpenAI.mockImplementation(() => ({ chat: { completions: { create: createErr } } }));
    const { callLocalStream, _resetStreamClient } = require('../local.stream');
    _resetStreamClient();
    await drain(callLocalStream(VALID_BODY, VALID_META)).catch(() => {});
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
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
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    setupMockStream(truncated());
    const { callLocalStream, _resetStreamClient } = require('../local.stream'); _resetStreamClient();
    const seen = [];
    const err = await (async () => { for await (const ch of callLocalStream(VALID_BODY, VALID_META)) seen.push(ch); })().catch((e) => e);
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(err).toBeInstanceOf(Error);
    expect(err).toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_INCOMPLETE', expect.objectContaining({ provider: 'local', emittedOutput: true }));
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
  });

  test.each(['stop', 'length', 'content_filter', 'tool_calls'])('finish_reason %s is a terminal signal — stream completes', async (reason) => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    async function* ended() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: reason }] };
    }
    setupMockStream(ended());
    const { callLocalStream, _resetStreamClient } = require('../local.stream'); _resetStreamClient();
    await expect(drain(callLocalStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'local' }));
  });

  test('finish_reason on the same chunk as the last content (some servers do this) completes', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    async function* sameChunk() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: 'stop' }] }; }
    setupMockStream(sameChunk());
    const { callLocalStream, _resetStreamClient } = require('../local.stream'); _resetStreamClient();
    await expect(drain(callLocalStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('a trailing usage-only chunk (choices: []) after the terminal chunk still completes', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    async function* withUsage() {
      yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: null }] };
      yield { choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] };
      yield { choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } };
    }
    setupMockStream(withUsage());
    const { callLocalStream, _resetStreamClient } = require('../local.stream'); _resetStreamClient();
    await expect(drain(callLocalStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('an empty-string finish_reason is NOT terminal (fail closed)', async () => {
    process.env.LOCAL_BASE_URL = 'http://localhost:11434/v1';
    async function* emptyReason() { yield { choices: [{ index: 0, delta: { content: 'ok' }, finish_reason: '' }] }; }
    setupMockStream(emptyReason());
    const { callLocalStream, _resetStreamClient } = require('../local.stream'); _resetStreamClient();
    await expect(drain(callLocalStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
  });
});
