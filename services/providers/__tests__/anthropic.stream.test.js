'use strict';

/**
 * anthropic.stream.js — dedicated adapter regression coverage.
 *
 * Unlike the three OpenAI-SDK-based streaming adapters (openai/mistral/
 * llama/local), anthropic.stream.js hand-parses the raw Anthropic Messages
 * API SSE wire format itself (_parseSseLine/_sseChunks) — the one adapter
 * with genuinely bespoke parsing logic,'s own action list. Rather
 * than exporting those private functions for isolated testing, this suite
 * exercises them at the real provider boundary: a mocked `fetch` resolves to
 * a Response-shaped object whose `.body.getReader()` yields raw UTF-8 bytes
 * of an actual Anthropic-shaped SSE transcript (message_start ->
 * content_block_start -> ping -> content_block_delta(s) -> content_block_stop
 * -> message_delta -> message_stop -> [DONE]) — proving the full read/decode/
 * line-buffer/parse pipeline end to end, not just a hand-picked subset of it.
 */

jest.mock('../../logger', () => ({ emit: jest.fn() }));

const { emit }                = require('../../logger');
const { callAnthropicStream } = require('../anthropic.stream');

const VALID_BODY = {
  model:    'claude-3-5-sonnet-20241022',
  messages: [{ role: 'user', content: 'Hello Anthropic' }],
};

const VALID_META = {
  requestId:   'req-001',
  requestHash: 'a'.repeat(64),
  policyHash:  'b'.repeat(64),
};

// ── SSE fixture builder ──────────────────────────────────────────────────────

function sseLine(event, data) {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

// A realistic, complete Anthropic Messages API streaming transcript for the
// text "Hello there" split across two content_block_delta events — the
// actual event/content-block shape Anthropic's real API sends, not a
// simplified stand-in.
function fullTranscript() {
  return (
    sseLine('message_start', {
      type: 'message_start',
      message: { id: 'msg_01', type: 'message', role: 'assistant', content: [], model: 'claude-3-5-sonnet-20241022', usage: { input_tokens: 10, output_tokens: 0 } },
    }) +
    sseLine('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }) +
    sseLine('ping', { type: 'ping' }) +
    sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'Hello' } }) +
    sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: ' there' } }) +
    sseLine('content_block_stop', { type: 'content_block_stop', index: 0 }) +
    sseLine('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 15 } }) +
    sseLine('message_stop', { type: 'message_stop' }) +
    'data: [DONE]\n\n'
  );
}

// Builds a fetch-Response-shaped object whose body reader yields raw bytes of
// `rawText`, optionally split into fixed-size pieces to simulate a network
// chunk boundary landing mid-line (or mid-JSON-object).
function makeSseResponse(rawText, { chunkSize = null, status = 200, ok = true } = {}) {
  const bytes = new TextEncoder().encode(rawText);
  const pieces = [];
  if (chunkSize) {
    for (let i = 0; i < bytes.length; i += chunkSize) pieces.push(bytes.slice(i, i + chunkSize));
  } else {
    pieces.push(bytes);
  }
  let idx = 0;
  return {
    ok,
    status,
    body: {
      getReader() {
        return {
          async read() {
            if (idx >= pieces.length) return { done: true, value: undefined };
            return { done: false, value: pieces[idx++] };
          },
          cancel: jest.fn(),
        };
      },
    },
  };
}

async function drain(gen) {
  const chunks = [];
  for await (const c of gen) chunks.push(c);
  return chunks;
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.ANTHROPIC_API_KEY = 'test-key';
});

afterEach(() => {
  delete process.env.ANTHROPIC_API_KEY;
  delete global.fetch;
});

describe('successful streaming — real SSE wire format', () => {
  test('yields only the text deltas, in order, ignoring every other event type', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(fullTranscript()));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'Hello' }, { delta: ' there' }]);
  });

  test('request is sent with stream: true, Accept: text/event-stream, and the x-api-key header', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(fullTranscript()));
    await drain(callAnthropicStream(VALID_BODY, VALID_META));
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('https://api.anthropic.com/v1/messages');
    expect(opts.headers['x-api-key']).toBe('test-key');
    expect(opts.headers.accept).toBe('text/event-stream');
    const body = JSON.parse(opts.body);
    expect(body.stream).toBe(true);
    expect(body.model).toBe('claude-3-5-sonnet-20241022');
  });

  test('system messages are extracted into the top-level system field, not left in messages[]', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(fullTranscript()));
    const bodyWithSystem = {
      ...VALID_BODY,
      messages: [
        { role: 'system', content: 'You are a helpful assistant.' },
        { role: 'user', content: 'Hello' },
      ],
    };
    await drain(callAnthropicStream(bodyWithSystem, VALID_META));
    const sentBody = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(sentBody.system).toBe('You are a helpful assistant.');
    expect(sentBody.messages.every((m) => m.role !== 'system')).toBe(true);
  });

  test('a single line split across two network reads is still parsed correctly (buffer carry-over)', async () => {
    // chunkSize deliberately small enough to guarantee at least one SSE
    // line is split mid-line across reads — proving _sseChunks's
    // buffer += decode(); lines = buffer.split('\n'); buffer = lines.pop()
    // carry-over logic, not just the happy path of one read = one message.
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(fullTranscript(), { chunkSize: 7 }));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'Hello' }, { delta: ' there' }]);
  });

  test('emits PROVIDER_STREAM_START and PROVIDER_STREAM_COMPLETE', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(fullTranscript()));
    await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_START', expect.objectContaining({ provider: 'anthropic' }));
    expect(emit).toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.objectContaining({ provider: 'anthropic' }));
  });
});

describe('stream parsing — non-delta events produce no output', () => {
  test('an SSE transcript with only structural events (no content_block_delta) yields zero chunks', async () => {
    const noDeltas =
      sseLine('message_start', { type: 'message_start' }) +
      sseLine('content_block_start', { type: 'content_block_start', index: 0 }) +
      sseLine('content_block_stop', { type: 'content_block_stop', index: 0 }) +
      sseLine('message_stop', { type: 'message_stop' }) +
      'data: [DONE]\n\n';
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(noDeltas));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([]);
  });

  test('a text_delta with an empty string is not yielded as a phantom empty chunk', async () => {
    const emptyDelta = sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: '' } }) + sseLine('message_stop', { type: 'message_stop' });
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(emptyDelta));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([]);
  });

  test('a non-text delta type (e.g. input_json_delta, tool-use content) is ignored, not mis-parsed as text', async () => {
    const toolUseDelta = sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"a":1}' } }) +
      sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } }) +
      sseLine('message_stop', { type: 'message_stop' });
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(toolUseDelta));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'ok' }]);
  });

  test('a malformed (non-JSON) data line is skipped rather than crashing the stream', async () => {
    const malformed = 'event: content_block_delta\ndata: {not valid json\n\n' +
      sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } }) +
      sseLine('message_stop', { type: 'message_stop' });
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(malformed));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks).toEqual([{ delta: 'ok' }]);
  });

  test('lines that do not start with "data: " (e.g. bare event: lines) are ignored', async () => {
    // fullTranscript() already includes event: lines ahead of every data:
    // line — this test isolates that no event: line is ever misread as data.
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(fullTranscript()));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks.every((c) => typeof c.delta === 'string' && c.delta.length > 0)).toBe(true);
  });
});

describe('stream completion', () => {
  // message_stop (not [DONE], which is not part of Anthropic's protocol) is the terminator.
  test('message_stop terminates the stream — nothing after it (if anything were sent) would be yielded', async () => {
    const withTrailingJunkAfterDone =
      fullTranscript() +
      sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'SHOULD NOT APPEAR' } });
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(withTrailingJunkAfterDone));
    const chunks = await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(chunks.map((c) => c.delta)).not.toContain('SHOULD NOT APPEAR');
  });

  // INVERTED from the pre-fix "ends without [DONE] still completes cleanly" and "empty body
  // completes with zero chunks" tests — those asserted the defect itself (a truncated stream recorded as success).
  test('a body that ends without message_stop is an INCOMPLETE stream — error, not success', async () => {
    const truncated = sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } });
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(truncated));
    const seen = [];
    const err = await (async () => { for await (const c of callAnthropicStream(VALID_BODY, VALID_META)) seen.push(c); })().catch((e) => e);
    expect(err).toMatchObject({ code: 'PROVIDER_UNAVAILABLE', providerMayHaveExecuted: true });
    expect(seen).toEqual([{ delta: 'ok' }]);
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_INCOMPLETE', expect.objectContaining({ provider: 'anthropic', requestId: 'req-001' }));
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
  });

  test('an empty response body (zero bytes) is an incomplete stream — error, not success', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(''));
    await expect(drain(callAnthropicStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
  });

  test('a stream "terminated" only by [DONE] (not Anthropic protocol) without message_stop is incomplete', async () => {
    const doneOnly = sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } }) + 'data: [DONE]\n\n';
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(doneOnly));
    await expect(drain(callAnthropicStream(VALID_BODY, VALID_META))).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
  });

  test('a final message_stop line with no trailing newline still completes the stream', async () => {
    const noTrailingNewline = sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'ok' } }) +
      'event: message_stop\ndata: {"type":"message_stop"}';
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(noTrailingNewline));
    await expect(drain(callAnthropicStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'ok' }]);
  });

  test('CRLF-delimited SSE (permitted by the SSE spec) parses and completes', async () => {
    const crlf = fullTranscript().replace(/\n/g, '\r\n');
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(crlf, { chunkSize: 5 }));
    await expect(drain(callAnthropicStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'Hello' }, { delta: ' there' }]);
  });

  test('the reader is cancelled on completion (resource cleanup)', async () => {
    const response = makeSseResponse(fullTranscript());
    const reader = response.body.getReader();
    response.body.getReader = () => reader; // return the SAME reader instance so we can inspect it
    global.fetch = jest.fn().mockResolvedValue(response);
    await drain(callAnthropicStream(VALID_BODY, VALID_META));
    expect(reader.cancel).toHaveBeenCalled();
  });
});

describe('authentication', () => {
  test('throws PROVIDER_AUTH_FAILED when API key missing, without ever calling fetch', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    global.fetch = jest.fn();
    const err = await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('payload validation', () => {
  test('throws PROVIDER_INVALID_REQUEST for system-only messages, without calling fetch', async () => {
    global.fetch = jest.fn();
    const err = await drain(callAnthropicStream({ ...VALID_BODY, messages: [{ role: 'system', content: 'x' }] }, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_INVALID_REQUEST');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('throws PROVIDER_MODEL_NOT_ALLOWED for an unlisted model', async () => {
    const err = await drain(callAnthropicStream({ ...VALID_BODY, model: 'gpt-4' }, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_MODEL_NOT_ALLOWED');
  });
});

describe('provider error propagation', () => {
  test('HTTP 401 → PROVIDER_AUTH_FAILED', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse('', { ok: false, status: 401 }));
    const err = await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_AUTH_FAILED');
  });

  test('HTTP 429 → PROVIDER_RATE_LIMITED', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse('', { ok: false, status: 429 }));
    const err = await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_RATE_LIMITED');
  });

  test('HTTP 500 → PROVIDER_UNAVAILABLE', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse('', { ok: false, status: 500 }));
    const err = await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('a rejected fetch() (network TypeError) → PROVIDER_UNAVAILABLE', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed'));
    const err = await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('a rejected fetch() with AbortError → PROVIDER_TIMEOUT', async () => {
    const abortErr = Object.assign(new Error('aborted'), { name: 'AbortError' });
    global.fetch = jest.fn().mockRejectedValue(abortErr);
    const err = await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch((e) => e);
    expect(err.code).toBe('PROVIDER_TIMEOUT');
  });

  test('a reader error mid-stream propagates as PROVIDER_UNAVAILABLE, and chunks already yielded are not lost', async () => {
    const seen = [];
    const response = makeSseResponse('');
    let readCount = 0;
    response.body.getReader = () => ({
      async read() {
        readCount++;
        if (readCount === 1) {
          return { done: false, value: new TextEncoder().encode(sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'partial' } })) };
        }
        throw new TypeError('stream read failed');
      },
      cancel: jest.fn(),
    });
    global.fetch = jest.fn().mockResolvedValue(response);
    const gen = callAnthropicStream(VALID_BODY, VALID_META);
    await expect((async () => {
      for await (const c of gen) seen.push(c);
    })()).rejects.toMatchObject({ code: 'PROVIDER_UNAVAILABLE' });
    expect(seen).toEqual([{ delta: 'partial' }]);
  });

  test('emits no PROVIDER_STREAM_COMPLETE when the request itself fails', async () => {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse('', { ok: false, status: 500 }));
    await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch(() => {});
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
  });
});

// ──: in-band SSE `error` events ────────────
// RECORDED-CONTRACT FIXTURES, not live captures: the frames below follow Anthropic's documented Messages
// streaming protocol (docs.anthropic.com, "Streaming Messages" → "Error events": an `event: error` frame whose
// data is {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}, which "may occasionally
// be sent" after a 200 when the API is overloaded). No real Anthropic call was made — no credential exists.
describe('in-stream error events fail the stream (never a truncated success)', () => {
  function errorFrame(type, message = 'x') {
    return sseLine('error', { type: 'error', error: { type, message } });
  }
  function partialThen(frame) {
    return (
      sseLine('message_start', { type: 'message_start', message: { id: 'msg_01', type: 'message', role: 'assistant', content: [] } }) +
      sseLine('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }) +
      sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'partial' } }) +
      frame +
      // anything after the error must never be yielded, and a later message_stop must not "rescue" it
      sseLine('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'AFTER-ERROR' } }) +
      sseLine('message_stop', { type: 'message_stop' })
    );
  }
  async function run(raw) {
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(raw, { chunkSize: 11 }));
    const seen = [];
    const err = await (async () => { for await (const c of callAnthropicStream(VALID_BODY, VALID_META)) seen.push(c); })().catch((e) => e);
    return { seen, err };
  }

  test.each([
    ['overloaded_error',      'PROVIDER_UNAVAILABLE'],
    ['api_error',             'PROVIDER_UNAVAILABLE'],
    ['rate_limit_error',      'PROVIDER_RATE_LIMITED'],
    ['authentication_error',  'PROVIDER_AUTH_FAILED'],
    ['permission_error',      'PROVIDER_AUTH_FAILED'],
    ['invalid_request_error', 'PROVIDER_INVALID_REQUEST'],
    ['not_found_error',       'PROVIDER_INVALID_REQUEST'],
    ['request_too_large',     'PROVIDER_INVALID_REQUEST'],
    ['some_future_error',     'PROVIDER_UNAVAILABLE'],
  ])('mid-stream %s → throws %s, flagged providerMayHaveExecuted; output before it is kept, after it never yielded', async (type, code) => {
    const { seen, err } = await run(partialThen(errorFrame(type)));
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe(code);
    expect(err.providerMayHaveExecuted).toBe(true);
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(emit).toHaveBeenCalledWith('WARN', 'PROVIDER_STREAM_ERROR_EVENT', expect.objectContaining({ provider: 'anthropic', errorType: type, code }));
    expect(emit).not.toHaveBeenCalledWith('INFO', 'PROVIDER_STREAM_COMPLETE', expect.anything());
  });

  test('an error event before any delta also fails the stream (zero chunks, not an empty success)', async () => {
    const raw = sseLine('message_start', { type: 'message_start', message: { id: 'm' } }) + errorFrame('overloaded_error');
    const { seen, err } = await run(raw);
    expect(seen).toEqual([]);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('an `event: error` frame with unparseable data is still an error (fail closed)', async () => {
    const { seen, err } = await run(partialThen('event: error\ndata: {not json\n\n'));
    expect(seen).toEqual([{ delta: 'partial' }]);
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('a data-only error frame (no event: line, type:"error" in the payload) is detected too', async () => {
    const { err } = await run(partialThen(`data: ${JSON.stringify({ type: 'error', error: { type: 'overloaded_error' } })}\n\n`));
    expect(err.code).toBe('PROVIDER_UNAVAILABLE');
  });

  test('ping events between deltas are ignored and do not affect completion', async () => {
    const raw = sseLine('ping', { type: 'ping' }) + fullTranscript() ;
    global.fetch = jest.fn().mockResolvedValue(makeSseResponse(raw));
    await expect(drain(callAnthropicStream(VALID_BODY, VALID_META))).resolves.toEqual([{ delta: 'Hello' }, { delta: ' there' }]);
  });

  test('the reader is cancelled (resource cleanup) when an error event fails the stream', async () => {
    const response = makeSseResponse(partialThen(errorFrame('overloaded_error')));
    const reader = response.body.getReader();
    response.body.getReader = () => reader;
    global.fetch = jest.fn().mockResolvedValue(response);
    await drain(callAnthropicStream(VALID_BODY, VALID_META)).catch(() => {});
    expect(reader.cancel).toHaveBeenCalled();
  });
});
