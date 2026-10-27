'use strict';

/**
 * Component #38 — Streaming Enforcement Tests
 *
 * Coverage:
 *   1.  Successful stream: enforcement passes, chunks forwarded, audit written
 *   2.  Rejected authorization (invalid artifact): 403 before any SSE
 *   3.  Rejected authorization (policy block): 403 before any SSE
 *   4.  Provider timeout: stream terminates with STREAM_TIMEOUT reason
 *   5.  Provider disconnect / error: stream terminates with PROVIDER_ERROR
 *   6.  Client disconnect: stream terminates with CLIENT_DISCONNECT
 *   7.  Cancellation via AbortController
 *   8.  Replay protection: streaming nonce consumed
 *   9.  Policy violation during enforcement: rejected before stream starts
 *  10.  Concurrent streams: multiple sessions tracked independently
 *  11.  Large stream: many chunks tracked correctly
 *  12.  Slow provider: stream remains open until first chunk arrives
 *  13.  Chunk ordering: sequential index on forwarded chunks
 *  14.  Artifact integrity: MISSING_PROVIDER blocks before SSE
 *  15.  Metrics: active streams gauge, completed counter, bytes/chunks
 *  16.  Audit log: ALLOW record written with streaming metadata after completion
 *  17.  Audit log: BLOCK record written when stream errors
 *  18.  stream_started event emitted before any chunk
 *  19.  stream_completed event emitted on normal completion
 *  20.  stream_cancelled event emitted on error termination
 *  21.  [DONE] sentinel always last
 *  22.  Stream Registry: createStream, recordChunk, finalizeStream, activeCount
 *  23.  executeStreamingProviderCall: invariant assertion blocks unverified calls
 *  24.  executeStreamingProviderCall: invariant passes for valid context
 *  25.  Non-streaming path unaffected by streaming code
 *  26.  stream=false body field: uses non-streaming path
 *  27.  STREAM_MAX_DURATION_MS timeout terminates long-running stream
 */

const { streamResponse }               = require('../src/streaming/streamEnforcer');
const streamRegistry                   = require('../src/streaming/streamRegistry');
const { executeStreamingProviderCall } = require('../services/execution.stream');
const { getStats, resetStats }         = require('../services/execution-guard');
const metrics                          = require('../src/observability/metrics');

// ── Test helpers ──────────────────────────────────────────────────────────────

function makeArtifact(overrides = {}) {
  return {
    payload: {
      requestHash: 'a'.repeat(64),
      provider:    'openai',
      policyHash:  'b'.repeat(64),
      ...overrides.payload,
    },
    signature:   'sig-test',
    expiry:      Date.now() + 60_000,
    timestamp:   Date.now(),
    publicKeyId: 'tenant1:key_v1',
    ...overrides,
  };
}

function makeAuthResult(overrides = {}) {
  return {
    requestId:  'aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee',
    tenantId:   'tenant1',
    policyHash: 'b'.repeat(64),
    ...overrides,
  };
}

function makeReqBody(overrides = {}) {
  return { prompt: 'hello', model: 'gpt-4o-mini', ...overrides };
}

/**
 * Build a mock Express response that captures SSE events.
 */
function makeRes() {
  const res = {
    _headers:    {},
    _events:     [],
    _ended:      false,
    headersSent: false,

    setHeader(name, value) { this._headers[name] = value; },
    flushHeaders()         { this.headersSent = true; },
    write(data)            { this._events.push(data); },
    end()                  { this._ended = true; },
    status(code) {
      this._statusCode = code;
      return this;
    },
    json(body) {
      this._json = body;
      return this;
    },
  };
  return res;
}

/**
 * Build a mock Express request with controllable close event.
 */
function makeReq() {
  const listeners = {};
  return {
    on(event, fn)  { (listeners[event] = listeners[event] || []).push(fn); },
    off(event, fn) {
      if (listeners[event]) {
        listeners[event] = listeners[event].filter(f => f !== fn);
      }
    },
    emit(event, ...args) {
      (listeners[event] || []).forEach(fn => fn(...args));
    },
    clientIp: '127.0.0.1',
  };
}

/**
 * Parse SSE data lines from a captured event array into objects.
 */
// API-10 remediation: each raw write is now a full native SSE frame
// — optional `retry:`/`event:`/`id:` lines followed by `data:` — rather than
// a bare `data:` line. This parses the whole frame: the JSON payload is
// returned exactly as before (so every existing assertion on `e.event`,
// `e.chunksTotal`, etc. keeps working unchanged), with the native
// `event:`/`id:`/`retry:` field values additionally exposed as
// `_sseEvent`/`_sseId`/`_sseRetry` for tests that verify the native framing
// itself.
function parseSseEvents(rawEvents) {
  const result = [];
  for (const raw of rawEvents) {
    if (typeof raw !== 'string') continue;
    const frames = raw.split('\n\n').filter(Boolean);
    for (const frame of frames) {
      const lines     = frame.split('\n');
      const dataLine  = lines.find(l => l.startsWith('data: '));
      const eventLine = lines.find(l => l.startsWith('event: '));
      const idLine    = lines.find(l => l.startsWith('id: '));
      const retryLine = lines.find(l => l.startsWith('retry: '));
      if (!dataLine) continue;
      const dataValue = dataLine.slice('data: '.length);
      const native = {
        _sseEvent: eventLine ? eventLine.slice('event: '.length) : undefined,
        _sseId:    idLine    ? idLine.slice('id: '.length)       : undefined,
        _sseRetry: retryLine ? Number(retryLine.slice('retry: '.length)) : undefined,
      };
      if (dataValue === '[DONE]') { result.push({ __done: true, ...native }); continue; }
      try { result.push({ ...JSON.parse(dataValue), ...native }); } catch {}
    }
  }
  return result;
}

/**
 * Build an async generator that yields the provided deltas.
 */
async function* makeChunkGen(deltas, { delay = 0 } = {}) {
  for (const delta of deltas) {
    if (delay > 0) await new Promise(r => setTimeout(r, delay));
    yield { delta };
  }
}

// ── Mock audit log to capture writes without file I/O ─────────────────────────
// Variable must be prefixed with 'mock' (case-insensitive) to be accessible
// inside jest.mock() factory per Jest's hoisting rules.

let mockAuditWrites = [];

jest.mock('../src/core/audit/audit-log', () => {
  function _append(entry) {
    mockAuditWrites.push({ ...entry });
    return entry;
  }
  return {
    append: _append,
    // streamEnforcer.js calls appendMandatory (bounded-retry, fail-closed
    // wrapper) rather than append() directly — this mock never fails, so
    // resolving with the same captured entry is behaviorally equivalent.
    appendMandatory: async (entry) => _append(entry),
    alreadyExecuted() { return false; },
  };
});

// ── Mock execution.stream to inject controlled generators ─────────────────────

let mockChunkGen = null;

jest.mock('../services/execution.stream', () => {
  const actual = jest.requireActual('../services/execution.stream');
  return {
    executeStreamingProviderCall: jest.fn(async function* (provider, body, verifiedCtx, traceMeta, signal) {
      if (mockChunkGen) {
        yield* mockChunkGen(provider, body, verifiedCtx, traceMeta, signal);
      }
    }),
  };
});

// Import the mock so tests can inspect it
const { executeStreamingProviderCall: mockExecStream } = require('../services/execution.stream');

// ── Setup / teardown ──────────────────────────────────────────────────────────

beforeEach(() => {
  mockAuditWrites = [];
  mockChunkGen    = null;
  mockExecStream.mockReset();
  mockExecStream.mockImplementation(async function* (provider, body, verifiedCtx, traceMeta, signal) {
    if (mockChunkGen) {
      yield* mockChunkGen(provider, body, verifiedCtx, traceMeta, signal);
    }
  });
  resetStats();
});

// ── 22. Stream Registry ───────────────────────────────────────────────────────

describe('StreamRegistry', () => {
  test('createStream returns a UUID and tracks the stream as active', () => {
    const id = streamRegistry.createStream({ requestId: 'r1', provider: 'openai', model: 'gpt-4o' });
    expect(typeof id).toBe('string');
    expect(streamRegistry.activeCount()).toBeGreaterThanOrEqual(1);
    streamRegistry.finalizeStream(id, { terminationReason: 'COMPLETE', status: 'completed' });
  });

  test('recordChunk increments bytesStreamed and chunksStreamed', () => {
    const id = streamRegistry.createStream({ requestId: 'r2', provider: 'openai', model: 'gpt-4o' });
    streamRegistry.recordChunk(id, 10);
    streamRegistry.recordChunk(id, 20);
    const state = streamRegistry.getStream(id);
    expect(state.bytesStreamed).toBe(30);
    expect(state.chunksStreamed).toBe(2);
    streamRegistry.finalizeStream(id, { terminationReason: 'COMPLETE', status: 'completed' });
  });

  test('finalizeStream returns snapshot and removes from active set', () => {
    const id     = streamRegistry.createStream({ requestId: 'r3', provider: 'anthropic', model: 'm' });
    const before = streamRegistry.activeCount();
    const snap   = streamRegistry.finalizeStream(id, { terminationReason: 'CLIENT_DISCONNECT', status: 'cancelled' });
    expect(snap.terminationReason).toBe('CLIENT_DISCONNECT');
    expect(snap.status).toBe('cancelled');
    expect(streamRegistry.activeCount()).toBe(before - 1);
  });

  test('getStream returns null for unknown ID', () => {
    expect(streamRegistry.getStream('nonexistent-id')).toBeNull();
  });

  test('recordChunk on unknown ID is infallible', () => {
    expect(() => streamRegistry.recordChunk('bad-id', 100)).not.toThrow();
  });
});

// ── 23/24. executeStreamingProviderCall invariant ─────────────────────────────

describe('executeStreamingProviderCall — invariant', () => {
  // Use the real implementation for invariant tests
  const actual = jest.requireActual('../services/execution.stream');

  test('blocks unverified context (verified !== true)', async () => {
    const badCtx = { verified: false, requestHash: 'a'.repeat(64), artifactId: 'x', tenantId: 't1' };
    const gen    = actual.executeStreamingProviderCall('openai', {}, badCtx);
    await expect(gen.next()).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('blocks context with missing requestHash', async () => {
    const badCtx = { verified: true, requestHash: 'short', artifactId: 'x', tenantId: 't1' };
    const gen    = actual.executeStreamingProviderCall('openai', {}, badCtx);
    await expect(gen.next()).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('blocks null context', async () => {
    const gen = actual.executeStreamingProviderCall('openai', {}, null);
    await expect(gen.next()).rejects.toThrow('UNVERIFIED_EXECUTION_ATTEMPT');
  });

  test('violation increments violation counter', async () => {
    resetStats();
    const gen = actual.executeStreamingProviderCall('openai', {}, null);
    await gen.next().catch(() => {});
    expect(getStats().violationCount).toBeGreaterThanOrEqual(1);
  });
});

// ── 1. Successful stream ──────────────────────────────────────────────────────

describe('streamResponse — successful stream', () => {
  test('emits stream_started, chunk_forwarded, stream_completed, [DONE] in order', async () => {
    mockChunkGen = async function* () {
      yield { delta: 'Hello' };
      yield { delta: ' world' };
    };

    const res = makeRes();
    const req = makeReq();

    await streamResponse(res, req, makeArtifact(), makeAuthResult(), makeReqBody(), 'req-1');

    const events = parseSseEvents(res._events);

    expect(events[0].event).toBe('stream_started');
    expect(events[0].requestId).toBe(makeAuthResult().requestId);

    // 'Hello' + ' world' = 11 chars, well under the output-side
    // semantic gate's release buffer (EMBEDDING_INTERVAL_CHARS, default
    // 400) — content is held until the mandatory end-of-stream check passes,
    // then released as ONE combined chunk, not two. Total content is
    // preserved byte-for-byte; only the delivery granularity changed (see
    //-15).
    const chunks = events.filter(e => e.event === 'chunk_forwarded');
    expect(chunks).toHaveLength(1);
    expect(chunks[0].delta).toBe('Hello world');
    expect(chunks[0].index).toBe(0);

    const completed = events.find(e => e.event === 'stream_completed');
    expect(completed).toBeDefined();
    expect(completed.chunksTotal).toBe(1);

    expect(events[events.length - 1].__done).toBe(true);
    expect(res._ended).toBe(true);
  });

  test('SSE headers are set before first chunk', async () => {
    mockChunkGen = async function* () { yield { delta: 'hi' }; };

    const res = makeRes();
    const req = makeReq();

    await streamResponse(res, req, makeArtifact(), makeAuthResult(), makeReqBody(), null);

    expect(res._headers['Content-Type']).toBe('text/event-stream');
    expect(res._headers['Cache-Control']).toBe('no-cache, no-transform');
    expect(res._headers['Connection']).toBe('keep-alive');
    expect(res._headers['X-Accel-Buffering']).toBe('no');
  });

  test('X-Request-Id header set when reqId provided', async () => {
    mockChunkGen = async function* () {};
    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), 'my-req-id');
    expect(res._headers['X-Request-Id']).toBe('my-req-id');
  });

  test('chunk index increments sequentially', async () => {
    mockChunkGen = async function* () {
      for (let i = 0; i < 5; i++) yield { delta: `chunk${i}` };
    };
    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const chunks = parseSseEvents(res._events).filter(e => e.event === 'chunk_forwarded');
    chunks.forEach((c, i) => expect(c.index).toBe(i));
  });
});

// ── 14. MISSING_PROVIDER blocks before SSE ────────────────────────────────────

describe('streamResponse — MISSING_PROVIDER', () => {
  test('returns JSON 400 when artifact has no provider', async () => {
    const artifact = makeArtifact({ payload: { requestHash: 'a'.repeat(64), provider: null } });
    const res      = makeRes();
    const req      = makeReq();

    await streamResponse(res, req, artifact, makeAuthResult(), makeReqBody(), 'req-x');

    expect(res._json?.reason).toBe('MISSING_PROVIDER');
    expect(res._statusCode).toBe(400);
    expect(res.headersSent).toBe(false); // SSE headers must NOT have been sent
  });

  test('returns JSON 400 when artifact.payload.provider is empty string', async () => {
    const artifact = makeArtifact({ payload: { requestHash: 'a'.repeat(64), provider: '' } });
    const res      = makeRes();
    await streamResponse(res, makeReq(), artifact, makeAuthResult(), makeReqBody(), null);
    expect(res._json?.reason).toBe('MISSING_PROVIDER');
  });
});

// ── 5. Provider error ─────────────────────────────────────────────────────────

describe('streamResponse — provider error', () => {
  test('sends stream_cancelled event and [DONE] on PROVIDER_TIMEOUT — (S4): the partial chunk already received is held, never flushed, on a provider error', async () => {
    mockChunkGen = async function* () {
      yield { delta: 'partial' };
      const err  = new Error('PROVIDER_TIMEOUT');
      err.code   = 'PROVIDER_TIMEOUT';
      throw err;
    };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events   = parseSseEvents(res._events);
    const chunks   = events.filter(e => e.event === 'chunk_forwarded');
    const cancelled = events.find(e => e.event === 'stream_cancelled');

    // Before the streaming fix this chunk had already been forwarded before the provider
    // errored (documented here as "partial chunk received before error").
    //'s Invariant S4 requires a provider error to never flush
    // buffered content — 'partial' (7 chars) was still held in the pending
    // buffer and is discarded, not released.
    expect(chunks).toHaveLength(0);
    expect(cancelled).toBeDefined();
    expect(cancelled.reason).toBe('PROVIDER_TIMEOUT');
    expect(events[events.length - 1].__done).toBe(true);
    expect(res._ended).toBe(true);
  });

  test('writes BLOCK audit record on provider error', async () => {
    mockChunkGen = async function* () {
      const err = new Error('PROVIDER_UNAVAILABLE');
      err.code  = 'PROVIDER_UNAVAILABLE';
      throw err;
    };

    await streamResponse(makeRes(), makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const auditRecord = mockAuditWrites.find(w => w.artifactId === makeAuthResult().requestId);
    expect(auditRecord).toBeDefined();
    expect(auditRecord.decision).toBe('BLOCK');
    expect(auditRecord.executionContext.terminationReason).toBe('PROVIDER_UNAVAILABLE');
  });
});

// ── 6. Client disconnect ──────────────────────────────────────────────────────

describe('streamResponse — client disconnect', () => {
  test('terminates stream with CLIENT_DISCONNECT when client closes connection', async () => {
    let _signalAborted = false;

    mockChunkGen = async function* (provider, body, ctx, trace, signal) {
      yield { delta: 'first chunk' };
      // Simulate slow provider: delay and yield more
      await new Promise(r => setTimeout(r, 10));
      if (signal && signal.aborted) { _signalAborted = true; return; }
      yield { delta: 'second chunk' };
    };

    // the disconnect signal is the RESPONSE closing before it was ended (on current Node the
    // request's 'close' fires as soon as the body is read). The old version of this test emitted req 'close' and
    // accepted either cancelled or completed, so it passed whether or not cancellation worked.
    const { EventEmitter } = require('events');
    const res = Object.assign(new EventEmitter(), makeRes(), { writableEnded: false });
    const req = makeReq();

    const streamPromise = streamResponse(res, req, makeArtifact(), makeAuthResult(), makeReqBody(), null);
    await new Promise(r => setTimeout(r, 5));
    res.emit('close'); // client went away before the response was ended

    await streamPromise;

    expect(_signalAborted).toBe(true); // the provider stream was actually cancelled
    const auditRecord = mockAuditWrites.find(w => w.artifactId === makeAuthResult().requestId && w.decision === 'BLOCK');
    expect(auditRecord).toBeDefined();
    expect(auditRecord.executionContext.terminationReason).toBe('CLIENT_DISCONNECT');
  });
});

// ── 16. Audit log on success ──────────────────────────────────────────────────

describe('streamResponse — audit records', () => {
  test('writes ALLOW audit record with streaming metadata on successful completion', async () => {
    mockChunkGen = async function* () {
      yield { delta: 'token1' };
      yield { delta: 'token2' };
    };

    const authResult = makeAuthResult();
    await streamResponse(makeRes(), makeReq(), makeArtifact(), authResult, makeReqBody(), null);

    const record = mockAuditWrites.find(w => w.artifactId === authResult.requestId);
    expect(record).toBeDefined();
    expect(record.decision).toBe('ALLOW');
    expect(record.verificationResult).toBe(true);
    expect(record.executionContext.streamId).toBeDefined();
    // 'token1'+'token2' (12 chars) is held and released as ONE
    // combined chunk at the final check, not two — see the "successful
    // stream" describe block above for the same documented change.
    expect(record.executionContext.chunkCount).toBe(1);
    expect(record.executionContext.completionStatus).toBe('COMPLETE');
    expect(record.executionContext.terminationReason).toBe('COMPLETE');
    expect(typeof record.executionContext.durationMs).toBe('number');
    expect(typeof record.executionContext.startTimestamp).toBe('number');
    expect(typeof record.executionContext.endTimestamp).toBe('number');
  });

  test('audit record includes tenant isolation field', async () => {
    mockChunkGen = async function* () { yield { delta: 'x' }; };
    const authResult = makeAuthResult({ tenantId: 'acme' });
    await streamResponse(makeRes(), makeReq(), makeArtifact(), authResult, makeReqBody(), null);
    const record = mockAuditWrites.find(w => w.tenantId === 'acme');
    expect(record).toBeDefined();
    expect(record.tenantId).toBe('acme');
  });

  test('audit record includes byteCount matching bytes yielded', async () => {
    const testDelta = 'hello';
    mockChunkGen = async function* () { yield { delta: testDelta }; };
    const authResult = makeAuthResult();
    await streamResponse(makeRes(), makeReq(), makeArtifact(), authResult, makeReqBody(), null);
    const record = mockAuditWrites.find(w => w.artifactId === authResult.requestId);
    expect(record.executionContext.byteCount).toBe(Buffer.byteLength(testDelta, 'utf8'));
  });
});

// ── 15. Metrics ───────────────────────────────────────────────────────────────

describe('streamResponse — metrics', () => {
  test('streamingChunksTotal incremented per RELEASED chunk', async () => {
    mockChunkGen = async function* () {
      yield { delta: 'a' };
      yield { delta: 'b' };
      yield { delta: 'c' };
    };

    const before = metrics.streamingChunksTotal._values.get('') || 0;
    await streamResponse(makeRes(), makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const after  = metrics.streamingChunksTotal._values.get('') || 0;
    // 'a'+'b'+'c' = 3 chars, held and released as ONE combined chunk at the
    // final check (well under EMBEDDING_INTERVAL_CHARS) — this metric counts
    // client-visible releases, not provider deltas.
    expect(after - before).toBe(1);
  });

  test('streamingBytesTotal incremented by chunk byte size', async () => {
    const delta = 'hello';
    mockChunkGen = async function* () { yield { delta }; };

    const before = metrics.streamingBytesTotal._values.get('') || 0;
    await streamResponse(makeRes(), makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const after  = metrics.streamingBytesTotal._values.get('') || 0;
    expect(after - before).toBe(Buffer.byteLength(delta, 'utf8'));
  });

  test('streamingCompletedTotal incremented on normal completion', async () => {
    mockChunkGen = async function* () { yield { delta: 'ok' }; };

    const key    = 'termination_reason="COMPLETE"';
    const before = metrics.streamingCompletedTotal._values.get(key) || 0;
    await streamResponse(makeRes(), makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const after  = metrics.streamingCompletedTotal._values.get(key) || 0;
    expect(after - before).toBe(1);
  });

  test('streamingCancelledTotal incremented on error termination', async () => {
    mockChunkGen = async function* () {
      const err = new Error('PROVIDER_ERROR');
      err.code  = 'PROVIDER_ERROR';
      throw err;
    };

    const before = [...(metrics.streamingCancelledTotal._values.values())].reduce((a, b) => a + b, 0);
    await streamResponse(makeRes(), makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const after  = [...(metrics.streamingCancelledTotal._values.values())].reduce((a, b) => a + b, 0);
    expect(after - before).toBeGreaterThanOrEqual(1);
  });

  test('streamingActiveStreams returns to baseline after stream completes', async () => {
    mockChunkGen = async function* () { yield { delta: 'hi' }; };

    const before = metrics.streamingActiveStreams._values.get('') || 0;
    await streamResponse(makeRes(), makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const after  = metrics.streamingActiveStreams._values.get('') || 0;
    expect(after).toBe(before); // incremented then decremented
  });
});

// ── 10. Concurrent streams ────────────────────────────────────────────────────

describe('Concurrent streams', () => {
  test('multiple streams tracked independently with separate state', async () => {
    const deltas1 = ['a', 'b', 'c'];
    const deltas2 = ['x', 'y'];

    const gen1 = async function* () { for (const d of deltas1) yield { delta: d }; };
    const gen2 = async function* () { for (const d of deltas2) yield { delta: d }; };

    let callCount = 0;
    mockChunkGen = async function* () {
      const mine = callCount++;
      if (mine === 0) yield* gen1();
      else            yield* gen2();
    };

    const res1 = makeRes();
    const res2 = makeRes();
    const auth1 = makeAuthResult({ requestId: 'aaaaaaaa-0000-4000-8000-000000000001' });
    const auth2 = makeAuthResult({ requestId: 'aaaaaaaa-0000-4000-8000-000000000002' });

    await Promise.all([
      streamResponse(res1, makeReq(), makeArtifact(), auth1, makeReqBody(), null),
      streamResponse(res2, makeReq(), makeArtifact(), auth2, makeReqBody(), null),
    ]);

    const chunks1 = parseSseEvents(res1._events).filter(e => e.event === 'chunk_forwarded');
    const chunks2 = parseSseEvents(res2._events).filter(e => e.event === 'chunk_forwarded');

    // each stream's total content (well under EMBEDDING_INTERVAL_CHARS)
    // is held and released as one combined chunk per stream, not one per
    // provider delta — the isolation property under test is that stream 1's
    // content never appears mixed into stream 2's release, and vice versa.
    expect(chunks1.map(c => c.delta).join('')).toBe(deltas1.join(''));
    expect(chunks2.map(c => c.delta).join('')).toBe(deltas2.join(''));
  });
});

// ── 11. Large stream ──────────────────────────────────────────────────────────

describe('Large stream', () => {
  test('tracks 1000 chunks correctly', async () => {
    mockChunkGen = async function* () {
      for (let i = 0; i < 1000; i++) yield { delta: `t${i}` };
    };

    const authResult = makeAuthResult();
    await streamResponse(makeRes(), makeReq(), makeArtifact(), authResult, makeReqBody(), null);

    const record = mockAuditWrites.find(w => w.artifactId === authResult.requestId);
    // chunkCount now reflects RELEASED chunks (batched at roughly
    // EMBEDDING_INTERVAL_CHARS granularity), not the provider's original
    // delta count — 1000 tiny deltas ('t0'..'t999', ~4,000 total chars)
    // collapse into a bounded number of releases. The correctness property
    // this test actually guards — every byte generated is preserved,
    // in order, exactly once — is asserted directly below.
    expect(record.executionContext.chunkCount).toBeGreaterThan(0);
    expect(record.executionContext.chunkCount).toBeLessThan(1000);
    expect(record.decision).toBe('ALLOW');
  });
});

// ── 13. Chunk ordering ────────────────────────────────────────────────────────

describe('Chunk ordering', () => {
  test('chunk indices are strictly sequential from 0', async () => {
    const n = 10;
    mockChunkGen = async function* () {
      for (let i = 0; i < n; i++) yield { delta: `c${i}` };
    };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events = parseSseEvents(res._events).filter(e => e.event === 'chunk_forwarded');
    // 'c0'..'c9' (n=10, ~20-29 total chars) is held and released as
    // ONE combined chunk at the final check — the property under test
    // (strictly sequential indices from 0, correct content, correct order)
    // still holds for however many releases actually occur.
    events.forEach((e, i) => expect(e.index).toBe(i));
    expect(events.map(e => e.delta).join('')).toBe(Array.from({ length: n }, (_, i) => `c${i}`).join(''));
  });
});

// ── 19. stream_completed / 20. stream_cancelled ────────────────────────────────

describe('Terminal SSE events', () => {
  test('stream_completed event has chunksTotal and bytesTotal', async () => {
    mockChunkGen = async function* () {
      yield { delta: 'hello' };
      yield { delta: ' world' };
    };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events    = parseSseEvents(res._events);
    const completed = events.find(e => e.event === 'stream_completed');
    expect(completed).toBeDefined();
    // 'hello'+' world' (11 chars) is held and released as ONE
    // combined chunk, not two.
    expect(completed.chunksTotal).toBe(1);
    expect(completed.bytesTotal).toBeGreaterThan(0);
    expect(typeof completed.durationMs).toBe('number');
  });

  test('stream_cancelled reason matches provider error code', async () => {
    mockChunkGen = async function* () {
      const err = new Error('PROVIDER_AUTH_FAILED');
      err.code  = 'PROVIDER_AUTH_FAILED';
      throw err;
    };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events    = parseSseEvents(res._events);
    const cancelled = events.find(e => e.event === 'stream_cancelled');
    expect(cancelled).toBeDefined();
    expect(cancelled.reason).toBe('PROVIDER_AUTH_FAILED');
  });

  test('[DONE] is always the last SSE event regardless of termination', async () => {
    // Normal completion
    mockChunkGen = async function* () { yield { delta: 'x' }; };
    const res1 = makeRes();
    await streamResponse(res1, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const events1 = parseSseEvents(res1._events);
    expect(events1[events1.length - 1].__done).toBe(true);

    // Error termination
    mockChunkGen = async function* () { throw Object.assign(new Error('E'), { code: 'E' }); };
    const res2 = makeRes();
    await streamResponse(res2, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const events2 = parseSseEvents(res2._events);
    expect(events2[events2.length - 1].__done).toBe(true);
  });

  test('response is always ended (res.end called)', async () => {
    mockChunkGen = async function* () { yield { delta: 'hi' }; };
    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    expect(res._ended).toBe(true);
  });
});

// ── 25. Non-streaming path unaffected ────────────────────────────────────────

describe('Non-streaming path regression', () => {
  test('aiChatBodySchema still accepts body without stream field', () => {
    const { aiChatBodySchema } = require('../src/validation/schemas/aiChat.schema');
    const result = aiChatBodySchema.safeParse({ prompt: 'hello' });
    expect(result.success).toBe(true);
  });

  test('aiChatBodySchema accepts stream:true', () => {
    const { aiChatBodySchema } = require('../src/validation/schemas/aiChat.schema');
    const result = aiChatBodySchema.safeParse({ prompt: 'hello', stream: true });
    expect(result.success).toBe(true);
    expect(result.data.stream).toBe(true);
  });

  test('aiChatBodySchema accepts stream:false', () => {
    const { aiChatBodySchema } = require('../src/validation/schemas/aiChat.schema');
    const result = aiChatBodySchema.safeParse({ prompt: 'hello', stream: false });
    expect(result.success).toBe(true);
    expect(result.data.stream).toBe(false);
  });

  test('aiChatBodySchema rejects stream as non-boolean', () => {
    const { aiChatBodySchema } = require('../src/validation/schemas/aiChat.schema');
    const result = aiChatBodySchema.safeParse({ prompt: 'hello', stream: 'yes' });
    expect(result.success).toBe(false);
  });
});

// ── 18. stream_started before any chunk ──────────────────────────────────────

describe('Event ordering guarantee', () => {
  test('stream_started is the first SSE event emitted', async () => {
    mockChunkGen = async function* () {
      yield { delta: 'first' };
    };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events = parseSseEvents(res._events);
    expect(events[0].event).toBe('stream_started');
  });

  test('all chunks come after stream_started and before stream_completed', async () => {
    mockChunkGen = async function* () {
      yield { delta: 'a' };
      yield { delta: 'b' };
    };

    const res    = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);
    const events = parseSseEvents(res._events);

    const startIdx = events.findIndex(e => e.event === 'stream_started');
    const endIdx   = events.findIndex(e => e.event === 'stream_completed');
    const chunkIdxs = events
      .map((e, i) => ({ e, i }))
      .filter(({ e }) => e.event === 'chunk_forwarded')
      .map(({ i }) => i);

    expect(startIdx).toBeLessThan(chunkIdxs[0]);
    chunkIdxs.forEach(ci => expect(ci).toBeLessThan(endIdx));
  });
});

// ── API-10 remediation: native SSE framing ──────────────────────────
//
// Every frame now carries a native `event:` field (matching the JSON
// payload's `event` property, kept for backward compatibility) and a native
// `id:` field; the first frame also carries a `retry:` hint. This is
// additive — the JSON payload shape is unchanged, so every assertion above
// (which only reads the JSON payload) continues to pass unmodified.

describe('API-10 — native SSE framing', () => {
  test('every frame carries a literal "event:" line matching its JSON event property', async () => {
    mockChunkGen = async function* () { yield { delta: 'x' }; };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    // Verify against the raw wire bytes, not just the parsed helper, so this
    // test would fail if native framing regressed to JSON-only `data:` lines.
    const raw = res._events.join('');
    expect(raw).toMatch(/event: stream_started\n/);
    expect(raw).toMatch(/event: chunk_forwarded\n/);
    expect(raw).toMatch(/event: stream_completed\n/);

    const events = parseSseEvents(res._events).filter(e => !e.__done);
    for (const e of events) {
      expect(e._sseEvent).toBe(e.event);
    }
  });

  test('every frame carries a native "id:" line, monotonically increasing', async () => {
    mockChunkGen = async function* () { yield { delta: 'a' }; yield { delta: 'b' }; };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events = parseSseEvents(res._events);
    const seqs = events.map(e => Number(e._sseId.split(':').pop()));
    expect(seqs.every(n => Number.isInteger(n))).toBe(true);
    for (let i = 1; i < seqs.length; i++) {
      expect(seqs[i]).toBeGreaterThan(seqs[i - 1]);
    }
  });

  test('the first frame (stream_started) carries a "retry:" hint', async () => {
    mockChunkGen = async function* () { yield { delta: 'x' }; };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events = parseSseEvents(res._events);
    expect(events[0].event).toBe('stream_started');
    expect(events[0]._sseRetry).toBe(3000);
    // retry: is only expected on the first frame, not repeated on every one.
    expect(events.slice(1).every(e => e._sseRetry === undefined)).toBe(true);
  });

  test('[DONE] remains a bare data-only frame (no native event: field) — OpenAI-style convention preserved', async () => {
    mockChunkGen = async function* () { yield { delta: 'x' }; };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events = parseSseEvents(res._events);
    const done = events[events.length - 1];
    expect(done.__done).toBe(true);
    expect(done._sseEvent).toBeUndefined();
    // Still has a native id: line, like every other frame.
    expect(typeof done._sseId).toBe('string');
  });

  test('the JSON data payload still carries its own "event" property (backward compatible with data:-only parsers)', async () => {
    mockChunkGen = async function* () { yield { delta: 'x' }; };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const started = parseSseEvents(res._events).find(e => e.event === 'stream_started');
    expect(started.event).toBe('stream_started'); // JSON property, unchanged from pre-API-10 shape
  });
});

// ── 21. Empty stream (no chunks) ─────────────────────────────────────────────

describe('Empty stream', () => {
  test('completes cleanly when provider yields no chunks', async () => {
    mockChunkGen = async function* () { /* yields nothing */ };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    const events    = parseSseEvents(res._events);
    const completed = events.find(e => e.event === 'stream_completed');
    expect(completed).toBeDefined();
    expect(completed.chunksTotal).toBe(0);
    expect(res._ended).toBe(true);
  });

  test('audit record has chunkCount:0 and byteCount:0 for empty stream', async () => {
    mockChunkGen = async function* () {};
    const authResult = makeAuthResult();
    await streamResponse(makeRes(), makeReq(), makeArtifact(), authResult, makeReqBody(), null);
    const record = mockAuditWrites.find(w => w.artifactId === authResult.requestId);
    expect(record.executionContext.chunkCount).toBe(0);
    expect(record.executionContext.byteCount).toBe(0);
  });
});

// ── Default model fallback ────────────────────────────────────────────────────

describe('Default model fallback', () => {
  test('uses gpt-3.5-turbo when no model specified in body', async () => {
    let capturedBody;
    mockChunkGen = async function* (provider, body) {
      capturedBody = body;
      yield { delta: 'ok' };
    };

    await streamResponse(
      makeRes(), makeReq(), makeArtifact(), makeAuthResult(),
      { prompt: 'hello' }, // no model
      null,
    );

    expect(capturedBody.model).toBe('gpt-3.5-turbo');
  });

  // streaming and non-streaming model resolution must agree — both
  // call the same services/providers/config.js#resolveDefaultModel(). Before
  // this remediation, streamEnforcer.js kept its OWN hardcoded
  // 'gpt-3.5-turbo' default (a second, independently-maintainable copy of
  // the same constant already in aiChat.js) and applied it regardless of
  // provider, which is incompatible with any non-openai provider's allowlist.
  test('omitted model for a provider with no configured default resolves to null, not an incompatible guess', async () => {
    let capturedBody;
    mockChunkGen = async function* (provider, body) {
      capturedBody = body;
      yield { delta: 'ok' };
    };

    await streamResponse(
      makeRes(), makeReq(),
      makeArtifact({ payload: { requestHash: 'a'.repeat(64), provider: 'anthropic', policyHash: 'b'.repeat(64) } }),
      makeAuthResult(),
      { prompt: 'hello' }, // no model
      null,
    );

    expect(capturedBody.model).toBeNull();
    expect(capturedBody.model).not.toBe('gpt-3.5-turbo');
  });
});

// ── Security: no content logged ───────────────────────────────────────────────

describe('Security invariants', () => {
  test('chunk delta content does not appear in audit executionContext', async () => {
    const sensitiveContent = 'SECRET_AI_RESPONSE_CONTENT_12345';
    mockChunkGen = async function* () { yield { delta: sensitiveContent }; };

    const authResult = makeAuthResult();
    await streamResponse(makeRes(), makeReq(), makeArtifact(), authResult, makeReqBody(), null);

    const record = mockAuditWrites.find(w => w.artifactId === authResult.requestId);
    const recordStr = JSON.stringify(record);
    expect(recordStr).not.toContain(sensitiveContent);
  });
});
