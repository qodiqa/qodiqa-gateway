'use strict';

/**
 * SEM-F — decision-path network invariant (D3) regression suite: streaming.
 * for
 * the request/non-streaming-response counterpart and the full two-layer
 * split rationale (Jest wiring-coverage vs. CI real-model check) — not
 * repeated here.
 *
 * Drives the real streamResponse() (src/streaming/streamEnforcer.js) with a
 * benign, multi-chunk stream long enough to trigger BOTH the periodic
 * embedding-gate check inside outputSemanticWindow.js's evaluate()
 * (QODIQA_STREAM_SEMANTIC_EMBEDDING_INTERVAL_CHARS, default 400 chars) and
 * the mandatory evaluateFinal() recheck at stream end, with
 * test/helpers/networkInvariant.js installed throughout, and asserts zero
 * outbound http/https/fetch calls.
 *
 * Mocking setup mirrors outputSemantic.stream.regression.test.js exactly
 * (same file, same reason it's a separate file from the request/response
 * suite: execution.stream/audit-log need mocking here, which would leak
 * into and change the request/response suite's own semantics if shared).
 */

const { installNetworkInvariant, NetworkInvariantViolation, LOCALHOST_ALLOWLIST } = require('../../../test/helpers/networkInvariant');

function nonLocalhostCalls(state) {
  return state.calls.filter((c) => !LOCALHOST_ALLOWLIST.has(c.host));
}

let mockAuditWrites = [];

jest.mock('../../core/audit/audit-log', () => {
  function _append(entry) {
    mockAuditWrites.push({ ...entry });
    return entry;
  }
  return {
    append: _append,
    appendMandatory: async (entry) => _append(entry),
    alreadyExecuted() { return false; },
  };
});

let mockChunkGen = null;

jest.mock('../../../services/execution.stream', () => ({
  executeStreamingProviderCall: jest.fn(async function* (provider, body, verifiedCtx, traceMeta, signal) {
    if (mockChunkGen) yield* mockChunkGen(provider, body, verifiedCtx, traceMeta, signal);
  }),
}));

const { streamResponse } = require('../streamEnforcer');

beforeEach(() => {
  mockAuditWrites = [];
  mockChunkGen = null;
});

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
    requestId:  'bbbbbbbb-cccc-4ddd-eeee-ffffffffffff',
    tenantId:   'tenant1',
    policyHash: 'b'.repeat(64),
    ...overrides,
  };
}

function makeReqBody(overrides = {}) {
  return { prompt: 'hello', model: 'gpt-4o-mini', ...overrides };
}

function makeRes() {
  return {
    _headers: {}, _events: [], _ended: false, headersSent: false,
    setHeader(name, value) { this._headers[name] = value; },
    flushHeaders()         { this.headersSent = true; },
    write(data)            { this._events.push(data); },
    end()                  { this._ended = true; },
    status(code)           { this._statusCode = code; return this; },
    json(body)             { this._json = body; return this; },
  };
}

function makeReq() {
  const listeners = {};
  return {
    on(event, fn)  { (listeners[event] = listeners[event] || []).push(fn); },
    off(event, fn) {
      if (listeners[event]) listeners[event] = listeners[event].filter(f => f !== fn);
    },
    emit(event, ...args) { (listeners[event] || []).forEach(fn => fn(...args)); },
    clientIp: '127.0.0.1',
  };
}

describe('SEM-F — decision-path network invariant (D3): streaming', () => {
  let interceptor;

  beforeEach(() => { interceptor = installNetworkInvariant(); });
  afterEach(() => { interceptor.restore(); });

  test('negative control: the interceptor actually intercepts a non-localhost call', () => {
    // Synchronous throw (matches production `await` callers) — see the
    // request/response suite's identical negative control for why this is
    // not a `.rejects` assertion.
    expect(() => fetch('https://example.com/should-be-blocked')).toThrow(NetworkInvariantViolation);
    expect(interceptor.state.callCount).toBeGreaterThan(0);
  });

  test('a long benign stream (triggers both the periodic embedding check and evaluateFinal) makes no non-localhost calls', async () => {
    // >400 chars total so the periodic embedding-gate check inside
    // evaluate() fires at least once mid-stream, not just evaluateFinal()
    // at the end.
    const sentence = 'The quick brown fox jumps over the lazy dog near the riverbank. ';
    const chunks = Array.from({ length: 10 }, () => sentence); // ~660 chars total
    mockChunkGen = async function* () {
      for (const c of chunks) yield { delta: c };
    };

    const res = makeRes();
    await streamResponse(res, makeReq(), makeArtifact(), makeAuthResult(), makeReqBody(), null);

    expect(res._ended).toBe(true);
    expect(mockAuditWrites.find((w) => w.artifactId === 'bbbbbbbb-cccc-4ddd-eeee-ffffffffffff')?.decision).toBe('ALLOW');
    expect(nonLocalhostCalls(interceptor.state)).toEqual([]);
  });
});
