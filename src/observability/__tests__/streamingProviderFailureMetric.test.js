'use strict';

/**
 * phase 11 — provider failures on the STREAMING
 * path (/ai/chat with stream: true → src/streaming/streamEnforcer.js) were counted only in the unlabelled
 * qodiqa_streaming_enforcement_failures_total, so the shipped QodiqaProviderFailures alert (on
 * qodiqa_provider_failures_total) was blind to them. Harness mirrors src/streaming/__tests__/streamEnforcer.contract.test.js.
 *
 *   SPF-01 a streaming provider error with an UPPER_SNAKE code → provider_failures_total{provider,code} +1;
 *          the client still gets exactly one stream_cancelled frame and [DONE] (no behaviour change)
 *   SPF-02 an unbounded / missing code is reported as OTHER (no free-form label values)
 *   SPF-03 a stream timeout and a client disconnect are NOT provider failures (counter unchanged)
 *   SPF-04 a throwing metrics registry never changes the stream's outcome
 */

process.env.STREAM_MAX_DURATION_MS = '150';

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));
const mockAppend = jest.fn();
jest.mock('../../core/audit/audit-log', () => ({ append: (e) => e, appendMandatory: (...a) => mockAppend(...a), alreadyExecuted() { return false; } }));
const mockRegister = jest.fn();
jest.mock('../../core/transparency/registrar', () => ({ register: (...a) => mockRegister(...a) }));
let mockChunkGen = null;
jest.mock('../../../services/execution.stream', () => ({
  executeStreamingProviderCall: jest.fn(async function* (...args) { if (mockChunkGen) yield* mockChunkGen(...args); }),
}));

const { streamResponse } = require('../../streaming/streamEnforcer');
const metrics = require('../metrics');

const RID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const HASH = 'h'.repeat(64);
const OK = { transparencyId: 't', entryHash: 'e'.repeat(64), signature: 's', keyId: 'k', persisted: true };

function makeRes() {
  return {
    _headers: {}, _events: [], headersSent: false, _ended: false,
    setHeader(n, v) { this._headers[n] = v; }, flushHeaders() { this.headersSent = true; },
    write(d) { this._events.push(String(d)); }, end() { this._ended = true; },
    status() { return this; }, json() { this.headersSent = true; return this; },
  };
}
function makeReq() {
  const l = {};
  return { _l: l, on(e, f) { (l[e] = l[e] || []).push(f); }, off(e, f) { if (l[e]) l[e] = l[e].filter((x) => x !== f); }, fire(e) { (l[e] || []).slice().forEach((f) => f()); }, clientIp: '127.0.0.1' };
}
const artifact = (provider = 'openai') => ({
  payload: { requestHash: 'a'.repeat(64), provider, policyHash: 'b'.repeat(64) },
  signature: 'sig-test', expiry: Date.now() + 60_000, timestamp: Date.now(), publicKeyId: 'tenant1:key_v1',
});
const auth = () => ({ requestId: RID, tenantId: 'tenant1', policyHash: 'b'.repeat(64), semanticEvidence: { gates: ['anchors'], blocked: false }, publicKeyId: 'tenant1:key_v1' });
const val = (key) => metrics.providerFailuresTotal._values.get(key) || 0;
const total = () => [...metrics.providerFailuresTotal._values.values()].reduce((a, b) => a + b, 0);
const events = (res) => res._events.map((e) => (e.match(/^event: (.*)$/m) || [])[1]).filter(Boolean);

beforeEach(() => {
  mockChunkGen = null;
  mockAppend.mockReset(); mockAppend.mockImplementation(async (f) => ({ hash: HASH, artifactId: f.artifactId }));
  mockRegister.mockReset(); mockRegister.mockImplementation(async () => OK);
});

describe('streaming provider failures reach qodiqa_provider_failures_total', () => {
  test('SPF-01 a streaming provider error increments {provider, code}; the client contract is unchanged', async () => {
    const key = 'code="PROVIDER_UPSTREAM_502",provider="openai"';
    const before = val(key);
    mockChunkGen = async function* () { yield { delta: 'Hello there, a harmless answer.' }; throw Object.assign(new Error('upstream 502'), { code: 'PROVIDER_UPSTREAM_502' }); };
    const res = makeRes();
    await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-spf1');
    expect(val(key)).toBe(before + 1);
    expect(events(res).filter((e) => e === 'stream_cancelled')).toHaveLength(1);
    expect(res._events[res._events.length - 1]).toMatch(/data: \[DONE\]/);
  });

  test('SPF-02 an unbounded or missing error code is reported as OTHER; an unbounded provider as other', async () => {
    const key = 'code="OTHER",provider="openai"';
    const before = val(key);
    mockChunkGen = async function* () { throw Object.assign(new Error('x'), { code: 'weird <html> code' }); }; // eslint-disable-line require-yield
    await streamResponse(makeRes(), makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-spf2a');
    mockChunkGen = async function* () { throw new Error('boom'); }; // eslint-disable-line require-yield
    await streamResponse(makeRes(), makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-spf2b');
    expect(val(key)).toBe(before + 2);
    const keyP = 'code="X_DOWN",provider="other"';
    const beforeP = val(keyP);
    mockChunkGen = async function* () { throw Object.assign(new Error('x'), { code: 'X_DOWN' }); }; // eslint-disable-line require-yield
    await streamResponse(makeRes(), makeReq(), artifact('not a provider/token'), auth(), { prompt: 'hello' }, 'req-spf2c');
    expect(val(keyP)).toBe(beforeP + 1);
  });

  test('SPF-03 a stream timeout and a client disconnect are not provider failures', async () => {
    const before = total();
    mockChunkGen = async function* (_p, _b, _c, _m, signal) {
      yield { delta: 'Hello there, a harmless answer.' };
      await new Promise((r) => (signal.aborted ? r() : signal.addEventListener('abort', r, { once: true })));
    };
    await streamResponse(makeRes(), makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-spf3a');
    const req = makeReq();
    mockChunkGen = async function* () { yield { delta: 'Hello there, a harmless answer.' }; req.fire('close'); yield { delta: 'more' }; };
    await streamResponse(makeRes(), req, artifact(), auth(), { prompt: 'hello' }, 'req-spf3b');
    expect(total()).toBe(before);
  });

  test('SPF-04 a throwing metrics registry never changes the stream outcome', async () => {
    const spy = jest.spyOn(metrics.providerFailuresTotal, 'inc').mockImplementation(() => { throw new Error('registry down'); });
    try {
      mockChunkGen = async function* () { throw Object.assign(new Error('upstream 502'), { code: 'PROVIDER_UPSTREAM_502' }); }; // eslint-disable-line require-yield
      const res = makeRes();
      await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-spf4'); // must not reject
      expect(events(res).filter((e) => e === 'stream_cancelled')).toHaveLength(1);
      expect(res._ended).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });
});
