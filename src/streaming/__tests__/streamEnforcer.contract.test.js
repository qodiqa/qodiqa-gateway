'use strict';

/**
 * TQ-05 — streamEnforcer.js contract tests.
 *
 * The 34-file mutation run left streamEnforcer.js at 35.22 %: the streaming path's EVIDENCE content (the closing
 * DECISION audit entry and its transparency leaf), its SSE wire format, and several fail-closed branches (audit/leaf
 * failure after delivery, stream timeout, client disconnect, provider error, missing provider, abandonment between
 * STREAM_OPENED and dispatch) were executed by other suites but never asserted. These tests pin that contract.
 * Same harness as streamLifecycle.test.js: the real streamResponse(), a mocked provider stream generator, mocked
 * audit log and transparency registrar. Deterministic: no sleeps decide an ordering — the timeout case waits on the
 * stream's own AbortSignal, the disconnect case fires the request's 'close' listener from inside the provider stream.
 *
 *   SC-01 SSE wire format: retry on the first frame only, `event:` per JSON frame, monotonically increasing
 *         `<streamId>:<n>` ids, a bare `data: [DONE]` last frame; the five SSE response headers
 *   SC-02 completed stream → DECISION ALLOW: verificationResult true, no BLOCK reason, completion COMPLETE, the
 *         chunk/byte counts and timing, publicKeyId / organizationId / semantic evidence carried through
 *   SC-03 the DECISION's transparency leaf: STREAM stage, ALLOW, verificationResult, policy rule + caller identity
 *   SC-04 provider error → BLOCK with the provider's code as reason, status ERROR, one stream_cancelled frame,
 *         verificationResult false on entry and leaf, WARN STREAM_PROVIDER_ERROR
 *   SC-05 stream timeout (STREAM_MAX_DURATION_MS) → BLOCK STREAM_TIMEOUT, status CANCELLED, nothing more released
 *   SC-06 client disconnect mid-stream → BLOCK CLIENT_DISCONNECT, CANCELLED, the held chunk never released
 *   SC-07 DECISION append fails after delivery → CRITICAL STREAM_AUDIT_FAILED, the leaf is still attempted (null audit
 *         hash); `already_executed` → INFO already_in_chain and NO second leaf
 *   SC-08 DECISION leaf fails → CRITICAL TRANSPARENCY_APPEND_FAILED and the failure metric; no throw
 *   SC-09 missing provider → 400 MISSING_PROVIDER before anything is opened, recorded or sent
 *   SC-10 pre-stream timeout fires while the lifecycle entries are written → STREAM_ABANDONED_BEFORE_DISPATCH, a BLOCK
 *         REQUEST_TIMEOUT DECISION with no executing provider, no header, provider never called
 *   SC-11 a stream with no X-Request-Id correlation id sets no such header
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

const { emit } = require('../../../services/logger');
const { streamResponse } = require('../streamEnforcer');
const { executeStreamingProviderCall } = require('../../../services/execution.stream');
const { EMPTY_OUTPUT_HASH } = require('../../core/audit/entryBuilder');
const metrics = require('../../observability/metrics');

const RID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const HASH = 'h'.repeat(64);
const SEM = { gates: ['anchors'], blocked: false };
const POLICY_DECISION = { policyId: 'POL-CONSENT', policyVersion: 3, policyRuleHash: 'r'.repeat(64) };

function makeRes() {
  return {
    _headers: {}, _events: [], headersSent: false, _status: null, _json: null, _ended: false,
    setHeader(n, v) { this._headers[n] = v; },
    flushHeaders()  { this.headersSent = true; },
    write(d)        { this._events.push(d); },
    end()           { this._ended = true; },
    status(c)       { this._status = c; return this; },
    json(b)         { this._json = b; this.headersSent = true; return this; },
  };
}
function makeReq() {
  const l = {};
  return { _l: l, on(e, f) { (l[e] = l[e] || []).push(f); }, off(e, f) { if (l[e]) l[e] = l[e].filter((x) => x !== f); }, fire(e) { (l[e] || []).slice().forEach((f) => f()); }, clientIp: '127.0.0.1' };
}
const artifact = (over = {}) => ({
  payload: { requestHash: 'a'.repeat(64), provider: 'openai', policyHash: 'b'.repeat(64), callerContext: { callerId: 'caller-1', callerName: 'ci' }, ...over },
  signature: 'sig-test', expiry: Date.now() + 60_000, timestamp: Date.now(), publicKeyId: 'tenant1:key_v1',
});
const auth = (over = {}) => ({
  requestId: RID, tenantId: 'tenant1', policyHash: 'b'.repeat(64), organizationId: 'org-1',
  semanticEvidence: SEM, publicKeyId: 'tenant1:key_v1', policyDecision: POLICY_DECISION, ...over,
});
// SSE frames → [{ raw, retry, event, id, data }]
function frames(res) {
  const out = [];
  for (const raw of res._events) {
    const f = { raw };
    for (const line of String(raw).split('\n')) {
      if (line.startsWith('retry: ')) f.retry = line.slice(7);
      else if (line.startsWith('event: ')) f.event = line.slice(7);
      else if (line.startsWith('id: ')) f.id = line.slice(4);
      else if (line.startsWith('data: ')) { const d = line.slice(6); try { f.data = JSON.parse(d); } catch { f.data = d; } }
    }
    out.push(f);
  }
  return out;
}
const decisionCall = () => mockAppend.mock.calls.map(([f]) => f).filter((f) => f.entryType === 'DECISION');
const decisionLeaves = () => mockRegister.mock.calls.map(([r]) => r).filter((r) => !r.payload.entryType);
const emitted = (sev, type) => emit.mock.calls.filter(([s, t]) => s === sev && t === type).map(([, , d]) => d);
const OK = { transparencyId: 't', entryHash: 'e'.repeat(64), signature: 's', keyId: 'k', persisted: true };
const BENIGN = ['Hello there, ', 'here is a short and harmless answer about the weather today. ', 'It is sunny and mild.'];

beforeEach(() => {
  mockChunkGen = null; executeStreamingProviderCall.mockClear(); emit.mockClear();
  mockAppend.mockReset();
  mockAppend.mockImplementation(async (f) => ({ hash: HASH, artifactId: f.artifactId }));
  mockRegister.mockReset();
  mockRegister.mockImplementation(async () => OK);
});

describe('streamEnforcer contract (TQ-05)', () => {
  test('SC-01 SSE wire format and response headers', async () => {
    mockChunkGen = async function* () { for (const d of BENIGN) yield { delta: d }; };
    const res = makeRes();
    await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello', model: 'gpt-4o-mini' }, 'req-sc1');
    expect(res._headers).toMatchObject({
      'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive',
      'X-Accel-Buffering': 'no', 'X-Request-Id': 'req-sc1',
    });
    const fs_ = frames(res);
    const streamId = fs_[0].data.streamId;
    expect(typeof streamId).toBe('string');
    // retry only on the first frame
    expect(fs_[0]).toMatchObject({ retry: '3000', event: 'stream_started', id: `${streamId}:0` });
    expect(fs_.slice(1).every((f) => f.retry === undefined)).toBe(true);
    expect(fs_[0].raw.startsWith('retry: 3000\nevent: stream_started\nid: ')).toBe(true);
    // ids strictly increase by one, every frame carries one
    expect(fs_.map((f) => f.id)).toEqual(fs_.map((_, i) => `${streamId}:${i}`));
    // every JSON frame names its event both natively and in the payload
    for (const f of fs_.slice(0, -1)) expect(f.event).toBe(f.data.event);
    expect(fs_.map((f) => f.event).filter(Boolean)).toContain('chunk_forwarded');
    expect(fs_[fs_.length - 2].event).toBe('stream_completed');
    // the last frame is a bare data: [DONE] with no event line
    const last = fs_[fs_.length - 1];
    expect(last.data).toBe('[DONE]');
    expect(last.event).toBeUndefined();
    expect(last.raw).toBe(`id: ${streamId}:${fs_.length - 1}\ndata: [DONE]\n\n`);
    expect(res._ended).toBe(true);
  });

  test('SC-02 completed stream → DECISION ALLOW with the full evidence context', async () => {
    mockChunkGen = async function* () { for (const d of BENIGN) yield { delta: d }; };
    const res = makeRes();
    const t0 = Date.now();
    await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello', model: 'gpt-4o-mini' }, 'req-sc2');
    const [dec] = decisionCall();
    const released = frames(res).filter((f) => f.event === 'chunk_forwarded').map((f) => f.data.delta).join('');
    expect(dec).toMatchObject({
      artifactId: RID, requestId: RID, decision: 'ALLOW', verificationResult: true, reason: null,
      stage: 'PROVIDER_EXECUTION', semantic: SEM, publicKeyId: 'tenant1:key_v1', organizationId: 'org-1',
      tokenUsage: null, model: 'gpt-4o-mini', provider: 'openai', executingProvider: 'openai',
      callerContext: { callerId: 'caller-1', callerName: 'ci' }, policyDecision: POLICY_DECISION,
    });
    expect(dec.responseId).toBe(frames(res)[0].data.streamId);
    const ec = dec.executionContext;
    expect(ec).toMatchObject({
      stage: 'PROVIDER_EXECUTION', completionStatus: 'COMPLETE', terminationReason: 'COMPLETE', semantic: SEM,
      publicKeyId: 'tenant1:key_v1', requestedProvider: 'openai', executingProvider: 'openai', failover: null,
      byteCount: Buffer.byteLength(released, 'utf8'),
    });
    expect(ec.chunkCount).toBe(frames(res).filter((f) => f.event === 'chunk_forwarded').length);
    expect(ec.endTimestamp).toBeGreaterThanOrEqual(ec.startTimestamp);
    expect(ec.startTimestamp).toBeGreaterThanOrEqual(t0);
    expect(ec.durationMs).toBe(ec.endTimestamp - ec.startTimestamp);
    const [rec] = emitted('INFO', 'STREAM_AUDIT_RECORDED');
    expect(rec).toMatchObject({ decision: 'ALLOW', auditEntryHash: HASH, policyHash: 'b'.repeat(64), terminationReason: 'COMPLETE' });
  });

  test('SC-03 the DECISION transparency leaf carries the stage, decision, rule and caller', async () => {
    mockChunkGen = async function* () { yield { delta: BENIGN[1] }; };
    await streamResponse(makeRes(), makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc3');
    const [leaf] = decisionLeaves();
    expect(leaf.artifactId).toBe(RID);
    expect(leaf.payload).toMatchObject({
      requestId: RID, decision: 'ALLOW', reason: 'COMPLETE', stage: 'STREAM', verificationResult: true,
      auditEntryHash: HASH, semantic: SEM, publicKeyId: 'tenant1:key_v1', tenantId: 'tenant1', provider: 'openai',
      policyRuleId: 'POL-CONSENT', policyRuleVersion: 3, policyRuleHash: 'r'.repeat(64), callerId: 'caller-1',
    });
  });

  test('SC-04 provider error → BLOCK with the provider code, one stream_cancelled frame, verificationResult false', async () => {
    mockChunkGen = async function* () { yield { delta: BENIGN[1] }; throw Object.assign(new Error('upstream 502'), { code: 'PROVIDER_UPSTREAM_502' }); };
    const res = makeRes();
    await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc4');
    const fs_ = frames(res);
    const cancelled = fs_.filter((f) => f.event === 'stream_cancelled');
    expect(cancelled).toHaveLength(1);
    expect(cancelled[0].data).toMatchObject({ reason: 'PROVIDER_UPSTREAM_502', requestId: RID });
    expect(fs_.some((f) => f.event === 'stream_completed')).toBe(false);
    expect(fs_[fs_.length - 1].data).toBe('[DONE]');
    const [dec] = decisionCall();
    expect(dec).toMatchObject({ decision: 'BLOCK', verificationResult: false, reason: 'PROVIDER_UPSTREAM_502' });
    expect(dec.executionContext).toMatchObject({ completionStatus: 'ERROR', terminationReason: 'PROVIDER_UPSTREAM_502' });
    expect(decisionLeaves()[0].payload).toMatchObject({ decision: 'BLOCK', verificationResult: false, reason: 'PROVIDER_UPSTREAM_502' });
    expect(emitted('WARN', 'STREAM_PROVIDER_ERROR')[0]).toMatchObject({ reason: 'PROVIDER_UPSTREAM_502', error: 'upstream 502' });
  });

  test('SC-04b a provider error without a code is PROVIDER_ERROR', async () => {
    mockChunkGen = async function* () { throw new Error('boom'); };   // eslint-disable-line require-yield
    await streamResponse(makeRes(), makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc4b');
    expect(decisionCall()[0]).toMatchObject({ decision: 'BLOCK', reason: 'PROVIDER_ERROR' });
  });

  test('SC-05 stream timeout → BLOCK STREAM_TIMEOUT, CANCELLED, nothing released after the timeout', async () => {
    mockChunkGen = async function* (_p, _b, _c, _m, signal) {
      yield { delta: BENIGN[1] };
      // wait for the stream's own timer to abort this stream, then keep producing as a misbehaving provider would
      await new Promise((r) => (signal.aborted ? r() : signal.addEventListener('abort', r, { once: true })));
      yield { delta: 'LATE CONTENT AFTER THE TIMEOUT that must never be released to the client.' };
    };
    const res = makeRes();
    await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc5');
    const fs_ = frames(res);
    expect(fs_.map((f) => (f.data && f.data.delta) || '').join('')).not.toMatch(/LATE CONTENT/);
    expect(fs_.find((f) => f.event === 'stream_cancelled').data).toMatchObject({ reason: 'STREAM_TIMEOUT' });
    const [dec] = decisionCall();
    expect(dec).toMatchObject({ decision: 'BLOCK', reason: 'STREAM_TIMEOUT', verificationResult: false });
    expect(dec.executionContext).toMatchObject({ completionStatus: 'CANCELLED', terminationReason: 'STREAM_TIMEOUT' });
  });

  test('SC-06 client disconnect mid-stream → BLOCK CLIENT_DISCONNECT, CANCELLED, the next chunk is not released', async () => {
    const req = makeReq();
    // the disconnect signal is the RESPONSE's 'close' (req 'close' fires when the body is read on current Node)
    const res = Object.assign(makeRes(), { _l: {} });
    res.on = (e, f) => { (res._l[e] = res._l[e] || []).push(f); };
    res.off = (e, f) => { if (res._l[e]) res._l[e] = res._l[e].filter((x) => x !== f); };
    mockChunkGen = async function* () {
      yield { delta: BENIGN[1] };
      (res._l.close || []).slice().forEach((f) => f()); // the client goes away
      yield { delta: 'AFTER DISCONNECT — must not be written.' };
    };
    await streamResponse(res, req, artifact(), auth(), { prompt: 'hello' }, 'req-sc6');
    const fs_ = frames(res);
    expect(fs_.map((f) => (f.data && f.data.delta) || '').join('')).not.toMatch(/AFTER DISCONNECT/);
    expect(fs_.find((f) => f.event === 'stream_cancelled').data).toMatchObject({ reason: 'CLIENT_DISCONNECT' });
    expect(decisionCall()[0].executionContext).toMatchObject({ completionStatus: 'CANCELLED', terminationReason: 'CLIENT_DISCONNECT' });
    expect(res._l.close).toEqual([]);                    // the close listener is removed at cleanup
  });

  test('SC-07 DECISION append fails after delivery → CRITICAL; the leaf is still written without an audit hash', async () => {
    mockChunkGen = async function* () { yield { delta: BENIGN[1] }; };
    mockAppend.mockImplementation(async (f) => {
      if (f.entryType === 'DECISION') throw Object.assign(new Error('AUDIT_PERSISTENCE_FAILED: disk full'), { code: 'AUDIT_PERSISTENCE_FAILED' });
      return { hash: HASH };
    });
    await streamResponse(makeRes(), makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc7');
    expect(emitted('CRITICAL', 'STREAM_AUDIT_FAILED')[0]).toMatchObject({ requestId: RID, error: 'AUDIT_PERSISTENCE_FAILED: disk full', code: 'AUDIT_PERSISTENCE_FAILED' });
    expect(emitted('INFO', 'STREAM_AUDIT_RECORDED')).toEqual([]);
    const leaves = decisionLeaves();
    expect(leaves).toHaveLength(1);
    expect(leaves[0].payload.auditEntryHash).toBeNull();
  });

  test('SC-07b already_executed on the DECISION → INFO already_in_chain and no second leaf', async () => {
    mockChunkGen = async function* () { yield { delta: BENIGN[1] }; };
    mockAppend.mockImplementation(async (f) => {
      if (f.entryType === 'DECISION') throw new Error('already_executed: artifact already in the chain');
      return { hash: HASH };
    });
    await streamResponse(makeRes(), makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc7b');
    expect(emitted('INFO', 'STREAM_AUDIT_RECORDED')).toEqual([expect.objectContaining({ note: 'already_in_chain' })]);
    expect(emitted('CRITICAL', 'STREAM_AUDIT_FAILED')).toEqual([]);
    expect(decisionLeaves()).toEqual([]);
  });

  test('SC-08 DECISION leaf fails → CRITICAL TRANSPARENCY_APPEND_FAILED and the failure metric; the stream still ends', async () => {
    mockChunkGen = async function* () { yield { delta: BENIGN[1] }; };
    mockRegister.mockImplementation(async (r) => {
      if (!r.payload.entryType) throw Object.assign(new Error('leaf store down'), { code: 'LEAF_DOWN' });
      return OK;
    });
    const spy = jest.spyOn(metrics.transparencyEnforcementFailuresTotal, 'inc');
    const res = makeRes();
    await expect(streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc8')).resolves.toBeUndefined();
    expect(emitted('CRITICAL', 'TRANSPARENCY_APPEND_FAILED')[0]).toMatchObject({ requestId: RID, stage: 'STREAM', error: 'leaf store down', code: 'LEAF_DOWN' });
    expect(spy).toHaveBeenCalledWith({ stage: 'STREAM' });
    expect(res._ended).toBe(true);
    spy.mockRestore();
  });

  test('SC-09 missing provider → 400 MISSING_PROVIDER, nothing opened, recorded or streamed', async () => {
    const res = makeRes();
    await streamResponse(res, makeReq(), artifact({ provider: '' }), auth(), { prompt: 'hello' }, 'req-sc9');
    expect(res._status).toBe(400);
    expect(res._json).toEqual({ decision: 'BLOCK', reason: 'MISSING_PROVIDER', details: {}, requestId: 'req-sc9' });
    expect(mockAppend).not.toHaveBeenCalled();
    expect(mockRegister).not.toHaveBeenCalled();
    expect(res._events).toEqual([]);
    expect(executeStreamingProviderCall).not.toHaveBeenCalled();
  });

  test('SC-10 pre-stream timeout during the lifecycle writes → abandoned before dispatch, BLOCK REQUEST_TIMEOUT', async () => {
    const ac = new AbortController();
    mockAppend.mockImplementation(async (f) => {
      if (f.entryType === 'STREAM_OPENED') ac.abort('timeout');   // the route's 504 fires while STREAM_OPENED is written
      return { hash: HASH };
    });
    const res = makeRes();
    await streamResponse(res, makeReq(), artifact(), auth({ preStreamSignal: ac.signal }), { prompt: 'hello' }, 'req-sc10');
    expect(emitted('WARN', 'STREAM_ABANDONED_BEFORE_DISPATCH')).toHaveLength(1);
    expect(res.headersSent).toBe(false);
    expect(res._events).toEqual([]);
    expect(executeStreamingProviderCall).not.toHaveBeenCalled();
    const [dec] = decisionCall();
    expect(dec).toMatchObject({ decision: 'BLOCK', reason: 'REQUEST_TIMEOUT', executingProvider: null, outputHash: EMPTY_OUTPUT_HASH });
    expect(dec.executionContext).toMatchObject({ completionStatus: 'ERROR', chunkCount: 0, byteCount: 0 });
  });

  // (The DECISION writer's "missing requestHash or policyHash" refusal is not reachable through streamResponse(): the
  // execution-token mint before dispatch already rejects a non-hex policy/request hash. Its mutants are recorded as
  // unreachable in TQ-05/README.md rather than tested through a contrived call.)
  test('SC-11 no correlation id → no X-Request-Id header', async () => {
    mockChunkGen = async function* () { yield { delta: BENIGN[1] }; };
    const res = makeRes();
    await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, null);
    expect(res._headers['X-Request-Id']).toBeUndefined();
    expect(res._headers['Content-Type']).toBe('text/event-stream');
  });
});
