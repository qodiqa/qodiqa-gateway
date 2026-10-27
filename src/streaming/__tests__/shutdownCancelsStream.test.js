'use strict';

/**
 * streamRegistry.cancelAll() (called by graceful shutdown) ends an open stream
 * through its normal cancelled path, so the closing DECISION is written before the process exits.
 * Harness = streamLifecycle.test.js's (real streamResponse(), mocked provider generator / audit-log / registrar).
 *
 *   SC76-01  cancelAll mid-stream → the provider's AbortSignal fires with 'server_shutdown'; DECISION BLOCK
 *            SERVER_SHUTDOWN (CANCELLED); terminal stream_cancelled{reason:SERVER_SHUTDOWN} + [DONE]; nothing after
 *            the cancel is released; the stream leaves the registry
 *   SC76-02  a stream that reaches dispatch AFTER cancelAll ran is cancelled immediately (latched), never completes
 *   SC76-03  a normally completing stream is unaffected and deregisters its canceller
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));
const mockAppend = jest.fn();
jest.mock('../../core/audit/audit-log', () => ({ append: (e) => e, appendMandatory: (...a) => mockAppend(...a), alreadyExecuted() { return false; } }));
const mockRegister = jest.fn();
jest.mock('../../core/transparency/registrar', () => ({ register: (...a) => mockRegister(...a) }));
let mockChunkGen = null;
jest.mock('../../../services/execution.stream', () => ({
  executeStreamingProviderCall: jest.fn(async function* (...args) { if (mockChunkGen) yield* mockChunkGen(...args); }),
}));

const { streamResponse } = require('../streamEnforcer');
const streamRegistry = require('../streamRegistry');
const { EMBEDDING_INTERVAL_CHARS } = require('../outputSemanticWindow');

const RID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const artifact = () => ({ payload: { requestHash: 'a'.repeat(64), provider: 'openai', policyHash: 'b'.repeat(64) }, signature: 'sig-test', expiry: Date.now() + 60_000, timestamp: Date.now(), publicKeyId: 'tenant1:key_v1' });
const auth = () => ({ requestId: RID, tenantId: 'tenant1', policyHash: 'b'.repeat(64) });
function makeRes() {
  return {
    _events: [], headersSent: false,
    setHeader() {}, flushHeaders() { this.headersSent = true; }, write(d) { this._events.push(String(d)); }, end() {},
    status() { return this; }, json() { this.headersSent = true; return this; },
  };
}
const makeReq = () => ({ on() {}, off() {}, clientIp: '127.0.0.1' });
const SENT = 'The weather today is sunny and mild with a light breeze. ';
const benign = (n) => { let s = ''; while (s.length < n) s += SENT; return s.slice(0, n); };
const decisions = () => mockAppend.mock.calls.map(([f]) => f).filter((f) => (f.entryType || 'DECISION') === 'DECISION');
const allText = (res) => res._events.join('');

beforeEach(() => {
  streamRegistry._resetForTests();
  mockChunkGen = null;
  mockAppend.mockReset();
  mockAppend.mockImplementation(async (f) => ({ hash: 'h'.repeat(64), artifactId: f.artifactId }));
  mockRegister.mockReset();
  mockRegister.mockImplementation(async () => ({ transparencyId: 't', entryHash: 'e'.repeat(64), signature: 's', keyId: 'k', persisted: true }));
});
afterAll(() => streamRegistry._resetForTests());

test('SC76-01 cancelAll mid-stream → BLOCK SERVER_SHUTDOWN DECISION, terminal event, nothing released after', async () => {
  let reason = null;
  mockChunkGen = async function* (_p, _b, _c, _m, signal) {
    yield { delta: benign(EMBEDDING_INTERVAL_CHARS + 20) };
    expect(streamRegistry.activeCount()).toBe(1);
    expect(streamRegistry.cancelAll('server_shutdown')).toBe(1);   // what shutdown.js does at timeoutMs/2
    reason = signal.reason;
    yield { delta: 'AFTER SHUTDOWN — must never be released. ' + benign(EMBEDDING_INTERVAL_CHARS) };
  };
  const res = makeRes();
  await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc76-1');
  expect(reason).toBe('server_shutdown');
  expect(allText(res)).not.toMatch(/AFTER SHUTDOWN/);
  expect(allText(res)).toMatch(/"event":"stream_cancelled"[^\n]*"reason":"SERVER_SHUTDOWN"/);
  expect(allText(res)).toContain('[DONE]');
  const decs = decisions();
  expect(decs).toHaveLength(1);
  expect(decs[0]).toMatchObject({ decision: 'BLOCK', reason: 'SERVER_SHUTDOWN' });
  expect(decs[0].executionContext).toMatchObject({ completionStatus: 'CANCELLED', terminationReason: 'SERVER_SHUTDOWN' });
  expect(streamRegistry.activeCount()).toBe(0);
});

test('SC76-02 a stream dispatched after cancelAll is cancelled immediately', async () => {
  streamRegistry.cancelAll('server_shutdown');
  let sawAbort = null;
  mockChunkGen = async function* (_p, _b, _c, _m, signal) {
    sawAbort = signal.aborted;
    yield { delta: benign(EMBEDDING_INTERVAL_CHARS + 20) };
  };
  const res = makeRes();
  await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc76-2');
  expect(sawAbort).toBe(true);
  expect(decisions()[0]).toMatchObject({ decision: 'BLOCK', reason: 'SERVER_SHUTDOWN' });
  expect(allText(res)).not.toContain('"chunk_forwarded"');
});

test('SC76-03 a normal stream completes (ALLOW) and leaves no canceller behind', async () => {
  mockChunkGen = async function* () { yield { delta: benign(120) }; };
  const res = makeRes();
  await streamResponse(res, makeReq(), artifact(), auth(), { prompt: 'hello' }, 'req-sc76-3');
  expect(decisions()[0]).toMatchObject({ decision: 'ALLOW' });
  expect(streamRegistry.cancelAll('server_shutdown')).toBe(0);
});
