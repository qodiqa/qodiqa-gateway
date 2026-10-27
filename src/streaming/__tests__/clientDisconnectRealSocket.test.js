'use strict';

/**
 * a client that disconnects mid-stream cancels the provider. REAL SOCKETS.
 *
 * The defect: streamEnforcer.js attached `req.on('close')` after the request body had been consumed. On current Node
 * an IncomingMessage emits 'close' as soon as its body has been read, so by the time the listener was attached the
 * event had already fired and never fired again: a client that went away did NOT abort the provider stream, and the
 * stream ran to completion and was recorded as a 'completed' ALLOW for content nobody received. The pre-existing
 * suites could not see it because their `req` is a hand-rolled emitter that only fires 'close' when told to.
 *
 * This suite uses a real node:http server and a real client socket. The handler consumes the request body exactly as
 * express.json() does in production BEFORE calling streamResponse(). The provider is a slow fake: it yields one chunk
 * large enough to be released past the output semantic window, then waits (up to 4 s) for its AbortSignal.
 *
 *   DD019-01  client destroys its socket after the first released chunk → the provider's AbortSignal fires within
 *             ~1 s, the closing DECISION is BLOCK CLIENT_DISCONNECT (CANCELLED), no ALLOW / 'completed' DECISION is
 *             recorded, and the provider's post-disconnect content is never written.
 *   DD019-02  control: a client that stays connected gets a normal completed stream (ALLOW) — the res 'close' that
 *             follows a normal res.end() must NOT be mistaken for a disconnect.
 *
 * Verified failing on the pre-fix code (req.on('close')): DD019-01 fails (no abort within the window; DECISION ALLOW).
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

const http = require('http');
const { streamResponse } = require('../streamEnforcer');
const { EMBEDDING_INTERVAL_CHARS } = require('../outputSemanticWindow');

const RID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const artifact = () => ({ payload: { requestHash: 'a'.repeat(64), provider: 'openai', policyHash: 'b'.repeat(64) }, signature: 'sig-test', expiry: Date.now() + 60_000, timestamp: Date.now(), publicKeyId: 'tenant1:key_v1' });
const auth = () => ({ requestId: RID, tenantId: 'tenant1', policyHash: 'b'.repeat(64) });

const SENTENCE = 'The weather today is sunny and mild with a light breeze from the west. ';
function benign(n) { let s = ''; while (s.length < n) s += SENTENCE; return s.slice(0, n); }

let server; let port; let handlerDone;

beforeEach(async () => {
  mockChunkGen = null;
  mockAppend.mockReset();
  mockAppend.mockImplementation(async (f) => ({ hash: 'h'.repeat(64), artifactId: f.artifactId }));
  mockRegister.mockReset();
  mockRegister.mockImplementation(async () => ({ transparencyId: 't', entryHash: 'e'.repeat(64), signature: 's', keyId: 'k', persisted: true }));
  handlerDone = null;
  server = http.createServer((req, res) => {
    // Consume the body first, exactly as express.json() does before the route runs.
    const parts = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(parts).toString('utf8') || '{}');
      handlerDone = streamResponse(res, req, artifact(), auth(), body, 'req-dd019')
        .then(() => { try { res.end(); } catch { /* socket gone */ } });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});

afterEach(async () => {
  if (handlerDone) await handlerDone;
  await new Promise((r) => server.close(r));
});

function decisions() { return mockAppend.mock.calls.map(([f]) => f).filter((f) => (f.entryType || 'DECISION') === 'DECISION'); }

function openStream({ destroyAfterFirstChunk }) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ prompt: 'hello', model: 'gpt-4o-mini', stream: true });
    const creq = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/ai/chat', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } });
    let text = ''; let destroyedAt = null;
    creq.on('response', (cres) => {
      cres.setEncoding('utf8');
      cres.on('data', (d) => {
        text += d;
        if (destroyAfterFirstChunk && destroyedAt === null && text.includes('"chunk_forwarded"')) {
          destroyedAt = Date.now();
          creq.destroy();
          resolve({ text, destroyedAt });
        }
      });
      cres.on('end', () => resolve({ text, destroyedAt }));
      cres.on('error', () => resolve({ text, destroyedAt }));
    });
    creq.on('error', (e) => { if (destroyedAt === null) reject(e); });
    creq.end(payload);
  });
}

describe('client disconnect cancels the provider (real socket)', () => {
  test('DD019-01 socket destroyed after the first chunk → AbortSignal within ~1 s, BLOCK CLIENT_DISCONNECT, no ALLOW', async () => {
    let abortedAt = null; let signalReason = null; let lateWritten = false;
    mockChunkGen = async function* (_p, _b, _ctx, _meta, signal) {
      yield { delta: benign(EMBEDDING_INTERVAL_CHARS + 50) };
      await new Promise((resolve) => {
        const t = setTimeout(resolve, 4000);
        if (signal) signal.addEventListener('abort', () => { abortedAt = Date.now(); signalReason = signal.reason; clearTimeout(t); resolve(); }, { once: true });
      });
      lateWritten = true;
      yield { delta: 'POST-DISCONNECT CONTENT that nobody will ever receive. ' + benign(EMBEDDING_INTERVAL_CHARS) };
    };

    const { text, destroyedAt } = await openStream({ destroyAfterFirstChunk: true });
    expect(text).toContain('"chunk_forwarded"');
    expect(destroyedAt).not.toBeNull();
    await handlerDone;

    expect(abortedAt).not.toBeNull();                      // the provider WAS told to stop
    expect(abortedAt - destroyedAt).toBeLessThan(1000);    // promptly
    expect(signalReason).toBe('client_disconnect');
    expect(lateWritten).toBe(true);                        // the fake resumed after the abort and offered more content…

    const decs = decisions();
    expect(decs).toHaveLength(1);
    expect(decs[0]).toMatchObject({ decision: 'BLOCK', reason: 'CLIENT_DISCONNECT', verificationResult: false });
    expect(decs[0].executionContext).toMatchObject({ completionStatus: 'CANCELLED', terminationReason: 'CLIENT_DISCONNECT' });
    expect(decs.some((d) => d.decision === 'ALLOW')).toBe(false);   // no 'completed' ALLOW for undelivered content
  }, 15000);

  test('DD019-02 control: a connected client gets a normal completed stream (ALLOW), not a false disconnect', async () => {
    let aborted = false;
    mockChunkGen = async function* (_p, _b, _ctx, _meta, signal) {
      if (signal) signal.addEventListener('abort', () => { aborted = true; }, { once: true });
      yield { delta: benign(EMBEDDING_INTERVAL_CHARS + 50) };
      await new Promise((r) => setTimeout(r, 50));
      yield { delta: benign(120) };
    };
    const { text } = await openStream({ destroyAfterFirstChunk: false });
    await handlerDone;
    expect(text).toContain('"stream_completed"');
    expect(text).toContain('[DONE]');
    expect(aborted).toBe(false);
    const decs = decisions();
    expect(decs).toHaveLength(1);
    expect(decs[0]).toMatchObject({ decision: 'ALLOW' });
  }, 15000);
});
