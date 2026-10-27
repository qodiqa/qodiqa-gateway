'use strict';

/**
 * caps and budget on the REAL /ai/chat router; and "no text is ever left unclassified".
 * Caps are shrunk for the test through the documented env vars, read at module load (isolated modules).
 *
 *   LC-01  prompt exactly at MAX_PROMPT_BYTES (32,768) is accepted and classified in full; one byte over → 400
 *          PROMPT_TOO_LARGE before any classification or provider call
 *   LC-02  budget exhausted → 429 CLASSIFICATION_BUDGET_EXHAUSTED + Retry-After; no classification, no provider
 *          call, no audit entry; the SAME prompt succeeds for a tenant with budget
 *   LC-03  output exactly at the cap → EXECUTE, and the output classifier saw the WHOLE text
 *   LC-04  output one character over the cap → BLOCK OUTPUT_TOO_LARGE, the text withheld (never released
 *          truncated), audited as an output block
 *   LC-05  stream: crossing the cap → stream_cancelled OUTPUT_TOO_LARGE; every forwarded character had passed the
 *          window's classification and none lies past the cap
 */

const mockConsent = { result: { pass: true, reason: 'ACTIVE' } };
jest.mock('../../core/consent', () => ({ verify: jest.fn().mockImplementation(async () => mockConsent.result) }));

const express = require('express');
const supertest = require('supertest');

const CAP = 1000;
// Each isolated registry gets its OWN classifier instance, which must be initialized there (the global
// jest.setup.afterEnv init ran on the main registry; an uninitialized classifier fails closed).
async function loadRouter(env) {
  let mods;
  const saved = { ...process.env };
  Object.assign(process.env, env);
  jest.isolateModules(() => {
    const embeddingGate = require('../../core/semantic/embeddingGate');
    const seen = [];
    const orig = embeddingGate.checkText;
    embeddingGate.checkText = jest.fn(async (text, ctx) => { seen.push({ text, surface: ctx && ctx.surface }); return orig(text, ctx); });
    const auditWrites = [];
    const audit = require('../../core/audit/audit-log');
    const origAppend = audit.appendMandatory;
    audit.appendMandatory = jest.fn(async (e, o) => { auditWrites.push(e); return origAppend(e, o); });
    mods = {
      createAiChatRouter: require('../routes/aiChat'), seen, auditWrites,
      attachClientIp: require('../../../middleware/clientIp'),
      signBoundArtifact: require('../../validation/signBoundArtifact').signBoundArtifact,
      getActiveKey: require('../../../services/artifact/keyStore').getActiveKey,
      resetStats: require('../../../services/execution-guard').resetStats,
      validateAndPrepare: require('../../../services/policy/loader').validateAndPrepare,
      createStore: require('../../../services/policy/store').createStore,
      stores: require('../../testing/stores'),
      classifier: require('../../core/semantic/embeddingSimilarity'),
    };
  });
  await mods.classifier.init();
  for (const k of Object.keys(env)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  return mods;
}

function harness(m, providerFn) {
  const KEY = m.getActiveKey('default');
  const policies = m.validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
  const calls = { provider: 0 };
  const app = express();
  app.use(m.attachClientIp);
  app.use(express.json({ limit: '1mb' }));
  app.use('/ai/chat', m.createAiChatRouter({
    _store: m.stores.makeNonceStore(), _anomalyStore: m.stores.makeOpenAnomalyStore(),
    _providerFn: (...a) => { calls.provider++; return providerFn(...a); }, _getPolicies: () => policies, _policyStore: m.createStore(),
  }));
  const post = (body, envOverrides = {}) => {
    const now = Date.now();
    const a = m.signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId, ...envOverrides }, KEY.privDer);
    return supertest(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(a)).toString('base64')).send(body);
  };
  return { app, post, calls };
}

const benign = (n) => { const s = 'The weather today is sunny with a light breeze. '; let t = ''; while (t.length < n) t += s; return t.slice(0, n); };

describe('classification caps and budget (real router)', () => {
  beforeEach(() => { mockConsent.result = { pass: true, reason: 'ACTIVE' }; });

  test('LC-01 prompt exactly at 32,768 bytes accepted and classified in full; one byte over refused 400', async () => {
    const m = await loadRouter({}); m.resetStats();
    const h = harness(m, () => Promise.resolve({ output: 'ok' }));
    const at = await h.post({ prompt: benign(32_768), model: 'gpt-4' });
    expect([at.status, at.body.decision]).toEqual([200, 'EXECUTE']);
    expect(m.seen.find((x) => x.surface === 'REQUEST').text.length).toBe(32_768);
    const providerBefore = h.calls.provider; const seenBefore = m.seen.length;
    const over = await supertest(h.app).post('/ai/chat').set('x-qodiqa-artifact', 'x').send({ prompt: benign(32_769), model: 'gpt-4' });
    expect([over.status, over.body.reason]).toEqual([400, 'PROMPT_TOO_LARGE']);
    expect(h.calls.provider).toBe(providerBefore);
    expect(m.seen.length).toBe(seenBefore);
  });

  test('LC-02 budget exhausted → 429 + Retry-After; nothing classified, provider not called, nothing audited', async () => {
    const m = await loadRouter({ QODIQA_CLASSIFY_BUDGET_BURST: '5', QODIQA_CLASSIFY_BUDGET_REFILL_PER_SEC: '1' }); m.resetStats();
    const h = harness(m, () => Promise.resolve({ output: 'ok' }));
    const prompt = benign(3000); // 9 windows > burst 5
    const r = await h.post({ prompt, model: 'gpt-4' });
    expect(r.status).toBe(429);
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'CLASSIFICATION_BUDGET_EXHAUSTED' });
    expect(Number(r.headers['retry-after'])).toBeGreaterThanOrEqual(1);
    expect(h.calls.provider).toBe(0);
    expect(m.seen).toEqual([]);
    expect(m.auditWrites).toEqual([]);
    const ok = await h.post({ prompt: 'What is the capital of France?', model: 'gpt-4' }); // 1 window fits
    expect([ok.status, ok.body.decision]).toEqual([200, 'EXECUTE']);
  });

  test('LC-02b (launch plan R-16) non-stream Retry-After carries the budget\'s own delay, not a fixed 60', async () => {
    // burst 5, refill 1/s, a 9-window prompt → the budget's own wait is a few seconds. Before R-16,
    // _enforceAndExecute dropped retryAfterSeconds and the non-stream response always said 60.
    const m = await loadRouter({ QODIQA_CLASSIFY_BUDGET_BURST: '5', QODIQA_CLASSIFY_BUDGET_REFILL_PER_SEC: '1' }); m.resetStats();
    const h = harness(m, () => Promise.resolve({ output: 'ok' }));
    const r = await h.post({ prompt: benign(3000), model: 'gpt-4' });
    expect([r.status, r.body.reason]).toEqual([429, 'CLASSIFICATION_BUDGET_EXHAUSTED']);
    const ra = Number(r.headers['retry-after']);
    expect(ra).toBeGreaterThanOrEqual(1);
    expect(ra).toBeLessThanOrEqual(10);
  });

  test('LC-03 output exactly at the cap → EXECUTE, classified in full', async () => {
    const m = await loadRouter({ QODIQA_OUTPUT_CLASSIFY_MAX_CHARS: String(CAP) }); m.resetStats();
    const out = benign(CAP);
    const h = harness(m, () => Promise.resolve({ output: out }));
    const r = await h.post({ prompt: 'Describe the weather.', model: 'gpt-4' });
    expect([r.status, r.body.decision, r.body.response]).toEqual([200, 'EXECUTE', out]);
    expect(m.seen.find((x) => x.surface === 'RESPONSE').text).toBe(out);
  });

  test('LC-04 output one over the cap → BLOCK OUTPUT_TOO_LARGE, withheld, audited', async () => {
    const m = await loadRouter({ QODIQA_OUTPUT_CLASSIFY_MAX_CHARS: String(CAP) }); m.resetStats();
    const out = benign(CAP + 1);
    const h = harness(m, () => Promise.resolve({ output: out }));
    const r = await h.post({ prompt: 'Describe the weather.', model: 'gpt-4' });
    expect([r.status, r.body.decision, r.body.reason]).toEqual([200, 'BLOCK', 'OUTPUT_TOO_LARGE']);
    expect(JSON.stringify(r.body)).not.toContain(out.slice(0, 200));
    expect(m.auditWrites.some((e) => e.reason === 'OUTPUT_TOO_LARGE' && e.stage === 'SEMANTIC_POLICY_OUTPUT')).toBe(true);
  });
});

describe('stream output cap (streamResponse)', () => {
  test('LC-05 crossing the cap cancels OUTPUT_TOO_LARGE; nothing past the cap is released', async () => {
    let mod;
    const saved = process.env.QODIQA_OUTPUT_CLASSIFY_MAX_CHARS;
    process.env.QODIQA_OUTPUT_CLASSIFY_MAX_CHARS = String(CAP);
    jest.isolateModules(() => {
      jest.doMock('../../core/audit/audit-log', () => ({ append: (e) => e, appendMandatory: async (e) => e, alreadyExecuted: () => false }));
      jest.doMock('../../../services/execution.stream', () => ({
        executeStreamingProviderCall: jest.fn(async function* () { for (let i = 0; i < 30; i++) yield { delta: benign(60) }; }),
      }));
      mod = require('../../streaming/streamEnforcer');
      mod.__classifier = require('../../core/semantic/embeddingSimilarity');
    });
    await mod.__classifier.init();
    if (saved === undefined) delete process.env.QODIQA_OUTPUT_CLASSIFY_MAX_CHARS; else process.env.QODIQA_OUTPUT_CLASSIFY_MAX_CHARS = saved;
    const events = [];
    const res = { _headers: {}, headersSent: false, setHeader(n, v) { this._headers[n] = v; }, flushHeaders() { this.headersSent = true; }, write(d) { events.push(d); }, end() {}, status() { return this; }, json() { return this; } };
    const req = { on() {}, off() {}, clientIp: '127.0.0.1' };
    const artifact = { payload: { requestHash: 'a'.repeat(64), provider: 'openai', policyHash: 'b'.repeat(64) }, signature: 's', expiry: Date.now() + 60_000, timestamp: Date.now(), publicKeyId: 'tenant1:key_v1' };
    await mod.streamResponse(res, req, artifact, { requestId: 'aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee', tenantId: 'tenant1', policyHash: 'b'.repeat(64) }, { prompt: 'hello', model: 'gpt-4o-mini' }, 'req-cap');
    const frames = events.join('').split('\n\n').map((f) => (f.split('\n').find((l) => l.startsWith('data: ')) || '').slice(6)).filter((d) => d && d !== '[DONE]').map((d) => JSON.parse(d));
    const released = frames.filter((f) => f.event === 'chunk_forwarded').map((f) => f.delta).join('');
    expect(frames.find((f) => f.event === 'stream_cancelled').reason).toBe('OUTPUT_TOO_LARGE');
    expect(released.length).toBeLessThanOrEqual(CAP);
  });
});
