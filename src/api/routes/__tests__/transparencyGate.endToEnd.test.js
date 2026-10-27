'use strict';

/**
 * (D-F5-1) on the real routes: while the transparency evidence store has been unavailable longer than its bound, a NEW execution is refused
 * (503 TRANSPARENCY_JOURNAL_UNAVAILABLE, Retry-After, the provider is never called) and BLOCK decisions keep being answered; once the store recovers
 * executions resume.
 *
 *   TG-01  healthy: EXECUTE
 *   TG-02  unavailable but inside the bound: EXECUTE still served
 *   TG-03  past the bound: EXECUTE refused with 503 + Retry-After, provider not called; a BLOCK is still a BLOCK
 *   TG-04  after recovery: EXECUTE again
 */

jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));

const request = require('supertest');
const express = require('express');
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const { apiKey: SIGN_KEY } = provisionTestSigningIdentity({ tenantId: 'default' });
let app; let jh; let calls = 0;
const realNow = Date.now;

beforeAll(() => {
  jest.resetModules();
  for (const k of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL']) delete process.env[k];
  process.env.OPENAI_API_KEY = PROVIDER_FIXTURE_KEYS.openai;
  process.env.QODIQA_CLIENT_ID = 'default';
  process.env.IDEMPOTENCY_ENABLED = 'false';
  jh = require('../../../core/transparency/journalHealth');
  const createSignRouter = require('../sign');
  const createAiChatRouter = require('../aiChat');
  const requestId = require('../../../../middleware/requestId');
  const attachClientIp = require('../../../../middleware/clientIp');
  const { validateAndPrepare } = require('../../../../services/policy/loader');
  const { createStore } = require('../../../../services/policy/store');
  const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
  const policies = validateAndPrepare({ policies: [{ id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
  app = express();
  app.use(requestId); app.use(attachClientIp);
  app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
  app.use('/sign', createSignRouter(() => policies));
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => policies, _policyStore: createStore(),
    _providerFn: async () => { calls += 1; return { output: 'ok' }; },
  }));
  process.env.QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS = '5000';
});
afterAll(() => { Date.now = realNow; jh._reset(); delete process.env.IDEMPOTENCY_ENABLED; delete process.env.QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS; });
beforeEach(() => { calls = 0; });

const BODY = { prompt: 'hello', model: 'gpt-4o' };
const signed = async () => (await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_KEY}`).send({ request: { method: 'POST', path: '/ai/chat', body: BODY } })).body.artifact;
const chat = async () => request(app).post('/ai/chat').set('Content-Type', 'application/json').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(await signed())).toString('base64')).send(JSON.stringify(BODY));

describe('EXECUTE refused while the transparency evidence store is unavailable past its bound', () => {
  test('TG-01 healthy: EXECUTE', async () => {
    const r = await chat();
    expect(r.status).toBe(200);
    expect(r.body.decision).toBe('EXECUTE');
    expect(calls).toBe(1);
  });

  test('TG-02 unavailable but inside the bound: EXECUTE still served', async () => {
    jh.noteFailure(new Error('journal volume gone'));
    Date.now = () => realNow() + 4000;
    const r = await chat();
    expect(r.status).toBe(200);
    expect(calls).toBe(1);
  });

  test('TG-03 past the bound: EXECUTE refused (503, Retry-After), provider never called; a BLOCK is still answered as a BLOCK', async () => {
    jh.noteFailure(new Error('journal volume gone'));
    Date.now = () => realNow() + 6000;
    const r = await chat();
    expect(r.status).toBe(503);
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'TRANSPARENCY_JOURNAL_UNAVAILABLE' });
    expect(r.headers['retry-after']).toBe('30');
    expect(calls).toBe(0);
    const block = await request(app).post('/ai/chat').set('Content-Type', 'application/json').send(JSON.stringify(BODY));   // no artifact: a normal refusal
    expect(block.body.decision).toBe('BLOCK');
    expect(block.body.reason).not.toBe('TRANSPARENCY_JOURNAL_UNAVAILABLE');
  });

  test('TG-04 after recovery EXECUTE resumes', async () => {
    jh.noteOk();
    Date.now = realNow;
    const r = await chat();
    expect(r.status).toBe(200);
    expect(calls).toBe(1);
  });
});
