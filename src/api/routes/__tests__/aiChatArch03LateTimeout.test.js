'use strict';

/**
 * — a non-streaming timeout that fires AFTER the
 * provider answered in time, while the output-side check is still running, must be recorded CANCELLED, never ALLOW.
 *
 * Before the fix the late-completion guard was checked once, right after the provider returned; the output-side check
 * and the representability check that follow both await, and the ALLOW append after them was not re-guarded, so the
 * client got 504 while the chain recorded ALLOW/EXECUTE (reproduced: the decisions recorded for the 504 were ["ALLOW"]).
 *
 * Deterministic by construction (a separate file from aiChatCancellation.test.js, whose 200 ms budget is too tight for
 * this ordering under parallel load): the provider answers immediately, and the output-side check is held until the
 * route's OWN AbortSignal has fired — no sleeps decide the ordering. The 2 s budget only has to exceed the request
 * pipeline before the provider call.
 *
 *   A3-01 timeout during the output-side check → BLOCK REQUEST_TIMEOUT CANCELLED, no ALLOW for that request
 *   A3-02 control: an output-side check that finishes inside the budget still records ALLOW / EXECUTE
 */

process.env.AI_CHAT_TIMEOUT_MS = '2000';

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));
// Same isolation as aiChatCancellation.test.js: this suite proves timeout orchestration, not semantic quality.
jest.mock('../../../core/semantic/embeddingGate', () => ({
  checkText: jest.fn().mockResolvedValue({ blocks: false }),
}));

const express   = require('express');
const supertest = require('supertest');

const createAiChatRouter     = require('../aiChat');
const attachClientIp         = require('../../../../middleware/clientIp');
const { signBoundArtifact }  = require('../../../validation/signBoundArtifact');
const { getActiveKey }       = require('../../../../services/artifact/keyStore');
const { resetStats }         = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { getModernChain, drainPendingWrites } = require('../../../core/audit/audit-log');
const embeddingGate          = require('../../../core/semantic/embeddingGate');

jest.setTimeout(30_000);

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };
const MOCK_RESPONSE = 'Mock AI response';
let KEY;

const _POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const _POLICY_STORE = createStore();

function buildArtifact() {
  const now = Date.now();
  const req = { method: 'POST', path: CHAT_PATH, body: CHAT_BODY };
  return signBoundArtifact(req, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
function makeApp(providerFn) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn,
    _getPolicies: () => _POLICIES, _policyStore: _POLICY_STORE,
  }));
  return app;
}
const post = (app, artifact) => supertest(app).post('/ai/chat')
  .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifact)).toString('base64')).send(CHAT_BODY);
const abortFired = (signal) => (signal.aborted ? Promise.resolve() : new Promise((r) => signal.addEventListener('abort', r, { once: true })));

beforeAll(async () => {
  KEY = getActiveKey('default');
  const warm = makeApp(() => Promise.resolve({ output: MOCK_RESPONSE }));
  await post(warm, buildArtifact());
  await drainPendingWrites();
}, 20_000);
beforeEach(() => resetStats());
afterEach(() => {
  embeddingGate.checkText.mockReset();
  embeddingGate.checkText.mockResolvedValue({ blocks: false });
});

describe('timeout during the output-side check, before the ALLOW append', () => {
  test('A3-01 a provider that answers in time, then a timeout during the output check → CANCELLED, never ALLOW', async () => {
    let routeSignal;
    let outputCheckStarted = false;
    // the provider answers immediately and hands us the route's own AbortSignal
    const provider = (_p, _b, _c, signal) => { routeSignal = signal; return Promise.resolve({ output: MOCK_RESPONSE }); };
    // request-side check: immediate; output-side check (the provider's text): held until the route timer has fired
    embeddingGate.checkText.mockImplementation(async (text) => {
      if (text === MOCK_RESPONSE) { outputCheckStarted = true; await abortFired(routeSignal); }
      return { blocks: false };
    });
    const before = (await getModernChain()).length;
    const artifact = buildArtifact();

    const res = await post(makeApp(provider), artifact);  // answered 504 by the route timer
    expect(res.status).toBe(504);
    expect(outputCheckStarted).toBe(true);               // we were past the provider and its late-completion guard

    await drainPendingWrites();
    // the background continuation finishes after the output check returns; wait for its record (bounded)
    let mine = [];
    for (let i = 0; i < 200 && !mine.length; i++) {
      await new Promise((r) => setTimeout(r, 10));
      await drainPendingWrites();
      mine = (await getModernChain()).slice(before).filter((e) => e.artifactId === artifact.payload.requestId);
    }
    expect(mine.map((e) => e.decision)).not.toContain('ALLOW');
    const last = mine[mine.length - 1];
    expect(last.decision).toBe('BLOCK');
    expect(last.executionContext.completionStatus).toBe('CANCELLED');
    expect(last.executionContext.reason).toBe('REQUEST_TIMEOUT');
  });

  test('A3-02 control: an output check that finishes inside the budget still records ALLOW / EXECUTE', async () => {
    embeddingGate.checkText.mockImplementation(async (text) => {
      if (text === MOCK_RESPONSE) await new Promise((r) => setTimeout(r, 20));
      return { blocks: false };
    });
    const before = (await getModernChain()).length;
    const res = await post(makeApp(() => Promise.resolve({ output: MOCK_RESPONSE })), buildArtifact());
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('EXECUTE');
    await drainPendingWrites();
    const mine = (await getModernChain()).slice(before).filter((e) => e.artifactId === res.body.artifactId);
    expect(mine.map((e) => e.decision)).toContain('ALLOW');
  });
});
