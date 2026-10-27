'use strict';

/**
 * TQ-05 — evidence binding of every BLOCK audit entry in /ai/chat.
 *
 * The 34-file mutation run left aiChat.js at 49.48 %. The largest single cluster of surviving mutants was the same at
 * every BLOCK site: the audit entry's `inputHash` / `requestHash` (the artifact's signed request hash), `signature`,
 * `policyHash`, `provider` and `publicKeyId` fields could be replaced by null and no test noticed. Those fields are what
 * binds a BLOCK decision to the request it refused — the evidence contract an auditor verifies. These tests drive each
 * reachable BLOCK stage through the real router and real audit chain and assert that binding, plus the decision,
 * reason, stage and the HTTP outcome. Deterministic: every trigger is a stubbed dependency, no timing is involved.
 *
 *   BE-01 VALIDATION            replayed artifact → REPLAY_DETECTED
 *   BE-02 POLICY_ENFORCEMENT    consent policy refuses → the policy's reason, with the policy hash
 *   BE-03 POLICY_ENFORCEMENT    the policy source throws → POLICY_BLOCKED (fail closed), provider never called
 *   BE-04 SEMANTIC_POLICY       request-side semantic block
 *   BE-05 SEMANTIC_POLICY_OUTPUT the provider's output is blocked → nothing delivered
 *   BE-06 PROVIDER_EXECUTION    provider error → the provider's code
 *   BE-07 PROVIDER_EXECUTION_CANCELLED  provider reports cancellation → CANCELLED, never ALLOW
 *   BE-08 control: an ALLOW entry carries the same binding
 */

process.env.AI_CHAT_TIMEOUT_MS = '5000';

const mockConsentVerify = jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' });
jest.mock('../../../core/consent', () => ({ verify: (...a) => mockConsentVerify(...a) }));
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
const OUTPUT = 'Mock AI response';
const HEX64 = /^[0-9a-f]{64}$/;
let KEY;

const POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true },
}] });

function buildArtifact() {
  const now = Date.now();
  return signBoundArtifact({ method: 'POST', path: CHAT_PATH, body: CHAT_BODY },
    { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
}
function makeApp({ provider = () => Promise.resolve({ output: OUTPUT }), getPolicies = () => POLICIES, store } = {}) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store: store || makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: provider,
    _getPolicies: getPolicies, _policyStore: createStore(),
  }));
  return app;
}
const post = (app, artifact) => supertest(app).post('/ai/chat')
  .set('x-qodiqa-artifact', Buffer.from(JSON.stringify(artifact)).toString('base64')).send(CHAT_BODY);

// The newest entry recorded for this artifact's request id (waits for the background write; bounded). A replay BLOCK
// is recorded under a fresh id and links the original through `replayOf`.
async function entryFor(artifact, before) {
  const id = artifact.payload.requestId;
  for (let i = 0; i < 200; i++) {
    await drainPendingWrites();
    const mine = (await getModernChain()).slice(before).filter((e) => e.artifactId === id || e.replayOf === id || (e.executionContext && e.executionContext.replayOf === id));
    if (mine.length) return mine[mine.length - 1];
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`no audit entry for ${id}`);
}
// The evidence binding every decision entry must carry. `provider` is recorded only once a provider was dispatched
// (aiChat.js _writeAuditBlock: null "for any BLOCK that occurred before a provider/model was selected").
function expectBound(entry, artifact, { provider, policyHash = HEX64 } = {}) {
  expect(entry.inputHash).toBe(artifact.payload.requestHash);
  expect(entry.requestHash).toBe(artifact.payload.requestHash);
  expect(entry.signature).toBe(artifact.signature);
  if (policyHash instanceof RegExp) expect(entry.policyHash).toMatch(policyHash); else expect(entry.policyHash).toBe(policyHash);
  expect(entry.publicKeyId).toBe(KEY.keyId);
  expect(entry.provider).toBe(provider);
}

beforeAll(async () => {
  KEY = getActiveKey('default');
  await post(makeApp(), buildArtifact());
  await drainPendingWrites();
}, 20_000);
beforeEach(() => {
  resetStats();
  embeddingGate.checkText.mockReset();
  embeddingGate.checkText.mockResolvedValue({ blocks: false });
  mockConsentVerify.mockReset();
  mockConsentVerify.mockResolvedValue({ pass: true, reason: 'ACTIVE' });
});

describe('BLOCK audit entries bind the refused request (TQ-05)', () => {
  test('BE-01 VALIDATION: a replayed artifact is refused and the refusal is bound to it', async () => {
    const store = makeNonceStore();
    const a = buildArtifact();
    expect((await post(makeApp({ store }), a)).body.decision).toBe('EXECUTE');
    await drainPendingWrites();
    const before = (await getModernChain()).length;
    const res = await post(makeApp({ store }), a);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'REPLAY_DETECTED' });
    const e = await entryFor(a, before);
    expect(e).toMatchObject({ decision: 'BLOCK' });
    expect(e.executionContext).toMatchObject({ reason: 'REPLAY_DETECTED', stage: 'VALIDATION' });
    expect(e.inputHash).toBe(a.payload.requestHash);
    expect(e.requestHash).toBe(a.payload.requestHash);
    expect(e.signature).toBe(a.signature);
    expect(e.artifactId).not.toBe(a.payload.requestId);   // a fresh id: the original's id is never reused
    expect(e.provider).toBeNull();                         // refused before any provider was selected
  });

  test('BE-02 POLICY_ENFORCEMENT: a consent refusal is recorded with the policy hash and the request binding', async () => {
    mockConsentVerify.mockResolvedValue({ pass: false, reason: 'CONSENT_REVOKED' });
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp(), a);
    expect(res.body.decision).toBe('BLOCK');
    const e = await entryFor(a, before);
    expect(e.decision).toBe('BLOCK');
    expect(e.executionContext.stage).toBe('POLICY_ENFORCEMENT');
    expect(e.executionContext.reason).toBe(res.body.reason);
    // the policy engine reports no policy hash for a refusal; the entry records that explicitly, never a guess
    expectBound(e, a, { provider: null, policyHash: 'UNAVAILABLE' });
  });

  test('BE-03 a policy source that throws fails CLOSED (POLICY_BLOCKED), bound to the request; the provider is never called', async () => {
    const provider = jest.fn(() => Promise.resolve({ output: OUTPUT }));
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp({ provider, getPolicies: () => { throw new Error('policy store exploded'); } }), a);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'POLICY_BLOCKED' });
    expect(provider).not.toHaveBeenCalled();
    const e = await entryFor(a, before);
    expect(e).toMatchObject({ decision: 'BLOCK' });
    expect(e.executionContext).toMatchObject({ reason: 'POLICY_BLOCKED', stage: 'POLICY_ENFORCEMENT' });
    expectBound(e, a, { provider: null, policyHash: 'UNAVAILABLE' });
  });

  test('BE-04 SEMANTIC_POLICY: a request-side semantic block is bound to the request; the provider is never called', async () => {
    embeddingGate.checkText.mockImplementation(async (text) => (text === CHAT_BODY.prompt
      ? { blocks: true, reason: 'SEMANTIC_POLICY_VIOLATION', score: 0.99 } : { blocks: false }));
    const provider = jest.fn(() => Promise.resolve({ output: OUTPUT }));
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp({ provider }), a);
    expect(res.body.decision).toBe('BLOCK');
    expect(provider).not.toHaveBeenCalled();
    const e = await entryFor(a, before);
    expect(e.decision).toBe('BLOCK');
    expect(e.executionContext.stage).toBe('SEMANTIC_POLICY');
    expectBound(e, a, { provider: null });
  });

  test('BE-05 SEMANTIC_POLICY_OUTPUT: a blocked provider output is never delivered and the BLOCK is bound', async () => {
    embeddingGate.checkText.mockImplementation(async (text) => (text === OUTPUT
      ? { blocks: true, reason: 'SEMANTIC_POLICY_VIOLATION', score: 0.99 } : { blocks: false }));
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp(), a);
    expect(res.body.decision).toBe('BLOCK');
    expect(JSON.stringify(res.body)).not.toContain(OUTPUT);
    const e = await entryFor(a, before);
    expect(e.decision).toBe('BLOCK');
    expect(e.executionContext.stage).toBe('SEMANTIC_POLICY_OUTPUT');
    expectBound(e, a, { provider: 'openai' });
  });

  test('BE-06 PROVIDER_EXECUTION: a provider error is recorded with its code and the request binding', async () => {
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp({ provider: () => Promise.reject(Object.assign(new Error('upstream 502'), { code: 'PROVIDER_UPSTREAM_502' })) }), a);
    expect(res.status).toBeGreaterThanOrEqual(500);
    const e = await entryFor(a, before);
    expect(e.decision).toBe('BLOCK');
    expect(e.executionContext).toMatchObject({ stage: 'PROVIDER_EXECUTION', reason: 'PROVIDER_UPSTREAM_502' });
    expectBound(e, a, { provider: 'openai' });
  });

  test('BE-07 PROVIDER_EXECUTION_CANCELLED: a provider-reported cancellation is CANCELLED, never ALLOW', async () => {
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    await post(makeApp({ provider: () => Promise.reject(Object.assign(new Error('cancelled'), { code: 'PROVIDER_CANCELLED' })) }), a);
    const e = await entryFor(a, before);
    expect(e.decision).toBe('BLOCK');
    expect(e.executionContext).toMatchObject({ stage: 'PROVIDER_EXECUTION_CANCELLED', completionStatus: 'CANCELLED' });
    expectBound(e, a, { provider: 'openai' });
  });

  test('BE-08 control: an ALLOW entry carries the same binding', async () => {
    const a = buildArtifact();
    const before = (await getModernChain()).length;
    const res = await post(makeApp(), a);
    expect(res.body.decision).toBe('EXECUTE');
    const e = await entryFor(a, before);
    expect(e.decision).toBe('ALLOW');
    expectBound(e, a, { provider: 'openai' });
  });
});
