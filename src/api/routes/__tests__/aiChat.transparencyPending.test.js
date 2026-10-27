'use strict';

/**
 * (D3) — /ai/chat with a PENDING transparency leaf.
 *
 * enforcementBridge.js resolves persisted:'pending' when the synchronous
 * registration failed on PostgreSQL persistence and the leaf was durably
 * queued (see enforcementBridge.pending.test.js for the bridge itself and
 * test/integration/transparencyQueue.integration.test.js for the real-PG outage).
 *
 * TP-01  ALLOW + pending → 200 EXECUTE (was 503), transparency.persisted
 *        'pending', entryHash/leafHash null, payloadHash present, proof ref
 * TP-02  ALLOW + pending → no fail-closed rejection, no CRITICAL
 * TP-03  ALLOW + bridge throws (nothing durable / signing) → still 503
 * TP-04  BLOCK + pending → 200 BLOCK unchanged, no CRITICAL
 */

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const mockRegisterDecision = jest.fn();
jest.mock('../../../core/transparency/enforcementBridge', () => ({
  registerEnforcementDecision: (...args) => mockRegisterDecision(...args),
}));

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...args) => mockEmit(...args) }));

const express   = require('express');
const supertest = require('supertest');

const createAiChatRouter    = require('../aiChat');
const attachClientIp        = require('../../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey }      = require('../../../../services/artifact/keyStore');
const { resetStats }        = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const metrics = require('../../../observability/metrics');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  resetStats();
  mockRegisterDecision.mockReset();
  mockEmit.mockClear();
  jest.spyOn(metrics.transparencyFailClosedRejectionsTotal, 'inc');
  jest.spyOn(metrics.transparencyEnforcementFailuresTotal, 'inc');
  jest.spyOn(metrics.transparencyEnforcementEntriesTotal, 'inc');
});
afterEach(() => {
  metrics.transparencyFailClosedRejectionsTotal.inc.mockRestore();
  metrics.transparencyEnforcementFailuresTotal.inc.mockRestore();
  metrics.transparencyEnforcementEntriesTotal.inc.mockRestore();
});

const MOCK_RESPONSE = 'Mock AI response';
function mockProvider() { return Promise.resolve({ output: MOCK_RESPONSE }); }

const CHAT_PATH = '/ai/chat';
const CHAT_BODY = { prompt: 'Hello, world!', model: 'gpt-4' };

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}
function buildArtifact(reqBody = CHAT_BODY, extraPayload = {}) {
  const req = { method: 'POST', path: CHAT_PATH, body: reqBody };
  return signBoundArtifact(req, freshEnvelope({ provider: 'openai', ...extraPayload }), KEY.privDer);
}
function toHeader(artifact) {
  return Buffer.from(JSON.stringify(artifact)).toString('base64');
}

const _DEFAULT_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });
const _DEFAULT_POLICY_STORE = createStore();

function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/ai/chat', createAiChatRouter({
    _store:        makeNonceStore(),
    _anomalyStore: makeOpenAnomalyStore(),
    _providerFn:   mockProvider,
    _getPolicies:  () => _DEFAULT_POLICIES,
    _policyStore:  _DEFAULT_POLICY_STORE,
  }));
  app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
  return app;
}

async function post(app, artifact, body = CHAT_BODY) {
  return supertest(app)
    .post('/ai/chat')
    .set('x-qodiqa-artifact', toHeader(artifact))
    .send(body);
}

const PENDING = {
  transparencyId: '0b0c3e2a-7c55-4b0f-9d43-6a2f5d9e1c01',
  payloadHash:    'c'.repeat(64),
  entryHash: null, signature: null, keyId: null, persisted: 'pending', row: null,
};

test('TP-01 ALLOW + pending → 200 EXECUTE with a pending transparency block', async () => {
  mockRegisterDecision.mockResolvedValue(PENDING);
  const res = await post(makeApp(), buildArtifact());
  expect(res.status).toBe(200);
  expect(res.body.decision).toBe('EXECUTE');
  expect(res.body.transparency).toEqual(expect.objectContaining({
    transparencyId:    PENDING.transparencyId,
    persisted:         'pending',
    entryHash:         null,
    leafHash:          null,
    payloadHash:       PENDING.payloadHash,
    merkleRoot:        null,
    inclusionProofRef: `/v1/transparency/proof/${PENDING.transparencyId}`, // R-18: versioned (public-allowlisted) path
  }));
});

test('TP-02 ALLOW + pending → no fail-closed rejection and no CRITICAL', async () => {
  mockRegisterDecision.mockResolvedValue(PENDING);
  await post(makeApp(), buildArtifact());
  expect(metrics.transparencyFailClosedRejectionsTotal.inc).not.toHaveBeenCalled();
  expect(mockEmit).not.toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_APPEND_FAILED', expect.anything());
  expect(metrics.transparencyEnforcementEntriesTotal.inc).toHaveBeenCalledWith({ decision: 'ALLOW' });
});

test('TP-03 ALLOW + the bridge throws (not durably recorded) → still fail-closed 503', async () => {
  mockRegisterDecision.mockRejectedValue(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }));
  const res = await post(makeApp(), buildArtifact());
  expect(res.status).toBe(503);
  expect(res.body.reason).toBe('TRANSPARENCY_PERSISTENCE_FAILED');
  expect(res.body).not.toHaveProperty('response');
});

test('TP-04 BLOCK + pending → 200 BLOCK, no CRITICAL', async () => {
  mockRegisterDecision.mockResolvedValue(PENDING);
  const res = await supertest(makeApp()).post('/ai/chat').send(CHAT_BODY);
  expect(res.status).toBe(200);
  expect(res.body.reason).toBe('MISSING_ARTIFACT');
  expect(mockEmit).not.toHaveBeenCalledWith('CRITICAL', 'TRANSPARENCY_APPEND_FAILED', expect.anything());
});
