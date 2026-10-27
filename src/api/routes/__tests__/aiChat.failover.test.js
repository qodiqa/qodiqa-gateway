'use strict';
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys');

/**
 * provider failover through the REAL
 * /ai/chat route and the REAL provider router (only the two provider adapters,
 * consent and the audit sink are doubles).
 *
 *   FW-01  the target has no consent for this caller → failover refused; the target is never
 *          called; the primary failure is returned and the refusal is in the audit executionContext
 *   FW-02  consent for both → executes on the target; executionContext records
 *          requestedProvider=openai, executingProvider=local, failover {from,to,cause}
 *   FW-03  the identity's provider scope excludes the target → refused even with consent
 * FW-04 the identity is revoked after minting → refused before any provider call
 */

const mockConsent = { allowed: new Set(['openai', 'local']) };
jest.mock('../../../core/consent', () => ({
  verify: jest.fn(async ({ action }) => (mockConsent.allowed.has(action)
    ? { pass: true, reason: 'ACTIVE' } : { pass: false, reason: 'NO_CONSENT' })),
}));
const mockAudit = [];
jest.mock('../../../core/audit/audit-log', () => ({
  appendMandatory: async (entry) => { mockAudit.push(entry); return { hash: `h${mockAudit.length}` }; },
  append: async (entry) => { mockAudit.push(entry); return { hash: `h${mockAudit.length}` }; },
  alreadyExecuted: () => false,
}));
jest.mock('../../../../services/providers/openai', () => ({ callOpenAI: jest.fn() }));
jest.mock('../../../../services/providers/local', () => ({ callLocal: jest.fn() }));

process.env.QODIQA_CLIENT_ID = 'default';
process.env.OPENAI_API_KEY = PROVIDER_FIXTURE_KEYS.openai;
process.env.LOCAL_BASE_URL = 'http://127.0.0.1:11434/v1';
process.env.PROVIDER_FAILOVER_OPENAI = 'local';

const request = require('supertest');
const express = require('express');
const createSignRouter   = require('../sign');
const createAiChatRouter = require('../aiChat');
const attachClientIp     = require('../../../../middleware/clientIp');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore }        = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const signingIdentityStore = require('../../../core/signing/signingIdentityStore');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { callOpenAI } = require('../../../../services/providers/openai');
const { callLocal }  = require('../../../../services/providers/local');

const { apiKey: SIGN_TOKEN, identityId } = provisionTestSigningIdentity({ tenantId: 'default' });
const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });

function makeApp() {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/sign', createSignRouter(() => POLICIES));
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => POLICIES, _policyStore: createStore() }));
  return app;
}

async function chat(app) {
  const body = { prompt: 'Hello', model: 'gpt-4o-mini' };
  const s = await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_TOKEN}`).send({ request: { method: 'POST', path: '/ai/chat', body }, payload: { provider: 'openai' } });
  expect(s.status).toBe(200);
  return request(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(s.body.artifact)).toString('base64')).send(body);
}
const lastCtx = () => mockAudit[mockAudit.length - 1].executionContext;

beforeEach(() => {
  mockAudit.length = 0;
  mockConsent.allowed = new Set(['openai', 'local']);
  callOpenAI.mockReset().mockRejectedValue(Object.assign(new Error('unavailable'), { code: 'PROVIDER_UNAVAILABLE' }));
  callLocal.mockReset().mockResolvedValue({ output: 'from local', provider: 'local', model: 'gpt-4o-mini', tokenUsage: null, executionMetadata: { responseId: 'r-local' } });
});
afterEach(async () => {
  await signingIdentityStore.updateSigningIdentity(identityId, { allowedProviders: null, enabled: true });
});

describe('failover is re-authorized for the target provider', () => {
  test('FW-01 no consent for the target → refused; target never called; refusal audited', async () => {
    mockConsent.allowed = new Set(['openai']);
    const res = await chat(makeApp());
    expect(res.body.decision).not.toBe('EXECUTE');
    expect(callOpenAI).toHaveBeenCalledTimes(1);
    expect(callLocal).not.toHaveBeenCalled();
    expect(lastCtx()).toMatchObject({
      stage: 'PROVIDER_EXECUTION', reason: 'PROVIDER_UNAVAILABLE',
      requestedProvider: 'openai', executingProvider: null,
      failover: { from: 'openai', to: 'local', cause: 'PROVIDER_UNAVAILABLE', refused: 'NO_CONSENT' }, // the consent layer's own reason
    });
  });

  test('FW-02 consent for both → executes on the target; requested and executing provider recorded', async () => {
    const res = await chat(makeApp());
    expect(res.body.decision).toBe('EXECUTE');
    expect(callLocal).toHaveBeenCalledTimes(1);
    expect(lastCtx()).toMatchObject({
      stage: 'PROVIDER_EXECUTION', provider: 'openai',
      requestedProvider: 'openai', executingProvider: 'local',
      failover: { from: 'openai', to: 'local', cause: 'PROVIDER_UNAVAILABLE' },
    });
  });

  test('FW-03 the identity\'s provider scope excludes the target → refused even with consent', async () => {
    await signingIdentityStore.updateSigningIdentity(identityId, { allowedProviders: ['openai'] });
    const res = await chat(makeApp());
    expect(res.body.decision).not.toBe('EXECUTE');
    expect(callLocal).not.toHaveBeenCalled();
    expect(lastCtx().failover).toMatchObject({ to: 'local', refused: 'SCOPE_PROVIDER_DENIED' });
  });

  test('FW-04 a signing identity disabled after minting cannot execute at all (no provider called)', async () => {
    const app = makeApp();
    const body = { prompt: 'Hello', model: 'gpt-4o-mini' };
    const s = await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_TOKEN}`).send({ request: { method: 'POST', path: '/ai/chat', body }, payload: { provider: 'openai' } });
    await signingIdentityStore.updateSigningIdentity(identityId, { enabled: false });
    const res = await request(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(s.body.artifact)).toString('base64')).send(body);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'SIGNING_IDENTITY_REVOKED' });
    expect(callOpenAI).not.toHaveBeenCalled();
    expect(callLocal).not.toHaveBeenCalled();
  });
});
