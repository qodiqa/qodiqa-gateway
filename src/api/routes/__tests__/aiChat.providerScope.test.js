'use strict';
// v7 (R-12 / R-14): audit appends pseudonymize consentProvenance.subject / callerContext.callerId, which needs
// PostgreSQL in production (fail-closed without it). This suite runs without a database, so it opts in to the
// EXPLICIT test-only pseudonym stand-in (test/helpers/subjectPseudonymMock.js).
jest.mock('../../../core/dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys');

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * /ai/chat:
 * the verifier re-checks the signing identity's allowedProviders on
 *          every alias (an artifact minted in scope cannot execute once the
 *          identity's scope excludes its provider);
 * the per-IP limiter (ai_chat_ip) runs BEFORE artifact decode: a flood
 *          without an artifact is throttled and never reaches the pre-auth
 *          reject path (let alone the audit chain).
 */

process.env.QODIQA_CLIENT_ID = 'default';
process.env.OPENAI_API_KEY = process.env.OPENAI_API_KEY || PROVIDER_FIXTURE_KEYS.openai;

const request = require('supertest');
const express = require('express');

const createSignRouter   = require('../sign');
const createAiChatRouter = require('../aiChat');
const attachClientIp     = require('../../../../middleware/clientIp');
const { getActiveKey, rotateKey } = require('../../../../services/artifact/keyStore');
const { validateAndPrepare }      = require('../../../../services/policy/loader');
const { createStore }             = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const signingIdentityStore        = require('../../../core/signing/signingIdentityStore');
const metrics                     = require('../../../observability/metrics');
const rl                          = require('../../../core/rateLimit');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

const { apiKey: SIGN_TOKEN, identityId } = provisionTestSigningIdentity({ tenantId: 'default' });

beforeAll(() => { try { getActiveKey('default'); } catch { rotateKey('default'); } });

const POLICIES = validateAndPrepare({ policies: [{ id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
const ALIASES = ['/ai/chat', '/v1/ai/chat', '/ai/chat/stream', '/v1/ai/chat/stream'];

function makeApp(providerFn) {
  const app = express();
  app.use(attachClientIp);
  app.use(express.json());
  app.use('/sign', createSignRouter(() => POLICIES));
  const chat = createAiChatRouter({
    _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => POLICIES,
    _policyStore: createStore(), _providerFn: providerFn,
  });
  for (const a of ALIASES) app.use(a, chat);
  return app;
}
const preAuthTotal = () => { let t = 0; for (const v of metrics.preAuthRejectsTotal._values.values()) t += v; return t; };

describe('verifier re-checks provider scope on every alias', () => {
  afterEach(() => { signingIdentityStore.updateSigningIdentity(identityId, { allowedProviders: null }); });

  test.each(ALIASES.filter((a) => !a.endsWith('/stream')))('%s: in-scope artifact executes; after the scope narrows it is BLOCKed (SCOPE_PROVIDER_DENIED) and the provider is never called', async (alias) => {
    const providerFn = jest.fn(() => Promise.resolve({ output: 'ok' }));
    const app = makeApp(providerFn);
    const body = { prompt: 'Hello' };
    const mint = async () => {
      const s = await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_TOKEN}`).send({ request: { method: 'POST', path: alias, body }, payload: { provider: 'openai' } });
      expect(s.status).toBe(200);
      return Buffer.from(JSON.stringify(s.body.artifact)).toString('base64');
    };
    const ok = await request(app).post(alias).set('x-qodiqa-artifact', await mint()).send(body);
    expect(ok.body.decision).toBe('EXECUTE');
    expect(providerFn).toHaveBeenCalledTimes(1);

    const art = await mint();
    signingIdentityStore.updateSigningIdentity(identityId, { allowedProviders: ['anthropic'] });
    const denied = await request(app).post(alias).set('x-qodiqa-artifact', art).send(body);
    expect(denied.body.decision).toBe('BLOCK');
    expect(denied.body.reason).toBe('SCOPE_PROVIDER_DENIED');
    expect(providerFn).toHaveBeenCalledTimes(1);
  });
});

describe('ai_chat_ip limits before artifact decode', () => {
  let saved;
  beforeEach(() => { saved = process.env.RL_ENABLED; process.env.RL_ENABLED = 'true'; rl._resetDegradedForTest(); });
  afterEach(() => { process.env.RL_ENABLED = saved; rl.loadConfig(); rl._resetDegradedForTest(); });

  test('a no-artifact flood is throttled (429) after the per-IP budget; throttled requests never reach pre-auth handling', async () => {
    rl.loadConfig({ surfaces: { ai_chat_ip: { maxRequests: 5, windowSeconds: 60, failMode: 'degrade' } } });
    const app = makeApp(() => Promise.resolve({ output: 'x' }));
    const before = preAuthTotal();
    const statuses = [];
    for (let i = 0; i < 12; i++) statuses.push((await request(app).post('/ai/chat').send({ prompt: 'x' })).status);
    expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]); // BLOCK MISSING_ARTIFACT (pre-auth)
    expect(statuses.slice(5).every((s) => s === 429)).toBe(true);
    expect(preAuthTotal() - before).toBe(5);
  });

  test('the per-IP budget is shared across aliases (one limiter, one key)', async () => {
    rl.loadConfig({ surfaces: { ai_chat_ip: { maxRequests: 4, windowSeconds: 60, failMode: 'degrade' } } });
    const app = makeApp(() => Promise.resolve({ output: 'x' }));
    const statuses = [];
    for (const a of [...ALIASES, ...ALIASES]) statuses.push((await request(app).post(a).send({ prompt: 'x' })).status);
    expect(statuses.filter((s) => s === 429).length).toBe(4);
  });
});
