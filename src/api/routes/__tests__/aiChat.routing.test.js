'use strict';
const { PROVIDER_FIXTURE_KEYS } = require('../../../../test/helpers/providerFixtureKeys');

/**
 * policy routing through the REAL /ai/chat route, the REAL provider router and the REAL failover authoriser (only the two adapters, consent and the audit sink are doubles).
 *   RT-01  a ROUTING rule sends the request to another candidate; evidence records requested vs executing provider and the decision
 *   RT-02  no consent for the candidate -> skipped (reason recorded), the requested provider serves
 *   RT-03  the signing identity's provider scope excludes the candidate -> skipped
 *   RT-04  model replacement: fill keeps the request's model, override replaces it
 *   RT-05  cheapest chooses by the rule's tariff
 *   RT-06  a `when` condition that is false leaves the request alone
 *   RT-07  data-class / ABAC rules are evaluated FOR the routed target (a DENY on that provider skips it)
 *   RT-08  the budget is charged for the provider and model that really serve the request
 */

const mockConsent = { allowed: new Set(['openai', 'local']) };
jest.mock('../../../core/consent', () => ({
  verify: jest.fn(async ({ action }) => (mockConsent.allowed.has(action) ? { pass: true, reason: 'ACTIVE' } : { pass: false, reason: 'NO_CONSENT' })),
}));
const mockAudit = [];
const mockFlags = { failIntent: false };
jest.mock('../../../core/audit/audit-log', () => ({
  appendMandatory: async (entry) => { if (mockFlags.failIntent && entry.entryType === 'INTENT') throw Object.assign(new Error('audit down'), { code: 'AUDIT_APPEND_FAILED' }); mockAudit.push(entry); return { hash: `h${mockAudit.length}` }; },
  append: async (entry) => { mockAudit.push(entry); return { hash: `h${mockAudit.length}` }; },
  alreadyExecuted: () => false,
}));
jest.mock('../../../../services/providers/openai', () => ({ callOpenAI: jest.fn() }));
jest.mock('../../../../services/providers/local', () => ({ callLocal: jest.fn() }));
jest.mock('../../../../services/providers/local.stream', () => ({ callLocalStream: jest.fn() }));
jest.mock('../../../../services/providers/openai.stream', () => ({ callOpenAIStream: jest.fn() }));

process.env.QODIQA_CLIENT_ID = 'default';
process.env.OPENAI_API_KEY = PROVIDER_FIXTURE_KEYS.openai;
process.env.LOCAL_BASE_URL = 'http://127.0.0.1:11434/v1';

const request = require('supertest');
const express = require('express');
const createSignRouter = require('../sign');
const createAiChatRouter = require('../aiChat');
const attachClientIp = require('../../../../middleware/clientIp');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore } = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const signingIdentityStore = require('../../../core/signing/signingIdentityStore');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { callOpenAI } = require('../../../../services/providers/openai');
const { callLocal } = require('../../../../services/providers/local');
const budget = require('../../../core/budget/budgetStage');

const { apiKey: SIGN_TOKEN, identityId } = provisionTestSigningIdentity({ tenantId: 'default' });
const consent = { id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } };
const routing = (cfg, id = 'POL-ROUTE') => ({ id, type: 'ROUTING', priority: 20, enabled: true, config: { routingFormat: 1, strategy: 'ordered', candidates: [{ provider: 'local' }, { provider: 'openai' }], ...cfg } });

function makeApp(rules) {
  const policies = validateAndPrepare({ policies: [consent, ...rules] });
  const store = createStore();
  const app = express(); app.use(attachClientIp); app.use(express.json());
  app.use('/sign', createSignRouter(() => policies));
  app.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _getPolicies: () => policies, _policyStore: store }));
  return { app, policies, store };
}
async function chat(app, body = { prompt: 'Hello', model: 'gpt-4o-mini' }) {
  const s = await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_TOKEN}`).send({ request: { method: 'POST', path: '/ai/chat', body }, payload: { provider: 'openai' } });
  expect(s.status).toBe(200);
  return request(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(s.body.artifact)).toString('base64')).send(body);
}
const lastCtx = () => mockAudit[mockAudit.length - 1].executionContext;
const ok = (provider) => ({ output: `from ${provider}`, provider, model: 'm', tokenUsage: { inputTokens: 10, outputTokens: 5, totalTokens: 15 }, executionMetadata: { responseId: `r-${provider}` } });

beforeEach(() => {
  mockAudit.length = 0; mockFlags.failIntent = false; mockConsent.allowed = new Set(['openai', 'local']);
  callOpenAI.mockReset().mockResolvedValue(ok('openai')); callLocal.mockReset().mockResolvedValue(ok('local'));
});
afterEach(async () => { await signingIdentityStore.updateSigningIdentity(identityId, { allowedProviders: null, enabled: true }); });

describe('policy routing', () => {
  test('RT-01 the request is routed to the first authorised candidate; the evidence says why', async () => {
    const { app } = makeApp([routing({})]);
    const res = await chat(app);
    expect(res.body.decision).toBe('EXECUTE'); expect(res.body.response).toBe('from local');
    expect(callLocal).toHaveBeenCalledTimes(1); expect(callOpenAI).not.toHaveBeenCalled();
    expect(lastCtx()).toMatchObject({ provider: 'openai', requestedProvider: 'openai', executingProvider: 'local' });
    expect(lastCtx().routed).toMatchObject({ ruleId: 'POL-ROUTE', strategy: 'ordered', from: 'openai', to: 'local', order: ['local', 'openai'], skipped: [] });
  });
  test('RT-02 no consent for the candidate: it is skipped with the reason and the requested provider serves', async () => {
    mockConsent.allowed = new Set(['openai']);
    const { app } = makeApp([routing({})]);
    const res = await chat(app);
    expect(res.body.response).toBe('from openai'); expect(callLocal).not.toHaveBeenCalled();
    expect(lastCtx().routed).toMatchObject({ to: 'openai', skipped: [{ provider: 'local', reason: 'NO_CONSENT' }] });
  });
  test('RT-03 the identity scope excludes the candidate', async () => {
    await signingIdentityStore.updateSigningIdentity(identityId, { allowedProviders: ['openai'] });
    const { app } = makeApp([routing({})]);
    const res = await chat(app);
    expect(res.body.response).toBe('from openai'); expect(lastCtx().routed.skipped).toEqual([{ provider: 'local', reason: 'SCOPE_PROVIDER_DENIED' }]);
  });
  test('RT-04 model mode: fill keeps the request model, override replaces it (and says so)', async () => {
    let r = await chat(makeApp([routing({ candidates: [{ provider: 'local', model: 'llama-tiny' }] })]).app);
    expect(callLocal.mock.calls[0][0].model).toBe('gpt-4o-mini'); expect(lastCtx().routed).toMatchObject({ to: 'local', modelFrom: 'gpt-4o-mini', modelTo: 'gpt-4o-mini' });
    callLocal.mockClear(); mockAudit.length = 0;
    r = await chat(makeApp([routing({ modelMode: 'override', candidates: [{ provider: 'local', model: 'llama-tiny' }] })]).app);
    expect(r.body.decision).toBe('EXECUTE'); expect(callLocal.mock.calls[0][0].model).toBe('llama-tiny');
    expect(lastCtx().routed).toMatchObject({ to: 'local', modelFrom: 'gpt-4o-mini', modelTo: 'llama-tiny' });
    callLocal.mockClear(); mockAudit.length = 0;
    r = await chat(makeApp([routing({ candidates: [{ provider: 'local', model: 'llama-tiny' }] })]).app, { prompt: 'no model named' });
    expect(callLocal.mock.calls[0][0].model).toBe('llama-tiny');                         // fill: the request named none
  });
  test('RT-05 cheapest uses the rule tariff', async () => {
    const price = (inM, outM) => ({ currency: 'USD', inputPerMillionMicros: inM, outputPerMillionMicros: outM });
    await chat(makeApp([routing({ strategy: 'cheapest', candidates: [{ provider: 'openai' }, { provider: 'local' }], pricing: { openai: price(5_000_000, 15_000_000), local: price(0, 0) } })]).app);
    expect(callLocal).toHaveBeenCalledTimes(1); expect(callOpenAI).not.toHaveBeenCalled();
    callLocal.mockClear(); mockAudit.length = 0;
    await chat(makeApp([routing({ strategy: 'cheapest', candidates: [{ provider: 'local' }, { provider: 'openai' }], pricing: { openai: price(1, 1), local: price(9_000_000, 9_000_000) } })]).app);
    expect(callOpenAI).toHaveBeenCalledTimes(1); expect(callLocal).not.toHaveBeenCalled();
  });
  test('RT-06 a false `when` leaves the request on its own provider with no routing record', async () => {
    const { app } = makeApp([routing({ when: { attr: 'request.purpose', op: 'eq', value: 'support' } })]);
    const res = await chat(app);
    expect(res.body.response).toBe('from openai'); expect(lastCtx().routed).toBeUndefined();
  });
  test('RT-07 ABAC / data-class rules are evaluated for the routed target', async () => {
    const deny = { id: 'POL-NO-LOCAL', type: 'ABAC', priority: 30, enabled: true, config: { abacFormat: 1, effect: 'DENY', reason: 'NO_LOCAL', when: { attr: 'request.provider', op: 'eq', value: 'local' } } };
    const { app } = makeApp([routing({}), deny]);
    const res = await chat(app);
    expect(res.body.response).toBe('from openai'); expect(callLocal).not.toHaveBeenCalled();
    expect(lastCtx().routed.skipped).toEqual([{ provider: 'local', reason: 'ABAC_NO_LOCAL' }]);
  });
  test('RT-08 the budget applies to the provider/model that really serves the request', async () => {
    const bud = { id: 'POL-BUD', type: 'BUDGET', priority: 50, enabled: true, config: { budgetFormat: 1, scope: 'tenant', period: 'day', models: ['llama-tiny'], limits: { requests: 1 } } };
    const { app } = makeApp([routing({ modelMode: 'override', candidates: [{ provider: 'local', model: 'llama-tiny' }] }), bud]);
    expect((await chat(app)).body.decision).toBe('EXECUTE');
    const second = await chat(app, { prompt: 'Hello again', model: 'gpt-4o-mini' });
    expect(second.body.reason).toBe('BUDGET_EXCEEDED_REQUESTS');                 // the original model (gpt-4o-mini) is not in the rule's list: only the routed one counts
    expect(budget.budgetPolicies).toBeDefined();
  });
});

describe('gate repairs (re-verification G-01..G-03)', () => {
  test('RT-09 G-01: a model-aware rule is judged on the model that will be SENT to the routed target (the candidate model, not an undefined one)', async () => {
    const def = 'llama-x';
    const deny = { id: 'POL-NO-LOCAL-MODEL', type: 'ABAC', priority: 30, enabled: true, config: { abacFormat: 1, effect: 'DENY', reason: 'NO_LOCAL_DEF', when: { all: [{ attr: 'request.provider', op: 'eq', value: 'local' }, { attr: 'request.model', op: 'eq', value: def }] } } };
    const { app } = makeApp([routing({ candidates: [{ provider: 'local', model: 'llama-x' }, { provider: 'openai' }] }), deny]);
    const res = await chat(app, { prompt: 'no model named' });
    expect(res.body.response).toBe('from openai'); expect(callLocal).not.toHaveBeenCalled();
    expect(lastCtx().routed.skipped).toEqual([{ provider: 'local', reason: 'ABAC_NO_LOCAL_DEF' }]);
  });
  test('RT-10 G-02: a tool rule that was never preprocessed refuses; a request rule is not a tool rule', () => {
    const abac = require('../../../../services/policy/evaluators/abac');
    expect(abac.evaluateTool([{ id: 'T', type: 'ABAC', enabled: true, config: { abacFormat: 1, effect: 'DENY', reason: 'X', appliesTo: 'tool', when: { attr: 'tool.name', op: 'eq', value: 'x' } } }], {})).toMatchObject({ pass: false, reason: 'EVALUATOR_ERROR', policyId: 'T' });
    expect(abac.evaluateTool([{ id: 'R', type: 'ABAC', enabled: true, config: { _appliesTo: 'request' } }], {})).toEqual({ pass: true });
  });
  test('RT-11 G-03: a stream refused before dispatch returns its reservation', async () => {
    const bud = { id: 'POL-BUD2', type: 'BUDGET', priority: 50, enabled: true, config: { budgetFormat: 1, scope: 'tenant', period: 'day', limits: { requests: 5 } } };
    const { app, policies, store } = makeApp([bud]);
    mockFlags.failIntent = true;
    const body = { prompt: 'Hello', model: 'gpt-4o-mini', stream: true };
    const s = await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_TOKEN}`).send({ request: { method: 'POST', path: '/ai/chat', body }, payload: { provider: 'openai' } });
    const r = await request(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(s.body.artifact)).toString('base64')).send(body);
    expect(r.status).toBeGreaterThanOrEqual(500); expect(callOpenAI).not.toHaveBeenCalled();
    const used = await budget.status(policies, { store, tenantId: 'default', callerId: null, userId: null });
    expect(used.every((x) => x.used === 0)).toBe(true);
  });
  test('RT-12 A-03/A-05: an unpreprocessed BUDGET rule throws; prototype-chain attribute names and cidr on a non-IP attribute are refused', () => {
    expect(() => budget.keyFor({ id: 'B', config: { scope: 'tenant' } }, 'requests', { tenantId: 't' })).toThrow(/not preprocessed/);
    const cond = require('../../../../services/policy/abac/condition');
    for (const attr of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) expect(() => cond.validate({ attr, op: 'exists' })).toThrow(/unknown attribute/);
    expect(() => cond.validate({ attr: 'tenant.id', op: 'cidr', value: ['10.0.0.0/8'] })).toThrow(/cidr/);
    expect(() => cond.validate({ attr: 'env.ip', op: 'cidr', value: ['10.0.0.0/8'] })).not.toThrow();
  });
});

describe('gate round-2 repairs (N-01..N-04)', () => {
  test('RT-13 N-01: the failover authoriser is told the model the router will really send', async () => {
    const { authorizeFailover } = require('../../../../services/providers/failoverAuth');
    const seen = [];
    const meta = { authorizeFailover: async (target, info) => { seen.push({ target, info }); return { ok: true }; } };
    await authorizeFailover(meta, 'openai', 'local', { code: 'PROVIDER_UNAVAILABLE' }, { model: 'gpt-4o-mini', messages: [] });
    await authorizeFailover(meta, 'openai', 'local', { code: 'PROVIDER_UNAVAILABLE' }, { messages: [] });
    expect(seen.map((x) => x.info.model)).toEqual(['gpt-4o-mini', null]);
  });
  test('RT-14 N-03: a forged derived key on a stored row does not survive a failed preprocess', () => {
    const floor = require('../../../core/tenancy/tenantPolicyFloor');
    const bad = floor.preprocessEntry({ id: 'X', type: 'ABAC', priority: 1, enabled: true, config: { abacFormat: 1, effect: 'DENY', reason: 'X', when: null, _appliesTo: 'tool', _when: { forged: true } } });
    expect(bad.config._appliesTo).toBeUndefined(); expect(bad.config._when).toBeUndefined();
    const abac = require('../../../../services/policy/evaluators/abac');
    expect(abac.evaluateTool([bad], {})).toMatchObject({ pass: false, reason: 'EVALUATOR_ERROR' });
  });
});

describe('routing of streaming requests', () => {
  test('RT-15 a stream is routed too: the routed provider streams, the evidence names requested and executing provider and the rule', async () => {
    const { callLocalStream } = require('../../../../services/providers/local.stream');
    const { callOpenAIStream } = require('../../../../services/providers/openai.stream');
    callLocalStream.mockReset().mockImplementation(async function* gen() { yield { delta: 'he' }; yield { delta: 'llo' }; });
    callOpenAIStream.mockReset().mockImplementation(async function* gen() { yield { delta: 'openai' }; });
    const { app } = makeApp([routing({})]);
    const body = { prompt: 'Hello', model: 'gpt-4o-mini', stream: true };
    const s = await request(app).post('/sign').set('Authorization', `Bearer ${SIGN_TOKEN}`).send({ request: { method: 'POST', path: '/ai/chat', body }, payload: { provider: 'openai' } });
    const r = await request(app).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(s.body.artifact)).toString('base64')).send(body).buffer(true).parse((res, cb) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => cb(null, d)); });
    const text = String(r.body);
    expect(text).toContain('stream_started'); expect(text).toContain('"provider":"local"');
    expect(callLocalStream).toHaveBeenCalledTimes(1); expect(callOpenAIStream).not.toHaveBeenCalled();
    const decision = mockAudit.filter((e) => e.executionContext && e.executionContext.stage === 'PROVIDER_EXECUTION').pop();
    expect(decision.executionContext).toMatchObject({ provider: 'openai', requestedProvider: 'openai', executingProvider: 'local' });
    expect(decision.executionContext.routed).toMatchObject({ ruleId: 'POL-ROUTE', from: 'openai', to: 'local' });
    expect(decision.executingProvider).toBe('local');
  });
});
