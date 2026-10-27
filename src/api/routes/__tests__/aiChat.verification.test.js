'use strict';

jest.mock('../../../core/consent', () => ({ verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }) }));

/**
 * repairs - regression tests for what the independent verification found.
 * a request without `model` is judged on the model the provider will be called with (budget model scope, ABAC request.model)
 * an ABAC rule that was not preprocessed fails closed
 * a latency abort after dispatch stays charged
 * tenant evaluation order is priority order
 * a BLOCK rule judges the original text even after a MASK rule
 * the token estimate is an upper bound for CJK
 * content normalisation and the cumulative regex work cap
 * budget keys carry the period
 * digits in a reason label are kept in the log
 */

const express = require('express');
const supertest = require('supertest');
const createAiChatRouter = require('../aiChat');
const attachClientIp = require('../../../../middleware/clientIp');
const { signBoundArtifact } = require('../../../validation/signBoundArtifact');
const { getActiveKey } = require('../../../../services/artifact/keyStore');
const { resetStats } = require('../../../../services/execution-guard');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createStore } = require('../../../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../../../testing/stores');
const { resolveDefaultModel } = require('../../../../services/providers/config');
const attrs = require('../../../../services/policy/abac/requestAttributes');
const abac = require('../../../../services/policy/evaluators/abac');
const contentStage = require('../../../core/content/contentStage');
const contentRule = require('../../../../services/policy/evaluators/contentRule');
const budget = require('../../../core/budget/budgetStage');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); process.env.QODIQA_DLP_TOKEN_KEY = 'b'.repeat(40); });
afterAll(() => { delete process.env.QODIQA_DLP_TOKEN_KEY; });
beforeEach(() => resetStats());

const consent = { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
function make(rules, providerFn) {
  const store = createStore(); const set = validateAndPrepare({ policies: [consent, ...rules] });
  const a = express(); a.use(attachClientIp); a.use(express.json());
  a.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn, _getPolicies: () => set, _policyStore: store }));
  const post = (body) => {
    const now = Date.now();
    const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
    return supertest(a).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(art)).toString('base64')).send(body);
  };
  return { post, store, set };
}
const ok = () => jest.fn(async () => ({ output: 'fine', model: 'm', tokenUsage: null, executionMetadata: { responseId: 'r' } }));
const DEF = resolveDefaultModel('openai');

describe('repairs', () => {
  test('a request without model is bound by rules that name the default model', async () => {
    const bud = { id: 'B', type: 'BUDGET', priority: 50, enabled: true, config: { budgetFormat: 1, scope: 'tenant', period: 'day', models: [DEF], limits: { requests: 1 } } };
    const m1 = make([bud], ok());
    expect((await m1.post({ prompt: 'hello one' })).body.decision).toBe('EXECUTE');
    expect((await m1.post({ prompt: 'hello two' })).body.reason).toBe('BUDGET_EXCEEDED_REQUESTS');
    const ab = { id: 'A', type: 'ABAC', priority: 30, enabled: true, config: { abacFormat: 1, effect: 'DENY', reason: 'NO_MODEL', when: { attr: 'request.model', op: 'eq', value: DEF } } };
    const m2 = make([ab], ok());
    expect((await m2.post({ prompt: 'hello', model: DEF })).body.reason).toBe('ABAC_NO_MODEL');
    expect((await m2.post({ prompt: 'hello' })).body.reason).toBe('ABAC_NO_MODEL');
    expect(attrs.effectiveModel({}, 'openai')).toBe(DEF); expect(attrs.effectiveModel({ model: 'x' }, 'openai')).toBe('x'); expect(attrs.effectiveModel({}, null)).toBeUndefined();
  });
  test('an ABAC rule that was not preprocessed throws (the engine reports EVALUATOR_ERROR) instead of passing', () => {
    expect(() => abac.evaluate({}, { effect: 'DENY', reason: 'X', when: {} })).toThrow(/preprocessed/);
    expect(abac.evaluate({}, { _appliesTo: 'tool' })).toEqual({ pass: true });
  });
  test('a latency abort after dispatch stays charged', async () => {
    const bud = { id: 'B', type: 'BUDGET', priority: 50, enabled: true, config: { budgetFormat: 1, scope: 'tenant', period: 'day', limits: { requests: 2 }, perRequest: { maxLatencyMs: 40 } } };
    // the test owns the latency clock. With a real 40 ms AbortSignal.timeout (armed before the INTENT write and the
    // dispatch) a loaded machine could expire it BEFORE dispatch: that request is refunded, yet the dispatch that follows it
    // still calls the provider, so the provider count and the charge diverged and the third request ran instead of being
    // refused. Here every call expires its limit exactly once, after dispatch, and the provider never answers.
    const real = AbortSignal.timeout.bind(AbortSignal); const armed = [];
    const spy = jest.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => { if (ms !== 40) return real(ms); const c = new AbortController(); armed.push(c); return c.signal; });
    try {
      const slow = jest.fn((_a, _b) => { armed.shift().abort(new DOMException('The operation was aborted due to timeout', 'TimeoutError')); return new Promise(() => {}); });
      const m = make([bud], slow);
      for (let i = 0; i < 2; i++) expect((await m.post({ prompt: `slow ${i}`, model: DEF })).body.decision).not.toBe('EXECUTE');
      expect(spy).toHaveBeenCalledWith(40);
      expect(slow).toHaveBeenCalledTimes(2);
      const third = await m.post({ prompt: 'slow 3', model: DEF });
      expect(third.body.reason).toBe('BUDGET_EXCEEDED_REQUESTS'); expect(slow).toHaveBeenCalledTimes(2);
    } finally { spy.mockRestore(); }
  });
  test('tenant sets are evaluated in priority order, ties by id, floor entries included', () => {
    jest.resetModules();
    jest.doMock('../../../core/policy/store', () => ({ listEnabledPolicies: () => [{ id: 'F-LOW', type: 'BLOCK_IP', priority: 1, config: { blocklist: [], cidrs: [] } }] }));
    const floor = require('../../../core/tenancy/tenantPolicyFloor');
    const mk = (id, priority) => ({ id, type: 'BLOCK_IP', priority, enabled: true, config: { blocklist: [], cidrs: [] } });
    expect(floor.mergeForEvaluation([mk('Z', 99), mk('B', 5), mk('A', 5)]).map((p) => p.id)).toEqual(['F-LOW', 'A', 'B', 'Z']);
    jest.dontMock('../../../core/policy/store'); jest.resetModules();
  });
  test('a BLOCK rule judges the original text even when a MASK rule runs first', async () => {
    const mask = { id: 'M', type: 'DLP', priority: 10, enabled: true, config: { dlpFormat: 1, direction: 'input', action: 'MASK', rules: ['EMAIL'] } };
    const block = { id: 'K', type: 'DLP', priority: 20, enabled: true, config: { dlpFormat: 1, direction: 'input', action: 'BLOCK', rules: ['EMAIL'] } };
    const p = ok(); const m = make([mask, block], p);
    const r = await m.post({ prompt: 'mail jane.roe@example.org now', model: DEF });
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_BLOCKED' }); expect(p).not.toHaveBeenCalled();
  });
  test('the token estimate does not undercount CJK or emoji', () => {
    expect(attrs.estimateTokens(['a'.repeat(300)])).toBe(100);
    expect(attrs.estimateTokens(['漢'.repeat(100)])).toBe(200); expect(attrs.estimateTokens(['\u{1F600}'.repeat(10)])).toBe(20);
  });
  test('normalisation catches blank letters and accents; the cumulative regex work is capped', () => {
    const mk = (cfg) => { const c = { contentFormat: 1, direction: 'input', action: 'BLOCK', ...cfg }; contentRule.validate(c); return [{ id: 'CR', type: 'CONTENT_RULE', priority: 1, enabled: true, config: contentRule.preprocess(c) }]; };
    const p = mk({ items: [{ id: 'a', kind: 'phrase', value: 'secret cafe' }] });
    expect(contentStage.check(['secret café'], p, 'input').blocked).toBe(true);
    expect(contentStage.check(['secㅤret c⠀afe'], p, 'input').blocked).toBe(true);
    const items = Array.from({ length: 60 }, (_, i) => ({ id: `r${i}`, kind: 'regex', value: `(a|b|c)+x${i}[0-9]{20}` }));
    expect(contentStage.check(['ab'.repeat(60_000)], mk({ items }), 'input')).toMatchObject({ blocked: true, reason: 'CONTENT_RULE_UNAVAILABLE' });
  });
  test('budget keys carry the period index', () => {
    const k = budget.keyFor({ id: 'B', config: { scope: 'tenant', _periodSeconds: 86400 } }, 'requests', { tenantId: 't' });
    expect(k).toMatch(/:requests:\d+$/);
  });
  test('digits in a reason label survive the log sanitiser', () => {
    const src = require('fs').readFileSync(require.resolve('../../../../services/policy/log'), 'utf8');
    expect(src).toMatch(/SAFE_REASON = \/\^\[A-Z0-9_\]/);
  });
});
