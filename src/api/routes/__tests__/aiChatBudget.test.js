'use strict';

jest.mock('../../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

/**
 * budgets on the real /ai/chat route.
 *   BC-01  a used-up request quota: 429, the provider not called
 *   BC-02  a request refused by ANOTHER rule never uses the budget
 *   BC-03  a provider failure returns the reservation
 *   BC-04  success settles the real usage (tokens) and accounts the cost in currency
 *   BC-05  a latency limit aborts a slow provider and returns the reservation
 */

jest.mock('../../../../services/logger', () => { const actual = jest.requireActual('../../../../services/logger'); return { ...actual, emit: jest.fn(actual.emit) }; });

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
const budget = require('../../../core/budget/budgetStage');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); process.env.QODIQA_DLP_TOKEN_KEY = 'b'.repeat(40); });
afterAll(() => { delete process.env.QODIQA_DLP_TOKEN_KEY; });
beforeEach(() => resetStats());

const consent = { id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
const PRICING = { currency: 'USD', inputPerMillionMicros: 2_000_000, outputPerMillionMicros: 8_000_000 };
const bud = (config, id = 'POL-BUDGET') => ({ id, type: 'BUDGET', priority: 50, enabled: true, config: { budgetFormat: 1, scope: 'tenant', period: 'day', ...config } });
const dlpBlock = { id: 'POL-DLP', type: 'DLP', priority: 10, enabled: true, config: { dlpFormat: 1, direction: 'input', action: 'BLOCK', rules: ['EMAIL'] } };

function make(rules, providerFn) {
  const store = createStore();
  const set = validateAndPrepare({ policies: [consent, ...rules] });
  const a = express(); a.use(attachClientIp); a.use(express.json());
  a.use('/ai/chat', createAiChatRouter({ _store: makeNonceStore(), _anomalyStore: makeOpenAnomalyStore(), _providerFn: providerFn, _getPolicies: () => set, _policyStore: store }));
  const post = (body) => {
    const now = Date.now();
    const art = signBoundArtifact({ method: 'POST', path: '/ai/chat', body }, { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
    return supertest(a).post('/ai/chat').set('x-qodiqa-artifact', Buffer.from(JSON.stringify(art)).toString('base64')).send(body);
  };
  const used = async () => (await budget.status(set, { store, tenantId: 'default', callerId: null, userId: null })).reduce((o, x) => ({ ...o, [x.metric]: x.used }), {});
  return { post, used, set };
}
const ok = (usage) => jest.fn(async () => ({ output: 'fine', model: 'gpt-4', tokenUsage: usage, executionMetadata: { responseId: 'r1' } }));

// Deterministic latency clock. The route arms the budget's latency limit with AbortSignal.timeout(maxLatencyMs)
// BEFORE the INTENT write and the dispatch, so with a real timer a loaded machine could expire it before dispatch (the
// request is then refunded as never dispatched) instead of after it - the case under test. The test owns this clock:
// every AbortSignal.timeout(limitMs) returns a signal that expires only when the test calls expire().
function latencyClock(limitMs) {
  const real = AbortSignal.timeout.bind(AbortSignal);
  const armed = [];
  const spy = jest.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
    if (ms !== limitMs) return real(ms);
    const c = new AbortController(); armed.push(c); return c.signal;
  });
  const expire = () => { const c = armed.shift(); if (!c) throw new Error('no latency timer armed'); c.abort(new DOMException('The operation was aborted due to timeout', 'TimeoutError')); };
  return { spy, expire, restore: () => spy.mockRestore() };
}

describe('budgets on /ai/chat', () => {
  test('BC-01 a used-up request quota answers 429 and the provider is not called', async () => {
    const p = ok({ inputTokens: 10, outputTokens: 5 }); const { post } = make([bud({ limits: { requests: 2 } })], p);
    expect((await post({ prompt: 'hello one', model: 'gpt-4' })).body.decision).toBe('EXECUTE');
    expect((await post({ prompt: 'hello two', model: 'gpt-4' })).body.decision).toBe('EXECUTE');
    const r = await post({ prompt: 'hello three', model: 'gpt-4' });
    expect(r.status).toBe(429); expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'BUDGET_EXCEEDED_REQUESTS' }); expect(r.body.details.budget.policyId).toBe('POL-BUDGET');
    expect(p).toHaveBeenCalledTimes(2);
  });
  test('BC-02 a request refused by another rule never uses the budget', async () => {
    const p = ok(null); const { post, used } = make([dlpBlock, bud({ limits: { requests: 5, tokens: 5000 } })], p);
    const r = await post({ prompt: 'write to jane.roe@example.org', model: 'gpt-4' });
    expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_BLOCKED' }); expect(await used()).toMatchObject({ requests: 0, tokens: 0 }); expect(p).not.toHaveBeenCalled();
  });
  test('BC-03 a provider failure returns the reservation', async () => {
    const failing = jest.fn(async () => { throw Object.assign(new Error('boom'), { code: 'PROVIDER_ERROR' }); });
    const { post, used } = make([bud({ limits: { requests: 5, tokens: 5000 } })], failing);
    const r = await post({ prompt: 'hello there', model: 'gpt-4' });
    expect(r.body.decision).not.toBe('EXECUTE'); expect(failing).toHaveBeenCalled();
    expect(await used()).toMatchObject({ requests: 0, tokens: 0 });
  });
  test('BC-04 success settles the real usage and accounts the cost', async () => {
    const { emit } = require('../../../../services/logger'); const spy = emit; spy.mockClear();
    const { post, used } = make([bud({ limits: { tokens: 100_000, costMicros: 1_000_000 }, pricing: PRICING })], ok({ inputTokens: 1000, outputTokens: 500 }));
    const r = await post({ prompt: 'hello there', model: 'gpt-4' });
    expect(r.body.decision).toBe('EXECUTE');
    expect(await used()).toMatchObject({ tokens: 1500, cost: 6000 });                              // 1000 in * $2/M + 500 out * $8/M = 6,000 micros ($0.006)
    const ev = spy.mock.calls.find((c) => c[1] === 'COST_ACCOUNTED');
    expect(ev && ev[2]).toMatchObject({ model: 'gpt-4', inputTokens: 1000, outputTokens: 500, costMicros: 6000, currency: 'USD', estimated: false });
  });
  test('BC-05 a latency limit aborts a slow provider and the call stays charged (it was dispatched)', async () => {
    const clock = latencyClock(50);
    try {
      // the provider is dispatched, then the 50 ms limit expires; the provider itself never answers until released after the response
      let answered = false; const release = [];
      const slow = jest.fn((_a, _b) => { clock.expire(); return new Promise((resolve) => release.push(() => { answered = true; resolve({ output: 'late', model: 'gpt-4' }); })); });
      const { post, used } = make([bud({ limits: { requests: 5 }, perRequest: { maxLatencyMs: 50 } })], slow);
      const r = await post({ prompt: 'hello there', model: 'gpt-4' });
      expect(clock.spy).toHaveBeenCalledWith(50);                                                   // the policy's limit arms the timer
      expect(slow).toHaveBeenCalledTimes(1);
      expect(answered).toBe(false); expect(r.body.decision).not.toBe('EXECUTE');                   // the limit, not the slow provider, ended the request
      expect(await used()).toMatchObject({ requests: 1 });                                          // F8V-03: not a free retry
      release.forEach((f) => f());
    } finally { clock.restore(); }
  });
});
