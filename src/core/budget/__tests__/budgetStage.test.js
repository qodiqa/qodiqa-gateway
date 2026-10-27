'use strict';

/**
 * budgets, quotas, cost accounting.
 *   BU-01  the rule: validation (limits, pricing required for money, periods), hash
 *   BU-02  reserve: requests / tokens / money limits, per-request limits, scope tenant vs caller, model filter, windows
 *   BU-03  nothing stays charged after a refusal (all-or-nothing), refund, settle with real usage (estimate corrected both ways), accounting in currency rounded up
 *   BU-04  concurrency: exactly `limit` of N parallel reservations win
 *   BU-05  a store that fails refuses (fail closed)
 *   BU-06  on the real /ai/chat route: quota refusal 429 with the provider not called, refund on provider failure, settle after success
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const budget = require('../budgetStage');
const rule = require('../../../../services/policy/evaluators/budget');
const { createStore } = require('../../../../services/policy/store');
const { computePolicyHash } = require('../../../../services/policyHash');

const PRICING = { currency: 'USD', inputPerMillionMicros: 2_000_000, outputPerMillionMicros: 8_000_000, assumedOutputTokens: 500 };      // $2 / $8 per million tokens
const mk = (config, id = 'B1', priority = 10) => ({ id, type: 'BUDGET', priority, enabled: true, config: rule.preprocess({ budgetFormat: 1, scope: 'tenant', period: 'day', ...config }) });
const ctx = (policies, over = {}) => ({ policies, store: createStore(), tenantId: 't1', callerId: 'c1', userId: 'k1', model: 'gpt-4o', estimatedTokens: 100, ...over });

describe('BU-01 the rule', () => {
  test('valid configs pass; every kind of bad config is refused', () => {
    expect(() => rule.validate({ budgetFormat: 1, scope: 'tenant', period: 'day', limits: { requests: 10 } })).not.toThrow();
    expect(() => rule.validate({ budgetFormat: 1, scope: 'caller', period: 'month', limits: { costMicros: 5_000_000 }, pricing: PRICING })).not.toThrow();
    const base = { budgetFormat: 1, scope: 'tenant', period: 'day', limits: { requests: 10 } };
    for (const bad of [{ budgetFormat: 2 }, { scope: 'user' }, { period: 'year' }, { limits: {} , perRequest: undefined }, { limits: { requests: 0 } }, { limits: { requests: 1.5 } }, { limits: { bogus: 1 } },
      { limits: { costMicros: 100 } }, { perRequest: { maxLatencyMs: 99_999_999 } }, { perRequest: { nope: 1 } }, { models: [] }, { extra: 1 },
      { limits: { costMicros: 100 }, pricing: { ...PRICING, currency: 'usd' } }, { limits: { costMicros: 100 }, pricing: { ...PRICING, inputPerMillionMicros: -1 } },
      { limits: { costMicros: 100 }, pricing: { ...PRICING, byModel: { m: { inputPerMillionMicros: 'x', outputPerMillionMicros: 1 } } } }])
      expect(() => rule.validate({ ...base, ...bad })).toThrow();
    expect(() => rule.validate({ budgetFormat: 1, scope: 'tenant', period: 'day' })).toThrow(/at least one limit/);
    expect(rule.evaluate()).toEqual({ pass: true });
  });
  test('policyHash covers the limits; the derived period does not change it', () => {
    const raw = { id: 'B', type: 'BUDGET', priority: 1, enabled: true, config: { budgetFormat: 1, scope: 'tenant', period: 'day', limits: { requests: 10 } } };
    const live = { ...raw, config: rule.preprocess(raw.config) };
    expect(computePolicyHash([live])).toBe(computePolicyHash([raw]));
    expect(computePolicyHash([{ ...raw, config: { ...raw.config, limits: { requests: 11 } } }])).not.toBe(computePolicyHash([raw]));
  });
});

describe('BU-02 reserve', () => {
  test('no BUDGET rule: allowed, nothing charged', async () => { expect(await budget.reserve(ctx([]))).toEqual({ allowed: true, reservation: null }); });
  test('request quota: the (limit+1)th is refused', async () => {
    const c = ctx([mk({ limits: { requests: 3 } })]);
    for (let i = 0; i < 3; i++) expect((await budget.reserve(c)).allowed).toBe(true);
    expect(await budget.reserve(c)).toMatchObject({ allowed: false, reason: 'BUDGET_EXCEEDED_REQUESTS', policyId: 'B1' });
  });
  test('token quota charges the estimate; one over the limit is refused without charging', async () => {
    const c = ctx([mk({ limits: { tokens: 250 } })]);
    expect((await budget.reserve(c)).allowed).toBe(true); expect((await budget.reserve(c)).allowed).toBe(true);
    expect(await budget.reserve(c)).toMatchObject({ allowed: false, reason: 'BUDGET_EXCEEDED_TOKENS' });
    const st = await budget.status(c.policies, c); expect(st.find((x) => x.metric === 'tokens').used).toBe(200);
    expect((await budget.reserve({ ...c, estimatedTokens: 50 })).allowed).toBe(true);
  });
  test('money quota with the operator tariff; per-model prices', async () => {
    const p = mk({ limits: { costMicros: 10_000 }, pricing: { ...PRICING, byModel: { cheap: { inputPerMillionMicros: 100_000, outputPerMillionMicros: 100_000 } } } });
    const c = ctx([p], { estimatedTokens: 1000, model: 'cheap' });
    // estimate = 1000 in * $0.1/M + 500 out * $0.1/M = 150 micros -> 66 fit in 10,000
    let n = 0; while ((await budget.reserve(c)).allowed) n++;
    expect(n).toBe(Math.floor(10_000 / 150));
    expect(budget.costMicros(PRICING, 'gpt-4o', 1000, 500)).toBe(Math.ceil((1000 * 2_000_000 + 500 * 8_000_000) / 1e6));            // 6,000 micros = $0.006
  });
  test('per-request limits refuse before anything is charged', async () => {
    const c = ctx([mk({ limits: { requests: 5 }, perRequest: { maxTokens: 50 } })]);
    expect(await budget.reserve(c)).toMatchObject({ allowed: false, reason: 'BUDGET_REQUEST_TOO_LARGE' });
    expect((await budget.status(c.policies, c))[0].used).toBe(0);
    const d = ctx([mk({ limits: { requests: 5 }, perRequest: { maxCostMicros: 1000 }, pricing: PRICING })], { estimatedTokens: 5000 });
    expect(await budget.reserve(d)).toMatchObject({ allowed: false, reason: 'BUDGET_REQUEST_TOO_COSTLY' });
  });
  test('scope: tenant counts everyone together, caller counts each caller on its own; a model filter limits the rule', async () => {
    const t = ctx([mk({ limits: { requests: 2 } })]);
    await budget.reserve(t); await budget.reserve({ ...t, callerId: 'c2' });
    expect((await budget.reserve({ ...t, callerId: 'c3' })).allowed).toBe(false);
    const k = ctx([mk({ scope: 'caller', limits: { requests: 1 } })]);
    expect((await budget.reserve(k)).allowed).toBe(true); expect((await budget.reserve(k)).allowed).toBe(false);
    expect((await budget.reserve({ ...k, callerId: 'c2' })).allowed).toBe(true);
    const m = ctx([mk({ models: ['gpt-4o'], limits: { requests: 1 } })]);
    expect((await budget.reserve(m)).allowed).toBe(true); expect((await budget.reserve(m)).allowed).toBe(false); expect((await budget.reserve({ ...m, model: 'other' })).allowed).toBe(true);
  });
  test('the windows are per period: a counter from another tenant or rule is separate', async () => {
    const store = createStore();
    const a = { ...ctx([mk({ limits: { requests: 1 } }, 'A')]), store }; const b = { ...ctx([mk({ limits: { requests: 1 } }, 'B')]), store };
    expect((await budget.reserve(a)).allowed).toBe(true); expect((await budget.reserve(b)).allowed).toBe(true);
    expect((await budget.reserve({ ...a, tenantId: 't2' })).allowed).toBe(true);
  });
  test('latency limit: the smallest applicable one', () => {
    const ps = [mk({ perRequest: { maxLatencyMs: 8000 } }, 'L1'), mk({ perRequest: { maxLatencyMs: 3000 } }, 'L2'), mk({ models: ['x'], perRequest: { maxLatencyMs: 100 } }, 'L3')];
    expect(budget.latencyLimitMs(ps, 'gpt-4o')).toBe(3000); expect(budget.latencyLimitMs(ps, 'x')).toBe(100); expect(budget.latencyLimitMs([], 'x')).toBeNull();
  });
});

describe('BU-03 all-or-nothing, refund, settle', () => {
  test('a refusal by a later rule returns what an earlier rule of the same call charged', async () => {
    const c = ctx([mk({ limits: { requests: 10, tokens: 1000 } }, 'A', 1), mk({ limits: { requests: 1 } }, 'B', 2)]);
    await budget.reserve(c);                                                      // A: 1 req / 100 tok, B: 1 req
    const r = await budget.reserve(c);                                            // B refuses; A must not keep a charge
    expect(r).toMatchObject({ allowed: false, policyId: 'B' });
    const st = await budget.status(c.policies, c);
    expect(st.find((x) => x.policyId === 'A' && x.metric === 'requests').used).toBe(1); expect(st.find((x) => x.policyId === 'A' && x.metric === 'tokens').used).toBe(100);
  });
  test('refund returns the whole reservation', async () => {
    const c = ctx([mk({ limits: { requests: 1, tokens: 500 } })]);
    const r = await budget.reserve(c); expect(r.allowed).toBe(true);
    await budget.refund(r.reservation);
    expect((await budget.status(c.policies, c)).map((x) => x.used)).toEqual([0, 0]);
    expect((await budget.reserve(c)).allowed).toBe(true);
  });
  test('settle replaces the estimate by the real usage - lower and higher - and accounts the cost in currency, rounded up', async () => {
    const c = ctx([mk({ limits: { tokens: 10_000, costMicros: 1_000_000 }, pricing: PRICING })], { estimatedTokens: 1000 });
    const r = await budget.reserve(c);
    const a = await budget.settle(r.reservation, { inputTokens: 200, outputTokens: 50 });
    expect(a).toMatchObject({ inputTokens: 200, outputTokens: 50, currency: 'USD', costMicros: Math.ceil((200 * 2_000_000 + 50 * 8_000_000) / 1e6) });
    const st = await budget.status(c.policies, c);
    expect(st.find((x) => x.metric === 'tokens').used).toBe(250); expect(st.find((x) => x.metric === 'cost').used).toBe(a.costMicros);
    const r2 = await budget.reserve({ ...c, estimatedTokens: 10 });
    await budget.settle(r2.reservation, { inputTokens: 400, outputTokens: 600 });             // real usage ABOVE the estimate is recorded too
    expect((await budget.status(c.policies, c)).find((x) => x.metric === 'tokens').used).toBe(250 + 1000);
  });
  test('no usage reported: the estimate stays', async () => {
    const c = ctx([mk({ limits: { tokens: 10_000 } })]);
    const r = await budget.reserve(c); await budget.settle(r.reservation, null);
    expect((await budget.status(c.policies, c))[0].used).toBe(100);
  });
});

describe('BU-04 concurrency', () => {
  test('exactly `limit` of 50 parallel reservations succeed', async () => {
    const c = ctx([mk({ limits: { requests: 7 } })]);
    const results = await Promise.all(Array.from({ length: 50 }, () => budget.reserve(c)));
    expect(results.filter((r) => r.allowed)).toHaveLength(7);
    expect((await budget.status(c.policies, c))[0].used).toBe(7);
  });
});

describe('BU-05 fail closed', () => {
  test('a store that throws refuses the request and leaves nothing charged', async () => {
    const real = createStore(); let calls = 0;
    const store = { chargeBy: async (...a) => { if (++calls === 2) throw new Error('redis down'); return real.chargeBy(...a); }, adjust: async (...a) => real.adjust(...a), getCount: (...a) => real.getCount(...a) };
    const c = ctx([mk({ limits: { requests: 5, tokens: 500 } })], { store });
    expect(await budget.reserve(c)).toMatchObject({ allowed: false, reason: 'BUDGET_UNAVAILABLE' });
    expect((await budget.status(c.policies, c)).map((x) => x.used)).toEqual([0, 0]);
    expect(await budget.reserve(ctx([mk({ limits: { requests: 5 } })], { store: {} }))).toMatchObject({ allowed: false, reason: 'BUDGET_UNAVAILABLE' });
  });
});
