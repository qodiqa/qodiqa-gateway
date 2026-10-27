'use strict';

/**
 * cost accounting with tariffs and the provider comparison.
 *   CA-01  account(): cost from the reported tokens and the ROUTING tariff; nothing invented without usage or tariff; metrics move
 *   CA-02  compare(): estimated cost, health, load, weights, unknown = worst, degraded last, mixed currencies flagged
 *   CA-03  the compare endpoint (validation, permissions)
 */

jest.mock('../../../../services/logger', () => { const a = jest.requireActual('../../../../services/logger'); return { ...a, emit: jest.fn() }; });

process.env.OPENAI_API_KEY = require('../../../../test/helpers/providerFixtureKeys').PROVIDER_FIXTURE_KEYS.openai;
process.env.LOCAL_BASE_URL = 'http://127.0.0.1:11434/v1';

const express = require('express');
const supertest = require('supertest');
const acct = require('../costAccounting');
const metrics = require('../../../observability/metrics');
const providerHealth = require('../../../../services/providers/providerHealth');
const providerLoad = require('../../../../services/providers/providerLoad');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { createProvidersAdminRouter } = require('../../../api/routes/admin/providers');

const consent = { id: 'C', type: 'REQUIRE_CONSENT', priority: 1, enabled: true, config: { requireValidArtifact: true } };
const price = (i, o, currency = 'USD') => ({ currency, inputPerMillionMicros: i, outputPerMillionMicros: o });
const rule = (pricing, id = 'R') => ({ id, type: 'ROUTING', priority: 20, enabled: true, config: { routingFormat: 1, strategy: 'ordered', candidates: [{ provider: 'openai' }, { provider: 'local' }], pricing } });
const load = (...r) => validateAndPrepare({ policies: [consent, ...r] });

beforeEach(() => { providerHealth.resetAll(); providerLoad.resetAll(); });

describe('accounting', () => {
  test('CA-01', () => {
    const p = load(rule({ openai: price(2_000_000, 8_000_000) }));
    const r = acct.account({ policies: p, provider: 'openai', model: 'gpt-4o', tokenUsage: { inputTokens: 1000, outputTokens: 500 } });
    expect(r).toEqual({ costMicros: 6000, currency: 'USD', ruleId: 'R' });                     // 1000*$2/M + 500*$8/M = $0.006
    const total = [...metrics.providerCostMicrosTotal._values.entries()].find(([k]) => k.includes('openai'));
    expect(total && total[1]).toBeGreaterThanOrEqual(6000);
    expect([...metrics.providerTokensTotal._values.keys()].some((k) => k.includes('openai') && k.includes('input'))).toBe(true);
    expect(acct.account({ policies: p, provider: 'local', model: 'm', tokenUsage: { inputTokens: 1, outputTokens: 1 } })).toBeNull();            // no tariff for local
    expect(acct.account({ policies: p, provider: 'openai', model: 'm', tokenUsage: null })).toBeNull();                                          // nothing reported
    expect(acct.account({ policies: p, provider: 'openai', model: 'm', tokenUsage: { inputTokens: 5, outputTokens: null } })).toBeNull();
    const byModel = load(rule({ openai: { ...price(1_000_000, 1_000_000), byModel: { 'gpt-4o': { inputPerMillionMicros: 10_000_000, outputPerMillionMicros: 10_000_000 } } } }));
    expect(acct.account({ policies: byModel, provider: 'openai', model: 'gpt-4o', tokenUsage: { inputTokens: 100, outputTokens: 100 } }).costMicros).toBe(2000);
    expect(acct.account({ policies: byModel, provider: 'openai', model: 'other', tokenUsage: { inputTokens: 100, outputTokens: 100 } }).costMicros).toBe(200);
  });
});

describe('comparison', () => {
  const names = ['openai', 'local'];
  test('CA-02', () => {
    const p = load(rule({ openai: price(5_000_000, 15_000_000), local: price(0, 0) }));
    providerHealth.recordOutcome('openai', { ok: true, latencyMs: 900 }); providerHealth.recordOutcome('local', { ok: true, latencyMs: 300 });
    const end = providerLoad.begin('openai');
    const c = acct.compare({ policies: p, names, inputTokens: 1000, outputTokens: 1000 });
    end();
    const by = Object.fromEntries(c.providers.map((r) => [r.provider, r]));
    expect(by.openai).toMatchObject({ estimatedCostMicros: 20000, currency: 'USD', avgLatencyMs: 900, inFlight: 1, degraded: false });
    expect(by.local).toMatchObject({ estimatedCostMicros: 0, avgLatencyMs: 300, inFlight: 0 });
    expect(c.ranked).toEqual(['local', 'openai']);
    expect(acct.compare({ policies: p, names, inputTokens: 1, outputTokens: 1, weights: { cost: 0, latency: 1, failure: 0 } }).ranked[0]).toBe('local');
    expect(() => acct.compare({ policies: p, names, inputTokens: 1, outputTokens: 1, weights: { cost: -1 } })).toThrow(RangeError);
    // unknown price scores the worst value: an unpriced provider does not win on cost
    const onlyOne = acct.compare({ policies: load(rule({ openai: price(1, 1) })), names, inputTokens: 1000, outputTokens: 1000, weights: { cost: 1, latency: 0, failure: 0 } });
    expect(onlyOne.ranked[0]).toBe('openai');
    // mixed currencies are flagged (their costs are not comparable)
    expect(() => load(rule({ openai: price(1, 1, 'USD'), local: price(1, 1, 'EUR') }))).toThrow(/one currency/);       // one rule prices in one currency
    expect(acct.compare({ policies: load(rule({ openai: price(1, 1, 'USD') }), rule({ local: price(1, 1, 'EUR') }, 'R2')), names, inputTokens: 1, outputTokens: 1 }).mixedCurrencies).toBe(true);     // two rules may differ: flagged
    // a degraded provider is ranked last whatever its score
    for (let i = 0; i < 8; i++) providerHealth.recordOutcome('local', { ok: false, timedOut: true, latencyMs: 9000 });
    expect(acct.compare({ policies: p, names, inputTokens: 1000, outputTokens: 1000 }).ranked).toEqual(['openai', 'local']);
    // an explicit list restricts, an unknown name is dropped
    expect(acct.compare({ policies: p, providers: ['openai', 'nope'], names, inputTokens: 1, outputTokens: 1 }).providers.map((r) => r.provider)).toEqual(['openai']);
  });
});

describe('compare endpoint', () => {
  const app = express(); app.use(express.json());
  app.use('/v1/admin/providers', createProvidersAdminRouter({ requirePermission: (perm) => (req, res, next) => (req.headers['x-deny'] === perm ? res.status(403).json({}) : next()),
    getPolicies: () => load(rule({ openai: price(1_000_000, 1_000_000), local: price(0, 0) })) }));
  test('CA-03', async () => {
    const ok = await supertest(app).post('/v1/admin/providers/compare').send({ inputTokens: 1000, outputTokens: 1000 });
    expect(ok.status).toBe(200); expect(ok.body.data.ranked).toEqual(expect.arrayContaining(['openai', 'local']));
    for (const bad of [{}, { inputTokens: -1, outputTokens: 1 }, { inputTokens: 1.5, outputTokens: 1 }, { inputTokens: 1, outputTokens: 1, providers: 'x' }, { inputTokens: 1, outputTokens: 1, weights: { cost: 'a' } }]) {
      expect((await supertest(app).post('/v1/admin/providers/compare').send(bad)).status).toBe(400);
    }
    expect((await supertest(app).post('/v1/admin/providers/compare').set('x-deny', 'READ_PROVIDERS').send({ inputTokens: 1, outputTokens: 1 })).status).toBe(403);
  });
});
