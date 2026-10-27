'use strict';

/**
 * safe cache for policy rule results.
 *   DC-01  same answers with and without the cache (differential, many contexts, all pure types)
 *   DC-02  a changed rule or policy set is never answered from the old entries
 *   DC-03  stateful rules are never cached (consent revocation, rate limit)
 *   DC-04  bounds, kill switch, errors not cached
 */

jest.mock('../../logger', () => { const a = jest.requireActual('../../logger'); return { ...a, emit: jest.fn(), blocked: jest.fn() }; });

const cache = require('../decisionCache');
const { evaluate } = require('../engine');
const { validateAndPrepare } = require('../loader');

const consent = { id: 'C', type: 'REQUIRE_CONSENT', priority: 100, enabled: true, config: { requireValidArtifact: true } };
const load = (policies) => validateAndPrepare({ policies: [consent, ...policies] }).filter((p) => p.type !== 'REQUIRE_CONSENT');
const mk = (o) => ({ priority: 10, enabled: true, ...o });
const SET = () => load([
  mk({ id: 'IP', type: 'BLOCK_IP', config: { blocklist: [], cidrs: ['10.0.0.0/8'] } }),
  mk({ id: 'TW', type: 'TIME_WINDOW', priority: 20, config: { allowedWindows: [{ days: ['MON','TUE','WED','THU','FRI','SAT','SUN'], start: '06:00', end: '20:00' }] } }),
  mk({ id: 'AB', type: 'ABAC', priority: 30, config: { abacFormat: 1, effect: 'DENY', reason: 'ABAC_X', when: { attr: 'tenant.id', op: 'eq', value: 'banned' } } }),
]);
const ctx = (o = {}) => ({ artifact: { valid: true }, userId: 'u', callerId: null, action: 'openai', tenantId: 'acme', requestId: 'r', ip: '1.2.3.4', timestamp: 1_800_000_000, ...o });
const strip = (d) => ({ decision: d.decision, reason: d.reason, policyId: d.policyId, path: d.evaluationPath.map((e) => [e.policyId, e.result, e.reason, e.ruleHash]) });

beforeEach(() => { cache._reset(); process.env.QODIQA_POLICY_DECISION_CACHE = 'true'; });
afterAll(() => { delete process.env.QODIQA_POLICY_DECISION_CACHE; });

describe('decision cache', () => {
  test('DC-01 identical to the uncached engine over many contexts, and it does hit', async () => {
    const set = SET(); const out = []; const ref = [];
    const contexts = [];
    for (const ip of ['1.2.3.4', '10.1.1.1']) for (const tenantId of ['acme', 'banned']) for (const ts of [1_800_000_000, 1_800_000_000 + 3600 * 12, 1_800_000_000 + 3600 * 20]) contexts.push(ctx({ ip, tenantId, timestamp: ts }));
    process.env.QODIQA_POLICY_DECISION_CACHE = 'false';
    for (const c of [...contexts, ...contexts]) ref.push(strip(await evaluate(c, set, null, {})));
    process.env.QODIQA_POLICY_DECISION_CACHE = 'true'; cache._reset();
    for (const c of [...contexts, ...contexts]) out.push(strip(await evaluate(c, set, null, {})));
    expect(out).toEqual(ref); expect(cache.stats().hits).toBeGreaterThan(0);
  });
  test('DC-02 a changed rule, a replaced policy set and a different context never reuse an old entry', async () => {
    const a = load([mk({ id: 'IP', type: 'BLOCK_IP', config: { blocklist: ['1.2.3.4'], cidrs: [] } })]);
    expect((await evaluate(ctx(), a, null, {})).decision).toBe('BLOCK'); expect((await evaluate(ctx(), a, null, {})).decision).toBe('BLOCK');
    const b = load([mk({ id: 'IP', type: 'BLOCK_IP', config: { blocklist: ['9.9.9.9'], cidrs: [] } })]);          // same id, edited rule
    expect((await evaluate(ctx(), b, null, {})).decision).toBe('EXECUTE');
    expect(cache.stats().invalidations).toBeGreaterThan(0);
    const c = load([mk({ id: 'IP', type: 'BLOCK_IP', config: { blocklist: ['1.2.3.4'], cidrs: [] }, enabled: false }), mk({ id: 'X', type: 'BLOCK_IP', config: { blocklist: ['7.7.7.7'], cidrs: [] } })]);
    expect((await evaluate(ctx(), c, null, {})).decision).toBe('EXECUTE');
    expect((await evaluate(ctx({ ip: '7.7.7.7' }), c, null, {})).decision).toBe('BLOCK');
  });
  test('DC-02b the operational mode is part of an ABAC key', async () => {
    const set = load([mk({ id: 'AB', type: 'ABAC', config: { abacFormat: 1, effect: 'DENY', reason: 'ABAC_X', when: { attr: 'ops.mode', op: 'eq', value: 'incident' } } })]);
    process.env.QODIQA_OPS_MODE = 'incident';
    try { expect((await evaluate(ctx(), set, null, {})).decision).toBe('BLOCK'); process.env.QODIQA_OPS_MODE = 'normal'; expect((await evaluate(ctx(), set, null, {})).decision).toBe('EXECUTE'); }
    finally { delete process.env.QODIQA_OPS_MODE; }
  });
  test('DC-03 consent and rate-limit rules are never cached', () => {
    expect([...cache.PURE].sort()).toEqual(['ABAC', 'BLOCK_IP', 'TIME_WINDOW']);
    let calls = 0; const ev = { evaluate: () => { calls++; return { pass: true }; } };
    for (const type of ['REQUIRE_CONSENT', 'RATE_LIMIT', 'DLP', 'UNKNOWN']) { cache.run({ type, config: {} }, 'h'.repeat(8), ev, ctx(), null); cache.run({ type, config: {} }, 'h'.repeat(8), ev, ctx(), null); }
    expect(calls).toBe(8);
  });
  test('DC-04 kill switch, no ruleHash, errors not cached, bounded', async () => {
    let calls = 0; const ev = { evaluate: () => { calls++; return { pass: true }; } }; const pol = { type: 'BLOCK_IP', config: {} };
    process.env.QODIQA_POLICY_DECISION_CACHE = 'false'; await cache.run(pol, 'hash', ev, ctx(), null); await cache.run(pol, 'hash', ev, ctx(), null); expect(calls).toBe(2);
    process.env.QODIQA_POLICY_DECISION_CACHE = 'true'; await cache.run(pol, null, ev, ctx(), null); await cache.run(pol, null, ev, ctx(), null); expect(calls).toBe(4);
    const bad = { evaluate: () => { throw new Error('x'); } }; expect(() => cache.run(pol, 'h2', bad, ctx(), null)).toThrow(); expect(cache.stats().size).toBe(0);
    delete process.env.QODIQA_POLICY_DECISION_CACHE; await cache.run(pol, 'dflt', ev, ctx(), null); await cache.run(pol, 'dflt', ev, ctx(), null); expect(calls).toBe(6);        // default OFF
    process.env.QODIQA_POLICY_DECISION_CACHE = 'true';
    for (let i = 0; i < cache.MAX_ENTRIES + 50; i++) await cache.run(pol, 'h3', ev, ctx({ timestamp: i }), null);
    expect(cache.stats().size).toBeLessThanOrEqual(cache.MAX_ENTRIES);
  });
});
