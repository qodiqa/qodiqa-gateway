'use strict';

/**
 * residency and retention rules.
 *   DG-01  DATA_RESIDENCY: validation, the decision per provider, fail closed on an unknown region, hash covers the rule, derived fields do not change the hash
 *   DG-02  through the policy engine and the real loader (a rule that does not validate does not load)
 *   DG-03  DATA_RETENTION: bounds per category, platform-kept categories are refused, the plan for the audit engine, applyRetention with an injected writer
 *   DG-04  the inventory lists every category with where it lives
 */

const residency = require('../../../../services/policy/evaluators/dataResidency');
const retention = require('../../../../services/policy/evaluators/dataRetention');
const cats = require('../categories');
const { computePolicyHash } = require('../../../../services/policyHash');
const { validateAndPrepare } = require('../../../../services/policy/loader');
const { evaluate } = require('../../../../services/policy/engine');

const RES = { residencyFormat: 1, tenantRegion: 'eu', allowedRegions: ['eu', 'ch'], providerRegions: { local: 'eu', swiss: 'ch', openai: 'us' } };
const ctx = (action) => ({ artifact: { valid: true }, userId: 'u1', action, tenantId: 't1', requestId: '11111111-1111-4111-8111-111111111111', ip: '203.0.113.9', timestamp: Math.floor(Date.now() / 1000) });
const live = (c) => residency.preprocess(c);

describe('DG-01 DATA_RESIDENCY', () => {
  test('valid config passes; bad configs are refused', () => {
    expect(() => residency.validate(RES)).not.toThrow();
    for (const bad of [{ residencyFormat: 2 }, { tenantRegion: 'EU' }, { tenantRegion: undefined }, { allowedRegions: [] }, { allowedRegions: ['eu', 7] }, { providerRegions: {} }, { providerRegions: { a: 'EU' } },
      { providerRegions: { 'bad name': 'eu' } }, { providerRegions: ['eu'] }, { extra: 1 }])
      expect(() => residency.validate({ ...RES, ...bad })).toThrow();
    expect(() => residency.validate({ ...RES, providerRegions: JSON.parse('{"__proto__":"eu"}') })).toThrow();
  });
  test('decision per provider: allowed region passes, other region is a blocked cross-region transfer, unknown provider region is blocked (fail closed)', () => {
    const c = live(RES);
    expect(residency.evaluate(ctx('local'), c)).toEqual({ pass: true });
    expect(residency.evaluate(ctx('swiss'), c)).toEqual({ pass: true });
    expect(residency.evaluate(ctx('openai'), c)).toEqual({ pass: false, reason: 'RESIDENCY_CROSS_REGION_BLOCKED' });
    expect(residency.evaluate(ctx('mystery'), c)).toEqual({ pass: false, reason: 'RESIDENCY_PROVIDER_REGION_UNKNOWN' });
    expect(residency.evaluate({ ...ctx('x'), action: undefined }, c)).toEqual({ pass: false, reason: 'RESIDENCY_PROVIDER_UNKNOWN' });
  });
  test('allowedRegions defaults to the tenant region', () => {
    const c = live({ residencyFormat: 1, tenantRegion: 'eu', providerRegions: RES.providerRegions });
    expect(residency.evaluate(ctx('local'), c).pass).toBe(true); expect(residency.evaluate(ctx('swiss'), c).pass).toBe(false);
  });
  test('policyHash covers the rule; derived fields do not change it', () => {
    const r = { id: 'RES', type: 'DATA_RESIDENCY', priority: 5, enabled: true, config: RES };
    expect(computePolicyHash([{ ...r, config: live(RES) }])).toBe(computePolicyHash([r]));
    expect(computePolicyHash([{ ...r, config: { ...RES, allowedRegions: ['eu'] } }])).not.toBe(computePolicyHash([r]));
    expect(computePolicyHash([{ ...r, config: { ...RES, providerRegions: { ...RES.providerRegions, local: 'us' } } }])).not.toBe(computePolicyHash([r]));
  });
});

describe('DG-02 through the loader and the engine', () => {
  const consent = { id: 'C', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } };
  const doc = (config) => ({ policies: [consent, { id: 'RES', type: 'DATA_RESIDENCY', priority: 5, enabled: true, config }] });
  test('a valid rule loads and blocks a cross-region provider', async () => {
    const policies = validateAndPrepare(doc(RES)).filter((p) => p.type !== 'REQUIRE_CONSENT');          // the consent rule needs an artifact; this test is about residency
    const ok = await evaluate(ctx('local'), policies);
    expect(ok.decision).toBe('EXECUTE');
    const blocked = await evaluate(ctx('openai'), policies);
    expect(blocked).toMatchObject({ decision: 'BLOCK', reason: 'RESIDENCY_CROSS_REGION_BLOCKED', policyId: 'RES' });
    expect(await evaluate(ctx('mystery'), policies)).toMatchObject({ decision: 'BLOCK', reason: 'RESIDENCY_PROVIDER_REGION_UNKNOWN' });
  });
  test('an invalid rule does not load', () => {
    expect(() => validateAndPrepare(doc({ ...RES, tenantRegion: 'EU' }))).toThrow();
    expect(() => validateAndPrepare({ policies: [consent, { id: 'RET', type: 'DATA_RETENTION', priority: 5, enabled: true, config: { retentionFormat: 1, byCategory: { nope: 5 } } }] })).toThrow();
  });
});

describe('DG-03 DATA_RETENTION', () => {
  const rule = (by) => ({ retentionFormat: 1, byCategory: by });
  test('validation per category: bounds, indefinite only where allowed, platform categories refused, unknown categories refused', () => {
    expect(() => retention.validate(rule({ audit_security: 730, audit_operational: 90 }))).not.toThrow();
    expect(() => retention.validate(rule({ audit_security: 0 }))).not.toThrow();                          // keep
    for (const bad of [{ audit_operational: 0 }, { audit_operational: 5 }, { audit_operational: 9999 }, { audit_security: 100 }, { audit_security: 1.5 }, { audit_security: '730' },
      { audit_enforcement_chain: 30 }, { agent_action_ledger: 30 }, { dlp_events: 30 }, { nope: 30 }, { constructor: 30 }])
      expect(() => retention.validate(rule(bad))).toThrow();
    expect(() => retention.validate({ retentionFormat: 1, byCategory: {} })).toThrow();
    expect(() => retention.validate({ ...rule({ audit_security: 730 }), extra: 1 })).toThrow();
    expect(retention.evaluate()).toEqual({ pass: true });
  });
  test('the plan names the audit categories and the tenant; ENFORCEMENT is never in it', () => {
    const plan = cats.retentionPlan('t1', { audit_security: 730, audit_provider: 90 });
    expect(plan.map((p) => [p.eventCategory, p.retainDays, p.tenantId, p.name])).toEqual([['SECURITY', 730, 't1', 'tenant:t1:audit_security'], ['PROVIDER', 90, 't1', 'tenant:t1:audit_provider']]);
    expect(plan.every((p) => p.eventTypePattern === null)).toBe(true);
    expect(cats.names().map((n) => cats.CATEGORIES[n].auditCategory)).not.toContain('ENFORCEMENT');
  });
  test('applyRetention writes through the audit-retention engine and refuses an invalid rule before writing anything', async () => {
    const written = [];
    const r = await cats.applyRetention('t1', { audit_security: 730 }, { upsertPolicy: async (row) => { written.push(row); } });
    expect(written).toHaveLength(1); expect(written[0]).toMatchObject({ tenantId: 't1', eventCategory: 'SECURITY', retainDays: 730 }); expect(r.applied).toHaveLength(1);
    await expect(cats.applyRetention('t1', { audit_security: 730, audit_operational: 1 }, { upsertPolicy: async (row) => { written.push(row); } })).rejects.toThrow();
    expect(written).toHaveLength(1);
  });
});

describe('DG-04 inventory', () => {
  test('every category says what it contains, where it lives and who enforces it', () => {
    const inv = cats.inventory();
    expect(inv.length).toBeGreaterThanOrEqual(7);
    for (const c of inv) { expect(c.description).toBeTruthy(); expect(c.contains.length).toBeGreaterThan(0); expect(c.store).toBeTruthy(); expect(['audit-retention', 'platform']).toContain(c.engine); }
    expect(inv.find((c) => c.category === 'audit_enforcement_chain').engine).toBe('platform');
  });
});
