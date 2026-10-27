'use strict';

/**
 * (residual) — the policy-layer tighten-only floor.
 * Pins the comparator per type, the clamp (present-but-non-compliant only),
 * and the evaluation-time union (floor ∪ tenant set, including the case a
 * tenant set never mentions REQUIRE_CONSENT at all).
 */

const FLOOR_FIXTURE = [
  { id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, config: { requireValidArtifact: true } },
  { id: 'FLOOR-BLOCK',   type: 'BLOCK_IP',         priority: 20, config: { blocklist: ['9.9.9.9'], cidrs: ['10.0.0.0/8'] } },
  { id: 'FLOOR-RATE',    type: 'RATE_LIMIT',       priority: 30, config: { windowSeconds: 60, maxRequests: 100 } },
  { id: 'FLOOR-WINDOW',  type: 'TIME_WINDOW',      priority: 40, config: { allowedWindows: [{ days: ['MON', 'TUE'], start: '09:00', end: '17:00' }] } },
];

let listEnabledPolicies;
let floor;

beforeEach(() => {
  jest.resetModules();
  listEnabledPolicies = jest.fn().mockReturnValue(FLOOR_FIXTURE);
  jest.doMock('../../policy/store', () => ({ listEnabledPolicies }));
  floor = require('../tenantPolicyFloor');
});

afterEach(() => jest.resetModules());

describe('tenantPolicyFloor', () => {
  test('getFloorPolicies/getFloorPolicy/isFloorPolicyId read the live global store', () => {
    expect(floor.getFloorPolicies()).toEqual(FLOOR_FIXTURE);
    expect(floor.getFloorPolicy('FLOOR-CONSENT')).toEqual(FLOOR_FIXTURE[0]);
    expect(floor.getFloorPolicy('NOPE')).toBeNull();
    expect(floor.isFloorPolicyId('FLOOR-RATE')).toBe(true);
    expect(floor.isFloorPolicyId('NOPE')).toBe(false);
  });

  describe('checkEntryAgainstFloor', () => {
    test('a non-floor id is always ok', () => {
      expect(floor.checkEntryAgainstFloor({ id: 'CUSTOM', type: 'BLOCK_IP', enabled: false, config: {} })).toEqual({ ok: true });
    });

    test('disabling a floor id is rejected, naming it', () => {
      const r = floor.checkEntryAgainstFloor({ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', enabled: false, config: { requireValidArtifact: true } });
      expect(r.ok).toBe(false);
      expect(r.floorPolicyId).toBe('FLOOR-CONSENT');
      expect(r.reason).toMatch(/FLOOR-CONSENT.*cannot be disabled/);
    });

    test('retyping a floor id is rejected', () => {
      const r = floor.checkEntryAgainstFloor({ id: 'FLOOR-CONSENT', type: 'BLOCK_IP', enabled: true, config: {} });
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/cannot be retyped/);
    });

    test('REQUIRE_CONSENT: requireValidArtifact !== true is a violation', () => {
      expect(floor.checkEntryAgainstFloor({ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', enabled: true, config: {} }).ok).toBe(false);
      expect(floor.checkEntryAgainstFloor({ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', enabled: true, config: { requireValidArtifact: true } }).ok).toBe(true);
    });

    test('BLOCK_IP: dropping a floor-blocked entry is a violation; a superset tightens', () => {
      expect(floor.checkEntryAgainstFloor({
        id: 'FLOOR-BLOCK', type: 'BLOCK_IP', enabled: true, config: { blocklist: [], cidrs: [] },
      }).ok).toBe(false);
      expect(floor.checkEntryAgainstFloor({
        id: 'FLOOR-BLOCK', type: 'BLOCK_IP', enabled: true,
        config: { blocklist: ['9.9.9.9', '1.2.3.4'], cidrs: ['10.0.0.0/8'] },
      }).ok).toBe(true);
    });

    test('RATE_LIMIT: a higher effective rate loosens; an equal or lower rate is fine', () => {
      expect(floor.checkEntryAgainstFloor({
        id: 'FLOOR-RATE', type: 'RATE_LIMIT', enabled: true, config: { windowSeconds: 60, maxRequests: 200 },
      }).ok).toBe(false); // 200/60 > 100/60
      expect(floor.checkEntryAgainstFloor({
        id: 'FLOOR-RATE', type: 'RATE_LIMIT', enabled: true, config: { windowSeconds: 60, maxRequests: 100 },
      }).ok).toBe(true); // equal rate
      expect(floor.checkEntryAgainstFloor({
        id: 'FLOOR-RATE', type: 'RATE_LIMIT', enabled: true, config: { windowSeconds: 120, maxRequests: 100 },
      }).ok).toBe(true); // same count, longer window — lower rate
    });

    test('TIME_WINDOW: a wider window loosens; a narrower or equal window is fine', () => {
      expect(floor.checkEntryAgainstFloor({
        id: 'FLOOR-WINDOW', type: 'TIME_WINDOW', enabled: true,
        config: { allowedWindows: [{ days: ['MON', 'TUE'], start: '08:00', end: '17:00' }] },
      }).ok).toBe(false); // starts earlier — wider
      expect(floor.checkEntryAgainstFloor({
        id: 'FLOOR-WINDOW', type: 'TIME_WINDOW', enabled: true,
        config: { allowedWindows: [{ days: ['MON', 'TUE'], start: '10:00', end: '15:00' }] },
      }).ok).toBe(true); // narrower
    });
  });

  describe('clampEntries — load-time defence', () => {
    test('a compliant stored set is returned unchanged, no changes reported', () => {
      const stored = [{ id: 'CUSTOM', type: 'BLOCK_IP', enabled: true, config: {} }];
      const { policies, changes } = floor.clampEntries(stored);
      expect(policies).toEqual(stored);
      expect(changes).toEqual([]);
    });

    test('a non-floor id is left alone even if it looks unsafe', () => {
      const stored = [{ id: 'CUSTOM', type: 'BLOCK_IP', enabled: false, config: {} }];
      const { policies, changes } = floor.clampEntries(stored);
      expect(policies).toEqual(stored);
      expect(changes).toEqual([]);
    });

    test('a disabled floor id is restored in place, reported in changes', () => {
      const stored = [{ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', enabled: false, config: { requireValidArtifact: true } }];
      const { policies, changes } = floor.clampEntries(stored);
      expect(policies).toEqual([{ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }]);
      expect(changes).toHaveLength(1);
      expect(changes[0]).toMatch(/FLOOR-CONSENT.*restored/);
    });

    test('a floor id simply absent from the stored set is NOT added — omission is not a stored violation', () => {
      const stored = [{ id: 'CUSTOM', type: 'BLOCK_IP', enabled: true, config: {} }];
      const { policies, changes } = floor.clampEntries(stored);
      expect(policies).toHaveLength(1);
      expect(changes).toEqual([]);
    });

    test('never throws on a non-array input', () => {
      expect(floor.clampEntries(null)).toEqual({ policies: [], changes: [] });
      expect(floor.clampEntries(undefined)).toEqual({ policies: [], changes: [] });
    });
  });

  describe('preprocessEntry — shared write/read boundary helper', () => {
    test('preprocesses a BLOCK_IP entry (Set-typed derived fields, policyId injected) and is idempotent', () => {
      const raw = { id: 'CUSTOM', type: 'BLOCK_IP', enabled: true, config: { blocklist: ['9.9.9.9'], cidrs: [] } };
      const once  = floor.preprocessEntry(raw);
      const twice = floor.preprocessEntry(once);
      expect(once.config._blocklistSet).toBeInstanceOf(Set);
      expect(once.config._blocklistSet.has('9.9.9.9')).toBe(true);
      expect(once.config.policyId).toBe('CUSTOM');
      expect(twice.config._blocklistSet.has('9.9.9.9')).toBe(true); // idempotent, not doubled/corrupted
    });

    test('an unknown type is left unchanged (no-op)', () => {
      const raw = { id: 'CUSTOM', type: 'ALLOW_ALL', enabled: true, config: { foo: 1 } };
      expect(floor.preprocessEntry(raw)).toEqual(raw);
    });

    test('a config that fails to preprocess is returned unchanged rather than throwing', () => {
      const raw = { id: 'CUSTOM', type: 'BLOCK_IP', enabled: true, config: { list: [] } }; // no blocklist/cidrs
      expect(() => floor.preprocessEntry(raw)).not.toThrow();
      expect(floor.preprocessEntry(raw)).toEqual(raw);
    });
  });

  describe('mergeForEvaluation — floor ∪ tenant set', () => {
    test('a tenant set that never mentions a floor policy still gets it in the effective set (the fix)', () => {
      const tenantOnly = [{ id: 'CUSTOM', type: 'BLOCK_IP', enabled: true, config: { blocklist: ['1.2.3.4'] } }];
      const effective = floor.mergeForEvaluation(tenantOnly);
      const ids = effective.map((p) => p.id);
      expect(ids).toEqual(expect.arrayContaining(['CUSTOM', 'FLOOR-CONSENT', 'FLOOR-BLOCK', 'FLOOR-RATE', 'FLOOR-WINDOW']));
      const consent = effective.find((p) => p.id === 'FLOOR-CONSENT');
      expect(consent.enabled).toBe(true);
      expect(consent.config.requireValidArtifact).toBe(true);
    });

    test('a tenant override that tightens a floor policy is kept, not overwritten', () => {
      const tightened = [{ id: 'FLOOR-RATE', type: 'RATE_LIMIT', enabled: true, config: { windowSeconds: 60, maxRequests: 10 } }];
      const effective = floor.mergeForEvaluation(tightened);
      const rate = effective.find((p) => p.id === 'FLOOR-RATE');
      expect(rate.config.maxRequests).toBe(10); // the tenant's own, stricter value survives
    });

    test('a tenant override that loosens a floor policy is restored (defence in depth for a bypassed write path)', () => {
      const loosened = [{ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', enabled: false, config: {} }];
      const effective = floor.mergeForEvaluation(loosened);
      const consent = effective.find((p) => p.id === 'FLOOR-CONSENT');
      expect(consent.enabled).toBe(true);
      expect(consent.config.requireValidArtifact).toBe(true);
    });

    test('every merged entry is preprocessed (evaluator-ready), not raw stored config', () => {
      // Regression pin: BLOCK_IP's evaluate() reads config._blocklistSet /
      // ._cidrRanges, which only exist after preprocess() — a raw stored
      // config throws EVALUATOR_ERROR on every request (see module header).
      const blockIpEvaluator = require('../../../../services/policy/evaluators/blockIp');
      const effective = floor.mergeForEvaluation([]);
      const block = effective.find((p) => p.id === 'FLOOR-BLOCK');
      expect(block.config._blocklistSet).toBeInstanceOf(Set);
      expect(block.config._blocklistSet.has('9.9.9.9')).toBe(true);
      expect(Array.isArray(block.config._cidrRanges)).toBe(true);
      expect(block.config.policyId).toBe('FLOOR-BLOCK');
      // Proves it actually evaluates instead of throwing.
      expect(() => blockIpEvaluator.evaluate({ ip: '1.2.3.4' }, block.config)).not.toThrow();
      expect(blockIpEvaluator.evaluate({ ip: '9.9.9.9' }, block.config)).toEqual({ pass: false, reason: 'IP_BLOCKED' });
    });
  });
});
