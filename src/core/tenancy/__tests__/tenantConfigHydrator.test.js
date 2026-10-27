'use strict';

/**
 * hydration behaviour (mocked PG): boot load into both
 * registries, the load-time clamp + TENANT_SEMANTIC_CONFIG_CLAMPED audit
 * event (the second half of the tighten-only enforcement), the
 * malformed-policy-set skip, and the PG-disabled no-op.
 */

jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn() }));
jest.mock('../tenantConfigStore', () => ({
  loadAllPolicySets: jest.fn(),
  loadAllSemanticConfigs: jest.fn(),
}));

const pool = require('../../../infra/postgres/pool');
const tenantConfigStore = require('../tenantConfigStore');
const tenantPolicyRegistry = require('../tenantPolicyRegistry');
const tenantSemanticRegistry = require('../tenantSemanticRegistry');
const logger = require('../../../../services/logger');
const hydrator = require('../tenantConfigHydrator');

describe('tenantConfigHydrator', () => {
  // The hydrator holds a destructured `emit` reference, so a spy on the
  // logger object never sees its calls — capture the emitted records off
  // the logger's own eventBus instead (the documented observation surface).
  let records;
  const onLog = (r) => records.push(r);

  beforeEach(() => {
    tenantPolicyRegistry._reset();
    tenantSemanticRegistry._reset();
    records = [];
    logger.eventBus.on('log', onLog);
    pool.isEnabled.mockReturnValue(true);
    tenantConfigStore.loadAllPolicySets.mockResolvedValue([]);
    tenantConfigStore.loadAllSemanticConfigs.mockResolvedValue([]);
  });

  afterEach(() => { logger.eventBus.removeListener('log', onLog); jest.restoreAllMocks(); });

  test('H1 PG disabled → no-op, registries untouched (dev fallback semantics)', async () => {
    pool.isEnabled.mockReturnValue(false);
    const r = await hydrator.hydrate();
    expect(r).toEqual({ hydrated: false, reason: 'PG_DISABLED' });
    expect(tenantConfigStore.loadAllPolicySets).not.toHaveBeenCalled();
  });

  test('H2 boot load populates both registries', async () => {
    tenantConfigStore.loadAllPolicySets.mockResolvedValue([
      { tenantId: 't-a', policies: [{ id: 'P1', type: 'BLOCK_IP', enabled: true, config: {} }], hash: 'h', version: 2 },
    ]);
    tenantConfigStore.loadAllSemanticConfigs.mockResolvedValue([
      { tenantId: 't-a', config: { thresholds: { REVIEW: 0.40 } }, hash: 'x', version: 3 },
    ]);
    const r = await hydrator.hydrate();
    expect(r).toEqual({ hydrated: true, policiesApplied: 1, semanticApplied: 1 });
    expect(tenantPolicyRegistry.getPoliciesForTenant('t-a')).toHaveLength(1);
    expect(tenantSemanticRegistry.getConfig('t-a').config).toEqual({ thresholds: { REVIEW: 0.40 } });
    expect(tenantSemanticRegistry.getConfig('t-a').version).toBe(3);
  });

  test('H3 a LOOSENING stored semantic row is clamped at load and the audit event names the changes', async () => {
    tenantConfigStore.loadAllSemanticConfigs.mockResolvedValue([
      { tenantId: 't-tampered', config: { thresholds: { DENY: 0.99, REVIEW: 0.50 }, enforcement: { REVIEW_BLOCKS: false } }, hash: 'x', version: 1 },
    ]);
    await hydrator.hydrate();
    const applied = tenantSemanticRegistry.getConfig('t-tampered').config;
    expect(applied.thresholds.DENY).toBe(0.70);   // clamped to the pinned default
    expect(applied.thresholds.REVIEW).toBe(0.50); // tighter value kept
    expect(applied.enforcement).toBeUndefined();  // REVIEW_BLOCKS=false dropped
    const clampEvent = records.find((r) => r.eventType === 'TENANT_SEMANTIC_CONFIG_CLAMPED');
    expect(clampEvent).toBeDefined();
    expect(clampEvent.tenantId).toBe('t-tampered');
    expect(clampEvent.changes.join(' ')).toMatch(/clamped/);
  });

  test('H4 a malformed policy-set row is skipped (global fallback for that tenant) with an ERROR event', async () => {
    tenantConfigStore.loadAllPolicySets.mockResolvedValue([
      { tenantId: 't-bad', policies: { not: 'an array' }, hash: 'h', version: 1 },
      { tenantId: 't-ok', policies: [], hash: 'h2', version: 1 },
    ]);
    const r = await hydrator.hydrate();
    expect(r.policiesApplied).toBe(1);
    expect(tenantPolicyRegistry.getPoliciesForTenant('t-bad')).toBeNull();
    expect(records.some((r) => r.eventType === 'TENANT_POLICY_SET_INVALID')).toBe(true);
  });

  test('H6 a stored floor-id policy that was disabled/loosened is restored at load, with a TENANT_POLICY_FLOOR_RESTORED audit event', async () => {
    // POL-001 (REQUIRE_CONSENT) is the real live policies.json's floor entry
    // — this pins the hydrator's load-time defence against a tampered/
    // hand-edited PG row, mirroring H3's semantic-config clamp test.
    tenantConfigStore.loadAllPolicySets.mockResolvedValue([
      { tenantId: 't-tampered', policies: [
        { id: 'POL-001', type: 'REQUIRE_CONSENT', enabled: false, config: { requireValidArtifact: true } },
        { id: 'CUSTOM', type: 'BLOCK_IP', enabled: true, config: {} },
      ], hash: 'h', version: 1 },
    ]);
    await hydrator.hydrate();
    const applied = tenantPolicyRegistry.getPoliciesForTenant('t-tampered');
    expect(applied).toHaveLength(2); // restored in place, nothing added
    const consent = applied.find((p) => p.id === 'POL-001');
    expect(consent.enabled).toBe(true);
    const restoreEvent = records.find((r) => r.eventType === 'TENANT_POLICY_FLOOR_RESTORED');
    expect(restoreEvent).toBeDefined();
    expect(restoreEvent.tenantId).toBe('t-tampered');
    expect(restoreEvent.changes.join(' ')).toMatch(/POL-001.*restored/);
  });

  test('H7 hydration preprocesses stored BLOCK_IP config — rows stored before the fix become evaluator-ready on load, idempotently across repeated refreshes', async () => {
    const blockIpEvaluator = require('../../../../services/policy/evaluators/blockIp');
    // PostgreSQL only ever holds RAW config (see tenantPolicyFloor.js) — this
    // row is indistinguishable from one written before the fix shipped.
    tenantConfigStore.loadAllPolicySets.mockResolvedValue([
      { tenantId: 't-preprocess', policies: [
        { id: 'CUSTOM-BLOCK', type: 'BLOCK_IP', enabled: true, config: { blocklist: ['9.9.9.9'], cidrs: [] } },
      ], hash: 'h', version: 1 },
    ]);

    await hydrator.hydrate();
    const first = tenantPolicyRegistry.getPoliciesForTenant('t-preprocess').find((p) => p.id === 'CUSTOM-BLOCK');
    expect(first.config._blocklistSet).toBeInstanceOf(Set);
    expect(first.config._blocklistSet.has('9.9.9.9')).toBe(true);
    expect(() => blockIpEvaluator.evaluate({ ip: '9.9.9.9' }, first.config)).not.toThrow();
    expect(blockIpEvaluator.evaluate({ ip: '9.9.9.9' }, first.config)).toEqual({ pass: false, reason: 'IP_BLOCKED' });
    expect(blockIpEvaluator.evaluate({ ip: '1.2.3.4' }, first.config)).toEqual({ pass: true });

    // A second refresh re-reads the SAME raw PG row (nothing persists
    // preprocessed) — idempotent, not a crash or a drifted result.
    await hydrator.hydrate();
    const second = tenantPolicyRegistry.getPoliciesForTenant('t-preprocess').find((p) => p.id === 'CUSTOM-BLOCK');
    expect(second.config._blocklistSet).toBeInstanceOf(Set);
    expect(second.config._blocklistSet.has('9.9.9.9')).toBe(true);
    expect(blockIpEvaluator.evaluate({ ip: '9.9.9.9' }, second.config)).toEqual({ pass: false, reason: 'IP_BLOCKED' });
  });

  test('H5 refresh timer: starts only with PG enabled, is unref-safe, and stop() clears it', async () => {
    expect(hydrator.startRefresh()).toBe(true);
    expect(hydrator.startRefresh()).toBe(false); // idempotent
    hydrator.stopRefresh();
    expect(hydrator.startRefresh()).toBe(true);
    hydrator.stopRefresh();
    pool.isEnabled.mockReturnValue(false);
    expect(hydrator.startRefresh()).toBe(false);
  });
});
