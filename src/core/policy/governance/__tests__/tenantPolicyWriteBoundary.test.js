'use strict';

/**
 * "Tenant governed policy publish never preprocesses a policy's
 * config before persisting it." Regression coverage on the STORED config
 * (not the merged/evaluated view's mergeForEvaluation() already
 * covered in tenantPolicyFloor.test.js): after a real governed publish,
 * tenantPolicyRegistry.getPoliciesForTenant() — the RAW getter, the one
 *'s finding warns a future consumer might read directly instead of
 * getEffectivePoliciesForTenant() — must already be evaluator-ready.
 *
 * Unlike tenantGovernance.test.js, this file does NOT mock
 * tenantPolicyRegistry or tenantPolicyFloor — the whole point is to observe
 * what a real publish actually leaves sitting in the real in-memory
 * registry, then hand that exact object to the real evaluator.
 */

describe('Tenant policy write-boundary preprocessing', () => {
  let service;
  let pool;
  let mockTx;
  let ChangeRequestStore;
  let governanceEvents;
  let policyStore;
  let provenanceBridge;
  let tenantConfigStore;
  let tenantPolicyRegistry;
  const ORIGINAL_ENV = process.env;

  function setup() {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, POLICY_GOVERNANCE_STRICT_MODE: 'true' };

    mockTx = { query: jest.fn() };
    pool = {
      withTransaction: jest.fn(async (fn) => fn(mockTx)),
      withTenantTransaction: jest.fn(async (_tenantId, fn) => fn(mockTx)),
    };
    ChangeRequestStore = {
      create: jest.fn(async (row) => ({ id: 'req-1', version: 1, status: 'DRAFT', ...row })),
      findById: jest.fn(),
      updateStatusInTx: jest.fn(async (_tx, { id, status }) => ({ id, status })),
      list: jest.fn(),
    };
    governanceEvents = {
      hashPayload: jest.fn().mockReturnValue('a'.repeat(64)),
      recordEvent: jest.fn().mockResolvedValue({}),
      recordPublication: jest.fn().mockResolvedValue({}),
    };
    // No floor policy in this fixture — keeps every assertion below scoped
    // to exactly the one tenant-native entry each test publishes.
    policyStore = {
      getPolicy: jest.fn(), validatePolicyCandidate: jest.fn().mockReturnValue({ valid: true, errors: [] }),
      createPolicy: jest.fn(), updatePolicy: jest.fn(), setEnabled: jest.fn(),
      listEnabledPolicies: jest.fn().mockReturnValue([]),
    };
    provenanceBridge = { recordPolicyProvenance: jest.fn() };
    tenantConfigStore = {
      getPolicySet: jest.fn().mockResolvedValue(null),
      upsertPolicySet: jest.fn(async ({ tenantId, policies }) => ({ tenantId, policies, hash: 'h'.repeat(64), version: 1 })),
    };

    jest.doMock('../../../../infra/postgres/pool', () => pool);
    jest.doMock('../ChangeRequestStore', () => ChangeRequestStore);
    jest.doMock('../governanceEvents', () => governanceEvents);
    jest.doMock('../../store', () => policyStore);
    jest.doMock('../provenanceBridge', () => provenanceBridge);
    jest.doMock('../../../tenancy/tenantConfigStore', () => tenantConfigStore);
    // tenantPolicyRegistry and tenantPolicyFloor are deliberately REAL.

    service = require('../PolicyGovernanceService');
    tenantPolicyRegistry = require('../../../tenancy/tenantPolicyRegistry');
    tenantPolicyRegistry._reset();
  }

  beforeEach(() => setup());
  afterEach(() => { process.env = ORIGINAL_ENV; jest.resetModules(); });

  const publisher = { id: 'publisher-1', username: 'dave', role: 'admin', sourceIp: '1.2.3.4' };

  function approvedRow(overrides = {}) {
    return {
      id: 'req-1', policy_id: 'TENANT-BLOCK', tenant_id: 'tenant-a', request_type: 'CREATE',
      status: 'APPROVED', version: 3, author_id: 'author-1', change_reason: 'r',
      payload: { type: 'BLOCK_IP', priority: 5, config: { blocklist: ['9.9.9.9'], cidrs: ['10.0.0.0/8'] } },
      payload_hash: 'a'.repeat(64), scheduled_for: null,
      ...overrides,
    };
  }

  test('a published tenant BLOCK_IP policy is stored evaluator-ready: matching IP blocks, non-matching IP executes', async () => {
    const blockIpEvaluator = require('../../../../../services/policy/evaluators/blockIp');
    ChangeRequestStore.findById.mockResolvedValue(approvedRow());

    await service.publish({ requestId: 'req-1', actor: publisher });

    // The RAW getter — exactly what warns a future direct consumer
    // would read instead of going through getEffectivePoliciesForTenant().
    const stored = tenantPolicyRegistry.getPoliciesForTenant('tenant-a');
    const entry  = stored.find((p) => p.id === 'TENANT-BLOCK');
    expect(entry).toBeDefined();
    expect(entry.config._blocklistSet).toBeInstanceOf(Set);
    expect(entry.config._blocklistSet.has('9.9.9.9')).toBe(true);
    expect(Array.isArray(entry.config._cidrRanges)).toBe(true);
    expect(entry.config.policyId).toBe('TENANT-BLOCK');

    // Working, non-throwing evaluate() straight off the stored config.
    expect(() => blockIpEvaluator.evaluate({ ip: '9.9.9.9' }, entry.config)).not.toThrow();
    expect(blockIpEvaluator.evaluate({ ip: '9.9.9.9' }, entry.config))
      .toEqual({ pass: false, reason: 'IP_BLOCKED' }); // matching IP blocks
    expect(blockIpEvaluator.evaluate({ ip: '1.2.3.4' }, entry.config))
      .toEqual({ pass: true }); // non-matching IP executes

    // Regression control: the earlier defect — evaluate() against the RAW
    // (never-preprocessed) payload config throws instead of deciding.
    expect(() => blockIpEvaluator.evaluate({ ip: '9.9.9.9' }, approvedRow().payload.config)).toThrow();
  });

  test('a published tenant RATE_LIMIT policy is stored with its policyId injected — no more "undefined:" store keys', async () => {
    const rateLimitEvaluator = require('../../../../../services/policy/evaluators/rateLimit');
    ChangeRequestStore.findById.mockResolvedValue(approvedRow({
      policy_id: 'TENANT-RATE',
      payload: { type: 'RATE_LIMIT', priority: 5, config: { windowSeconds: 60, maxRequests: 5, keyBy: 'ip' } },
    }));

    await service.publish({ requestId: 'req-1', actor: publisher });

    const stored = tenantPolicyRegistry.getPoliciesForTenant('tenant-a');
    const entry  = stored.find((p) => p.id === 'TENANT-RATE');
    expect(entry).toBeDefined();
    expect(entry.config.policyId).toBe('TENANT-RATE'); // the fix

    const store = { checkAndIncrement: jest.fn().mockResolvedValue({ allowed: true, count: 1 }) };
    const result = await rateLimitEvaluator.evaluate({ ip: '203.0.113.9' }, entry.config, store);
    expect(result).toEqual({ pass: true });
    expect(store.checkAndIncrement).toHaveBeenCalledWith('TENANT-RATE:203.0.113.9', 60, 5);

    // Regression control: without the injected policyId, the store key
    // degrades to "undefined:<ip>" — every tenant RATE_LIMIT policy of this
    // shape would have shared one counter bucket before the fix.
    const badStore = { checkAndIncrement: jest.fn().mockResolvedValue({ allowed: true, count: 1 }) };
    await rateLimitEvaluator.evaluate({ ip: '203.0.113.9' }, { windowSeconds: 60, maxRequests: 5, keyBy: 'ip' }, badStore);
    expect(badStore.checkAndIncrement).toHaveBeenCalledWith('undefined:203.0.113.9', 60, 5);
  });
});
