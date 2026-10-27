'use strict';

/**
 * tenant-targeted change requests through the flow
 * (mocked persistence, same harness conventions as
 * PolicyGovernanceService.test.js). Pins:
 *
 * D* draft-time validation: the tighten-only invariant REJECTS a
 *       loosening TENANT-SEMANTIC-CONFIG draft before any workflow row is
 *       written; tenant policy drafts validate against the TENANT set, not
 *       the global store; the reserved id needs a tenantId.
 *   P*  publish: a tenant-targeted request writes the tenant stores + the
 *       in-memory registries and NEVER touches the global policy store or
 *       the global provenance chain; the tighten-only invariant is
 *       re-checked at publish (defense in depth).
 */

describe('Tenant-targeted policy governance', () => {
  let service;
  let pool;
  let mockTx;
  let ChangeRequestStore;
  let governanceEvents;
  let policyStore;
  let provenanceBridge;
  let tenantConfigStore;
  let tenantPolicyRegistry;
  let tenantSemanticRegistry;
  const ORIGINAL_ENV = process.env;

  function setup() {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, POLICY_GOVERNANCE_STRICT_MODE: 'true' };

    mockTx = { query: jest.fn() };
    pool = {
      withTransaction: jest.fn(async (fn) => fn(mockTx)),
      // Tenant-scoped stages run under the request's tenant context
      // (_txForRequest → withTenantTransaction) — same tx double.
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
    policyStore = {
      getPolicy: jest.fn(), validatePolicyCandidate: jest.fn().mockReturnValue({ valid: true, errors: [] }),
      createPolicy: jest.fn(), updatePolicy: jest.fn(), setEnabled: jest.fn(),
      // the live floor tenantPolicyFloor.js reads off this store —
      // a single fixture floor policy, distinct from every id these tests
      // otherwise use (POL-001, P-1, P-X, ...), so existing scenarios are
      // untouched unless a test deliberately targets FLOOR-CONSENT.
      listEnabledPolicies: jest.fn().mockReturnValue([
        { id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, config: { requireValidArtifact: true } },
      ]),
    };
    provenanceBridge = { recordPolicyProvenance: jest.fn() };
    tenantConfigStore = {
      getPolicySet: jest.fn().mockResolvedValue(null),
      upsertPolicySet: jest.fn(async ({ tenantId, policies }) => ({ tenantId, policies, hash: 'h'.repeat(64), version: 1 })),
      upsertSemanticConfig: jest.fn(async ({ tenantId, config }) => ({ tenantId, config, hash: 's'.repeat(64), version: 1 })),
    };
    tenantPolicyRegistry = { setPolicies: jest.fn() };
    tenantSemanticRegistry = {
      // The REAL tighten-only validator/clamp semantics matter here — use the
      // real module, spy-free (it has no I/O), and only mock setConfig.
      ...jest.requireActual('../../../tenancy/tenantSemanticRegistry'),
      setConfig: jest.fn(),
    };

    jest.doMock('../../../../infra/postgres/pool', () => pool);
    jest.doMock('../ChangeRequestStore', () => ChangeRequestStore);
    jest.doMock('../governanceEvents', () => governanceEvents);
    jest.doMock('../../store', () => policyStore);
    jest.doMock('../provenanceBridge', () => provenanceBridge);
    jest.doMock('../../../tenancy/tenantConfigStore', () => tenantConfigStore);
    jest.doMock('../../../tenancy/tenantPolicyRegistry', () => tenantPolicyRegistry);
    jest.doMock('../../../tenancy/tenantSemanticRegistry', () => tenantSemanticRegistry);

    service = require('../PolicyGovernanceService');
  }

  beforeEach(() => setup());
  afterEach(() => { process.env = ORIGINAL_ENV; jest.resetModules(); });

  const author    = { id: 'author-1',    username: 'alice', role: 'operator', sourceIp: '1.2.3.4' };
  const publisher = { id: 'publisher-1', username: 'dave',  role: 'admin',    sourceIp: '1.2.3.4' };

  // ── D: draft-time validation ───────────────────────────────────────────────

  test('D1 a LOOSENING semantic-config draft is rejected before any workflow row exists (write-time invariant)', async () => {
    await expect(service.draft({
      policyId: 'TENANT-SEMANTIC-CONFIG', tenantId: 'tenant-a', requestType: 'UPDATE',
      payload: { thresholds: { DENY: 0.90 } }, changeReason: 'loosen it', actor: author,
    })).rejects.toThrow(/TENANT_SEMANTIC_TIGHTEN_ONLY_VIOLATION.*LOOSEN/);
    expect(ChangeRequestStore.create).not.toHaveBeenCalled();
  });

  test('D2 a non-representable knob (REVIEW_BLOCKS / FT flags) is rejected the same way', async () => {
    await expect(service.draft({
      policyId: 'TENANT-SEMANTIC-CONFIG', tenantId: 'tenant-a', requestType: 'UPDATE',
      payload: { enforcement: { REVIEW_BLOCKS: false } }, changeReason: 'x', actor: author,
    })).rejects.toThrow(/TENANT_SEMANTIC_TIGHTEN_ONLY_VIOLATION/);
    expect(ChangeRequestStore.create).not.toHaveBeenCalled();
  });

  test('D3 a TIGHTENING semantic-config draft is accepted and creates the workflow row', async () => {
    await service.draft({
      policyId: 'TENANT-SEMANTIC-CONFIG', tenantId: 'tenant-a', requestType: 'UPDATE',
      payload: { thresholds: { REVIEW: 0.40 } }, changeReason: 'tighten', actor: author,
    });
    expect(ChangeRequestStore.create).toHaveBeenCalledWith(expect.objectContaining({
      policy_id: 'TENANT-SEMANTIC-CONFIG', tenant_id: 'tenant-a', request_type: 'UPDATE',
    }));
  });

  test('D4 the reserved id without a tenantId is rejected', async () => {
    await expect(service.draft({
      policyId: 'TENANT-SEMANTIC-CONFIG', requestType: 'UPDATE',
      payload: { thresholds: { REVIEW: 0.40 } }, changeReason: 'x', actor: author,
    })).rejects.toThrow(/reserved for tenant-targeted/);
  });

  test('D5 tenant policy CREATE validates against the TENANT set — a global id may be shadowed', async () => {
    policyStore.getPolicy.mockReturnValue({ id: 'POL-001' }); // exists GLOBALLY
    tenantConfigStore.getPolicySet.mockResolvedValue(null);   // not in the tenant set
    await service.draft({
      policyId: 'POL-001', tenantId: 'tenant-a', requestType: 'CREATE',
      payload: { type: 'REQUIRE_CONSENT', priority: 1, config: {} }, changeReason: 'shadow', actor: author,
    });
    expect(ChangeRequestStore.create).toHaveBeenCalled();
  });

  test('D6 tenant policy UPDATE of a policy absent from the tenant set is NOT_FOUND', async () => {
    tenantConfigStore.getPolicySet.mockResolvedValue({ tenantId: 'tenant-a', policies: [], version: 1 });
    await expect(service.draft({
      policyId: 'P-X', tenantId: 'tenant-a', requestType: 'UPDATE',
      payload: { config: {} }, changeReason: 'x', actor: author,
    })).rejects.toThrow(/NOT_FOUND/);
  });

  // ── D7-D9: the policy floor (residual) ────────────────────

  test('D7 a CREATE sharing a floor id with a weaker config is rejected, naming the floor policy', async () => {
    tenantConfigStore.getPolicySet.mockResolvedValue(null);
    await expect(service.draft({
      policyId: 'FLOOR-CONSENT', tenantId: 'tenant-a', requestType: 'CREATE',
      payload: { type: 'REQUIRE_CONSENT', priority: 1, config: {} }, changeReason: 'drop consent', actor: author,
    })).rejects.toThrow(/VALIDATION_FAILED.*FLOOR-CONSENT/);
    expect(ChangeRequestStore.create).not.toHaveBeenCalled();
  });

  test('D8 a CREATE sharing a floor id that TIGHTENS it is accepted', async () => {
    tenantConfigStore.getPolicySet.mockResolvedValue(null);
    await service.draft({
      policyId: 'FLOOR-CONSENT', tenantId: 'tenant-a', requestType: 'CREATE',
      payload: { type: 'REQUIRE_CONSENT', priority: 1, config: { requireValidArtifact: true, requiredScope: 'narrow' } },
      changeReason: 'tighten consent', actor: author,
    });
    expect(ChangeRequestStore.create).toHaveBeenCalled();
  });

  test('D9 a DISABLE targeting an existing floor-id tenant policy is rejected', async () => {
    tenantConfigStore.getPolicySet.mockResolvedValue({
      tenantId: 'tenant-a',
      policies: [{ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', enabled: true, config: { requireValidArtifact: true } }],
      version: 1,
    });
    await expect(service.draft({
      policyId: 'FLOOR-CONSENT', tenantId: 'tenant-a', requestType: 'DISABLE',
      payload: {}, changeReason: 'x', actor: author,
    })).rejects.toThrow(/VALIDATION_FAILED.*FLOOR-CONSENT/);
  });

  // ── P: publish ─────────────────────────────────────────────────────────────

  function approvedRow(overrides = {}) {
    return {
      id: 'req-1', policy_id: 'P-1', tenant_id: 'tenant-a', request_type: 'CREATE',
      status: 'APPROVED', version: 3, author_id: author.id, change_reason: 'r',
      payload: { type: 'BLOCK_IP', priority: 5, config: { list: [] } }, payload_hash: 'a'.repeat(64),
      scheduled_for: null,
      ...overrides,
    };
  }

  test('P1 tenant policy publish writes the tenant store + registry, never the global store/provenance', async () => {
    ChangeRequestStore.findById.mockResolvedValue(approvedRow());
    const { policy } = await service.publish({ requestId: 'req-1', actor: publisher });
    expect(tenantConfigStore.upsertPolicySet).toHaveBeenCalledWith(expect.objectContaining({ tenantId: 'tenant-a' }));
    expect(tenantPolicyRegistry.setPolicies).toHaveBeenCalledWith('tenant-a', expect.arrayContaining([
      expect.objectContaining({ id: 'P-1', enabled: true }),
    ]));
    expect(policy.target).toBe('TENANT_POLICY_SET');
    expect(policyStore.createPolicy).not.toHaveBeenCalled();
    expect(policyStore.updatePolicy).not.toHaveBeenCalled();
    expect(provenanceBridge.recordPolicyProvenance).not.toHaveBeenCalled();
    expect(governanceEvents.recordPublication).toHaveBeenCalledWith(mockTx, expect.objectContaining({ tenantId: 'tenant-a' }));
  });

  test('P2 tenant semantic publish upserts the config + registry and re-validates tighten-only', async () => {
    ChangeRequestStore.findById.mockResolvedValue(approvedRow({
      policy_id: 'TENANT-SEMANTIC-CONFIG', request_type: 'UPDATE',
      payload: { thresholds: { REVIEW: 0.40 } },
    }));
    const { policy } = await service.publish({ requestId: 'req-1', actor: publisher });
    expect(tenantConfigStore.upsertSemanticConfig).toHaveBeenCalledWith(expect.objectContaining({
      tenantId: 'tenant-a', config: { thresholds: { REVIEW: 0.40 } },
    }));
    expect(tenantSemanticRegistry.setConfig).toHaveBeenCalledWith('tenant-a', { thresholds: { REVIEW: 0.40 } }, { version: 1 });
    expect(policy.target).toBe('TENANT_SEMANTIC_CONFIG');
  });

  test('P3 defense in depth: a loosening payload that somehow reached APPROVED still cannot publish', async () => {
    ChangeRequestStore.findById.mockResolvedValue(approvedRow({
      policy_id: 'TENANT-SEMANTIC-CONFIG', request_type: 'UPDATE',
      payload: { thresholds: { DENY: 0.95 } },
    }));
    await expect(service.publish({ requestId: 'req-1', actor: publisher }))
      .rejects.toThrow(/TENANT_SEMANTIC_TIGHTEN_ONLY_VIOLATION/);
    expect(tenantConfigStore.upsertSemanticConfig).not.toHaveBeenCalled();
    expect(tenantSemanticRegistry.setConfig).not.toHaveBeenCalled();
  });

  test('P5 defense in depth: a policy-floor violation that somehow reached APPROVED still cannot publish', async () => {
    tenantConfigStore.getPolicySet.mockResolvedValue({
      tenantId: 'tenant-a',
      policies: [{ id: 'FLOOR-CONSENT', type: 'REQUIRE_CONSENT', enabled: true, config: { requireValidArtifact: true } }],
      version: 1,
    });
    ChangeRequestStore.findById.mockResolvedValue(approvedRow({
      policy_id: 'FLOOR-CONSENT', request_type: 'DISABLE', payload: {},
    }));
    await expect(service.publish({ requestId: 'req-1', actor: publisher }))
      .rejects.toThrow(/VALIDATION_FAILED.*FLOOR-CONSENT/);
    expect(tenantConfigStore.upsertPolicySet).not.toHaveBeenCalled();
    expect(tenantPolicyRegistry.setPolicies).not.toHaveBeenCalled();
  });

  test('P4 a GLOBAL publish is byte-identical to before: global store + provenance, no tenant stores', async () => {
    ChangeRequestStore.findById.mockResolvedValue(approvedRow({ tenant_id: null }));
    policyStore.createPolicy.mockReturnValue({ id: 'P-1', currentVersion: 2 });
    await service.publish({ requestId: 'req-1', actor: publisher });
    expect(policyStore.createPolicy).toHaveBeenCalled();
    expect(provenanceBridge.recordPolicyProvenance).toHaveBeenCalled();
    expect(tenantConfigStore.upsertPolicySet).not.toHaveBeenCalled();
    expect(tenantConfigStore.upsertSemanticConfig).not.toHaveBeenCalled();
  });
});
