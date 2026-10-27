'use strict';

/**
 * EmergencyPolicyService — test suite (mocked dependencies)
 *
 * Covers: activate() bounds checking and immediate application,
 * retroApprove()'s activator != approver enforcement, the lazy
 * expiry-then-auto-revert path, and sweepExpired()'s batch behavior.
 */

describe('EmergencyPolicyService', () => {
  let service;
  let pool;
  let mockTx;
  let ChangeRequestStore;
  let governanceEvents;
  let policyStore;
  let provenanceBridge;
  let emitMock;
  let applyTenantPublishMock;

  beforeEach(() => {
    jest.resetModules();
    mockTx = { query: jest.fn() };
    pool = {
      query: jest.fn(),
      withTransaction: jest.fn(async (fn) => fn(mockTx)),
      withTenantTransaction: jest.fn(async (tenantId, fn) => fn(mockTx)),
    };
    ChangeRequestStore = { create: jest.fn(), updateStatusInTx: jest.fn() };
    governanceEvents = {
      hashPayload: jest.fn().mockReturnValue('a'.repeat(64)),
      recordEvent: jest.fn().mockResolvedValue({}),
      recordPublication: jest.fn().mockResolvedValue({}),
    };
    policyStore = { createPolicy: jest.fn(), updatePolicy: jest.fn(), setEnabled: jest.fn() };
    provenanceBridge = { recordPolicyProvenance: jest.fn() };
    emitMock = jest.fn();
    applyTenantPublishMock = jest.fn().mockResolvedValue({ id: 'p1', currentVersion: 1 });

    jest.doMock('../../../../infra/postgres/pool', () => pool);
    jest.doMock('../../../../infra/postgres/rolePools', () => require('../../../../../test/helpers/rolePoolsDelegate')(pool)); //
    jest.doMock('../ChangeRequestStore', () => ChangeRequestStore);
    jest.doMock('../governanceEvents', () => governanceEvents);
    jest.doMock('../../store', () => policyStore);
    jest.doMock('../provenanceBridge', () => provenanceBridge);
    jest.doMock('../../../../../services/logger', () => ({ emit: emitMock }));
    // D5/D6's tenant-scoped branches (activate()/_revertInTx())
    // call this real sibling module's applyTenantPublish — mocked here so a
    // tenant-scoped test case doesn't depend on PolicyGovernanceService's own
    // real behavior (which needs a real policy store row to succeed).
    jest.doMock('../PolicyGovernanceService', () => ({ applyTenantPublish: applyTenantPublishMock }));

    service = require('../EmergencyPolicyService');
  });

  afterEach(() => jest.resetModules());

  const activator = { id: 'activator-1', username: 'oncall', role: 'admin', sourceIp: '1.2.3.4' };
  const approver  = { id: 'approver-1', username: 'carol', role: 'compliance', sourceIp: '1.2.3.4' };

  describe('activate()', () => {
    test('requires incidentReference and justification', async () => {
      await expect(service.activate({
        policyId: 'p1', requestType: 'ENABLE', payload: {}, incidentReference: '', justification: '', actor: activator,
      })).rejects.toThrow('required');
    });

    test('rejects ttlHours out of bounds', async () => {
      await expect(service.activate({
        policyId: 'p1', requestType: 'ENABLE', payload: {}, incidentReference: 'INC-1', justification: 'x',
        ttlHours: 200, actor: activator,
      })).rejects.toThrow('ttlHours');
    });

    test('rejects an unsupported request type (e.g. ROLLBACK/ARCHIVE)', async () => {
      await expect(service.activate({
        policyId: 'p1', requestType: 'ROLLBACK', payload: {}, incidentReference: 'INC-1', justification: 'x', actor: activator,
      })).rejects.toThrow('does not support');
    });

    test('applies immediately (bypasses the normal gate) and records an emergency activation', async () => {
      ChangeRequestStore.create.mockResolvedValue({ id: 'req-1', version: 1 });
      policyStore.setEnabled.mockReturnValue({ id: 'p1', currentVersion: 5 });
      ChangeRequestStore.updateStatusInTx.mockResolvedValue({ id: 'req-1', status: 'PUBLISHED' });
      mockTx.query.mockResolvedValueOnce({ rows: [{ id: 'em-1', retrospective_status: 'PENDING' }] });

      const result = await service.activate({
        policyId: 'p1', requestType: 'ENABLE', payload: {}, incidentReference: 'INC-1', justification: 'prod outage', actor: activator,
      });

      expect(policyStore.setEnabled).toHaveBeenCalledWith('p1', true, expect.anything());
      expect(result.emergency.id).toBe('em-1');
      expect(result.changeRequest.status).toBe('PUBLISHED');
      expect(emitMock).toHaveBeenCalledWith('WARN', 'POLICY_EMERGENCY_ACTIVATED', expect.objectContaining({ incidentReference: 'INC-1' }));
      expect(provenanceBridge.recordPolicyProvenance).toHaveBeenCalled();
    });
  });

  describe('retroApprove()', () => {
    function pendingRow(overrides = {}) {
      return {
        id: 'em-1', change_request_id: 'req-1', policy_id: 'p1', tenant_id: null,
        activated_by: activator.id, retrospective_status: 'PENDING',
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        ...overrides,
      };
    }

    test('rejects an invalid decision value', async () => {
      await expect(service.retroApprove({ emergencyId: 'em-1', actor: approver, decision: 'MAYBE' }))
        .rejects.toThrow("decision must be 'APPROVED' or 'REJECTED'");
    });

    test('rejects when the activation does not exist', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [] });
      await expect(service.retroApprove({ emergencyId: 'missing', actor: approver, decision: 'APPROVED' }))
        .rejects.toThrow('not found');
    });

    test('rejects when already decided', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [pendingRow({ retrospective_status: 'APPROVED' })] });
      await expect(service.retroApprove({ emergencyId: 'em-1', actor: approver, decision: 'APPROVED' }))
        .rejects.toThrow('already APPROVED');
    });

    test('rejects the activator retrospectively approving their own emergency change', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [pendingRow()] });
      await expect(service.retroApprove({ emergencyId: 'em-1', actor: activator, decision: 'APPROVED' }))
        .rejects.toThrow(/activated/i);
    });

    test('an independent approver APPROVEs successfully, no revert', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [pendingRow()] })            // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [pendingRow({ retrospective_status: 'APPROVED' })] }); // UPDATE decision

      const result = await service.retroApprove({ emergencyId: 'em-1', actor: approver, decision: 'APPROVED' });
      expect(result.emergency.retrospective_status).toBe('APPROVED');
      expect(policyStore.setEnabled).not.toHaveBeenCalled();
    });

    test('an independent approver REJECTs — the policy is reverted (disabled)', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [pendingRow()] })                                    // SELECT FOR UPDATE
        .mockResolvedValueOnce({ rows: [pendingRow({ retrospective_status: 'REJECTED' })] }) // UPDATE decision
        .mockResolvedValueOnce({ rows: [pendingRow({ retrospective_status: 'REJECTED', reverted_at: new Date().toISOString() })] }); // _revertInTx UPDATE
      policyStore.setEnabled.mockReturnValue({ id: 'p1', currentVersion: 6 });

      const result = await service.retroApprove({ emergencyId: 'em-1', actor: approver, decision: 'REJECTED' });
      expect(policyStore.setEnabled).toHaveBeenCalledWith('p1', false, expect.anything());
      expect(result.emergency.retrospective_status).toBe('REJECTED');
    });

    test('an expired-but-still-PENDING activation is refused and auto-reverted instead of decided', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [pendingRow({ expires_at: new Date(Date.now() - 3600_000).toISOString() })] }) // SELECT FOR UPDATE — already expired
        .mockResolvedValueOnce({ rows: [pendingRow({ retrospective_status: 'EXPIRED' })] }); // _revertInTx UPDATE
      policyStore.setEnabled.mockReturnValue({ id: 'p1', currentVersion: 7 });

      await expect(service.retroApprove({ emergencyId: 'em-1', actor: approver, decision: 'APPROVED' }))
        .rejects.toMatchObject({ code: 'EMERGENCY_EXPIRED' });
      expect(policyStore.setEnabled).toHaveBeenCalledWith('p1', false, expect.anything());
    });
  });

  describe('sweepExpired()', () => {
    test('reverts every PENDING+expired activation and skips ones already handled concurrently', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ id: 'em-1' }, { id: 'em-2' }] });

      // em-1: still PENDING and expired when locked -> reverted
      mockTx.query
        .mockResolvedValueOnce({
          rows: [{ id: 'em-1', policy_id: 'p1', change_request_id: 'req-1', tenant_id: null,
            retrospective_status: 'PENDING', expires_at: new Date(Date.now() - 1000).toISOString() }],
        })
        .mockResolvedValueOnce({ rows: [{ id: 'em-1', retrospective_status: 'EXPIRED' }] });
      // em-2: already handled concurrently (no longer PENDING) -> skipped
      mockTx.query.mockResolvedValueOnce({
        rows: [{ id: 'em-2', retrospective_status: 'APPROVED', expires_at: new Date(Date.now() - 1000).toISOString() }],
      });
      policyStore.setEnabled.mockReturnValue({ id: 'p1', currentVersion: 8 });

      const result = await service.sweepExpired();

      expect(result.swept).toBe(1);
      expect(result.ids).toEqual(['em-1']);
      expect(policyStore.setEnabled).toHaveBeenCalledTimes(1);
    });

    test('returns zero when nothing is pending/expired', async () => {
      pool.query.mockResolvedValueOnce({ rows: [] });
      const result = await service.sweepExpired();
      expect(result).toEqual({ swept: 0, ids: [] });
    });

    test('a failure reverting one item does not abort the sweep for the rest', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ id: 'em-1' }] });
      pool.withTransaction.mockImplementationOnce(async () => { throw new Error('db hiccup'); });

      const result = await service.sweepExpired();
      expect(result.swept).toBe(0);
      expect(emitMock).toHaveBeenCalledWith('ERROR', 'POLICY_EMERGENCY_SWEEP_FAILED', expect.objectContaining({ emergencyId: 'em-1' }));
    });

    // Reproduces the fixed defect. Before this fix,
    // the discovery query ran with no tenant context and pea_tenant_select's
    // RLS silently hid every tenant-scoped row, so a tenant-scoped emergency
    // activation that expired without retrospective approval was NEVER
    // auto-reverted (result.swept would be 0 for it). This test also proves
    // the row-lock/revert step runs under the ROW's OWN tenant context
    // (pool.withTenantTransaction), not the RLS-blind pool.withTransaction —
    // fixing only the discovery half (via the bypass function) without this
    // would still silently fail to revert a tenant-scoped row.
    test('discovers and reverts a TENANT-SCOPED expired activation via its own tenant context', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ id: 'em-3', tenant_id: 'tenantA' }] });
      mockTx.query
        .mockResolvedValueOnce({
          rows: [{ id: 'em-3', policy_id: 'p1', change_request_id: 'req-3', tenant_id: 'tenantA',
            retrospective_status: 'PENDING', expires_at: new Date(Date.now() - 1000).toISOString() }],
        })
        .mockResolvedValueOnce({ rows: [{ id: 'em-3', tenant_id: 'tenantA', retrospective_status: 'EXPIRED' }] });

      const result = await service.sweepExpired();

      expect(result.swept).toBe(1);
      expect(result.ids).toEqual(['em-3']);
      expect(pool.withTenantTransaction).toHaveBeenCalledWith('tenantA', expect.any(Function));
      expect(pool.withTransaction).not.toHaveBeenCalled();
      // _revertInTx's tenant-scoped branch (D6) must be used, not the global policyStore
      expect(applyTenantPublishMock).toHaveBeenCalledWith(
        expect.objectContaining({ tenant_id: 'tenantA', policy_id: 'p1', request_type: 'DISABLE' }),
        expect.anything(),
      );
      expect(policyStore.setEnabled).not.toHaveBeenCalled();
    });
  });
});
