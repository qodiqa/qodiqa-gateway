'use strict';

/**
 * RollbackGovernanceService — test suite (mocked dependencies)
 *
 * Covers: requestRollback() version/existence checks, and
 * approveAndPublishRollback()'s independent-approval enforcement —
 * rejecting both the requester and the original publisher of the version
 * being replaced.
 */

describe('RollbackGovernanceService', () => {
  let service;
  let pool;
  let mockTx;
  let ChangeRequestStore;
  let governanceEvents;
  let policyStore;
  let provenanceBridge;

  beforeEach(() => {
    jest.resetModules();
    mockTx = { query: jest.fn() };
    pool = { query: jest.fn(), withTransaction: jest.fn(async (fn) => fn(mockTx)) };
    ChangeRequestStore = { create: jest.fn(), findById: jest.fn(), updateStatusInTx: jest.fn() };
    governanceEvents = {
      hashPayload: jest.fn().mockReturnValue('a'.repeat(64)),
      recordEvent: jest.fn().mockResolvedValue({}),
      recordApproval: jest.fn().mockResolvedValue({}),
      recordRollback: jest.fn().mockResolvedValue({}),
    };
    policyStore = { getVersion: jest.fn(), getPolicy: jest.fn(), rollbackPolicy: jest.fn() };
    provenanceBridge = { recordPolicyProvenance: jest.fn() };

    jest.doMock('../../../../infra/postgres/pool', () => pool);
    jest.doMock('../ChangeRequestStore', () => ChangeRequestStore);
    jest.doMock('../governanceEvents', () => governanceEvents);
    jest.doMock('../../store', () => policyStore);
    jest.doMock('../provenanceBridge', () => provenanceBridge);

    service = require('../RollbackGovernanceService');
  });

  afterEach(() => jest.resetModules());

  const requester = { id: 'requester-1', username: 'alice', role: 'operator', sourceIp: '1.2.3.4' };
  const originalPublisher = { id: 'publisher-1', username: 'admin', role: 'admin', sourceIp: '1.2.3.4' };
  const independentApprover = { id: 'approver-1', username: 'carol', role: 'compliance', sourceIp: '1.2.3.4' };

  describe('requestRollback()', () => {
    test('rejects an unknown target version', async () => {
      policyStore.getVersion.mockReturnValue(null);
      await expect(service.requestRollback({
        policyId: 'p1', toVersion: 5, reason: 'bad deploy', actor: requester,
      })).rejects.toThrow('VERSION_NOT_FOUND'.length ? /not found/i : '');
    });

    test('rejects an unknown policy', async () => {
      policyStore.getVersion.mockReturnValue({ v: 1 });
      policyStore.getPolicy.mockReturnValue(null);
      await expect(service.requestRollback({
        policyId: 'ghost', toVersion: 1, reason: 'x', actor: requester,
      })).rejects.toThrow('not found');
    });

    test('creates and auto-submits a ROLLBACK request, recording the original publisher', async () => {
      policyStore.getVersion.mockReturnValue({ v: 1 });
      policyStore.getPolicy.mockReturnValue({ id: 'p1', currentVersion: 2 });
      pool.query.mockResolvedValueOnce({ rows: [{ published_by: originalPublisher.id }] });
      ChangeRequestStore.create.mockResolvedValue({ id: 'req-1', version: 1, policy_id: 'p1' });
      ChangeRequestStore.updateStatusInTx.mockResolvedValue({ id: 'req-1', status: 'SUBMITTED' });

      const result = await service.requestRollback({
        policyId: 'p1', toVersion: 1, reason: 'bad deploy', actor: requester,
      });

      expect(result.changeRequest.status).toBe('SUBMITTED');
      expect(result.fromVersion).toBe(2);
      expect(result.toVersion).toBe(1);
      expect(result.originalPublisherId).toBe(originalPublisher.id);
      expect(ChangeRequestStore.create).toHaveBeenCalledWith(expect.objectContaining({ request_type: 'ROLLBACK' }));
    });
  });

  describe('approveAndPublishRollback()', () => {
    function submittedRollback(overrides = {}) {
      return {
        id: 'req-1', request_type: 'ROLLBACK', status: 'SUBMITTED', version: 1,
        policy_id: 'p1', author_id: requester.id, tenant_id: null,
        payload: { toVersion: 1 }, change_reason: 'bad deploy',
        ...overrides,
      };
    }

    test('rejects when the request is not of type ROLLBACK', async () => {
      ChangeRequestStore.findById.mockResolvedValue(submittedRollback({ request_type: 'UPDATE' }));
      await expect(service.approveAndPublishRollback({ requestId: 'req-1', actor: independentApprover }))
        .rejects.toThrow('not a ROLLBACK request');
    });

    test('rejects when the request is not awaiting approval', async () => {
      ChangeRequestStore.findById.mockResolvedValue(submittedRollback({ status: 'PUBLISHED' }));
      await expect(service.approveAndPublishRollback({ requestId: 'req-1', actor: independentApprover }))
        .rejects.toThrow('not awaiting approval');
    });

    test('F1-RB-01 refuses to apply a rollback whose stored payload no longer matches its payload_hash', async () => {
      governanceEvents.hashPayload.mockReturnValue('b'.repeat(64));        // hash of the payload as it is NOW
      ChangeRequestStore.findById.mockResolvedValue(submittedRollback({ payload_hash: 'a'.repeat(64) })); // hash fixed at draft time
      policyStore.getPolicy.mockReturnValue({ id: 'p1', currentVersion: 2 });
      await expect(service.approveAndPublishRollback({ requestId: 'req-1', actor: independentApprover }))
        .rejects.toMatchObject({ code: 'PAYLOAD_HASH_MISMATCH' });
      expect(policyStore.rollbackPolicy).not.toHaveBeenCalled();
    });

    test('rejects approval by the rollback requester themselves', async () => {
      ChangeRequestStore.findById.mockResolvedValue(submittedRollback());
      policyStore.getPolicy.mockReturnValue({ id: 'p1', currentVersion: 2 });
      pool.query.mockResolvedValueOnce({ rows: [{ published_by: originalPublisher.id }] });

      await expect(service.approveAndPublishRollback({ requestId: 'req-1', actor: requester }))
        .rejects.toThrow(/requester/i);
      expect(policyStore.rollbackPolicy).not.toHaveBeenCalled();
    });

    test('rejects approval by the original publisher of the version being replaced', async () => {
      ChangeRequestStore.findById.mockResolvedValue(submittedRollback());
      policyStore.getPolicy.mockReturnValue({ id: 'p1', currentVersion: 2 });
      pool.query.mockResolvedValueOnce({ rows: [{ published_by: originalPublisher.id }] });

      await expect(service.approveAndPublishRollback({ requestId: 'req-1', actor: originalPublisher }))
        .rejects.toThrow(/original publisher|activated/i);
      expect(policyStore.rollbackPolicy).not.toHaveBeenCalled();
    });

    test('an independent approver (neither requester nor original publisher) succeeds', async () => {
      ChangeRequestStore.findById.mockResolvedValue(submittedRollback());
      policyStore.getPolicy.mockReturnValue({ id: 'p1', currentVersion: 2 });
      pool.query.mockResolvedValueOnce({ rows: [{ published_by: originalPublisher.id }] });
      policyStore.rollbackPolicy.mockReturnValue({ id: 'p1', currentVersion: 3 });
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(submittedRollback({ status: 'PUBLISHED' }));

      const result = await service.approveAndPublishRollback({ requestId: 'req-1', actor: independentApprover });

      expect(result.changeRequest.status).toBe('PUBLISHED');
      expect(policyStore.rollbackPolicy).toHaveBeenCalledWith('p1', expect.objectContaining({ toVersion: 1 }));
      expect(governanceEvents.recordRollback).toHaveBeenCalledWith(mockTx, expect.objectContaining({
        originalPublisherId: originalPublisher.id, rollbackApprover: independentApprover,
      }));
      expect(provenanceBridge.recordPolicyProvenance).toHaveBeenCalledWith(
        expect.objectContaining({ currentVersion: 3 }), expect.objectContaining({ eventType: 'POLICY_ROLLED_BACK' }),
      );
    });
  });
});
