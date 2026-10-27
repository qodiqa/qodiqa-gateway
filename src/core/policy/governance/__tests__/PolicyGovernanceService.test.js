'use strict';

/**
 * PolicyGovernanceService — test suite (mocked dependencies)
 *
 * Covers: draft-time validation, the full happy path, self-approval /
 * self-review / self-publish rejection, invalid transitions, strict vs.
 * relaxed mode, transactional evidence recording, and that publish() calls
 * the correct store.js mutator per request_type.
 */

describe('PolicyGovernanceService', () => {
  let service;
  let pool;
  let mockTx;
  let ChangeRequestStore;
  let governanceEvents;
  let policyStore;
  let provenanceBridge;
  const ORIGINAL_ENV = process.env;

  function setup({ strict = true } = {}) {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, POLICY_GOVERNANCE_STRICT_MODE: strict ? 'true' : 'false' };

    mockTx = { query: jest.fn() };
    pool = { withTransaction: jest.fn(async (fn) => fn(mockTx)) };
    ChangeRequestStore = {
      create: jest.fn(), findById: jest.fn(), updateStatusInTx: jest.fn(), list: jest.fn(),
    };
    governanceEvents = {
      hashPayload: jest.fn().mockReturnValue('a'.repeat(64)),
      recordEvent: jest.fn().mockResolvedValue({}),
    };
    policyStore = {
      getPolicy: jest.fn(), validatePolicyCandidate: jest.fn().mockReturnValue({ valid: true, errors: [] }),
      createPolicy: jest.fn(), updatePolicy: jest.fn(), setEnabled: jest.fn(),
    };
    provenanceBridge = { recordPolicyProvenance: jest.fn() };

    jest.doMock('../../../../infra/postgres/pool', () => pool);
    jest.doMock('../ChangeRequestStore', () => ChangeRequestStore);
    jest.doMock('../governanceEvents', () => governanceEvents);
    jest.doMock('../../store', () => policyStore);
    jest.doMock('../provenanceBridge', () => provenanceBridge);

    service = require('../PolicyGovernanceService');
  }

  beforeEach(() => setup());
  afterEach(() => { process.env = ORIGINAL_ENV; jest.resetModules(); });

  const author   = { id: 'author-1',   username: 'alice', role: 'operator',   sourceIp: '1.2.3.4' };
  const reviewer = { id: 'reviewer-1', username: 'bob',   role: 'compliance', sourceIp: '1.2.3.4' };
  const approver = { id: 'approver-1', username: 'carol', role: 'compliance', sourceIp: '1.2.3.4' };
  const publisher = { id: 'admin-1',  username: 'dave',  role: 'admin',      sourceIp: '1.2.3.4' };

  function draftRow(overrides = {}) {
    return {
      id: 'req-1', policy_id: 'p1', tenant_id: null, request_type: 'CREATE',
      status: 'DRAFT', version: 1, author_id: author.id, change_reason: 'test change',
      payload: { id: 'p1', type: 'BLOCK_IP', priority: 10, config: {} },
      ...overrides,
    };
  }

  describe('draft()', () => {
    test('CREATE: validates the candidate and rejects a duplicate id', async () => {
      policyStore.getPolicy.mockReturnValue({ id: 'p1' }); // already exists
      await expect(service.draft({
        policyId: 'p1', requestType: 'CREATE', payload: { id: 'p1', type: 'BLOCK_IP', priority: 1, config: {} },
        changeReason: 'x', actor: author,
      })).rejects.toThrow('POLICY_ALREADY_EXISTS');
      expect(ChangeRequestStore.create).not.toHaveBeenCalled();
    });

    test('CREATE: rejects an invalid candidate before creating any request', async () => {
      policyStore.getPolicy.mockReturnValue(null);
      policyStore.validatePolicyCandidate.mockReturnValue({ valid: false, errors: ['type is invalid'] });
      await expect(service.draft({
        policyId: 'p1', requestType: 'CREATE', payload: { id: 'p1', type: 'BOGUS' },
        changeReason: 'x', actor: author,
      })).rejects.toThrow('VALIDATION_FAILED');
      expect(ChangeRequestStore.create).not.toHaveBeenCalled();
    });

    test('CREATE: succeeds and records a DRAFT_CREATED event', async () => {
      policyStore.getPolicy.mockReturnValue(null);
      ChangeRequestStore.create.mockResolvedValue(draftRow());

      const result = await service.draft({
        policyId: 'p1', requestType: 'CREATE', payload: { id: 'p1', type: 'BLOCK_IP', priority: 1, config: {} },
        changeReason: 'x', actor: author,
      });

      expect(result.id).toBe('req-1');
      expect(governanceEvents.recordEvent).toHaveBeenCalledWith(mockTx, expect.objectContaining({ eventType: 'DRAFT_CREATED' }));
    });

    test('F13-GOV-01: the payload is hashed and stored in its JSON form (undefined members dropped), so the publish-time hash check can match', async () => {
      policyStore.getPolicy.mockReturnValue(null);
      ChangeRequestStore.create.mockImplementation(async (row) => ({ id: 'req-1', ...row }));
      await service.draft({
        policyId: 'p9', requestType: 'CREATE',
        payload: { id: 'p9', name: undefined, description: undefined, type: 'BLOCK_IP', priority: 5, config: {} },
        changeReason: 'x', actor: author,
      });
      const row = ChangeRequestStore.create.mock.calls[0][0];
      expect(Object.prototype.hasOwnProperty.call(row.payload, 'name')).toBe(false);
      expect(governanceEvents.hashPayload).toHaveBeenCalledWith(row.payload);
      expect(row.payload).toEqual(JSON.parse(JSON.stringify(row.payload)));
    });

    test('ENABLE/DISABLE: rejects a nonexistent policy id at draft time', async () => {
      policyStore.getPolicy.mockReturnValue(null);
      await expect(service.draft({
        policyId: 'ghost', requestType: 'ENABLE', payload: {}, changeReason: 'x', actor: author,
      })).rejects.toThrow('NOT_FOUND');
    });

    test('UPDATE: merges payload onto the current record for validation', async () => {
      policyStore.getPolicy.mockReturnValue({ id: 'p1', type: 'BLOCK_IP', enabled: true, priority: 5, config: {} });
      ChangeRequestStore.create.mockResolvedValue(draftRow({ request_type: 'UPDATE' }));

      await service.draft({
        policyId: 'p1', requestType: 'UPDATE', payload: { priority: 20 }, changeReason: 'x', actor: author,
      });

      expect(policyStore.validatePolicyCandidate).toHaveBeenCalledWith(
        expect.objectContaining({ priority: 20, type: 'BLOCK_IP' }), 'p1',
      );
    });
  });

  describe('submit()', () => {
    test('DRAFT -> SUBMITTED by the author succeeds', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow());
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));

      const result = await service.submit({ requestId: 'req-1', actor: author });
      expect(result.status).toBe('SUBMITTED');
    });

    test('rejects submission by anyone other than the author', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow());
      await expect(service.submit({ requestId: 'req-1', actor: reviewer }))
        .rejects.toThrow('Only the author may submit');
    });

    test('rejects an invalid transition (already SUBMITTED)', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
      await expect(service.submit({ requestId: 'req-1', actor: author }))
        .rejects.toThrow(service.InvalidTransitionError);
    });
  });

  describe('startReview() / review()', () => {
    test('startReview rejects the author reviewing their own draft', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
      await expect(service.startReview({ requestId: 'req-1', actor: author }))
        .rejects.toThrow('AUTHOR_EQ_REVIEWER'.length ? /reviewer/i : '');
    });

    // the service consults the TRANSITIVE provisioning lineage of the real RBAC records.
    // author-1 creates and keys mid-1 (subordinate), mid-1 creates and keys reviewer-1 → reviewer-1 is not independent.
    test('startReview refuses a reviewer provisioned by an identity the author provisioned (transitive)', async () => {
      const recs = {
        'mid-1':      { id: 'mid-1', createdById: 'author-1', createdBy: 'alice', apiKeyIssuedById: 'author-1', apiKeyIssuedBy: 'alice' },
        'reviewer-1': { id: 'reviewer-1', createdById: 'mid-1', createdBy: 'mallory', apiKeyIssuedById: 'mid-1', apiKeyIssuedBy: 'mallory' },
      };
      const rbac = require('../../../rbac/store');
      const spy = jest.spyOn(rbac, 'getUser').mockImplementation((id) => recs[id] || null);
      try {
        ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
        await expect(service.startReview({ requestId: 'req-1', actor: reviewer }))
          .rejects.toMatchObject({ code: 'MAKER_CHECKER_VIOLATION', rule: 'REVIEWER_PROVISIONED_BY_AUTHOR' });
        // legitimate: the same reviewer provisioned out of band (no lineage to the author) proceeds
        recs['reviewer-1'] = { id: 'reviewer-1', createdById: null, createdBy: 'out-of-band', apiKeyIssuedById: null, apiKeyIssuedBy: 'out-of-band' };
        ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'IN_REVIEW', reviewer_id: reviewer.id }));
        await expect(service.startReview({ requestId: 'req-1', actor: reviewer })).resolves.toMatchObject({ status: 'IN_REVIEW' });
      } finally { spy.mockRestore(); }
    });

    test('startReview succeeds for a different individual', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'IN_REVIEW', reviewer_id: reviewer.id }));
      const result = await service.startReview({ requestId: 'req-1', actor: reviewer });
      expect(result.status).toBe('IN_REVIEW');
    });

    test('review(APPROVED): IN_REVIEW -> REVIEWED, records a policy_reviews row', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'IN_REVIEW', reviewer_id: reviewer.id }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'REVIEWED' }));
      governanceEvents.recordReview = jest.fn().mockResolvedValue({});

      const result = await service.review({ requestId: 'req-1', actor: reviewer, decision: 'APPROVED' });
      expect(result.status).toBe('REVIEWED');
      expect(governanceEvents.recordReview).toHaveBeenCalledWith(mockTx, expect.objectContaining({ decision: 'APPROVED' }));
    });

    test('review(CHANGES_REQUESTED): IN_REVIEW -> DRAFT (sent back for rework)', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'IN_REVIEW', reviewer_id: reviewer.id }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'DRAFT' }));
      governanceEvents.recordReview = jest.fn().mockResolvedValue({});

      const result = await service.review({ requestId: 'req-1', actor: reviewer, decision: 'CHANGES_REQUESTED' });
      expect(result.status).toBe('DRAFT');
    });

    test('review rejects a decider who is not the claimed reviewer', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'IN_REVIEW', reviewer_id: reviewer.id }));
      await expect(service.review({ requestId: 'req-1', actor: approver, decision: 'APPROVED' }))
        .rejects.toThrow('claimed by a different reviewer');
    });

    test('review rejects an invalid decision value', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'IN_REVIEW' }));
      await expect(service.review({ requestId: 'req-1', actor: reviewer, decision: 'MAYBE' }))
        .rejects.toThrow("decision must be 'APPROVED' or 'CHANGES_REQUESTED'");
    });
  });

  describe('approve()', () => {
    test('rejects the author approving their own request', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'REVIEWED', reviewer_id: reviewer.id }));
      await expect(service.approve({ requestId: 'req-1', actor: author }))
        .rejects.toThrow(/approver/i);
    });

    test('strict mode: rejects the reviewer also being the approver', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'REVIEWED', reviewer_id: reviewer.id }));
      await expect(service.approve({ requestId: 'req-1', actor: reviewer }))
        .rejects.toThrow(/reviewer/i);
    });

    test('strict mode: a distinct approver succeeds, records a policy_approvals row', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'REVIEWED', reviewer_id: reviewer.id }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'APPROVED' }));
      governanceEvents.recordApproval = jest.fn().mockResolvedValue({});

      const result = await service.approve({ requestId: 'req-1', actor: approver });
      expect(result.status).toBe('APPROVED');
      expect(governanceEvents.recordApproval).toHaveBeenCalledWith(mockTx, expect.objectContaining({ decision: 'APPROVED' }));
    });

    test('relaxed mode: SUBMITTED -> APPROVED directly is allowed (no prior reviewer)', async () => {
      setup({ strict: false });
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'APPROVED' }));
      governanceEvents.recordApproval = jest.fn().mockResolvedValue({});

      const result = await service.approve({ requestId: 'req-1', actor: approver });
      expect(result.status).toBe('APPROVED');
    });

    test('rejects approving a DRAFT (invalid transition)', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'DRAFT' }));
      await expect(service.approve({ requestId: 'req-1', actor: approver }))
        .rejects.toThrow(service.InvalidTransitionError);
    });
  });

  describe('reject()', () => {
    test('requires a reason', async () => {
      await expect(service.reject({ requestId: 'req-1', actor: approver }))
        .rejects.toThrow('reason is required');
    });

    test('REVIEWED -> REJECTED', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'REVIEWED' }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'REJECTED' }));
      governanceEvents.recordApproval = jest.fn().mockResolvedValue({});

      const result = await service.reject({ requestId: 'req-1', actor: approver, reason: 'not compliant' });
      expect(result.status).toBe('REJECTED');
    });
  });

  describe('schedule()', () => {
    test('rejects a past or missing timestamp', async () => {
      await expect(service.schedule({ requestId: 'req-1', actor: approver, scheduledFor: null }))
        .rejects.toThrow('valid future timestamp');
      await expect(service.schedule({ requestId: 'req-1', actor: approver, scheduledFor: '2000-01-01T00:00:00Z' }))
        .rejects.toThrow('valid future timestamp');
    });

    test('APPROVED -> SCHEDULED with a future timestamp', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'APPROVED' }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'SCHEDULED' }));
      const future = new Date(Date.now() + 3600_000).toISOString();

      const result = await service.schedule({ requestId: 'req-1', actor: approver, scheduledFor: future });
      expect(result.status).toBe('SCHEDULED');
    });
  });

  describe('publish()', () => {
    test('rejects the author publishing their own request', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'APPROVED' }));
      await expect(service.publish({ requestId: 'req-1', actor: author }))
        .rejects.toThrow(/publisher/i);
    });

    // publish() skipped the "not provisioned by the author" check that review/approve apply.
    test('4.3 publish refuses a publisher provisioned by the author (transitive lineage)', async () => {
      const recs = {
        'admin-1': { id: 'admin-1', createdById: 'author-1', createdBy: 'alice', apiKeyIssuedById: 'author-1', apiKeyIssuedBy: 'alice' },
      };
      const rbac = require('../../../rbac/store');
      const spy = jest.spyOn(rbac, 'getUser').mockImplementation((id) => recs[id] || null);
      try {
        ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'APPROVED' }));
        await expect(service.publish({ requestId: 'req-1', actor: publisher }))
          .rejects.toMatchObject({ code: 'MAKER_CHECKER_VIOLATION', rule: 'PUBLISHER_PROVISIONED_BY_AUTHOR' });
        expect(policyStore.createPolicy).not.toHaveBeenCalled();
      } finally { spy.mockRestore(); }
    });

    test('4.3 publish refuses a payload that no longer matches the approved payload_hash, and applies nothing', async () => {
      governanceEvents.hashPayload.mockReturnValueOnce('b'.repeat(64)); // what the stored payload hashes to NOW
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'APPROVED', payload_hash: 'a'.repeat(64) })); // what was approved
      await expect(service.publish({ requestId: 'req-1', actor: publisher })).rejects.toMatchObject({ code: 'PAYLOAD_HASH_MISMATCH' });
      expect(policyStore.createPolicy).not.toHaveBeenCalled();
      expect(policyStore.updatePolicy).not.toHaveBeenCalled();
    });

    test('rejects publishing a SCHEDULED request before its scheduled time', async () => {
      const future = new Date(Date.now() + 3600_000).toISOString();
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SCHEDULED', scheduled_for: future }));
      await expect(service.publish({ requestId: 'req-1', actor: publisher }))
        .rejects.toThrow('NOT_YET_SCHEDULED'.length ? /scheduled time/i : '');
    });

    test('CREATE: calls policyStore.createPolicy and records the publication + provenance', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({
        status: 'APPROVED', payload: { id: 'p1', name: 'X', type: 'BLOCK_IP', priority: 1, config: {} },
      }));
      policyStore.createPolicy.mockReturnValue({ id: 'p1', currentVersion: 1 });
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'PUBLISHED' }));
      governanceEvents.recordPublication = jest.fn().mockResolvedValue({});

      const result = await service.publish({ requestId: 'req-1', actor: publisher });

      expect(policyStore.createPolicy).toHaveBeenCalledWith(expect.objectContaining({ id: 'p1', actor: publisher.username }));
      expect(result.changeRequest.status).toBe('PUBLISHED');
      expect(result.policy.currentVersion).toBe(1);
      expect(provenanceBridge.recordPolicyProvenance).toHaveBeenCalledWith(
        expect.objectContaining({ currentVersion: 1 }), expect.objectContaining({ eventType: 'POLICY_CREATED' }),
      );
    });

    test('UPDATE: calls policyStore.updatePolicy', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'APPROVED', request_type: 'UPDATE', payload: { priority: 20 } }));
      policyStore.updatePolicy.mockReturnValue({ id: 'p1', currentVersion: 2 });
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'PUBLISHED' }));
      governanceEvents.recordPublication = jest.fn().mockResolvedValue({});

      await service.publish({ requestId: 'req-1', actor: publisher });
      expect(policyStore.updatePolicy).toHaveBeenCalledWith('p1', { priority: 20 }, expect.objectContaining({ actor: publisher.username }));
    });

    test('ENABLE: calls policyStore.setEnabled(true)', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'APPROVED', request_type: 'ENABLE', payload: {} }));
      policyStore.setEnabled.mockReturnValue({ id: 'p1', currentVersion: 3 });
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'PUBLISHED' }));
      governanceEvents.recordPublication = jest.fn().mockResolvedValue({});

      await service.publish({ requestId: 'req-1', actor: publisher });
      expect(policyStore.setEnabled).toHaveBeenCalledWith('p1', true, expect.anything());
    });

    test('DISABLE: calls policyStore.setEnabled(false)', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'APPROVED', request_type: 'DISABLE', payload: {} }));
      policyStore.setEnabled.mockReturnValue({ id: 'p1', currentVersion: 4 });
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'PUBLISHED' }));
      governanceEvents.recordPublication = jest.fn().mockResolvedValue({});

      await service.publish({ requestId: 'req-1', actor: publisher });
      expect(policyStore.setEnabled).toHaveBeenCalledWith('p1', false, expect.anything());
    });

    test('rejects publishing a DRAFT (invalid transition)', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'DRAFT' }));
      await expect(service.publish({ requestId: 'req-1', actor: publisher }))
        .rejects.toThrow(service.InvalidTransitionError);
    });
  });

  describe('withdraw()', () => {
    test('author can withdraw their own non-terminal request', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'WITHDRAWN' }));
      const result = await service.withdraw({ requestId: 'req-1', actor: author });
      expect(result.status).toBe('WITHDRAWN');
    });

    test('an admin who is not the author can also withdraw', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
      ChangeRequestStore.updateStatusInTx.mockResolvedValue(draftRow({ status: 'WITHDRAWN' }));
      const result = await service.withdraw({ requestId: 'req-1', actor: publisher }); // publisher.role === 'admin'
      expect(result.status).toBe('WITHDRAWN');
    });

    test('a non-author, non-admin reviewer cannot withdraw someone else\'s request', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'SUBMITTED' }));
      await expect(service.withdraw({ requestId: 'req-1', actor: reviewer }))
        .rejects.toThrow('Only the author or an admin');
    });

    test('rejects withdrawing an already-terminal request', async () => {
      ChangeRequestStore.findById.mockResolvedValue(draftRow({ status: 'PUBLISHED' }));
      await expect(service.withdraw({ requestId: 'req-1', actor: author }))
        .rejects.toThrow('terminal status');
    });
  });
});
