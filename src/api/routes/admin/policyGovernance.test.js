'use strict';

/**
 * Policy Governance Administration API — route test suite.
 *
 * Mocks the core governance services entirely — business logic is covered
 * by src/core/policy/governance/__tests__/*.test.js. This suite covers:
 * request validation, RBAC gating (using the real permission matrix),
 * response envelope shape, error->HTTP status mapping (including the real
 * MakerCheckerViolationError/ConcurrentModificationError classes), and
 * that _reloadPolicies() is called after every route that touches the live
 * store (publish / rollback-approve / emergency activate/retro-approve/
 * sweep) but never after routes that don't (draft/submit/review/approve).
 */

const mockPolicyGovernanceService = {
  draft: jest.fn(), submit: jest.fn(), startReview: jest.fn(), review: jest.fn(),
  approve: jest.fn(), reject: jest.fn(), schedule: jest.fn(), publish: jest.fn(), withdraw: jest.fn(),
  getRequest: jest.fn(), listRequests: jest.fn(),
};
const mockRollbackGovernanceService = { requestRollback: jest.fn(), approveAndPublishRollback: jest.fn() };
const mockEmergencyPolicyService    = { activate: jest.fn(), retroApprove: jest.fn(), sweepExpired: jest.fn() };
const mockEvidenceGenerator         = { generate: jest.fn() };

jest.mock('../../../core/policy/governance/PolicyGovernanceService', () => mockPolicyGovernanceService);
jest.mock('../../../core/policy/governance/RollbackGovernanceService', () => mockRollbackGovernanceService);
jest.mock('../../../core/policy/governance/EmergencyPolicyService', () => mockEmergencyPolicyService);
jest.mock('../../../core/policy/governance/evidenceGenerator', () => mockEvidenceGenerator);

const request = require('supertest');
const express = require('express');
const { isPermitted } = require('../../../core/rbac/roles');
const { ConcurrentModificationError } = require('../../../core/policy/governance/ChangeRequestStore');
const { MakerCheckerViolationError }  = require('../../../core/policy/governance/makerCheckerRules');
const { createPolicyGovernanceRouter } = require('./policyGovernance');

function makeApp({ role = 'admin', reloadPolicies } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'tester', role }; req.clientIp = '9.9.9.9'; next(); });

  const requirePermission = (permission) => (req, res, next) => {
    if (!isPermitted(req.rbacUser?.role, permission)) {
      return res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions' });
    }
    next();
  };

  app.use('/v1/policy/governance', createPolicyGovernanceRouter({ requirePermission, _reloadPolicies: reloadPolicies }));
  return app;
}

const UUID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

beforeEach(() => jest.clearAllMocks());

describe('RBAC gating (real permission matrix)', () => {
  test('operator can propose (PROPOSE_POLICY_CHANGE) but not publish (PUBLISH_POLICY_CHANGE)', async () => {
    const app = makeApp({ role: 'operator' });
    mockPolicyGovernanceService.draft.mockResolvedValue({ id: UUID, status: 'DRAFT' });

    await request(app).post('/v1/policy/governance/draft')
      .send({ policyId: 'p1', requestType: 'CREATE', changeReason: 'x' }).expect(201);
    await request(app).post(`/v1/policy/governance/${UUID}/publish`).send({}).expect(403);
  });

  test('viewer role has no policy-governance permissions at all', async () => {
    const app = makeApp({ role: 'viewer' });
    await request(app).get('/v1/policy/governance').expect(403);
  });

  test('auditor can review (REVIEW_POLICY_CHANGE) but not approve (APPROVE_POLICY_CHANGE)', async () => {
    const app = makeApp({ role: 'auditor' });
    mockPolicyGovernanceService.getRequest.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });
    mockPolicyGovernanceService.review.mockResolvedValue({ id: UUID, status: 'REVIEWED' });

    await request(app).post(`/v1/policy/governance/${UUID}/review`).send({ decision: 'APPROVED' }).expect(200);
    await request(app).post(`/v1/policy/governance/${UUID}/approve`).send({}).expect(403);
  });

  test('only admin holds EMERGENCY_POLICY_OVERRIDE', async () => {
    const app = makeApp({ role: 'compliance' });
    await request(app).post('/v1/policy/governance/emergency/activate')
      .send({ policyId: 'p1', requestType: 'ENABLE', incidentReference: 'INC-1', justification: 'x' }).expect(403);
  });
});

describe('GET / and GET /:id', () => {
  test('lists requests with the success envelope', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.listRequests.mockResolvedValue({ requests: [{ id: UUID }], total: 1 });
    const res = await request(app).get('/v1/policy/governance').expect(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.requests).toHaveLength(1);
  });

  test('404s when the request does not exist', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.getRequest.mockResolvedValue(null);
    const res = await request(app).get(`/v1/policy/governance/${UUID}`).expect(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('rejects a non-UUID id', async () => {
    const app = makeApp();
    await request(app).get('/v1/policy/governance/not-a-uuid').expect(400);
  });

  test('GET /:id/evidence returns the evidence package', async () => {
    const app = makeApp();
    mockEvidenceGenerator.generate.mockResolvedValue({ changeRequest: { id: UUID }, hashChainIntegrity: { valid: true } });
    const res = await request(app).get(`/v1/policy/governance/${UUID}/evidence`).expect(200);
    expect(res.body.data.hashChainIntegrity.valid).toBe(true);
  });
});

describe('POST /draft', () => {
  test('rejects a missing changeReason', async () => {
    const app = makeApp();
    const res = await request(app).post('/v1/policy/governance/draft')
      .send({ policyId: 'p1', requestType: 'CREATE' }).expect(400);
    expect(res.body.error.code).toBe('INVALID_BODY');
  });

  test('rejects an unknown requestType', async () => {
    const app = makeApp();
    await request(app).post('/v1/policy/governance/draft')
      .send({ policyId: 'p1', requestType: 'DESTROY', changeReason: 'x' }).expect(400);
  });

  test('item 9 audit: rejects an unrecognised extra body key (draftSchema was .passthrough(), now .strict())', async () => {
    const app = makeApp();
    const res = await request(app).post('/v1/policy/governance/draft')
      .send({ policyId: 'p1', requestType: 'CREATE', changeReason: 'x', unexpectedKey: 'nope' })
      .expect(400);
    expect(res.body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: null,
      error:     { code: 'INVALID_BODY', message: expect.any(String) },
    });
    expect(mockPolicyGovernanceService.draft).not.toHaveBeenCalled();
  });
});

describe('reload wiring — only routes that touch the live store call _reloadPolicies()', () => {
  test('publish calls _reloadPolicies() after a successful store mutation', async () => {
    const reloadPolicies = jest.fn();
    const app = makeApp({ reloadPolicies });
    mockPolicyGovernanceService.publish.mockResolvedValue({ changeRequest: { id: UUID, status: 'PUBLISHED' }, policy: {} });

    await request(app).post(`/v1/policy/governance/${UUID}/publish`).send({}).expect(200);
    expect(reloadPolicies).toHaveBeenCalledTimes(1);
  });

  test('publish returns RELOAD_FAILED (500) if reload throws, without masking that the mutation already happened', async () => {
    const reloadPolicies = jest.fn(() => { throw new Error('policies.json corrupt'); });
    const app = makeApp({ reloadPolicies });
    mockPolicyGovernanceService.publish.mockResolvedValue({ changeRequest: { id: UUID, status: 'PUBLISHED' }, policy: {} });

    const res = await request(app).post(`/v1/policy/governance/${UUID}/publish`).send({}).expect(500);
    expect(res.body.error.code).toBe('RELOAD_FAILED');
  });

  test('submit does NOT call _reloadPolicies() — nothing was mutated in the live store', async () => {
    const reloadPolicies = jest.fn();
    const app = makeApp({ reloadPolicies });
    mockPolicyGovernanceService.submit.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });

    await request(app).post(`/v1/policy/governance/${UUID}/submit`).send({}).expect(200);
    expect(reloadPolicies).not.toHaveBeenCalled();
  });

  test('rollback/approve calls _reloadPolicies()', async () => {
    const reloadPolicies = jest.fn();
    const app = makeApp({ reloadPolicies });
    mockRollbackGovernanceService.approveAndPublishRollback.mockResolvedValue({ changeRequest: { id: UUID, status: 'PUBLISHED' } });

    await request(app).post(`/v1/policy/governance/${UUID}/rollback/approve`).send({}).expect(200);
    expect(reloadPolicies).toHaveBeenCalledTimes(1);
  });

  test('emergency/activate calls _reloadPolicies()', async () => {
    const reloadPolicies = jest.fn();
    const app = makeApp({ reloadPolicies });
    mockEmergencyPolicyService.activate.mockResolvedValue({ changeRequest: { id: UUID }, emergency: {}, policy: {} });

    await request(app).post('/v1/policy/governance/emergency/activate')
      .send({ policyId: 'p1', requestType: 'ENABLE', incidentReference: 'INC-1', justification: 'x' }).expect(201);
    expect(reloadPolicies).toHaveBeenCalledTimes(1);
  });

  test('emergency/sweep-expired only reloads when something was actually swept', async () => {
    const reloadPolicies = jest.fn();
    const app = makeApp({ reloadPolicies });
    mockEmergencyPolicyService.sweepExpired.mockResolvedValue({ swept: 0, ids: [] });

    await request(app).post('/v1/policy/governance/emergency/sweep-expired').expect(200);
    expect(reloadPolicies).not.toHaveBeenCalled();
  });
});

describe('error -> HTTP status mapping', () => {
  test('MakerCheckerViolationError maps to 403 with its rule code', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.approve.mockRejectedValue(new MakerCheckerViolationError('nope', 'AUTHOR_EQ_APPROVER'));

    const res = await request(app).post(`/v1/policy/governance/${UUID}/approve`).send({}).expect(403);
    expect(res.body.error.code).toBe('AUTHOR_EQ_APPROVER');
  });

  test('ConcurrentModificationError maps to 409', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.approve.mockRejectedValue(new ConcurrentModificationError(UUID));

    const res = await request(app).post(`/v1/policy/governance/${UUID}/approve`).send({}).expect(409);
    expect(res.body.error.code).toBe('CONCURRENT_MODIFICATION');
  });

  test('InvalidTransitionError-shaped error (code INVALID_TRANSITION) maps to 409', async () => {
    const app = makeApp();
    const err = new Error('bad transition'); err.code = 'INVALID_TRANSITION';
    mockPolicyGovernanceService.publish.mockRejectedValue(err);

    const res = await request(app).post(`/v1/policy/governance/${UUID}/publish`).send({}).expect(409);
    expect(res.body.error.code).toBe('INVALID_TRANSITION');
  });

  test('NOT_FOUND maps to 404', async () => {
    const app = makeApp();
    const err = new Error('gone'); err.code = 'NOT_FOUND';
    mockPolicyGovernanceService.withdraw.mockRejectedValue(err);

    await request(app).post(`/v1/policy/governance/${UUID}/withdraw`).send({}).expect(404);
  });

  test('unclassified failure routes through the centralized handler: 500, sanitized envelope, byte-exact', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.reject.mockRejectedValue(new Error('unexpected'));

    const res = await request(app).post(`/v1/policy/governance/${UUID}/reject`).send({ reason: 'x' }).expect(500);
    expect(res.body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: null,
      error:     { code: 'POLICY_GOVERNANCE_OPERATION_FAILED', message: 'An unexpected error occurred' },
    });
  });

  test('unclassified failure never leaks err.message, driver/SQL internals, or a stack trace to the client', async () => {
    const app = makeApp();
    const sensitive = new Error(
      'connection to 10.0.0.7:5432 failed: password authentication failed for user "qodiqa_app" ' +
      'at Object.query (/src/core/policy/governance/ChangeRequestStore.js:212:9)',
    );
    mockPolicyGovernanceService.publish.mockRejectedValue(sensitive);

    const res = await request(app).post(`/v1/policy/governance/${UUID}/publish`).send({}).expect(500);

    const raw = JSON.stringify(res.body);
    expect(raw).not.toContain('10.0.0.7');
    expect(raw).not.toContain('password authentication failed');
    expect(raw).not.toContain('ChangeRequestStore.js');
    expect(raw).not.toContain('qodiqa_app');
    expect(res.body.error.message).toBe('An unexpected error occurred');
    expect(res.body.error.stack).toBeUndefined();
  });

  test('classified errors (maker-checker, concurrency, state-machine) still surface their deliberate, safe domain message (unchanged)', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.approve.mockRejectedValue(new MakerCheckerViolationError('author cannot approve their own change', 'AUTHOR_EQ_APPROVER'));
    const res = await request(app).post(`/v1/policy/governance/${UUID}/approve`).send({}).expect(403);
    expect(res.body.error.message).toBe('author cannot approve their own change');
  });
});

describe('full lifecycle happy path (mocked services)', () => {
  test('draft -> submit -> review -> approve -> publish', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.draft.mockResolvedValue({ id: UUID, status: 'DRAFT' });
    mockPolicyGovernanceService.submit.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });
    mockPolicyGovernanceService.getRequest.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });
    mockPolicyGovernanceService.review.mockResolvedValue({ id: UUID, status: 'REVIEWED' });
    mockPolicyGovernanceService.approve.mockResolvedValue({ id: UUID, status: 'APPROVED' });
    mockPolicyGovernanceService.publish.mockResolvedValue({ changeRequest: { id: UUID, status: 'PUBLISHED' }, policy: {} });

    await request(app).post('/v1/policy/governance/draft')
      .send({ policyId: 'p1', requestType: 'CREATE', changeReason: 'x' }).expect(201);
    await request(app).post(`/v1/policy/governance/${UUID}/submit`).send({}).expect(200);
    await request(app).post(`/v1/policy/governance/${UUID}/review`).send({ decision: 'APPROVED' }).expect(200);
    await request(app).post(`/v1/policy/governance/${UUID}/approve`).send({}).expect(200);
    const publishRes = await request(app).post(`/v1/policy/governance/${UUID}/publish`).send({}).expect(200);
    expect(publishRes.body.data.changeRequest.status).toBe('PUBLISHED');
  });

  test('POST /:id/review auto-claims (startReview) when status is SUBMITTED', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.getRequest.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });
    mockPolicyGovernanceService.startReview.mockResolvedValue({ id: UUID, status: 'IN_REVIEW' });
    mockPolicyGovernanceService.review.mockResolvedValue({ id: UUID, status: 'REVIEWED' });

    await request(app).post(`/v1/policy/governance/${UUID}/review`).send({ decision: 'APPROVED' }).expect(200);
    expect(mockPolicyGovernanceService.startReview).toHaveBeenCalledTimes(1);
  });

  test('POST /:id/review does NOT re-claim when already IN_REVIEW', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.getRequest.mockResolvedValue({ id: UUID, status: 'IN_REVIEW' });
    mockPolicyGovernanceService.review.mockResolvedValue({ id: UUID, status: 'REVIEWED' });

    await request(app).post(`/v1/policy/governance/${UUID}/review`).send({ decision: 'APPROVED' }).expect(200);
    expect(mockPolicyGovernanceService.startReview).not.toHaveBeenCalled();
  });

  test('rollback request then approve', async () => {
    const app = makeApp();
    mockRollbackGovernanceService.requestRollback.mockResolvedValue({ changeRequest: { id: UUID, status: 'SUBMITTED' }, fromVersion: 2, toVersion: 1 });
    mockRollbackGovernanceService.approveAndPublishRollback.mockResolvedValue({ changeRequest: { id: UUID, status: 'PUBLISHED' } });

    await request(app).post('/v1/policy/governance/rollback')
      .send({ policyId: 'p1', toVersion: 1, reason: 'bad deploy' }).expect(201);
    await request(app).post(`/v1/policy/governance/${UUID}/rollback/approve`).send({}).expect(200);
  });

  test('emergency activate then retro-approve', async () => {
    const app = makeApp();
    mockEmergencyPolicyService.activate.mockResolvedValue({ changeRequest: { id: UUID }, emergency: { id: UUID }, policy: {} });
    mockEmergencyPolicyService.retroApprove.mockResolvedValue({ emergency: { id: UUID, retrospective_status: 'APPROVED' } });

    await request(app).post('/v1/policy/governance/emergency/activate')
      .send({ policyId: 'p1', requestType: 'ENABLE', incidentReference: 'INC-1', justification: 'outage' }).expect(201);
    await request(app).post(`/v1/policy/governance/emergency/${UUID}/retro-approve`)
      .send({ decision: 'APPROVED' }).expect(200);
  });
});

describe('405 catch-all', () => {
  test('unsupported method under the mount is rejected', async () => {
    const app = makeApp();
    await request(app).delete(`/v1/policy/governance/${UUID}`).expect(405);
  });
});
