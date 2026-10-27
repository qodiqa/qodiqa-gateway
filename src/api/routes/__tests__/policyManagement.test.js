'use strict';

/**
 * Policy Management UI Router — test suite.
 *
 * focus: the five write routes (POST/PUT /policies, /enable,
 * /disable, /rollback) must never activate anything directly anymore —
 * they must create a governed change request via
 * PolicyGovernanceService/RollbackGovernanceService and return it. This
 * suite is the only direct coverage of that repointing (the underlying
 * services have their own thorough unit tests under
 * src/core/policy/governance/__tests__/).
 */

const mockStore = {
  getDashboard: jest.fn(), listPolicies: jest.fn(), getPolicy: jest.fn(),
  getVersions: jest.fn(), getVersion: jest.fn(), getHistory: jest.fn(),
  validatePolicyCandidate: jest.fn().mockReturnValue({ valid: true, errors: [], warnings: [], score: 100 }),
};
const mockPolicyGovernanceService = { draft: jest.fn(), submit: jest.fn() };
const mockRollbackGovernanceService = { requestRollback: jest.fn() };

jest.mock('../../../core/policy/store', () => mockStore);
jest.mock('../../../core/policy/governance/PolicyGovernanceService', () => mockPolicyGovernanceService);
jest.mock('../../../core/policy/governance/RollbackGovernanceService', () => mockRollbackGovernanceService);

const request = require('supertest');
const express = require('express');
const createPolicyManagementRouter = require('../policyManagement');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'tester', role: 'admin' }; req.clientIp = '9.9.9.9'; next(); });
  app.use('/policy-ui', createPolicyManagementRouter({}));
  return app;
}

const UUID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

beforeEach(() => jest.clearAllMocks());

describe('POST /policies — creates a change request, never activates', () => {
  test('drafts and auto-submits instead of calling store.createPolicy directly', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.draft.mockResolvedValue({ id: UUID, status: 'DRAFT' });
    mockPolicyGovernanceService.submit.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });

    const res = await request(app)
      .post('/policy-ui/policies')
      .send({ id: 'p1', type: 'BLOCK_IP', priority: 10, config: {}, changeReason: 'add new policy' })
      .expect(201);

    expect(mockPolicyGovernanceService.draft).toHaveBeenCalledWith(expect.objectContaining({
      policyId: 'p1', requestType: 'CREATE', changeReason: 'add new policy',
    }));
    expect(mockPolicyGovernanceService.submit).toHaveBeenCalled();
    expect(res.body.data.changeRequest.status).toBe('SUBMITTED');
    // The response must never claim the policy itself was returned/activated.
    expect(res.body.data.policy).toBeUndefined();
    expect(res.body.data.message).toMatch(/submitted for review/i);
  });

  test('rejects a missing changeReason before ever calling the governance service', async () => {
    // API-9 remediation: a missing required field is a schema-shape failure,
    // not a business-rule violation — now 400, not 422.
    const app = makeApp();
    await request(app).post('/policy-ui/policies').send({ id: 'p1', type: 'BLOCK_IP' }).expect(400);
    expect(mockPolicyGovernanceService.draft).not.toHaveBeenCalled();
  });

  test('propagates VALIDATION_FAILED from draft() as 422', async () => {
    const app = makeApp();
    const err = new Error('VALIDATION_FAILED: bad type'); err.code = 'VALIDATION_FAILED';
    mockPolicyGovernanceService.draft.mockRejectedValue(err);

    await request(app).post('/policy-ui/policies')
      .send({ id: 'p1', type: 'BOGUS', changeReason: 'x' }).expect(422);
  });
});

describe('PUT /policies/:policyId — creates an UPDATE change request', () => {
  test('never calls store.updatePolicy directly', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.draft.mockResolvedValue({ id: UUID, status: 'DRAFT' });
    mockPolicyGovernanceService.submit.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });

    await request(app)
      .put('/policy-ui/policies/p1')
      .send({ priority: 20, changeReason: 'raise priority' })
      .expect(200);

    expect(mockPolicyGovernanceService.draft).toHaveBeenCalledWith(expect.objectContaining({
      policyId: 'p1', requestType: 'UPDATE', payload: { priority: 20 },
    }));
  });
});

describe('POST /policies/:policyId/enable — no direct activation path survives', () => {
  test('creates a governed ENABLE change request instead of enabling anything', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.draft.mockResolvedValue({ id: UUID, status: 'DRAFT' });
    mockPolicyGovernanceService.submit.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });

    const res = await request(app)
      .post('/policy-ui/policies/p1/enable')
      .send({ changeReason: 'turn it on' })
      .expect(200);

    expect(mockPolicyGovernanceService.draft).toHaveBeenCalledWith(expect.objectContaining({ requestType: 'ENABLE' }));
    expect(res.body.data.changeRequest.status).toBe('SUBMITTED');
    expect(res.body.data.message).toMatch(/not been enabled yet/i);
  });
});

describe('POST /policies/:policyId/disable', () => {
  test('creates a governed DISABLE change request', async () => {
    const app = makeApp();
    mockPolicyGovernanceService.draft.mockResolvedValue({ id: UUID, status: 'DRAFT' });
    mockPolicyGovernanceService.submit.mockResolvedValue({ id: UUID, status: 'SUBMITTED' });

    await request(app).post('/policy-ui/policies/p1/disable').send({ changeReason: 'incident' }).expect(200);
    expect(mockPolicyGovernanceService.draft).toHaveBeenCalledWith(expect.objectContaining({ requestType: 'DISABLE' }));
  });
});

describe('POST /policies/:policyId/rollback — creates a governed rollback request', () => {
  test('delegates to RollbackGovernanceService.requestRollback(), never applies immediately', async () => {
    const app = makeApp();
    mockRollbackGovernanceService.requestRollback.mockResolvedValue({
      changeRequest: { id: UUID, status: 'SUBMITTED' }, fromVersion: 3, toVersion: 1,
    });

    const res = await request(app)
      .post('/policy-ui/policies/p1/rollback')
      .send({ toVersion: 1, changeReason: 'bad deploy' })
      .expect(200);

    expect(mockRollbackGovernanceService.requestRollback).toHaveBeenCalledWith(expect.objectContaining({
      policyId: 'p1', toVersion: 1, reason: 'bad deploy',
    }));
    expect(res.body.data.changeRequest.status).toBe('SUBMITTED');
    expect(res.body.data.message).toMatch(/not been applied yet/i);
  });

  test('requires a changeReason', async () => {
    // API-9 remediation: 400, not 422 — see the POST /policies test above.
    const app = makeApp();
    await request(app).post('/policy-ui/policies/p1/rollback').send({ toVersion: 1 }).expect(400);
    expect(mockRollbackGovernanceService.requestRollback).not.toHaveBeenCalled();
  });
});

describe('read routes are unaffected', () => {
  test('GET /dashboard still reads directly from the store', async () => {
    const app = makeApp();
    mockStore.getDashboard.mockReturnValue({ total: 5 });
    const res = await request(app).get('/policy-ui/dashboard').expect(200);
    expect(res.body.data.total).toBe(5);
  });

  test('GET /policies/:policyId still reads directly from the store', async () => {
    const app = makeApp();
    mockStore.getPolicy.mockReturnValue({ id: 'p1' });
    const res = await request(app).get('/policy-ui/policies/p1').expect(200);
    expect(res.body.data.policy.id).toBe('p1');
  });
});
