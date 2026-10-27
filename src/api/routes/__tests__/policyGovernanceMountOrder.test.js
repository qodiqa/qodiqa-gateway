'use strict';

/**
 * src/app.js mount-order regression coverage.
 *
 * /v1/policy (policySimulateRouter + policyVisualRouter) is a strict prefix
 * of /v1/policy/governance. Express tries app.use() mounts in registration
 * order and stops at the first one that responds — mounting the broad
 * /v1/policy prefix before /v1/policy/governance let policySimulateRouter's
 * own next-less 405 catch-all (policySimulate.js's
 * `router.use((req, res) => ...)`, no `next` param) swallow every
 * /v1/policy/governance/* request before the governance router was ever
 * reached ( and the S6 premise
 * correction on /policy-ui's own governance dependency).
 *
 * Fixed by reordering the two mount blocks in src/app.js — the governance
 * mount now comes first. This suite guards that order two ways: a static
 * source-position check (fails loudly with no Express boot required if
 * anyone reorders the lines back), and a live multi-mount topology test
 * reproducing both routers co-mounted in the app.js order.
 */

const fs      = require('fs');
const path    = require('path');
const express = require('express');
const request = require('supertest');

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

const { isPermitted }                = require('../../../core/rbac/roles');
const { createPolicyGovernanceRouter } = require('../admin/policyGovernance');
const { createPolicySimulateRouter }   = require('../policySimulate');

beforeEach(() => jest.clearAllMocks());

describe('(static regression guard) — src/app.js mounts /v1/policy/governance before /v1/policy', () => {
  test('the governance mount line appears before the policy-simulate mount line', () => {
    const appSrc = fs.readFileSync(path.join(__dirname, '../../../app.js'), 'utf8');

    const governanceIdx = appSrc.indexOf("app.use('/v1/policy/governance'");
    const policyIdx      = appSrc.indexOf("app.use('/v1/policy'");

    expect(governanceIdx).toBeGreaterThan(-1);
    expect(policyIdx).toBeGreaterThan(-1);
    expect(governanceIdx).toBeLessThan(policyIdx);
  });
});

describe('(live multi-mount topology) — governance and simulate routers co-mounted in the fixed app.js order', () => {
  // Same order as the fixed src/app.js: governance mounted before the
  // broader /v1/policy prefix. Swap these two app.use() calls and the
  // "governance reachable" test below fails — that is the regression this
  // suite exists to catch.
  function makeMultiMountApp({ role = 'operator' } = {}) {
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'tester', role }; req.clientIp = '9.9.9.9'; next(); });

    const requirePermission = (permission) => (req, res, next) => {
      if (!isPermitted(req.rbacUser?.role, permission)) {
        return res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions' });
      }
      next();
    };

    app.use('/v1/policy/governance', createPolicyGovernanceRouter({ requirePermission }));
    app.use('/v1/policy', createPolicySimulateRouter(() => [], null));
    return app;
  }

  test('POST /v1/policy/governance/draft reaches the governance handler, not the 405 catch-all', async () => {
    const app = makeMultiMountApp();
    mockPolicyGovernanceService.draft.mockResolvedValue({ id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', status: 'DRAFT' });

    const res = await request(app)
      .post('/v1/policy/governance/draft')
      .send({ policyId: 'p1', requestType: 'CREATE', changeReason: 'x' });

    expect(res.status).not.toBe(405);
    expect(res.body?.error?.message).not.toBe('Method not allowed');
    expect(res.status).toBe(201);
    expect(mockPolicyGovernanceService.draft).toHaveBeenCalledTimes(1);
  });

  test('GET /v1/policy/governance (list) reaches the governance handler, not the 405 catch-all', async () => {
    const app = makeMultiMountApp();
    mockPolicyGovernanceService.listRequests.mockReturnValue([]);

    const res = await request(app).get('/v1/policy/governance');

    expect(res.status).not.toBe(405);
    expect(res.status).toBe(200);
  });

  test('POST /v1/policy/simulate still reaches the simulate handler when co-mounted with governance (fix does not break the broader prefix)', async () => {
    const app = makeMultiMountApp();

    const res = await request(app)
      .post('/v1/policy/simulate')
      .send({ context: { ip: '1.2.3.4', timestamp: 1736164800 } });

    expect(res.status).not.toBe(405);
    expect(res.body?.status).toBe('success');
  });
});
