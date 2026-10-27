'use strict';

/**
 * (Findings Register): organizationId supplied at tenant creation is
 * stored/echoed but does NOT call assignTenantToOrg() — enforcement stays
 * inert until POST /v1/admin/organizations/:orgId/tenants/:tenantId is also
 * called. approved decision (Option B): keep the field decorative at
 * creation time, but make the gap loud via a WARN, not silent.
 */

jest.mock('../../../../core/tenancy/tenantRegistry', () => ({
  registerTenant: jest.fn(),
  getTenant:      jest.fn(),
  updateTenant:   jest.fn(),
  listTenants:    jest.fn(),
}));
jest.mock('../../../../core/organizations/organizationRegistry', () => ({
  getOrganizationForTenant: jest.fn(),
}));
jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

const request = require('supertest');
const express = require('express');
const { createTenantsAdminRouter } = require('../tenants');
const { registerTenant }           = require('../../../../core/tenancy/tenantRegistry');
const { emit }                     = require('../../../../../services/logger');

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.requestId = 'test-req-id'; next(); });
  app.use('/v1/admin/tenants', createTenantsAdminRouter());
  return app;
}

function warnCalls(code) {
  return emit.mock.calls.filter(([level, c]) => level === 'WARN' && c === code);
}

describe('POST /v1/admin/tenants — TENANT_ORG_NOT_ENFORCEMENT_LINKED', () => {
  beforeEach(() => jest.clearAllMocks());

  test('organizationId supplied → WARN fires with tenantId + organizationId', async () => {
    registerTenant.mockReturnValue({ tenantId: 'tenant-1', organizationId: 'org-1' });

    const res = await request(makeApp())
      .post('/v1/admin/tenants')
      .send({ tenantId: 'tenant-1', organizationId: 'org-1' });

    expect(res.status).toBe(201);
    const calls = warnCalls('TENANT_ORG_NOT_ENFORCEMENT_LINKED');
    expect(calls).toHaveLength(1);
    expect(calls[0][2]).toMatchObject({ tenantId: 'tenant-1', organizationId: 'org-1' });
  });

  test('organizationId absent → WARN does not fire', async () => {
    registerTenant.mockReturnValue({ tenantId: 'tenant-2' });

    const res = await request(makeApp())
      .post('/v1/admin/tenants')
      .send({ tenantId: 'tenant-2' });

    expect(res.status).toBe(201);
    expect(warnCalls('TENANT_ORG_NOT_ENFORCEMENT_LINKED')).toHaveLength(0);
  });
});
