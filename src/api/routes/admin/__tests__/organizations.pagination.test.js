'use strict';

/**
 * GET /v1/admin/organizations — API-1 remediation.
 *
 * Below the safety ceiling, omitting pagination params still returns the
 * full unbounded array (backward compatible). Above the ceiling, pagination
 * is forced even though the caller didn't ask, closing true unbounded
 * enumeration. organizationRegistry is mocked so this doesn't need to
 * actually register 5000+ real organizations.
 */

jest.mock('../../../../core/organizations/organizationRegistry', () => ({
  registerOrganization:    jest.fn(),
  getOrganization:         jest.fn(),
  updateOrganization:      jest.fn(),
  publishOrganizationStatus: jest.fn(),
  assignTenantToOrg:       jest.fn(),
  removeTenantFromOrg:     jest.fn(),
  listOrganizations:       jest.fn(),
}));
jest.mock('../../../../core/tenancy/tenantRegistry', () => ({
  getTenant: jest.fn(), registerTenant: jest.fn(), updateTenant: jest.fn(),
}));
jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

const request = require('supertest');
const express = require('express');
const { createOrganizationsAdminRouter } = require('../organizations');
const { listOrganizations } = require('../../../../core/organizations/organizationRegistry');

function makeApp() {
  const app = express();
  app.use((req, res, next) => { req.requestId = 'test-req-id'; next(); });
  app.use('/v1/admin/organizations', createOrganizationsAdminRouter());
  return app;
}

function makeOrgs(n) {
  return Array.from({ length: n }, (_, i) => ({ organizationId: `org-${i}`, organizationName: `Org ${i}` }));
}

describe('GET /v1/admin/organizations — pagination safety ceiling (API-1)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('under the ceiling, no pagination requested → full unbounded array (unchanged)', async () => {
    listOrganizations.mockReturnValue(makeOrgs(100));

    const res = await request(makeApp()).get('/v1/admin/organizations');

    expect(res.status).toBe(200);
    expect(res.body.data.organizations).toHaveLength(100);
    expect(res.body.data.page).toBeUndefined();
  });

  test('over the ceiling, no pagination requested → pagination is forced anyway', async () => {
    listOrganizations.mockReturnValue(makeOrgs(5001));

    const res = await request(makeApp()).get('/v1/admin/organizations');

    expect(res.status).toBe(200);
    expect(res.body.data.organizations.length).toBeLessThan(5001);
    expect(res.body.data.page).toBe(1);
    expect(res.body.data.totalItems).toBe(5001);
  });

  test('over the ceiling, explicit pagination still works as before', async () => {
    listOrganizations.mockReturnValue(makeOrgs(5001));

    const res = await request(makeApp()).get('/v1/admin/organizations?page=2&pageSize=10');

    expect(res.status).toBe(200);
    expect(res.body.data.organizations).toHaveLength(10);
    expect(res.body.data.page).toBe(2);
  });
});
