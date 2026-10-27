'use strict';

/**
 * API-4 remediation — canonical pagination contract, integration coverage.
 *
 * Complements src/utils/pagination.test.js (pure-utility unit tests) by
 * verifying the utility is correctly WIRED into real route handlers across
 * the three shapes the remediation introduced:
 *
 *   PGI-01…12  Attestation admin/history — canonical page/pageSize/sortOrder
 *              with legacy limit/offset/sortDir/sort aliases, max clamp 500.
 *   PGI-13…20  DSR list — legacy limit/offset primary, canonical page/pageSize
 *              added as new aliases, zod-validated.
 *   PGI-21…28  Organizations list — opt-in pagination over a previously
 *              unbounded in-memory array.
 *
 * Each block covers: canonical params, legacy aliases, boundary conditions,
 * invalid values, maximum page size, empty pages, last-page behavior, and
 * (for the in-memory case) deterministic ordering.
 */

const request = require('supertest');
const express = require('express');

// ── Block A: Attestation admin/history ───────────────────────────────────────

const mockListAttestations = jest.fn();
jest.mock('../../../core/attestation/attestationStore', () => ({
  listAttestations: (...args) => mockListAttestations(...args),
  aggregateStats:   jest.fn(),
}));
jest.mock('../../../../services/artifact/keyManager', () => ({}));
jest.mock('../../../core/verification/portal', () => ({}));
jest.mock('../../../core/rateLimit', () => ({ createRateLimitMiddleware: () => (_r, _s, n) => n() }));

const { createAttestationAdminRouter } = require('../attestation');

function makeAttestationApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  app.use('/v1/attestation', createAttestationAdminRouter({ requirePermission: () => (_r, _s, n) => n() }));
  return app;
}

describe('PGI-01…12 — attestation admin/history (canonical + legacy pagination)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('PGI-01 defaults to page=1, pageSize=50 when nothing supplied', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ page: 1, pageSize: 50, sortOrder: 'desc' }));
  });

  test('PGI-02 canonical page/pageSize/sortOrder are forwarded', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 3, pageSize: 20 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?page=3&pageSize=20&sortOrder=asc');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ page: 3, pageSize: 20, sortOrder: 'asc' }));
  });

  test('PGI-03 legacy limit/offset aliases translate to page/pageSize', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 2, pageSize: 10 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?limit=10&offset=10');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ page: 2, pageSize: 10 }));
  });

  test('PGI-04 legacy sortDir alias translates to sortOrder', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?sortDir=asc');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ sortOrder: 'asc' }));
  });

  test('PGI-05 canonical page/pageSize take precedence over legacy limit/offset', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 5, pageSize: 15 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?page=5&pageSize=15&limit=999&offset=999');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ page: 5, pageSize: 15 }));
  });

  test('PGI-06 pageSize is clamped to the maximum of 500', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 500 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?pageSize=99999');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ pageSize: 500 }));
  });

  test('PGI-07 boundary: page=0 and pageSize=0 are treated as absent (not a clamp to 1) and fall back to defaults', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?page=0&pageSize=0');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ page: 1, pageSize: 50 }));
  });

  test('PGI-08 invalid (non-numeric) page/pageSize fall back to defaults', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?page=abc&pageSize=xyz');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ page: 1, pageSize: 50 }));
  });

  test('PGI-09 invalid sortOrder value falls back to default desc', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
    await request(makeAttestationApp()).get('/v1/attestation/admin/history?sortOrder=sideways');
    expect(mockListAttestations).toHaveBeenCalledWith(expect.objectContaining({ sortOrder: 'desc' }));
  });

  test('PGI-10 empty result set: response carries totalPages 0 and hasNextPage false', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [], total: 0, page: 1, pageSize: 50 });
    const res = await request(makeAttestationApp()).get('/v1/attestation/admin/history');
    expect(res.status).toBe(200);
    expect(res.body.data.total).toBe(0);
    expect(res.body.data.totalItems).toBe(0);
    expect(res.body.data.totalPages).toBe(0);
    expect(res.body.data.hasNextPage).toBe(false);
    expect(res.body.data.hasPreviousPage).toBe(false);
  });

  test('PGI-11 last page: hasNextPage false, hasPreviousPage true', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [{ id: 1 }], total: 21, page: 3, pageSize: 10 });
    const res = await request(makeAttestationApp()).get('/v1/attestation/admin/history?page=3&pageSize=10');
    expect(res.body.data.totalPages).toBe(3);
    expect(res.body.data.hasNextPage).toBe(false);
    expect(res.body.data.hasPreviousPage).toBe(true);
  });

  test('PGI-12 middle page: hasNextPage and hasPreviousPage both true, legacy `total` preserved alongside `totalItems`', async () => {
    mockListAttestations.mockResolvedValue({ attestations: [{ id: 1 }], total: 21, page: 2, pageSize: 10 });
    const res = await request(makeAttestationApp()).get('/v1/attestation/admin/history?page=2&pageSize=10');
    expect(res.body.data.total).toBe(21);
    expect(res.body.data.totalItems).toBe(21);
    expect(res.body.data.hasNextPage).toBe(true);
    expect(res.body.data.hasPreviousPage).toBe(true);
  });
});

// ── Block B: DSR list ─────────────────────────────────────────────────────────

const mockDsrService = { listRequests: jest.fn() };
jest.mock('../../../core/dsr/DataSubjectRightsService', () => mockDsrService);

const { createDsrRouter } = require('../admin/dsr');

function makeDsrApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'tester', role: 'admin' }; next(); });
  app.use('/v1/admin/dsr', createDsrRouter({ requirePermission: undefined }));
  return app;
}

describe('PGI-13…20 — DSR list (legacy limit/offset primary + canonical page/pageSize)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('PGI-13 defaults to limit=50, offset=0 when nothing supplied', async () => {
    mockDsrService.listRequests.mockResolvedValue({ requests: [], total: 0 });
    await request(makeDsrApp()).get('/v1/admin/dsr');
    expect(mockDsrService.listRequests).toHaveBeenCalledWith(expect.objectContaining({ limit: 50, offset: 0 }));
  });

  test('PGI-14 legacy limit/offset still work exactly as before', async () => {
    mockDsrService.listRequests.mockResolvedValue({ requests: [], total: 0 });
    await request(makeDsrApp()).get('/v1/admin/dsr?limit=25&offset=25');
    expect(mockDsrService.listRequests).toHaveBeenCalledWith(expect.objectContaining({ limit: 25, offset: 25 }));
  });

  test('PGI-15 canonical page/pageSize now work as new aliases', async () => {
    mockDsrService.listRequests.mockResolvedValue({ requests: [], total: 0 });
    await request(makeDsrApp()).get('/v1/admin/dsr?page=3&pageSize=10');
    expect(mockDsrService.listRequests).toHaveBeenCalledWith(expect.objectContaining({ limit: 10, offset: 20 }));
  });

  test('PGI-16 canonical page/pageSize take precedence over legacy limit/offset', async () => {
    mockDsrService.listRequests.mockResolvedValue({ requests: [], total: 0 });
    await request(makeDsrApp()).get('/v1/admin/dsr?page=2&pageSize=5&limit=999&offset=999');
    expect(mockDsrService.listRequests).toHaveBeenCalledWith(expect.objectContaining({ limit: 5, offset: 5 }));
  });

  test('PGI-17 canonical pageSize is capped at 200 by schema validation (invalid value -> 400)', async () => {
    const res = await request(makeDsrApp()).get('/v1/admin/dsr?pageSize=500');
    expect(res.status).toBe(400);
  });

  test('PGI-18 legacy limit is accepted with no schema rejection (unlike canonical pageSize) but still effectively capped at 200 — same ceiling as before, now enforced at the route instead of only in the store', async () => {
    mockDsrService.listRequests.mockResolvedValue({ requests: [], total: 0 });
    const res = await request(makeDsrApp()).get('/v1/admin/dsr?limit=500');
    expect(res.status).toBe(200);
    expect(mockDsrService.listRequests).toHaveBeenCalledWith(expect.objectContaining({ limit: 200 }));
  });

  test('PGI-19 response carries canonical metadata (totalItems/totalPages/hasNextPage/hasPreviousPage) alongside legacy total', async () => {
    mockDsrService.listRequests.mockResolvedValue({ requests: [{ id: 1 }], total: 45 });
    const res = await request(makeDsrApp()).get('/v1/admin/dsr?page=1&pageSize=20');
    expect(res.body.data.total).toBe(45);
    expect(res.body.data.totalItems).toBe(45);
    expect(res.body.data.totalPages).toBe(3);
    expect(res.body.data.hasNextPage).toBe(true);
    expect(res.body.data.hasPreviousPage).toBe(false);
  });

  test('PGI-20 empty result set carries totalPages 0 and hasNextPage/hasPreviousPage false', async () => {
    mockDsrService.listRequests.mockResolvedValue({ requests: [], total: 0 });
    const res = await request(makeDsrApp()).get('/v1/admin/dsr');
    expect(res.body.data.totalPages).toBe(0);
    expect(res.body.data.hasNextPage).toBe(false);
    expect(res.body.data.hasPreviousPage).toBe(false);
  });
});

// ── Block C: Organizations list (opt-in pagination, in-memory array) ─────────

const mockListOrganizations = jest.fn();
jest.mock('../../../core/organizations/organizationRegistry', () => ({
  registerOrganization:     jest.fn(),
  getOrganization:          jest.fn(),
  updateOrganization:       jest.fn(),
  publishOrganizationStatus: jest.fn(),
  assignTenantToOrg:        jest.fn(),
  removeTenantFromOrg:      jest.fn(),
  listOrganizations:        (...args) => mockListOrganizations(...args),
}));
jest.mock('../../../core/tenancy/tenantRegistry', () => ({
  getTenant: jest.fn(), registerTenant: jest.fn(), updateTenant: jest.fn(),
}));

const { createOrganizationsAdminRouter } = require('../admin/organizations');

function makeOrgApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req'; next(); });
  app.use('/v1/admin/organizations', createOrganizationsAdminRouter());
  return app;
}

function makeOrgs(n) {
  return Array.from({ length: n }, (_, i) => ({ organizationId: `org-${i}`, organizationName: `Org ${i}` }));
}

describe('PGI-21…28 — organizations list (opt-in pagination over an unbounded array)', () => {
  beforeEach(() => jest.clearAllMocks());

  test('PGI-21 omitting all pagination params preserves the original unbounded response', async () => {
    mockListOrganizations.mockReturnValue(makeOrgs(30));
    const res = await request(makeOrgApp()).get('/v1/admin/organizations');
    expect(res.body.data.organizations).toHaveLength(30);
    expect(res.body.data.total).toBe(30);
    expect(res.body.data.page).toBeUndefined();
    expect(res.body.data.totalPages).toBeUndefined();
  });

  test('PGI-22 supplying page/pageSize switches to sliced output with canonical metadata', async () => {
    mockListOrganizations.mockReturnValue(makeOrgs(30));
    const res = await request(makeOrgApp()).get('/v1/admin/organizations?page=2&pageSize=10');
    expect(res.body.data.organizations).toHaveLength(10);
    expect(res.body.data.organizations[0].organizationId).toBe('org-10');
    expect(res.body.data.total).toBe(30);
    expect(res.body.data.totalItems).toBe(30);
    expect(res.body.data.totalPages).toBe(3);
    expect(res.body.data.hasNextPage).toBe(true);
    expect(res.body.data.hasPreviousPage).toBe(true);
  });

  test('PGI-23 supplying legacy limit/offset also switches to sliced output', async () => {
    mockListOrganizations.mockReturnValue(makeOrgs(30));
    const res = await request(makeOrgApp()).get('/v1/admin/organizations?limit=5&offset=10');
    expect(res.body.data.organizations).toHaveLength(5);
    expect(res.body.data.organizations[0].organizationId).toBe('org-10');
  });

  test('PGI-24 last page returns a partial slice with hasNextPage false', async () => {
    mockListOrganizations.mockReturnValue(makeOrgs(25));
    const res = await request(makeOrgApp()).get('/v1/admin/organizations?page=3&pageSize=10');
    expect(res.body.data.organizations).toHaveLength(5);
    expect(res.body.data.hasNextPage).toBe(false);
    expect(res.body.data.hasPreviousPage).toBe(true);
  });

  test('PGI-25 a page beyond the data range returns an empty slice, not an error', async () => {
    mockListOrganizations.mockReturnValue(makeOrgs(5));
    const res = await request(makeOrgApp()).get('/v1/admin/organizations?page=99&pageSize=10');
    expect(res.status).toBe(200);
    expect(res.body.data.organizations).toEqual([]);
    expect(res.body.data.hasNextPage).toBe(false);
  });

  test('PGI-26 empty backing collection yields totalPages 0', async () => {
    mockListOrganizations.mockReturnValue([]);
    const res = await request(makeOrgApp()).get('/v1/admin/organizations?page=1&pageSize=10');
    expect(res.body.data.organizations).toEqual([]);
    expect(res.body.data.totalItems).toBe(0);
    expect(res.body.data.totalPages).toBe(0);
  });

  test('PGI-27 pageSize is clamped to the maximum of 500', async () => {
    mockListOrganizations.mockReturnValue(makeOrgs(3));
    const res = await request(makeOrgApp()).get('/v1/admin/organizations?pageSize=99999');
    expect(res.body.data.pageSize).toBe(500);
  });

  test('PGI-28 slicing is deterministic across repeated identical requests', async () => {
    const orgs = makeOrgs(17);
    mockListOrganizations.mockReturnValue(orgs);
    const res1 = await request(makeOrgApp()).get('/v1/admin/organizations?page=2&pageSize=5');
    mockListOrganizations.mockReturnValue(orgs);
    const res2 = await request(makeOrgApp()).get('/v1/admin/organizations?page=2&pageSize=5');
    expect(res1.body.data.organizations.map(o => o.organizationId))
      .toEqual(res2.body.data.organizations.map(o => o.organizationId));
    expect(res1.body.data.organizations.map(o => o.organizationId))
      .toEqual(['org-5', 'org-6', 'org-7', 'org-8', 'org-9']);
  });
});
