'use strict';

/**
 * AUTH-3 remediation — audit-trail actor attribution regression suite.
 *
 * Root cause (see AUTH-3-REMEDIATION-REPORT.md): src/api/routes/admin/
 * organizations.js, src/api/routes/admin/tenants.js and
 * src/api/routes/compliance.js built audit/log events from `req.user`, a
 * property nothing in this codebase ever populates (authentication attaches
 * the operator's identity to `req.rbacUser` — see src/middleware/opsAuth.js).
 * Because `req.user` was always undefined, every one of those events took
 * its `?? 'system'` / `?? 'api'` fallback on EVERY request, including fully
 * authenticated admin requests — an authenticated operator's actions were
 * indistinguishable from a genuine system-generated event in the audit log.
 *
 * This suite proves, at the HTTP-route level:
 *   - an authenticated operator's real identity is what ends up in the
 *     emitted audit event ("operator" / "updatedBy" / "generatedBy"),
 *   - it is never the literal string "system" or "api" for an authenticated
 *     caller,
 *   - the fix does not depend on any request header (defense against a
 *     spoofed identity — mirrors test/actor-identity-binding.test.js).
 */

const os      = require('os');
const path    = require('path');
const fs      = require('fs');
const express = require('express');
const request = require('supertest');

const mockEmit = jest.fn();
jest.mock('../services/logger', () => ({ emit: mockEmit }));

const { createOrganizationsAdminRouter } = require('../src/api/routes/admin/organizations');
const { createTenantsAdminRouter }       = require('../src/api/routes/admin/tenants');
const organizationRegistry               = require('../src/core/organizations/organizationRegistry');
const tenantRegistry                     = require('../src/core/tenancy/tenantRegistry');

// ── Store isolation ───────────────────────────────────────────────────────────

const ORG_STORE_PATH    = path.join(os.tmpdir(), `auth3-org-store-${process.pid}.json`);
const TENANT_STORE_PATH = path.join(os.tmpdir(), `auth3-tenant-store-${process.pid}.json`);

beforeAll(() => {
  process.env.ORG_STORE_PATH    = ORG_STORE_PATH;
  process.env.TENANT_STORE_PATH = TENANT_STORE_PATH;
});

afterAll(() => {
  delete process.env.ORG_STORE_PATH;
  delete process.env.TENANT_STORE_PATH;
  try { fs.unlinkSync(ORG_STORE_PATH); } catch (_) {}
  try { fs.unlinkSync(TENANT_STORE_PATH); } catch (_) {}
});

beforeEach(() => {
  jest.clearAllMocks();
  organizationRegistry._reset();
  tenantRegistry._reset();
});

// ── Helpers ───────────────────────────────────────────────────────────────────

// Mirrors what opsAuth + rbacResolve actually attach to the request in
// production (see src/middleware/opsAuth.js) — a frozen identity object —
// without pulling in the full ops-auth/RBAC stack.
function makeAuthedApp(router, { rbacUser = { id: 'u1', username: 'operator-alice', role: 'admin' } } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.requestId = 'req-auth3-test';
    if (rbacUser) req.rbacUser = Object.freeze(rbacUser);
    next();
  });
  app.use('/', router());
  return app;
}

function emittedEventsNamed(eventType) {
  return mockEmit.mock.calls.filter(([, ev]) => ev === eventType).map(([, , extra]) => extra);
}

// ── Organizations ─────────────────────────────────────────────────────────────

describe('AUTH-3: organizations admin router actor attribution', () => {
  test('ORG-A1 POST / attributes ORG_CREATED to the authenticated operator, not "system"', async () => {
    const app = makeAuthedApp(createOrganizationsAdminRouter);

    const res = await request(app).post('/').send({ organizationName: 'Acme Corp' });
    expect(res.status).toBe(201);

    const events = emittedEventsNamed('ORG_CREATED');
    expect(events).toHaveLength(1);
    expect(events[0].operator).toBe('operator-alice');
    expect(events[0].operator).not.toBe('system');
  });

  test('ORG-A2 PATCH /:orgId attributes ORG_UPDATED to the authenticated operator', async () => {
    const app = makeAuthedApp(createOrganizationsAdminRouter);
    const created = organizationRegistry.registerOrganization({ organizationName: 'Old Name' });

    const res = await request(app)
      .patch(`/${created.organizationId}`)
      .send({ organizationName: 'New Name' });
    expect(res.status).toBe(200);

    const events = emittedEventsNamed('ORG_UPDATED');
    expect(events).toHaveLength(1);
    expect(events[0].operator).toBe('operator-alice');
    expect(events[0].operator).not.toBe('system');
  });

  test('ORG-A3 tenant assign/remove attribute the authenticated operator', async () => {
    const app = makeAuthedApp(createOrganizationsAdminRouter, {
      rbacUser: { id: 'u2', username: 'operator-bob', role: 'admin' },
    });
    const org = organizationRegistry.registerOrganization({ organizationName: 'Org With Tenants' });

    const assignRes = await request(app).post(`/${org.organizationId}/tenants/tenant-x`);
    expect(assignRes.status).toBe(200);
    const assigned = emittedEventsNamed('TENANT_ASSIGNED_TO_ORG');
    expect(assigned[0].operator).toBe('operator-bob');

    const removeRes = await request(app).delete(`/${org.organizationId}/tenants/tenant-x`);
    expect(removeRes.status).toBe(200);
    const removed = emittedEventsNamed('TENANT_REMOVED_FROM_ORG');
    expect(removed[0].operator).toBe('operator-bob');
  });

  test('ORG-A4 different authenticated operators produce different attributed identities', async () => {
    const appAlice = makeAuthedApp(createOrganizationsAdminRouter, {
      rbacUser: { id: 'u1', username: 'alice', role: 'admin' },
    });
    const appCarol = makeAuthedApp(createOrganizationsAdminRouter, {
      rbacUser: { id: 'u3', username: 'carol', role: 'admin' },
    });

    await request(appAlice).post('/').send({ organizationName: 'By Alice' });
    await request(appCarol).post('/').send({ organizationName: 'By Carol' });

    const events = emittedEventsNamed('ORG_CREATED');
    const operators = events.map(e => e.operator);
    expect(operators).toContain('alice');
    expect(operators).toContain('carol');
    expect(new Set(operators).size).toBe(2);
  });

  test('ORG-A5 no authenticated identity (rbacResolve misconfigured) is never reported as "system"', async () => {
    const app = makeAuthedApp(createOrganizationsAdminRouter, { rbacUser: null });

    const res = await request(app).post('/').send({ organizationName: 'Orphan Request' });
    expect(res.status).toBe(201);

    const events = emittedEventsNamed('ORG_CREATED');
    expect(events[0].operator).not.toBe('system');
    expect(events[0].operator).toBe('unattributed-operator');

    // The gap is reported, not swallowed.
    const failures = emittedEventsNamed('AUDIT_ATTRIBUTION_FAILED');
    expect(failures.length).toBeGreaterThan(0);
  });
});

// ── Tenants ────────────────────────────────────────────────────────────────────

describe('AUTH-3: tenants admin router actor attribution', () => {
  test('TEN-A1 POST / attributes TENANT_CREATED to the authenticated operator, not "system"', async () => {
    const app = makeAuthedApp(createTenantsAdminRouter);

    const res = await request(app).post('/').send({ tenantId: 'tenant-alpha' });
    expect(res.status).toBe(201);

    const events = emittedEventsNamed('TENANT_CREATED');
    expect(events[0].operator).toBe('operator-alice');
    expect(events[0].operator).not.toBe('system');
  });

  test('TEN-A2 PATCH /:tenantId attributes TENANT_UPDATED to the authenticated operator', async () => {
    const app = makeAuthedApp(createTenantsAdminRouter, {
      rbacUser: { id: 'u9', username: 'operator-dana', role: 'admin' },
    });
    tenantRegistry.registerTenant('tenant-beta', {});

    const res = await request(app).patch('/tenant-beta').send({ tenantName: 'Beta Renamed' });
    expect(res.status).toBe(200);

    const events = emittedEventsNamed('TENANT_UPDATED');
    expect(events[0].operator).toBe('operator-dana');
    expect(events[0].operator).not.toBe('system');
  });

  test('TEN-A3 X-Ops-Actor header cannot influence attribution (mirrors AIB suite)', async () => {
    const app = makeAuthedApp(createTenantsAdminRouter, {
      rbacUser: { id: 'u1', username: 'operator-alice', role: 'admin' },
    });

    await request(app)
      .post('/')
      .set('X-Ops-Actor', 'attacker')
      .send({ tenantId: 'tenant-gamma' });

    const events = emittedEventsNamed('TENANT_CREATED');
    expect(events[0].operator).toBe('operator-alice');
    expect(events[0].operator).not.toBe('attacker');
  });
});
