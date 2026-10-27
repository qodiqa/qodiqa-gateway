'use strict';

// the code under test reads the monotonic clock (src/infra/time/monotonicClock.js), which jest fake timers
// and Date.now spies do not move. Point it at Date.now so this suite keeps driving time the way it always has; the
// monotonic behaviour itself is pinned by src/infra/time/__tests__/monotonicSites.test.js.
jest.mock('../../../infra/time/monotonicClock', () => ({ monoNowMs: () => Date.now(), wallFromMono: (m) => m || null }));

// control-plane core, without a database (the PostgreSQL behaviour
// is proven on a real database by test/integration/controlPlanePg.integration.test.js).
//   CPU-01  backend resolution: production is always pg; pg is explicit opt-in elsewhere
//   CPU-02  pg mode (faked pool): reads answer from a fresh snapshot; past 5 s without a
//           successful pull every read is refused (CONTROL_PLANE_STALE, 503)
//   CPU-03  a write naming a stale version is refused (409) and the snapshot is unchanged
//   CPU-04  the staleness bound can be tightened, never loosened past 5 s
//   CPU-05  notifier messages: MAC-signed; unsigned / tampered / malformed ones are rejected
//   CPU-06  memory mode never writes a file, for any store mutation

const fs = require('fs');

describe('control-plane core', () => {
  afterEach(async () => {
    const cp = require('../index');
    cp._setPoolForTest(null);
    await cp._resetForTest();
    delete process.env.QODIQA_CONTROL_PLANE_MAX_STALENESS_MS;
    process.env.QODIQA_CONTROL_PLANE_BACKEND = 'memory';
    jest.restoreAllMocks();
  });

  test('CPU-01 backend resolution', () => {
    const { resolveBackend } = require('../index');
    expect(resolveBackend({ NODE_ENV: 'production' })).toBe('pg');
    expect(resolveBackend({ NODE_ENV: 'production', QODIQA_CONTROL_PLANE_BACKEND: 'memory' })).toBe('pg');
    expect(resolveBackend({ NODE_ENV: 'development' })).toBe('memory');
    expect(resolveBackend({ NODE_ENV: 'development', QODIQA_PG_ENABLED: 'true', QODIQA_PG_CONTROL_PASSWORD: 'x' })).toBe('memory');
    expect(resolveBackend({ NODE_ENV: 'test', QODIQA_CONTROL_PLANE_BACKEND: 'pg' })).toBe('pg');
  });

  function fakePool(rows) {
    const calls = [];
    return {
      calls,
      fail: false,
      conflict: false,
      async query(sql, params) {
        calls.push(sql.trim().split(/\s+/)[0]);
        if (this.fail) { const e = new Error('ECONNREFUSED'); e.code = 'ECONNREFUSED'; throw e; }
        if (/^SELECT s\.horizon/m.test(sql.trim())) return { rows: rows.splice(0).map((r) => ({ horizon: '10', ...r })).concat([{ horizon: '10', store: null }]) };
        if (/^UPDATE control_plane_records\s+SET data/m.test(sql.trim())) return this.conflict ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ version: String(Number(params[5]) + 1) }] };
        if (/^INSERT/m.test(sql.trim())) return { rowCount: 1, rows: [{ version: '1' }] };
        return { rowCount: 0, rows: [] };
      },
    };
  }

  test('CPU-02 pg mode: fresh snapshot answers; past 5 s without a pull, reads are refused with 503', async () => {
    jest.resetModules(); // the jest setup files load this module before the clock mock above applies; reload it under the mock
    process.env.QODIQA_CONTROL_PLANE_BACKEND = 'pg';
    const cp = require('../index');
    await cp._resetForTest();
    const tenants = require('../../tenancy/tenantRegistry');
    const pool = fakePool([{ store: 'tenant', record_id: 't1', data: { tenantId: 't1', status: 'suspended' }, version: '1', deleted: false, last_used_at: null }]);
    cp._setPoolForTest(pool);
    await cp.start({ notifier: false });
    expect(tenants.assertActiveTenant('t1')).toEqual({ valid: false, reason: 'TENANT_SUSPENDED' });
    pool.fail = true;
    const t0 = Date.now();
    const spy = jest.spyOn(Date, 'now').mockReturnValue(t0 + 5_001);
    let err = null; try { tenants.assertActiveTenant('t1'); } catch (e) { err = e; }
    expect(err && err.code).toBe('CONTROL_PLANE_STALE');
    expect(err.status).toBe(503);
    spy.mockReturnValue(t0 + 4_000);
    expect(tenants.assertActiveTenant('t1').reason).toBe('TENANT_SUSPENDED');       // still inside the bound
  });

  test('CPU-03 a write naming a stale version is refused with 409; the snapshot keeps the committed state', async () => {
    process.env.QODIQA_CONTROL_PLANE_BACKEND = 'pg';
    const cp = require('../index');
    await cp._resetForTest();
    const tenants = require('../../tenancy/tenantRegistry');
    const pool = fakePool([{ store: 'tenant', record_id: 't2', data: { tenantId: 't2', status: 'suspended' }, version: '3', deleted: false, last_used_at: null }]);
    cp._setPoolForTest(pool);
    await cp.start({ notifier: false });
    pool.conflict = true;
    const err = await tenants.updateTenant('t2', { status: 'active' }).catch((e) => e);
    expect(err.code).toBe('CONTROL_PLANE_VERSION_CONFLICT');
    expect(err.status).toBe(409);
    expect(tenants.getTenant('t2').status).toBe('suspended');
  });

  test('CPU-04 the staleness bound can only be tightened', () => {
    const cp = require('../index');
    process.env.QODIQA_CONTROL_PLANE_MAX_STALENESS_MS = '60000';
    expect(cp.status().maxStalenessMs).toBe(5000);
    process.env.QODIQA_CONTROL_PLANE_MAX_STALENESS_MS = '1000';
    expect(cp.status().maxStalenessMs).toBe(1000);
  });

  test('CPU-05 notifier messages are MAC-signed; unsigned, tampered and malformed messages are rejected', () => {
    const { buildMessage, verifyMessage } = require('../notifier');
    const m = buildMessage({ store: 'signing_identity', recordId: 'id-1', origin: 'o1' });
    expect(verifyMessage(JSON.stringify(m))).toMatchObject({ ok: true });
    expect(verifyMessage(JSON.stringify({ ...m, recordId: 'id-2' }))).toMatchObject({ ok: false, reason: 'BAD_MAC' });
    const { signature, ...unsigned } = m; void signature;
    expect(verifyMessage(JSON.stringify(unsigned))).toMatchObject({ ok: false, reason: 'MISSING' });
    expect(verifyMessage('{not json')).toMatchObject({ ok: false, reason: 'MALFORMED' });
  });

  test('CPU-06 memory mode never writes a file, for any store mutation', async () => {
    process.env.QODIQA_CONTROL_PLANE_BACKEND = 'memory';
    const cp = require('../index');
    await cp._resetForTest();
    const rbac = require('../../rbac/store');
    const roles = require('../../rbac/customRoleStore');
    const signing = require('../../signing/signingIdentityStore');
    const tenants = require('../../tenancy/tenantRegistry');
    const orgs = require('../../organizations/organizationRegistry');
    const portal = require('../../portal/tenantPortalUserStore');
    const policy = require('../../policy/store');
    // Jest itself writes its transform cache when a module is first required in a checkout
    // whose cache is cold (every fresh clone) — those writes are Jest's, not the store's, and are excluded. Any
    // other file write still fails this test.
    const writes = ['writeFileSync', 'renameSync', 'copyFileSync', 'appendFileSync'].map((f) => jest.spyOn(fs, f));
    const storeWrites = (w) => w.mock.calls.filter((c) => !/jest-transform-cache/.test(String(c[0]))).length;
    const u = rbac.createUser({ username: 'cpu06-user', role: 'viewer' });
    rbac.issueApiKey(u.id); rbac.updateUser(u.id, { role: 'auditor' }); rbac.revokeApiKey(u.id); rbac.deleteUser(u.id);
    const r = roles.createRole({ name: 'cpu06 role', permissions: ['READ_AUDIT'] }); roles.updateRole(r.id, { enabled: false }); roles.deleteRole(r.id);
    const i = signing.createSigningIdentity({ name: 'cpu06-si', tenantId: 'cpu06', environment: 'test', permissions: ['SIGN_ARTIFACT'] });
    signing.issueSigningKey(i.id); signing.touchLastUsed(i.id); signing.revokeSigningKey(i.id); signing.deleteSigningIdentity(i.id);
    tenants.registerTenant('cpu06t'); tenants.updateTenant('cpu06t', { status: 'suspended' });
    const o = orgs.registerOrganization({ organizationName: 'cpu06org' }); orgs.assignTenantToOrg('cpu06t', o.organizationId); orgs.updateOrganization(o.organizationId, { status: 'suspended' });
    portal.findOrCreateByIdpSubject({ idpIssuer: 'https://idp', idpSubject: 'cpu06', tenantId: 'cpu06t', email: null });
    policy.createPolicy({ id: 'cpu06-pol', type: 'REQUIRE_CONSENT', priority: 99, config: { requireValidArtifact: true } }); policy.setEnabled('cpu06-pol', false);
    for (const w of writes) expect({ fn: w.getMockName(), calls: storeWrites(w) }).toEqual({ fn: w.getMockName(), calls: 0 });
  });
});
