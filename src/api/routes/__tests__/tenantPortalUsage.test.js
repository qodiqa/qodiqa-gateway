'use strict';

/**
 * Action 2 — tenant-portal usage metering API + CSV export.
 *
 * Same integration posture as tenantPortal.test.js: REAL
 * createPortalSessionMiddleware + REAL portalSessionToken + REAL
 * rbacResolve/requirePermission — the exact chain server/startup.js wires —
 * so the authorization / tenant-isolation assertions below exercise the
 * production integration, not a stand-in. Only the evidence layer
 * (src/core/audit/audit-log.js) is mocked, with the REAL canonical reducer
 * (src/core/usage/usageAggregation.js) running over per-tenant fixture
 * entries — the mock replaces storage, never metering semantics.
 *
 * Covers the mandatory suites: unauthenticated / cross-tenant / forged
 * tenant parameter / missing permission; API-export consistency; API
 * idempotency; sensitive-evidence leakage (fixtures carry decoy secrets).
 */

const request = require('supertest');
const express = require('express');

const SECRET = 'e'.repeat(64);

const T0 = Date.parse('2026-08-10T00:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;

// Decoy sensitive material — MUST never appear in any metering response.
const DECOY_PROMPT = 'DECOY_PROMPT_do_not_expose_9f2c';
const DECOY_SECRET = 'sk-DECOY_SECRET_51b7e02fa4';
const DECOY_OUTPUT = 'DECOY_MODEL_OUTPUT_77aa';

function _entry(tenantId, id, atMs, tokenUsage, extraCtx = {}) {
  return {
    artifactId: id,
    decision: 'ALLOW',
    timestamp: new Date(atMs).toISOString(),
    tenantId,
    signature: DECOY_SECRET,
    requestHash: 'a'.repeat(64),
    executionContext: {
      stage: 'PROVIDER_EXECUTION',
      tokenUsage,
      prompt: DECOY_PROMPT,          // never actually written by the pipeline —
      output: DECOY_OUTPUT,          // present here purely as leakage tripwires
      ...extraCtx,
    },
  };
}

const FIXTURES = {
  acme: [
    _entry('acme', 'acme-1', T0,          { inputTokens: 100, outputTokens: 10, totalTokens: 110 }),
    _entry('acme', 'acme-2', T0 + 1000,   { inputTokens: 200, outputTokens: 20, totalTokens: 220 }),
    _entry('acme', 'acme-3', T0 + 2 * DAY, { inputTokens: null, outputTokens: null, totalTokens: null }), // streaming-style
  ],
  globex: [
    _entry('globex', 'globex-1', T0, { inputTokens: 7, outputTokens: 7, totalTokens: 14 }),
  ],
};

function freshApp() {
  jest.resetModules();
  process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;

  jest.doMock('../../../core/tenancy/tenantRegistry', () => ({
    getTenant: jest.fn((id) => ({ tenantId: id, tenantName: id, status: 'active' })),
    assertActiveTenant: jest.fn((id) => ({ valid: true, tenant: { tenantId: id } })),
  }));

  const mockUsers = new Map();
  jest.doMock('../../../core/portal/tenantPortalUserStore', () => ({
    findOrCreateByIdpSubject: jest.fn(),
    getById: jest.fn((id) => mockUsers.get(id) || null),
  }));

  jest.doMock('../../../core/consent', () => ({ list: jest.fn(async () => ({ records: [], total: 0 })) }));
  jest.doMock('../../../../services/artifact/tenantKeyManager', () => ({ getTenantKeyStatus: jest.fn(() => ({})) }));
  jest.doMock('../../../core/portal/oidcClient', () => ({ buildAuthorizationUrl: jest.fn(), exchangeCode: jest.fn() }));
  jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

  // Evidence layer: real reducer over per-tenant fixtures. Tenant scoping
  // happens exactly where production does it — the evidence read is keyed
  // by the SERVER-DERIVED tenantId argument.
  const aggregateSpy = jest.fn(async (tenantId, { fromMs, toMs }) => {
    const { reduceUsage } = jest.requireActual('../../../core/usage/usageAggregation');
    return reduceUsage(FIXTURES[tenantId] ?? [], { fromMs, toMs });
  });
  jest.doMock('../../../core/audit/audit-log.js', () => ({ aggregateTenantUsage: aggregateSpy }));

  const { createTenantPortalRouter } = require('../tenantPortal');
  const { createPortalSessionMiddleware } = require('../../../middleware/portalAuth');
  const { createRbacResolveMiddleware, createRequirePermission } = require('../../../middleware/rbac');
  const { isPermitted, isValidPermission } = require('../../../core/rbac/authorize');
  const { mintSessionToken } = require('../../../../services/portal/portalSessionToken');

  const portalUserStore = require('../../../core/portal/tenantPortalUserStore');
  const portalSessionAuth = createPortalSessionMiddleware({
    verifySessionToken: require('../../../../services/portal/portalSessionToken').verifySessionToken,
    getPortalUserById:  portalUserStore.getById,
  });

  const router = createTenantPortalRouter({
    requirePermission: createRequirePermission({ isPermitted, isValidPermission }),
    portalSessionAuth,
    rbacResolve: createRbacResolveMiddleware({}),
    rateLimit: (req, res, next) => next(),
  });

  const app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.requestId = 'test-req'; res.locals.requestId = 'test-req'; next(); });
  app.use('/tenant-portal', router);

  function tokenFor(tenantId, recOverrides = {}) {
    const id = `pu_${tenantId}_${recOverrides.role ?? 'tenant'}`;
    const rec = { id, tenantId, role: 'tenant', enabled: true, email: `u@${tenantId}.example`, ...recOverrides };
    mockUsers.set(id, rec);
    return mintSessionToken({ portalUserId: rec.id, tenantId: rec.tenantId, role: rec.role });
  }

  return { app, tokenFor, aggregateSpy };
}

afterEach(() => {
  delete process.env.QODIQA_PORTAL_SESSION_SECRET;
  jest.dontMock('../../../core/tenancy/tenantRegistry');
  jest.dontMock('../../../core/portal/tenantPortalUserStore');
  jest.dontMock('../../../core/consent');
  jest.dontMock('../../../../services/artifact/tenantKeyManager');
  jest.dontMock('../../../core/portal/oidcClient');
  jest.dontMock('../../../../services/logger');
  jest.dontMock('../../../core/audit/audit-log.js');
});

const RANGE = { from: '2026-08-01T00:00:00Z', to: '2026-09-01T00:00:00Z' };

describe('authentication and authorization', () => {
  test('unauthenticated request is rejected 401', async () => {
    const { app } = freshApp();
    const res = await request(app).get('/tenant-portal/api/usage');
    expect(res.status).toBe(401);
  });

  test('garbage bearer token is rejected 401', async () => {
    const { app } = freshApp();
    const res = await request(app).get('/tenant-portal/api/usage').set('Authorization', 'Bearer nonsense');
    expect(res.status).toBe(401);
  });

  test('authenticated identity WITHOUT READ_TENANT_USAGE (viewer role) is rejected 403', async () => {
    const { app, tokenFor } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage')
      .set('Authorization', `Bearer ${tokenFor('acme', { role: 'viewer' })}`);
    expect(res.status).toBe(403);
  });

  test('tenant A can read tenant A usage', async () => {
    const { app, tokenFor } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage').query(RANGE)
      .set('Authorization', `Bearer ${tokenFor('acme')}`);
    expect(res.status).toBe(200);
    expect(res.body.data.tenantId).toBe('acme');
    expect(res.body.data.totals).toEqual({ executions: 3, inputTokens: 300, outputTokens: 30, totalTokens: 330 });
  });

  test('tenant B never sees tenant A data', async () => {
    const { app, tokenFor } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage').query(RANGE)
      .set('Authorization', `Bearer ${tokenFor('globex')}`);
    expect(res.status).toBe(200);
    expect(res.body.data.tenantId).toBe('globex');
    expect(res.body.data.totals).toEqual({ executions: 1, inputTokens: 7, outputTokens: 7, totalTokens: 14 });
  });

  test('forged ?tenantId= parameter is ignored — server-derived tenant wins', async () => {
    const { app, tokenFor, aggregateSpy } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage')
      .query({ ...RANGE, tenantId: 'acme', tenant: 'acme' })
      .set('Authorization', `Bearer ${tokenFor('globex')}`);
    expect(res.status).toBe(200);
    expect(res.body.data.tenantId).toBe('globex');
    expect(res.body.data.totals.totalTokens).toBe(14); // globex's — never acme's 330
    for (const call of aggregateSpy.mock.calls) expect(call[0]).toBe('globex');
  });
});

describe('metering API behavior', () => {
  test('range is validated: malformed / inverted ranges are 400, never coerced', async () => {
    const { app, tokenFor } = freshApp();
    const token = tokenFor('acme');
    for (const query of [
      { from: 'garbage' },
      { from: '2026-08-02T00:00:00Z', to: '2026-08-01T00:00:00Z' },
      { from: '2019-01-01T00:00:00Z', to: '2026-08-01T00:00:00Z' },
    ]) {
      const res = await request(app)
        .get('/tenant-portal/api/usage').query(query)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(400);
    }
  });

  test('read-only and repeatable: identical calls return identical bodies', async () => {
    const { app, tokenFor } = freshApp();
    const token = tokenFor('acme');
    const first  = await request(app).get('/tenant-portal/api/usage').query(RANGE).set('Authorization', `Bearer ${token}`);
    const second = await request(app).get('/tenant-portal/api/usage').query(RANGE).set('Authorization', `Bearer ${token}`);
    expect(second.body.data).toEqual(first.body.data);
  });

  test('series rows are per-UTC-day, ascending, and reconcile to totals', async () => {
    const { app, tokenFor } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage').query(RANGE)
      .set('Authorization', `Bearer ${tokenFor('acme')}`);
    const { series, totals } = res.body.data;
    expect(series.map((r) => r.day)).toEqual(['2026-08-10', '2026-08-12']);
    const sum = (k) => series.reduce((a, r) => a + r[k], 0);
    expect(sum('executions')).toBe(totals.executions);
    expect(sum('totalTokens')).toBe(totals.totalTokens);
  });
});

describe('CSV export', () => {
  function parseCsv(text) {
    return text.trim().split('\r\n').map((line) =>
      line.split(',').map((cell) => cell.replace(/^"|"$/g, '').replace(/""/g, '"')));
  }

  test('export requires the same authentication and permission as the API', async () => {
    const { app, tokenFor } = freshApp();
    expect((await request(app).get('/tenant-portal/api/usage/export')).status).toBe(401);
    expect((await request(app).get('/tenant-portal/api/usage/export')
      .set('Authorization', `Bearer ${tokenFor('acme', { role: 'viewer' })}`)).status).toBe(403);
  });

  test('CSV totals are IDENTICAL to API totals for the same tenant/range (MANDATORY)', async () => {
    const { app, tokenFor } = freshApp();
    const token = tokenFor('acme');
    const api = await request(app).get('/tenant-portal/api/usage').query(RANGE).set('Authorization', `Bearer ${token}`);
    const csv = await request(app).get('/tenant-portal/api/usage/export').query(RANGE).set('Authorization', `Bearer ${token}`);

    expect(csv.status).toBe(200);
    expect(csv.headers['content-type']).toMatch(/text\/csv/);
    expect(csv.headers['content-disposition']).toMatch(/attachment/);

    const rows = parseCsv(csv.text);
    expect(rows[0]).toEqual(['day', 'executions', 'inputTokens', 'outputTokens', 'totalTokens']);
    const totalRow = rows[rows.length - 1];
    expect(totalRow[0]).toBe('TOTAL');
    expect(Number(totalRow[1])).toBe(api.body.data.totals.executions);
    expect(Number(totalRow[2])).toBe(api.body.data.totals.inputTokens);
    expect(Number(totalRow[3])).toBe(api.body.data.totals.outputTokens);
    expect(Number(totalRow[4])).toBe(api.body.data.totals.totalTokens);

    // every series row matches too — same aggregation behind both surfaces
    const seriesRows = rows.slice(1, -1);
    expect(seriesRows.map((r) => r[0])).toEqual(api.body.data.series.map((s) => s.day));
    seriesRows.forEach((r, i) => {
      expect(Number(r[4])).toBe(api.body.data.series[i].totalTokens);
    });
  });

  test('export is tenant-scoped exactly like the API', async () => {
    const { app, tokenFor } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage/export').query(RANGE)
      .set('Authorization', `Bearer ${tokenFor('globex')}`);
    const rows = parseCsv(res.text);
    expect(rows[rows.length - 1][4]).toBe('14'); // globex total, never acme's
  });

  test('export validates ranges like the API (400 on malformed input)', async () => {
    const { app, tokenFor } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage/export').query({ from: 'garbage' })
      .set('Authorization', `Bearer ${tokenFor('acme')}`);
    expect(res.status).toBe(400);
  });
});

describe('sensitive-evidence leakage (MANDATORY security suite)', () => {
  test('neither API nor export ever contains prompts, outputs, signatures, or secrets', async () => {
    const { app, tokenFor } = freshApp();
    const token = tokenFor('acme');
    const api = await request(app).get('/tenant-portal/api/usage').query(RANGE).set('Authorization', `Bearer ${token}`);
    const csv = await request(app).get('/tenant-portal/api/usage/export').query(RANGE).set('Authorization', `Bearer ${token}`);

    for (const body of [JSON.stringify(api.body), csv.text]) {
      expect(body).not.toContain(DECOY_PROMPT);
      expect(body).not.toContain(DECOY_SECRET);
      expect(body).not.toContain(DECOY_OUTPUT);
      expect(body).not.toContain('a'.repeat(64));      // requestHash
      expect(body).not.toContain('acme-1');            // evidence identifiers
    }
    // the session token itself never round-trips into the payload
    expect(JSON.stringify(api.body)).not.toContain(token);
  });

  test('response data surface is exactly the documented schema — nothing extra', async () => {
    const { app, tokenFor } = freshApp();
    const res = await request(app)
      .get('/tenant-portal/api/usage').query(RANGE)
      .set('Authorization', `Bearer ${tokenFor('acme')}`);
    expect(Object.keys(res.body.data).sort()).toEqual(['range', 'series', 'tenantId', 'totals']);
    expect(Object.keys(res.body.data.totals).sort()).toEqual(['executions', 'inputTokens', 'outputTokens', 'totalTokens']);
    for (const row of res.body.data.series) {
      expect(Object.keys(row).sort()).toEqual(['day', 'executions', 'inputTokens', 'outputTokens', 'totalTokens']);
    }
  });
});
