'use strict';

/**
 * Centralized Audit Store Tests
 *
 * AS-01 … AS-15  centralStore module (unit, PG-disabled)
 * AS-16 … AS-30  centralStore classification and extraction helpers (unit)
 * AS-31 … AS-50  auditStore route responses (HTTP, PG-disabled / mocked)
 * AS-51 … AS-65  retention module (unit, PG-disabled)
 * AS-66 … AS-70  logger.js registration integration
 * AS-71 … AS-75  RBAC permission matrix (MANAGE_RETENTION)
 */

const { randomUUID } = require('crypto');

// ── Helpers ────────────────────────────────────────────────────────────────────

// Isolated require helper — resets module cache for each import group
function freshRequire(modulePath) {
  delete require.cache[require.resolve(modulePath)];
  return require(modulePath);
}

// ── Mock pgPool (disabled by default) ─────────────────────────────────────────
// Variable name must start with 'mock' for Jest factory scope rules.

const mockPool = {
  _enabled: false,
  isEnabled: function() { return this._enabled; },
  query:     jest.fn(),
};

// cross-tenant DEFINER reads now go through rolePools (qodiqa_system / qodiqa_reporting);
// the forwarder sends them to the same mocked pool and records which pool served each call.
jest.mock('../../../infra/postgres/rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../../../infra/postgres/pool')));
jest.mock('../../../infra/postgres/pool', () => mockPool);

// ── Mock logger ────────────────────────────────────────────────────────────────

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
  allowed: jest.fn(),
  blocked: jest.fn(),
  eventBus: { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

// ── Load modules under test ────────────────────────────────────────────────────

const centralStore = require('../../../core/audit/centralStore');
const retention    = require('../../../core/audit/retention');
const { PERMISSIONS } = require('../../../core/rbac/roles');

// ── centralStore — PG disabled ─────────────────────────────────────────────────

describe('centralStore — PG disabled', () => {
  beforeEach(() => { mockPool._enabled = false; mockPool.query.mockClear(); });

  test('AS-01 ingest() returns undefined when PG disabled', async () => {
    const result = await centralStore.ingest('INFO', 'TEST_EVENT', { foo: 'bar' });
    expect(result).toBeUndefined();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('AS-02 search() returns empty result when PG disabled', async () => {
    const result = await centralStore.search({ eventType: 'FOO' });
    expect(result).toEqual({ events: [], total: 0, page: 1, pageSize: 50 });
  });

  test('AS-03 getEvent() returns null when PG disabled', async () => {
    expect(await centralStore.getEvent(randomUUID())).toBeNull();
  });

  test('AS-04 correlate() returns empty array when PG disabled', async () => {
    expect(await centralStore.correlate(randomUUID())).toEqual([]);
  });

  test('AS-05 artifactTimeline() returns empty array when PG disabled', async () => {
    expect(await centralStore.artifactTimeline(randomUUID())).toEqual([]);
  });

  test('AS-06 actorActivity() returns empty array when PG disabled', async () => {
    expect(await centralStore.actorActivity('user-1')).toEqual([]);
  });

  test('AS-07 stats() returns null when PG disabled', async () => {
    expect(await centralStore.stats()).toBeNull();
  });

  test('AS-08 ingestionRate() returns empty array when PG disabled', async () => {
    expect(await centralStore.ingestionRate(60)).toEqual([]);
  });

  test('AS-09 topEventTypes() returns empty array when PG disabled', async () => {
    expect(await centralStore.topEventTypes()).toEqual([]);
  });

  test('AS-10 ingest() does not throw even if called concurrently', async () => {
    const calls = Array.from({ length: 50 }, (_, i) =>
      centralStore.ingest('INFO', `EVENT_${i}`, { i })
    );
    await expect(Promise.all(calls)).resolves.toBeDefined();
  });
});

// ── centralStore — PG enabled, ingest ─────────────────────────────────────────

describe('centralStore.ingest() — PG enabled', () => {
  beforeEach(() => {
    mockPool._enabled = true;
    mockPool.query.mockResolvedValue({ rows: [], rowCount: 1 });
  });
  afterEach(() => { mockPool._enabled = false; mockPool.query.mockClear(); });

  test('AS-11 ingest() calls pgPool.query once', async () => {
    await centralStore.ingest('INFO', 'GATEWAY_ALLOW', {
      requestId: randomUUID(), artifactId: randomUUID(), decision: 'ALLOW',
    });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    expect(mockPool.query).toHaveBeenCalledTimes(1);
  });

  test('AS-12 ingest() passes correct category for GATEWAY_ALLOW', async () => {
    await centralStore.ingest('INFO', 'GATEWAY_ALLOW', { decision: 'ALLOW' });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const sql = mockPool.query.mock.calls[0][0];
    const params = mockPool.query.mock.calls[0][1];
    expect(sql).toContain('platform_audit_events');
    expect(params).toContain('ENFORCEMENT');
  });

  test('AS-13 ingest() classifies RBAC_DENY as SECURITY category', async () => {
    await centralStore.ingest('WARN', 'RBAC_DENY', {});
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain('SECURITY');
  });

  test('AS-14 ingest() classifies PG_POOL_ERROR as INFRASTRUCTURE category', async () => {
    await centralStore.ingest('ERROR', 'PG_POOL_ERROR', { error: 'connection refused' });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain('INFRASTRUCTURE');
  });

  test('AS-15 ingest() swallows PG errors without throwing', async () => {
    mockPool.query.mockRejectedValueOnce(new Error('DB down'));
    await expect(centralStore.ingest('INFO', 'TEST_EVENT', {})).resolves.toBeUndefined();
    // the failing query is now the batched flush's — it must be swallowed exactly the same way.
    await expect(centralStore.flush()).resolves.toBeUndefined();
  });

  // trace_id/span_id correlation columns and canonical timestamp field.
  test('AS-15b ingest() extracts and persists trace_id/span_id from payload', async () => {
    await centralStore.ingest('INFO', 'GATEWAY_ALLOW', {
      traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), decision: 'ALLOW',
    });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const sql    = mockPool.query.mock.calls[0][0];
    const params = mockPool.query.mock.calls[0][1];
    expect(sql).toContain('trace_id');
    expect(sql).toContain('span_id');
    expect(params).toContain('a'.repeat(32));
    expect(params).toContain('b'.repeat(16));
  });

  test('AS-15c ingest() rejects a malformed traceId/spanId (not persisted as garbage correlation data)', async () => {
    await centralStore.ingest('INFO', 'GATEWAY_ALLOW', {
      traceId: 'not-a-valid-trace-id', spanId: 'nope', decision: 'ALLOW',
    });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).not.toContain('not-a-valid-trace-id');
    expect(params).not.toContain('nope');
  });

  test('AS-15d ingest() reads occurred_at from payload.timestamp (canonical field), not payload.ts', async () => {
    const ts = '2024-06-01T00:00:00.000Z';
    await centralStore.ingest('INFO', 'GATEWAY_ALLOW', { timestamp: ts, decision: 'ALLOW' });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params[0]).toEqual(new Date(ts));
  });
});

// ── Trace correlation ─────────────────────────────────────────────────────────

describe('centralStore.correlateByTrace()', () => {
  beforeEach(() => { mockPool._enabled = true; mockPool.query.mockClear(); });
  afterEach(() => { mockPool._enabled = false; mockPool.query.mockClear(); });

  test('AS-15e correlateByTrace() returns empty array when PG disabled', async () => {
    mockPool._enabled = false;
    expect(await centralStore.correlateByTrace('a'.repeat(32))).toEqual([]);
  });

  test('AS-15f correlateByTrace() queries platform_audit_events by trace_id', async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [{ event_id: '1' }] });
    const rows = await centralStore.correlateByTrace('a'.repeat(32));
    const sql    = mockPool.query.mock.calls[0][0];
    const params = mockPool.query.mock.calls[0][1];
    expect(sql).toContain('WHERE trace_id = $1');
    expect(params).toEqual(['a'.repeat(32)]);
    expect(rows).toEqual([{ event_id: '1' }]);
  });
});

// ── Event classification ───────────────────────────────────────────────────────

describe('centralStore event classification', () => {
  beforeEach(() => {
    mockPool._enabled = true;
    mockPool.query.mockResolvedValue({ rows: [], rowCount: 1 });
  });
  afterEach(() => { mockPool._enabled = false; mockPool.query.mockClear(); });

  const cases = [
    ['GATEWAY_BLOCK',              'ENFORCEMENT'],
    ['AUDIT_BLOCK_RECORDED',       'ENFORCEMENT'],
    ['POLICY_DRIFT_DETECTED',      'ENFORCEMENT'],
    ['NONCE_V2_REPLAY_DETECTED',   'SECURITY'],
    ['EXECUTION_INVARIANT_VIOLATED','SECURITY'],
    ['KEY_PLAINTEXT_DETECTED',     'SECURITY'],
    ['PROVIDER_SSRF_REJECTED',     'SECURITY'],
    ['AUDIT_CHAIN_CORRUPTED',      'SECURITY'],
    ['RBAC_ALLOW',                 'ACCESS_CONTROL'],
    ['RBAC_USER_CREATED',          'ACCESS_CONTROL'],
    ['KEY_ROTATION_AUTO',          'KEY_MANAGEMENT'],
    ['TENANT_KEY_EXPIRED_ACTIVE',  'KEY_MANAGEMENT'],
    ['POLICY_CREATED',             'POLICY'],
    ['POLICIES_RELOADED',          'POLICY'],
    ['PROVIDER_EXECUTION_COMPLETE','PROVIDER'],
    ['AUDIT_CHAIN_VALIDATED',      'AUDIT_CHAIN'],
    ['EVIDENCE_PDF_GENERATED',     'EVIDENCE'],
    ['GATEWAY_START',              'LIFECYCLE'],
    ['SHUTDOWN_COMPLETE',          'LIFECYCLE'],
    ['REDIS_CONNECTED',            'INFRASTRUCTURE'],
    ['PG_POOL_INITIALIZED',        'INFRASTRUCTURE'],
    ['ANOMALY_THRESHOLD_EXCEEDED', 'SECURITY'],
    ['OPS_AUTH_INVALID_TOKEN',     'SECURITY'],
    ['OPS_ALLOWLIST_BLOCKED',      'SECURITY'],
  ];

  test.each(cases)('AS-16 %s → %s category', async (eventType, expectedCategory) => {
    await centralStore.ingest('INFO', eventType, {});
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain(expectedCategory);
    mockPool.query.mockClear();
  });
});

// ── Outcome classification ─────────────────────────────────────────────────────

describe('centralStore outcome classification', () => {
  beforeEach(() => {
    mockPool._enabled = true;
    mockPool.query.mockResolvedValue({ rows: [], rowCount: 1 });
  });
  afterEach(() => { mockPool._enabled = false; mockPool.query.mockClear(); });

  test('AS-26 decision=ALLOW payload → outcome ALLOW', async () => {
    await centralStore.ingest('INFO', 'GATEWAY_ALLOW', { decision: 'ALLOW' });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain('ALLOW');
  });

  test('AS-27 decision=BLOCK payload → outcome BLOCK', async () => {
    await centralStore.ingest('WARN', 'GATEWAY_BLOCK', { decision: 'BLOCK' });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain('BLOCK');
  });

  test('AS-28 RBAC_DENY → outcome FAILURE', async () => {
    await centralStore.ingest('WARN', 'RBAC_DENY', {});
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain('FAILURE');
  });

  test('AS-29 PG_POOL_INITIALIZED → outcome SUCCESS', async () => {
    await centralStore.ingest('INFO', 'PG_POOL_INITIALIZED', {});
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain('SUCCESS');
  });

  test('AS-30 KEY_EXPIRING_SOON → outcome WARNING', async () => {
    await centralStore.ingest('WARN', 'KEY_EXPIRING_SOON', { daysRemaining: 3 });
    await centralStore.flush(); // (step 5): rows are written by the batched flush
    const params = mockPool.query.mock.calls[0][1];
    expect(params).toContain('WARNING');
  });
});

// ── auditStore route tests ─────────────────────────────────────────────────────

const express    = require('express');
const supertest  = require('supertest');
const createAuditStoreRouter = require('../auditStore');

function buildApp(pgEnabled = false, mockRows = [], mockTotal = 0) {
  mockPool._enabled = pgEnabled;
  mockPool.query.mockResolvedValue({ rows: mockRows, rowCount: mockRows.length });

  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.requestId = randomUUID();
    req.rbacUser  = { id: 'test-user', username: 'tester', role: 'admin' };
    next();
  });
  app.use('/', createAuditStoreRouter());
  return app;
}

describe('auditStore routes — PG disabled', () => {
  beforeEach(() => { mockPool._enabled = false; });
  afterEach(() => { mockPool.query.mockClear(); });

  test('AS-31 GET /events returns 200 with empty events when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/events');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.events).toEqual([]);
    expect(res.body.data.total).toBe(0);
  });

  test('AS-32 GET /events/:eventId returns 400 for invalid UUID', async () => {
    const res = await supertest(buildApp(false)).get('/events/not-a-uuid');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_EVENT_ID');
  });

  test('AS-33 GET /correlate/:requestId returns 400 for invalid UUID', async () => {
    const res = await supertest(buildApp(false)).get('/correlate/bad-id');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST_ID');
  });

  test('AS-34 GET /correlate/:requestId returns 200 with empty events when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get(`/correlate/${randomUUID()}`);
    expect(res.status).toBe(200);
    expect(res.body.data.events).toEqual([]);
  });

  test('AS-35 GET /artifact/:id/timeline returns 200 empty when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get(`/artifact/${randomUUID()}/timeline`);
    expect(res.status).toBe(200);
    expect(res.body.data.events).toEqual([]);
  });

  test('AS-36 GET /artifact/:id/timeline returns 400 for overly long ID', async () => {
    const longId = 'x'.repeat(200);
    const res = await supertest(buildApp(false)).get(`/artifact/${longId}/timeline`);
    expect(res.status).toBe(400);
  });

  test('AS-37 GET /actor/:actorId/activity returns 200 empty when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/actor/user-1/activity');
    expect(res.status).toBe(200);
    expect(res.body.data.events).toEqual([]);
  });

  test('AS-38 GET /stats returns 200 with null stats when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/stats');
    expect(res.status).toBe(200);
    expect(res.body.data.stats).toBeNull();
  });

  test('AS-39 GET /ingestion-rate returns 200 empty when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/ingestion-rate');
    expect(res.status).toBe(200);
    expect(res.body.data.rate).toEqual([]);
  });

  test('AS-40 GET /top-events returns 200 empty when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/top-events');
    expect(res.status).toBe(200);
    expect(res.body.data.events).toEqual([]);
  });

  test('AS-41 GET /retention/policies returns 200 empty when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/retention/policies');
    expect(res.status).toBe(200);
    expect(res.body.data.policies).toEqual([]);
  });

  test('AS-42 GET /retention/holds returns 200 empty when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/retention/holds');
    expect(res.status).toBe(200);
    expect(res.body.data.holds).toEqual([]);
  });

  test('AS-43 GET /retention/runs returns 200 empty when PG disabled', async () => {
    const res = await supertest(buildApp(false)).get('/retention/runs');
    expect(res.status).toBe(200);
    expect(res.body.data.runs).toEqual([]);
  });
});

describe('auditStore routes — validation', () => {
  test('AS-44 POST /retention/policies returns 400 for missing name', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/policies')
      .send({ retainDays: 30 });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_NAME');
  });

  test('AS-45 POST /retention/policies returns 400 for missing retainDays', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/policies')
      .send({ name: 'test-policy' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_RETAIN_DAYS');
  });

  test('AS-46 POST /retention/policies returns 400 for negative retainDays', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/policies')
      .send({ name: 'test-policy', retainDays: -1 });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_RETAIN_DAYS');
  });

  test('item 9 audit: POST /retention/policies rejects an unrecognised extra body key (retentionPolicyBodySchema was .passthrough(), now .strict())', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/policies')
      .send({ name: 'test-policy', retainDays: 30, unexpectedKey: 'nope' });
    expect(res.status).toBe(400);
  });

  test('item 9 audit: POST /retention/holds rejects an unrecognised extra body key (legalHoldBodySchema was .passthrough(), now .strict())', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/holds')
      .send({ holdName: 'hold-1', reason: 'legal matter', artifactId: randomUUID(), unexpectedKey: 'nope' });
    expect(res.status).toBe(400);
  });

  test('AS-47 POST /retention/holds returns 400 for missing holdName', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/holds')
      .send({ reason: 'legal matter', artifactId: randomUUID() });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_HOLD_NAME');
  });

  test('AS-48 POST /retention/holds returns 400 for missing reason', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/holds')
      .send({ holdName: 'hold-1', artifactId: randomUUID() });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_HOLD_REASON');
  });

  test('AS-49 POST /retention/holds returns 400 when no scope provided', async () => {
    const res = await supertest(buildApp(false))
      .post('/retention/holds')
      .send({ holdName: 'hold-1', reason: 'legal' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('HOLD_SCOPE_REQUIRED');
  });

  test('AS-50 GET /events respects pageSize cap at 500', async () => {
    mockPool._enabled = true;
    mockPool.query.mockResolvedValue({ rows: [], rowCount: 0 });
    const res = await supertest(buildApp(true)).get('/events?pageSize=9999');
    // Should not error — pageSize is clamped
    expect(res.status).toBe(200);
    mockPool._enabled = false;
  });
});

// ── retention module — PG disabled ────────────────────────────────────────────

describe('retention — PG disabled', () => {
  beforeEach(() => { mockPool._enabled = false; mockPool.query.mockClear(); });

  test('AS-51 listPolicies() returns empty array when PG disabled', async () => {
    expect(await retention.listPolicies()).toEqual([]);
  });

  test('AS-52 listLegalHolds() returns empty array when PG disabled', async () => {
    expect(await retention.listLegalHolds()).toEqual([]);
  });

  test('AS-53 listRuns() returns empty array when PG disabled', async () => {
    expect(await retention.listRuns()).toEqual([]);
  });

  test('AS-54 stampRetentionDates() returns {stamped:0} when PG disabled', async () => {
    expect(await retention.stampRetentionDates()).toEqual({ stamped: 0 });
  });

  test('AS-55 expireEvents() returns zeros when PG disabled', async () => {
    const r = await retention.expireEvents();
    expect(r.expired).toBe(0);
    expect(r.held).toBe(0);
  });

  test('AS-56 placeLegalHold() throws when PG disabled', async () => {
    await expect(retention.placeLegalHold({
      holdName: 'hold', reason: 'legal', artifactId: randomUUID(), heldBy: 'admin',
    })).rejects.toThrow('PostgreSQL not enabled');
  });

  test('AS-57 upsertPolicy() throws when PG disabled', async () => {
    await expect(retention.upsertPolicy({ name: 'p', retainDays: 30 }))
      .rejects.toThrow('PostgreSQL not enabled');
  });

  test('AS-58 releaseLegalHold() throws when PG disabled', async () => {
    await expect(retention.releaseLegalHold('hold', 'admin'))
      .rejects.toThrow('PostgreSQL not enabled');
  });

  test('AS-59 runRetentionCycle() completes without error when PG disabled', async () => {
    const result = await retention.runRetentionCycle();
    expect(result.expired).toBe(0);
    expect(result.stamped).toBe(0);
    expect(result.error).toBeNull();
  });
});

// ── retention — input validation ──────────────────────────────────────────────

describe('retention — validation (PG disabled)', () => {
  test('AS-60 upsertPolicy() throws for missing name', async () => {
    await expect(retention.upsertPolicy({ retainDays: 30 }))
      .rejects.toThrow('name is required');
  });

  test('AS-61 upsertPolicy() throws for missing retainDays', async () => {
    await expect(retention.upsertPolicy({ name: 'p' }))
      .rejects.toThrow('retainDays is required');
  });

  test('AS-62 placeLegalHold() throws for missing holdName', async () => {
    await expect(retention.placeLegalHold({ reason: 'r', artifactId: 'a', heldBy: 'u' }))
      .rejects.toThrow('holdName is required');
  });

  test('AS-63 placeLegalHold() throws for missing reason', async () => {
    await expect(retention.placeLegalHold({ holdName: 'h', artifactId: 'a', heldBy: 'u' }))
      .rejects.toThrow('reason is required');
  });

  test('AS-64 placeLegalHold() throws for missing heldBy', async () => {
    await expect(retention.placeLegalHold({ holdName: 'h', reason: 'r', artifactId: 'a' }))
      .rejects.toThrow('heldBy is required');
  });

  test('AS-65 placeLegalHold() throws when no scope provided', async () => {
    await expect(retention.placeLegalHold({ holdName: 'h', reason: 'r', heldBy: 'u' }))
      .rejects.toThrow('At least one of');
  });
});

// ── logger.js integration ─────────────────────────────────────────────────────
// These tests use jest.requireActual to load the real logger module so the
// registerCentralStore → ingest wiring can be verified without the module mock.

describe('logger.js registerCentralStore integration (real module)', () => {
  let realLogger;

  beforeEach(() => {
    jest.resetModules();
    realLogger = jest.requireActual('../../../../services/logger');
    // Reset any previously registered store
    realLogger.registerCentralStore(null);
  });

  afterEach(() => {
    realLogger.registerCentralStore(null);
  });

  test('AS-66 registerCentralStore is exported from the real logger.js', () => {
    expect(typeof realLogger.registerCentralStore).toBe('function');
  });

  test('AS-67 real logger exports emit, allowed, blocked, eventBus, registerCentralStore', () => {
    expect(typeof realLogger.emit).toBe('function');
    expect(typeof realLogger.allowed).toBe('function');
    expect(typeof realLogger.blocked).toBe('function');
    expect(realLogger.eventBus).toBeDefined();
    expect(typeof realLogger.registerCentralStore).toBe('function');
  });

  test('AS-68 emit() does not throw when no centralStore registered', () => {
    realLogger.registerCentralStore(null);
    expect(() => realLogger.emit('INFO', 'TEST_EVENT_68', {})).not.toThrow();
  });

  test('AS-69 emit() calls store.ingest() after registerCentralStore(store)', () => {
    const mockStore = { ingest: jest.fn().mockResolvedValue(undefined) };
    realLogger.registerCentralStore(mockStore);
    realLogger.emit('INFO', 'TEST_EVENT_69', { foo: 'bar' });
    expect(mockStore.ingest).toHaveBeenCalledTimes(1);
    expect(mockStore.ingest).toHaveBeenCalledWith(
      'INFO',
      'TEST_EVENT_69',
      expect.objectContaining({ eventType: 'TEST_EVENT_69', severity: 'INFO', foo: 'bar' }),
    );
  });

  test('AS-70 registerCentralStore(null) stops ingest() from being called', () => {
    const mockStore = { ingest: jest.fn().mockResolvedValue(undefined) };
    realLogger.registerCentralStore(mockStore);
    realLogger.registerCentralStore(null);
    realLogger.emit('INFO', 'TEST_EVENT_70', {});
    expect(mockStore.ingest).not.toHaveBeenCalled();
  });
});

// ── RBAC permission matrix ────────────────────────────────────────────────────

describe('RBAC MANAGE_RETENTION permission', () => {
  test('AS-71 MANAGE_RETENTION exists in PERMISSIONS', () => {
    expect(PERMISSIONS.MANAGE_RETENTION).toBeDefined();
  });

  test('AS-72 admin role has MANAGE_RETENTION', () => {
    expect(PERMISSIONS.MANAGE_RETENTION).toContain('admin');
  });

  test('AS-73 compliance role has MANAGE_RETENTION', () => {
    expect(PERMISSIONS.MANAGE_RETENTION).toContain('compliance');
  });

  test('AS-74 auditor role does NOT have MANAGE_RETENTION', () => {
    expect(PERMISSIONS.MANAGE_RETENTION).not.toContain('auditor');
  });

  test('AS-75 viewer role does NOT have MANAGE_RETENTION', () => {
    expect(PERMISSIONS.MANAGE_RETENTION).not.toContain('viewer');
  });
});
