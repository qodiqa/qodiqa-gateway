'use strict';

/**
 * step 6 — REAL PostgreSQL proof of the owner's personal-data conditions on request_trails
 * (migration 069): caller IP and identity id are covered by the catalog-based GDPR erasure, and trails take the
 * retention of non-enforcement OPERATIONAL events, never indefinite.
 *
 * RT-01 qodiqa_erasure_targets() lists request_trails.actor_id (since / migration 080: the explicit allowlist)
 *   RT-02  qodiqa_erase_subject() (as qodiqa_system) replaces the identity with the pseudonym AND nulls caller_ip in the
 *          same statement; correlate() then shows the pseudonym and no IP; another subject's trail is untouched
 *   RT-03  the real retention stamp gives every trail retain_until = now + the OPERATIONAL policy's period (30 days
 *          seeded) — never NULL after a cycle
 *   RT-04  the real expiry deletes expired trails and keeps a trail under legal hold
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const DB = `qodiqa_w10rt_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const SIGN_A = '11111111-2222-4333-8444-5555555555a1';
const SIGN_B = '11111111-2222-4333-8444-5555555555b2';
const CHAT_A = '99999999-8888-4777-8666-5555555555a1';
const PSEUDO = 'ap1:' + 'e'.repeat(64);

describeOrSkip('request_trails personal data: erasure + OPERATIONAL retention (real PostgreSQL)', () => {
  let maint; let pgPool; let rolePools; let retentionPool; let store; let retention; let own;
  const saved = {};

  beforeAll(async () => {
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD']) saved[k] = process.env[k];
    if (!/^[a-z0-9_]+$/.test(DB)) throw new Error('unsafe db name');
    maint = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER, password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    process.env.QODIQA_PG_DATABASE = DB;
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    rolePools = require('../../src/infra/postgres/rolePools');
    retentionPool = require('../../src/infra/postgres/retentionPool');
    pgPool.initialize();
    await pgPool.runMigrations();
    retentionPool.initialize();
    store = require('../../src/core/audit/centralStore');
    retention = require('../../src/core/audit/retention');
    own = pgPool;   // elevated suite pool (BYPASSRLS) for ground truth only
    const at = (ms) => new Date(Date.now() - 60_000 + ms).toISOString();
    // subject A (tenant t1): a /sign request + its chat; subject B (tenant t1): another /sign request
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(0), requestId: SIGN_A, ip: '203.0.113.9', identityId: 'subject-a', tenantId: 't1' });
    await store.ingest('INFO', 'SIGN_DECISION', { timestamp: at(2), requestId: SIGN_A, artifactId: CHAT_A, decision: 'ALLOW', ip: '203.0.113.9', identityId: 'subject-a', tenantId: 't1' });
    await store.ingest('INFO', 'POLICY_EXECUTE', { timestamp: at(10), requestId: CHAT_A });
    await store.ingest('INFO', 'SIGN_AUTH_OK', { timestamp: at(20), requestId: SIGN_B, ip: '198.51.100.7', identityId: 'subject-b', tenantId: 't1' });
    await store.flush();
  }, 120_000);

  afterAll(async () => {
    await retentionPool.shutdown().catch(() => {});
    await pgPool.shutdown().catch(() => {});
    await rolePools.shutdownAll().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try { await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch (e) { console.warn(`[w10rt] could not drop ${DB}: ${e.message}`); }
      await maint.end();
    }
  }, 60_000);

  const trail = async (key) => (await own.query('SELECT * FROM request_trails WHERE trail_key = $1', [key])).rows[0];

  test('RT-01 the erasure targets list request_trails.actor_id', async () => {
    const { rows } = await own.query('SELECT table_name, column_name, has_tenant FROM qodiqa_erasure_targets() WHERE table_name = $1', ['request_trails']);
    expect(rows).toEqual([{ table_name: 'request_trails', column_name: 'actor_id', has_tenant: true }]);
  });

  test('RT-02 erasure pseudonymizes the identity and nulls the caller IP; the other subject is untouched', async () => {
    expect(await trail(SIGN_A)).toMatchObject({ actor_id: 'subject-a', caller_ip: '203.0.113.9' });
    const before = await store.correlate(SIGN_A);
    expect(before.filter((r) => r.payload.fromTrail).map((r) => [r.payload.ip, r.payload.identityId])).toEqual([['203.0.113.9', 'subject-a'], ['203.0.113.9', 'subject-a']]);

    const { rows } = await rolePools.system.query('SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', ['t1', 'subject-a', PSEUDO, 500], 'w10rt_erase');
    const target = rows.find((r) => r.target === 'request_trails.actor_id');
    expect(target).toMatchObject({ rows_updated: '1', remaining: '0' });

    const a = await trail(SIGN_A);
    expect(a).toMatchObject({ actor_id: PSEUDO, caller_ip: null });
    expect(JSON.stringify(a.steps)).not.toMatch(/203\.0\.113\.9|subject-a/);
    expect(await trail(SIGN_B)).toMatchObject({ actor_id: 'subject-b', caller_ip: '198.51.100.7' });
    const after = await store.correlate(SIGN_A);
    expect(after.filter((r) => r.payload.fromTrail).map((r) => [r.payload.ip, r.payload.identityId])).toEqual([[null, PSEUDO], [null, PSEUDO]]);
  });

  test('RT-03 the real retention stamp gives every trail the OPERATIONAL period (never NULL)', async () => {
    const r = await retention.stampRetentionDates();
    expect(r.trailRetainDays).toBe(30);
    expect(r.trailsStamped).toBe(3);
    const { rows } = await own.query('SELECT count(*) FILTER (WHERE retain_until IS NULL)::int nulls, min(retain_until) mn, max(retain_until) mx FROM request_trails');
    expect(rows[0].nulls).toBe(0);
    const days = (d) => (new Date(d) - Date.now()) / 86_400_000;
    expect(days(rows[0].mn)).toBeGreaterThan(29.9);
    expect(days(rows[0].mx)).toBeLessThan(30.1);
  });

  test('RT-04 the real expiry deletes expired trails and keeps one under legal hold', async () => {
    await own.query("UPDATE request_trails SET retain_until = NOW() - interval '1 day'");
    await own.query('UPDATE request_trails SET legal_hold = true WHERE trail_key = $1', [SIGN_B]);
    const r = await retention.expireEvents();
    expect(r.trailsExpired).toBe(2);
    const { rows } = await own.query('SELECT trail_key FROM request_trails');
    expect(rows.map((x) => x.trail_key)).toEqual([SIGN_B]);
  });
});
