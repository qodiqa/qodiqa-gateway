'use strict';

/**
 * Retention role separation: real-PostgreSQL integration test.
 *
 * Proves migration 038_retention_dedicated_role.sql actually produces a
 * least-privilege qodiqa_retention role: it can run the exact statement
 * shapes retention.js's automated cycle issues, but cannot write outside
 * that scope (no DDL, no admin tables, no INSERT on platform_audit_events).
 *
 * Real PostgreSQL only (no mocking) — this is entirely about actual GRANT/
 * RLS enforcement, which a mocked client has no semantics for. Creates and
 * drops its own uniquely-named scratch database; never touches any
 * pre-existing one (per this repo's DB-safety practice — see
 * poolAdvisoryLock.integration.test.js for the same convention).
 *
 * RRS-01  qodiqa_retention can SELECT/UPDATE/DELETE platform_audit_events
 *         via the exact stampRetentionDates()/expireEvents() statement shapes
 * RRS-02  qodiqa_retention CANNOT INSERT into platform_audit_events
 * RRS-03  qodiqa_retention CANNOT access an unrelated admin table (rbac_users)
 * RRS-04  qodiqa_retention CANNOT create/alter schema objects (no DDL rights)
 * RRS-05 (D3-A — supersedes the earlier assertion that qodiqa_app
 *         kept UPDATE/DELETE) platform_audit_events is append-only for the app
 *         role: UPDATE of any other column and DELETE are refused; the only
 *         change it may make is placing a legal hold (legal_hold false -> true),
 *         and a hold cannot be lifted by it. qodiqa_retention keeps its path.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

function connectionConfig(database, user, password) {
  return {
    host:     process.env.QODIQA_PG_HOST || 'localhost',
    port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database,
    user,
    password,
    ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  };
}

// Both qodiqa_retention and qodiqa_app already exist cluster-wide on this
// (or any previously-bootstrapped) Postgres instance — migration 038/002's
// CREATE ROLE branches are guarded on existence and are skipped here, so
// their real passwords are whatever was actually set at cluster-bootstrap
// time, NOT the placeholder literal the migration SQL contains. Locally,
// .env already carries qodiqa_retention's real password
// (QODIQA_PG_RETENTION_PASSWORD) and qodiqa_app's real password (paired
// with QODIQA_PG_USER=qodiqa_app as QODIQA_PG_PASSWORD, the same
// credential the app itself authenticates with). In CI, neither var is
// set and the ambient QODIQA_PG_USER is the container's own superuser
// ('qodiqa'), not qodiqa_app — there, both roles are genuinely fresh
// (migration 002/038's own literal CREATE ROLE ... PASSWORD statements ran
// for real), so the placeholder fallback is correct.
const RETENTION_PASSWORD = process.env.QODIQA_PG_RETENTION_PASSWORD || 'REPLACE_WITH_VAULT_SECRET_RETENTION';
const APP_PASSWORD = process.env.QODIQA_PG_USER === 'qodiqa_app'
  ? process.env.QODIQA_PG_PASSWORD
  : 'REPLACE_WITH_VAULT_SECRET_APP';

describeOrSkip('retention role separation (migration 038)', () => {
  let admin;
  let dbName;
  let retentionClient;
  let appClient;
  let probeEventId;

  beforeAll(async () => {
    // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
    // BYPASSRLS) for CREATE DATABASE, running the full migration set (002/
    // 018/038 require CREATEROLE+BYPASSRLS), and RLS-bypassing seed inserts
    // — falls back to the pre-existing chain so CI's ephemeral
    // postgres:17-alpine superuser container (QODIQA_PG_USER=qodiqa there)
    // is unaffected. retentionClient/appClient below deliberately stay on
    // their own named roles — this suite exists to test those roles' actual
    // privilege boundaries, not to run as an elevated role.
    const migrationUser = process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'postgres';
    const migrationPassword = process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD;
    admin = new Pool(connectionConfig(
      process.env.QODIQA_PG_DATABASE || 'qodiqa',
      migrationUser,
      migrationPassword,
    ));
    dbName = `qodiqa_wp020_retention_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${dbName}`);

    // Apply every migration (001..038) against the fresh, isolated database
    // using the same superuser connection migrations require for CREATE ROLE
    // / GRANT / CREATE TABLE.
    const migrationPool = new Pool(connectionConfig(
      dbName,
      migrationUser,
      migrationPassword,
    ));
    const savedEnv = { ...process.env };
    process.env.QODIQA_PG_DATABASE = dbName;
    jest.resetModules();
    const { runMigrations } = require('../../src/infra/postgres/migrate');
    await runMigrations({ pool: migrationPool });
    await migrationPool.end();
    process.env = savedEnv;

    retentionClient = new Pool(connectionConfig(dbName, 'qodiqa_retention', RETENTION_PASSWORD));
    appClient       = new Pool(connectionConfig(dbName, 'qodiqa_app', APP_PASSWORD));

    // Seed a probe row via the admin (superuser) connection — bypasses RLS
    // entirely, so this seeding step itself proves nothing about either
    // role's privileges; it only sets up fixtures for RRS-01/02 below.
    const seedPool = new Pool(connectionConfig(
      dbName,
      migrationUser,
      migrationPassword,
    ));
    const seedRes = await seedPool.query(
      `INSERT INTO platform_audit_events (occurred_at, event_type, event_category, severity, component, retain_until, legal_hold)
       VALUES (NOW(), 'WP020_PROBE', 'OPERATIONAL', 'INFO', 'retentionRoleSeparation.integration.test', NOW() - interval '1 second', false)
       RETURNING id`,
    );
    probeEventId = seedRes.rows[0].id;
    await seedPool.end();
  }, 60000);

  afterAll(async () => {
    if (retentionClient) await retentionClient.end().catch(() => {});
    if (appClient)       await appClient.end().catch(() => {});
    if (admin && dbName) {
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      ).catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
      await admin.end().catch(() => {});
    }
  }, 30000);

  test('RRS-01 qodiqa_retention can stamp and expire via the exact retention.js statement shapes', async () => {
    const updateRes = await retentionClient.query(
      `UPDATE platform_audit_events SET retain_until = NOW() - interval '1 second' WHERE id = $1`,
      [probeEventId],
    );
    expect(updateRes.rowCount).toBe(1);

    const deleteRes = await retentionClient.query(
      `DELETE FROM platform_audit_events
       WHERE id IN (
         SELECT id FROM platform_audit_events WHERE id = $1 FOR UPDATE SKIP LOCKED
       )`,
      [probeEventId],
    );
    expect(deleteRes.rowCount).toBe(1);
  });

  test('RRS-02 qodiqa_retention cannot INSERT into platform_audit_events', async () => {
    await expect(
      retentionClient.query(
        `INSERT INTO platform_audit_events (occurred_at, event_type, event_category, severity, component, retain_until, legal_hold)
         VALUES (NOW(), 'SHOULD_FAIL', 'OPERATIONAL', 'INFO', 'test', NOW(), false)`,
      ),
    ).rejects.toMatchObject({ code: '42501' });
  });

  test('RRS-03 qodiqa_retention cannot access an unrelated admin table (rbac_users)', async () => {
    await expect(
      retentionClient.query(`SELECT * FROM rbac_users LIMIT 1`),
    ).rejects.toMatchObject({ code: '42501' });
  });

  test('RRS-04 qodiqa_retention has no DDL rights', async () => {
    await expect(
      retentionClient.query(`CREATE TABLE wp020_should_not_exist (id INT)`),
    ).rejects.toThrow();
  });

  test('RRS-05 platform_audit_events is append-only for qodiqa_app: no UPDATE/DELETE, legal hold only', async () => {
    const seedPool = new Pool(connectionConfig(
      dbName,
      process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'postgres',
      process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD,
    ));
    const seedRes = await seedPool.query(
      `INSERT INTO platform_audit_events (occurred_at, event_type, event_category, severity, component, retain_until, legal_hold)
       VALUES (NOW(), 'WP020_APP_PROBE', 'OPERATIONAL', 'INFO', 'test', NOW() - interval '1 second', false)
       RETURNING id`,
    );
    const rowId = seedRes.rows[0].id;
    await seedPool.end();

    // Any column other than legal_hold: no table-level UPDATE privilege any more.
    await expect(appClient.query(
      `UPDATE platform_audit_events SET retain_until = NOW() - interval '1 second' WHERE id = $1`, [rowId],
    )).rejects.toMatchObject({ code: '42501' });
    // DELETE: revoked.
    await expect(appClient.query('DELETE FROM platform_audit_events WHERE id = $1', [rowId]))
      .rejects.toMatchObject({ code: '42501' });
    // The one sanctioned change: place a legal hold (retention.js placeLegalHold).
    const hold = await appClient.query('UPDATE platform_audit_events SET legal_hold = true WHERE id = $1 AND legal_hold = false', [rowId]);
    expect(hold.rowCount).toBe(1);
    // ...and it cannot be lifted by the app role (trigger guard).
    await expect(appClient.query('UPDATE platform_audit_events SET legal_hold = false WHERE id = $1', [rowId]))
      .rejects.toMatchObject({ code: '42501' });
  });
});
