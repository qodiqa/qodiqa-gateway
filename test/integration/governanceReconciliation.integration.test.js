'use strict';

/**
 * Governance publish reconciliation: real-PostgreSQL integration test.
 *
 * reconciliation.js's unit tests (src/core/policy/governance/__tests__/
 * reconciliation.test.js) inject a fake pool and prove the classification
 * logic; they cannot catch a SQL syntax/type error in the actual queries
 * (DISTINCT ON, NULLS LAST, GROUP BY ... HAVING) since the fake never
 * parses SQL. This test runs reconcile() against a real, freshly-migrated,
 * isolated PostgreSQL database to prove the queries themselves are valid
 * and produce correct results against the real schema (migrations 009 and
 * 029). Creates and drops its own uniquely-named scratch database; never
 * touches any pre-existing one.
 *
 * GRI-01  Clean database (no governance rows at all): reconcile() completes
 *         with outcome CLEAN and zero mismatches — proves every query is
 *         syntactically valid against the real schema.
 * GRI-02  A real PUBLISHED change request with a matching publication and
 *         matching provenance row: no divergence detected.
 * GRI-03  A real PUBLISHED change request with NO matching publication row:
 *         MISSING_PUBLICATION detected.
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

describeOrSkip('governance publish reconciliation (real PostgreSQL)', () => {
  let admin;
  let dbName;
  let pgPool;
  let reconciliation;
  let policyStoreStub;

  beforeAll(async () => {
    // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
    // BYPASSRLS) for both CREATE DATABASE and running migrations (002/018
    // require CREATEROLE+BYPASSRLS) — falls back to the pre-existing chain
    // so CI's ephemeral postgres:17-alpine superuser container
    // (QODIQA_PG_USER=qodiqa there) is unaffected.
    const migrationUser = process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'postgres';
    const migrationPassword = process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD;
    admin = new Pool(connectionConfig(
      process.env.QODIQA_PG_DATABASE || 'qodiqa',
      migrationUser,
      migrationPassword,
    ));
    dbName = `qodiqa_wp020_governance_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${dbName}`);

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

    pgPool = require('../../src/infra/postgres/pool');
    process.env.QODIQA_PG_DATABASE = dbName;
    pgPool.initialize();

    reconciliation = require('../../src/core/policy/governance/reconciliation');
    policyStoreStub = { getPolicy: jest.fn().mockReturnValue(null) };
  }, 60000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown();
    if (admin && dbName) {
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      ).catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
      await admin.end().catch(() => {});
    }
  }, 30000);

  test('GRI-01 clean database: every query is valid, outcome CLEAN, zero mismatches', async () => {
    const result = await reconciliation.reconcile({ _policyStore: policyStoreStub, _emit: jest.fn() });

    expect(result.outcome).toBe('CLEAN');
    expect(result.mismatches).toBe(0);
    expect(result.policiesScanned).toBe(0);
    expect(result.publicationsScanned).toBe(0);
  });

  test('GRI-02 real PUBLISHED change request + matching publication + matching provenance: no divergence', async () => {
    const crRes = await pgPool.query(
      `INSERT INTO policy_change_requests
         (policy_id, request_type, status, payload, change_reason, author_id, author_username, author_role,
          publisher_id, publisher_username, published_at, resulting_policy_version)
       VALUES ($1, 'CREATE', 'PUBLISHED', '{}'::jsonb, 'test', 'author-1', 'author', 'admin',
               'pub-1', 'publisher', NOW(), 1)
       RETURNING id`,
      ['gri-policy-a'],
    );
    const changeRequestId = crRes.rows[0].id;

    const content = { id: 'gri-policy-a', type: 'blockIp', priority: 1, enabled: true, config: {} };
    const provenance = require('../../src/core/policy/provenance');
    const contentHash = provenance.computePolicyHash(content);

    await pgPool.query(
      `INSERT INTO policy_publications
         (change_request_id, policy_id, published_by, published_username, resulting_policy_version, policy_hash, checksum)
       VALUES ($1, $2, 'pub-1', 'publisher', 1, 'payload-hash-not-content-hash', 'checksum-x')`,
      [changeRequestId, 'gri-policy-a'],
    );

    await pgPool.query(
      `INSERT INTO policy_provenance_versions
         (policy_id, version_number, root_version, event_type, actor_id, actor_username, actor_role, source_ip,
          change_reason, policy_content, policy_hash)
       VALUES ($1, 1, 1, 'POLICY_CREATED', 'author-1', 'author', 'admin', '127.0.0.1', 'test', $2::jsonb, $3)`,
      ['gri-policy-a', JSON.stringify(content), contentHash],
    );

    policyStoreStub.getPolicy.mockReturnValue({
      id: 'gri-policy-a', currentVersion: 1, versions: [{ v: 1, snapshot: content }],
    });

    const result = await reconciliation.reconcile({ _policyStore: policyStoreStub, _emit: jest.fn() });

    expect(result.mismatches).toBe(0);
    expect(result.policiesScanned).toBeGreaterThanOrEqual(1);
  });

  test('GRI-03 real PUBLISHED change request with no matching publication row: MISSING_PUBLICATION detected', async () => {
    await pgPool.query(
      `INSERT INTO policy_change_requests
         (policy_id, request_type, status, payload, change_reason, author_id, author_username, author_role,
          publisher_id, publisher_username, published_at, resulting_policy_version)
       VALUES ($1, 'CREATE', 'PUBLISHED', '{}'::jsonb, 'test', 'author-1', 'author', 'admin',
               'pub-1', 'publisher', NOW(), 1)`,
      ['gri-policy-orphan'],
    );

    policyStoreStub.getPolicy.mockReturnValue({
      id: 'gri-policy-orphan', currentVersion: 1, versions: [{ v: 1, snapshot: {} }],
    });

    const emitted = [];
    await reconciliation.reconcile({ _policyStore: policyStoreStub, _emit: (...args) => emitted.push(args) });

    const divergence = emitted.find(e =>
      e[1] === 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED' &&
      e[2].policyId === 'gri-policy-orphan',
    );
    expect(divergence).toBeDefined();
    expect(divergence[2].divergenceType).toBe('MISSING_PUBLICATION');
  });
});
