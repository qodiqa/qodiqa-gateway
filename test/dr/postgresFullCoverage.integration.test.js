'use strict';

/**
 * remediation — live PostgreSQL backup/restore coverage proof.
 *
 * Runs the ACTUAL scripts/dr/postgres.js dump -> restore -> validate cycle
 * against a real PostgreSQL instance (a local dev Postgres in this
 * environment; the equivalent CI job — dr-postgres in
 * .github/workflows/backup-restore.yml — uses a service container instead).
 * This is the strongest proof in the remediation: it doesn't just assert the
 * CODE calls discoverTables() instead of a hardcoded list (see
 * backupCoverage.test.js for that, offline), it proves that against a real
 * database with a real (migrated) schema, EVERY table — including the ones
 * called out by name: consent, investigations, compliance reports,
 * audit, security — is captured and comes back byte-for-byte-equivalent in
 * row count, with valid foreign keys and synced sequences.
 *
 * Self-contained: creates two throwaway databases (source + restore target),
 * migrates both with the real migration runner, seeds representative rows,
 * and drops both databases again in afterAll — never touches whatever
 * QODIQA_PG_DATABASE / QODIQA_PG_URL points the rest of the app at.
 *
 * Skips entirely (describe.skip) when no Postgres connection is configured,
 * matching the existing pattern of "Postgres is a complement, not a
 * requirement" used throughout scripts/dr/ (see postgres.js's header
 * comment) — this suite adds coverage, it does not make Postgres mandatory
 * to run the rest of the test suite.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { dropTestDatabase } = require('../helpers/dropTestDatabase');

const { dumpPostgres, restorePostgres } = require('../../scripts/dr/postgres');
const { validatePostgresRestore } = require('../../scripts/dr/probes/postgresProbe');
const { EXPECTED_TABLES } = require('../../scripts/dr/table-registry');

function _adminConnInfo() {
  // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
  // BYPASSRLS) for CREATE DATABASE + running migrations on both scratch
  // databases (002/018 require CREATEROLE+BYPASSRLS) — falls back to the
  // pre-existing chain so CI's ephemeral postgres:17-alpine superuser
  // container (QODIQA_PG_USER=qodiqa there) is unaffected.
  if (process.env.QODIQA_PG_URL || process.env.DATABASE_URL) {
    const u = new URL(process.env.QODIQA_PG_URL || process.env.DATABASE_URL);
    return {
      host: u.hostname,
      port: u.port || 5432,
      user: process.env.QODIQA_PG_TEST_USER || decodeURIComponent(u.username),
      password: process.env.QODIQA_PG_TEST_PASSWORD || decodeURIComponent(u.password),
    };
  }
  if (process.env.QODIQA_PG_HOST) {
    return {
      host: process.env.QODIQA_PG_HOST,
      port: process.env.QODIQA_PG_PORT || 5432,
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER,
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD,
    };
  }
  return null;
}

// 2026-10-06: opt-in like every other PostgreSQL suite. "Any host configured" was not a safe signal — this
// suite loads .env itself, and on a developer machine .env names the cluster hosting LIVE (a verification run created and
// dropped its two scratch databases there). CI's dr-postgres job sets
// QODIQA_ALLOW_PG_INTEGRATION_TESTS=true for this step.
const ADMIN = process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true' ? _adminConnInfo() : null;
const HAS_DB = !!ADMIN;

function _urlFor(database) {
  return `postgres://${encodeURIComponent(ADMIN.user)}:${encodeURIComponent(ADMIN.password)}@${ADMIN.host}:${ADMIN.port}/${database}`;
}

(HAS_DB ? describe : describe.skip)('live PostgreSQL backup/restore full coverage', () => {
  jest.setTimeout(120_000);

  const suffix = crypto.randomBytes(4).toString('hex');
  const sourceDb  = `qodiqa_dr_it_src_${suffix}`;
  const restoreDb = `qodiqa_dr_it_dst_${suffix}`;
  let maintenancePool;
  let seeded;

  beforeAll(async () => {
    maintenancePool = new Pool({ connectionString: _urlFor('postgres') });
    await maintenancePool.query(`CREATE DATABASE ${sourceDb}`);
    await maintenancePool.query(`CREATE DATABASE ${restoreDb}`);

    const { runMigrations } = require('../../src/infra/postgres/migrate.js');
    const sourcePool  = new Pool({ connectionString: _urlFor(sourceDb) });
    const restorePool = new Pool({ connectionString: _urlFor(restoreDb) });
    try {
      await runMigrations({ pool: sourcePool });
      await runMigrations({ pool: restorePool });
    } finally {
      await sourcePool.end();
      await restorePool.end();
    }

    seeded = await _seedRepresentativeData(_urlFor(sourceDb));
  });

  afterAll(async () => {
    if (!maintenancePool) return;
    // the previous best-effort drop swallowed its error and leaked these databases
    //. The helper retries the forced drop and REPORTS a failure.
    for (const db of [sourceDb, restoreDb]) {
      const r = await dropTestDatabase(maintenancePool, db);
      // eslint-disable-next-line no-console
      if (!r.dropped) console.warn(`[postgresFullCoverage] failed to drop ${db}: ${r.error} — attached: ${JSON.stringify(r.attached)}`);
    }
    await maintenancePool.end();
  });

  test('dump discovers and captures every table in the live schema (not a hardcoded 8)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dr-it-dump-'));
    const dump = await dumpPostgres(dir, { connectionString: _urlFor(sourceDb) });

    // The historical bug: coverage stuck at 8 no matter how many tables
    // the schema actually had. Assert coverage scales with the schema.
    expect(dump.coverage.discoveredTableCount).toBeGreaterThanOrEqual(50);
    expect(dump.coverage.dumpedTableCount).toBe(dump.coverage.discoveredTableCount);
    expect(dump.tables.every(t => t.present)).toBe(true);

    // Every table named explicitly is actually in the dump.
    const dumpedNames = dump.tables.map(t => t.table);
    for (const table of ['consent_records', 'consent_audit_log', 'investigations',
      'investigation_artifacts', 'compliance_reports', 'compliance_control_assessments',
      'audit_chain', 'rbac_users']) {
      expect(dumpedNames).toContain(table);
    }
  });

  test('full backup -> restore -> validate cycle: every table, every row, valid FKs, synced sequences', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dr-it-cycle-'));

    const dump = await dumpPostgres(dir, { connectionString: _urlFor(sourceDb) });
    const restoreResult = await restorePostgres(dir, dump, { connectionString: _urlFor(restoreDb) });
    // the restore verified the target's SECURITY DEFINER ownership (NOLOGIN, non-superuser qodiqa_definer)
    expect(restoreResult.definerOwnership).toEqual({ verified: true, owner: 'qodiqa_definer', definers: 47, schemaOwner: 'qodiqa_owner' }); // + closure (081)

    // Every table that had rows in the source restored the SAME row count.
    for (const entry of restoreResult.tables) {
      if (entry.skipped) continue;
      expect(entry.restored).toBe(entry.expected);
    }

    // Independently re-verify row counts directly against the restore target
    // (not just trusting restorePostgres's own bookkeeping).
    const restorePool = new Pool({ connectionString: _urlFor(restoreDb) });
    try {
      for (const t of dump.tables.filter(t => t.present)) {
        const { rows } = await restorePool.query(`SELECT count(*)::int AS c FROM "${t.table}"`);
        expect(rows[0].c).toBe(t.rowCount);
      }
    } finally {
      await restorePool.end();
    }

    // The dedicated probe: FK validity + sequence sync + row counts.
    const validation = await validatePostgresRestore(dump, { connectionString: _urlFor(restoreDb) });
    expect(validation.rowCountMismatches).toEqual([]);
    expect(validation.fkViolations).toEqual([]);
    expect(validation.sequenceIssues).toEqual([]);
    expect(validation.valid).toBe(true);

    // Representative-data proof, by name, for the exact categories
    // called out: consent, investigations, compliance reports.
    const checkPool = new Pool({ connectionString: _urlFor(restoreDb) });
    try {
      const consent = await checkPool.query(`SELECT actor_id, state FROM consent_records WHERE actor_id = $1`, [seeded.actorId]);
      expect(consent.rows).toHaveLength(1);
      expect(consent.rows[0].state).toBe('ACTIVE');

      const inv = await checkPool.query(`SELECT title FROM investigations WHERE id = $1`, [seeded.investigationId]);
      expect(inv.rows).toHaveLength(1);

      const rpt = await checkPool.query(`SELECT report_ref, status FROM compliance_reports WHERE id = $1`, [seeded.reportId]);
      expect(rpt.rows).toHaveLength(1);
      expect(rpt.rows[0].status).toBe('COMPLETE');

      // Prove the sequence fix: a fresh DEFAULT-driven insert must not
      // collide with restored data.
      const ins = await checkPool.query(
        `INSERT INTO qodiqa_migrations (version, name, checksum) VALUES (99999, 'dr-it-seq-proof', $1) RETURNING id`,
        ['a'.repeat(64)],
      );
      expect(ins.rows[0].id).toBeGreaterThan(0);
    } finally {
      await checkPool.end();
    }
  });

  test('restore is FK-safe regardless of discovery order — dependency-ordered insert never violates a constraint', async () => {
    // Already proven implicitly by the previous test succeeding without an
    // FK-violation error (restorePostgres throws on the first insert
    // failure — see scripts/dr/postgres.js), but assert it explicitly: a
    // parent table's rows must appear before its children's in the manifest
    // the dump produced.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-dr-it-order-'));
    const dump = await dumpPostgres(dir, { connectionString: _urlFor(sourceDb) });
    const order = dump.tables.map(t => t.table);

    const parentBeforeChild = [
      ['investigations', 'investigation_artifacts'],
      ['investigations', 'investigation_audit_events'],
      ['consent_records', 'consent_audit_log'],
      ['compliance_frameworks', 'compliance_reports'],
      ['compliance_reports', 'compliance_control_assessments'],
      ['rbac_users', 'evidence_packages'],
    ];
    for (const [parent, child] of parentBeforeChild) {
      expect(order.indexOf(parent)).toBeGreaterThanOrEqual(0);
      expect(order.indexOf(child)).toBeGreaterThanOrEqual(0);
      expect(order.indexOf(parent)).toBeLessThan(order.indexOf(child));
    }
  });
});

/** Seed representative rows across the exact data categories named. */
async function _seedRepresentativeData(connectionString) {
  const pool = new Pool({ connectionString });
  try {
    const actorId = `actor-dr-it-${crypto.randomBytes(4).toString('hex')}`;
    const u = await pool.query(`INSERT INTO rbac_users (username, role) VALUES ($1, 'auditor') RETURNING id`,
      [`dr-it-user-${crypto.randomBytes(3).toString('hex')}`]);

    const c = await pool.query(
      `INSERT INTO consent_records (actor_id, action, state, granted_by) VALUES ($1, 'inference', 'ACTIVE', 'dr-it-suite') RETURNING id`,
      [actorId],
    );
    await pool.query(
      `INSERT INTO consent_audit_log (consent_id, event_type, actor, actor_id, action, verification_result)
       VALUES ($1, 'GRANTED', 'dr-it-suite', $2, 'inference', 'VERIFIED')`,
      [c.rows[0].id, actorId],
    );

    const investigationId = 'INV-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    await pool.query(`INSERT INTO investigations (id, title, investigator) VALUES ($1, $2, 'dr-it-suite')`,
      [investigationId, 'integration test investigation']);
    await pool.query(`INSERT INTO investigation_artifacts (investigation_id, artifact_id) VALUES ($1, $2)`,
      [investigationId, 'artifact-dr-it-1']);
    await pool.query(`INSERT INTO investigation_audit_events (investigation_id, event_type) VALUES ($1, 'CREATED')`,
      [investigationId]);
    await pool.query(
      `INSERT INTO evidence_packages (artifact_id, schema_version, generator_version, requestor_id, package_hash)
       VALUES ('artifact-dr-it-1', '1.0', '1.0.0', $1, $2)`,
      [u.rows[0].id, 'e'.repeat(64)],
    );

    const rpt = await pool.query(
      `INSERT INTO compliance_reports (report_ref, framework_id, framework_name, title, period_start, period_end, generated_by, status)
       VALUES ($1, 'GDPR', 'General Data Protection Regulation', 'integration test report', NOW() - interval '30 days', NOW(), 'dr-it-suite', 'COMPLETE')
       RETURNING id`,
      [`RPT-DR-IT-${crypto.randomBytes(4).toString('hex')}`],
    );
    await pool.query(
      `INSERT INTO compliance_control_assessments (report_id, control_id, framework_id, status, score)
       SELECT $1, id, framework_id, 'PASS', 100 FROM compliance_controls LIMIT 1`,
      [rpt.rows[0].id],
    ).catch(() => { /* control catalog may be empty in a fresh schema — not the point of this test */ });

    await pool.query(
      `INSERT INTO audit_chain (hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time,
                                 input_hash, signature, request_hash, policy_hash, verification_result)
       VALUES ($1, 'GENESIS', '{}', 'artifact-dr-it-1', 'ALLOW', NOW(), '1', $2, $3, $4, $5, true)`,
      [crypto.randomBytes(32).toString('hex'), 'i'.repeat(64), 's'.repeat(64), 'r'.repeat(64), 'p'.repeat(64)],
    );

    return { actorId, investigationId, reportId: rpt.rows[0].id };
  } finally {
    await pool.end();
  }
}
