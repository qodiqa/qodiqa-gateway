'use strict';

/**
 * SECURITY DEFINER adversarial invocation (real disposable Postgres).
 * Extended to cover migration 053's 8 additional functions and to
 * replace the static ALL_21 inventory with an explicit, reviewed registry
 * (SECURITY_DEFINER_INVENTORY, in the "Nested SECURITY DEFINER chains and
 * search_path" describe block below) that fails loudly — by function name —
 * if a future migration adds a SECURITY DEFINER function without registering
 * it here, rather than a bare count that only reports "wrong number".
 *
 * inventoried the original 21 SECURITY DEFINER functions but left
 * per-function cross-tenant invocation outstanding; built this suite
 * to prove it for those 21; migration 053 later added 8 more that
 * went uncovered until (discovered by the consolidated
 * tenant-isolation gate) added SD-22..SD-29 below. This suite now proves, for
 * every one of the 29 registered functions, that its documented cross-tenant
 * read is: (a) unconditional on caller tenant context (never accidentally
 * gated on session state), (b) genuinely reaches across tenants (proving the
 * bypass is real, not a coincidence of the seed data), (c) never mutates data
 * (all 29 are pure reads), and (d) is unreachable by any role without an
 * explicit EXECUTE grant. for
 * the original design rationale — in particular why a uniform, per-function
 * data-driven battery was used instead of bespoke test bodies (the static
 * review established that the
 * original 21 share an identical structural pattern: pure SELECT, no tenant
 * parameter, no tenant-context read, no writes, no nested calls — migration
 * 053's 8 share the exact same pattern, confirmed in
 *).
 *
 * Real qodiqa_app pooled connection for every function invocation under
 * test (never BYPASSRLS for the thing being tested) — qodiqa_test
 * (BYPASSRLS) is used only for seeding and ground-truth row counts, exactly
 * mirroring test/security/crossTenantAdversarial.integration.test.js's own pattern.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');
const path     = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const REPO_ROOT = path.join(__dirname, '..', '..');
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_sdadv_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const NOPRIV_ROLE = `sdadv_norole_${crypto.randomBytes(4).toString('hex')}`;
const NOPRIV_PASSWORD = crypto.randomBytes(16).toString('hex');

const TENANT_A = 'sdadv-tenant-alpha';
const TENANT_B = 'sdadv-tenant-bravo';
const SENTINEL_A = `SDADV-ALPHA-${crypto.randomBytes(8).toString('hex')}`;
const SENTINEL_B = `SDADV-BRAVO-${crypto.randomBytes(8).toString('hex')}`;
const SENTINEL_P = `SDADV-PLATFORM-${crypto.randomBytes(8).toString('hex')}`;

let _maintenancePool;   // qodiqa_test — create/drop the disposable DB and the throwaway role
let _bypassPool;        // qodiqa_test — seeding + ground-truth row counts (BYPASSRLS)
let _appPool;           // qodiqa_app — the role under test for every function invocation
let _noPrivPool;        // throwaway role with zero grants — permission-boundary proof
let _systemPool;       // qodiqa_system (integrity / background)
let _reportingPool;    // qodiqa_reporting (operator consoles)
let pgPool, tenantConfigStore, changeRequestStore;

const SEED = {};

jest.setTimeout(120_000);

function hex64() {
  return crypto.randomBytes(32).toString('hex');
}

describeOrSkip('SECURITY DEFINER adversarial invocation (real disposable Postgres)', () => {
  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) {
      throw new Error(`Generated test DB name "${TEST_DB_NAME}" failed identifier validation — refusing to proceed.`);
    }

    _maintenancePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user:     process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
      password: process.env.QODIQA_PG_TEST_PASSWORD,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);
    await _maintenancePool.query(
      `CREATE ROLE ${NOPRIV_ROLE} LOGIN PASSWORD '${NOPRIV_PASSWORD}'`,
    );

    const _ownerPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
      password: process.env.QODIQA_PG_TEST_PASSWORD,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _ownerPool.query(`GRANT ALL ON SCHEMA public TO ${process.env.QODIQA_PG_MIG_USER || 'qodiqa_mig'}`);
    await _ownerPool.query(`GRANT CONNECT ON DATABASE "${TEST_DB_NAME}" TO ${NOPRIV_ROLE}`);
    await _ownerPool.end();

    const _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;

    const { spawnSync } = require('child_process');
    const migrateRes = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        QODIQA_PG_DATABASE: TEST_DB_NAME,
        QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
        QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD,
      },
      encoding: 'utf8',
      timeout: 45_000,
    });
    if (migrateRes.status !== 0) {
      throw new Error(`migrate.js failed (status=${migrateRes.status}): \nstdout:\n${migrateRes.stdout}\nstderr:\n${migrateRes.stderr}`);
    }
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    SEED._testDbName = TEST_DB_NAME;

    jest.resetModules();
    pgPool            = require('../../src/infra/postgres/pool');
    tenantConfigStore = require('../../src/core/tenancy/tenantConfigStore');
    changeRequestStore = require('../../src/core/policy/governance/ChangeRequestStore');

    const _prevDb = process.env.QODIQA_PG_DATABASE;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    pgPool.initialize(); // qodiqa_app, per QODIQA_PG_USER — the real pooled role under test
    process.env.QODIQA_PG_DATABASE = _prevDb;

    _appPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_PASSWORD,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    _bypassPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
      password: process.env.QODIQA_PG_TEST_PASSWORD,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    // the only sanctioned cross-tenant readers (migration 060/061).
    _systemPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_SYSTEM_USER || 'qodiqa_system',
      password: process.env.QODIQA_PG_SYSTEM_PASSWORD,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    _reportingPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_REPORTING_USER || 'qodiqa_reporting',
      password: process.env.QODIQA_PG_REPORTING_PASSWORD,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    _noPrivPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: NOPRIV_ROLE,
      password: NOPRIV_PASSWORD,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });

    // ── Seed audit_chain: A, a REPLAY row owned by B claiming replayOf=A's artifact, and a platform (NULL-tenant) row ──
    // idx_audit_chain_prev_hash_unique requires a genuinely chained prev_hash per row (only one
    // row may ever claim 'GENESIS') — build a real 3-link chain rather than 3 independent rows.
    const auditRow = ({ tenantId, artifactId, executionContext, prevHash }) => _bypassPool.query(
      `INSERT INTO audit_chain (
         hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time,
         input_hash, signature, request_hash, policy_hash, verification_result, tenant_id, execution_context
       ) VALUES ($1,$2,'{}',$3,'ALLOW',now(),$4,$5,$6,$7,$8,true,$9,$10)
       RETURNING seq, hash, artifact_id, tenant_id`,
      [hex64(), prevHash, artifactId, String(process.hrtime.bigint()), hex64(), hex64(), hex64(), hex64(), tenantId, executionContext ? JSON.stringify(executionContext) : null],
    );

    const ART_A = `sdadv-artifact-A-${SENTINEL_A}`;
    const ART_B_REPLAY = `sdadv-artifact-Breplay-${SENTINEL_B}`;
    const ART_P = `sdadv-artifact-P-${SENTINEL_P}`;

    const rA = await auditRow({ tenantId: TENANT_A, artifactId: ART_A, prevHash: 'GENESIS' });
    const rReplayB = await auditRow({ tenantId: TENANT_B, artifactId: ART_B_REPLAY, executionContext: { replayOf: ART_A }, prevHash: rA.rows[0].hash });
    const rP = await auditRow({ tenantId: null, artifactId: ART_P, prevHash: rReplayB.rows[0].hash });

    SEED.audit = {
      artA: ART_A, artBReplay: ART_B_REPLAY, artP: ART_P,
      hashA: rA.rows[0].hash, hashBReplay: rReplayB.rows[0].hash, hashP: rP.rows[0].hash,
      seqA: rA.rows[0].seq, seqBReplay: rReplayB.rows[0].seq, seqP: rP.rows[0].seq,
    };

    // ── Seed transparency_log_entries: A, B, platform ──
    const tlRow = ({ tenantId, artifactId, evidenceChainId }) => _bypassPool.query(
      `INSERT INTO transparency_log_entries (
         entry_type, artifact_id, evidence_chain_id, payload, payload_hash, entry_hash,
         signer_key_id, signature, tenant_id
       ) VALUES ('ARTIFACT',$1,$2,'{}',$3,$4,'sdadv-key',$5,$6)
       RETURNING id, transparency_id, entry_hash, artifact_id, evidence_chain_id, tenant_id`,
      [artifactId, evidenceChainId, hex64(), hex64(), hex64(), tenantId],
    );

    const TL_ART_A = `sdadv-tl-artifact-A-${SENTINEL_A}`;
    const TL_ART_B = `sdadv-tl-artifact-B-${SENTINEL_B}`;
    const TL_ART_P = `sdadv-tl-artifact-P-${SENTINEL_P}`;
    const EVID_A = crypto.randomUUID();
    const EVID_B = crypto.randomUUID();

    const tA = await tlRow({ tenantId: TENANT_A, artifactId: TL_ART_A, evidenceChainId: EVID_A });
    const tB = await tlRow({ tenantId: TENANT_B, artifactId: TL_ART_B, evidenceChainId: EVID_B });
    const tP = await tlRow({ tenantId: null, artifactId: TL_ART_P, evidenceChainId: null });

    SEED.tl = {
      idA: tA.rows[0].id, idB: tB.rows[0].id, idP: tP.rows[0].id,
      transparencyIdA: tA.rows[0].transparency_id, transparencyIdB: tB.rows[0].transparency_id,
      hashA: tA.rows[0].entry_hash, hashB: tB.rows[0].entry_hash, hashP: tP.rows[0].entry_hash,
      artA: TL_ART_A, artB: TL_ART_B, artP: TL_ART_P,
      evidA: EVID_A, evidB: EVID_B,
    };

    // ── Seed policy_change_requests via the real, correctly-tenant-scoped ChangeRequestStore ──
    const reqA = await changeRequestStore.create({
      policy_id: 'sdadv-policy-a', tenant_id: TENANT_A, request_type: 'UPDATE',
      payload: { sentinel: SENTINEL_A }, change_reason: 'sdadv seed A',
      author: { id: 'sdadv-a', username: 'sdadv-a', role: 'admin' },
    });
    const reqB = await changeRequestStore.create({
      policy_id: 'sdadv-policy-b', tenant_id: TENANT_B, request_type: 'UPDATE',
      payload: { sentinel: SENTINEL_B }, change_reason: 'sdadv seed B',
      author: { id: 'sdadv-b', username: 'sdadv-b', role: 'admin' },
    });
    SEED.pcr = { idA: reqA.id, idB: reqB.id };

    // ── Seed tenant_policy_sets / tenant_semantic_configs via the real tenantConfigStore ──
    await tenantConfigStore.upsertPolicySet({
      tenantId: TENANT_A, policies: [{ id: 'p1', type: 'RATE_LIMIT', sentinel: SENTINEL_A }], updatedBy: 'sdadv-test',
    });
    await tenantConfigStore.upsertPolicySet({
      tenantId: TENANT_B, policies: [{ id: 'p1', type: 'RATE_LIMIT', sentinel: SENTINEL_B }], updatedBy: 'sdadv-test',
    });
    await tenantConfigStore.upsertSemanticConfig({
      tenantId: TENANT_A, config: { sentinel: SENTINEL_A }, updatedBy: 'sdadv-test',
    });
    await tenantConfigStore.upsertSemanticConfig({
      tenantId: TENANT_B, config: { sentinel: SENTINEL_B }, updatedBy: 'sdadv-test',
    });

    // ── seed the 8 tables migration 053's SECURITY DEFINER functions bypass ──
    // (platform_audit_events, evidence_chain_records, qodiqa_alerts/_history,
    // consent_audit_log, audit_retention_policies, audit_legal_holds,
    // compliance_reports) — A/B rows carrying SENTINEL_A/SENTINEL_B, exactly the
    // same tenant-A/tenant-B/platform shape already used above, so SD-22..SD-29
    // below can assert genuine cross-tenant reach the same way SD-01..SD-21 do.
    const paeRow = await _bypassPool.query(
      `INSERT INTO platform_audit_events (event_id, schema_version, occurred_at, ingested_at, event_type, event_category, severity, component, tenant_id, outcome, payload)
       VALUES (gen_random_uuid(),'1.0',now(),now(),'GATEWAY_ALLOW','ENFORCEMENT','INFO','ENFORCEMENT_GATEWAY',$1,'ALLOW',$2)
       RETURNING event_id`,
      [TENANT_A, JSON.stringify({ sentinel: SENTINEL_A })],
    );
    await _bypassPool.query(
      `INSERT INTO platform_audit_events (event_id, schema_version, occurred_at, ingested_at, event_type, event_category, severity, component, tenant_id, outcome, payload)
       VALUES (gen_random_uuid(),'1.0',now(),now(),'GATEWAY_ALLOW','ENFORCEMENT','INFO','ENFORCEMENT_GATEWAY',$1,'ALLOW',$2)`,
      [TENANT_B, JSON.stringify({ sentinel: SENTINEL_B })],
    );
    SEED.pae = { idA: paeRow.rows[0].event_id };

    const ecrRow = await _bypassPool.query(
      `INSERT INTO evidence_chain_records (evidence_id, artifact_id, artifact_hash, policy_id, policy_hash, audit_record_id, audit_record_hash, evidence_hash, decision, tenant_id, created_at, schema_version)
       VALUES (gen_random_uuid(),$1,'ah','POLICY_SET','ph',gen_random_uuid(),$2,$3,'ALLOW',$4,now(),1) RETURNING evidence_id`,
      [`sdadv-ecr-artifact-A-${SENTINEL_A}`, hex64(), hex64(), TENANT_A],
    );
    await _bypassPool.query(
      `INSERT INTO evidence_chain_records (evidence_id, artifact_id, artifact_hash, policy_id, policy_hash, audit_record_id, audit_record_hash, evidence_hash, decision, tenant_id, created_at, schema_version)
       VALUES (gen_random_uuid(),$1,'ah','POLICY_SET','ph',gen_random_uuid(),$2,$3,'ALLOW',$4,now(),1)`,
      [`sdadv-ecr-artifact-B-${SENTINEL_B}`, hex64(), hex64(), TENANT_B],
    );
    SEED.ecr = { idA: ecrRow.rows[0].evidence_id };

    const alertA = await _bypassPool.query(
      `INSERT INTO qodiqa_alerts (id, alert_type, alert_subtype, severity, status, risk_score, confidence, title, tenant_id, detected_at, retain_until, dedup_key)
       VALUES (gen_random_uuid(),'ANOMALY','x','MEDIUM','OPEN',50,0.5,$1,$2,now(),now()+interval '30 days',$3) RETURNING id`,
      [`sdadv alert ${SENTINEL_A}`, TENANT_A, `sdadv-dedup-a-${SENTINEL_A}`],
    );
    const alertB = await _bypassPool.query(
      `INSERT INTO qodiqa_alerts (id, alert_type, alert_subtype, severity, status, risk_score, confidence, title, tenant_id, detected_at, retain_until, dedup_key)
       VALUES (gen_random_uuid(),'ANOMALY','x','MEDIUM','OPEN',50,0.5,$1,$2,now(),now()+interval '30 days',$3) RETURNING id`,
      [`sdadv alert ${SENTINEL_B}`, TENANT_B, `sdadv-dedup-b-${SENTINEL_B}`],
    );
    await _bypassPool.query(
      `INSERT INTO qodiqa_alert_history (alert_id, action, actor, to_status, detail) VALUES ($1,'CREATED','seed','OPEN',$2)`,
      [alertA.rows[0].id, JSON.stringify({ sentinel: SENTINEL_A })],
    );
    await _bypassPool.query(
      `INSERT INTO qodiqa_alert_history (alert_id, action, actor, to_status, detail) VALUES ($1,'CREATED','seed','OPEN',$2)`,
      [alertB.rows[0].id, JSON.stringify({ sentinel: SENTINEL_B })],
    );
    SEED.alerts = { idA: alertA.rows[0].id, idB: alertB.rows[0].id };

    await _bypassPool.query(
      `INSERT INTO consent_audit_log (event_type, actor, actor_id, tenant_id, detail) VALUES ('CONSENT_GRANTED','seed',$1,$2,$3)`,
      [`sdadv-actor-a-${SENTINEL_A}`, TENANT_A, JSON.stringify({ sentinel: SENTINEL_A })],
    );
    await _bypassPool.query(
      `INSERT INTO consent_audit_log (event_type, actor, actor_id, tenant_id, detail) VALUES ('CONSENT_GRANTED','seed',$1,$2,$3)`,
      [`sdadv-actor-b-${SENTINEL_B}`, TENANT_B, JSON.stringify({ sentinel: SENTINEL_B })],
    );

    await _bypassPool.query(
      `INSERT INTO audit_retention_policies (name, tenant_id, retain_days) VALUES ($1,$2,90)`,
      [`sdadv-policy-a-${SENTINEL_A}`, TENANT_A],
    );
    await _bypassPool.query(
      `INSERT INTO audit_retention_policies (name, tenant_id, retain_days) VALUES ($1,$2,90)`,
      [`sdadv-policy-b-${SENTINEL_B}`, TENANT_B],
    );

    await _bypassPool.query(
      `INSERT INTO audit_legal_holds (hold_name, reason, tenant_id, held_by) VALUES ($1,'litigation',$2,'seed')`,
      [`sdadv-hold-a-${SENTINEL_A}`, TENANT_A],
    );
    await _bypassPool.query(
      `INSERT INTO audit_legal_holds (hold_name, reason, tenant_id, held_by) VALUES ($1,'litigation',$2,'seed')`,
      [`sdadv-hold-b-${SENTINEL_B}`, TENANT_B],
    );

    const rptA = await _bypassPool.query(
      `INSERT INTO compliance_reports (id, report_ref, framework_id, framework_name, tenant_id, title, period_start, period_end, generated_by, generator_version, schema_version, status, controls_total)
       VALUES (gen_random_uuid(),$1,'GDPR','GDPR',$2,$3,now()-interval '1 day',now(),'seed','1.0.0','1.0','COMPLETE',0) RETURNING id`,
      [`RPT-SDADV-A-${SENTINEL_A}`, TENANT_A, `sdadv report ${SENTINEL_A}`],
    );
    const rptB = await _bypassPool.query(
      `INSERT INTO compliance_reports (id, report_ref, framework_id, framework_name, tenant_id, title, period_start, period_end, generated_by, generator_version, schema_version, status, controls_total)
       VALUES (gen_random_uuid(),$1,'GDPR','GDPR',$2,$3,now()-interval '1 day',now(),'seed','1.0.0','1.0','COMPLETE',0) RETURNING id`,
      [`RPT-SDADV-B-${SENTINEL_B}`, TENANT_B, `sdadv report ${SENTINEL_B}`],
    );
    SEED.reports = { idA: rptA.rows[0].id, idB: rptB.rows[0].id };

    // Grant EXECUTE on all functions to the throwaway role's PREDECESSOR state is
    // intentionally absent — NOPRIV_ROLE gets CONNECT only, never EXECUTE on anything,
    // which is exactly the permission-boundary condition under test.
  }, 120_000);

  afterAll(async () => {
    if (_appPool) await _appPool.end().catch(() => {});
    if (_bypassPool) await _bypassPool.end().catch(() => {});
    if (_noPrivPool) await _noPrivPool.end().catch(() => {});
    if (_systemPool) await _systemPool.end().catch(() => {});
    if (_reportingPool) await _reportingPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[securityDefinerAdversarial] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      try {
        await _maintenancePool.query(`DROP ROLE IF EXISTS ${NOPRIV_ROLE}`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[securityDefinerAdversarial] failed to drop role ${NOPRIV_ROLE}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  // ── Helpers ──────────────────────────────────────────────────────────────────

  async function callAs(mode, sql, params = [], pool = _appPool) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      if (mode === 'A') await client.query(`SELECT set_config('qodiqa.tenant_id', $1, true)`, [TENANT_A]);
      else if (mode === 'B') await client.query(`SELECT set_config('qodiqa.tenant_id', $1, true)`, [TENANT_B]);
      else if (mode === 'invalid') await client.query(`SELECT set_config('qodiqa.tenant_id', $1, true)`, ['zzz-sdadv-nonexistent-tenant']);
      const res = await client.query(sql, params);
      await client.query('COMMIT');
      return res.rows;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  }

  async function bypassCount(table) {
    const res = await _bypassPool.query(`SELECT count(*)::int AS c FROM ${table}`);
    return res.rows[0].c;
  }

  function serialize(rows) {
    // Stable serialization: sort by every key's string value so row ORDER
    // differences (which can legitimately vary run to run for ties on
    // identical timestamps) don't cause a false context-dependence failure.
    return JSON.stringify(
      [...rows].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    );
  }

  /**
   * Registers one adversarial test for a single SECURITY DEFINER function.
   * Exercises: (1) context-independence across none/A/B/invalid tenant
   * context, (2) zero write side-effect on the underlying table,
   * (3) a function-specific cross-tenant reach assertion, (4) permission
   * denial for a role with no EXECUTE grant.
   */
  // the non-owner role each function is granted to
  //. 'owner' = no non-owner grant at all.
  const GRANTED = {
    qodiqa_audit_chain_full_read: 'system', qodiqa_audit_chain_fetch_batch: 'system', qodiqa_audit_chain_detect_sequence_gaps: 'system',
    qodiqa_audit_chain_fetch_row_by_seq: 'system', qodiqa_audit_chain_max_seq: 'system', qodiqa_audit_chain_hash_exists: 'system',
    qodiqa_audit_chain_true_tail: 'system', qodiqa_audit_chain_fetch_by_artifact_id: 'reporting', qodiqa_audit_chain_fetch_replay_lineage: 'reporting',
    qodiqa_transparency_log_fetch_batch: 'system', qodiqa_transparency_log_fetch_hashes_in_range: 'system', qodiqa_transparency_log_fetch_boundary: 'system',
    qodiqa_transparency_log_fetch_by_transparency_id: 'system', qodiqa_transparency_log_fetch_by_entry_hash: 'owner',
    qodiqa_transparency_log_fetch_by_artifact_id: 'reporting', qodiqa_transparency_log_latest_entry: 'system',
    qodiqa_transparency_log_fetch_range_full: 'reporting', qodiqa_transparency_log_read_all: 'reporting',
    qodiqa_policy_change_request_by_id: 'reporting', qodiqa_tenant_policy_sets_full_read: 'system', qodiqa_tenant_semantic_configs_full_read: 'system',
    qodiqa_platform_audit_events_full_read: 'reporting', qodiqa_evidence_chain_records_full_read: 'reporting', qodiqa_qodiqa_alerts_full_read: 'reporting',
    qodiqa_qodiqa_alert_history_full_read: 'reporting', qodiqa_consent_audit_log_full_read: 'system', qodiqa_audit_retention_policies_full_read: 'reporting',
    qodiqa_audit_legal_holds_full_read: 'reporting', qodiqa_compliance_reports_full_read: 'reporting', qodiqa_policy_emergency_activations_full_read: 'system',
    // step 6 (migration 069): per-request trails + audit-chain decision facts for the ops console
    qodiqa_request_trails_by_ids: 'reporting', qodiqa_audit_chain_decisions: 'reporting',
    // S2 (migration 073): the audit_chain row counter — O(1) read + exact cross-check for qodiqa_system; the
    // DR rebuild and the three trigger functions have no non-owner grant.
    qodiqa_audit_chain_mirror_count: 'system', qodiqa_audit_chain_mirror_count_check: 'system', qodiqa_audit_chain_mirror_count_rebuild: 'owner',
    qodiqa_audit_chain_mirror_count_on_insert: 'owner', qodiqa_audit_chain_mirror_count_on_delete: 'owner', qodiqa_audit_chain_mirror_count_on_truncate: 'owner',
  };
  // qodiqa_transparency_log_fetch_hashes_in_range is ALSO app-executable.
  const ALSO_APP = new Set(['qodiqa_transparency_log_fetch_hashes_in_range']);
  const fnOf = (sql) => (sql.match(/qodiqa_[a-z_]+(?=\s*\()/) || [])[0];
  function poolFor(fn) {
    const g = GRANTED[fn];
    if (!g) throw new Error(`no grant mapping for ${fn}`);
    return g === 'system' ? _systemPool : g === 'reporting' ? _reportingPool : _bypassPool;
  }

  function defineFunctionTest(id, { sql, params = () => [], table, crossTenantCheck }) {
    test(`SD-${id}: context-independent, no write, cross-tenant reach, permission-bounded (as its granted role)`, async () => {
      const args = params();
      const fn = fnOf(sql);
      const granted = poolFor(fn);
      const before = await bypassCount(table);

      const results = {};
      for (const mode of ['none', 'A', 'B', 'invalid']) {
        results[mode] = await callAs(mode, sql, args, granted);
      }

      // (1) Context-independence: identical result regardless of active tenant context.
      const baseline = serialize(results.none);
      expect(serialize(results.A)).toBe(baseline);
      expect(serialize(results.B)).toBe(baseline);
      expect(serialize(results.invalid)).toBe(baseline);

      // (2) No write side-effect.
      const after = await bypassCount(table);
      expect(after).toBe(before);

      // (3) Function-specific cross-tenant reach.
      if (crossTenantCheck) crossTenantCheck(results.none);

      // (4) Permission boundary: a role with zero EXECUTE grants is denied.
      await expect(_noPrivPool.query(sql, args)).rejects.toThrow(/permission denied/i);

      // (5) the request-serving role is refused, and so is
      //     every dedicated role this function is NOT granted to (least privilege).
      if (!ALSO_APP.has(fn)) await expect(_appPool.query(sql, args)).rejects.toThrow(/permission denied/i);
      if (granted !== _systemPool) await expect(_systemPool.query(sql, args)).rejects.toThrow(/permission denied/i);
      if (granted !== _reportingPool) await expect(_reportingPool.query(sql, args)).rejects.toThrow(/permission denied/i);
    });
  }

  // (D1-A): the two functions with no caller were dropped by migration 061.
  test.each(['qodiqa_audit_chain_last_row', 'qodiqa_transparency_log_fetch_by_evidence_chain_id'])(
    'SD-removed %s no longer exists (definition preserved in quarantine/w5/)', async (name) => {
      const r = await _bypassPool.query('SELECT count(*)::int AS n FROM pg_proc WHERE proname = $1', [name]);
      expect(r.rows[0].n).toBe(0);
    });

  // ── The 21 functions ─────────────────────────────────────────────────────────

  // SD-01-audit-last-row: function dropped by migration 061 — see 'SD-removed' above.

  defineFunctionTest('02-audit-full-read', {
    sql: 'SELECT * FROM qodiqa_audit_chain_full_read()',
    table: 'audit_chain',
    crossTenantCheck: (rows) => {
      const hashes = rows.map((r) => r.hash.trim());
      expect(hashes).toEqual(expect.arrayContaining([SEED.audit.hashA, SEED.audit.hashBReplay, SEED.audit.hashP]));
    },
  });

  defineFunctionTest('03-audit-fetch-batch', {
    sql: 'SELECT * FROM qodiqa_audit_chain_fetch_batch($1, $2)',
    params: () => [0, 1000],
    table: 'audit_chain',
    crossTenantCheck: (rows) => {
      const hashes = rows.map((r) => r.hash.trim());
      expect(hashes).toEqual(expect.arrayContaining([SEED.audit.hashA, SEED.audit.hashBReplay, SEED.audit.hashP]));
    },
  });

  defineFunctionTest('04-audit-detect-sequence-gaps', {
    sql: 'SELECT * FROM qodiqa_audit_chain_detect_sequence_gaps($1, $2)',
    params: () => [0, 1000],
    table: 'audit_chain',
  });

  defineFunctionTest('05-audit-fetch-row-by-seq', {
    sql: 'SELECT qodiqa_audit_chain_fetch_row_by_seq($1) AS hash',
    params: () => [SEED.audit.seqA],
    table: 'audit_chain',
    crossTenantCheck: (rows) => {
      // Called with tenant A's own seq — the real cross-tenant proof for
      // this function is exercised by SD-05b below (tenant B's context
      // fetching tenant A's row by seq); this case just pins the value.
      expect(rows[0].hash.trim()).toBe(SEED.audit.hashA);
    },
  });

  test('SD-05b-audit-fetch-row-by-seq cross-tenant: tenant B context fetching tenant A\'s row by seq', async () => {
    const rows = await callAs('B', 'SELECT qodiqa_audit_chain_fetch_row_by_seq($1) AS hash', [SEED.audit.seqA], poolFor('qodiqa_audit_chain_fetch_row_by_seq'));
    expect(rows[0].hash.trim()).toBe(SEED.audit.hashA);
  });

  defineFunctionTest('06-audit-max-seq', {
    sql: 'SELECT qodiqa_audit_chain_max_seq() AS max_seq',
    table: 'audit_chain',
    crossTenantCheck: (rows) => {
      expect(Number(rows[0].max_seq)).toBeGreaterThanOrEqual(Number(SEED.audit.seqP));
    },
  });

  defineFunctionTest('07-audit-fetch-by-artifact-id', {
    sql: 'SELECT * FROM qodiqa_audit_chain_fetch_by_artifact_id($1)',
    params: () => [SEED.audit.artBReplay],
    table: 'audit_chain',
    crossTenantCheck: (rows) => {
      // Queried (in "none" context) for tenant B's artifact — proves the
      // lookup is by artifact id, not gated by any tenant.
      expect(rows[0].hash.trim()).toBe(SEED.audit.hashBReplay);
      expect(rows[0].tenant_id).toBe(TENANT_B);
    },
  });

  test('SD-07b-audit-fetch-by-artifact-id cross-tenant: tenant A context fetching tenant B\'s row by artifact id', async () => {
    const rows = await callAs('A', 'SELECT * FROM qodiqa_audit_chain_fetch_by_artifact_id($1)', [SEED.audit.artBReplay], poolFor('qodiqa_audit_chain_fetch_by_artifact_id'));
    expect(rows).toHaveLength(1);
    expect(rows[0].tenant_id).toBe(TENANT_B);
  });

  defineFunctionTest('08-audit-fetch-replay-lineage', {
    sql: 'SELECT * FROM qodiqa_audit_chain_fetch_replay_lineage($1)',
    params: () => [SEED.audit.artA],
    table: 'audit_chain',
    crossTenantCheck: (rows) => {
      // Tenant A's own artifact was replayed by a row OWNED BY TENANT B.
      // Querying replay lineage for A's artifact must surface B's row —
      // the clearest possible proof this function crosses tenant boundaries
      // by design (not merely "returns extra platform rows").
      expect(rows).toHaveLength(1);
      expect(rows[0].hash.trim()).toBe(SEED.audit.hashBReplay);
      expect(rows[0].tenant_id).toBe(TENANT_B);
    },
  });

  defineFunctionTest('09-transparency-fetch-batch', {
    sql: 'SELECT * FROM qodiqa_transparency_log_fetch_batch($1, $2)',
    params: () => [0, 1000],
    table: 'transparency_log_entries',
    crossTenantCheck: (rows) => {
      const hashes = rows.map((r) => r.entry_hash.trim());
      expect(hashes).toEqual(expect.arrayContaining([SEED.tl.hashA, SEED.tl.hashB, SEED.tl.hashP]));
    },
  });

  defineFunctionTest('10-transparency-fetch-hashes-in-range', {
    sql: 'SELECT * FROM qodiqa_transparency_log_fetch_hashes_in_range($1, $2)',
    params: () => [0, 999999999],
    table: 'transparency_log_entries',
    crossTenantCheck: (rows) => {
      const hashes = rows.map((r) => r.entry_hash.trim());
      expect(hashes).toEqual(expect.arrayContaining([SEED.tl.hashA, SEED.tl.hashB, SEED.tl.hashP]));
    },
  });

  defineFunctionTest('11-transparency-fetch-boundary', {
    sql: 'SELECT * FROM qodiqa_transparency_log_fetch_boundary($1)',
    params: () => [SEED.tl.idP + 1],
    table: 'transparency_log_entries',
  });

  defineFunctionTest('12-transparency-fetch-by-transparency-id', {
    sql: 'SELECT * FROM qodiqa_transparency_log_fetch_by_transparency_id($1)',
    params: () => [SEED.tl.transparencyIdB],
    table: 'transparency_log_entries',
    crossTenantCheck: (rows) => {
      expect(rows).toHaveLength(1);
      expect(rows[0].tenant_id).toBe(TENANT_B);
    },
  });

  test('SD-12b-transparency-fetch-by-transparency-id cross-tenant: tenant A context fetching tenant B\'s entry', async () => {
    const rows = await callAs('A', 'SELECT * FROM qodiqa_transparency_log_fetch_by_transparency_id($1)', [SEED.tl.transparencyIdB], poolFor('qodiqa_transparency_log_fetch_by_transparency_id'));
    expect(rows).toHaveLength(1);
    expect(rows[0].tenant_id).toBe(TENANT_B);
  });

  defineFunctionTest('13-transparency-fetch-by-entry-hash', {
    sql: 'SELECT * FROM qodiqa_transparency_log_fetch_by_entry_hash($1)',
    params: () => [SEED.tl.hashB],
    table: 'transparency_log_entries',
    crossTenantCheck: (rows) => {
      expect(rows).toHaveLength(1);
      expect(rows[0].tenant_id).toBe(TENANT_B);
    },
  });

  defineFunctionTest('14-transparency-fetch-by-artifact-id', {
    sql: 'SELECT * FROM qodiqa_transparency_log_fetch_by_artifact_id($1)',
    params: () => [SEED.tl.artB],
    table: 'transparency_log_entries',
    crossTenantCheck: (rows) => {
      expect(rows).toHaveLength(1);
      expect(rows[0].tenant_id).toBe(TENANT_B);
    },
  });

  // SD-15-transparency-fetch-by-evidence-chain-id: function dropped by migration 061 — see 'SD-removed' above.

  defineFunctionTest('16-transparency-latest-entry', {
    sql: 'SELECT * FROM qodiqa_transparency_log_latest_entry()',
    table: 'transparency_log_entries',
  });

  defineFunctionTest('17-transparency-fetch-range-full', {
    sql: 'SELECT * FROM qodiqa_transparency_log_fetch_range_full($1, $2)',
    params: () => [0, 999999999],
    table: 'transparency_log_entries',
    crossTenantCheck: (rows) => {
      const byArtifact = Object.fromEntries(rows.map((r) => [r.artifact_id, r]));
      // The one function whose output feeds the signed Merkle root — its
      // tenant_id OUTPUT column must correctly reflect the true owning
      // tenant per row, not merely be present.
      expect(byArtifact[SEED.tl.artA].tenant_id).toBe(TENANT_A);
      expect(byArtifact[SEED.tl.artB].tenant_id).toBe(TENANT_B);
      expect(byArtifact[SEED.tl.artP].tenant_id).toBeNull();
    },
  });

  defineFunctionTest('18-transparency-read-all', {
    sql: 'SELECT * FROM qodiqa_transparency_log_read_all()',
    table: 'transparency_log_entries',
    crossTenantCheck: (rows) => {
      const hashes = rows.map((r) => r.entry_hash.trim());
      expect(hashes).toEqual(expect.arrayContaining([SEED.tl.hashA, SEED.tl.hashB, SEED.tl.hashP]));
    },
  });

  defineFunctionTest('19-policy-change-request-by-id', {
    sql: 'SELECT * FROM qodiqa_policy_change_request_by_id($1)',
    params: () => [SEED.pcr.idB],
    table: 'policy_change_requests',
    crossTenantCheck: (rows) => {
      expect(rows).toHaveLength(1);
      expect(rows[0].tenant_id).toBe(TENANT_B);
      expect(rows[0].payload.sentinel).toBe(SENTINEL_B);
    },
  });

  test('SD-19b-policy-change-request-by-id cross-tenant: tenant A context fetching tenant B\'s request', async () => {
    const rows = await callAs('A', 'SELECT * FROM qodiqa_policy_change_request_by_id($1)', [SEED.pcr.idB], poolFor('qodiqa_policy_change_request_by_id'));
    expect(rows).toHaveLength(1);
    expect(rows[0].tenant_id).toBe(TENANT_B);
  });

  defineFunctionTest('20-tenant-policy-sets-full-read', {
    sql: 'SELECT * FROM qodiqa_tenant_policy_sets_full_read()',
    table: 'tenant_policy_sets',
    crossTenantCheck: (rows) => {
      const byTenant = Object.fromEntries(rows.map((r) => [r.tenant_id, r]));
      expect(JSON.stringify(byTenant[TENANT_A].policies)).toContain(SENTINEL_A);
      expect(JSON.stringify(byTenant[TENANT_B].policies)).toContain(SENTINEL_B);
    },
  });

  defineFunctionTest('21-tenant-semantic-configs-full-read', {
    sql: 'SELECT * FROM qodiqa_tenant_semantic_configs_full_read()',
    table: 'tenant_semantic_configs',
    crossTenantCheck: (rows) => {
      const byTenant = Object.fromEntries(rows.map((r) => [r.tenant_id, r]));
      expect(JSON.stringify(byTenant[TENANT_A].config)).toContain(SENTINEL_A);
      expect(JSON.stringify(byTenant[TENANT_B].config)).toContain(SENTINEL_B);
    },
  });

  // ── the 8 functions migration 053 added (never covered by SD-XX before) ──

  defineFunctionTest('22-platform-audit-events-full-read', {
    sql: 'SELECT * FROM qodiqa_platform_audit_events_full_read()',
    table: 'platform_audit_events',
    crossTenantCheck: (rows) => {
      const payloads = rows.map((r) => JSON.stringify(r.payload));
      expect(payloads.some((p) => p.includes(SENTINEL_A))).toBe(true);
      expect(payloads.some((p) => p.includes(SENTINEL_B))).toBe(true);
    },
  });

  defineFunctionTest('23-evidence-chain-records-full-read', {
    sql: 'SELECT * FROM qodiqa_evidence_chain_records_full_read()',
    table: 'evidence_chain_records',
    crossTenantCheck: (rows) => {
      const artifactIds = rows.map((r) => r.artifact_id);
      expect(artifactIds.some((a) => a.includes(SENTINEL_A))).toBe(true);
      expect(artifactIds.some((a) => a.includes(SENTINEL_B))).toBe(true);
    },
  });

  defineFunctionTest('24-qodiqa-alerts-full-read', {
    sql: 'SELECT * FROM qodiqa_qodiqa_alerts_full_read()',
    table: 'qodiqa_alerts',
    crossTenantCheck: (rows) => {
      const titles = rows.map((r) => r.title);
      expect(titles.some((t) => t.includes(SENTINEL_A))).toBe(true);
      expect(titles.some((t) => t.includes(SENTINEL_B))).toBe(true);
    },
  });

  defineFunctionTest('25-qodiqa-alert-history-full-read', {
    sql: 'SELECT * FROM qodiqa_qodiqa_alert_history_full_read()',
    table: 'qodiqa_alert_history',
    crossTenantCheck: (rows) => {
      const alertIds = rows.map((r) => r.alert_id);
      expect(alertIds).toEqual(expect.arrayContaining([SEED.alerts.idA, SEED.alerts.idB]));
    },
  });

  defineFunctionTest('26-consent-audit-log-full-read', {
    sql: 'SELECT * FROM qodiqa_consent_audit_log_full_read()',
    table: 'consent_audit_log',
    crossTenantCheck: (rows) => {
      const actorIds = rows.map((r) => r.actor_id);
      expect(actorIds.some((a) => a && a.includes(SENTINEL_A))).toBe(true);
      expect(actorIds.some((a) => a && a.includes(SENTINEL_B))).toBe(true);
    },
  });

  defineFunctionTest('27-audit-retention-policies-full-read', {
    sql: 'SELECT * FROM qodiqa_audit_retention_policies_full_read()',
    table: 'audit_retention_policies',
    crossTenantCheck: (rows) => {
      const names = rows.map((r) => r.name);
      expect(names.some((n) => n.includes(SENTINEL_A))).toBe(true);
      expect(names.some((n) => n.includes(SENTINEL_B))).toBe(true);
    },
  });

  defineFunctionTest('28-audit-legal-holds-full-read', {
    sql: 'SELECT * FROM qodiqa_audit_legal_holds_full_read()',
    table: 'audit_legal_holds',
    crossTenantCheck: (rows) => {
      const names = rows.map((r) => r.hold_name);
      expect(names.some((n) => n.includes(SENTINEL_A))).toBe(true);
      expect(names.some((n) => n.includes(SENTINEL_B))).toBe(true);
    },
  });

  defineFunctionTest('29-compliance-reports-full-read', {
    sql: 'SELECT * FROM qodiqa_compliance_reports_full_read()',
    table: 'compliance_reports',
    crossTenantCheck: (rows) => {
      const ids = rows.map((r) => r.id);
      expect(ids).toEqual(expect.arrayContaining([SEED.reports.idA, SEED.reports.idB]));
    },
  });

  // ── Contrast baseline: ordinary qodiqa_app SELECT (no DEFINER function) respects RLS ──

  describe('Contrast baseline — ordinary reads (no SECURITY DEFINER) stay tenant-scoped', () => {
    test('CB-01 audit_chain: tenant A context sees its own + platform rows, never tenant B\'s replay row', async () => {
      const rows = await callAs('A', 'SELECT hash, tenant_id FROM audit_chain');
      const hashes = rows.map((r) => r.hash.trim());
      expect(hashes).toContain(SEED.audit.hashA);
      expect(hashes).not.toContain(SEED.audit.hashBReplay);
    });

    test('CB-02 transparency_log_entries: tenant A context never sees tenant B\'s row', async () => {
      const rows = await callAs('A', 'SELECT entry_hash, tenant_id FROM transparency_log_entries');
      const hashes = rows.map((r) => r.entry_hash.trim());
      expect(hashes).not.toContain(SEED.tl.hashB);
    });

    test('CB-03 tenant_policy_sets: tenant A context never sees tenant B\'s policy set', async () => {
      const rows = await callAs('A', 'SELECT tenant_id, policies FROM tenant_policy_sets');
      expect(rows.map((r) => r.tenant_id)).not.toContain(TENANT_B);
    });

    test('CB-04 tenant_semantic_configs: tenant A context never sees tenant B\'s config', async () => {
      const rows = await callAs('A', 'SELECT tenant_id, config FROM tenant_semantic_configs');
      expect(rows.map((r) => r.tenant_id)).not.toContain(TENANT_B);
    });

    test('CB-05 policy_change_requests: tenant A context never sees tenant B\'s request', async () => {
      const rows = await callAs('A', 'SELECT id, tenant_id FROM policy_change_requests');
      expect(rows.map((r) => r.id)).not.toContain(SEED.pcr.idB);
    });
  });

  // ── Nested-chain and search_path regression proofs (static findings, asserted live) ──
  //
  // SECURITY_DEFINER_INVENTORY replaces the old ALL_21 array. It is the
  // single AUTHORITATIVE, EXPLICITLY-REVIEWED registry of every SECURITY DEFINER
  // function this repository currently approves — adding a 30th function to the
  // schema without adding it here is treated as a security event (NC-01 fails,
  // by name; NC-06 below proves this is a real tripwire, not merely a count).
  // This is deliberately NOT auto-derived from a live query: the whole point is
  // that registration is a manual, reviewed step (task brief section 5) — a
  // migration that silently ships a new SECURITY DEFINER function must not be
  // able to make this suite "self-heal" around it.
  // migration 063. Functional behaviour (> 200 rows, every
  // table, key destroyed, ledger, restore replay) is test/integration/erasureComplete.integration.test.js;
  // here: the privilege boundary and the database-side guards.
  describe('erasure functions — writer exception, qodiqa_system only', () => {
    const PSEUDO = 'ap1:' + 'c'.repeat(64);
    const ERASE_FNS = [
      ['qodiqa_erase_subject', 'SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', ['sdadv-t', 'sdadv-subject', PSEUDO, 10], ['system']],
      ['qodiqa_erase_subject_finalize', 'SELECT * FROM qodiqa_erase_subject_finalize($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)',
        [crypto.randomUUID(), null, 'sdadv-subject', PSEUDO, 'd'.repeat(64), crypto.randomUUID(), '{}', 'op', '{}', 'e'.repeat(64)], ['system']],
      ['qodiqa_erasure_subject_candidates', 'SELECT * FROM qodiqa_erasure_subject_candidates()', [], ['system']],
      ['qodiqa_erasure_ledger_list', 'SELECT * FROM qodiqa_erasure_ledger_list($1, $2)', [0, 10], ['system', 'reporting']],
    ];

    test.each(ERASE_FNS)('ERA-01 %s: refused to qodiqa_app, qodiqa_read-less roles and every non-granted dedicated role', async (_n, sql, args, granted) => {
      await expect(_appPool.query(sql, args)).rejects.toThrow(/permission denied/i);
      await expect(_noPrivPool.query(sql, args)).rejects.toThrow(/permission denied/i);
      if (!granted.includes('system')) await expect(_systemPool.query(sql, args)).rejects.toThrow(/permission denied/i);
      if (!granted.includes('reporting')) await expect(_reportingPool.query(sql, args)).rejects.toThrow(/permission denied/i);
    });

    test('ERA-02 qodiqa_erase_subject refuses a pseudonym that is not ap1:<64 hex>, or equal to the identifier', async () => {
      await expect(_systemPool.query('SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', [null, 'sdadv-subject', 'not-a-pseudonym', 10]))
        .rejects.toThrow(/invalid arguments/);
      await expect(_systemPool.query('SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', [null, PSEUDO, PSEUDO, 10]))
        .rejects.toThrow(/invalid arguments/);
    });

    test('ERA-03 finalize refuses a request that is not an in-progress erasure (never marks anything COMPLETED)', async () => {
      await expect(_systemPool.query(ERASE_FNS[1][1], ERASE_FNS[1][2])).rejects.toThrow(/not an in-progress erasure/);
    });

    test('ERA-04 dsr_erasure_ledger is append-only for every role, the owner included (UPDATE/DELETE/TRUNCATE)', async () => {
      const run = crypto.randomUUID();
      await _bypassPool.query("INSERT INTO dsr_erasure_ledger (tenant_id, subject_ref, run_id) VALUES (NULL, $1, $2)", ['f'.repeat(64), run]);
      await expect(_bypassPool.query('UPDATE dsr_erasure_ledger SET tenant_id = $1 WHERE run_id = $2', ['x', run])).rejects.toThrow(/append-only/);
      await expect(_bypassPool.query('DELETE FROM dsr_erasure_ledger WHERE run_id = $1', [run])).rejects.toThrow(/append-only/);
      await expect(_bypassPool.query('TRUNCATE dsr_erasure_ledger')).rejects.toThrow(/append-only/);
      // no table privilege for any request-serving or dedicated role
      for (const p of [_appPool, _systemPool, _reportingPool]) {
        await expect(p.query('SELECT 1 FROM dsr_erasure_ledger LIMIT 1')).rejects.toThrow(/permission denied/i);
      }
    });

    test('ERA-05 subject_pseudonym_keys: the app may read/insert only its own tenant\'s keys and may never delete one', async () => {
      await expect(_appPool.query('DELETE FROM subject_pseudonym_keys')).rejects.toThrow(/permission denied/i);
      await expect(_appPool.query('UPDATE subject_pseudonym_keys SET key_enc = key_enc')).rejects.toThrow(/permission denied/i);
      const r = await _bypassPool.query("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'subject_pseudonym_keys'");
      expect(r.rows[0]).toEqual({ relrowsecurity: true, relforcerowsecurity: true });
    });
  });

  describe('minimized public functions (qodiqa_app) — D4-A, NF-2', () => {
    const FORBIDDEN_COLS = ['tenant_id', 'registered_by', 'signer_key_version', 'payload'];
    test('PUB-01 public entry lookups reach any tenant\'s entry but return no tenant metadata', async () => {
      const byId = await callAs('A', 'SELECT * FROM qodiqa_transparency_public_entry($1)', [SEED.tl.transparencyIdB]);
      expect(byId).toHaveLength(1);
      for (const c of FORBIDDEN_COLS) expect(byId[0]).not.toHaveProperty(c);
      const byHash = await callAs('none', 'SELECT * FROM qodiqa_transparency_public_entry_by_hash($1)', [byId[0].entry_hash]);
      expect(byHash[0].transparency_id).toBe(SEED.tl.transparencyIdB);
      for (const c of FORBIDDEN_COLS) expect(byHash[0]).not.toHaveProperty(c);
    });
    test('PUB-02 public list: every tenant\'s entries, no tenant metadata, no tenant filter parameter', async () => {
      const rows = await callAs('B', 'SELECT * FROM qodiqa_transparency_public_list(NULL, NULL, NULL, NULL, NULL, 500, 0, false)');
      expect(rows.length).toBe(await bypassCount('transparency_log_entries'));
      for (const r of rows) for (const c of FORBIDDEN_COLS) expect(r).not.toHaveProperty(c);
      const args = await _bypassPool.query("SELECT pg_get_function_identity_arguments('qodiqa_transparency_public_list'::regproc) AS a");
      expect(args.rows[0].a).not.toMatch(/tenant/);
      const capped = await callAs('none', 'SELECT count(*)::int AS n FROM qodiqa_transparency_public_list(NULL, NULL, NULL, NULL, NULL, 100000, 0, false)');
      expect(capped[0].n).toBeLessThanOrEqual(500);
    });
    test('PUB-03 hash-only reader returns exactly (id, entry_hash)', async () => {
      const rows = await callAs('A', 'SELECT * FROM qodiqa_transparency_public_hashes_from_id(1, 10)');
      expect(rows.length).toBeGreaterThan(0);
      expect(Object.keys(rows[0]).sort()).toEqual(['entry_hash', 'id']);
    });
    test('PUB-04 evidence public lookup returns a record only to the tenant the artifact claims', async () => {
      const own = await _bypassPool.query('SELECT artifact_id, tenant_id FROM evidence_chain_records WHERE tenant_id IS NOT NULL LIMIT 1');
      expect(own.rows.length).toBe(1); // the seed carries tenant-owned evidence (A and B)
      const { artifact_id: art, tenant_id: owner } = own.rows[0];
      const mine = await callAs('none', 'SELECT * FROM qodiqa_evidence_public_lookup($1, $2)', [art, owner]);
      expect(mine).toHaveLength(1);
      const other = await callAs('none', 'SELECT * FROM qodiqa_evidence_public_lookup($1, $2)', [art, 'sdadv-some-other-tenant']);
      expect(other).toHaveLength(0);
    });
    test('PUB-05 the public functions are executable by qodiqa_app and by no other non-owner role', async () => {
      for (const sig of ['qodiqa_transparency_public_entry(uuid)', 'qodiqa_transparency_public_entry_by_hash(character)',
        'qodiqa_transparency_public_hashes_from_id(bigint, integer)', 'qodiqa_evidence_public_lookup(character varying, text)']) {
        const r = await _bypassPool.query(`SELECT has_function_privilege('qodiqa_app', $1, 'EXECUTE') AS app,
          has_function_privilege('qodiqa_read', $1, 'EXECUTE') AS rd, has_function_privilege('qodiqa_reporting', $1, 'EXECUTE') AS rep`, [sig]);
        expect(r.rows[0]).toEqual({ app: true, rd: false, rep: false });
      }
    });
  });

  describe('Nested SECURITY DEFINER chains and search_path — live regression proof', () => {
    const SECURITY_DEFINER_INVENTORY = [
      // ── original 21 ──
      { name: 'qodiqa_audit_chain_full_read', migration: 44 },
      { name: 'qodiqa_audit_chain_fetch_batch', migration: 48 },
      { name: 'qodiqa_audit_chain_detect_sequence_gaps', migration: 48 },
      { name: 'qodiqa_audit_chain_fetch_row_by_seq', migration: 48 },
      { name: 'qodiqa_audit_chain_max_seq', migration: 48 },
      { name: 'qodiqa_audit_chain_fetch_by_artifact_id', migration: 48 },
      { name: 'qodiqa_audit_chain_fetch_replay_lineage', migration: 48 },
      { name: 'qodiqa_transparency_log_fetch_batch', migration: 49 },
      { name: 'qodiqa_transparency_log_fetch_hashes_in_range', migration: 49 },
      { name: 'qodiqa_transparency_log_fetch_boundary', migration: 49 },
      { name: 'qodiqa_transparency_log_fetch_by_transparency_id', migration: 50 },
      { name: 'qodiqa_transparency_log_fetch_by_entry_hash', migration: 50 },
      { name: 'qodiqa_transparency_log_fetch_by_artifact_id', migration: 50 },
      { name: 'qodiqa_transparency_log_latest_entry', migration: 50 },
      { name: 'qodiqa_transparency_log_fetch_range_full', migration: 50 },
      { name: 'qodiqa_transparency_log_read_all', migration: 50 },
      { name: 'qodiqa_policy_change_request_by_id', migration: 51 },
      { name: 'qodiqa_tenant_policy_sets_full_read', migration: 51 },
      { name: 'qodiqa_tenant_semantic_configs_full_read', migration: 51 },
      // ── the 8 added by migration 053, previously unregistered ──
      { name: 'qodiqa_platform_audit_events_full_read', migration: 53 },
      { name: 'qodiqa_evidence_chain_records_full_read', migration: 53 },
      { name: 'qodiqa_qodiqa_alerts_full_read', migration: 53 },
      { name: 'qodiqa_qodiqa_alert_history_full_read', migration: 53 },
      { name: 'qodiqa_consent_audit_log_full_read', migration: 53 },
      { name: 'qodiqa_audit_retention_policies_full_read', migration: 53 },
      { name: 'qodiqa_audit_legal_holds_full_read', migration: 53 },
      { name: 'qodiqa_compliance_reports_full_read', migration: 53 },
      // ── the emergency sweep full-read function ──
      { name: 'qodiqa_policy_emergency_activations_full_read', migration: 56 },
      // ── parent guard + link-defined tail for the audit mirror ──
      { name: 'qodiqa_audit_chain_hash_exists', migration: 58 },
      { name: 'qodiqa_audit_chain_true_tail', migration: 58 },
      // ── minimized public functions (app role), migration 061 ──
      { name: 'qodiqa_transparency_public_entry', migration: 61 },
      { name: 'qodiqa_transparency_public_entry_by_hash', migration: 61 },
      { name: 'qodiqa_transparency_public_list', migration: 61 },
      { name: 'qodiqa_transparency_public_hashes_from_id', migration: 61 },
      { name: 'qodiqa_evidence_public_lookup', migration: 61 },
      // ── GDPR erasure, migration 063. The two erase functions are the
      //    registered WRITER exception to this suite's "pure read" property — see ERA-* below. ──
      { name: 'qodiqa_erase_subject', migration: 63 },
      { name: 'qodiqa_erase_subject_finalize', migration: 63 },
      { name: 'qodiqa_erasure_subject_candidates', migration: 63 },
      { name: 'qodiqa_erasure_ledger_list', migration: 63 },
      // ── step 6 (migration 069): read-only, EXECUTE qodiqa_reporting only. ──
      { name: 'qodiqa_request_trails_by_ids', migration: 69 },
      { name: 'qodiqa_audit_chain_decisions', migration: 69 },
      // ── S2 (migration 073): audit_chain row counter. The three trigger functions and the DR rebuild are the
      //    registered WRITERS of the derived audit_chain_mirror_count (never of audit data); see MC-* in
      //    test/integration/auditChainMirrorCount.integration.test.js. ──
      { name: 'qodiqa_audit_chain_mirror_count_on_insert', migration: 73 },
      { name: 'qodiqa_audit_chain_mirror_count_on_delete', migration: 73 },
      { name: 'qodiqa_audit_chain_mirror_count_on_truncate', migration: 73 },
      { name: 'qodiqa_audit_chain_mirror_count', migration: 73 },
      { name: 'qodiqa_audit_chain_mirror_count_check', migration: 73 },
      { name: 'qodiqa_audit_chain_mirror_count_rebuild', migration: 73 },
    ];
    const APPROVED_NAMES = SECURITY_DEFINER_INVENTORY.map((f) => f.name);
    // Sanity-check the registry itself has no accidental duplicate entry —
    // a duplicate would silently under-count without this.
    if (new Set(APPROVED_NAMES).size !== APPROVED_NAMES.length) {
      throw new Error('SECURITY_DEFINER_INVENTORY contains a duplicate function name — fix the registry itself.');
    }

    async function liveSecurityDefinerNames() {
      const res = await _bypassPool.query(`
        SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosecdef = true AND n.nspname = 'public'
      `);
      return res.rows.map((r) => r.proname);
    }

    test('NC-01 every registered SECURITY DEFINER function exists, and no unregistered one does (inventory tripwire)', async () => {
      const live = await liveSecurityDefinerNames();
      const missing = APPROVED_NAMES.filter((n) => !live.includes(n));
      const unregistered = live.filter((n) => !APPROVED_NAMES.includes(n));
      // Two separate assertions (not one toEqual on the full sorted arrays) so a
      // failure's own message names exactly which function is missing/unregistered,
      // per task brief section 7's "produce useful failure output identifying the
      // exact unexpected function" requirement.
      expect({ missing }).toEqual({ missing: [] });
      expect({ unregistered }).toEqual({ unregistered: [] });
    });

    test('NC-02 no function body references another SECURITY DEFINER function by name (no nested chains)', async () => {
      const res = await _bypassPool.query(`
        SELECT p.proname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosecdef = true AND n.nspname = 'public'
      `);
      for (const row of res.rows) {
        for (const otherName of APPROVED_NAMES) {
          if (otherName === row.proname) continue;
          expect(row.prosrc.includes(otherName)).toBe(false);
        }
      }
    });

    test('NC-03 every function pins search_path to pg_catalog, public, pg_temp (pg_temp last, 078 /) — no exceptions', async () => {
      const res = await _bypassPool.query(`
        SELECT p.proname, p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosecdef = true AND n.nspname = 'public'
      `);
      // Length is derived from the registry itself (not a second hard-coded
      // literal) — NC-01 above is what actually proves live reality matches the
      // registry; this only fails independently if the registry and the live
      // count diverge in a way NC-01 didn't already catch (defense in depth).
      expect(res.rows).toHaveLength(SECURITY_DEFINER_INVENTORY.length);
      for (const row of res.rows) {
        expect(row.proconfig).toEqual(['search_path=pg_catalog, public, pg_temp']);
      }
    });

    test('NC-04 neither qodiqa_app nor PUBLIC can CREATE in schema public (structural anti-shadowing check)', async () => {
      const res = await _bypassPool.query(`
        SELECT has_schema_privilege('qodiqa_app','public','CREATE') AS app_create,
               has_schema_privilege('public','public','CREATE') AS public_create
      `);
      expect(res.rows[0].app_create).toBe(false);
      expect(res.rows[0].public_create).toBe(false);
    });

    test('NC-05 PUBLIC pseudo-role cannot EXECUTE any registered function', async () => {
      const res = await _bypassPool.query(`
        SELECT p.proname, has_function_privilege('public', p.oid, 'EXECUTE') AS public_execute
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosecdef = true AND n.nspname = 'public'
      `);
      expect(res.rows).toHaveLength(SECURITY_DEFINER_INVENTORY.length);
      for (const row of res.rows) {
        expect(row.public_execute).toBe(false);
      }
    });

    // ── negative test (task brief section 8): proves NC-01 is a real
    //    tripwire, not merely a list that happens to match today. Creates a
    //    throwaway, unregistered SECURITY DEFINER function on THIS disposable
    //    database only, proves the inventory check catches it BY NAME, drops
    //    it, and proves the check is clean again. Runs as qodiqa_test
    //    (BYPASSRLS — the only role with CREATE on schema public; qodiqa_app
    //    itself cannot create the rogue function, which is the point).
    describe('NC-06 unregistered SECURITY DEFINER tripwire (negative test)', () => {
      const ROGUE_NAME = `sdadv_rogue_probe_${crypto.randomBytes(4).toString('hex')}`;

      test('an unregistered SECURITY DEFINER function is detected by name, then clears after removal', async () => {
        // Before: registry and live schema agree (this is also covered by NC-01
        // itself, re-asserted here so this test is self-contained/order-independent).
        const before = await liveSecurityDefinerNames();
        expect(before.filter((n) => !APPROVED_NAMES.includes(n))).toEqual([]);

        // Create the rogue, UNREGISTERED function — deliberately mirrors the
        // exact shape of a real one (pure SELECT, STABLE, search_path pinned,
        // PUBLIC revoked) so this test isolates "was it registered", not "was
        // it otherwise misconfigured".
        await _bypassPool.query(`
          CREATE OR REPLACE FUNCTION ${ROGUE_NAME}()
          RETURNS SETOF audit_chain
          LANGUAGE sql SECURITY DEFINER STABLE
          SET search_path = pg_catalog, public
          AS $$ SELECT * FROM audit_chain $$
        `);
        await _bypassPool.query(`REVOKE ALL ON FUNCTION ${ROGUE_NAME}() FROM PUBLIC`);
        await _bypassPool.query(`GRANT EXECUTE ON FUNCTION ${ROGUE_NAME}() TO qodiqa_app`);

        try {
          // DURING: the inventory check must fail, and must name the rogue
          // function specifically — not merely report "count mismatch".
          const during = await liveSecurityDefinerNames();
          const unregistered = during.filter((n) => !APPROVED_NAMES.includes(n));
          expect(unregistered).toEqual([ROGUE_NAME]);
        } finally {
          // Always drop the rogue function, even if an assertion above threw —
          // this is a shared disposable database other tests in this suite run
          // against, and it must not leak a stray function into any subsequent
          // NC-0x test in the same run.
          await _bypassPool.query(`DROP FUNCTION IF EXISTS ${ROGUE_NAME}()`);
        }

        // AFTER: removing the unregistered function restores a clean result.
        const after = await liveSecurityDefinerNames();
        expect(after.filter((n) => !APPROVED_NAMES.includes(n))).toEqual([]);
        expect(after.sort()).toEqual([...APPROVED_NAMES].sort());
      });
    });
  });
});
