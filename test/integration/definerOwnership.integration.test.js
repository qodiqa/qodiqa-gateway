'use strict';

/**
 * — SECURITY DEFINER ownership and the erasure-target allowlist (real disposable PostgreSQL).
 *
 *   DO-01  the live definer set equals the pinned 47-signature manifest, and migration 079 / the restore SQL carry the same list
 *   DO-02  every definer is owned by qodiqa_definer, which is NOT a superuser (checkDefinerOwnership: owner, search_path, no PUBLIC)
 *   DO-03  qodiqa_definer has exactly the approved role attributes, no memberships, no runtime member, no CREATE anywhere
 *   DO-04  qodiqa_definer's explicit privileges equal the pinned manifest (tables, columns, sequences, functions) — nothing more
 *   DO-05  the approved EXECUTE grants are exactly preserved (6 app / 16 reporting / 22 system)
 *   DO-06  a trigger fired INSIDE a definer (the erasure UPDATE) runs as qodiqa_definer, never as a superuser (harmless probe)
 *   DO-07  qodiqa_erasure_targets() returns exactly the seven approved pairs
 *   DO-08  a planted public table with actor_id + a probe trigger is never selected: erasure refuses (55000), the probe never fires,
 *          the planted row is unchanged
 *   DO-09  a missing / incompatible approved target fails closed (55000)
 *   DO-10  the owner-only mirror-count rebuild still works as qodiqa_definer and keeps the counter exact
 *   DO-11  re-executing migrations 079 and 080 is idempotent (no catalog change)
 *   DO-12  restore drift (definers re-owned by the restoring role) is detected and scripts/dr/definer-ownership.sql repairs it
 *   DO-13  rollback (deploy/sql/rollback-schema-owner.sql + deploy/sql/rollback-definer-ownership.sql) then forward recovery (079-081)
 *   DO-14  closure (migration 081): every table/sequence/index/non-definer function/enum owned by qodiqa_owner (NOLOGIN,
 *          non-superuser, no BYPASSRLS, member of nothing, no runtime member); 081's lists equal schema-ownership.sql's
 *   DO-15  qodiqa_mig owns nothing; on audit_chain it holds exactly SELECT+INSERT (no UPDATE/DELETE/TRUNCATE/TRIGGER)
 *   DO-16  default privileges exist only FOR ROLE qodiqa_owner (backup SELECT); qodiqa_backup can read every table
 *   DO-17  schema-ownership restore drift is detected and scripts/dr/schema-ownership.sql repairs it
 *
 * Every probe is instrumentation (it records current_user / rolsuper into a fixture table). No privilege-escalation
 * payload is executed. All fixtures live in this file's own disposable database.
 */

// phase 17: no .env loading — the PostgreSQL target and credentials come only from the explicit process env (pl-env.sh / CI).

const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const M = require('../../src/infra/postgres/definerOwnership');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO = path.join(__dirname, '..', '..');
const DB = `qodiqa_er16_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const MIG_DIR = path.join(REPO, 'src', 'infra', 'postgres', 'migrations');
const SQL_079 = fs.readFileSync(path.join(MIG_DIR, '079_definer_owner_role.sql'), 'utf8');
const SQL_080 = fs.readFileSync(path.join(MIG_DIR, '080_erasure_target_allowlist.sql'), 'utf8');
const SQL_RESTORE = fs.readFileSync(path.join(REPO, 'scripts', 'dr', 'definer-ownership.sql'), 'utf8');
const SQL_ROLLBACK = fs.readFileSync(path.join(REPO, 'deploy', 'sql', 'rollback-definer-ownership.sql'), 'utf8');
const SQL_082 = fs.readFileSync(path.join(MIG_DIR, '082_audit_definer_audit_chain_lock_privilege.sql'), 'utf8');
const SQL_081 = fs.readFileSync(path.join(MIG_DIR, '081_schema_owner_role.sql'), 'utf8');
const SQL_SCHEMA_RESTORE = fs.readFileSync(path.join(REPO, 'scripts', 'dr', 'schema-ownership.sql'), 'utf8');
const SQL_SCHEMA_ROLLBACK = fs.readFileSync(path.join(REPO, 'deploy', 'sql', 'rollback-schema-owner.sql'), 'utf8');
// tables created by migrations AFTER 081. Migration 081 (frozen) refuses a schema with relations outside its list, so the tests that RE-EXECUTE it
// or roll back and forward over it park those tables in another schema for the duration (an operator doing the same rolls the later migrations back first).
const parkPost081 = async (client, tables) => {
  await client.query('CREATE SCHEMA IF NOT EXISTS post081_parked');
  const have = (await client.query("SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND relkind = 'r' AND relname = ANY($1)", [tables])).rows.map((r) => r.relname);
  for (const t of have) await client.query(`ALTER TABLE public.${t} SET SCHEMA post081_parked`);
  return have;
};
const unparkPost081 = async (client, have) => { for (const t of have) await client.query(`ALTER TABLE post081_parked.${t} SET SCHEMA public`); };
const sqlList = (sql, name) => [...sql.match(new RegExp(`${name} CONSTANT text\\[\\] := ARRAY\\[([\\s\\S]*?)\\];`))[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);

const conn = (database, user, password) => new Pool({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user, password, max: 2, connectionTimeoutMillis: 5000,
  ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
});
const TEST_USER = process.env.QODIQA_PG_TEST_USER || 'qodiqa_test';
const PSEUDO = `ap1:${'ab'.repeat(32)}`;

// the approved EXECUTE grants
const APP = ['qodiqa_evidence_public_lookup', 'qodiqa_transparency_log_fetch_hashes_in_range', 'qodiqa_transparency_public_entry',
  'qodiqa_transparency_public_entry_by_hash', 'qodiqa_transparency_public_hashes_from_id', 'qodiqa_transparency_public_list'];
const REPORTING = ['qodiqa_audit_chain_decisions', 'qodiqa_audit_chain_fetch_by_artifact_id', 'qodiqa_audit_chain_fetch_replay_lineage',
  'qodiqa_audit_legal_holds_full_read', 'qodiqa_audit_retention_policies_full_read', 'qodiqa_compliance_reports_full_read',
  'qodiqa_erasure_ledger_list', 'qodiqa_evidence_chain_records_full_read', 'qodiqa_platform_audit_events_full_read',
  'qodiqa_policy_change_request_by_id', 'qodiqa_qodiqa_alert_history_full_read', 'qodiqa_qodiqa_alerts_full_read',
  'qodiqa_request_trails_by_ids', 'qodiqa_transparency_log_fetch_by_artifact_id', 'qodiqa_transparency_log_fetch_range_full',
  'qodiqa_transparency_log_read_all'];
const SYSTEM = ['qodiqa_audit_chain_detect_sequence_gaps', 'qodiqa_audit_chain_fetch_batch', 'qodiqa_audit_chain_fetch_row_by_seq',
  'qodiqa_audit_chain_full_read', 'qodiqa_audit_chain_hash_exists', 'qodiqa_audit_chain_max_seq', 'qodiqa_audit_chain_mirror_count',
  'qodiqa_audit_chain_mirror_count_check', 'qodiqa_audit_chain_true_tail', 'qodiqa_consent_audit_log_full_read', 'qodiqa_erase_subject',
  'qodiqa_erase_subject_finalize', 'qodiqa_erasure_ledger_list', 'qodiqa_erasure_subject_candidates',
  'qodiqa_policy_emergency_activations_full_read', 'qodiqa_tenant_policy_sets_full_read', 'qodiqa_tenant_semantic_configs_full_read',
  'qodiqa_transparency_log_fetch_batch', 'qodiqa_transparency_log_fetch_boundary', 'qodiqa_transparency_log_fetch_by_transparency_id',
  'qodiqa_transparency_log_fetch_hashes_in_range', 'qodiqa_transparency_log_latest_entry'];

const sqlArray = (sql) => [...sql.match(/approved CONSTANT text\[\] := ARRAY\[([\s\S]*?)\];/)[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);

let maint; let owner; let system;

describeOrSkip('SECURITY DEFINER ownership and the erasure allowlist (real disposable PostgreSQL)', () => {
  beforeAll(async () => {
    maint = conn(process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
    await maint.query(`CREATE DATABASE "${DB}"`);
    const r = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO, encoding: 'utf8', timeout: 90_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: TEST_USER, QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (r.status !== 0) throw new Error(`migrate.js failed (${r.status}):\n${r.stdout}\n${r.stderr}`);
    owner = conn(DB, TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
    system = conn(DB, 'qodiqa_system', process.env.QODIQA_PG_SYSTEM_PASSWORD);
  });

  afterAll(async () => {
    await system?.end().catch(() => {});
    await owner?.end().catch(() => {});
    if (maint) {
      try { await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch (e) { console.warn(`[er16] could not drop ${DB}: ${e.message}`); }
      await maint.end();
    }
  });

  const definerAcl = async () => (await owner.query(`
    SELECT p.oid::regprocedure::text AS sig, p.proname AS name, r.rolname AS owner,
           COALESCE((SELECT array_agg(DISTINCT g.rolname::text ORDER BY g.rolname::text) FROM aclexplode(p.proacl) a JOIN pg_roles g ON g.oid = a.grantee
                     WHERE a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner), '{}'::text[]) AS grantees,
           array_to_string(p.proconfig, ';') AS config
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
     WHERE n.nspname = 'public' AND p.prosecdef ORDER BY 1`)).rows;

  test('DO-01 the live definer set equals the pinned 47-signature manifest; 079 and the restore SQL carry the same list', async () => {
    const live = (await owner.query(`SET search_path = public, pg_catalog; SELECT p.oid::regprocedure::text AS sig FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prosecdef ORDER BY 1`))[1].rows.map((x) => x.sig);
    expect(M.DEFINER_SIGNATURES).toHaveLength(47);
    expect([...live].sort()).toEqual([...M.DEFINER_SIGNATURES].sort());
    expect(sqlArray(SQL_079)).toEqual([...M.DEFINER_SIGNATURES]);
    expect(sqlArray(SQL_RESTORE)).toEqual([...M.DEFINER_SIGNATURES]);
  });

  test('DO-02 every definer is owned by qodiqa_definer, which is not a superuser (search_path pinned, never PUBLIC)', async () => {
    const res = await M.checkDefinerOwnership(owner);
    expect(res.problems).toEqual([]);
    expect(res.ok).toBe(true);
    const supers = (await owner.query(`SELECT p.oid::regprocedure::text AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_roles r ON r.oid = p.proowner WHERE n.nspname = 'public' AND p.prosecdef AND (r.rolsuper OR r.rolname <> 'qodiqa_definer')`)).rows;
    expect(supers).toEqual([]);
  });

  test('DO-03 qodiqa_definer: exact role attributes, member of nothing, no runtime member, no CREATE on the schema or database', async () => {
    const { rows: [r] } = await owner.query(`SELECT rolsuper AS super, rolcreatedb AS createdb, rolcreaterole AS createrole, rolcanlogin AS login,
      rolreplication AS replication, rolbypassrls AS bypassrls FROM pg_roles WHERE rolname = 'qodiqa_definer'`);
    expect(r).toEqual(M.ROLE_ATTRIBUTES);
    expect((await owner.query(`SELECT 1 FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'qodiqa_definer'`)).rowCount).toBe(0);
    const members = (await owner.query(`SELECT u.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
      WHERE g.rolname = 'qodiqa_definer'`)).rows.map((x) => x.rolname);
    for (const f of M.FORBIDDEN_MEMBERS) expect({ f, member: members.includes(f) }).toEqual({ f, member: false });
    const { rows: [c] } = await owner.query(`SELECT has_schema_privilege('qodiqa_definer', 'public', 'CREATE') AS schema_create,
      has_database_privilege('qodiqa_definer', current_database(), 'CREATE') AS db_create,
      has_database_privilege('qodiqa_definer', current_database(), 'TEMP') AS db_temp`);
    expect({ schema_create: c.schema_create, db_create: c.db_create }).toEqual({ schema_create: false, db_create: false });
  });

  test('DO-04 qodiqa_definer holds exactly the pinned privilege manifest (tables, columns, sequences, functions)', async () => {
    const tables = (await owner.query(`
      SELECT c.relname AS t, array_agg(DISTINCT a.privilege_type ORDER BY a.privilege_type) AS p
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a
       WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m') AND a.grantee = 'qodiqa_definer'::regrole GROUP BY 1 ORDER BY 1`)).rows;
    const cols = (await owner.query(`
      SELECT c.relname AS t, a.privilege_type AS p, array_agg(at.attname::text ORDER BY at.attname) AS cols
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_attribute at ON at.attrelid = c.oid, aclexplode(at.attacl) a
       WHERE n.nspname = 'public' AND at.attnum > 0 AND a.grantee = 'qodiqa_definer'::regrole GROUP BY 1, 2 ORDER BY 1, 2`)).rows;
    const live = {};
    for (const x of tables) live[x.t] = { table: x.p, columns: {} };
    for (const x of cols) { live[x.t] = live[x.t] || { table: [], columns: {} }; live[x.t].columns[x.p] = x.cols; }
    const vnum = Number((await owner.query('SHOW server_version_num')).rows[0].server_version_num);
    expect(live).toEqual(JSON.parse(JSON.stringify(M.tablePrivilegesFor(vnum)))); // MAINTAIN replaces UPDATE on audit_chain from PG 17
    const seqs = (await owner.query(`
      SELECT c.relname AS s, array_agg(DISTINCT a.privilege_type ORDER BY a.privilege_type) AS p
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a
       WHERE n.nspname = 'public' AND c.relkind = 'S' AND a.grantee = 'qodiqa_definer'::regrole GROUP BY 1 ORDER BY 1`)).rows;
    expect(Object.fromEntries(seqs.map((x) => [x.s, x.p]))).toEqual({ ...M.SEQUENCE_PRIVILEGES });
    const fns = (await owner.query(`SET search_path = public, pg_catalog; SELECT p.oid::regprocedure::text AS f FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace, aclexplode(p.proacl) a
      WHERE n.nspname = 'public' AND a.grantee = 'qodiqa_definer'::regrole AND p.proowner <> 'qodiqa_definer'::regrole ORDER BY 1`))[1].rows.map((x) => x.f);
    expect(fns).toEqual([...M.FUNCTION_EXECUTE]);
    expect((await owner.query(`SELECT 1 FROM pg_default_acl d, aclexplode(d.defaclacl) a WHERE a.grantee = 'qodiqa_definer'::regrole`)).rowCount).toBe(0);
  });

  test('DO-05 the approved EXECUTE grants are preserved exactly (6 app / 16 reporting / 22 system), search_path pinned', async () => {
    const acl = await definerAcl();
    const by = (role) => acl.filter((f) => f.grantees.includes(role)).map((f) => f.name).sort();
    expect(by('qodiqa_app')).toEqual([...APP].sort());
    expect(by('qodiqa_reporting')).toEqual([...REPORTING].sort());
    expect(by('qodiqa_system')).toEqual([...SYSTEM].sort());
    for (const f of acl) {
      expect({ f: f.sig, others: f.grantees.filter((g) => !['qodiqa_app', 'qodiqa_reporting', 'qodiqa_system'].includes(g)) }).toEqual({ f: f.sig, others: [] });
      expect({ f: f.sig, config: f.config }).toEqual({ f: f.sig, config: 'search_path=pg_catalog, public, pg_temp' });
    }
  });

  test('DO-06 a trigger fired inside the erasure definer runs as qodiqa_definer, never as a superuser (instrumentation only)', async () => {
    await owner.query(`CREATE TABLE er16_probe (who text, is_super boolean, at timestamptz DEFAULT now())`);
    await owner.query(`GRANT INSERT ON er16_probe TO PUBLIC`);
    await owner.query(`CREATE FUNCTION er16_probe_fn() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN INSERT INTO er16_probe (who, is_super) SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user; RETURN NEW; END $$`);
    await owner.query(`CREATE TRIGGER er16_probe_trg BEFORE UPDATE ON consent_audit_log FOR EACH ROW EXECUTE FUNCTION er16_probe_fn()`);
    try {
      await owner.query(`INSERT INTO consent_audit_log (event_type, actor, actor_id, tenant_id) VALUES ('ER16_PROBE', 'er16', 'er16-subject-1', 'er16-t')`);
      const { rows } = await system.query('SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', ['er16-t', 'er16-subject-1', PSEUDO, 500]);
      expect(rows.find((x) => x.target === 'consent_audit_log.actor_id')).toMatchObject({ rows_updated: '1', remaining: '0' });
      const probe = (await owner.query('SELECT who, is_super FROM er16_probe')).rows;
      expect(probe).toEqual([{ who: 'qodiqa_definer', is_super: false }]);
    } finally {
      await owner.query('DROP TRIGGER IF EXISTS er16_probe_trg ON consent_audit_log');
    }
  });

  test('DO-07 qodiqa_erasure_targets() returns exactly the seven approved pairs', async () => {
    const { rows } = await owner.query('SELECT table_name, column_name, has_tenant FROM qodiqa_erasure_targets()');
    expect(rows).toEqual([
      ['consent_audit_log', 'actor_id'], ['dsr_exports', 'actor_id'], ['dsr_rectifications', 'actor_id'], ['platform_audit_events', 'actor_id'],
      ['qodiqa_alerts', 'actor_id'], ['request_trails', 'actor_id'], ['revocation_events', 'subject_id'],
    ].map(([table_name, column_name]) => ({ table_name, column_name, has_tenant: true })));
  });

  test('DO-08 a planted actor_id table with a probe trigger is never selected: erasure refuses, the probe never fires, the row is unchanged', async () => {
    await owner.query('TRUNCATE er16_probe');
    await owner.query(`CREATE TABLE er16_planted (actor_id text, tenant_id text)`);
    await owner.query(`CREATE TRIGGER er16_planted_trg BEFORE UPDATE ON er16_planted FOR EACH ROW EXECUTE FUNCTION er16_probe_fn()`);
    await owner.query(`INSERT INTO er16_planted VALUES ('er16-subject-2', 'er16-t')`);
    try {
      for (const call of [
        () => system.query('SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', ['er16-t', 'er16-subject-2', PSEUDO, 500]),
        () => system.query('SELECT * FROM qodiqa_erasure_subject_candidates()'),
        () => owner.query('SELECT * FROM qodiqa_erasure_targets()'),
      ]) {
        const err = await call().then(() => null, (e) => e);
        expect(err).not.toBeNull();
        expect(err.code).toBe('55000');
        expect(err.message).toMatch(/undeclared subject-identifier column\(s\) er16_planted\.actor_id/);
      }
      expect((await owner.query('SELECT count(*)::int AS n FROM er16_probe')).rows[0].n).toBe(0);
      expect((await owner.query('SELECT actor_id FROM er16_planted')).rows).toEqual([{ actor_id: 'er16-subject-2' }]);
    } finally {
      await owner.query('DROP TABLE IF EXISTS er16_planted');
    }
    // with the planted table gone, erasure runs again
    const { rows } = await system.query('SELECT * FROM qodiqa_erase_subject($1, $2, $3, $4)', ['er16-t', 'er16-subject-2', PSEUDO, 500]);
    expect(rows.length).toBe(8);
    // this file's own probe fixtures are removed: later tests (DO-11, DO-14) require the exact approved object set
    await owner.query('DROP TABLE er16_probe');
    await owner.query('DROP FUNCTION er16_probe_fn()');
  });

  test('DO-09 a missing or incompatible approved target fails closed (55000), nothing is erased', async () => {
    const c = await owner.connect();
    try {
      for (const ddl of ['ALTER TABLE dsr_exports RENAME COLUMN actor_id TO actor_id_er16', 'ALTER TABLE qodiqa_alerts DROP COLUMN tenant_id CASCADE',
        'ALTER TABLE request_trails ALTER COLUMN actor_id TYPE bytea USING convert_to(actor_id, \'UTF8\')']) {
        await c.query('BEGIN');
        try {
          await c.query(ddl);
          const err = await c.query('SELECT * FROM qodiqa_erasure_targets()').then(() => null, (e) => e);
          expect({ ddl, code: err && err.code }).toEqual({ ddl, code: '55000' });
          expect(err.message).toMatch(/is missing or incompatible/);
        } finally { await c.query('ROLLBACK'); }
      }
    } finally { c.release(); }
    expect((await owner.query('SELECT count(*)::int AS n FROM qodiqa_erasure_targets()')).rows[0].n).toBe(7);
  });

  test('DO-10 the owner-only mirror-count rebuild runs as qodiqa_definer and keeps the counter exact', async () => {
    const { rows: [rb] } = await owner.query('SELECT previous, rebuilt FROM qodiqa_audit_chain_mirror_count_rebuild()');
    const { rows: [ck] } = await owner.query('SELECT stored, exact, in_sync FROM qodiqa_audit_chain_mirror_count_check()');
    expect(Number(rb.rebuilt)).toBe(Number(ck.exact));
    expect(ck.in_sync).toBe(true);
    await expect(system.query('SELECT * FROM qodiqa_audit_chain_mirror_count_rebuild()')).rejects.toThrow(/permission denied/);
  });

  test('DO-14 every relation, non-definer function and enum is owned by qodiqa_owner; the role is NOLOGIN, non-superuser, no BYPASSRLS', async () => {
    expect((await M.checkSchemaOwnership(owner)).problems).toEqual([]);
    const { rows: [r] } = await owner.query(`SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, rolreplication, rolbypassrls
      FROM pg_roles WHERE rolname = 'qodiqa_owner'`);
    expect(r).toEqual({ rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolcanlogin: false, rolreplication: false, rolbypassrls: false });
    const owners = (await owner.query(`SELECT DISTINCT pg_get_userbyid(c.relowner) AS o FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname NOT LIKE 'er16_%'
      UNION SELECT DISTINCT pg_get_userbyid(t.typowner) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'public' AND t.typtype = 'e'`)).rows.map((x) => x.o);
    expect(owners).toEqual(['qodiqa_owner']);
    const members = (await owner.query(`SELECT u.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
      WHERE g.rolname = 'qodiqa_owner'`)).rows.map((x) => x.rolname);
    for (const f of [...M.FORBIDDEN_MEMBERS, 'qodiqa_definer']) expect({ f, member: members.includes(f) }).toEqual({ f, member: false });
    expect((await owner.query(`SELECT 1 FROM pg_auth_members m JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = 'qodiqa_owner'`)).rowCount).toBe(0);
    expect(sqlList(SQL_SCHEMA_RESTORE, 'approved_tables')).toEqual(sqlList(SQL_081, 'approved_tables'));
    expect(sqlList(SQL_SCHEMA_RESTORE, 'approved_functions')).toEqual(sqlList(SQL_081, 'approved_functions'));
    expect(sqlList(SQL_081, 'approved_tables')).toHaveLength(84);
  });

  test('DO-15 qodiqa_mig owns nothing and holds exactly SELECT + INSERT on audit_chain', async () => {
    expect((await owner.query(`SELECT 1 FROM pg_class WHERE relowner = 'qodiqa_mig'::regrole`)).rowCount).toBe(0);
    const p = (await owner.query(`SELECT array_agg(x ORDER BY x) AS p FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) x
      WHERE has_table_privilege('qodiqa_mig', 'public.audit_chain', x)`)).rows[0].p;
    expect(p).toEqual(['INSERT', 'SELECT']);
    // its other migration-001 tables keep what it held as their owner (no silent loss)
    const ok = (await owner.query(`SELECT has_table_privilege('qodiqa_mig', 'public.signing_keys', 'UPDATE')
      AND has_table_privilege('qodiqa_mig', 'public.qodiqa_migrations', 'INSERT') AS ok`)).rows[0].ok;
    expect(ok).toBe(true);
  });

  test('DO-16 default privileges exist only FOR ROLE qodiqa_owner (backup SELECT), and qodiqa_backup reads every table', async () => {
    const d = (await owner.query(`SELECT defaclrole::regrole::text AS r, defaclobjtype AS t, defaclacl::text AS a FROM pg_default_acl ORDER BY 2`)).rows;
    expect(d).toEqual([{ r: 'qodiqa_owner', t: 'S', a: '{qodiqa_backup=r/qodiqa_owner}' }, { r: 'qodiqa_owner', t: 'r', a: '{qodiqa_backup=r/qodiqa_owner}' }]);
    expect((await owner.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND NOT has_table_privilege('qodiqa_backup', c.oid, 'SELECT')`)).rows).toEqual([]);
  });

  test('DO-17 schema-ownership restore drift is detected; scripts/dr/schema-ownership.sql repairs it', async () => {
    const before = await snapshot();
    await owner.query(`DO $$ BEGIN
      EXECUTE format('ALTER TABLE public.audit_chain OWNER TO %I', current_user);
      EXECUTE format('ALTER TABLE public.tenants OWNER TO %I', current_user);
      EXECUTE format('ALTER FUNCTION qodiqa_current_tenant() OWNER TO %I', current_user);
    END $$`);
    const drift = await M.checkSchemaOwnership(owner);
    expect(drift.ok).toBe(false);
    expect(drift.problems.join('\n')).toMatch(/audit_chain is owned by/);
    await owner.query(SQL_SCHEMA_RESTORE);
    expect((await M.checkSchemaOwnership(owner)).problems).toEqual([]);
    expect(await snapshot()).toBe(before);
  });

  const snapshot = async () => JSON.stringify((await owner.query(`
    SELECT p.oid::regprocedure::text, r.rolname, p.proacl::text, array_to_string(p.proconfig, ';'), md5(p.prosrc)
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
     WHERE n.nspname = 'public' AND (p.prosecdef OR p.proname = 'qodiqa_erasure_targets') ORDER BY 1`)).rows)
    + JSON.stringify((await owner.query(`SELECT c.relname, c.relacl::text, (SELECT string_agg(attname || ':' || attacl::text, ',' ORDER BY attnum)
       FROM pg_attribute WHERE attrelid = c.oid AND attacl IS NOT NULL) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname NOT LIKE 'er16_%' ORDER BY 1`)).rows)
    + JSON.stringify((await owner.query(`SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relname NOT LIKE 'er16_%' ORDER BY 1`)).rows)
    + JSON.stringify((await owner.query(`SELECT p.oid::regprocedure::text, pg_get_userbyid(p.proowner), p.proacl::text FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND NOT p.prosecdef AND p.proname NOT LIKE 'er16_%' ORDER BY 1`)).rows)
    + JSON.stringify((await owner.query(`SELECT defaclrole::regrole::text, defaclobjtype, defaclacl::text FROM pg_default_acl ORDER BY 1, 2`)).rows);

  test('DO-11 re-executing migrations 079, 080 and 081 is idempotent (catalog unchanged)', async () => {
    const parked = await parkPost081(owner, sqlList(SQL_SCHEMA_RESTORE, 'post_081_tables'));
    try {
    const before = await snapshot();
    await owner.query(SQL_079);
    await owner.query(SQL_080);
    await owner.query(SQL_081);
    await owner.query(SQL_082); // 079 re-grants the table-wide UPDATE that 082 narrows on PG >= 17, so the chain is re-executed in order
    expect(await snapshot()).toBe(before);
    const r = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO, encoding: 'utf8', timeout: 60_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: TEST_USER, QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Migration complete\. Applied: 0/);
    } finally { await unparkPost081(owner, parked); }
  });

  test('DO-12 restore drift (definers owned by the restoring role) is detected; scripts/dr/definer-ownership.sql repairs it', async () => {
    const before = await snapshot();
    await owner.query(`DO $$ BEGIN
      EXECUTE format('ALTER FUNCTION qodiqa_erase_subject(text,text,text,integer) OWNER TO %I', current_user);
      EXECUTE format('ALTER FUNCTION qodiqa_transparency_public_entry(uuid) OWNER TO %I', current_user);
    END $$`);
    const drift = await M.checkDefinerOwnership(owner);
    expect(drift.ok).toBe(false);
    expect(drift.problems.join('\n')).toMatch(/qodiqa_erase_subject\(text,text,text,integer\) is owned by/);
    await owner.query(SQL_RESTORE);
    expect((await M.checkDefinerOwnership(owner)).problems).toEqual([]);
    expect(await snapshot()).toBe(before);
  });

  test('DO-18 audit_chain: the definer has MAINTAIN instead of table-wide UPDATE on PostgreSQL >= 17, and still has UPDATE below 17', async () => {
    const vnum = Number((await owner.query('SHOW server_version_num')).rows[0].server_version_num);
    const has = async (priv) => (await owner.query(`SELECT has_table_privilege('qodiqa_definer', 'public.audit_chain', $1) AS ok`, [priv])).rows[0].ok;
    if (vnum >= 170000) {
      expect({ update: await has('UPDATE'), maintain: await has('MAINTAIN'), select: await has('SELECT') }).toEqual({ update: false, maintain: true, select: true });
    } else {
      expect({ update: await has('UPDATE'), select: await has('SELECT') }).toEqual({ update: true, select: true });
    }
    for (const priv of ['INSERT', 'DELETE', 'TRUNCATE']) expect({ priv, ok: await has(priv) }).toEqual({ priv, ok: false });
  });

  test('DO-13 rollback (rollback-schema-owner.sql + rollback-definer-ownership.sql) then forward recovery (079-081) on this disposable database', async () => {
    const parked = await parkPost081(owner, sqlList(SQL_SCHEMA_RESTORE, 'post_081_tables'));
    try {
    const before = await snapshot();
    await owner.query(SQL_SCHEMA_ROLLBACK);
    expect((await owner.query(`SELECT pg_get_userbyid(relowner) AS o FROM pg_class WHERE relname = 'audit_chain'`)).rows[0].o).toBe('qodiqa_mig');
    await owner.query(SQL_ROLLBACK);
    const rolledBack = (await owner.query(`SELECT count(*)::int AS n FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_roles r ON r.oid = p.proowner WHERE n.nspname = 'public' AND p.prosecdef AND r.rolname = 'qodiqa_definer'`)).rows[0].n;
    expect(rolledBack).toBe(0);
    expect((await owner.query(`SELECT version FROM qodiqa_migrations WHERE version IN (79, 80, 81, 82)`)).rowCount).toBe(0);
    const r = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO, encoding: 'utf8', timeout: 60_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: TEST_USER, QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    expect({ status: r.status, out: r.stdout.match(/Migration complete\. Applied: \d+/)?.[0] }).toEqual({ status: 0, out: 'Migration complete. Applied: 4' });
    expect((await M.checkDefinerOwnership(owner)).problems).toEqual([]);
    expect((await M.checkSchemaOwnership(owner)).problems).toEqual([]);
    expect(await snapshot()).toBe(before);
    } finally { await unparkPost081(owner, parked); }
  });
});
