'use strict';

/**
 * — the pinned SECURITY DEFINER ownership manifest and its catalog check.
 *
 * Every SECURITY DEFINER function in schema public runs as its owner. Migration 079 makes that owner the NOLOGIN,
 * non-superuser role qodiqa_definer, which holds BYPASSRLS plus exactly the privileges below. This module is the one
 * place that list lives in JavaScript; migration 079 and scripts/dr/definer-ownership.sql carry the same list in SQL
 * (they must be self-contained), and test/integration/definerOwnership.integration.test.js pins all three equal and equal to
 * the live catalog.
 *
 * checkDefinerOwnership(client) is used by the DR restore paths (scripts/dr/postgres.js, scripts/dr/pgDump.js) so a
 * restored target can never silently carry superuser-owned (or otherwise mis-owned) definer functions.
 */

const DEFINER_OWNER = 'qodiqa_definer';
const SEARCH_PATH = 'search_path=pg_catalog, public, pg_temp';

// regprocedure text form (search_path = public, pg_catalog), sorted
const DEFINER_SIGNATURES = Object.freeze([
  'qodiqa_audit_chain_decisions(text[])',
  'qodiqa_audit_chain_detect_sequence_gaps(bigint,integer)',
  'qodiqa_audit_chain_fetch_batch(bigint,integer)',
  'qodiqa_audit_chain_fetch_by_artifact_id(character varying)',
  'qodiqa_audit_chain_fetch_replay_lineage(character varying)',
  'qodiqa_audit_chain_fetch_row_by_seq(bigint)',
  'qodiqa_audit_chain_full_read()',
  'qodiqa_audit_chain_hash_exists(character)',
  'qodiqa_audit_chain_max_seq()',
  'qodiqa_audit_chain_mirror_count()',
  'qodiqa_audit_chain_mirror_count_check()',
  'qodiqa_audit_chain_mirror_count_on_delete()',
  'qodiqa_audit_chain_mirror_count_on_insert()',
  'qodiqa_audit_chain_mirror_count_on_truncate()',
  'qodiqa_audit_chain_mirror_count_rebuild()',
  'qodiqa_audit_chain_true_tail()',
  'qodiqa_audit_legal_holds_full_read()',
  'qodiqa_audit_retention_policies_full_read()',
  'qodiqa_compliance_reports_full_read()',
  'qodiqa_consent_audit_log_full_read()',
  'qodiqa_erase_subject(text,text,text,integer)',
  'qodiqa_erase_subject_finalize(uuid,text,text,text,text,uuid,jsonb,text,text,text)',
  'qodiqa_erasure_ledger_list(bigint,integer)',
  'qodiqa_erasure_subject_candidates()',
  'qodiqa_evidence_chain_records_full_read()',
  'qodiqa_evidence_public_lookup(character varying,text)',
  'qodiqa_platform_audit_events_full_read()',
  'qodiqa_policy_change_request_by_id(uuid)',
  'qodiqa_policy_emergency_activations_full_read()',
  'qodiqa_qodiqa_alert_history_full_read()',
  'qodiqa_qodiqa_alerts_full_read()',
  'qodiqa_request_trails_by_ids(uuid,text)',
  'qodiqa_tenant_policy_sets_full_read()',
  'qodiqa_tenant_semantic_configs_full_read()',
  'qodiqa_transparency_log_fetch_batch(bigint,integer)',
  'qodiqa_transparency_log_fetch_boundary(bigint)',
  'qodiqa_transparency_log_fetch_by_artifact_id(character varying)',
  'qodiqa_transparency_log_fetch_by_entry_hash(character)',
  'qodiqa_transparency_log_fetch_by_transparency_id(uuid)',
  'qodiqa_transparency_log_fetch_hashes_in_range(bigint,bigint)',
  'qodiqa_transparency_log_fetch_range_full(bigint,bigint)',
  'qodiqa_transparency_log_latest_entry()',
  'qodiqa_transparency_log_read_all()',
  'qodiqa_transparency_public_entry(uuid)',
  'qodiqa_transparency_public_entry_by_hash(character)',
  'qodiqa_transparency_public_hashes_from_id(bigint,integer)',
  'qodiqa_transparency_public_list(text,text,text,timestamp with time zone,timestamp with time zone,integer,integer,boolean)',
]);

// The exact privileges qodiqa_definer holds in a migrated database (migration 079), derived from the 47 bodies.
// table → { table: [table-level privileges], columns: { PRIVILEGE: [columns] } }
const SELECT_ONLY = ['audit_legal_holds', 'audit_retention_policies', 'compliance_reports', 'consent_records',
  'evidence_chain_records', 'policy_change_requests', 'policy_emergency_activations',
  'qodiqa_alert_history', 'tenant_policy_sets', 'tenant_semantic_configs', 'transparency_log_entries'];
const TABLE_PRIVILEGES = Object.freeze({
  ...Object.fromEntries(SELECT_ONLY.map((t) => [t, { table: ['SELECT'], columns: {} }])),
  audit_chain:              { table: ['SELECT', 'UPDATE'], columns: {} }, // UPDATE: LOCK ... SHARE ROW EXCLUSIVE in the rebuild only
  audit_chain_mirror_count: { table: ['INSERT', 'SELECT'], columns: { UPDATE: ['rebuilt_at', 'row_count', 'updated_at'] } },
  consent_audit_log:        { table: ['SELECT'], columns: { UPDATE: ['actor_id'] } },
  dsr_erasure_ledger:       { table: ['INSERT', 'SELECT'], columns: {} },
  dsr_exports:              { table: ['SELECT'], columns: { UPDATE: ['actor_id'] } },
  dsr_rectifications:       { table: ['SELECT'], columns: { UPDATE: ['actor_id', 'new_value', 'old_value'] } },
  dsr_request_events:       { table: ['INSERT'], columns: {} },
  dsr_requests:             { table: ['SELECT'], columns: { UPDATE: ['actor_id', 'completed_at', 'result', 'status'] } },
  platform_audit_events:    { table: ['SELECT'], columns: { UPDATE: ['actor_id', 'payload'] } },
  qodiqa_alerts:            { table: ['SELECT'], columns: { UPDATE: ['actor_id', 'client_ip'] } },
  request_trails:           { table: ['SELECT'], columns: { UPDATE: ['actor_id', 'caller_ip'] } },
  revocation_events:        { table: ['SELECT'], columns: { UPDATE: ['raw_payload', 'subject_id'] } },
  subject_pseudonym_keys:   { table: ['DELETE', 'SELECT'], columns: {} },
});
// (migration 082): on PostgreSQL >= 17 the audit_chain table-wide UPDATE is replaced by MAINTAIN (it authorises LOCK TABLE in every
// mode without authorising any row change); on PostgreSQL < 17 there is no narrower privilege and the manifest above stays in force.
function tablePrivilegesFor(serverVersionNum) {
  if (Number(serverVersionNum) >= 170000) {
    return Object.freeze({ ...TABLE_PRIVILEGES, audit_chain: { table: ['MAINTAIN', 'SELECT'], columns: {} } });
  }
  return TABLE_PRIVILEGES;
}
const SEQUENCE_PRIVILEGES = Object.freeze({ dsr_erasure_ledger_id_seq: ['USAGE'], dsr_request_events_id_seq: ['USAGE'] });
const FUNCTION_EXECUTE = Object.freeze(['qodiqa_erasure_targets()']); // non-definer functions it may call
const ROLE_ATTRIBUTES = Object.freeze({ super: false, createdb: false, createrole: false, login: false, replication: false, bypassrls: true });

// Roles that must never be able to assume qodiqa_definer (runtime credentials and the migration role).
const FORBIDDEN_MEMBERS = Object.freeze(['qodiqa_app', 'qodiqa_read', 'qodiqa_mig', 'qodiqa_retention', 'qodiqa_system',
  'qodiqa_reporting', 'qodiqa_control', 'qodiqa_backup']);

/**
 * Read-only catalog check. Returns { ok, problems: string[], facts }.
 * @param {{query: Function}} client  a pg client/pool connected to the target database
 */
async function checkDefinerOwnership(client) {
  const q = async (sql, p) => (await client.query(sql, p)).rows;
  const problems = [];
  const fns = await q(`
    SELECT p.oid::regprocedure::text AS sig, r.rolname AS owner, r.rolsuper AS owner_super,
           COALESCE(p.proconfig, '{}') AS config, p.proacl IS NULL AS default_acl,
           COALESCE((SELECT bool_or(a.grantee = 0) FROM aclexplode(p.proacl) a), false) AS public_exec
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
     WHERE n.nspname = 'public' AND p.prosecdef`);
  // regprocedure text depends on search_path: normalise a schema-qualified form
  const norm = (s) => s.replace(/^public\./, '');
  const live = new Map(fns.map((f) => [norm(f.sig), f]));
  for (const s of DEFINER_SIGNATURES) if (!live.has(s)) problems.push(`missing SECURITY DEFINER function ${s}`);
  for (const [s, f] of live) {
    if (!DEFINER_SIGNATURES.includes(s)) problems.push(`unexpected SECURITY DEFINER function ${s} (owner ${f.owner})`);
    if (f.owner !== DEFINER_OWNER) problems.push(`${s} is owned by ${f.owner}, not ${DEFINER_OWNER}`);
    if (f.owner_super) problems.push(`${s} is owned by a SUPERUSER (${f.owner})`);
    if (!f.config.includes(SEARCH_PATH)) problems.push(`${s} lacks the pinned ${SEARCH_PATH}`);
    if (f.default_acl || f.public_exec) problems.push(`${s} is executable by PUBLIC`);
  }
  const [role] = await q(`SELECT rolsuper AS super, rolcreatedb AS createdb, rolcreaterole AS createrole, rolcanlogin AS login,
                                 rolreplication AS replication, rolbypassrls AS bypassrls
                            FROM pg_catalog.pg_roles WHERE rolname = $1`, [DEFINER_OWNER]);
  if (!role) problems.push(`role ${DEFINER_OWNER} does not exist`);
  else {
    for (const [k, v] of Object.entries(ROLE_ATTRIBUTES)) if (role[k] !== v) problems.push(`${DEFINER_OWNER}.${k} is ${role[k]}, expected ${v}`);
    const members = (await q(`SELECT u.rolname FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
                                JOIN pg_catalog.pg_roles u ON u.oid = m.member WHERE g.rolname = $1`, [DEFINER_OWNER])).map((r) => r.rolname);
    for (const m of members.filter((x) => FORBIDDEN_MEMBERS.includes(x))) problems.push(`${m} can assume ${DEFINER_OWNER}`);
    const memberOf = await q(`SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles u ON u.oid = m.member WHERE u.rolname = $1`, [DEFINER_OWNER]);
    if (memberOf.length) problems.push(`${DEFINER_OWNER} is a member of another role`);
  }
  return { ok: problems.length === 0, problems, facts: { definers: live.size } };
}

const SCHEMA_OWNER = 'qodiqa_owner';
const RESTORE_SQL = require('path').join(__dirname, '..', '..', '..', 'scripts', 'dr', 'definer-ownership.sql');
const SCHEMA_RESTORE_SQL = require('path').join(__dirname, '..', '..', '..', 'scripts', 'dr', 'schema-ownership.sql');

// ONE query (DR unit-test fakes answer it by pattern): is the schema at migration 079 (definer owner) / 081 (schema owner)?
async function _er16Level(client) {
  const { rows: [r] } = await client.query(
    "SELECT to_regclass('public.qodiqa_migrations') IS NOT NULL AND EXISTS (SELECT 1 FROM public.qodiqa_migrations WHERE version = 79) AS er16, "
    + "to_regclass('public.qodiqa_migrations') IS NOT NULL AND EXISTS (SELECT 1 FROM public.qodiqa_migrations WHERE version = 81) AS er16_owner");
  return { definer: r.er16 === true, owner: r.er16_owner === true };
}

function _fail(message, code) { const e = new Error(message); e.code = code; return e; }

/**
 * closure (migration 081): every relation and non-definer function in public owned by qodiqa_owner (NOLOGIN,
 * non-superuser, no BYPASSRLS); qodiqa_backup can read every table; the only default privileges are qodiqa_owner's;
 * qodiqa_mig cannot UPDATE/DELETE/TRUNCATE/TRIGGER audit_chain. Read-only.
 */
async function checkSchemaOwnership(client) {
  const q = async (sql, p) => (await client.query(sql, p)).rows;
  const problems = [];
  const [role] = await q(`SELECT rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, rolreplication, rolbypassrls
                            FROM pg_catalog.pg_roles WHERE rolname = $1`, [SCHEMA_OWNER]);
  if (!role) problems.push(`role ${SCHEMA_OWNER} does not exist`);
  else if (Object.values(role).some(Boolean)) problems.push(`${SCHEMA_OWNER} has a forbidden attribute: ${JSON.stringify(role)}`);
  for (const r of await q(`SELECT c.relname, pg_get_userbyid(c.relowner) AS owner FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r','p','S','v','m','i','I') AND pg_get_userbyid(c.relowner) <> $1`, [SCHEMA_OWNER])) {
    problems.push(`${r.relname} is owned by ${r.owner}`);
  }
  for (const r of await q(`SELECT p.oid::regprocedure::text AS sig, pg_get_userbyid(p.proowner) AS owner FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND NOT p.prosecdef AND pg_get_userbyid(p.proowner) <> $1`, [SCHEMA_OWNER])) {
    problems.push(`${r.sig} is owned by ${r.owner}`);
  }
  for (const r of await q(`SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND NOT has_table_privilege('qodiqa_backup', c.oid, 'SELECT')`)) {
    problems.push(`qodiqa_backup cannot read ${r.relname}`);
  }
  for (const r of await q(`SELECT defaclrole::regrole::text AS r FROM pg_catalog.pg_default_acl WHERE defaclrole::regrole::text <> $1`, [SCHEMA_OWNER])) {
    problems.push(`default privileges for ${r.r}`);
  }
  const [m] = await q(`SELECT has_table_privilege('qodiqa_mig', 'public.audit_chain', 'UPDATE')
      OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'DELETE') OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'TRUNCATE')
      OR has_table_privilege('qodiqa_mig', 'public.audit_chain', 'TRIGGER') AS x`);
  if (m.x) problems.push('qodiqa_mig can UPDATE/DELETE/TRUNCATE/TRIGGER audit_chain');
  return { ok: problems.length === 0, problems };
}

/**
 * DR restore (pg_restore --no-owner): hand the restored objects back to qodiqa_owner (081+: scripts/dr/schema-
 * ownership.sql) and the definer functions to qodiqa_definer (079+: scripts/dr/definer-ownership.sql), as the restoring
 * role, and verify. Throws (code RESTORE_DEFINER_OWNERSHIP_FAILED) on any failure. A schema that predates migration
 * 079 is reported as { applied: false, reason: 'pre-er16-schema' }.
 */
async function reestablishDefinerOwnership(client) {
  const lvl = await _er16Level(client);
  if (!lvl.definer) return { applied: false, reason: 'pre-er16-schema' };
  try {
    if (lvl.owner) await client.query(require('fs').readFileSync(SCHEMA_RESTORE_SQL, 'utf8'));
    await client.query(require('fs').readFileSync(RESTORE_SQL, 'utf8'));
  } catch (err) {
    throw _fail(`re-establishing ownership failed: ${err.message} — the restored target is INCOMPLETE; restore as the bootstrap/migration identity that ran migrations 079/081`, 'RESTORE_DEFINER_OWNERSHIP_FAILED');
  }
  return _verified(client, lvl, 'applied');
}

async function _verified(client, lvl, key) {
  const res = await checkDefinerOwnership(client);
  const sch = lvl.owner ? await checkSchemaOwnership(client) : { ok: true, problems: [] };
  if (!res.ok || !sch.ok) {
    throw _fail(`ownership of the restore target is wrong: ${[...res.problems, ...sch.problems].join('; ')}`, 'RESTORE_DEFINER_OWNERSHIP_FAILED');
  }
  return { [key]: true, owner: DEFINER_OWNER, definers: res.facts.definers, schemaOwner: lvl.owner ? SCHEMA_OWNER : null };
}

/** Data-only restore into a migrated target: verify (never change) definer (079+) and schema (081+) ownership. */
async function verifyRestoredDefinerOwnership(client) {
  const lvl = await _er16Level(client);
  if (!lvl.definer) return { verified: false, reason: 'pre-er16-schema' };
  return _verified(client, lvl, 'verified');
}

module.exports = {
  DEFINER_OWNER, SEARCH_PATH, DEFINER_SIGNATURES, TABLE_PRIVILEGES, tablePrivilegesFor, SEQUENCE_PRIVILEGES, FUNCTION_EXECUTE,
  ROLE_ATTRIBUTES, FORBIDDEN_MEMBERS, SCHEMA_OWNER, checkDefinerOwnership, checkSchemaOwnership, reestablishDefinerOwnership,
  verifyRestoredDefinerOwnership,
};
