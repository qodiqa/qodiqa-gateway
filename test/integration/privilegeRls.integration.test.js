'use strict';

/**
 * step 8 — privileges and row-level security on
 * a real disposable PostgreSQL database with the full migration chain
 * (test:component:serial: it runs the chain).
 *
 * PM-01 the live catalog equals (roles,
 *              table privileges/RLS/triggers, DEFINER executors, D2 policies)
 *   RLS-91…100 the former skipped stubs of src/infra/postgres/__tests__/rls.test.js,
 *              now real: tenant isolation on webhook_endpoints and consent_records,
 *              connection-reuse leakage, BYPASSRLS ground truth, append-only insert
 *   XT-*       cross-tenant probes as the request-serving role (qodiqa_app)
 * LB-* consent lawful-basis constraints (migration 064)
 *
 * Roles: qodiqa_app for everything under test; qodiqa_test (BYPASSRLS) only to
 * create/migrate/seed and for ground-truth counts — on FORCE RLS tables an app
 * count is a slice, never a total.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_w5pr_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const A = 'w5pr-tenant-alpha';
const B = 'w5pr-tenant-bravo';
const OWNER_ROLES = ['qodiqa_test', 'qodiqa_mig'];
// A throwaway SELECT-only role (no BYPASSRLS) to exercise the tenants/organizations
// policies — no application role holds any privilege there. Created and dropped by
// this suite only (same pattern as securityDefinerAdversarial's NOPRIV_ROLE).
const PROBE_ROLE = `w5pr_probe_${crypto.randomBytes(4).toString('hex')}`;
const PROBE_PASSWORD = crypto.randomBytes(16).toString('hex');

const base = () => ({
  host: process.env.QODIQA_PG_HOST || 'localhost',
  port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  connectionTimeoutMillis: 5000,
});
let maint; let owner; let app; let probe;

/** Run fn in one transaction on ONE app connection, with the tenant GUC set (or not). */
async function asApp(tenant, fn, client) {
  const c = client || await app.connect();
  try {
    await c.query('BEGIN');
    if (tenant !== undefined) await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [tenant]);
    const out = await fn(c);
    await c.query('COMMIT');
    return out;
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    if (!client) c.release();
  }
}
const count = async (c, sql, p = []) => Number((await c.query(sql, p)).rows[0].n);

async function seedWebhook(tenant) {
  const r = await owner.query(
    "INSERT INTO webhook_endpoints (tenant_id, url, secret_enc, secret_iv, secret_tag) VALUES ($1, $2, 'x', 'x', 'x') RETURNING id",
    [tenant, `https://hooks.example/${tenant}`]);
  return r.rows[0].id;
}

describeOrSkip('privileges and RLS on real PostgreSQL', () => {
  const seed = {};

  beforeAll(async () => {
    maint = new Pool({ ...base(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const { spawnSync } = require('child_process');
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 90_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    owner = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    app = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env.QODIQA_PG_PASSWORD, max: 2 });
    await maint.query(`CREATE ROLE ${PROBE_ROLE} LOGIN NOBYPASSRLS PASSWORD '${PROBE_PASSWORD}'`);
    await owner.query(`GRANT CONNECT ON DATABASE "${DB}" TO ${PROBE_ROLE}`);
    await owner.query(`GRANT USAGE ON SCHEMA public TO ${PROBE_ROLE}`);
    await owner.query(`GRANT SELECT ON tenants, organizations TO ${PROBE_ROLE}`);
    probe = new Pool({ ...base(), database: DB, user: PROBE_ROLE, password: PROBE_PASSWORD, max: 1 });

    seed.whA = await seedWebhook(A);
    seed.whB = await seedWebhook(B);
    for (const [tenant, actor] of [[null, 'w5pr-platform-actor'], [A, 'w5pr-actor-a'], [B, 'w5pr-actor-b']]) {
      await owner.query("INSERT INTO consent_records (actor_id, action, tenant_id, state, granted_by) VALUES ($1, 'w5pr-action', $2, 'ACTIVE', 'op')", [actor, tenant]);
    }
  });

  afterAll(async () => {
    if (app) await app.end();
    if (probe) await probe.end();
    if (owner) await owner.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      await maint.query(`DROP ROLE IF EXISTS ${PROBE_ROLE}`); // this suite's own probe role (its only grants lived in the dropped DB)
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  // ── PM-01: the catalog equals the reviewed policy ────────────────────────────
  test('PM-01 the live privilege matrix equals the newest policy, (ownership-normalised)', async () => {
    const { collectMatrix, normalizeOwnership } = require('../../scripts/security/privilegeMatrix');
    // the newest policy
    // DB-05 (migration 076): the policy + the DB-05 delta. (migrations 079/080): the newest policy is the DB-05
    // policy + the delta (definer owner role; every definer owner must NOT be a superuser). DB-05 stay on record.
    const md = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'security', 'PRIVILEGE-POLICY.md'), 'utf8');
    const policy = JSON.parse(md.match(/```json\n([\s\S]*?)\n```/)[1]);
    const c = await owner.connect();
    let live;
    try { live = normalizeOwnership(await collectMatrix(c)); } finally { c.release(); }

    // roles (policy roles only; other qodiqa_* roles on the cluster are out of scope)
    const liveRoles = Object.fromEntries(live.roles.map((r) => [r.name, { super: r.super, inherit: r.inherit, createrole: r.createrole, createdb: r.createdb, login: r.login, bypassrls: r.bypassrls, member_of: r.member_of }]));
    // migration 067 grants qodiqa_backup the predefined, READ-ONLY role
    // pg_read_all_data wherever the migrating identity may (a superuser — every real deployment and the CI service), and
    // falls back to explicit SELECT grants elsewhere; the policy's reference state is the latter. Exactly that one
    // documented membership is normalised away — any other membership, on any role, still fails.
    if (liveRoles.qodiqa_backup && Array.isArray(liveRoles.qodiqa_backup.member_of)) {
      liveRoles.qodiqa_backup = { ...liveRoles.qodiqa_backup, member_of: liveRoles.qodiqa_backup.member_of.filter((m) => m !== 'pg_read_all_data') };
    }
    for (const [name, want] of Object.entries(policy.roles)) {
      if (OWNER_ROLES.includes(name)) continue; // owner identities differ by design (disposable vs deployment)
      expect({ name, got: liveRoles[name] }).toEqual({ name, got: want });
    }

    // tables: same set, same shape
    const appRoles = Object.keys(policy.roles).filter((r) => !OWNER_ROLES.includes(r)).sort();
    const liveTables = {};
    for (const t of live.tables) {
      const privs = {}; for (const r of appRoles) privs[r] = t.privs[r] || [];
      liveTables[t.name] = { kind: t.kind, rls: t.rls, forceRls: t.forceRls, publicPrivs: t.publicPrivs, privs, columnOnlyUpdate: t.columnOnlyUpdate, triggers: t.triggers.map((x) => x.name).sort() };
    }
    const wantTables = Object.fromEntries(Object.entries(policy.tables).map(([k, v]) => [k, { kind: v.kind, rls: v.rls, forceRls: v.forceRls, publicPrivs: v.publicPrivs, privs: Object.fromEntries(appRoles.map((r) => [r, v.privs[r] || []])), columnOnlyUpdate: v.columnOnlyUpdate, triggers: [...v.triggers].sort() }]));
    // (migration 082): from PostgreSQL 17 the definer holds MAINTAIN (not part of this matrix's vocabulary) instead of UPDATE on audit_chain
    const _vnum = Number((await owner.query('SHOW server_version_num')).rows[0].server_version_num);
    if (_vnum >= 170000 && wantTables.audit_chain && wantTables.audit_chain.privs.qodiqa_definer) {
      wantTables.audit_chain.privs.qodiqa_definer = wantTables.audit_chain.privs.qodiqa_definer.filter((p) => p !== 'UPDATE');
    }
    expect(Object.keys(liveTables).sort()).toEqual(Object.keys(wantTables).sort());
    for (const name of Object.keys(wantTables)) expect({ name, got: liveTables[name] }).toEqual({ name, got: wantTables[name] });

    // SECURITY DEFINER functions: same set, same executors, never PUBLIC, search_path pinned
    const liveFns = Object.fromEntries(live.definerFunctions.map((f) => [`${f.name}(${f.args})`, {
      executableBy: [...f.executableBy].sort(), ownerBypassRls: f.ownerBypassRls, ownerSuper: f.ownerSuper, publicExecute: f.publicExecute, searchPathSet: f.searchPath === 'search_path=pg_catalog, public, pg_temp' }]));
    const wantFns = Object.fromEntries(Object.entries(policy.functions).map(([k, v]) => [k, { executableBy: [...v.executableBy].sort(), ownerBypassRls: v.ownerBypassRls, ownerSuper: v.ownerSuper, publicExecute: v.publicExecute, searchPathSet: v.searchPathSet }]));
    expect(Object.keys(liveFns).sort()).toEqual(Object.keys(wantFns).sort());
    for (const k of Object.keys(wantFns)) expect({ k, got: liveFns[k] }).toEqual({ k, got: wantFns[k] });

    // D2: the replaced tenants/organizations policies exist with their command
    for (const p of policy.policies) {
      expect(live.policies.some((x) => x.table === p.table && x.name === p.name && x.cmd === p.cmd)).toBe(true);
    }
  });

  // ── RLS-91 … RLS-100 (former stubs, now real) ────────────────────────────────
  test('RLS-91 a tenant reads only its own webhook_endpoints', async () => {
    const ids = await asApp(A, async (c) => (await c.query('SELECT id FROM webhook_endpoints')).rows.map((r) => r.id));
    expect(ids).toEqual([seed.whA]);
  });

  test("RLS-92 a tenant cannot read another tenant's webhook endpoint, even by id", async () => {
    expect(await asApp(A, (c) => count(c, 'SELECT count(*) AS n FROM webhook_endpoints WHERE id = $1', [seed.whB]))).toBe(0);
  });

  test("RLS-93 a tenant cannot update another tenant's endpoint (0 rows), ground truth unchanged", async () => {
    const r = await asApp(A, (c) => c.query("UPDATE webhook_endpoints SET url = 'https://evil.example' WHERE id = $1", [seed.whB]));
    expect(r.rowCount).toBe(0);
    expect((await owner.query('SELECT url FROM webhook_endpoints WHERE id = $1', [seed.whB])).rows[0].url).toBe(`https://hooks.example/${B}`);
  });

  test('RLS-94 INSERT with a tenant_id other than the context is rejected by the policy', async () => {
    await expect(asApp(B, (c) => c.query(
      "INSERT INTO webhook_endpoints (tenant_id, url, secret_enc, secret_iv, secret_tag) VALUES ($1, 'https://x.example', 'x', 'x', 'x')", [A])))
      .rejects.toThrow(/row-level security/);
  });

  test('RLS-95 without tenant context webhook_endpoints returns 0 rows (fail-closed); ground truth has 2', async () => {
    expect(await asApp(undefined, (c) => count(c, 'SELECT count(*) AS n FROM webhook_endpoints'))).toBe(0);
    expect(await count(owner, 'SELECT count(*) AS n FROM webhook_endpoints')).toBeGreaterThanOrEqual(2);
  });

  test('RLS-96 consent_records: platform-level (NULL tenant) rows are visible without context', async () => {
    expect(await asApp(undefined, (c) => count(c, "SELECT count(*) AS n FROM consent_records WHERE actor_id = 'w5pr-platform-actor'"))).toBe(1);
  });

  test('RLS-97 consent_records: tenant rows are NOT visible without context, nor to another tenant', async () => {
    expect(await asApp(undefined, (c) => count(c, "SELECT count(*) AS n FROM consent_records WHERE actor_id IN ('w5pr-actor-a','w5pr-actor-b')"))).toBe(0);
    expect(await asApp(A, (c) => count(c, "SELECT count(*) AS n FROM consent_records WHERE actor_id = 'w5pr-actor-b'"))).toBe(0);
    expect(await asApp(A, (c) => count(c, "SELECT count(*) AS n FROM consent_records WHERE actor_id = 'w5pr-actor-a'"))).toBe(1);
  });

  test('RLS-98 connection reuse: the tenant context of one transaction does not leak into the next', async () => {
    const c = await app.connect();
    try {
      expect(await asApp(A, (x) => count(x, 'SELECT count(*) AS n FROM webhook_endpoints'), c)).toBe(1);
      expect(await asApp(undefined, (x) => count(x, 'SELECT count(*) AS n FROM webhook_endpoints'), c)).toBe(0);
      expect((await c.query("SELECT coalesce(current_setting('qodiqa.tenant_id', true), '') AS t")).rows[0].t).toBe('');
    } finally { c.release(); }
  });

  test("RLS-99 a BYPASSRLS role sees every tenant's rows; qodiqa_mig (deployment owner) is BYPASSRLS, qodiqa_app is not", async () => {
    expect(await count(owner, 'SELECT count(*) AS n FROM webhook_endpoints WHERE tenant_id IN ($1, $2)', [A, B])).toBe(2);
    const roles = (await owner.query("SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname IN ('qodiqa_mig','qodiqa_app','qodiqa_system','qodiqa_reporting')")).rows;
    expect(Object.fromEntries(roles.map((r) => [r.rolname, r.rolbypassrls]))).toEqual({ qodiqa_mig: true, qodiqa_app: false, qodiqa_system: false, qodiqa_reporting: false });
  });

  test('RLS-100 audit_chain accepts an append without tenant context (INSERT policy WITH CHECK true)', async () => {
    const h = crypto.randomBytes(32).toString('hex');
    const r = await asApp(undefined, (c) => c.query(
      `INSERT INTO audit_chain (hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time, input_hash, signature, request_hash, policy_hash, verification_result)
       VALUES ($1, $2, '{}', $3, 'ALLOW', NOW(), '0', $4, 'sig', $4, $4, true)`,
      [h, '0'.repeat(64), `w5pr-${h.slice(0, 8)}`, h]));
    expect(r.rowCount).toBe(1);
  });

  // ── XT: cross-tenant probes as the request-serving role ──────────────────────
  test('XT-01 tenants / organizations: no app-role privilege; under RLS zero rows without context, own row only with it', async () => {
    await owner.query('INSERT INTO tenants (tenant_id, tenant_name) VALUES ($1, $1), ($2, $2)', [A, B]);
    await owner.query("INSERT INTO organizations (organization_id, organization_name) VALUES ('w5pr-org', 'w5pr-org')");
    // (a) the request-serving role holds no privilege at all (file stores stay authoritative until)
    await expect(asApp(undefined, (c) => c.query('SELECT 1 FROM tenants'))).rejects.toThrow(/permission denied/);
    // (b) the policies themselves, through a SELECT-only non-BYPASSRLS role
    const q = async (tenant, sql) => {
      const c = await probe.connect();
      try {
        await c.query('BEGIN');
        if (tenant !== undefined) await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [tenant]);
        const r = await c.query(sql); await c.query('COMMIT'); return r.rows;
      } finally { c.release(); }
    };
    expect(await q(undefined, 'SELECT tenant_id FROM tenants')).toEqual([]);           // earlier: every row
    expect(await q('', 'SELECT tenant_id FROM tenants')).toEqual([]);                  // empty GUC is no context
    expect((await q(A, 'SELECT tenant_id FROM tenants')).map((r) => r.tenant_id)).toEqual([A]);
    expect(await q(undefined, 'SELECT organization_id FROM organizations')).toEqual([]); // earlier: every row
    // ground truth: both tenants exist
    expect(await count(owner, 'SELECT count(*) AS n FROM tenants WHERE tenant_id IN ($1, $2)', [A, B])).toBe(2);
  });

  test('XT-02 qodiqa_app cannot UPDATE or DELETE platform_audit_events except placing a legal hold', async () => {
    const id = (await owner.query(
      "INSERT INTO platform_audit_events (occurred_at, event_type, event_category, severity, component, payload) VALUES (NOW(), 'W5PR', 'SECURITY', 'INFO', 'w5pr', '{}') RETURNING id")).rows[0].id;
    await expect(asApp(undefined, (c) => c.query('DELETE FROM platform_audit_events WHERE id = $1', [id]))).rejects.toThrow(/permission denied/);
    await expect(asApp(undefined, (c) => c.query("UPDATE platform_audit_events SET event_type = 'X' WHERE id = $1", [id]))).rejects.toThrow(/permission denied/);
    const hold = await asApp(undefined, (c) => c.query('UPDATE platform_audit_events SET legal_hold = true WHERE id = $1', [id]));
    expect(hold.rowCount).toBe(1);
  });

  test("XT-03 subject_pseudonym_keys: a tenant sees only its own subjects' keys", async () => {
    await owner.query("INSERT INTO subject_pseudonym_keys (tenant_id, actor_id, key_enc) VALUES ($1, 'w5pr-s', '{}'), ($2, 'w5pr-s', '{}')", [A, B]);
    expect(await asApp(A, (c) => count(c, "SELECT count(*) AS n FROM subject_pseudonym_keys WHERE actor_id = 'w5pr-s'"))).toBe(1);
    expect(await asApp(undefined, (c) => count(c, "SELECT count(*) AS n FROM subject_pseudonym_keys WHERE actor_id = 'w5pr-s'"))).toBe(0);
    await expect(asApp(A, (c) => c.query("INSERT INTO subject_pseudonym_keys (tenant_id, actor_id, key_enc) VALUES ($1, 'w5pr-x', '{}')", [B])))
      .rejects.toThrow(/row-level security/);
  });

  test('XT-04 qodiqa_app holds no privilege on the erasure ledger and cannot run any cross-tenant DEFINER function', async () => {
    await expect(asApp(undefined, (c) => c.query('SELECT 1 FROM dsr_erasure_ledger'))).rejects.toThrow(/permission denied/);
    const fns = (await owner.query(`SELECT p.oid::regprocedure::text AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.prosecdef AND has_function_privilege('qodiqa_app', p.oid, 'EXECUTE')`)).rows.map((r) => r.sig).sort();
    // only the minimized public functions (verification fields, no tenant metadata) and the hash-only range reader
    expect(fns).toEqual([
      'qodiqa_evidence_public_lookup(character varying,text)',
      'qodiqa_transparency_log_fetch_hashes_in_range(bigint,bigint)',
      'qodiqa_transparency_public_entry(uuid)',
      'qodiqa_transparency_public_entry_by_hash(character)',
      'qodiqa_transparency_public_hashes_from_id(bigint,integer)',
      'qodiqa_transparency_public_list(text,text,text,timestamp with time zone,timestamp with time zone,integer,integer,boolean)',
    ]);
  });

  // ── LB: lawful basis (migration 064) ─────────────────────────────────────────
  test('LB-01 pre-existing / basis-less rows are LEGACY_UNSPECIFIED, never auto-labelled', async () => {
    const r = (await owner.query("SELECT lawful_basis, lawful_basis_status FROM consent_records WHERE actor_id = 'w5pr-platform-actor'")).rows[0];
    expect(r).toEqual({ lawful_basis: null, lawful_basis_status: 'LEGACY_UNSPECIFIED' });
  });

  test('LB-02 SPECIFIED requires a basis and a purpose; the enums and the purpose-code pattern are enforced', async () => {
    const ins = (cols, vals) => owner.query(`INSERT INTO consent_records (actor_id, action, state, granted_by, ${cols}) VALUES ('w5pr-lb-' || md5(random()::text), 'lb', 'ACTIVE', 'op', ${vals})`);
    await expect(ins('lawful_basis_status', "'SPECIFIED'")).rejects.toThrow(/lawful_basis_status_check/);
    await expect(ins('lawful_basis, lawful_basis_status', "'consent', 'SPECIFIED'")).rejects.toThrow(/lawful_basis_status_check/);
    await expect(ins('lawful_basis, purpose, lawful_basis_status', "'implied', 'p', 'SPECIFIED'")).rejects.toThrow(/lawful_basis_check/);
    await expect(ins('lawful_basis, purpose, purpose_code, lawful_basis_status', "'consent', 'p', 'Bad Code', 'SPECIFIED'")).rejects.toThrow(/purpose_code_check/);
    await expect(ins('lawful_basis, purpose, special_category_condition, lawful_basis_status', "'consent', 'p', 'art9_2_z', 'SPECIFIED'")).rejects.toThrow(/special_category_condition_check/);
    await expect(ins('lawful_basis, purpose, purpose_code, special_category_condition, lawful_basis_status', "'contract', 'Service', 'svc.core', 'art9_2_h', 'SPECIFIED'")).resolves.toBeDefined();
  });

  test('LB-03 the biometric and medical scopes are marked GDPR Art. 9(1) special categories', async () => {
    const rows = (await owner.query('SELECT scope_name FROM consent_scopes WHERE special_category ORDER BY 1')).rows.map((r) => r.scope_name);
    expect(rows).toEqual(['biometric', 'medical']);
  });
});
