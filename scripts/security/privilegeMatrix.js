#!/usr/bin/env node
'use strict';
/**
 * step 1 — PostgreSQL privilege matrix, generated from the catalog.
 *
 * Library (used by the step-8 policy test):
 *   collectMatrix(client) → a deterministic object describing
 *     roles (attributes, memberships) · every relation's owner, RLS enabled/FORCE,
 *     effective table privileges per qodiqa_* role (has_table_privilege: owner,
 *     grants and inherited membership included) and PUBLIC grants · column-only
 *     UPDATE grants · every RLS policy's text · every SECURITY DEFINER function
 *     with owner, the owner's rolbypassrls/rolsuper, search_path config and who can
 *     EXECUTE it (per role + PUBLIC) · non-internal triggers per table.
 *   renderMarkdown(matrix, { title, source }) · diffMatrices(a, b)
 *
 * CLI (default): builds a DISPOSABLE database with the full migration chain and
 * matrices it, then matrices LIVE read-only and cross-checks the two.
 *   - disposable DB: qodiqa_w5pm_<pid>_<hex>, created by qodiqa_test, migrated by
 *     the SAME role (PG15+: only the creator/owner has CREATE on public),
 *     ledgered in %TEMP%/qodiqa-w5-ledger.jsonl BEFORE creation, dropped in
 * finally and verified gone;
 *   - LIVE (`qodiqa`): qodiqa_test, `BEGIN READ ONLY`, catalog reads only.
 * Outputs:, privilege-matrix-disposable.json,
 *   privilege-matrix-live.json. Credentials come from .env into a private object,
 *   never printed and never merged into process.env.
 *   Flags: --no-live (skip LIVE), --out <dir>.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const REPO = path.join(__dirname, '..', '..');
const PRIVS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'];

async function collectMatrix(c) {
  const q = async (sql, p) => (await c.query(sql, p)).rows;
  const roles = await q(`
    SELECT r.rolname AS name, r.rolsuper AS super, r.rolinherit AS inherit, r.rolcreaterole AS createrole,
           r.rolcreatedb AS createdb, r.rolcanlogin AS login, r.rolbypassrls AS bypassrls,
           COALESCE((SELECT array_agg(g.rolname::text ORDER BY g.rolname) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid WHERE m.member = r.oid), '{}') AS member_of
      FROM pg_roles r WHERE r.rolname LIKE 'qodiqa%' ORDER BY r.rolname`);
  const roleNames = roles.map((r) => r.name);

  const rels = await q(`
    SELECT c.oid, n.nspname AS schema, c.relname AS name, c.relkind AS kind, pg_get_userbyid(c.relowner) AS owner,
           c.relrowsecurity AS rls, c.relforcerowsecurity AS force_rls,
           COALESCE((SELECT array_agg(DISTINCT a.privilege_type ORDER BY a.privilege_type) FROM aclexplode(c.relacl) a WHERE a.grantee = 0), '{}') AS public_privs
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r','p','v','m') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
     ORDER BY n.nspname, c.relname`);
  const tables = [];
  for (const t of rels) {
    const privs = {}; const colOnlyUpdate = [];
    for (const r of roleNames) {
      const row = (await q(`SELECT ${PRIVS.map((p, i) => `has_table_privilege($1, $2::oid, '${p}') AS p${i}`).join(', ')},
                                   has_any_column_privilege($1, $2::oid, 'UPDATE') AS colupd`, [r, t.oid]))[0];
      privs[r] = PRIVS.filter((_, i) => row[`p${i}`]);
      if (row.colupd && !privs[r].includes('UPDATE')) colOnlyUpdate.push(r);
    }
    const cols = (await q(`SELECT attname FROM pg_attribute WHERE attrelid = $1 AND attnum > 0 AND NOT attisdropped ORDER BY attnum`, [t.oid])).map((x) => x.attname);
    const triggers = (await q(`SELECT tgname AS name, pg_get_triggerdef(oid) AS def FROM pg_trigger WHERE tgrelid = $1 AND NOT tgisinternal ORDER BY tgname`, [t.oid]));
    tables.push({ schema: t.schema, name: t.name, kind: t.kind, owner: t.owner, rls: t.rls, forceRls: t.force_rls, publicPrivs: t.public_privs,
      privs, columnOnlyUpdate: colOnlyUpdate,
      tenantColumns: cols.filter((x) => /^(tenant_id|organization_id|org_id)$/.test(x)), actorColumns: cols.filter((x) => /actor_id|user_id|subject_id|requested_by|approved_by/.test(x)),
      triggers });
  }

  const policies = await q(`SELECT schemaname AS schema, tablename AS table, policyname AS name, permissive, roles::text[] AS roles, cmd, qual, with_check
                              FROM pg_policies ORDER BY schemaname, tablename, policyname`);

  const fnRows = await q(`
    SELECT p.oid, n.nspname AS schema, p.proname AS name, pg_get_function_identity_arguments(p.oid) AS args,
           pg_get_userbyid(p.proowner) AS owner, o.rolbypassrls AS owner_bypassrls, o.rolsuper AS owner_super,
           p.proconfig AS config, p.prosrc AS src,
           (p.proacl IS NULL) AS default_acl,
           COALESCE((SELECT bool_or(a.privilege_type = 'EXECUTE') FROM aclexplode(p.proacl) a WHERE a.grantee = 0), false) AS public_exec_grant
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles o ON o.oid = p.proowner
     WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
     ORDER BY n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)`);
  const tableNames = tables.map((t) => t.name).sort((a, b) => b.length - a.length);
  const definerFunctions = [];
  for (const f of fnRows) {
    const execBy = [];
    for (const r of roleNames) if ((await q(`SELECT has_function_privilege($1, $2::oid, 'EXECUTE') AS x`, [r, f.oid]))[0].x) execBy.push(r);
    const src = f.src || '';
    const tablesReferenced = [...new Set(tableNames.filter((t) => new RegExp(`\\b${t}\\b`).test(src)))].sort();
    definerFunctions.push({ schema: f.schema, name: f.name, args: f.args, owner: f.owner, ownerBypassRls: f.owner_bypassrls, ownerSuper: f.owner_super,
      searchPath: (f.config || []).filter((x) => /^search_path=/.test(x)).join(',') || null,
      executableBy: execBy, publicExecute: f.default_acl || f.public_exec_grant,
      readsTenantContext: /current_setting\s*\(\s*'[a-z_]+\.[a-z_]*tenant/i.test(src), tablesReferenced,
      srcSha256: crypto.createHash('sha256').update(src).digest('hex').slice(0, 16) });
  }

  const tenantGucs = [...new Set(policies.flatMap((p) => `${p.qual || ''} ${p.with_check || ''}`.match(/current_setting\('([^']+)'/g) || []).map((x) => x.replace(/current_setting\('|'$/g, '')))].sort();
  return { roles, tables, policies, definerFunctions, tenantGucs,
    appWritable: tables.filter((t) => (t.privs.qodiqa_app || []).some((p) => ['UPDATE', 'DELETE', 'TRUNCATE'].includes(p)) || t.columnOnlyUpdate.includes('qodiqa_app'))
      .map((t) => ({ table: t.name, ops: (t.privs.qodiqa_app || []).filter((p) => ['UPDATE', 'DELETE', 'TRUNCATE'].includes(p)).concat(t.columnOnlyUpdate.includes('qodiqa_app') ? ['UPDATE(columns)'] : []), rls: t.rls, forceRls: t.forceRls, triggers: t.triggers.map((x) => x.name) })) };
}

// ── diff (by stable keys) ────────────────────────────────────────────────────
function diffMatrices(a, b) {
  const keyed = (arr, k) => new Map(arr.map((x) => [k(x), x]));
  const out = {};
  const sets = {
    roles: [(x) => x.name], tables: [(x) => `${x.schema}.${x.name}`], policies: [(x) => `${x.schema}.${x.table}.${x.name}`],
    definerFunctions: [(x) => `${x.schema}.${x.name}(${x.args})`],
  };
  for (const [s, [k]] of Object.entries(sets)) {
    const A = keyed(a[s], k); const B = keyed(b[s], k);
    const onlyA = [...A.keys()].filter((x) => !B.has(x)).sort();
    const onlyB = [...B.keys()].filter((x) => !A.has(x)).sort();
    const changed = [];
    for (const key of [...A.keys()].filter((x) => B.has(x)).sort()) {
      const x = A.get(key); const y = B.get(key);
      const fields = Object.keys({ ...x, ...y }).filter((f) => JSON.stringify(x[f]) !== JSON.stringify(y[f]));
      if (fields.length) changed.push({ key, fields: Object.fromEntries(fields.map((f) => [f, { a: x[f], b: y[f] }])) });
    }
    out[s] = { onlyA, onlyB, changed };
  }
  return out;
}

// ── markdown ─────────────────────────────────────────────────────────────────
const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
function renderMarkdown(m, { title, source }) {
  const L = [`# ${title}`, '', source, ''];
  L.push('## 1. Roles', '', '| role | login | super | bypassrls | createdb | createrole | inherit | member of |', '|---|---|---|---|---|---|---|---|');
  for (const r of m.roles) L.push(`| ${r.name} | ${r.login} | ${r.super} | **${r.bypassrls}** | ${r.createdb} | ${r.createrole} | ${r.inherit} | ${r.member_of.join(', ') || '—'} |`);
  const roleNames = m.roles.map((r) => r.name);
  const ab = (ps) => (ps.length === 0 ? '—' : ps.length === 5 ? 'ALL' : ps.map((p) => p[0]).join(''));
  L.push('', '## 2. Relations: owner, RLS, effective privileges', '',
    'Privileges are effective (`has_table_privilege`: ownership, grants and inherited membership). Codes: S=SELECT I=INSERT U=UPDATE D=DELETE T=TRUNCATE, ALL=all five. `u*` = UPDATE on some columns only. Kind: r table, p partitioned, v view, m matview.', '',
    `| relation | kind | owner | RLS | FORCE | ${roleNames.join(' | ')} | PUBLIC | tenant cols | actor cols | triggers |`, `|---|---|---|---|---|${roleNames.map(() => '---').join('|')}|---|---|---|---|`);
  for (const t of m.tables) {
    L.push(`| ${t.name} | ${t.kind} | ${t.owner} | ${t.rls ? 'on' : '**off**'} | ${t.forceRls ? 'on' : 'off'} | ${roleNames.map((r) => ab(t.privs[r] || []) + (t.columnOnlyUpdate.includes(r) ? ' u*' : '')).join(' | ')} | ${t.publicPrivs.join(',') || '—'} | ${t.tenantColumns.join(', ') || '—'} | ${t.actorColumns.join(', ') || '—'} | ${t.triggers.map((x) => x.name).join(', ') || '—'} |`);
  }
  L.push('', '## 3. Tables the app role (qodiqa_app) can UPDATE, DELETE or TRUNCATE', '', '| table | operations | RLS | FORCE | triggers |', '|---|---|---|---|---|');
  for (const a of m.appWritable) L.push(`| ${a.table} | ${a.ops.join(', ')} | ${a.rls ? 'on' : 'off'} | ${a.forceRls ? 'on' : 'off'} | ${a.triggers.join(', ') || '—'} |`);
  L.push('', `## 4. SECURITY DEFINER functions (${m.definerFunctions.length})`, '',
    'Bypass depends on the OWNER\'s rolbypassrls (not inherited). "tenant ctx" = the body reads a `<ns>.*tenant*` setting such as `qodiqa.tenant_id` (heuristic, source text). Tables = tables named in the body.', '',
    `| function | owner | owner bypassrls | owner super | search_path | EXECUTE by | PUBLIC exec | tenant ctx | tables referenced |`, '|---|---|---|---|---|---|---|---|---|');
  for (const f of m.definerFunctions) L.push(`| ${f.name}(${esc(f.args)}) | ${f.owner} | **${f.ownerBypassRls}** | ${f.ownerSuper} | ${esc(f.searchPath) || '**unset**'} | ${f.executableBy.join(', ') || '—'} | ${f.publicExecute ? '**yes**' : 'no'} | ${f.readsTenantContext ? 'yes' : '**no**'} | ${f.tablesReferenced.join(', ') || '—'} |`);
  L.push('', `## 5. RLS policies (${m.policies.length}); tenant GUCs used: ${m.tenantGucs.map((g) => `\`${g}\``).join(', ') || '—'}`, '', '| table | policy | permissive | roles | cmd | USING | WITH CHECK |', '|---|---|---|---|---|---|---|');
  for (const p of m.policies) L.push(`| ${p.table} | ${p.name} | ${p.permissive} | ${p.roles.join(',')} | ${p.cmd} | \`${esc(p.qual) || '—'}\` | \`${esc(p.with_check) || '—'}\` |`);
  return L.join('\n') + '\n';
}

// Ownership-normalised view: the two BYPASSRLS maintenance roles (qodiqa_test creates/migrates disposable DBs,
// qodiqa_mig owns LIVE objects after migration 055) differ only because the owner holds ALL. Removing the owner
// field and those two roles' entries leaves exactly what the application roles can do.
const OWNER_ROLES = ['qodiqa_test', 'qodiqa_mig'];
function normalizeOwnership(m) {
  // (hosted-CI rehearsal): an object's privileges held BY ITS OWNER are ownership, not policy — strip the
  // object's actual owner as well as the known migrating identities, so a cluster migrated by a differently named
  // superuser (a CI service's own admin role) compares like the reference one. Any non-owner grantee still counts.
  // (migration 079): definer functions are no longer owned by the migrating identity, so a SUPERUSER migrator (CI's
  // service role, the disposable cluster's admin) is no longer stripped as "the owner". A superuser holds every
  // privilege by definition — that is not policy either, so superuser roles are stripped too. Non-superuser grantees
  // still count, and the owner's own superuser status is compared separately (ownerSuper).
  const supers = new Set((m.roles || []).filter((r) => r.super).map((r) => r.name));
  const isOwner = (owner) => (r) => OWNER_ROLES.includes(r) || supers.has(r) || (owner && r === owner);
  const strip = (o, owner) => Object.fromEntries(Object.entries(o).filter(([k]) => !isOwner(owner)(k)));
  return { ...m,
    tables: m.tables.map(({ owner, ...t }) => ({ ...t, privs: strip(t.privs, owner), columnOnlyUpdate: t.columnOnlyUpdate.filter((r) => !isOwner(owner)(r)) })),
    definerFunctions: m.definerFunctions.map(({ owner, ...f }) => ({ ...f, executableBy: f.executableBy.filter((r) => !isOwner(owner)(r)) })) };
}

module.exports = { collectMatrix, diffMatrices, normalizeOwnership, renderMarkdown, PRIVS, OWNER_ROLES };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  (async () => {
    const { Client, Pool } = require('pg');
    const E = require('dotenv').parse(fs.readFileSync(path.join(REPO, '.env')));
    const argv = process.argv.slice(2);
    const OUT = argv.includes('--out') ? path.resolve(argv[argv.indexOf('--out') + 1]) : path.join(REPO, 'evidence', 'w5');
    fs.mkdirSync(OUT, { recursive: true });
    const conn = { host: E.QODIQA_PG_HOST || 'localhost', port: parseInt(E.QODIQA_PG_PORT || '5432', 10), user: E.QODIQA_PG_TEST_USER, password: E.QODIQA_PG_TEST_PASSWORD };
    const LEDGER = path.join(os.tmpdir(), 'qodiqa-w5-ledger.jsonl');
    const git = (...a) => require('child_process').execFileSync('git', a, { cwd: REPO, encoding: 'utf8' }).trim();
    const sha = git('rev-parse', 'HEAD');
    const migrationsOnDisk = fs.readdirSync(path.join(REPO, 'src/infra/postgres/migrations')).filter((f) => /^\d+_.*\.sql$/.test(f)).sort();

    const db = `qodiqa_w5pm_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
    fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event: 'planned', by: 'scripts/security/privilegeMatrix.js' }) + '\n');
    let disp; let dropped = null;
    const m = new Client({ ...conn, database: 'postgres' }); await m.connect();
    try { await m.query(`CREATE DATABASE "${db}"`); } finally { await m.end(); }
    fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event: 'created' }) + '\n');
    try {
      const pool = new Pool({ ...conn, database: db });
      const logger = require(path.join(REPO, 'services/logger')); const _emit = logger.emit; logger.emit = () => {};
      try { await require(path.join(REPO, 'src/infra/postgres/migrate')).runMigrations({ pool }); } finally { await pool.end(); logger.emit = _emit; }
      const c = new Client({ ...conn, database: db }); await c.connect();
      try {
        const applied = (await c.query('SELECT max(version)::int AS v, count(*)::int AS n FROM qodiqa_migrations')).rows[0];
        disp = { applied, matrix: await collectMatrix(c) };
      } finally { await c.end(); }
    } finally {
      const d = new Client({ ...conn, database: 'postgres' }); await d.connect();
      try {
        try { await d.query(`DROP DATABASE IF EXISTS "${db}"`); } catch { await d.query(`DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`); }
        dropped = (await d.query('SELECT 1 FROM pg_database WHERE datname = $1', [db])).rowCount === 0;
        fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event: dropped ? 'dropped' : 'DROP-FAILED' }) + '\n');
      } finally { await d.end(); }
    }

    let live = null;
    if (!argv.includes('--no-live')) {
      const c = new Client({ ...conn, database: 'qodiqa' }); await c.connect();
      try {
        await c.query('BEGIN READ ONLY');
        const applied = (await c.query('SELECT max(version)::int AS v, count(*)::int AS n FROM qodiqa_migrations')).rows[0];
        live = { applied, matrix: await collectMatrix(c) };
        await c.query('ROLLBACK');
      } finally { await c.end(); }
    }

    fs.writeFileSync(path.join(OUT, 'privilege-matrix-disposable.json'), JSON.stringify({ sha, db, dropped, ...disp }, null, 1));
    if (live) fs.writeFileSync(path.join(OUT, 'privilege-matrix-live.json'), JSON.stringify({ sha, db: 'qodiqa', ...live }, null, 1));

    const md = [renderMarkdown(disp.matrix, {
      title: 'Current privilege matrix (generated)',
      source: `Generated by \`scripts/security/privilegeMatrix.js\` at \`${sha}\` from the catalog of a **disposable** database (\`${db}\`, dropped: ${dropped}) with the **full migration chain** (${disp.applied.n} migrations, latest ${disp.applied.v}; ${migrationsOnDisk.length} files on disk), created and migrated by \`qodiqa_test\`. Raw data: \`privilege-matrix-disposable.json\`.`,
    }).trimEnd()];
    if (live) {
      const diff = diffMatrices(normalizeOwnership(disp.matrix), normalizeOwnership(live.matrix));
      const rawDiff = diffMatrices(disp.matrix, live.matrix);
      const ownerChanges = (s) => rawDiff[s].changed.filter((c) => c.fields.owner).map((c) => `\`${c.key.replace(/^public\./, '')}\``);
      md.push('', '## 6. Cross-check against LIVE (`qodiqa`, read-only as qodiqa_test)', '',
        `LIVE has ${live.applied.n} migrations, latest ${live.applied.v}; this disposable DB has ${disp.applied.n}, latest ${disp.applied.v}. "A" = disposable, "B" = LIVE. Raw data: \`privilege-matrix-live.json\`, \`privilege-matrix-crosscheck.json\` (raw and normalised diffs).`, '',
        `**Ownership.** The owner differs on ${ownerChanges('tables').length} relations and ${ownerChanges('definerFunctions').length} DEFINER functions: \`qodiqa_test\` on the disposable DB (it creates and migrates the DB, PG15+) vs \`qodiqa_mig\` on LIVE. Both are BYPASSRLS, so every DEFINER function bypasses RLS identically in both. The comparison below removes the owner field and these two roles' entries (the owner holds ALL), and compares exactly what \`qodiqa_app\`, \`qodiqa_read\` and \`qodiqa_retention\` can do, plus RLS flags, policies and triggers.`, '',
        `- owner differs (relations): ${ownerChanges('tables').join(', ') || '—'}`,
        `- owner differs (functions): ${ownerChanges('definerFunctions').join(', ') || '—'}`, '',
        '### Residual differences after ownership normalisation', '');
      for (const [s, d] of Object.entries(diff)) {
        md.push(`#### ${s}: only disposable ${d.onlyA.length} · only LIVE ${d.onlyB.length} · differing ${d.changed.length}`, '');
        if (d.onlyA.length) md.push(`- only in disposable: ${d.onlyA.map((x) => `\`${x}\``).join(', ')}`);
        if (d.onlyB.length) md.push(`- only in LIVE: ${d.onlyB.map((x) => `\`${x}\``).join(', ')}`);
        for (const ch of d.changed) md.push(`- \`${ch.key}\`: ${Object.entries(ch.fields).map(([f, v]) => `${f} ${esc(JSON.stringify(v.a))} → ${esc(JSON.stringify(v.b))}`).join('; ')}`);
        md.push('');
      }
      fs.writeFileSync(path.join(OUT, 'privilege-matrix-crosscheck.json'), JSON.stringify({ normalised: diff, raw: rawDiff }, null, 1));
    }
    fs.writeFileSync(path.join(OUT, 'PRIVILEGE-MATRIX-CURRENT.md'), md.join('\n') + '\n');
    console.log(JSON.stringify({ sha, disposable: { db, dropped, ...disp.applied, tables: disp.matrix.tables.length, definer: disp.matrix.definerFunctions.length, policies: disp.matrix.policies.length, appWritable: disp.matrix.appWritable.length },
      live: live && { ...live.applied, tables: live.matrix.tables.length, definer: live.matrix.definerFunctions.length, policies: live.matrix.policies.length, appWritable: live.matrix.appWritable.length } }));
  })().catch((e) => { console.error('privilegeMatrix error:', e.stack || e.message); process.exit(1); });
}
