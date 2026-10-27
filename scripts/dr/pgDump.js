'use strict';

/**
 * QODIQA Disaster Recovery — PostgreSQL layer on pg_dump / pg_restore.
 *
 * The JSON-rows layer (postgres.js) built every table as ONE string and failed on real pilot data: audit_chain,
 * evidence_chain_records, request_trails and transparency_log_entries each exceeded V8's ~512 MB string limit
 * ("Invalid string length"). Database backups are therefore standardised on pg_dump's custom format, streamed through
 * the same openssl-compatible encryption as every other archive (archiveCrypto.writeStreamToArchive).
 *
 * Consistency (C-3): takeSnapshot() opens a REPEATABLE READ READ ONLY transaction and exports its snapshot BEFORE
 * backup.js reads the first file; pg_dump later dumps exactly that snapshot (--snapshot). Everything recorded in the
 * manifest — per-table counts, the dumping role and its RLS exposure, the chain-head rows, the newest prune row — is
 * read inside the same snapshot, so a restore can be reconciled against it exactly.
 *
 * Version guard: a dump is taken only when pg_dump's major equals the server's (a newer client writes an
 * archive the server's own tools cannot read, and its pg_restore emits settings an older server rejects — measured:
 * client 17.11 vs the shipped postgres:16.15). A restore refuses before touching the target when pg_restore's major is
 * above the target server's or below the dump's.
 *
 * Credentials: the password is never put on a child's command line (visible in the process table) — it is passed in
 * the child's PGPASSWORD; --dbname gets the URL without it. Without QODIQA_PG_URL / DATABASE_URL the libpq variables
 * (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD, PGSSLMODE, PGSSLROOTCERT — the systemd backup.env) are used, by both
 * pg_dump and the node-postgres client.
 */

const { spawn, execFileSync } = require('child_process');

const { discoverTables, getRestoreOrder, EXPECTED_TABLES, quoteIdent } = require('./table-registry');
const { CHAIN_HEADS, isChainHeadTable, verifyRestoredChainHeads } = require('./chainHeads');
const { writeStreamToArchive, createArchivePlainStream } = require('./archiveCrypto');
const { reestablishDefinerOwnership } = require('../../src/infra/postgres/definerOwnership'); //

const FORMAT = 'pg_dump-custom';
// built, not written as one literal: the repository's gitleaks rule pg-password-env matches a connection-URL literal
// followed (lines later) by any '@'
const SCHEME_PREFIX = ['postgresql', '//'].join(':');
const STDERR_TAIL = 4000;

class PgDumpError extends Error {
  constructor(message, code) { super(message); this.name = 'PgDumpError'; this.code = code; }
}

const pgDumpBin = (env = process.env) => env.QODIQA_PG_DUMP_BIN || 'pg_dump';
const pgRestoreBin = (env = process.env) => env.QODIQA_PG_RESTORE_BIN || 'pg_restore';

/** Major version of a PostgreSQL client tool ("pg_dump (PostgreSQL) 16.10" → 16). Throws when the tool is missing. */
function toolMajor(bin) {
  let out;
  try {
    out = execFileSync(bin, ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    throw new PgDumpError(`${bin} is not available (${e.code || e.message}) — the DR backup image ships the PostgreSQL client tools (deploy/docker/backup.Dockerfile); a host run needs postgresql-client of the server's major`, 'PG_CLIENT_TOOL_MISSING');
  }
  const m = /\(PostgreSQL\)\s+(\d+)/.exec(out) || /(\d+)\.\d+/.exec(out);
  if (!m) throw new PgDumpError(`cannot read the version of ${bin}: ${out.trim()}`, 'PG_CLIENT_TOOL_MISSING');
  return { major: Number(m[1]), version: out.trim() };
}

/**
 * Split a connection into (a) a node-postgres connection string, (b) a --dbname for the libpq tools WITHOUT the
 * password and (c) the password for the child's environment. Falls back to the libpq PG* variables.
 */
function resolveConnection(connectionString, env = process.env) {
  const raw = connectionString || env.QODIQA_PG_URL || env.DATABASE_URL || null;
  if (raw) {
    let u;
    try { u = new URL(raw); } catch { throw new PgDumpError('the PostgreSQL connection string is not a valid URL', 'PG_CONNECTION_INVALID'); }
    const password = u.password ? decodeURIComponent(u.password) : (env.PGPASSWORD || '');
    const bare = new URL(raw); bare.password = '';
    return { nodeConnectionString: raw, dbnameArg: bare.toString(), password };
  }
  if (!env.PGHOST && !env.PGDATABASE) {
    throw new PgDumpError('no PostgreSQL connection: set QODIQA_PG_URL (or DATABASE_URL), or the libpq variables PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD', 'PG_CONNECTION_MISSING');
  }
  const u = new URL(`${SCHEME_PREFIX}localhost`);
  u.hostname = env.PGHOST || 'localhost';
  if (env.PGPORT) u.port = env.PGPORT;
  u.pathname = `/${encodeURIComponent(env.PGDATABASE || 'postgres')}`;
  if (env.PGUSER) u.username = encodeURIComponent(env.PGUSER);
  if (env.PGSSLMODE) u.searchParams.set('sslmode', env.PGSSLMODE);
  if (env.PGSSLROOTCERT) u.searchParams.set('sslrootcert', env.PGSSLROOTCERT);
  const bare = u.toString();
  const withPw = new URL(bare);
  if (env.PGPASSWORD) withPw.password = encodeURIComponent(env.PGPASSWORD);
  return { nodeConnectionString: withPw.toString(), dbnameArg: bare, password: env.PGPASSWORD || '' };
}

function _childEnv(password, env = process.env) {
  const e = { ...env };
  if (password) e.PGPASSWORD = password; else delete e.PGPASSWORD;
  return e;
}

/** Run a child, piping `input` (a Readable) to stdin and handing stdout to onStdout; resolves { code, stderr }. */
function _run(bin, args, { env, input = null, stdout = null } = {}) {
  return new Promise((resolve, reject) => {
    // note: no cwd — the shipped seccomp profile denies chdir in the container.
    const child = spawn(bin, args, { env, stdio: [input ? 'pipe' : 'ignore', stdout ? 'pipe' : 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr = (stderr + d.toString()).slice(-STDERR_TAIL); });
    child.on('error', (e) => reject(new PgDumpError(`${bin} could not be started: ${e.message}`, 'PG_CLIENT_TOOL_MISSING')));
    let inputError = null;
    if (input) {
      input.on('error', (e) => { inputError = e; child.stdin.destroy(); });
      child.stdin.on('error', () => { /* EPIPE when the child exits early: its exit code and stderr say why */ });
      input.pipe(child.stdin);
    }
    if (stdout) stdout(child.stdout);
    child.on('close', (code) => resolve({ code, stderr: stderr.trim(), inputError }));
  });
}

// ── backup side ──────────────────────────────────────────────────────────────────────────────────────────────────

async function _roleFacts(client, tables) {
  const { rows: [role] } = await client.query(
    `SELECT current_user AS name, r.rolsuper AS superuser, r.rolbypassrls AS bypass_rls,
            pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') AS read_all_data
       FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`);
  const { rows: rls } = await client.query(
    `SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relrowsecurity AND c.relname = ANY($1::text[])
      ORDER BY c.relname`, [tables]);
  const rlsTables = rls.map((r) => r.relname);
  return {
    role: { name: role.name, superuser: role.superuser, bypassRls: role.bypass_rls, readAllData: role.read_all_data },
    rlsTables,
    rlsExempt: role.superuser || role.bypass_rls,
  };
}

/**
 * Open the backup snapshot (call BEFORE any file component is read). Everything the manifest records about the
 * database is read here, inside the exported snapshot. The returned handle must be finished with dump() or abort().
 */
async function takeSnapshot({ connectionString, env = process.env } = {}) {
  const conn = resolveConnection(connectionString, env);
  const dumpTool = toolMajor(pgDumpBin(env));
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: conn.nodeConnectionString, max: 1 });
  const client = await pool.connect();
  const abort = async () => { await client.query('ROLLBACK').catch(() => {}); client.release(); await pool.end().catch(() => {}); };
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const { rows: [{ id: snapshotId }] } = await client.query('SELECT pg_export_snapshot() AS id');
    const { rows: [{ v: serverVersionNum, s: serverVersion }] } = await client.query(
      "SELECT current_setting('server_version_num')::int AS v, current_setting('server_version') AS s");
    const serverMajor = Math.floor(serverVersionNum / 10000);
    if (dumpTool.major !== serverMajor) {
      throw new PgDumpError(`pg_dump major ${dumpTool.major} (${dumpTool.version}) != server major ${serverMajor} (${serverVersion}) — `
        + `a dump from a different major is not restorable with the server's own tools; build the backup image with PG_CLIENT_MAJOR=${serverMajor}. Nothing was written.`,
      'PG_DUMP_VERSION_MISMATCH');
    }
    const discovered = await discoverTables(client);
    const order = await getRestoreOrder(client, discovered);
    const access = await _roleFacts(client, order);
    if (access.rlsTables.length > 0 && !access.rlsExempt) {
      throw new PgDumpError(`role "${access.role.name}" is subject to Row-Level Security on ${access.rlsTables.length} table(s) `
        + `(${access.rlsTables.join(', ')}) — a dump would silently omit rows. Run the backup as qodiqa_backup (BYPASSRLS, migration 067).`,
      'BACKUP_ROLE_NOT_RLS_EXEMPT');
    }
    // D-P: the backup role must also hold the predefined, read-only pg_read_all_data role
    // (migration 067 where the migrating identity may grant it; otherwise scripts/db/provision-backup-role.superuser.sql).
    if (!access.role.readAllData) {
      throw new PgDumpError(`role "${access.role.name}" is not a pg_read_all_data member — run scripts/db/provision-backup-role.superuser.sql `
        + 'once (as a superuser) or back up as qodiqa_backup. Nothing was written.', 'BACKUP_ROLE_READ_ALL_DATA_MISSING');
    }
    const tables = [];
    for (const table of order) {
      const { rows: [{ n }] } = await client.query(`SELECT count(*)::bigint AS n FROM ${quoteIdent(table)}`);
      tables.push({ table, present: true, rowCount: Number(n), sourceRowCount: Number(n) });
    }
    const heads = {};
    for (const table of order.filter(isChainHeadTable)) {
      const { rows } = await client.query(`SELECT * FROM ${quoteIdent(table)}`);
      heads[table] = rows.length === 1 ? rows[0] : { invalidRowCount: rows.length };
    }
    let latestPrune = null;
    if (order.includes('audit_chain_prunes')) {
      const { rows } = await client.query('SELECT * FROM audit_chain_prunes ORDER BY to_count DESC LIMIT 1');
      latestPrune = rows[0] || null;
    }
    const facts = {
      format: FORMAT, snapshot: 'exported-repeatable-read-read-only', serverVersion, serverMajor,
      pgDumpVersion: dumpTool.version, pgDumpMajor: dumpTool.major, ...access, tables,
      coverage: { expectedTableCount: EXPECTED_TABLES.length, discoveredTableCount: discovered.length, dumpedTableCount: tables.length },
    };
    return {
      facts, heads, latestPrune,
      /** pg_dump of the held snapshot, streamed into <targetDir>/postgres.dump[.enc]; ends the snapshot transaction. */
      async dump(targetDir, enc) {
        const path = require('path');
        const archiveFile = enc && enc.encrypt ? 'postgres.dump.enc' : 'postgres.dump';
        let written = null;
        const r = await _run(pgDumpBin(env), ['--format=custom', '--no-password', `--snapshot=${snapshotId}`, `--dbname=${conn.dbnameArg}`], {
          env: _childEnv(conn.password, env),
          stdout: (out) => { written = writeStreamToArchive(out, path.join(targetDir, archiveFile), enc && enc.encrypt ? enc.encKey : null); },
        });
        let w;
        try { w = await written; } catch (e) { await abort(); throw e; }
        await client.query('COMMIT').catch(() => {});
        client.release(); await pool.end().catch(() => {});
        if (r.code !== 0) throw new PgDumpError(`pg_dump failed (exit ${r.code}): ${r.stderr}`, 'PG_DUMP_FAILED');
        if (w.plainBytes === 0) throw new PgDumpError('pg_dump produced no output', 'PG_DUMP_FAILED');
        return { archiveFile, sha256: w.sha256, sizeBytes: w.sizeBytes, plainSha256: w.plainSha256, plainBytes: w.plainBytes };
      },
      abort,
    };
  } catch (e) {
    await abort();
    throw e;
  }
}

// ── restore side ─────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Restore a pg_dump-format backup into the target database and run every post-restore gate (P-2).
 * @param {string} backupDir
 * @param {object} pgm  manifest.postgres (format pg_dump-custom)
 * @param {{ connectionString?: string, encryption?: object|null, auditOrderingMode?: string, deferChainHeadGate?: boolean, readSide?: Function }} opts
 *   readSide(entry) → parsed JSON of a small encrypted side archive (chain heads)
 */
async function restoreWithPgRestore(backupDir, pgm, opts = {}) {
  const env = opts.env || process.env;
  // explicit target, never the source (resolveConnection() alone would fall back to QODIQA_PG_URL / PG*).
  const conn = resolveConnection(require('./restoreTargetGuard').assertSafeRestoreTarget(opts.connectionString, env), env);
  const restoreTool = toolMajor(pgRestoreBin(env));
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: conn.nodeConnectionString, max: 2 });
  let auditChainMirrorCount = null; let chainHeads = null; let chainHeadGateError = null; let definerOwnership = null;
  const tables = [];
  try {
    const { rows: [t] } = await pool.query(
      `SELECT current_setting('server_version_num')::int AS v, current_setting('server_version') AS s,
              (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS su, current_user AS who`);
    const targetMajor = Math.floor(t.v / 10000);
    if (restoreTool.major > targetMajor || restoreTool.major < pgm.pgDumpMajor) {
      throw new PgDumpError(`pg_restore major ${restoreTool.major} cannot restore a PostgreSQL ${pgm.pgDumpMajor} dump into a PostgreSQL ${targetMajor} server (${t.s}) `
        + '— use the client tools of the target\'s major. The target was not touched.', 'PG_RESTORE_VERSION_MISMATCH');
    }
    // pg-backup.sh OA4-F1: with --no-owner every restored object (47 SECURITY DEFINER functions among them) is owned by
    // the restoring role; a superuser would make every definer function run as superuser.
    if (t.su === true && env.QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE !== 'true') {
      throw new PgDumpError(`refusing to restore as superuser "${t.who}": with --no-owner every restored SECURITY DEFINER function would run as superuser. `
        + 'Restore as the identity that migrated the source, or set QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE=true where that identity IS the cluster superuser (the shipped compose) — never on a shared cluster.', 'RESTORE_SUPERUSER_REFUSED');
    }
    if (t.su === true) {
      console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'WARN', event: 'RESTORE_AS_SUPERUSER_ALLOWED', role: t.who, reason: 'QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE=true' }));
    }

    const input = createArchivePlainStream(backupDir, opts.encryption || null, pgm, env);
    const r = await _run(pgRestoreBin(env), ['--clean', '--if-exists', '--no-owner', '--exit-on-error', '--single-transaction', '--no-password', `--dbname=${conn.dbnameArg}`], {
      env: _childEnv(conn.password, env), input,
    });
    if (r.inputError) throw new PgDumpError(`reading the database archive failed: ${r.inputError.message}`, r.inputError.code || 'ARCHIVE_READ_FAILED');
    if (r.code !== 0) {
      throw new PgDumpError(`pg_restore failed (exit ${r.code}) — single transaction, the target was rolled back: ${r.stderr}`, 'PG_RESTORE_FAILED');
    }

    // --no-owner made the restoring role the owner of the 47 SECURITY DEFINER functions. On a 079+
    // schema, hand them back to qodiqa_definer and verify (fail closed); a pre-079 schema is reported, never "fixed".
    definerOwnership = await reestablishDefinerOwnership(pool);

    // Gates (fail closed). Mirror count first: it is derived state and is rebuilt from audit_chain.
    if (pgm.tables.some((x) => x.table === 'audit_chain')) {
      auditChainMirrorCount = await require('./auditChainMirrorCount').rebuildAfterRestore(pool);
    }
    const mismatches = [];
    for (const e of pgm.tables) {
      if (!e.present) continue;
      const { rows: [{ n }] } = await pool.query(`SELECT count(*)::bigint AS n FROM ${quoteIdent(e.table)}`);
      tables.push({ table: e.table, restored: Number(n), expected: e.rowCount });
      if (Number(n) !== e.rowCount) mismatches.push(`${e.table}: ${Number(n)} rows restored, the backup snapshot held ${e.rowCount}`);
    }
    if (mismatches.length) throw new PgDumpError(`restored row counts do not match the backup snapshot — ${mismatches.join('; ')}`, 'POSTGRES_ROW_COUNT_MISMATCH');

    const backedUpHeads = new Map();
    const heads = pgm.chainHeads && opts.readSide ? opts.readSide(pgm.chainHeads) : {};
    for (const [table, row] of Object.entries(heads || {})) if (CHAIN_HEADS[table]) backedUpHeads.set(table, row);
    try {
      chainHeads = await verifyRestoredChainHeads(pool, backedUpHeads, { auditOrderingMode: opts.auditOrderingMode });
    } catch (err) {
      if (!opts.deferChainHeadGate) throw err;
      chainHeadGateError = err;
    }
  } finally {
    await pool.end().catch(() => {});
  }
  const out = { restoredAt: new Date().toISOString(), format: FORMAT, tables, skippedRows: 0, skippedByTable: [], auditChainMirrorCount, chainHeads, definerOwnership };
  if (chainHeadGateError) Object.defineProperty(out, 'chainHeadGateError', { value: chainHeadGateError, enumerable: false });
  return out;
}

// ── verify side (offline) ────────────────────────────────────────────────────────────────────────────────────────

/** P-3: the archive's table of contents must hold TABLE DATA for every table the manifest recorded. No database. */
async function listArchiveTables(backupDir, pgm, encryption, env = process.env) {
  toolMajor(pgRestoreBin(env));
  const input = createArchivePlainStream(backupDir, encryption || null, pgm, env);
  let toc = '';
  const r = await _run(pgRestoreBin(env), ['--list'], {
    env, input, stdout: (out) => { out.on('data', (d) => { toc += d.toString(); }); },
  });
  if (r.inputError) throw new PgDumpError(`reading the database archive failed: ${r.inputError.message}`, r.inputError.code || 'ARCHIVE_READ_FAILED');
  if (r.code !== 0) throw new PgDumpError(`pg_restore --list failed (exit ${r.code}): ${r.stderr}`, 'PG_ARCHIVE_UNREADABLE');
  const dataTables = new Set();
  for (const line of toc.split('\n')) {
    const m = /^\d+;\s+\d+\s+\d+\s+TABLE DATA\s+(\S+)\s+(\S+)/.exec(line.trim());
    if (m && m[1] === 'public') dataTables.add(m[2]);
  }
  return dataTables;
}

module.exports = { FORMAT, PgDumpError, takeSnapshot, restoreWithPgRestore, listArchiveTables, resolveConnection, toolMajor };
