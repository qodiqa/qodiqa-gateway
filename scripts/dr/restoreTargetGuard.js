'use strict';

/**
 * — a restore must never default to, or equal, the database it was dumped from.
 *
 * Before: runRestore()/restorePostgres()/cycle.js resolved the target as `QODIQA_PG_RESTORE_URL || QODIQA_PG_URL ||
 * DATABASE_URL` (and pg_dump-custom restores additionally accepted libpq PG* variables), so with QODIQA_PG_RESTORE_URL unset
 * a `pg_restore --clean` ran over the SOURCE database, with no check that the target differed.
 *
 * Now: the target must be given EXPLICITLY (argument or QODIQA_PG_RESTORE_URL) and must not identify the same
 * host:port/database as any source identity visible in the environment (QODIQA_PG_URL, DATABASE_URL, QODIQA_PG_HOST/PORT/
 * DATABASE, libpq PGHOST/PGPORT/PGDATABASE). Loopback aliases (localhost / 127.0.0.1 / ::1) are treated as the same host.
 */

class RestoreTargetError extends Error {
  constructor(message, code) { super(message); this.name = 'RestoreTargetError'; this.code = code; }
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '']);

function _identity(host, port, db) {
  const h = String(host || '').toLowerCase();
  return `${LOOPBACK.has(h) ? 'loopback' : h}:${String(port || '5432')}/${db || ''}`;
}

function _fromUrl(raw) {
  try {
    const u = new URL(raw);
    return _identity(u.hostname, u.port, decodeURIComponent((u.pathname || '').replace(/^\//, '')));
  } catch (_) { return null; }
}

/** Identities of every database the environment names as a SOURCE (what a backup was / would be dumped from). */
function sourceIdentities(env = process.env) {
  const ids = new Set();
  for (const k of ['QODIQA_PG_URL', 'DATABASE_URL']) { if (env[k]) { const id = _fromUrl(env[k]); if (id) ids.add(id); } }
  if (env.QODIQA_PG_HOST || env.QODIQA_PG_DATABASE) ids.add(_identity(env.QODIQA_PG_HOST, env.QODIQA_PG_PORT, env.QODIQA_PG_DATABASE));
  if (env.PGHOST || env.PGDATABASE) ids.add(_identity(env.PGHOST, env.PGPORT, env.PGDATABASE));
  return ids;
}

/**
 * @param {string|null|undefined} connectionString  explicit target (argument), else QODIQA_PG_RESTORE_URL
 * @returns {string} the validated connection string
 * @throws {RestoreTargetError} RESTORE_TARGET_REQUIRED | RESTORE_TARGET_INVALID | RESTORE_TARGET_IS_SOURCE
 */
function assertSafeRestoreTarget(connectionString, env = process.env) {
  const target = connectionString || env.QODIQA_PG_RESTORE_URL || null;
  if (!target) {
    throw new RestoreTargetError('no PostgreSQL restore target: set QODIQA_PG_RESTORE_URL (or pass connectionString) to a database that is NOT the backup source — there is no fallback to QODIQA_PG_URL / DATABASE_URL / PG* any more', 'RESTORE_TARGET_REQUIRED');
  }
  const id = _fromUrl(target);
  if (!id) throw new RestoreTargetError('the PostgreSQL restore target is not a valid URL', 'RESTORE_TARGET_INVALID');
  if (sourceIdentities(env).has(id)) {
    throw new RestoreTargetError(`the restore target (${id}) is the same database as the backup source — refusing to restore over it; point QODIQA_PG_RESTORE_URL at a separate (clean) database`, 'RESTORE_TARGET_IS_SOURCE');
  }
  return target;
}

module.exports = { assertSafeRestoreTarget, sourceIdentities, RestoreTargetError };
