'use strict';

/**
 * S2 — DR step for the derived audit_chain row counter (migration 073).
 *
 * Called by restorePostgres() (scripts/dr/postgres.js) on the RESTORE connection — the owner identity that restores
 * every table (the same connection scripts/dr/erasureReplay.js uses; registered in
 * OWNER_CONNECTION_FILES). audit_chain_mirror_count is never restored as data
 * (scripts/dr/table-registry.js EXCLUDED_TABLES); after audit_chain has been restored it is rebuilt from the restored
 * rows by the owner-only rebuild function, then the DR invariant counter == count(*) is proven with the authoritative
 * cross-check. Throws — the restore fails — when the rebuild is not permitted or the invariant does not hold. A target
 * without migration 073 has no counter: reported as { present: false }, never invented.
 *
 * @param {import('pg').Pool} pool  the restore connection
 * @returns {Promise<{present: false} | {present: true, previous: number|null, rebuilt: number, stored: number, exact: number, inSync: true}>}
 */
async function rebuildAfterRestore(pool) {
  const has = await pool.query("SELECT to_regprocedure('qodiqa_audit_chain_mirror_count_rebuild()') IS NOT NULL AS ok");
  if (!has.rows[0].ok) return { present: false };
  let rebuilt;
  try {
    rebuilt = (await pool.query('SELECT previous, rebuilt FROM qodiqa_audit_chain_mirror_count_rebuild()')).rows[0];
  } catch (err) {
    throw new Error(`restorePostgres: rebuilding audit_chain_mirror_count failed (${err.message}) — the restore identity must own the schema objects (it must EXECUTE the owner-only rebuild function, as it must write every table)`);
  }
  const check = (await pool.query('SELECT stored, exact, in_sync FROM qodiqa_audit_chain_mirror_count_check()')).rows[0];
  const out = { present: true, previous: rebuilt.previous === null ? null : Number(rebuilt.previous), rebuilt: Number(rebuilt.rebuilt),
    stored: Number(check.stored), exact: Number(check.exact), inSync: check.in_sync === true };
  if (!out.inSync) {
    throw new Error(`restorePostgres: audit_chain_mirror_count ${out.stored} != count(*) ${out.exact} after rebuild (DR invariant violated)`);
  }
  return out;
}

module.exports = { rebuildAfterRestore };
