'use strict';

/**
 * QODIQA Disaster Recovery — chain-head pointer rows.
 *
 * Four single-row "head" tables hold the tail of a hash-chained ledger and are the ONLY place the production append
 * paths read the previous hash from:
 *
 *   audit_chain_head        → audit_chain               (migration 026; distributedOrdering.js reads it FOR UPDATE)
 *   evidence_chain_head     → evidence_chain_records    (migration 042; chainStore.js)
 *   transparency_log_head   → transparency_log_entries  (migration 042; registrar.register())
 *   transparency_roots_head → transparency_roots        (migration 042; registrar.generateRoot())
 *
 * A freshly migrated restore target already holds each singleton row (seeded at genesis by those migrations), so the
 * generic row restore's `INSERT … ON CONFLICT DO NOTHING` used to SKIP the backed-up head and leave it at genesis while
 * the ledger rows were restored. The first append after recovery then chained from genesis: a second genesis / forked
 * chain (or, for audit_chain, a refused append on the UNIQUE prev-hash index). restorePostgres() now restores these
 * rows with ON CONFLICT (id) DO UPDATE and calls verifyRestoredChainHeads() below before reporting success.
 *
 * The invariant checked is the one the migrations themselves seed with: head = (hash, position) of the ledger's last
 * row, or the empty-chain value. audit_chain_head is maintained only by the distributed ordering path; in single-node
 * mode it is never advanced (audit_chain is a mirror there and the file log is authoritative), so its head = tail
 * check is ENFORCED only for a backup taken in distributed mode and reported (not enforced) otherwise.
 */

const { quoteIdent } = require('./table-registry');

const CHAIN_HEADS = Object.freeze({
  audit_chain_head: {
    ledger: 'audit_chain', hashCol: 'hash', posCol: 'seq', headPosCol: 'tail_seq',
    empty: { hash: 'GENESIS', pos: 0 }, enforce: (mode) => mode === 'distributed',
    // (migration 098): the head also carries the schema version of its tail entry
    versionCol: 'schema_version', headVersionCol: 'tail_schema_version',
  },
  evidence_chain_head: {
    ledger: 'evidence_chain_records', hashCol: 'evidence_hash', posCol: 'id', headPosCol: 'tail_id',
    empty: { hash: null, pos: 0 }, enforce: () => true,
  },
  transparency_log_head: {
    ledger: 'transparency_log_entries', hashCol: 'entry_hash', posCol: 'id', headPosCol: 'tail_id',
    empty: { hash: null, pos: 0 }, enforce: () => true,
  },
  transparency_roots_head: {
    ledger: 'transparency_roots', hashCol: 'root_hash', posCol: 'id', headPosCol: 'tail_id',
    empty: { hash: null, pos: 0 }, enforce: () => true,
  },
});

const isChainHeadTable = (table) => Object.prototype.hasOwnProperty.call(CHAIN_HEADS, table);

// CHAR(64) columns come back blank-padded on some schema generations; compare trimmed text, null stays null.
const normHash = (v) => (v === null || v === undefined ? null : String(v).trim());
const normPos = (v) => (v === null || v === undefined ? null : Number(v));

async function _hasColumn(pool, table, column) {
  const { rows } = await pool.query("SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2", [table, column]);
  return rows.length > 0;
}

async function _readHead(pool, table) {
  const spec = CHAIN_HEADS[table];
  const withVersion = spec.headVersionCol && await _hasColumn(pool, table, spec.headVersionCol);
  const { rows } = await pool.query(`SELECT tail_hash, ${quoteIdent(spec.headPosCol)} AS pos${withVersion ? `, ${quoteIdent(spec.headVersionCol)} AS ver` : ''} FROM ${quoteIdent(table)}`);
  if (rows.length !== 1) return { rows: rows.length };
  return { hash: normHash(rows[0].tail_hash), pos: normPos(rows[0].pos), ...(withVersion ? { ver: normPos(rows[0].ver) } : {}) };
}

async function _readTail(pool, table) {
  const spec = CHAIN_HEADS[table];
  const { rows } = await pool.query(
    `SELECT ${quoteIdent(spec.hashCol)} AS h, ${quoteIdent(spec.posCol)} AS p${spec.versionCol ? `, ${quoteIdent(spec.versionCol)} AS v` : ''} FROM ${quoteIdent(spec.ledger)} `
    + `ORDER BY ${quoteIdent(spec.posCol)} DESC LIMIT 1`);
  if (rows.length === 0) return { ...spec.empty, ...(spec.versionCol ? { ver: 0 } : {}) };
  return { hash: normHash(rows[0].h), pos: normPos(rows[0].p), ...(spec.versionCol ? { ver: normPos(rows[0].v) } : {}) };
}

/**
 * (migration 098): `audit_chain_head.tail_schema_version` is DERIVED from the ledger (the schema version of the entry the head points at).
 * A backup taken before 098 has no such column, and a restore must never leave a stale value that lets the distributed writer append a lower
 * version, so it is recomputed from the restored ledger after the rows are restored. No-op when the column does not exist.
 * @returns {Promise<boolean>} whether a repair ran
 */
async function repairAuditChainHeadVersion(pool) {
  if (!(await _hasColumn(pool, 'audit_chain_head', 'tail_schema_version'))) return false;
  await pool.query('UPDATE audit_chain_head h SET tail_schema_version = COALESCE((SELECT a.schema_version FROM audit_chain a WHERE a.hash = h.tail_hash LIMIT 1), 0)');
  return true;
}

/**
 * Head-vs-tail report for every chain-head table present in the database (no writes).
 * @param {import('pg').Pool} pool
 * @param {{ auditOrderingMode?: string }} [opts]
 * @returns {Promise<{ valid: boolean, heads: object[] }>}
 */
async function chainHeadReport(pool, { auditOrderingMode = 'single-node' } = {}) {
  const { rows: present } = await pool.query(
    `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ANY($1::text[])`,
    [Object.keys(CHAIN_HEADS)]);
  const have = new Set(present.map((r) => r.table_name));
  const heads = [];
  for (const table of Object.keys(CHAIN_HEADS)) {
    if (!have.has(table)) continue;
    const spec = CHAIN_HEADS[table];
    const head = await _readHead(pool, table);
    const tail = await _readTail(pool, table);
    const consistent = head.rows === undefined && head.hash === tail.hash && head.pos === tail.pos
      && (head.ver === undefined || tail.ver === undefined || head.ver === tail.ver);
    const enforced = spec.enforce(auditOrderingMode);
    heads.push({ table, ledger: spec.ledger, head, tail, consistent, enforced });
  }
  return { valid: heads.every((h) => h.consistent || !h.enforced), heads };
}

/**
 * Post-restore gate. Fails closed (throws, code CHAIN_HEAD_RESTORE_FAILED) when
 *   - a head row that the backup holds is not exactly the backed-up value in the target, or
 *   - an enforced head does not equal its restored ledger's tail.
 *
 * @param {import('pg').Pool} pool                    restore-target pool
 * @param {Map<string, object>} backedUpHeads          table → the single backed-up head row (raw JSON row)
 * @param {{ auditOrderingMode?: string }} [opts]
 */
async function verifyRestoredChainHeads(pool, backedUpHeads, { auditOrderingMode = 'single-node' } = {}) {
  const report = await chainHeadReport(pool, { auditOrderingMode });
  const problems = [];
  for (const h of report.heads) {
    const src = backedUpHeads.get(h.table);
    if (src && src.invalidRowCount !== undefined) {
      problems.push(`${h.table}: the backup holds ${src.invalidRowCount} rows for a single-row head table`);
      continue;
    }
    h.source =src ? { hash: normHash(src.tail_hash), pos: normPos(src[CHAIN_HEADS[h.table].headPosCol]) } : null;
    h.matchesSource = src ? (h.head.hash === h.source.hash && h.head.pos === h.source.pos) : null;
    if (src && !h.matchesSource) {
      problems.push(`${h.table}: target head ${JSON.stringify(h.head)} is not the backed-up head ${JSON.stringify(h.source)}`);
    }
    if (h.enforced && !h.consistent) {
      problems.push(`${h.table}: head ${JSON.stringify(h.head)} is not the tail of the restored ${h.ledger} ${JSON.stringify(h.tail)} — the next append would fork the chain`);
    }
  }
  report.valid = problems.length === 0;
  if (problems.length > 0) {
    const err = new Error(`restorePostgres: chain-head verification failed — ${problems.join('; ')}`);
    err.code = 'CHAIN_HEAD_RESTORE_FAILED';
    err.chainHeads = report;
    throw err;
  }
  return report;
}

module.exports = { CHAIN_HEADS, isChainHeadTable, chainHeadReport, verifyRestoredChainHeads, repairAuditChainHeadVersion };
