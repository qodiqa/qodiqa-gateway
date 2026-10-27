'use strict';

/**
 * S0 — audit_chain test scaffolding. Test-only; no production code.
 *
 *   ORACLE_TRUE_TAIL_SQL   the migration-058 body of qodiqa_audit_chain_true_tail(), verbatim, evaluated as a plain query:
 *                          the reference every replacement is compared against.
 *   chainRows(n, opts)     deterministic linear chain rows (GENESIS-rooted, or rooted at a given parent hash):
 *                          hash = sha256(tag:i) hex, prev_hash = previous hash, explicit seq values.
 * seqPlan(n, opts) explicit seq values: monotone with optional gaps, optional adjacent swaps (earlier inversions,
 * / migration 058), optional top swap (the tail is then NOT the max-seq row).
 *   insertRows(client, rows)  bulk INSERT (multi-row VALUES, ON CONFLICT (hash) DO NOTHING — the mirror's own idempotence).
 *
 * The tamper-injection library listed under S0 in the design is first consumed by S6-S8 and is added there.
 */

const crypto = require('crypto');

const ORACLE_TRUE_TAIL_SQL = `
  SELECT a.hash, a.seq
  FROM audit_chain a
  WHERE NOT EXISTS (SELECT 1 FROM audit_chain b WHERE b.prev_hash = a.hash)
  ORDER BY a.seq DESC
  LIMIT 1`;

const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/**
 * @param {number} n
 * @param {{ tag?: string, parent?: string }} [opts]  parent: prev_hash of the first row (default 'GENESIS')
 * @returns {{ hash: string, prevHash: string }[]}
 */
function chainRows(n, { tag = 'w11', parent = 'GENESIS' } = {}) {
  const out = [];
  let prev = parent;
  for (let i = 0; i < n; i++) {
    const hash = sha(`${tag}:${i}`);
    out.push({ hash, prevHash: prev });
    prev = hash;
  }
  return out;
}

/**
 * @param {number} n
 * @param {{ start?: number, gapEvery?: number, gapSize?: number, swaps?: number[], swapTop?: boolean }} [opts]
 *   swaps: indexes i whose seq is exchanged with i+1; swapTop: exchange the last two (tail gets the lower seq)
 * @returns {number[]}
 */
function seqPlan(n, { start = 1, gapEvery = 0, gapSize = 3, swaps = [], swapTop = false } = {}) {
  const seqs = [];
  let s = start;
  for (let i = 0; i < n; i++) {
    seqs.push(s);
    s += 1 + (gapEvery > 0 && (i + 1) % gapEvery === 0 ? gapSize : 0);
  }
  for (const i of swaps) if (i >= 0 && i + 1 < n) [seqs[i], seqs[i + 1]] = [seqs[i + 1], seqs[i]];
  if (swapTop && n >= 2) [seqs[n - 2], seqs[n - 1]] = [seqs[n - 1], seqs[n - 2]];
  return seqs;
}

const COLS = ['seq', 'hash', 'prev_hash', 'canonical', 'artifact_id', 'decision', 'recorded_at', 'high_res_time',
  'input_hash', 'signature', 'request_hash', 'policy_hash', 'verification_result'];

/**
 * Insert rows with explicit seqs. Values are minimal but satisfy every NOT NULL / CHECK constraint.
 * @param {import('pg').Client|import('pg').Pool} client  a connection allowed to INSERT into audit_chain
 * @param {{ hash: string, prevHash: string }[]} rows
 * @param {number[]} seqs  same length as rows
 * @param {{ batch?: number }} [opts]
 * @returns {Promise<number>} rows actually inserted
 */
async function insertRows(client, rows, seqs, { batch = 1000 } = {}) {
  if (rows.length !== seqs.length) throw new Error('insertRows: rows/seqs length mismatch');
  let inserted = 0;
  for (let off = 0; off < rows.length; off += batch) {
    const slice = rows.slice(off, off + batch);
    const vals = []; const ph = [];
    slice.forEach((r, j) => {
      const base = j * COLS.length;
      ph.push(`(${COLS.map((_, k) => `$${base + k + 1}`).join(',')})`);
      vals.push(seqs[off + j], r.hash, r.prevHash, `{"w11":"${r.hash}"}`, `w11-${r.hash}`, 'ALLOW', new Date(0), '0',
        'a'.repeat(64), 's'.repeat(64), 'r'.repeat(64), 'p'.repeat(64), true);
    });
    const res = await client.query(`INSERT INTO audit_chain (${COLS.join(',')}) VALUES ${ph.join(',')} ON CONFLICT (hash) DO NOTHING`, vals);
    inserted += res.rowCount;
  }
  return inserted;
}

module.exports = { ORACLE_TRUE_TAIL_SQL, chainRows, seqPlan, insertRows };
