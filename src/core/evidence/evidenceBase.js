'use strict';

/**
 * step 6 — where the KEPT evidence chain starts after a retention prune.
 *
 * scripts/audit/prune.js (the operator command, M4) archives and removes evidence_chain_records up to an id E and
 * records the prune, append-only, in audit_chain_prunes (migration 071). base_record.evidence then holds
 *
 *   { lastPrunedId: E, lastPrunedHash: <evidence_hash of record E>, signedHead: { id, hash } }
 *
 * where signedHead is the evidence head the SIGNED checkpoint vouches for (checkpoint.payload.evidenceHead, E ≤
 * signedHead.id). The first kept record links to lastPrunedHash instead of null, and the kept chain must reach
 * signedHead.hash at signedHead.id — which is what binds the (unsigned) lastPrunedHash to the signature.
 *
 * getEvidenceBase() returns:
 *   null                    no evidence prune has ever run (or the table predates migration 071) — genesis rules apply
 *   { lastPrunedId, lastPrunedHash, signedHead, checkpointId }
 *   { error }               a prune row exists but its checkpoint does not verify or does not match — callers FAIL CLOSED
 *
 * The result is cached for the life of the process: a prune runs only with the server stopped
 * (--confirm-server-stopped), so a running process never sees the base move. _resetEvidenceBaseCache() for tests.
 */

const HASH_RE = /^[0-9a-f]{64}$/;
let _cache; // undefined = not read yet

function _validate(rec, verifyCheckpoint) {
  const ev = rec && rec.evidence;
  if (!ev) return null;
  // The checkpoint that vouches for this evidence head: the prune's own, or — when a later prune removed no evidence
  // and carried the base forward — the earlier one, carried with it.
  const cp = ev.checkpoint || (rec && rec.checkpoint);
  const v = verifyCheckpoint(cp);
  if (!v.ok) return { error: `EVIDENCE_BASE_CHECKPOINT_INVALID: ${v.reason}` };
  const head = cp.payload.evidenceHead;
  const sh = ev.signedHead;
  if (!head || !sh || Number(head.id) !== Number(sh.id) || head.hash !== sh.hash) {
    return { error: 'EVIDENCE_BASE_MISMATCH: the prune record\'s evidence head is not the one the signed checkpoint vouches for' };
  }
  const lastPrunedId = Number(ev.lastPrunedId);
  if (!Number.isSafeInteger(lastPrunedId) || lastPrunedId < 1 || lastPrunedId > Number(sh.id) || !HASH_RE.test(ev.lastPrunedHash || '')) {
    return { error: 'EVIDENCE_BASE_MALFORMED: lastPrunedId/lastPrunedHash out of range' };
  }
  if (lastPrunedId === Number(sh.id) && ev.lastPrunedHash !== sh.hash) {
    return { error: 'EVIDENCE_BASE_MISMATCH: the last pruned record is the signed head but its hash differs' };
  }
  return { lastPrunedId, lastPrunedHash: ev.lastPrunedHash, signedHead: { id: Number(sh.id), hash: sh.hash }, checkpointId: cp.payload.checkpointId };
}

/**
 * @param {object} [o]
 * @param {(sql: string, params: any[], label: string) => Promise<{rows: object[]}>} [o.query]  default qodiqa_reporting
 * @param {(signed: object) => {ok: boolean, reason?: string}} [o.verifyCheckpoint]
 */
async function getEvidenceBase(o = {}) {
  if (_cache !== undefined && !o.query) return _cache;
  const query = o.query || ((sql, params, label) => require('../../infra/postgres/rolePools').reporting.query(sql, params, label));
  const verifyCheckpoint = o.verifyCheckpoint || require('../audit/checkpoint/checkpoint').verifyCheckpoint;
  let res;
  try {
    res = await query(
      `SELECT base_record FROM audit_chain_prunes WHERE base_record ? 'evidence' AND base_record->'evidence' <> 'null'::jsonb
        ORDER BY to_count DESC LIMIT 1`, [], 'evidence_base_read');
  } catch (e) {
    if (e && e.code === '42P01') { if (!o.query) _cache = null; return null; } // pre-071 schema: no prune can have run
    throw e;
  }
  const row = res && Array.isArray(res.rows) ? res.rows[0] : null;
  const rec = row && row.base_record && typeof row.base_record === 'object' ? row.base_record : null;
  const out = rec ? _validate(rec, verifyCheckpoint) : null;
  if (!o.query) _cache = out;
  return out;
}

function _resetEvidenceBaseCache() { _cache = undefined; }

module.exports = { getEvidenceBase, _resetEvidenceBaseCache, _validate };
