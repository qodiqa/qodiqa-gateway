'use strict';

/**
 * recover a PostgreSQL audit mirror that is BEHIND the authoritative file chain,
 * at boot, BEFORE the fail-closed mirror consistency check (src/core/audit/mirrorConsistencyCheck.js) runs.
 *
 * The two recoverable states the fault suite found, both "PG is an exact ordered prefix of audit.log":
 * a crash after an entry's fsync into audit.log and before its PG mirror INSERT committed;
 * mirror writes failed during a PostgreSQL outage (queued in persistence_recovery_queue / the journal) and
 *           the process restarted before the recovery worker caught up.
 * Before this step both made boot refuse (MISSING_IN_PG / AUDIT_MIRROR_CONSISTENCY_VIOLATION) until an operator ran
 * scripts/migrate-files-to-pg.js.
 *
 * What it does — and ONLY this: read PostgreSQL's true chain tail (qodiqa_audit_chain_true_tail(), S1); find
 * that exact hash in the file chain; replay every LATER file entry, in chain order, through the SAME code the live
 * mirror writer uses (pg-audit-backend insertMirrorRow — parent-guarded, ON CONFLICT (hash) DO NOTHING, the
 * projection — then recordEvidenceForEntry, which durably queues a failed evidence write as it always has). Then it
 * re-reads the PG tail and requires it to equal the file tail.
 *
 * What it never does (left to the unchanged, fail-closed consistency check, which still runs right after):
 *   - touch an EMPTY mirror (a mirror wiped or never populated stays an operator decision: migrate-files-to-pg.js);
 *   - touch a mirror whose tail is NOT in the file chain (PG ahead, fork, tampering, a restored older file);
 *   - modify, delete or reorder any existing PG row, or write anything to audit.log.
 * Idempotent: a second run finds PG's tail = the file tail and replays nothing; a row already present is skipped.
 * Fail-closed: any error stops the replay and is reported; the consistency check then refuses to start the server if
 * the mirror is still behind. No Redis dependency.
 *
 * Single-node file chain with the PG mirror enabled only; a no-op in distributed mode (PG is the authority there) and
 * when QODIQA_PG_ENABLED is not "true". Rollback switch: QODIQA_AUDIT_MIRROR_BOOT_RECOVERY=off (= the earlier boot).
 */

const OUTCOME = Object.freeze({
  DISABLED:     'disabled',      // switched off / PG disabled / distributed mode
  IN_SYNC:      'in_sync',       // PG tail == file tail (nothing to do)
  RECOVERED:    'recovered',     // PG was a strict prefix; the missing tail was replayed and PG now == file
  PG_EMPTY:     'pg_empty',      // not repaired (operator decision); the check decides
  NOT_A_PREFIX: 'not_a_prefix',  // PG tail not in the file chain; not repaired; the check decides
  FAILED:       'failed',        // replay or re-verification failed; the check decides (fail-closed)
});

async function recoverMirrorBeforeBootCheck({
  _env = process.env,
  _auditLog = require('./audit-log'),
  _pgAuditBackend = require('../../infra/postgres/pg-audit-backend'),
  _pgPool = require('../../infra/postgres/pool'),
  _emit = require('../../../services/logger').emit,
} = {}) {
  if (_env.QODIQA_AUDIT_MIRROR_BOOT_RECOVERY === 'off' || _env.QODIQA_PG_ENABLED !== 'true'
      || _auditLog.ORDERING_MODE === 'distributed' || !_pgPool.isEnabled()) {
    return { outcome: OUTCOME.DISABLED, replayed: 0 };
  }

  const snap = _auditLog.memorySnapshot();
  const fileCount = snap.modernCount;
  const fileTail = _auditLog.getAuditTailHash();
  const report = (outcome, extra = {}) => {
    const r = { outcome, fileCount, fileTail, ...extra };
    const level = outcome === OUTCOME.FAILED || outcome === OUTCOME.NOT_A_PREFIX ? 'ERROR'
      : outcome === OUTCOME.RECOVERED || outcome === OUTCOME.PG_EMPTY ? 'WARN' : 'INFO';
    _emit(level, 'AUDIT_MIRROR_BOOT_RECOVERY', r);
    return r;
  };

  let pgTail;
  try { pgTail = await _pgAuditBackend.getChainTail(); } catch (err) {
    return report(OUTCOME.FAILED, { replayed: 0, stage: 'read_pg_tail', error: err.message });
  }
  if (!fileTail || fileCount === 0) return report(pgTail ? OUTCOME.NOT_A_PREFIX : OUTCOME.IN_SYNC, { replayed: 0, pgTail: pgTail ? pgTail.hash : null });
  if (!pgTail) return report(OUTCOME.PG_EMPTY, { replayed: 0, pgTail: null });
  if (pgTail.hash === fileTail) return report(OUTCOME.IN_SYNC, { replayed: 0, pgTail: pgTail.hash });

  // Locate PG's tail in the file chain: newest-first through the in-memory window (O(1) per position), then a
  // streamed page scan of the rest of the file if it is older than the window.
  const start = (_auditLog.getChainStart() || {}).startCount || 0;
  let pos = -1;
  const windowFloor = Math.max(start, fileCount - (Number.isFinite(_auditLog.WINDOW_SIZE) ? _auditLog.WINDOW_SIZE : fileCount));
  for (let p = fileCount - 1; p >= windowFloor; p--) {
    const e = await _auditLog.getModernEntryAt(p);
    if (!e) break;
    if (e.hash === pgTail.hash) { pos = p; break; }
  }
  let missing = null;
  if (pos >= 0) {
    missing = [];
    for (let p = pos + 1; p < fileCount; p++) {
      const e = await _auditLog.getModernEntryAt(p);
      if (!e) return report(OUTCOME.FAILED, { replayed: 0, stage: 'read_file_entry', position: p, pgTail: pgTail.hash });
      missing.push(e);
    }
  } else {
    // Older than the window: one streamed pass over the file, collecting everything after PG's tail.
    let seen = false; let collected = [];
    await _auditLog.forEachModernChainPage(async (page) => {
      for (const e of page) {
        if (seen) collected.push(e);
        else if (e.hash === pgTail.hash) seen = true;
      }
    });
    if (!seen) return report(OUTCOME.NOT_A_PREFIX, { replayed: 0, pgTail: pgTail.hash });
    missing = collected;
    collected = null;
  }

  // Replay in chain order through the live mirror writer's own insert + evidence path.
  let replayed = 0; let alreadyPresent = 0;
  for (const e of missing) {
    try {
      const r = await _pgPool.withTransaction((tx) => _pgAuditBackend.insertMirrorRow(tx, e, { label: 'audit_mirror_boot_recovery' }),
        { isolationLevel: 'READ COMMITTED' });
      if (r && r.alreadyPresent) alreadyPresent++; else replayed++;
    } catch (err) {
      return report(OUTCOME.FAILED, { replayed, alreadyPresent, stage: 'insert', hash: e.hash, error: err.message, code: err.code || null, pgTail: pgTail.hash });
    }
    await _pgAuditBackend.recordEvidenceForEntry(e);   // never throws: a failed evidence write is durably queued
  }

  let after;
  try { after = await _pgAuditBackend.getChainTail(); } catch (err) {
    return report(OUTCOME.FAILED, { replayed, alreadyPresent, stage: 'reverify_pg_tail', error: err.message, pgTail: pgTail.hash });
  }
  if (!after || after.hash !== fileTail) {
    return report(OUTCOME.FAILED, { replayed, alreadyPresent, stage: 'reverify_pg_tail', pgTail: pgTail.hash, pgTailAfter: after ? after.hash : null });
  }
  return report(OUTCOME.RECOVERED, { replayed, alreadyPresent, pgTail: pgTail.hash, pgTailAfter: after.hash });
}

module.exports = { recoverMirrorBeforeBootCheck, OUTCOME };
