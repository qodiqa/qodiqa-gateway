'use strict';

/**
 * Live Audit Chain Verifier — Persisted Watermark/Cursor (CHAIN-2)
 *
 * Lets a periodic scan verify only the delta since the last confirmed-good
 * position (O(delta)) instead of rescanning the whole chain every tick, and
 * lets a process restart seed its starting watermark from durable state
 * instead of forcing a full rescan on every boot.
 *
 * Two independent backends, matching the two storage modes ChainVerifier.js
 * has to support:
 *   - File mode (single-node, with or without a PG dual-write mirror): a
 *     JSON sidecar next to the audit log file itself, `<audit.log>.verify.json`
 *     — the same atomic tmp-write-then-rename pattern audit-log.js uses for
 *     its own `.sum` checksum sidecar.
 *   - PG mode (distributed / PG-authoritative): the single-row
 *     audit_chain_verifier_state table (migration 031), mirroring
 *     audit_chain_head's (migration 026) and gap_scanner_state's
 *     (migration 019, scannerState.js) singleton-row shape.
 *
 * Neither backend is ever a source of truth about chain CONTENTS — only
 * about where the verifier last confirmed consistency up to. A missing,
 * corrupt, or stale watermark is never fatal on its own: the verifier
 * degrades gracefully to re-checking more than strictly necessary, never to
 * silently skipping a check (see loadFileState()'s corrupt-sidecar handling
 * below).
 */

const fs   = require('fs');
const fsp  = fs.promises;
const path = require('path');
const pgPool = require('../../../infra/postgres/pool');

const LOG_PATH = process.env.QODIQA_AUDIT_LOG
  || path.join(__dirname, '..', '..', '..', '..', 'audit.log');
const SIDECAR_PATH = LOG_PATH + '.verify.json';

const PG_TABLE = 'audit_chain_verifier_state';

// ── File-mode watermark ───────────────────────────────────────────────────

async function loadFileState() {
  try {
    if (!fs.existsSync(SIDECAR_PATH)) return null;
    const raw = await fsp.readFile(SIDECAR_PATH, 'utf8');
    if (!raw.trim()) return null;
    return JSON.parse(raw);
  } catch {
    // A corrupt/unreadable sidecar is treated the same as "no watermark yet"
    // — the verifier re-seeds from current chain state on its next scan
    // rather than throwing. This file is a convenience cursor; audit.log and
    // audit.log.sum remain the only things this module ever trusts for
    // actual chain integrity.
    return null;
  }
}

async function saveFileState(state) {
  try {
    const tmp = SIDECAR_PATH + '.tmp';
    await fsp.writeFile(tmp, JSON.stringify(state), 'utf8');
    try { await fsp.rename(tmp, SIDECAR_PATH); }
    catch {
      await fsp.copyFile(tmp, SIDECAR_PATH);
      try { await fsp.unlink(tmp); } catch {}
    }
  } catch {
    // Best-effort: a failed watermark write only means the next scan
    // verifies a larger tail than strictly necessary (more work, not less)
    // — it can never cause a violation to go unchecked.
  }
}

// ── PG-mode watermark ─────────────────────────────────────────────────────

async function loadPgState(tx) {
  if (!tx && !pgPool.isEnabled()) return null;
  const sql = `SELECT * FROM ${PG_TABLE} WHERE id = 1 LIMIT 1`;
  const res = tx
    ? await tx.query(sql, [])
    : await pgPool.query(sql, [], 'audit_chain_verifier_state_load');
  return res.rows[0] ?? null;
}

/**
 * @param {object} state
 * @param {number|null} [state.lastVerifiedSeq]
 * @param {string|null} [state.lastVerifiedHash]
 * @param {number|null} [state.lastPgDivergenceSeq]
 * @param {string}      [state.lastScanMode]        'FULL' | 'INCREMENTAL'
 * @param {string}      [state.lastScanTrigger]     'STARTUP' | 'SCHEDULED' | 'MANUAL'
 * @param {Date}        [state.lastScanAt]
 * @param {Date|null}   [state.lastFullScanAt]       only advances on a FULL scan
 * @param {number}      [state.lastScanDurationMs]
 * @param {number}      [state.lastScanViolationsDetected]
 * @param {number}      [state.lastScanEntriesChecked]
 * @param {object}      [tx] optional transactional client
 */
async function savePgState(state, tx) {
  if (!tx && !pgPool.isEnabled()) return;

  const {
    lastVerifiedSeq      = null,
    lastVerifiedHash     = null,
    lastPgDivergenceSeq  = null,
    lastScanMode         = null,
    lastScanTrigger      = null,
    lastScanAt           = null,
    lastFullScanAt       = null,
    lastScanDurationMs   = null,
    lastScanViolationsDetected = 0,
    lastScanEntriesChecked     = 0,
  } = state;

  const sql = `
    UPDATE ${PG_TABLE}
    SET
      last_verified_seq             = COALESCE($1, last_verified_seq),
      last_verified_hash            = COALESCE($2, last_verified_hash),
      last_pg_divergence_seq        = COALESCE($3, last_pg_divergence_seq),
      last_scan_mode                = $4,
      last_scan_trigger             = $5,
      last_scan_at                  = $6,
      last_full_scan_at             = COALESCE($7, last_full_scan_at),
      last_scan_duration_ms         = $8,
      last_scan_violations_detected = $9,
      last_scan_entries_checked     = $10,
      updated_at                    = NOW()
    WHERE id = 1
  `;
  const params = [
    lastVerifiedSeq,
    lastVerifiedHash,
    lastPgDivergenceSeq,
    lastScanMode,
    lastScanTrigger,
    lastScanAt,
    lastFullScanAt,
    lastScanDurationMs,
    lastScanViolationsDetected,
    lastScanEntriesChecked,
  ];

  if (tx) await tx.query(sql, params);
  else    await pgPool.query(sql, params, 'audit_chain_verifier_state_save');
}

module.exports = { loadFileState, saveFileState, loadPgState, savePgState, SIDECAR_PATH };
