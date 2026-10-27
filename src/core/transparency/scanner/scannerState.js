'use strict';

/**
 * Transparency Gap Scanner — Persistent State — Component #34
 *
 * Reads and writes the single-row gap_scanner_state table (migration 019).
 * State survives process restarts — the scanner resumes from last_scanned_id.
 *
 * All methods are safe to call when PostgreSQL is not enabled:
 *   load()  → returns null
 *   save()  → no-op
 */

const pgPool = require('../../../infra/postgres/pool');

const TABLE = 'gap_scanner_state';

/**
 * Load the current scan state.
 *
 * @param {object} [tx] — optional transactional client (for use inside scan transaction)
 * @returns {Promise<object|null>} state row or null (PG disabled / row missing)
 */
async function load(tx) {
  if (!tx && !pgPool.isEnabled()) return null;

  const sql = `SELECT * FROM ${TABLE} WHERE id = 1 LIMIT 1`;
  const res = tx
    ? await tx.query(sql, [])
    : await pgPool.query(sql, [], 'gap_scanner_state_load');
  return res.rows[0] ?? null;
}

/**
 * Persist scan state after a successful scan.
 *
 * @param {object} state
 * @param {bigint|number|null} state.lastScannedId
 * @param {bigint|number|null} state.lastCompletedRootId
 * @param {string}             state.lastScanMode        — 'FULL' | 'INCREMENTAL'
 * @param {Date}               state.lastScanAt
 * @param {number}             state.lastScanDurationMs
 * @param {number}             state.lastScanGapsDetected
 * @param {number}             state.lastScanEntriesChecked
 * @param {Date|null}          state.lastFullScanAt      — only updated on FULL scan
 * @returns {Promise<void>}
 */
async function save(state) {
  if (!pgPool.isEnabled()) return;

  const {
    lastScannedId,
    lastCompletedRootId,
    lastScanMode,
    lastScanAt,
    lastScanDurationMs,
    lastScanGapsDetected,
    lastScanEntriesChecked,
    lastFullScanAt,
  } = state;

  await pgPool.query(`
    UPDATE ${TABLE}
    SET
      last_scanned_id           = $1,
      last_completed_root_id    = $2,
      last_scan_mode            = $3,
      last_scan_at              = $4,
      last_scan_duration_ms     = $5,
      last_scan_gaps_detected   = $6,
      last_scan_entries_checked = $7,
      last_full_scan_at         = CASE WHEN $8::TEXT = 'FULL' THEN $9 ELSE last_full_scan_at END,
      updated_at                = NOW()
    WHERE id = 1
  `, [
    lastScannedId       != null ? Number(lastScannedId)       : null,
    lastCompletedRootId != null ? Number(lastCompletedRootId) : null,
    lastScanMode,
    lastScanAt,
    lastScanDurationMs,
    lastScanGapsDetected,
    lastScanEntriesChecked,
    lastScanMode,
    lastFullScanAt ?? null,
  ], 'gap_scanner_state_save');
}

module.exports = { load, save };
