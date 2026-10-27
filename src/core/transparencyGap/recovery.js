'use strict';

/**
 * Transparency Gap Recovery & Reconciliation — Component #14
 *
 * Tracks active gaps and their resolution state in process memory.
 * The audit trail (emit events) provides the durable record; this module
 * provides the operational view for admin tooling and reconciliation.
 *
 * Gap lifecycle:
 *   ACTIVE     — detected, unresolved
 *   RESOLVED   — resolved (manually or by reconciliation)
 *
 * Resolved gaps are never deleted — they move to the resolved Map for audit.
 *
 * Reconciliation heuristics:
 *   PARTIAL_APPEND + recentlyQueued       → likely self-resolves when PG recovers
 *   MISSING_TRANSPARENCY_ENTRY + lag      → likely self-resolves when replication catches up
 *   HASH_CHAIN_BREAK / SEQUENCE_BREAK     → requires manual intervention
 *   CHECKPOINT_DIVERGENCE                 → requires manual intervention
 */

const { emit } = require('../../../services/logger');

const SOURCE = 'TRANSPARENCY_GAP_RECOVERY';

// ── In-process gap store ──────────────────────────────────────────────────────

const _active   = new Map(); // gapId → gap record
const _resolved = new Map(); // gapId → { ...gap, resolvedAt, resolution }

// ── Gap tracking ──────────────────────────────────────────────────────────────

/**
 * Track a newly detected gap.
 * Idempotent: if a gap with this ID is already tracked, does nothing.
 *
 * @param {object} gap  — classified gap record
 */
function track(gap) {
  if (_active.has(gap.gapId) || _resolved.has(gap.gapId)) return;
  _active.set(gap.gapId, { ...gap, trackedAt: new Date().toISOString() });
}

/**
 * Resolve a tracked gap (mark as resolved).
 *
 * @param {string} gapId
 * @param {string} [resolution='MANUAL']   — resolution reason
 * @returns {boolean}  true if the gap was found and resolved
 */
function resolve(gapId, resolution = 'MANUAL') {
  const gap = _active.get(gapId);
  if (!gap) return false;

  const resolvedRecord = {
    ...gap,
    resolution,
    resolvedAt: new Date().toISOString(),
  };

  _active.delete(gapId);
  _resolved.set(gapId, resolvedRecord);

  emit('INFO', 'TRANSPARENCY_GAP_RESOLVED', {
    source:     SOURCE,
    gapId,
    gapType:    gap.gapType,
    severity:   gap.severity,
    service:    gap.service,
    artifactId: gap.artifactId,
    resolution,
    timestamp:  resolvedRecord.resolvedAt,
  });

  return true;
}

// ── Reconciliation ────────────────────────────────────────────────────────────

/**
 * Determine whether a gap is likely self-healing (temporary).
 *
 * @param {object} gap   — active gap record
 * @returns {{ selfHealing: boolean, reason: string }}
 */
function _reconciliationHint(gap) {
  const { gapType, details = {} } = gap;

  if (gapType === 'PARTIAL_APPEND' && details.recentlyQueued) {
    return { selfHealing: true, reason: 'persistence queue holds the operation; will resolve when PG recovers' };
  }
  if (gapType === 'MISSING_TRANSPARENCY_ENTRY' && details.temporaryLag) {
    return { selfHealing: true, reason: 'temporary replication lag detected; likely self-resolves' };
  }
  if (gapType === 'ARTIFACT_WITHOUT_TRANSPARENCY' || gapType === 'TRANSPARENCY_WITHOUT_ARTIFACT') {
    return { selfHealing: false, reason: 'data inconsistency — verify artifact registration pipeline' };
  }
  return { selfHealing: false, reason: 'manual investigation required' };
}

/**
 * Attempt to reconcile an active gap.
 * Returns the reconciliation assessment without modifying gap state.
 *
 * @param {string} gapId
 * @returns {{ found: boolean, selfHealing?: boolean, reason?: string, gap?: object }}
 */
function reconcile(gapId) {
  const gap = _active.get(gapId);
  if (!gap) {
    if (_resolved.has(gapId)) {
      return { found: true, selfHealing: true, reason: 'gap already resolved', gap: _resolved.get(gapId) };
    }
    return { found: false };
  }

  const hint = _reconciliationHint(gap);
  return { found: true, ...hint, gap };
}

/**
 * Attempt to auto-resolve gaps that are flagged as self-healing.
 * Called by the consumer after verifying the underlying condition is gone.
 *
 * @param {string} gapId
 * @returns {boolean}  true if resolved
 */
function attemptAutoResolve(gapId) {
  const gap = _active.get(gapId);
  if (!gap) return false;

  const hint = _reconciliationHint(gap);
  if (!hint.selfHealing) return false;

  return resolve(gapId, 'AUTO_RECONCILED');
}

// ── Admin visibility ──────────────────────────────────────────────────────────

/**
 * @returns {object[]}  List of all currently active (unresolved) gaps
 */
function listActive() {
  return [..._active.values()];
}

/**
 * @returns {object[]}  List of recently resolved gaps (all in memory)
 */
function listResolved() {
  return [..._resolved.values()];
}

/**
 * Return aggregate statistics for admin/ops tooling.
 *
 * @returns {object}
 */
function getStats() {
  const active   = [..._active.values()];
  const resolved = [..._resolved.values()];

  // Severity distribution among active gaps
  const bySeverity = { INFO: 0, WARNING: 0, CRITICAL: 0 };
  const byType     = {};
  let   oldestMs   = null;

  for (const g of active) {
    bySeverity[g.severity] = (bySeverity[g.severity] ?? 0) + 1;
    byType[g.gapType]      = (byType[g.gapType]      ?? 0) + 1;

    const ts = new Date(g.detectedAt).getTime();
    if (oldestMs === null || ts < oldestMs) oldestMs = ts;
  }

  const resolutionRate = (active.length + resolved.length) > 0
    ? (resolved.length / (active.length + resolved.length))
    : null;

  return {
    activeCount:    active.length,
    resolvedCount:  resolved.length,
    bySeverity,
    byType,
    oldestUnresolvedAt: oldestMs ? new Date(oldestMs).toISOString() : null,
    resolutionRate,
  };
}

function _reset() {
  _active.clear();
  _resolved.clear();
}

module.exports = {
  track,
  resolve,
  reconcile,
  attemptAutoResolve,
  listActive,
  listResolved,
  getStats,
  _reset,
};
