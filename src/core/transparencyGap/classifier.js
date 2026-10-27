'use strict';

/**
 * Transparency Gap Classifier — Component #14
 *
 * Deterministic severity assignment.  Given a gap type and its context details,
 * returns exactly one of: INFO | WARNING | CRITICAL.
 *
 * Rules (in priority order):
 *
 *   CRITICAL — integrity-affecting, requires immediate action:
 *     HASH_CHAIN_BREAK              always
 *     SEQUENCE_BREAK                always (chain integrity is broken)
 *     CHECKPOINT_DIVERGENCE         always
 *     MISSING_VERIFICATION_EVIDENCE always (unreconciled transparency evidence)
 *
 *   INFO — temporary, self-healing expected:
 *     PARTIAL_APPEND                when details.recentlyQueued === true
 *     MISSING_TRANSPARENCY_ENTRY    when details.temporaryLag === true
 *
 *   WARNING — non-critical inconsistency:
 *     PARTIAL_APPEND                when NOT recently queued
 *     MISSING_TRANSPARENCY_ENTRY    when NOT temporary lag
 *     ARTIFACT_WITHOUT_TRANSPARENCY always
 *     TRANSPARENCY_WITHOUT_ARTIFACT always
 *
 * No external I/O.  Pure function — same input always produces same output.
 */

const { GAP_TYPE } = require('./detector');

const SEVERITY = Object.freeze({
  INFO:     'INFO',
  WARNING:  'WARNING',
  CRITICAL: 'CRITICAL',
});

// ── Classification table ──────────────────────────────────────────────────────

const _ALWAYS_CRITICAL = new Set([
  GAP_TYPE.HASH_CHAIN_BREAK,
  GAP_TYPE.SEQUENCE_BREAK,
  GAP_TYPE.CHECKPOINT_DIVERGENCE,
  GAP_TYPE.MISSING_VERIFICATION_EVIDENCE,
]);

/**
 * Classify the severity of a gap.
 *
 * @param {string} gapType    — one of GAP_TYPE values
 * @param {object} [details]  — gap details object (context-specific flags)
 * @returns {'INFO'|'WARNING'|'CRITICAL'}
 */
function classify(gapType, details = {}) {
  if (_ALWAYS_CRITICAL.has(gapType)) return SEVERITY.CRITICAL;

  switch (gapType) {
    case GAP_TYPE.PARTIAL_APPEND:
      return details.recentlyQueued ? SEVERITY.INFO : SEVERITY.WARNING;

    case GAP_TYPE.MISSING_TRANSPARENCY_ENTRY:
      return details.temporaryLag ? SEVERITY.INFO : SEVERITY.WARNING;

    case GAP_TYPE.ARTIFACT_WITHOUT_TRANSPARENCY:
    case GAP_TYPE.TRANSPARENCY_WITHOUT_ARTIFACT:
      return SEVERITY.WARNING;

    default:
      return SEVERITY.WARNING;
  }
}

/**
 * @returns {boolean}  true if the severity level requires immediate escalation
 */
function isCritical(severity) {
  return severity === SEVERITY.CRITICAL;
}

/**
 * @returns {boolean}  true if the gap should be tracked (WARNING or CRITICAL)
 */
function requiresTracking(severity) {
  return severity === SEVERITY.WARNING || severity === SEVERITY.CRITICAL;
}

module.exports = {
  SEVERITY,
  classify,
  isCritical,
  requiresTracking,
};
