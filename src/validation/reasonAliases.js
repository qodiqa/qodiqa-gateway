'use strict';

/**
 * Normalizes legacy reason codes returned by validateBoundRequest to their
 * canonical forms.  Both /verify and /ai/chat call validateBoundRequest; this
 * map ensures identical reason codes are returned at both endpoints for the
 * same underlying fault.
 *
 * Legacy code            → Canonical code
 * ─────────────────────────────────────────
 * MALFORMED_ARTIFACT     → INVALID_ARTIFACT
 * TIMESTAMP_IN_FUTURE    → FUTURE_TIMESTAMP
 * REQUEST_HASH_MISMATCH  → REQUEST_MISMATCH
 * NONCE_ALREADY_USED     → REPLAY_DETECTED
 */
const REASON_ALIASES = Object.freeze({
  MALFORMED_ARTIFACT:    'INVALID_ARTIFACT',
  TIMESTAMP_IN_FUTURE:   'FUTURE_TIMESTAMP',
  REQUEST_HASH_MISMATCH: 'REQUEST_MISMATCH',
  NONCE_ALREADY_USED:    'REPLAY_DETECTED',
});

function normalizeReason(raw) {
  return REASON_ALIASES[raw] || raw || 'INTERNAL_ERROR';
}

module.exports = { REASON_ALIASES, normalizeReason };
