'use strict';

/**
 * Live Audit Chain Verifier — Violation Taxonomy (CHAIN-2)
 *
 * Single source of truth for what kind of chain integrity problem was found
 * and how severe it is. Both the file-mode and PG-mode verification paths in
 * ChainVerifier.js route every finding through severityOf()/alertEventFor()
 * here so classification never drifts between the two modes.
 *
 * CRITICAL findings reuse the audit chain's existing AUDIT_CHAIN_CORRUPTED
 * alert (src/alerting/detection/OperationalDetector.js — already CRITICAL,
 * "DO NOT allow further writes"). MEDIUM findings use a new
 * AUDIT_CHAIN_STRUCTURAL_ANOMALY event/subtype (see src/alerting/constants.js)
 * — see SEQUENCE_GAP's comment below for why a bare sequence gap is not
 * treated as tamper evidence by itself.
 */

const VIOLATION_REASON = Object.freeze({
  HASH_MISMATCH:                 'HASH_MISMATCH',
  PREV_HASH_MISMATCH:            'PREV_HASH_MISMATCH',
  INVALID_GENESIS:               'INVALID_GENESIS',
  MULTIPLE_GENESIS:              'MULTIPLE_GENESIS',
  DUPLICATE_ARTIFACT_ID:         'DUPLICATE_ARTIFACT_ID',
  DUPLICATE_SEQUENCE:            'DUPLICATE_SEQUENCE',
  MALFORMED_RECORD:              'MALFORMED_RECORD',
  TRUNCATION:                    'TRUNCATION',
  ORPHAN_RECORD:                 'ORPHAN_RECORD',
  FILE_MEMORY_DIVERGENCE:        'FILE_MEMORY_DIVERGENCE',
  PG_MIRROR_MISSING_IN_FILE:     'PG_MIRROR_MISSING_IN_FILE',
  PG_MIRROR_MISSING_IN_PG:       'PG_MIRROR_MISSING_IN_PG',
  PG_MIRROR_HASH_MISMATCH:       'PG_MIRROR_HASH_MISMATCH',
  PG_MIRROR_PREV_HASH_MISMATCH:  'PG_MIRROR_PREV_HASH_MISMATCH',
  PG_MIRROR_METADATA_MISMATCH:   'PG_MIRROR_METADATA_MISMATCH',
  PG_MIRROR_GENESIS_MISMATCH:    'PG_MIRROR_GENESIS_MISMATCH',
  // MEDIUM — see comment above VIOLATION_SEVERITY_MEDIUM below.
  SEQUENCE_GAP:                  'SEQUENCE_GAP',
  // TRACE-3: a consent_audit_log row whose stored checksum does not match
  // the recomputed one — see src/core/consent/ConsentStore.js
  // verifyConsentAuditIntegrity(). CRITICAL like every other reason above
  // except SEQUENCE_GAP: unlike a burned BIGSERIAL value, a checksum
  // mismatch requires either tampering or a real defect, never routine
  // background noise.
  CONSENT_CHECKSUM_MISMATCH:     'CONSENT_CHECKSUM_MISMATCH',
});

const SEVERITY = Object.freeze({ CRITICAL: 'CRITICAL', MEDIUM: 'MEDIUM' });

// audit_chain.seq is BIGSERIAL with NO uniqueness constraint (see
// migrations/001_initial_schema.sql), and PostgreSQL's nextval() is
// non-transactional — a statement that reserves a sequence value and then
// rolls back permanently burns it. A gap is therefore expected background
// noise, not tamper evidence by itself; escalating every routine gap to the
// same CRITICAL "stop the presses" alert as a broken hash chain would train
// operators to ignore the alert. Every other reason here requires either a
// cryptographic break or an explicit non-default write to occur, so all of
// them stay CRITICAL.
const _MEDIUM_REASONS = new Set([VIOLATION_REASON.SEQUENCE_GAP]);

function severityOf(reason) {
  return _MEDIUM_REASONS.has(reason) ? SEVERITY.MEDIUM : SEVERITY.CRITICAL;
}

function alertEventFor(reason) {
  return severityOf(reason) === SEVERITY.MEDIUM
    ? 'AUDIT_CHAIN_STRUCTURAL_ANOMALY'
    : 'AUDIT_CHAIN_CORRUPTED';
}

// Maps audit-log.js's _walkChain() reason codes (the file-mode / PG-batch
// hash-chain walker, shared by both storage modes) onto this module's
// taxonomy, so callers never have to know both vocabularies.
function mapAuditLogReason(reason) {
  switch (reason) {
    case 'AUDIT_CHAIN_TAMPERED':  return VIOLATION_REASON.HASH_MISMATCH;
    case 'AUDIT_CHAIN_BROKEN':    return VIOLATION_REASON.PREV_HASH_MISMATCH;
    case 'AUDIT_DUPLICATE_ENTRY': return VIOLATION_REASON.DUPLICATE_ARTIFACT_ID;
    case 'AUDIT_ENTRY_MISSING':   return VIOLATION_REASON.MALFORMED_RECORD;
    default:                      return VIOLATION_REASON.MALFORMED_RECORD;
  }
}

// Maps mirrorConsistencyCheck.js's MISMATCH_REASON vocabulary (file-vs-PG
// dual-write divergence) onto this module's taxonomy.
function mapMirrorReason(reason) {
  switch (reason) {
    case 'MISSING_IN_FILE':    return VIOLATION_REASON.PG_MIRROR_MISSING_IN_FILE;
    case 'MISSING_IN_PG':      return VIOLATION_REASON.PG_MIRROR_MISSING_IN_PG;
    case 'HASH_MISMATCH':      return VIOLATION_REASON.PG_MIRROR_HASH_MISMATCH;
    case 'PREV_HASH_MISMATCH': return VIOLATION_REASON.PG_MIRROR_PREV_HASH_MISMATCH;
    case 'METADATA_MISMATCH':  return VIOLATION_REASON.PG_MIRROR_METADATA_MISMATCH;
    case 'GENESIS_MISMATCH':   return VIOLATION_REASON.PG_MIRROR_GENESIS_MISMATCH;
    default:                   return VIOLATION_REASON.PG_MIRROR_HASH_MISMATCH;
  }
}

// Explicit no-op extension point (requirement: archive-boundary checks).
// The execution audit chain has no retention/archival today — retention.js
// operates exclusively on the separate platform_audit_events table and
// explicitly excludes the ENFORCEMENT category (see its seed data / WHERE
// clauses). This always returns "not applicable" rather than pretending to
// check archival behavior that doesn't exist; it exists so that if archival
// is ever added for this chain, there is an obvious, already-wired place to
// implement the real check.
function checkArchiveBoundary() {
  return { applicable: false, reason: 'NO_ARCHIVAL_IMPLEMENTED' };
}

module.exports = {
  VIOLATION_REASON,
  SEVERITY,
  severityOf,
  alertEventFor,
  mapAuditLogReason,
  mapMirrorReason,
  checkArchiveBoundary,
};
