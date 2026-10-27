'use strict';

/**
 * QODIQA Public Verification Portal — Component #23
 *
 * Pure logic module: no I/O, no side effects.
 * Provides artifact fingerprinting, check execution, and report assembly.
 *
 * Check suite (in execution order):
 *   SCHEMA         — artifact fields and types are structurally valid
 *   KEY_VALID      — publicKeyId resolves to a known, non-revoked key
 *   TIMESTAMP      — timestamp is not in the future
 *   NOT_EXPIRED    — artifact has not expired
 *   SIGNATURE      — Ed25519 signature is cryptographically valid
 *   CLOCK_SKEW     — artifact was not held and replayed beyond the skew window
 *   REPLAY_CHECK   — fingerprint has not been submitted before (advisory)
 *   EVIDENCE_CHAIN — artifact_id found in the QODIQA evidence chain (advisory)
 *
 * Overall result:
 *   VERIFIED              — checks 1-6 pass, no advisory warnings
 *   VERIFIED_WITH_WARNINGS — checks 1-6 pass, one or more advisory warnings raised
 *   FAILED                — any of checks 1-6 fail
 */

const { createHash }       = require('crypto');
const { canonicalHash }    = require('../../../services/utils/evidencePackage');
const { validateArtifact } = require('../../validation/validateArtifact');

// ── Fingerprint ───────────────────────────────────────────────────────────────

/**
 * Compute a stable SHA-256 fingerprint for an artifact.
 * Used for replay detection: identical submissions share a fingerprint.
 *
 * @param {unknown} artifact
 * @returns {string}  64-char lowercase hex SHA-256
 */
function computeArtifactFingerprint(artifact) {
  return canonicalHash(artifact);
}

// ── Evidence-chain correlation ─────────────────────────────────────────
//
// An artifact's identifier is its signed payload.requestId — "artifactId is
// simply artifact.payload.requestId" (QODIQA-PROTOCOL-SPEC.md §10.11) — and
// that is the key audit_chain and evidence_chain_records are written under
// (§12.1). /sign generates it server-side (crypto.randomUUID(), overriding any
// caller value) and it is the replay nonce, so it is unique per execution.
// payload.artifactId is NOT part of the protocol: /sign accepts an open payload
// record, so it is whatever the signing caller chose. Keying on it meant a
// genuine executed artifact was never found (EVIDENCE_CHAIN WARN), while an
// artifact that embedded ANOTHER execution's id was reported VERIFIED /
// ATTESTED with that execution's evidence.

/**
 * The evidence-chain lookup key for an artifact: its signed payload.requestId.
 *
 * @param {unknown} artifact
 * @returns {string|null}
 */
function evidenceArtifactId(artifact) {
  const id = artifact?.payload?.requestId;
  return typeof id === 'string' && id ? id : null;
}

/**
 * Fetch the evidence-chain record for an artifact, or null. A record whose
 * tenant does not match the artifact's signed payload.tenantId is treated as
 * absent (defense in depth: the lookup itself reads across tenants).
 *
 * @param {unknown} artifact
 * @param {{ getByArtifactId: (id: string) => Promise<object|null> }} chainStore
 * @returns {Promise<object|null>}
 */
async function lookupEvidenceRecord(artifact, chainStore) {
  const id = evidenceArtifactId(artifact);
  if (!id) return null;
  // anonymous callers reach this; use the tenant-filtered
  // public lookup (the DB returns only a same-tenant or platform record). The
  // JS check below is kept as defence in depth. Injected test doubles that
  // only implement getByArtifactId keep working.
  const record = typeof chainStore.getPublicByArtifactId === 'function'
    ? await chainStore.getPublicByArtifactId(id, artifact?.payload?.tenantId ?? null)
    : await chainStore.getByArtifactId(id);
  if (!record) return null;
  if (record.tenant_id != null && record.tenant_id !== artifact?.payload?.tenantId) return null;
  return record;
}

// ── Check execution order ─────────────────────────────────────────────────────

const _CHECK_ORDER = Object.freeze([
  'SCHEMA',
  'KEY_VALID',
  'TIMESTAMP',
  'NOT_EXPIRED',
  'SIGNATURE',
  'CLOCK_SKEW',
]);

// Maps validateArtifact() block reasons to the first check that failed.
const _REASON_TO_FAILED_CHECK = Object.freeze({
  INVALID_ARTIFACT:    'SCHEMA',
  KEY_NOT_FOUND:       'KEY_VALID',
  PUBLIC_KEY_NOT_FOUND: 'KEY_VALID',
  FUTURE_TIMESTAMP:    'TIMESTAMP',
  TIMESTAMP_IN_FUTURE: 'TIMESTAMP',
  EXPIRED:             'NOT_EXPIRED',
  ARTIFACT_EXPIRED:    'NOT_EXPIRED',
  ARTIFACT_ALREADY_EXPIRED: 'NOT_EXPIRED',
  ARTIFACT_STALE:      'NOT_EXPIRED',
  INVALID_SIGNATURE:   'SIGNATURE',
  SIGNATURE_INVALID:   'SIGNATURE',
  CLOCK_SKEW_EXCEEDED: 'CLOCK_SKEW',
  // the reasons validateArtifact() ACTUALLY emits for these cases were missing from the map, so an
  // artifact older than the allowed window or signed with a revoked / deprecated / not-yet-active key was reported as a SCHEMA
  // failure (wrong failedCheck in the report, in the portal metrics and in the certification of the critical control).
  TIME_SKEW_EXCEEDED:  'CLOCK_SKEW',
  KEY_REVOKED:         'KEY_VALID',
  KEY_DEPRECATED:      'KEY_VALID',
  KEY_ARCHIVED:        'KEY_VALID',
  KEY_NOT_YET_ACTIVE:  'KEY_VALID',
  KEY_NOT_ACTIVE_AT_SIGNING_TIME: 'KEY_VALID',
  KEY_STATUS_UNKNOWN:  'KEY_VALID',
  SIGNING_TIME_UNKNOWN: 'KEY_VALID',
});

// ── Core check runner ─────────────────────────────────────────────────────────

/**
 * Run the full portal check suite against an artifact.
 *
 * Pure function: all external state (fingerprint lookup, evidence record) must
 * be resolved by the caller before calling this function.
 *
 * @param {unknown} artifact              — the artifact to verify
 * @param {object}  [opts]
 * @param {boolean} [opts.fingerprintSeen=false]  — true if fingerprint was seen before
 * @param {object|null} [opts.evidenceRecord=null] — evidence chain record (if PG enabled)
 * @param {boolean} [opts.pgEnabled=false]        — whether PG/evidence lookup ran
 * @param {Function} [opts._clock]                — override for deterministic testing only
 * @returns {{ valid: boolean, failedCheck: string|null, failureReason: string|null, checks: object[] }}
 */
function runPortalChecks(artifact, {
  fingerprintSeen = false,
  evidenceRecord  = null,
  pgEnabled       = false,
  _clock,
} = {}) {
  const checks = [];

  function pass(check) {
    checks.push({ check, result: 'PASS' });
  }
  function fail(check, reason) {
    checks.push({ check, result: 'FAIL', reason: reason || 'Validation failed' });
  }
  function warn(check, reason) {
    checks.push({ check, result: 'WARN', reason });
  }
  function skip(check, reason) {
    checks.push({ check, result: 'SKIP', reason });
  }

  // Run the complete validateArtifact suite (covers checks 1-6)
  const clockOpts = _clock ? { _clock } : {};
  const validation = validateArtifact(artifact, clockOpts);

  if (validation.decision === 'BLOCK') {
    const failedCheck = _REASON_TO_FAILED_CHECK[validation.reason] || 'SCHEMA';
    const failIdx     = _CHECK_ORDER.indexOf(failedCheck);

    for (let i = 0; i < _CHECK_ORDER.length; i++) {
      const c = _CHECK_ORDER[i];
      if (i < failIdx) {
        pass(c);
      } else if (i === failIdx) {
        const reason = validation.details?.issue
          || validation.details?.message
          || validation.reason;
        fail(c, reason);
      } else {
        skip(c, 'Skipped: prior check failed');
      }
    }

    // Advisory checks are skipped when core validation fails
    skip('REPLAY_CHECK',   'Skipped: core validation failed');
    skip('EVIDENCE_CHAIN', 'Skipped: core validation failed');

    return {
      valid:         false,
      failedCheck,
      failureReason: validation.reason,
      checks,
    };
  }

  // All core checks passed
  for (const c of _CHECK_ORDER) {
    pass(c);
  }

  // ── Advisory check 7: REPLAY_CHECK ──────────────────────────────────────────
  if (fingerprintSeen) {
    warn(
      'REPLAY_CHECK',
      'Artifact fingerprint was previously submitted to the verification portal. '
      + 'This may indicate a replay attempt or a duplicate verification request.',
    );
  } else {
    pass('REPLAY_CHECK');
  }

  // ── Advisory check 8: EVIDENCE_CHAIN ────────────────────────────────────────
  if (!pgEnabled) {
    skip('EVIDENCE_CHAIN', 'Evidence chain lookup unavailable: PostgreSQL not configured');
  } else if (evidenceRecord) {
    pass('EVIDENCE_CHAIN');
  } else {
    warn(
      'EVIDENCE_CHAIN',
      'Artifact not found in the QODIQA evidence chain. '
      + 'This artifact may not have been enforced through this gateway.',
    );
  }

  const hasWarnings = checks.some(c => c.result === 'WARN');

  return {
    valid:         true,
    failedCheck:   null,
    failureReason: null,
    checks,
    hasWarnings,
  };
}

// ── Report assembly ───────────────────────────────────────────────────────────

/**
 * Assemble a structured verification report from the check results.
 *
 * @param {object[]} checks        — ordered check results from runPortalChecks()
 * @param {object}   [meta]
 * @param {string}   [meta.publicKeyId]
 * @param {number}   [meta.timestampMs]
 * @param {number}   [meta.expiryMs]
 * @param {string}   [meta.artifactId]
 * @returns {{ overallResult, failedCheck, failureReason, warnings, checks, metadata }}
 */
function buildVerificationReport(checks, meta = {}) {
  const failedEntry = checks.find(c => c.result === 'FAIL');
  const warnings    = checks.filter(c => c.result === 'WARN');

  let overallResult;
  if (failedEntry) {
    overallResult = 'FAILED';
  } else if (warnings.length > 0) {
    overallResult = 'VERIFIED_WITH_WARNINGS';
  } else {
    overallResult = 'VERIFIED';
  }

  return {
    overallResult,
    failedCheck:   failedEntry?.check    ?? null,
    failureReason: failedEntry?.reason   ?? null,
    warnings:      warnings.map(w => ({ check: w.check, reason: w.reason })),
    checks,
    metadata: {
      publicKeyId:  meta.publicKeyId  ?? null,
      timestampMs:  meta.timestampMs  ?? null,
      expiryMs:     meta.expiryMs     ?? null,
      artifactId:   meta.artifactId   ?? null,
    },
  };
}

// ── Evidence package assembly ─────────────────────────────────────────────────

/**
 * Assemble a QODIQA::PORTAL_EVIDENCE::V1 package from a persisted
 * portal_verifications row.  Pure function: no I/O.
 *
 * The packageHash field covers all content fields deterministically so the
 * package can be independently verified for integrity.
 *
 * @param {object} record  — row returned by portalStore.getByVerificationId()
 * @returns {object}       — evidence package object
 */
function assemblePortalEvidencePackage(record) {
  if (!record || typeof record !== 'object') {
    throw new TypeError('assemblePortalEvidencePackage: record must be a non-null object');
  }

  const content = {
    packageType:       'QODIQA::PORTAL_EVIDENCE::V1',
    schemaVersion:     '1.0',
    verificationId:    record.verification_id   ?? record.verificationId   ?? null,
    overallResult:     record.overall_result    ?? record.overallResult    ?? null,
    failedCheck:       record.failed_check      ?? record.failedCheck      ?? null,
    failureReason:     record.failure_reason    ?? record.failureReason    ?? null,
    warnings:          record.warnings          ?? [],
    checksPerformed:   record.checks_performed  ?? record.checksPerformed  ?? [],
    artifactFingerprint: record.artifact_fingerprint ?? record.artifactFingerprint ?? null,
    artifactPublicKeyId: record.artifact_public_key_id ?? record.artifactPublicKeyId ?? null,
    artifactTimestampMs: record.artifact_timestamp_ms ?? record.artifactTimestampMs ?? null,
    artifactExpiryMs:    record.artifact_expiry_ms    ?? record.artifactExpiryMs    ?? null,
    artifactId:          record.artifact_id           ?? record.artifactId           ?? null,
    transparencyId:      record.transparency_id       ?? record.transparencyId       ?? null,
    submittedBy:         record.submitted_by          ?? record.submittedBy          ?? null,
    submissionIp:        record.submission_ip         ?? record.submissionIp         ?? null,
    durationMs:          record.duration_ms           ?? record.durationMs           ?? null,
    verifiedAt:          record.verified_at           ?? record.verifiedAt           ?? null,
  };

  const packageHash = canonicalHash(content);

  return {
    ...content,
    packageId:   createHash('sha256')
      .update(`${content.verificationId}:PORTAL_EVIDENCE`, 'utf8')
      .digest('hex'),
    generatedAt: new Date().toISOString(),
    packageHash,
  };
}

// ── Authoritative package re-assembly from stored originals (H129-A) ──────────
//
// The QODIQA::PORTAL_EVIDENCE::V1 package the system issues for an original is
// re-assembled deterministically from the stored record (packageId/generatedAt
// are excluded from packageHash). These two mappings are the single source of
// truth used by BOTH the issuing routes (GET /portal/evidence/:id and
// GET /v1/attestation/:id/evidence) and attestor.verifyEvidencePackage(), which
// binds a submitted package to its original by comparing content hashes — so an
// issuer change and the verifier can never drift apart.

// TIMESTAMPTZ columns arrive from pg as native Dates, which stableStringify()
// (canonicalHash's basis) rejects — and its twin.
function _isoOrValue(v) {
  return v instanceof Date ? v.toISOString() : v;
}

/**
 * Package for a stored portal_verifications row (as issued by
 * GET /portal/evidence/:verificationId).
 */
function assembleEvidencePackageFromPortalRecord(record) {
  return assemblePortalEvidencePackage({
    ...record,
    verified_at: _isoOrValue(record.verified_at),
  });
}

/**
 * Package for a stored attestations row (as issued by
 * GET /v1/attestation/:attestationId/evidence).
 */
function assembleEvidencePackageFromAttestationRecord(record) {
  return assemblePortalEvidencePackage({
    verification_id:        record.attestation_id,
    artifact_fingerprint:   record.artifact_fingerprint,
    artifact_public_key_id: record.artifact_public_key_id,
    artifact_timestamp_ms:  record.artifact_timestamp_ms,
    artifact_expiry_ms:     record.artifact_expiry_ms,
    artifact_id:            record.artifact_id,
    overall_result:         record.verification_result?.overallResult ?? record.attestation_decision,
    checks_performed:       record.checks_performed ?? [],
    failed_check:           record.failed_check,
    failure_reason:         record.failure_reason,
    warnings:               record.warnings ?? [],
    transparency_id:        record.transparency_id,
    submitted_by:           record.requested_by,
    submission_ip:          record.request_ip,
    duration_ms:            record.duration_ms,
    verified_at:            _isoOrValue(record.generated_at),
  });
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  computeArtifactFingerprint,
  evidenceArtifactId,
  lookupEvidenceRecord,
  runPortalChecks,
  buildVerificationReport,
  assemblePortalEvidencePackage,
  assembleEvidencePackageFromPortalRecord,
  assembleEvidencePackageFromAttestationRecord,
  _CHECK_ORDER,
  _REASON_TO_FAILED_CHECK,
};
