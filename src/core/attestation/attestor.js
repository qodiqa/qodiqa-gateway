'use strict';

/**
 * QODIQA Attestation Orchestrator — Component #24
 *
 * Orchestrates all attestation generation by composing existing QODIQA systems.
 * No verification logic is duplicated — this module is purely an orchestration
 * and result-assembly layer.
 *
 * Systems reused (no logic duplicated):
 *   portal.js          — computeArtifactFingerprint, runPortalChecks,
 *                        buildVerificationReport, assemblePortalEvidencePackage
 *   chainStore.js      — verifyEvidence, verifyChainRange
 *   attestationStore   — persistence
 *   registrar.js       — transparency log registration
 *   stableStringify    — deterministic serialisation
 *
 * Attestation decisions:
 *   ATTESTED               — all core checks pass, no advisory warnings
 *   ATTESTED_WITH_WARNINGS — core checks pass, advisory warnings raised
 *   NOT_ATTESTED           — one or more core checks failed
 */

const { randomUUID }    = require('crypto');
const { canonicalVerify } = require('../../../services/utils/evidencePackage');
const portal            = require('../verification/portal');
const chainStore        = require('../evidence/chainStore');
const attestationStore  = require('./attestationStore');
const registrar         = require('../transparency/registrar');
const pgPool            = require('../../infra/postgres/pool');
const metrics           = require('../../observability/metrics');
const { emit }          = require('../../../services/logger');
const { parseKeyId }    = require('../../../services/artifact/keyId');

// ── Constants ─────────────────────────────────────────────────────────────────

const ATTESTATION_VERSION = '1.0';

// Maps portal overallResult to attestation decision
const _DECISION_MAP = Object.freeze({
  VERIFIED:               'ATTESTED',
  VERIFIED_WITH_WARNINGS: 'ATTESTED_WITH_WARNINGS',
  FAILED:                 'NOT_ATTESTED',
});

// ── Internal helpers ──────────────────────────────────────────────────────────

// attestation.completed webhook. Webhook endpoints are strictly
// per-tenant (webhook_endpoints RLS), and these attestation routes are public,
// so the event goes ONLY to a tenant the system itself has proven for this
// attestation — never to one a caller merely claims (a forged artifact can
// name any publicKeyId). Each call site passes its proven tenant or null:
//   artifact   — the signing key's tenant, when the core key/signature/time
//                checks passed (checkResult.valid);
//   evidence   — the package's artifactPublicKeyId tenant, when the package is
//                content-bound to its stored original (attested);
//   chain      — the single tenant of the verified evidence records, when the
//                chain is valid and not cross-tenant.
// null → no event (INFO). Fire-and-forget; never affects the attestation.
function _tenantOfKeyId(keyId) {
  try { return parseKeyId(keyId).tenantId; } catch { return null; }
}

function _notifyAttestationCompleted({ attestationId, attestationType, attestationDecision, tenantId }) {
  if (!tenantId) {
    emit('INFO', 'WEBHOOK_EVENT_NOT_DISPATCHED', {
      eventType: 'attestation.completed', attestationId, attestationType, reason: 'NO_PROVEN_TENANT',
    });
    return;
  }
  try {
    const dispatcher = require('../webhooks/webhookDispatcher');
    dispatcher.dispatchEvent('attestation.completed', dispatcher.buildAttestationCompletedPayload({
      attestationId, decision: attestationDecision, tenantId,
    }));
  } catch (err) {
    emit('WARN', 'WEBHOOK_DISPATCH_FAILED', { eventType: 'attestation.completed', attestationId, error: err.message });
  }
}

// (D7 → B): persistence side effects of an attestation — the transparency
// leaf, the attestation record and (via recordAttestation().finally) the
// attestation.completed webhook. opts.persist === false (an ANONYMOUS public
// verification) swaps them for no-ops, so an unauthenticated caller receives
// the full verification result but creates nothing permanent. Every internal
// caller (certification evaluation, authenticated verifications) keeps the
// default: persist.
function _persistence(opts) {
  if (opts && opts.persist === false) {
    return { persist: false, register: async () => ({ transparencyId: null }), recordAttestation: () => Promise.resolve(null) };
  }
  return { persist: true, register: (a) => registrar.register(a), recordAttestation: (r) => attestationStore.recordAttestation(r) };
}

// Output shape for an ephemeral (not persisted) result: no ids that would
// point at records that do not exist.
function _shapeEphemeral(result, opts) {
  if (!opts || opts.persist !== false || !result || typeof result !== 'object') return result;
  const out = { ...result, attestationId: null, persisted: false };
  if (result.transparencyReferences) out.transparencyReferences = { ...result.transparencyReferences, transparencyId: null, registeredAt: null };
  return out;
}

function _cryptoResult(report, checkResult) {
  const sigCheck  = (checkResult.checks || []).find(c => c.check === 'SIGNATURE');
  const keyCheck  = (checkResult.checks || []).find(c => c.check === 'KEY_VALID');
  const tsCheck   = (checkResult.checks || []).find(c => c.check === 'TIMESTAMP');
  const expCheck  = (checkResult.checks || []).find(c => c.check === 'NOT_EXPIRED');
  const skewCheck = (checkResult.checks || []).find(c => c.check === 'CLOCK_SKEW');

  return {
    signatureVerification: {
      status:            sigCheck?.result ?? 'SKIP',
      reason:            sigCheck?.reason ?? null,
      algorithm:         'Ed25519',
    },
    keyVerification: {
      status:            keyCheck?.result ?? 'SKIP',
      reason:            keyCheck?.reason ?? null,
    },
    timestampVerification: {
      status:            tsCheck?.result  ?? 'SKIP',
      reason:            tsCheck?.reason  ?? null,
    },
    expiryVerification: {
      status:            expCheck?.result ?? 'SKIP',
      reason:            expCheck?.reason ?? null,
    },
    clockSkewVerification: {
      status:            skewCheck?.result ?? 'SKIP',
      reason:            skewCheck?.reason ?? null,
    },
  };
}

function _complianceResult(report, evidenceRecord) {
  const coreChecks = (report.checks || []).filter(c =>
    ['SCHEMA', 'KEY_VALID', 'TIMESTAMP', 'NOT_EXPIRED', 'SIGNATURE', 'CLOCK_SKEW'].includes(c.check),
  );
  const allCorePass = coreChecks.every(c => c.result === 'PASS');

  return {
    policyCompliance: {
      status:         allCorePass ? 'COMPLIANT' : 'NON_COMPLIANT',
      coreChecksPassed: coreChecks.filter(c => c.result === 'PASS').length,
      totalCoreChecks:  coreChecks.length,
    },
    evidenceChainStatus: {
      present:        !!evidenceRecord,
      evidenceId:     evidenceRecord?.evidence_id ?? null,
      artifactId:     evidenceRecord?.artifact_id ?? null,
    },
    conformanceStatus: allCorePass ? 'CONFORMS' : 'DOES_NOT_CONFORM',
    verificationStatus: report.overallResult,
  };
}

function _chainResult(evidenceRecord) {
  if (!evidenceRecord) {
    return {
      chainPresent:   false,
      evidenceId:     null,
      artifactId:     null,
      chainHash:      null,
      chainDecision:  null,
    };
  }
  return {
    chainPresent:   true,
    evidenceId:     evidenceRecord.evidence_id   ?? null,
    artifactId:     evidenceRecord.artifact_id   ?? null,
    chainHash:      evidenceRecord.evidence_hash ?? null,
    chainDecision:  evidenceRecord.decision      ?? null,
  };
}

// ── generateAttestation ───────────────────────────────────────────────────────

/**
 * Generate a QODIQA attestation for a given artifact.
 *
 * Orchestrates existing systems: portal check suite → evidence chain lookup →
 * transparency registration → evidence package assembly → persistence.
 *
 * @param {unknown} artifact             — the QODIQA artifact to attest
 * @param {object}  [opts]
 * @param {string}  [opts.requestedBy]   — caller identifier for audit
 * @param {string}  [opts.requestIp]     — caller IP for audit
 * @returns {Promise<object>}            — attestation result object
 */
async function generateAttestation(artifact, opts = {}) {
  return _shapeEphemeral(await _generateAttestation(artifact, opts), opts);
}
async function _generateAttestation(artifact, opts = {}) {
  const start         = Date.now();
  const attestationId = randomUUID();
  const P             = _persistence(opts);

  emit('INFO', 'ATTESTATION_STARTED', {
    attestationId,
    attestationType: 'ARTIFACT_VERIFICATION',
    requestedBy: opts.requestedBy || 'external',
  });

  // 1. Compute fingerprint for replay detection (reuse portal logic)
  const fingerprint = portal.computeArtifactFingerprint(artifact);

  // 2. Replay + evidence chain lookups (parallel, best-effort)
  const isPgEnabled   = pgPool.isEnabled();
  let priorAttestation = null;
  let evidenceRecord   = null;

  if (isPgEnabled) {
    const [priorRes, evidenceRes] = await Promise.allSettled([
      attestationStore.getByFingerprint(fingerprint),
      // keyed on the signed payload.requestId (see portal.lookupEvidenceRecord).
      portal.lookupEvidenceRecord(artifact, chainStore),
    ]);

    if (priorRes.status === 'fulfilled') priorAttestation = priorRes.value;
    if (evidenceRes.status === 'fulfilled') evidenceRecord = evidenceRes.value;
  }

  // 3. Run portal check suite (no duplication — reuse runPortalChecks)
  const checkResult = portal.runPortalChecks(artifact, {
    fingerprintSeen: !!priorAttestation,
    evidenceRecord,
    pgEnabled:       isPgEnabled,
  });

  // 4. Build verification report (reuse buildVerificationReport)
  const artMeta = {
    publicKeyId: typeof artifact?.publicKeyId === 'string' ? artifact.publicKeyId : null,
    timestampMs: typeof artifact?.timestamp   === 'number' ? artifact.timestamp   : null,
    expiryMs:    typeof artifact?.expiry      === 'number' ? artifact.expiry      : null,
    artifactId:  portal.evidenceArtifactId(artifact),
  };

  const report = portal.buildVerificationReport(checkResult.checks, artMeta);

  // 5. Map to attestation decision
  const attestationDecision = _DECISION_MAP[report.overallResult] ?? 'NOT_ATTESTED';

  // 6. Assemble structured result payloads
  const cryptographicResult = _cryptoResult(report, checkResult);
  // an evidence record is only correlated to an artifact that passed
  // core (signature/key/time) validation. Otherwise any caller could put a
  // known requestId into an unsigned artifact and read that execution's
  // evidence id/hash/decision back from this public endpoint (reproduced live).
  const correlatedEvidence  = checkResult.valid ? evidenceRecord : null;
  const complianceResult    = _complianceResult(report, correlatedEvidence);
  const chainResult         = _chainResult(correlatedEvidence);

  // 7. Register transparency log entry (await: ID needed for persistence)
  let transparencyId = null;
  try {
    const tReg = await P.register({
      entryType:    'VERIFICATION',
      payload:      {
        attestationId,
        attestationDecision,
        overallResult:   report.overallResult,
        failedCheck:     report.failedCheck,
        artifactId:      artMeta.artifactId,
        publicKeyId:     artMeta.publicKeyId,
        fingerprintSeen: !!priorAttestation,
      },
      registeredBy: 'attestation',
    });
    transparencyId = tReg.transparencyId ?? null;
  } catch (err) {
    emit('WARN', 'ATTESTATION_TRANSPARENCY_REGISTER_FAILED', {
      attestationId,
      error: err.message,
    });
  }

  // 8. Assemble evidence package (reuse assemblePortalEvidencePackage)
  const evidencePkg = portal.assemblePortalEvidencePackage({
    verification_id:        attestationId,
    artifact_fingerprint:   fingerprint,
    artifact_public_key_id: artMeta.publicKeyId,
    artifact_timestamp_ms:  artMeta.timestampMs,
    artifact_expiry_ms:     artMeta.expiryMs,
    artifact_id:            artMeta.artifactId,
    overall_result:         report.overallResult,
    checks_performed:       report.checks,
    failed_check:           report.failedCheck,
    failure_reason:         report.failureReason,
    warnings:               report.warnings,
    transparency_id:        transparencyId,
    submitted_by:           opts.requestedBy || 'external',
    submission_ip:          opts.requestIp   || null,
    duration_ms:            Date.now() - start,
    verified_at:            new Date().toISOString(),
  });

  const durationMs = Date.now() - start;

  // 9. Emit metrics
  metrics.attestationsTotal.inc({ decision: attestationDecision });
  if (attestationDecision === 'NOT_ATTESTED') {
    metrics.attestationFailuresTotal.inc({ failed_check: report.failedCheck || 'UNKNOWN' });
  }

  // 10. Emit audit event
  emit('INFO', 'ATTESTATION_COMPLETE', {
    attestationId,
    attestationDecision,
    overallResult: report.overallResult,
    failedCheck:   report.failedCheck,
    durationMs,
  });

  // 11. Persist attestation record (fire-and-forget, non-blocking)
  P.recordAttestation({
    attestationId,
    attestationType:    'ARTIFACT_VERIFICATION',
    version:            ATTESTATION_VERSION,
    artifactFingerprint: fingerprint,
    artifactPublicKeyId: artMeta.publicKeyId,
    artifactTimestampMs: artMeta.timestampMs,
    artifactExpiryMs:    artMeta.expiryMs,
    artifactId:          artMeta.artifactId,
    attestationDecision,
    verificationResult:  report,
    cryptographicResult,
    complianceResult,
    chainResult,
    checksPerformed:     report.checks,
    warnings:            report.warnings,
    failedCheck:         report.failedCheck,
    failureReason:       report.failureReason,
    transparencyId,
    evidencePackageHash: evidencePkg.packageHash,
    requestedBy:         opts.requestedBy || 'external',
    requestIp:           opts.requestIp   || null,
    durationMs,
  }).catch(err => {
    emit('WARN', 'ATTESTATION_PERSIST_FAILED', { attestationId, error: err.message });
    metrics.attestationPersistFailuresTotal.inc({});
  }).finally(() => P.persist && _notifyAttestationCompleted({
    attestationId, attestationType: 'ARTIFACT_VERIFICATION', attestationDecision,
    tenantId: checkResult.valid ? _tenantOfKeyId(artMeta.publicKeyId) : null,
  }));

  return {
    attestationId,
    attestationType:  'ARTIFACT_VERIFICATION',
    version:          ATTESTATION_VERSION,
    generatedAt:      new Date().toISOString(),
    attestationDecision,
    verificationResult: {
      overallResult: report.overallResult,
      failedCheck:   report.failedCheck,
      failureReason: report.failureReason,
      warnings:      report.warnings,
      checks:        report.checks,
    },
    cryptographicResult,
    complianceResult,
    chainResult,
    transparencyReferences: {
      transparencyId,
      registeredAt: transparencyId ? new Date().toISOString() : null,
    },
    evidencePackage: {
      packageHash:  evidencePkg.packageHash,
      packageId:    evidencePkg.packageId,
      packageType:  evidencePkg.packageType,
    },
    metadata: {
      publicKeyId:  artMeta.publicKeyId,
      timestampMs:  artMeta.timestampMs,
      expiryMs:     artMeta.expiryMs,
      artifactId:   artMeta.artifactId,
      durationMs,
    },
  };
}

// ── verifyEvidencePackage ─────────────────────────────────────────────────────

/**
 * Verify a QODIQA evidence package against its stored original.
 *
 * ATTESTED only when (H129-A, design decision Option B) the package is
 * self-consistent (packageHash recomputes), its original record exists, AND its
 * content hash equals the package the system issues for that original,
 * re-assembled from the stored record. The self-hash alone is unkeyed and
 * caller-computable, so it never suffices.
 *
 * @param {object} pkg   — evidence package as returned by the evidence endpoint
 * @param {object} [opts]
 * @param {string} [opts.requestedBy]
 * @param {string} [opts.requestIp]
 * @returns {Promise<object>}   — evidence verification result
 */
async function verifyEvidencePackage(pkg, opts = {}) {
  return _shapeEphemeral(await _verifyEvidencePackage(pkg, opts), opts);
}
async function _verifyEvidencePackage(pkg, opts = {}) {
  const start         = Date.now();
  const attestationId = randomUUID();
  const P             = _persistence(opts);

  emit('INFO', 'ATTESTATION_EVIDENCE_VERIFY_STARTED', { attestationId });

  // 1. Structural validation
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    return {
      attestationId,
      attestationType: 'EVIDENCE_VERIFICATION',
      valid:           false,
      failureReason:   'Evidence package must be a non-null object',
      integrityVerification: null,
      chainVerification:     null,
      durationMs:      Date.now() - start,
    };
  }

  if (pkg.packageType !== 'QODIQA::PORTAL_EVIDENCE::V1') {
    return {
      attestationId,
      attestationType: 'EVIDENCE_VERIFICATION',
      valid:           false,
      failureReason:   `Unsupported package type: ${pkg.packageType}`,
      integrityVerification: null,
      chainVerification:     null,
      durationMs:      Date.now() - start,
    };
  }

  // 2. Integrity verification: recompute packageHash from content fields
  const integrity = canonicalVerify(pkg);
  const hashMatch = integrity.match;

  const integrityVerification = {
    computedHash: integrity.computedHash,
    providedHash: integrity.providedHash,
    match:        hashMatch,
    algorithm:    integrity.algorithm,
  };

  // 3. Original record lookup (attestation store first, then portal store).
  //    A lookup failure leaves no original — which can never attest (step 4).
  let originalRecord = null;
  let originalSource = null;
  if (pkg.verificationId && isPgReady()) {
    try {
      const attStore  = require('./attestationStore');
      const portStore = require('../verification/portalStore');
      const att = await attStore.getByAttestationId(pkg.verificationId);
      if (att) {
        originalRecord = att; originalSource = 'attestation';
      } else {
        const pv = await portStore.getByVerificationId(pkg.verificationId);
        if (pv) { originalRecord = pv; originalSource = 'portal'; }
      }
    } catch { /* lookup failed — no original */ }
  }

  // 4. H129-A (design decision, Option B): bind the package to its original.
  //    packageHash is an unkeyed SHA-256 any caller can compute, so a
  //    self-consistent package proves nothing on its own. The authoritative
  //    package is re-assembled from the STORED original with the exact mapping
  //    the issuing route uses (portal.js), and the submitted content hash must
  //    equal it — binding every content field (decision/overallResult,
  //    artifact fingerprint and id, artifactPublicKeyId = tenant key,
  //    transparencyId, checks, ...) to the original. The authoritative hash is
  //    never returned.
  let contentBound = false;
  if (hashMatch && originalRecord) {
    try {
      const authoritative = originalSource === 'attestation'
        ? portal.assembleEvidencePackageFromAttestationRecord(originalRecord)
        : portal.assembleEvidencePackageFromPortalRecord(originalRecord);
      contentBound = authoritative.packageHash === integrity.computedHash;
    } catch { contentBound = false; }
  }
  const attested = hashMatch && !!originalRecord && contentBound;

  const chainVerification = {
    originalFound:  !!originalRecord,
    originalResult: originalRecord?.attestation_decision
      || originalRecord?.overall_result
      || null,
    verificationId: pkg.verificationId ?? null,
    contentBound,
  };

  const attestationDecision = attested ? 'ATTESTED' : 'NOT_ATTESTED';
  const failedCheck = !hashMatch ? 'INTEGRITY'
    : !originalRecord ? 'ORIGINAL_NOT_FOUND'
    : !contentBound ? 'ORIGINAL_BINDING'
    : null;
  const failureReason = {
    INTEGRITY:          'Package hash mismatch: evidence package has been tampered',
    ORIGINAL_NOT_FOUND: 'Original verification record not found: package cannot be bound to an original',
    ORIGINAL_BINDING:   'Package content does not match the stored original record',
  }[failedCheck] ?? null;
  const durationMs          = Date.now() - start;

  emit('INFO', 'ATTESTATION_EVIDENCE_VERIFY_COMPLETE', {
    attestationId,
    hashMatch,
    originalFound: !!originalRecord,
    contentBound,
    durationMs,
  });

  metrics.attestationsTotal.inc({ decision: attestationDecision });
  metrics.attestationEvidenceVerificationsTotal.inc({ result: attested ? 'VALID' : 'INVALID' });

  // Register transparency (non-blocking)
  let transparencyId = null;
  try {
    const tReg = await P.register({
      entryType:    'VERIFICATION',
      payload:      {
        attestationId,
        attestationType:  'EVIDENCE_VERIFICATION',
        attestationDecision,
        hashMatch,
        packageType:      pkg.packageType,
        verificationId:   pkg.verificationId ?? null,
      },
      registeredBy: 'attestation',
    });
    transparencyId = tReg.transparencyId ?? null;
  } catch { /* non-fatal */ }

  // Persist evidence attestation (fire-and-forget)
  P.recordAttestation({
    attestationId,
    attestationType:    'EVIDENCE_VERIFICATION',
    version:            ATTESTATION_VERSION,
    artifactFingerprint: null,
    attestationDecision,
    verificationResult:  {
      packageType:    pkg.packageType,
      verificationId: pkg.verificationId ?? null,
      overallResult:  originalRecord?.attestation_decision || originalRecord?.overall_result || null,
    },
    cryptographicResult: integrityVerification,
    complianceResult:    chainVerification,
    chainResult:         {},
    checksPerformed:     [],
    warnings:            [],
    failedCheck,
    failureReason,
    transparencyId,
    evidencePackageHash: pkg.packageHash ?? null,
    requestedBy:         opts.requestedBy || 'external',
    requestIp:           opts.requestIp   || null,
    durationMs,
  }).catch(err => {
    emit('WARN', 'ATTESTATION_PERSIST_FAILED', { attestationId, error: err.message });
    metrics.attestationPersistFailuresTotal.inc({});
  }).finally(() => P.persist && _notifyAttestationCompleted({
    attestationId, attestationType: 'EVIDENCE_VERIFICATION', attestationDecision,
    tenantId: attested ? _tenantOfKeyId(pkg.artifactPublicKeyId) : null,
  }));

  return {
    attestationId,
    attestationType:      'EVIDENCE_VERIFICATION',
    version:              ATTESTATION_VERSION,
    generatedAt:          new Date().toISOString(),
    attestationDecision,
    // H129-A: `valid` is the bound verdict (certification scores packages on
    // it); integrityVerification.match still reports the bare self-hash check.
    valid:                attested,
    integrityVerification,
    chainVerification,
    transparencyReferences: { transparencyId },
    durationMs,
  };
}

// ── verifyChain ───────────────────────────────────────────────────────────────

/**
 * Verify evidence chain integrity by reusing chainStore.
 *
 * Accepts either an array of evidenceIds for per-record verification or a
 * { startId, endId } range for bulk chain continuity validation. Only the
 * former can yield ATTESTED, and only when every requested record is VALID
 *.
 *
 * @param {object}   input
 * @param {string[]} [input.evidenceIds]           — specific evidence IDs to verify
 * @param {object}   [input.range]                 — { startId, endId } range
 * @param {number}   [input.range.startId]
 * @param {number}   [input.range.endId]
 * @param {object}   [opts]
 * @param {string}   [opts.requestedBy]
 * @param {string}   [opts.requestIp]
 * @returns {Promise<object>}  — chain verification result
 */
async function verifyChain(input, opts = {}) {
  return _shapeEphemeral(await _verifyChain(input, opts), opts);
}
async function _verifyChain(input, opts = {}) {
  const start         = Date.now();
  const attestationId = randomUUID();
  const P             = _persistence(opts);

  emit('INFO', 'ATTESTATION_CHAIN_VERIFY_STARTED', { attestationId });

  const { evidenceIds = [], range = null } = input || {};

  const requestedIds     = Array.isArray(evidenceIds) ? evidenceIds : [];
  const perRecordResults = [];
  let   rangeResult      = null;

  // H132-D: request integrity for explicit evidenceIds. A repeated id carries no
  // meaning and must not inflate the verified count, and a set spanning more than
  // one tenant (or, with a tenant context such as certification's submitted
  // artifacts, any record outside it) is an integrity failure — never ATTESTED.
  const expectedTenants = Array.isArray(opts.expectedTenantIds) ? opts.expectedTenantIds : null;
  const distinctIds     = [...new Set(requestedIds)];
  const requestIntegrity = {
    duplicateIds:      distinctIds.length !== requestedIds.length,
    crossTenant:       false,
  };

  // (D6): the single tenant proven by the verified evidence records, if any.
  let chainTenant = null;

  // Per-record verification (reuse chainStore.verifyEvidence — no duplication)
  if (requestedIds.length > 0) {
    const ids = distinctIds.slice(0, 50); // cap at 50 per request
    const tenants = new Set();
    for (const evidenceId of ids) {
      try {
        const r = await chainStore.verifyEvidence(evidenceId, {
          verifiedBy: opts.requestedBy || 'attestation',
        });
        perRecordResults.push(_redactVerifierHashes({ evidenceId, ...r }));
        if (r.result === 'VALID') {
          const rec = await chainStore.getByEvidenceId(evidenceId);
          const t = rec ? (rec.tenant_id ?? null) : null;
          tenants.add(t);
          if (expectedTenants && !expectedTenants.includes(t)) requestIntegrity.crossTenant = true;
        }
      } catch {
        // H132-D: never echo a raw driver/PostgreSQL message to the caller.
        perRecordResults.push({
          evidenceId,
          result:        'ERROR',
          failureReason: 'Evidence record could not be verified',
        });
      }
    }
    if (tenants.size > 1) requestIntegrity.crossTenant = true;
    if (tenants.size === 1) chainTenant = [...tenants][0];
  }

  // Range continuity check (reuse chainStore.verifyChainRange — no duplication)
  if (range && typeof range === 'object') {
    try {
      rangeResult = await chainStore.verifyChainRange({
        startId:    range.startId,
        endId:      range.endId,
        limit:      range.limit ?? 1000,
        verifiedBy: opts.requestedBy || 'attestation',
        tenantId:   expectedTenants && expectedTenants.length === 1 ? expectedTenants[0] : undefined,
      });
      rangeResult = { ...rangeResult, failureDetail: _redactHexHashes(rangeResult.failureDetail) };
    } catch {
      // H132-D: generic detail — the raw PostgreSQL error text is logged, not returned.
      rangeResult = {
        valid:          false,
        complete:       false,
        requestedCount: null,
        retrievedCount: 0,
        checkedCount:   0,
        failureId:      null,
        failureDetail:  'Range verification failed',
      };
    }
  }

  // (design decision, Option A): ATTESTED is a positive verification
  // result, never the mere absence of an INVALID one. It requires at least one
  // requested evidence record, every requested record verified (none dropped by
  // the 50-id cap), and every result exactly VALID — ERROR (incl. an unknown
  // id), PARTIAL, INVALID or anything else is NOT_ATTESTED. A range is a chain
  // continuity check only: its records never receive a per-record VALID verdict
  // (and an empty range requests records that do not exist), so any request
  // containing a range is NOT_ATTESTED; rangeResult is still reported.
  const rangeRequested = !!(range && typeof range === 'object');
  const valid = requestedIds.length > 0
    && !requestIntegrity.duplicateIds
    && !requestIntegrity.crossTenant
    && perRecordResults.length === requestedIds.length
    && perRecordResults.every(r => r.result === 'VALID')
    && !rangeRequested;

  const attestationDecision = valid ? 'ATTESTED' : 'NOT_ATTESTED';
  const durationMs          = Date.now() - start;

  emit('INFO', 'ATTESTATION_CHAIN_VERIFY_COMPLETE', {
    attestationId,
    attestationDecision,
    perRecordCount: perRecordResults.length,
    hasRangeCheck:  !!rangeResult,
    durationMs,
  });

  metrics.attestationsTotal.inc({ decision: attestationDecision });
  metrics.attestationChainVerificationsTotal.inc({ result: valid ? 'VALID' : 'INVALID' });

  // Register transparency (non-blocking)
  let transparencyId = null;
  try {
    const tReg = await P.register({
      entryType:    'VERIFICATION',
      payload:      {
        attestationId,
        attestationType: 'CHAIN_VERIFICATION',
        attestationDecision,
        evidenceCount:   perRecordResults.length,
        rangeChecked:    !!rangeResult,
      },
      registeredBy: 'attestation',
    });
    transparencyId = tReg.transparencyId ?? null;
  } catch { /* non-fatal */ }

  // Persist chain attestation (fire-and-forget)
  P.recordAttestation({
    attestationId,
    attestationType:    'CHAIN_VERIFICATION',
    version:            ATTESTATION_VERSION,
    artifactFingerprint: null,
    attestationDecision,
    verificationResult:  { perRecordResults, rangeResult },
    cryptographicResult: {},
    complianceResult:    {},
    chainResult:         { perRecordResults, rangeResult, requestIntegrity, valid },
    checksPerformed:     [],
    warnings:            [],
    failedCheck:         valid ? null : 'CHAIN_INTEGRITY',
    failureReason:       valid ? null : 'Chain integrity validation failed',
    transparencyId,
    evidencePackageHash: null,
    requestedBy:         opts.requestedBy || 'external',
    requestIp:           opts.requestIp   || null,
    durationMs,
  }).catch(err => {
    emit('WARN', 'ATTESTATION_PERSIST_FAILED', { attestationId, error: err.message });
    metrics.attestationPersistFailuresTotal.inc({});
  }).finally(() => P.persist && _notifyAttestationCompleted({
    attestationId, attestationType: 'CHAIN_VERIFICATION', attestationDecision,
    tenantId: (valid && !range && !requestIntegrity.crossTenant) ? chainTenant : null,
  }));

  return {
    attestationId,
    attestationType:    'CHAIN_VERIFICATION',
    version:            ATTESTATION_VERSION,
    generatedAt:        new Date().toISOString(),
    attestationDecision,
    chainIntegrity: {
      valid,
      perRecordResults,
      rangeResult,
      requestIntegrity,
    },
    transparencyReferences: { transparencyId },
    verificationPath: {
      evidenceIdsChecked: perRecordResults.map(r => r.evidenceId),
      rangeChecked:       rangeResult
        ? { startId: range?.startId, endId: range?.endId, checkedCount: rangeResult.checkedCount }
        : null,
    },
    durationMs,
  };
}

// ── Historical attestation advisory (H129-A, retrieval-time flag) ─────────────
//
// EVIDENCE_VERIFICATION attestations decided before H129-A attested on the
// unkeyed package self-hash alone. They are never rewritten; retrieval flags
// them instead. The discriminator is data, not dates: every record written by
// the bound verifier stores complianceResult.contentBound; the pre-fix code
// never did. Only ATTESTED records are flagged — a pre-fix NOT_ATTESTED was a
// genuine integrity failure and stays accurate.
const UNBOUND_PACKAGE_ADVISORY = Object.freeze({
  code:     'EVIDENCE_PACKAGE_NOT_BOUND_TO_ORIGINAL',
  message:  'Generated before evidence packages were bound to their original record (H129-A): '
          + 'this ATTESTED decision rests only on an unkeyed package self-hash and does not establish '
          + 'that the package matches its original. The stored record is unchanged.',
  storedDecisionUnchanged: true,
});

function historicalIntegrityAdvisory(record) {
  if (!record || record.attestation_type !== 'EVIDENCE_VERIFICATION') return null;
  if (record.attestation_decision !== 'ATTESTED') return null;
  const cr = record.compliance_result;
  if (cr && typeof cr === 'object' && Object.prototype.hasOwnProperty.call(cr, 'contentBound')) return null;
  return UNBOUND_PACKAGE_ADVISORY;
}

/** Response copy of a stored attestation row with the advisory attached (row itself untouched). */
function withIntegrityAdvisory(record) {
  const advisory = historicalIntegrityAdvisory(record);
  return advisory ? { ...record, integrityAdvisory: advisory } : record;
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function isPgReady() {
  try { return pgPool.isEnabled(); } catch { return false; }
}

// (evidence-verifier RLS): verifyChain() backs the UNAUTHENTICATED
// POST /v1/attestation/chain/verify, and its result is persisted and served by
// the equally public GET /v1/attestation/:attestationId. Verifier diagnostics
// embed stored/recomputed hash values of evidence and audit records that belong
// to some tenant, which an anonymous caller does not own — redact every 64-hex
// value from the public copy. Step names and PASS/FAIL/SKIP results are
// unchanged; the RBAC-gated /evidence-chain route keeps full diagnostics.
const _HEX64 = /\b[0-9a-fA-F]{64}\b/g;

function _redactHexHashes(s) {
  return typeof s === 'string' ? s.replace(_HEX64, '[redacted]') : s;
}

function _redactVerifierHashes(r) {
  const redactSteps = (arr) => (Array.isArray(arr)
    ? arr.map((st) => (st && typeof st.reason === 'string' ? { ...st, reason: _redactHexHashes(st.reason) } : st))
    : arr);
  return {
    ...r,
    failureReason: _redactHexHashes(r.failureReason),
    stepsFailed:   redactSteps(r.stepsFailed),
    steps:         redactSteps(r.steps),
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  generateAttestation,
  verifyEvidencePackage,
  verifyChain,
  historicalIntegrityAdvisory,
  withIntegrityAdvisory,
  ATTESTATION_VERSION,
  _DECISION_MAP,
};
