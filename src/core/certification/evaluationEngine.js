'use strict';

/**
 * QODIQA Certification Evaluation Engine — Component #25
 *
 * Orchestrates the certification evaluation pipeline by composing existing
 * QODIQA trust primitives.  No verification logic is duplicated — this module
 * is a pure orchestration and scoring layer.
 *
 * Systems reused (no logic duplicated):
 *   attestor.js         — generateAttestation, verifyEvidencePackage, verifyChain
 *   registrar.js        — transparency log registration
 *   certificationStore  — persistence
 *
 * Scoring algorithm (deterministic, documented, reproducible):
 *
 *   Verification Controls (max 40):
 *     artifactVerification   max 15  — decision outcome of all submitted artifacts
 *     signatureVerification  max 10  — cryptographic signature status per artifact
 *     evidenceVerification   max 10  — certification eligibility of submitted evidence
 *                                      packages (H132-B: authentic + bound + positive
 *                                      original + same artifact/tenant + not repeated)
 *     chainVerification      max  5  — chain continuity result
 *
 *   Operational Controls (max 35):
 *     transparencyRegistration max 10  — proportion of attestations registered
 *     evidenceGeneration       max 15  — evidence packages submitted and eligible (H132-B)
 *     auditCoverage            max 10  — full audit trail (transparency + evidence hashes)
 *
 *   Compliance Controls (max 25):
 *     policyCompliance   max 10  — COMPLIANT status across all artifacts
 *     conformanceStatus  max 10  — CONFORMS status across all artifacts
 *     controlCoverage    max  5  — required control breadth (artifacts + evidence)
 *
 *   Total: 100 points
 *
 * Certification levels:
 *     95–100  CERTIFIED_PREMIUM
 *     80–94   CERTIFIED_PLUS
 *     60–79   CERTIFIED
 *     0–59    NOT_CERTIFIED
 *
 * Critical control failures override score — always force NOT_CERTIFIED:
 *   • No artifacts submitted
 *   • Any artifact has attestationDecision === 'NOT_ATTESTED'
 *   • Artifacts present but no ELIGIBLE evidence package (MISSING_EVIDENCE_PACKAGE;
 *     H132-B — see _evidenceEligibility)
 */

const { createHash, randomUUID } = require('crypto');
const { canonicalHash }    = require('../../../services/utils/evidencePackage');
const attestor             = require('../attestation/attestor');
const portal               = require('../verification/portal');
const { parseKeyId }       = require('../../../services/artifact/keyId');
const registrar            = require('../transparency/registrar');
const certificationStore   = require('./certificationStore');
const certificateArtifact  = require('./certificateArtifact');
const certificateStore     = require('./certificateStore');
const metrics              = require('../../observability/metrics');
const { emit }             = require('../../../services/logger');

// ── Constants ─────────────────────────────────────────────────────────────────

const CERTIFICATION_VERSION = '1.0';

// Validity period for certified decisions. Configurable via env var.
// Only applies to CERTIFIED, CERTIFIED_PLUS, CERTIFIED_PREMIUM.
// NOT_CERTIFIED decisions have no validity window.
const CERTIFICATION_VALIDITY_DAYS = (() => {
  const v = parseInt(process.env.CERTIFICATION_VALIDITY_DAYS, 10);
  return Number.isFinite(v) && v > 0 ? v : 365;
})();

const SCORE_WEIGHTS = Object.freeze({
  verificationControls: Object.freeze({
    artifactVerification:  15,
    signatureVerification: 10,
    evidenceVerification:  10,
    chainVerification:      5,
  }),
  operationalControls: Object.freeze({
    transparencyRegistration: 10,
    evidenceGeneration:       15,
    auditCoverage:            10,
  }),
  complianceControls: Object.freeze({
    policyCompliance:  10,
    conformanceStatus: 10,
    controlCoverage:    5,
  }),
});

const CERTIFICATION_LEVELS = Object.freeze({
  CERTIFIED_PREMIUM: Object.freeze({ min: 95, max: 100 }),
  CERTIFIED_PLUS:    Object.freeze({ min: 80, max: 94  }),
  CERTIFIED:         Object.freeze({ min: 60, max: 79  }),
  NOT_CERTIFIED:     Object.freeze({ min: 0,  max: 59  }),
});

// ── Main evaluation function ──────────────────────────────────────────────────

/**
 * Evaluate a set of QODIQA artifacts, evidence packages, and chain data
 * against the QODIQA certification standard.
 *
 * Orchestrates: attestor (verification) → scoring → transparency → persistence.
 * No verification logic is duplicated.
 *
 * @param {object}   input
 * @param {Array}    [input.artifacts=[]]        — QODIQA artifact objects to attest
 * @param {Array}    [input.evidencePackages=[]] — evidence packages to verify
 * @param {object}   [input.chain=null]          — { evidenceIds?, range? } for chain check
 * @param {object}   [opts]
 * @param {string}   [opts.requestedBy]
 * @param {string}   [opts.requestIp]
 * @returns {Promise<object>}  Full certification result
 */
async function evaluate(input, opts = {}) {
  const start           = Date.now();
  const certificationId = randomUUID();
  const requestedBy     = opts.requestedBy || 'external';
  const requestIp       = opts.requestIp   || null;

  const { artifacts = [], evidencePackages = [], chain = null } = input || {};

  emit('INFO', 'CERTIFICATION_STARTED', {
    certificationId,
    artifactsCount:         artifacts.length,
    evidencePackagesCount:  evidencePackages.length,
    requestedBy,
  });

  // 1. Attest each artifact — reuse attestor, no verification logic duplicated
  const attestationResults = [];
  for (const artifact of artifacts) {
    const r = await attestor.generateAttestation(artifact, { requestedBy, requestIp });
    attestationResults.push(r);
  }

  // 2. Verify each evidence package — reuse attestor. H132-B: the package
  //    verifier's `valid` is authenticity + binding to its stored original only;
  //    certification additionally requires the certification-evidence predicate
  //    (_evidenceEligibility), evaluated here and used for scoring and the gate.
  const verifiedEvidence = [];
  for (const pkg of evidencePackages) {
    const r = await attestor.verifyEvidencePackage(pkg, { requestedBy, requestIp });
    verifiedEvidence.push(r);
  }
  const evidenceResults = _evidenceEligibility(evidencePackages, verifiedEvidence, artifacts, attestationResults);

  // 3. Chain verification if requested — reuse attestor. H132-D: evidence
  //    records must belong to the tenant(s) of the submitted artifacts.
  let chainResult = null;
  if (chain && typeof chain === 'object') {
    const hasIds   = Array.isArray(chain.evidenceIds) && chain.evidenceIds.length > 0;
    const hasRange = chain.range && typeof chain.range === 'object';
    if (hasIds || hasRange) {
      chainResult = await attestor.verifyChain(chain, {
        requestedBy, requestIp, expectedTenantIds: _artifactTenants(artifacts),
      });
    }
  }

  // 4. Compute score breakdown
  const scoreBreakdown = _computeScoreBreakdown(attestationResults, evidenceResults, chainResult);
  const totalScore     = scoreBreakdown.totalScore;

  // 5. Detect critical control failures
  const criticalControlFailures = _detectCriticalFailures(attestationResults, artifacts);

  // Component #22: evidence package mandatory for certification eligibility.
  // Only checked when artifacts are present (empty artifacts already produces
  // ARTIFACT_SUBMISSION). A passing score alone is not sufficient — verifiable
  // evidence must accompany any certification claim.
  // H132-B: the requirement is met only by an ELIGIBLE package (authentic and
  // bound, positive original outcome, same artifact and tenant, not repeated) —
  // not by the mere presence of an object in evidencePackages.
  if (artifacts.length > 0 && evidencePackages.length === 0) {
    criticalControlFailures.push({
      control:  'MISSING_EVIDENCE_PACKAGE',
      reason:   'No evidence packages submitted — at least one evidence package is required for certification',
      severity: 'CRITICAL',
    });
  } else if (artifacts.length > 0 && !evidenceResults.some(r => r.eligible)) {
    criticalControlFailures.push({
      control:  'MISSING_EVIDENCE_PACKAGE',
      reason:   'No eligible evidence package submitted — at least one evidence package must be authentic, bound to a positive original verification of a submitted artifact, and belong to that artifact\'s tenant',
      severity: 'CRITICAL',
    });
  }

  const hasCriticalFailure = criticalControlFailures.length > 0;

  // 6. Determine certification level (score + critical failure check)
  const certificationLevel    = _determineCertificationLevel(totalScore, hasCriticalFailure);
  const certificationDecision = certificationLevel === 'NOT_CERTIFIED' ? 'NOT_CERTIFIED' : 'CERTIFIED';

  // 7. Collect passed / failed controls
  const { passedControls, failedControls } = _collectControls(scoreBreakdown);

  // 8. Build reference sets for the certification record
  const attestationReferences = attestationResults.map(r => ({
    attestationId:       r.attestationId,
    attestationDecision: r.attestationDecision,
    attestationType:     r.attestationType,
    transparencyId:      r.transparencyReferences?.transparencyId ?? null,
    evidencePackageHash: r.evidencePackage?.packageHash           ?? null,
  }));

  const evidenceReferences = evidenceResults.map(r => ({
    attestationId:     r.attestationId,
    valid:             r.valid,
    hashMatch:         r.integrityVerification?.match ?? false,
    transparencyId:    r.transparencyReferences?.transparencyId ?? null,
    eligible:          r.eligible,
    ineligibleReason:  r.ineligibleReason,
  }));

  const verificationReferences = {
    artifactVerifications:  attestationResults.length,
    evidenceVerifications:  evidenceResults.length,
    chainVerificationRun:   chainResult !== null,
    chainAttestationId:     chainResult?.attestationId      ?? null,
    chainDecision:          chainResult?.attestationDecision ?? null,
  };

  // 9. Assemble certification evidence package
  const durationMs  = Date.now() - start;
  const evidencePkg = assembleCertificationEvidence({
    certificationId,
    certificationLevel,
    certificationDecision,
    totalScore,
    scoreBreakdown,
    criticalControlFailures,
    passedControls,
    failedControls,
    attestationReferences,
    evidenceReferences,
    verificationReferences,
    requestedBy,
    durationMs,
  });

  // 10. Register transparency log entry — await so ID is captured before persist
  let transparencyId = null;
  try {
    const tReg = await registrar.register({
      entryType: 'SYSTEM',
      payload: {
        kind: 'CERTIFICATION',   // audit remediation 2026-10-27: 'CERTIFICATION' is not a registrable entryType (registrar + tle_entry_type_valid), so every registration was rejected; SYSTEM carries it with the kind in the payload
        certificationId,
        certificationLevel,
        certificationDecision,
        score:            totalScore,
        artifactsCount:   artifacts.length,
        criticalFailures: criticalControlFailures.length,
      },
      registeredBy: 'certification',
    });
    transparencyId = tReg.transparencyId ?? null;
  } catch (err) {
    emit('WARN', 'CERTIFICATION_TRANSPARENCY_REGISTER_FAILED', {
      certificationId,
      error: err.message,
    });
  }

  // 11. Emit metrics
  metrics.certificationsTotal.inc({ level: certificationLevel });
  if (certificationLevel === 'NOT_CERTIFIED') {
    metrics.certificationFailuresTotal.inc({
      reason: hasCriticalFailure ? 'CRITICAL_CONTROL' : 'LOW_SCORE',
    });
  }

  // 12. Compute lifecycle fields
  const generatedAt = new Date();
  const isCertified = certificationDecision === 'CERTIFIED';
  const expiresAt   = isCertified
    ? new Date(generatedAt.getTime() + CERTIFICATION_VALIDITY_DAYS * 86_400_000).toISOString()
    : null;
  const renewal     = isCertified ? 'ELIGIBLE' : 'NOT_APPLICABLE';

  // 13. Emit audit event
  emit('INFO', 'CERTIFICATION_COMPLETE', {
    certificationId,
    certificationLevel,
    certificationDecision,
    score:            totalScore,
    criticalFailures: criticalControlFailures.length,
    durationMs:       Date.now() - start,
    expiresAt,
  });

  const result = {
    certificationId,
    certificationLevel,
    certificationDecision,
    version:     CERTIFICATION_VERSION,
    generatedAt: generatedAt.toISOString(),
    expiresAt,
    renewal,
    score:       totalScore,
    scoreBreakdown,
    criticalControlFailures,
    passedControls,
    failedControls,
    attestationReferences,
    evidenceReferences,
    verificationReferences,
    evidencePackage: {
      packageHash: evidencePkg.packageHash,
      packageId:   evidencePkg.packageId,
      packageType: evidencePkg.packageType,
    },
    transparencyReferences: {
      transparencyId,
      registeredAt: transparencyId ? new Date().toISOString() : null,
    },
    metadata: {
      artifactsEvaluated:       artifacts.length,
      evidencePackagesVerified: evidencePackages.length,
      chainVerified:            chainResult !== null,
      requestedBy,
      durationMs:               Date.now() - start,
    },
  };

  // 14. Issue signed certificate artifact for CERTIFIED decisions (fire-and-forget)
  if (certificationDecision === 'CERTIFIED') {
    setImmediate(() => {
      try {
        const { bundle } = certificateArtifact.issueCertificateArtifact(result);
        certificateStore.storeCertificate(bundle).catch(err => {
          emit('WARN', 'CERTIFICATE_ARTIFACT_STORE_FAILED', { certificationId, error: err.message });
        });
      } catch (err) {
        emit('WARN', 'CERTIFICATE_ARTIFACT_ISSUE_FAILED', { certificationId, error: err.message });
      }
    });
  }

  // 15. Persist (fire-and-forget — non-blocking)
  certificationStore.recordCertification({
    certificationId,
    certificationLevel,
    certificationDecision,
    score:                  totalScore,
    scoreBreakdown,
    criticalControlFailures,
    passedControls,
    failedControls,
    evaluationResult:       result,
    attestationReferences,
    evidenceReferences,
    verificationReferences,
    evidencePackageHash:    evidencePkg.packageHash,
    transparencyId,
    artifactsCount:         artifacts.length,
    evidencePackagesCount:  evidencePackages.length,
    requestedBy,
    requestIp,
    durationMs:             Date.now() - start,
    expiresAt,
    renewal,
  }).catch(err => {
    emit('WARN', 'CERTIFICATION_PERSIST_FAILED', { certificationId, error: err.message });
    metrics.certificationPersistFailuresTotal.inc({});
  }).finally(() => _notifyCertificationCompleted({
    certificationId, certificationLevel, certificationDecision, score: totalScore,
    tenantId: _provenCertificationTenant(artifacts, attestationResults),
  }));

  return result;
}

// ── certification.completed webhook ─────────────────────────
//
// Webhook endpoints are strictly per-tenant (webhook_endpoints RLS) and
// /v1/certification/evaluate is public, so the event goes ONLY to a tenant the
// evaluation itself proved: the signing-key tenant of the artifacts that
// ATTESTED (their key/signature/time checks passed), and only when every one of
// them belongs to that same single tenant. A forged artifact can name any
// publicKeyId, so a NOT_ATTESTED artifact proves nothing and is ignored; a
// multi-tenant evaluation notifies nobody (no tenant learns about another's
// certification). null → no event (INFO). Fire-and-forget after the persist
// attempt settles; never affects the evaluation.

function _provenCertificationTenant(artifacts, attestationResults) {
  const tenants = new Set();
  artifacts.forEach((a, i) => {
    const d = attestationResults[i]?.attestationDecision;
    if (d !== 'ATTESTED' && d !== 'ATTESTED_WITH_WARNINGS') return;
    tenants.add(a && typeof a === 'object' ? _tenantOfKeyId(a.publicKeyId) : null);
  });
  return tenants.size === 1 ? [...tenants][0] : null;
}

function _notifyCertificationCompleted({ certificationId, certificationLevel, certificationDecision, score, tenantId }) {
  if (!tenantId) {
    emit('INFO', 'WEBHOOK_EVENT_NOT_DISPATCHED', {
      eventType: 'certification.completed', certificationId, reason: 'NO_PROVEN_TENANT',
    });
    return;
  }
  try {
    const dispatcher = require('../webhooks/webhookDispatcher');
    dispatcher.dispatchEvent('certification.completed', dispatcher.buildCertificationCompletedPayload({
      certificationId, level: certificationLevel, score, status: certificationDecision, tenantId,
    }));
  } catch (err) {
    emit('WARN', 'WEBHOOK_DISPATCH_FAILED', { eventType: 'certification.completed', certificationId, error: err.message });
  }
}

// ── Score computation ─────────────────────────────────────────────────────────

function _computeScoreBreakdown(attestationResults, evidenceResults, chainResult) {
  const vc = _scoreVerificationControls(attestationResults, evidenceResults, chainResult);
  const oc = _scoreOperationalControls(attestationResults, evidenceResults, chainResult);
  const cc = _scoreComplianceControls(attestationResults, evidenceResults);

  return {
    verificationControls: vc,
    operationalControls:  oc,
    complianceControls:   cc,
    totalScore:           Math.min(100, vc.score + oc.score + cc.score),
  };
}

function _scoreVerificationControls(attestationResults, evidenceResults, chainResult) {
  const W = SCORE_WEIGHTS.verificationControls;

  // ── Artifact verification (max 15) ─────────────────────────────────────────
  let artifactScore = 0;
  let artifactDetail = '';
  if (attestationResults.length === 0) {
    artifactScore  = 0;
    artifactDetail = 'No artifacts submitted — certification requires at least one artifact';
  } else {
    const attested     = attestationResults.filter(r => r.attestationDecision === 'ATTESTED').length;
    const withWarnings = attestationResults.filter(r => r.attestationDecision === 'ATTESTED_WITH_WARNINGS').length;
    const notAttested  = attestationResults.filter(r => r.attestationDecision === 'NOT_ATTESTED').length;
    if (notAttested > 0) {
      artifactScore  = 0;
      artifactDetail = `${notAttested} of ${attestationResults.length} artifact(s) NOT_ATTESTED (critical failure)`;
    } else if (withWarnings > 0) {
      artifactScore  = 10;
      artifactDetail = `${attested + withWarnings} artifact(s) pass core checks; ${withWarnings} with advisory warnings`;
    } else {
      artifactScore  = W.artifactVerification;
      artifactDetail = `All ${attested} artifact(s) ATTESTED — full score`;
    }
  }

  // ── Signature verification (max 10) ────────────────────────────────────────
  let sigScore = 0;
  let sigDetail = '';
  if (attestationResults.length === 0) {
    sigScore  = 0;
    sigDetail = 'No artifacts to verify signatures for';
  } else {
    const sigPasses = attestationResults.filter(
      r => r.cryptographicResult?.signatureVerification?.status === 'PASS',
    ).length;
    if (sigPasses === attestationResults.length) {
      sigScore  = W.signatureVerification;
      sigDetail = `All ${sigPasses} artifact signature(s) cryptographically verified`;
    } else {
      sigScore  = 0;
      sigDetail = `${attestationResults.length - sigPasses} signature verification(s) failed`;
    }
  }

  // ── Evidence verification (max 10) ─────────────────────────────────────────
  let evidScore = 0;
  let evidDetail = '';
  if (evidenceResults.length === 0) {
    evidScore  = 5; // neutral: evidence recommended but not required for base certification
    evidDetail = 'No evidence packages submitted — neutral score (5/10)';
  } else {
    // H132-B: scored on certification eligibility, not on authenticity alone.
    const validCount = evidenceResults.filter(r => r.eligible).length;
    if (validCount === evidenceResults.length) {
      evidScore  = W.evidenceVerification;
      evidDetail = `All ${validCount} evidence package(s) verified and eligible`;
    } else {
      evidScore  = Math.floor((validCount / evidenceResults.length) * W.evidenceVerification);
      evidDetail = `${validCount} of ${evidenceResults.length} evidence package(s) eligible`;
    }
  }

  // ── Chain verification (max 5) ─────────────────────────────────────────────
  let chainScore = 0;
  let chainDetail = '';
  if (!chainResult) {
    chainScore  = 3; // neutral: chain verification is optional
    chainDetail = 'Chain verification not requested — neutral score (3/5)';
  } else if (chainResult.attestationDecision === 'ATTESTED') {
    chainScore  = W.chainVerification;
    chainDetail = 'Evidence chain integrity verified — full score';
  } else {
    chainScore  = 0;
    chainDetail = 'Evidence chain integrity check failed';
  }

  const score = artifactScore + sigScore + evidScore + chainScore;
  return {
    score,
    max: W.artifactVerification + W.signatureVerification + W.evidenceVerification + W.chainVerification,
    details: {
      artifactVerification:  { score: artifactScore, max: W.artifactVerification,  detail: artifactDetail },
      signatureVerification: { score: sigScore,       max: W.signatureVerification, detail: sigDetail },
      evidenceVerification:  { score: evidScore,      max: W.evidenceVerification,  detail: evidDetail },
      chainVerification:     { score: chainScore,     max: W.chainVerification,     detail: chainDetail },
    },
  };
}

function _scoreOperationalControls(attestationResults, evidenceResults, chainResult) {
  const W = SCORE_WEIGHTS.operationalControls;

  // ── Transparency registration (max 10) ─────────────────────────────────────
  let transScore = 0;
  let transDetail = '';
  const allAtts = [...attestationResults, ...evidenceResults];
  if (allAtts.length === 0) {
    transScore  = 0;
    transDetail = 'No attestations generated — no transparency registrations to evaluate';
  } else {
    const withTrans = allAtts.filter(r => r.transparencyReferences?.transparencyId).length;
    if (withTrans === allAtts.length) {
      transScore  = W.transparencyRegistration;
      transDetail = `All ${withTrans} attestation(s) registered in transparency log`;
    } else {
      transScore  = Math.floor((withTrans / allAtts.length) * W.transparencyRegistration);
      transDetail = `${withTrans} of ${allAtts.length} attestation(s) have transparency IDs`;
    }
  }

  // ── Evidence generation (max 15) ───────────────────────────────────────────
  let evidGenScore = 0;
  let evidGenDetail = '';
  if (evidenceResults.length === 0) {
    evidGenScore  = 0;
    evidGenDetail = 'No evidence packages submitted';
  } else {
    const validCount = evidenceResults.filter(r => r.eligible).length;
    if (validCount === evidenceResults.length) {
      evidGenScore  = W.evidenceGeneration;
      evidGenDetail = `All ${validCount} evidence package(s) generated, verified and eligible`;
    } else {
      evidGenScore  = Math.floor((validCount / evidenceResults.length) * W.evidenceGeneration);
      evidGenDetail = `${validCount} of ${evidenceResults.length} evidence package(s) eligible`;
    }
  }

  // ── Audit coverage (max 10) ────────────────────────────────────────────────
  let auditScore = 0;
  let auditDetail = '';
  if (attestationResults.length === 0) {
    auditScore  = 0;
    auditDetail = 'No attestations generated — audit coverage unavailable';
  } else {
    const withTrans  = attestationResults.filter(r => r.transparencyReferences?.transparencyId).length;
    const withEvidPkg = attestationResults.filter(r => r.evidencePackage?.packageHash).length;
    const total       = attestationResults.length;

    if (withTrans === total && withEvidPkg === total) {
      auditScore  = W.auditCoverage;
      auditDetail = `Full audit coverage: all ${total} attestation(s) have transparency IDs and evidence package hashes`;
    } else if (withTrans === total) {
      auditScore  = 7;
      auditDetail = `All ${total} attestation(s) have transparency IDs; ${withEvidPkg}/${total} have evidence package hashes`;
    } else if (withEvidPkg === total) {
      auditScore  = 5;
      auditDetail = `All ${total} attestation(s) have evidence package hashes; ${withTrans}/${total} have transparency IDs`;
    } else {
      auditScore  = Math.floor(((withTrans + withEvidPkg) / (total * 2)) * W.auditCoverage);
      auditDetail = `Partial coverage: ${withTrans}/${total} transparency IDs, ${withEvidPkg}/${total} evidence hashes`;
    }
  }

  const score = transScore + evidGenScore + auditScore;
  return {
    score,
    max: W.transparencyRegistration + W.evidenceGeneration + W.auditCoverage,
    details: {
      transparencyRegistration: { score: transScore,    max: W.transparencyRegistration, detail: transDetail },
      evidenceGeneration:       { score: evidGenScore,  max: W.evidenceGeneration,       detail: evidGenDetail },
      auditCoverage:            { score: auditScore,    max: W.auditCoverage,            detail: auditDetail },
    },
  };
}

function _scoreComplianceControls(attestationResults, evidenceResults) {
  const W = SCORE_WEIGHTS.complianceControls;

  // ── Policy compliance (max 10) ─────────────────────────────────────────────
  let policyScore = 0;
  let policyDetail = '';
  if (attestationResults.length === 0) {
    policyScore  = 0;
    policyDetail = 'No artifacts evaluated for policy compliance';
  } else {
    const compliant = attestationResults.filter(
      r => r.complianceResult?.policyCompliance?.status === 'COMPLIANT',
    ).length;
    if (compliant === attestationResults.length) {
      policyScore  = W.policyCompliance;
      policyDetail = `All ${compliant} artifact(s) policy-compliant`;
    } else {
      policyScore  = Math.floor((compliant / attestationResults.length) * W.policyCompliance);
      policyDetail = `${compliant} of ${attestationResults.length} artifact(s) policy-compliant`;
    }
  }

  // ── Conformance status (max 10) ────────────────────────────────────────────
  let conformScore = 0;
  let conformDetail = '';
  if (attestationResults.length === 0) {
    conformScore  = 0;
    conformDetail = 'No artifacts evaluated for conformance';
  } else {
    const conforms = attestationResults.filter(
      r => r.complianceResult?.conformanceStatus === 'CONFORMS',
    ).length;
    if (conforms === attestationResults.length) {
      conformScore  = W.conformanceStatus;
      conformDetail = `All ${conforms} artifact(s) conform to QODIQA standard`;
    } else {
      conformScore  = Math.floor((conforms / attestationResults.length) * W.conformanceStatus);
      conformDetail = `${conforms} of ${attestationResults.length} artifact(s) conform`;
    }
  }

  // ── Control coverage (max 5) ───────────────────────────────────────────────
  // 2 pts for having artifacts, 2 pts for having evidence packages, +1 bonus for both
  const hasArtifacts = attestationResults.length > 0;
  const hasEvidence  = evidenceResults.length > 0;
  let coverageScore  = 0;
  if (hasArtifacts) coverageScore += 2;
  if (hasEvidence)  coverageScore += 2;
  if (hasArtifacts && hasEvidence) coverageScore += 1;
  const coverageDetail = `Control breadth: artifacts=${attestationResults.length}, evidence packages=${evidenceResults.length}`;

  const score = policyScore + conformScore + coverageScore;
  return {
    score,
    max: W.policyCompliance + W.conformanceStatus + W.controlCoverage,
    details: {
      policyCompliance:  { score: policyScore,   max: W.policyCompliance,  detail: policyDetail },
      conformanceStatus: { score: conformScore,   max: W.conformanceStatus, detail: conformDetail },
      controlCoverage:   { score: coverageScore,  max: W.controlCoverage,   detail: coverageDetail },
    },
  };
}

// ── Certification evidence eligibility (H132-B) ───────────────────────────────
//
// attestor.verifyEvidencePackage() proves AUTHENTICITY only: the package is
// self-consistent and bound to an existing stored original (H129-A, unchanged —
// its ATTESTED / valid keep exactly that meaning). A genuine package can still
// record a FAILED / NOT_ATTESTED verification, another artifact, or another
// tenant. Certification therefore counts a package as evidence only when ALL of:
//   1. valid                — authentic and bound to its original (H129-A);
//   2. originalFound        — the original verification record exists;
//   3. positive outcome     — the ORIGINAL's stored outcome (read by the verifier
//                             from the database, never from the caller) is
//                             VERIFIED / VERIFIED_WITH_WARNINGS (portal) or
//                             ATTESTED / ATTESTED_WITH_WARNINGS (attestation);
//   4. same artifact        — the package's artifact fingerprint equals the
//                             fingerprint of a submitted artifact that attested;
//   5. same tenant          — the package's artifactPublicKeyId equals that
//                             artifact's publicKeyId (tenant = parseKeyId().tenantId);
//   6. not repeated         — each original (verificationId) counts once per
//                             evaluation;
//   7. well-formed          — anything else (empty / malformed objects) fails 1.
// Fields 4–5 are read from the package only once 1 holds, i.e. after they are
// proven equal to the stored original's content.

const _POSITIVE_ORIGINAL_OUTCOMES = new Set([
  'VERIFIED', 'VERIFIED_WITH_WARNINGS', 'ATTESTED', 'ATTESTED_WITH_WARNINGS',
]);

function _tenantOfKeyId(keyId) {
  try { return parseKeyId(keyId).tenantId; } catch { return null; }
}

function _artifactTenants(artifacts) {
  const tenants = new Set();
  for (const a of artifacts) {
    const t = a && typeof a === 'object' ? _tenantOfKeyId(a.publicKeyId) : null;
    if (t) tenants.add(t);
  }
  return [...tenants];
}

function _evidenceEligibility(evidencePackages, verifiedEvidence, artifacts, attestationResults) {
  // Submitted artifacts that attested, by fingerprint -> publicKeyId.
  const attestedArtifacts = new Map();
  artifacts.forEach((a, i) => {
    const d = attestationResults[i]?.attestationDecision;
    if (d !== 'ATTESTED' && d !== 'ATTESTED_WITH_WARNINGS') return;
    let fp = null;
    try { fp = portal.computeArtifactFingerprint(a); } catch { fp = null; }
    if (fp) attestedArtifacts.set(fp, a.publicKeyId ?? null);
  });

  const seenOriginals = new Set();
  return verifiedEvidence.map((r, i) => {
    const pkg = evidencePackages[i];
    let ineligibleReason = null;
    if (!r.valid) {
      ineligibleReason = 'NOT_AUTHENTIC';
    } else if (!r.chainVerification?.originalFound) {
      ineligibleReason = 'ORIGINAL_NOT_FOUND';
    } else if (!_POSITIVE_ORIGINAL_OUTCOMES.has(r.chainVerification?.originalResult)) {
      ineligibleReason = 'ORIGINAL_OUTCOME_NOT_POSITIVE';
    } else if (!pkg.artifactFingerprint || !attestedArtifacts.has(pkg.artifactFingerprint)) {
      ineligibleReason = 'ARTIFACT_NOT_SUBMITTED';
    } else if (!pkg.artifactPublicKeyId
      || attestedArtifacts.get(pkg.artifactFingerprint) !== pkg.artifactPublicKeyId
      || !_tenantOfKeyId(pkg.artifactPublicKeyId)) {
      ineligibleReason = 'TENANT_MISMATCH';
    } else if (seenOriginals.has(String(pkg.verificationId))) {
      ineligibleReason = 'DUPLICATE_EVIDENCE';
    }
    if (!ineligibleReason) seenOriginals.add(String(pkg.verificationId));
    return { ...r, eligible: ineligibleReason === null, ineligibleReason };
  });
}

// ── Decision helpers ──────────────────────────────────────────────────────────

/**
 * Identify critical control failures that must force NOT_CERTIFIED.
 * A high score must never override a critical control failure.
 *
 * Critical controls:
 *   1. No artifacts submitted — evaluation cannot certify without evidence
 *   2. Any artifact NOT_ATTESTED — means a core check failed
 *      (SCHEMA, KEY_VALID, TIMESTAMP, NOT_EXPIRED, SIGNATURE, or CLOCK_SKEW)
 */
function _detectCriticalFailures(attestationResults, artifacts) {
  const failures = [];

  if (artifacts.length === 0) {
    failures.push({
      control:  'ARTIFACT_SUBMISSION',
      reason:   'No artifacts submitted — at least one QODIQA artifact is required for certification',
      severity: 'CRITICAL',
    });
    return failures;
  }

  for (const r of attestationResults) {
    if (r.attestationDecision === 'NOT_ATTESTED') {
      failures.push({
        control:       r.verificationResult?.failedCheck || 'CORE_CHECK',
        reason:        r.verificationResult?.failureReason
          || `Artifact verification failed: ${r.verificationResult?.failedCheck || 'unknown check'}`,
        severity:      'CRITICAL',
        attestationId: r.attestationId,
      });
    }
  }

  return failures;
}

/**
 * Map score + critical failure flag to a certification level.
 * Critical failures always produce NOT_CERTIFIED regardless of score.
 */
function _determineCertificationLevel(score, hasCriticalFailure) {
  if (hasCriticalFailure) return 'NOT_CERTIFIED';
  if (score >= 95) return 'CERTIFIED_PREMIUM';
  if (score >= 80) return 'CERTIFIED_PLUS';
  if (score >= 60) return 'CERTIFIED';
  return 'NOT_CERTIFIED';
}

/**
 * Partition score breakdown into passed and failed controls.
 * A control is "passed" when it achieves its maximum score; otherwise "failed".
 */
function _collectControls(scoreBreakdown) {
  const passedControls = [];
  const failedControls = [];

  const groups = [
    scoreBreakdown.verificationControls.details,
    scoreBreakdown.operationalControls.details,
    scoreBreakdown.complianceControls.details,
  ];

  for (const group of groups) {
    for (const [name, detail] of Object.entries(group)) {
      const entry = {
        control: name,
        score:   detail.score,
        max:     detail.max,
        detail:  detail.detail,
      };
      if (detail.score >= detail.max) {
        passedControls.push(entry);
      } else {
        failedControls.push(entry);
      }
    }
  }

  return { passedControls, failedControls };
}

// ── Evidence package assembly ─────────────────────────────────────────────────

/**
 * Assemble a QODIQA::CERTIFICATION_EVIDENCE::V1 package.
 *
 * packageHash is computed as canonicalHash(content) where content
 * excludes packageId, generatedAt, and packageHash — making it independently
 * verifiable from the stored content fields.
 *
 * @param {object} data  — fields to include in the package
 * @returns {object}     — complete certification evidence package
 */
function assembleCertificationEvidence(data) {
  const content = {
    packageType:              'QODIQA::CERTIFICATION_EVIDENCE::V1',
    schemaVersion:            '1.0',
    certificationId:          data.certificationId,
    certificationLevel:       data.certificationLevel,
    certificationDecision:    data.certificationDecision,
    score:                    data.totalScore,
    scoreBreakdown:           data.scoreBreakdown,
    criticalControlFailures:  data.criticalControlFailures,
    passedControls:           data.passedControls,
    failedControls:           data.failedControls,
    attestationReferences:    data.attestationReferences,
    evidenceReferences:       data.evidenceReferences,
    verificationReferences:   data.verificationReferences,
    requestedBy:              data.requestedBy,
    durationMs:               data.durationMs,
    evaluatedAt:              new Date().toISOString(),
  };

  const packageHash = canonicalHash(content);

  return {
    ...content,
    packageId:   createHash('sha256')
      .update(`${data.certificationId}:CERTIFICATION_EVIDENCE`, 'utf8')
      .digest('hex'),
    generatedAt: new Date().toISOString(),
    packageHash,
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  evaluate,
  assembleCertificationEvidence,
  CERTIFICATION_VERSION,
  SCORE_WEIGHTS,
  CERTIFICATION_LEVELS,
  // Internal exports for unit testing
  _scoreVerificationControls,
  _scoreOperationalControls,
  _scoreComplianceControls,
  _detectCriticalFailures,
  _determineCertificationLevel,
  _collectControls,
  _computeScoreBreakdown,
  CERTIFICATION_VALIDITY_DAYS,
};
