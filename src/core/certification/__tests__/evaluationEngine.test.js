'use strict';

/**
 * Unit tests for Component #25 — Certification Evaluation Engine
 *
 * CE-01..CE-15  Constants and exports
 * CE-16..CE-35  _scoreVerificationControls
 * CE-36..CE-52  _scoreOperationalControls
 * CE-53..CE-65  _scoreComplianceControls
 * CE-66..CE-72  _detectCriticalFailures
 * CE-73..CE-79  _determineCertificationLevel
 * CE-80..CE-83  _collectControls
 * CE-84..CE-86  _computeScoreBreakdown
 * CE-87..CE-93  assembleCertificationEvidence
 * CE-94..CE-110 evaluate() — end-to-end with mocked dependencies
 * CE-111..CE-115 certificationStore PG-disabled behaviour
 */

// ── Mock external dependencies ────────────────────────────────────────────────

jest.mock('../../attestation/attestor');
jest.mock('../../transparency/registrar');
jest.mock('../certificationStore');
jest.mock('../../../observability/metrics', () => ({
  certificationsTotal:              { inc: jest.fn() },
  certificationFailuresTotal:       { inc: jest.fn() },
  certificationPersistFailuresTotal:{ inc: jest.fn() },
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../infra/postgres/pool', () => ({
  isEnabled: jest.fn().mockReturnValue(false),
  query:     jest.fn(),
}));

const attestor           = require('../../attestation/attestor');
const registrar          = require('../../transparency/registrar');
const certificationStore = require('../certificationStore');
const metrics            = require('../../../observability/metrics');
const pgPool             = require('../../../infra/postgres/pool');

const {
  evaluate,
  assembleCertificationEvidence,
  CERTIFICATION_VERSION,
  SCORE_WEIGHTS,
  CERTIFICATION_LEVELS,
  _scoreVerificationControls,
  _scoreOperationalControls,
  _scoreComplianceControls,
  _detectCriticalFailures,
  _determineCertificationLevel,
  _collectControls,
  _computeScoreBreakdown,
} = require('../evaluationEngine');

// ── Test data factories ───────────────────────────────────────────────────────

let _id = 0;
function uid() { return `id-${++_id}`; }

function makeAttestation(overrides = {}) {
  return {
    attestationId:       `att-${uid()}`,
    attestationDecision: 'ATTESTED',
    attestationType:     'ARTIFACT_VERIFICATION',
    transparencyReferences: { transparencyId: `trans-${uid()}` },
    evidencePackage:     { packageHash: 'a'.repeat(64) },
    cryptographicResult: { signatureVerification: { status: 'PASS' } },
    complianceResult: {
      policyCompliance:  { status: 'COMPLIANT' },
      conformanceStatus: 'CONFORMS',
    },
    verificationResult: { failedCheck: null, failureReason: null },
    ...overrides,
  };
}

// H132-B: the scoring helpers consume certification ELIGIBILITY (computed by
// evaluate() via _evidenceEligibility), not the package verifier's `valid`
// alone. For the helper-level tests an eligible result is a valid one unless a
// test says otherwise.
function makeEvidenceResult(overrides = {}) {
  const valid = overrides.valid ?? true;
  return {
    attestationId:       `ev-att-${uid()}`,
    valid,
    eligible:            valid,
    attestationDecision: 'ATTESTED',
    transparencyReferences: { transparencyId: `ev-trans-${uid()}` },
    integrityVerification: { match: true },
    chainVerification:   { originalFound: true, originalResult: 'VERIFIED', contentBound: true },
    ...overrides,
  };
}

// H132-B: an artifact plus a package genuinely about it (same fingerprint and
// tenant key) — what evaluate() now requires before a package counts. Using
// `{}` for both (the previous fixture) is exactly the H132-B defect.
const { computeArtifactFingerprint } = require('../../verification/portal');
function makeBoundPair(tenant = 'tenant-a') {
  const artifact = { payload: { requestId: uid() }, publicKeyId: `${tenant}:key_v1`, signature: 'sig' };
  const pkg = {
    packageType:         'QODIQA::PORTAL_EVIDENCE::V1',
    verificationId:      `ver-${uid()}`,
    artifactFingerprint: computeArtifactFingerprint(artifact),
    artifactPublicKeyId: artifact.publicKeyId,
  };
  return { artifact, pkg };
}

function makeChainResult(overrides = {}) {
  return {
    attestationId:       `chain-att-${uid()}`,
    attestationDecision: 'ATTESTED',
    ...overrides,
  };
}

// ── beforeEach ────────────────────────────────────────────────────────────────

beforeEach(() => {
  jest.clearAllMocks();

  // Default mock behaviours for evaluate() tests
  attestor.generateAttestation.mockResolvedValue(makeAttestation());
  attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult());
  attestor.verifyChain.mockResolvedValue(makeChainResult());
  registrar.register.mockResolvedValue({ transparencyId: 'trans-reg-001' });
  certificationStore.recordCertification.mockResolvedValue({ id: 1 });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-01..CE-15  Constants and exports
// ─────────────────────────────────────────────────────────────────────────────

describe('Constants and exports', () => {
  test('CE-01 CERTIFICATION_VERSION is 1.0', () => {
    expect(CERTIFICATION_VERSION).toBe('1.0');
  });

  test('CE-02 SCORE_WEIGHTS verificationControls sums to 40', () => {
    const vc = SCORE_WEIGHTS.verificationControls;
    const sum = vc.artifactVerification + vc.signatureVerification + vc.evidenceVerification + vc.chainVerification;
    expect(sum).toBe(40);
  });

  test('CE-03 SCORE_WEIGHTS operationalControls sums to 35', () => {
    const oc = SCORE_WEIGHTS.operationalControls;
    const sum = oc.transparencyRegistration + oc.evidenceGeneration + oc.auditCoverage;
    expect(sum).toBe(35);
  });

  test('CE-04 SCORE_WEIGHTS complianceControls sums to 25', () => {
    const cc = SCORE_WEIGHTS.complianceControls;
    const sum = cc.policyCompliance + cc.conformanceStatus + cc.controlCoverage;
    expect(sum).toBe(25);
  });

  test('CE-05 SCORE_WEIGHTS individual weights are correct', () => {
    expect(SCORE_WEIGHTS.verificationControls.artifactVerification).toBe(15);
    expect(SCORE_WEIGHTS.verificationControls.signatureVerification).toBe(10);
    expect(SCORE_WEIGHTS.verificationControls.evidenceVerification).toBe(10);
    expect(SCORE_WEIGHTS.verificationControls.chainVerification).toBe(5);
    expect(SCORE_WEIGHTS.operationalControls.transparencyRegistration).toBe(10);
    expect(SCORE_WEIGHTS.operationalControls.evidenceGeneration).toBe(15);
    expect(SCORE_WEIGHTS.operationalControls.auditCoverage).toBe(10);
    expect(SCORE_WEIGHTS.complianceControls.policyCompliance).toBe(10);
    expect(SCORE_WEIGHTS.complianceControls.conformanceStatus).toBe(10);
    expect(SCORE_WEIGHTS.complianceControls.controlCoverage).toBe(5);
  });

  test('CE-06 CERTIFICATION_LEVELS thresholds are correct', () => {
    expect(CERTIFICATION_LEVELS.CERTIFIED_PREMIUM.min).toBe(95);
    expect(CERTIFICATION_LEVELS.CERTIFIED_PREMIUM.max).toBe(100);
    expect(CERTIFICATION_LEVELS.CERTIFIED_PLUS.min).toBe(80);
    expect(CERTIFICATION_LEVELS.CERTIFIED_PLUS.max).toBe(94);
    expect(CERTIFICATION_LEVELS.CERTIFIED.min).toBe(60);
    expect(CERTIFICATION_LEVELS.CERTIFIED.max).toBe(79);
    expect(CERTIFICATION_LEVELS.NOT_CERTIFIED.min).toBe(0);
    expect(CERTIFICATION_LEVELS.NOT_CERTIFIED.max).toBe(59);
  });

  test('CE-07 all internal scoring functions are exported', () => {
    expect(typeof _scoreVerificationControls).toBe('function');
    expect(typeof _scoreOperationalControls).toBe('function');
    expect(typeof _scoreComplianceControls).toBe('function');
    expect(typeof _detectCriticalFailures).toBe('function');
    expect(typeof _determineCertificationLevel).toBe('function');
    expect(typeof _collectControls).toBe('function');
    expect(typeof _computeScoreBreakdown).toBe('function');
  });

  test('CE-08 SCORE_WEIGHTS is frozen', () => {
    expect(Object.isFrozen(SCORE_WEIGHTS)).toBe(true);
    expect(Object.isFrozen(SCORE_WEIGHTS.verificationControls)).toBe(true);
  });

  test('CE-09 CERTIFICATION_LEVELS is frozen', () => {
    expect(Object.isFrozen(CERTIFICATION_LEVELS)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-16..CE-35  _scoreVerificationControls
// ─────────────────────────────────────────────────────────────────────────────

describe('_scoreVerificationControls', () => {
  test('CE-16 empty arrays → neutral scores (0+0+5+3=8)', () => {
    const r = _scoreVerificationControls([], [], null);
    expect(r.score).toBe(8);
    expect(r.max).toBe(40);
    expect(r.details.artifactVerification.score).toBe(0);
    expect(r.details.signatureVerification.score).toBe(0);
    expect(r.details.evidenceVerification.score).toBe(5);
    expect(r.details.chainVerification.score).toBe(3);
  });

  test('CE-17 all ATTESTED + all sig PASS + no evidence + no chain → 15+10+5+3=33', () => {
    const atts = [makeAttestation(), makeAttestation()];
    const r = _scoreVerificationControls(atts, [], null);
    expect(r.score).toBe(33);
    expect(r.details.artifactVerification.score).toBe(15);
    expect(r.details.signatureVerification.score).toBe(10);
    expect(r.details.evidenceVerification.score).toBe(5);
    expect(r.details.chainVerification.score).toBe(3);
  });

  test('CE-18 all ATTESTED + evidence valid + chain ATTESTED → 15+10+10+5=40', () => {
    const atts  = [makeAttestation()];
    const evids = [makeEvidenceResult()];
    const chain = makeChainResult({ attestationDecision: 'ATTESTED' });
    const r = _scoreVerificationControls(atts, evids, chain);
    expect(r.score).toBe(40);
  });

  test('CE-19 ATTESTED_WITH_WARNINGS → artifactScore=10', () => {
    const atts = [makeAttestation({ attestationDecision: 'ATTESTED_WITH_WARNINGS' })];
    const r = _scoreVerificationControls(atts, [], null);
    expect(r.details.artifactVerification.score).toBe(10);
  });

  test('CE-20 any NOT_ATTESTED → artifactScore=0', () => {
    const atts = [
      makeAttestation({ attestationDecision: 'ATTESTED' }),
      makeAttestation({ attestationDecision: 'NOT_ATTESTED' }),
    ];
    const r = _scoreVerificationControls(atts, [], null);
    expect(r.details.artifactVerification.score).toBe(0);
  });

  test('CE-21 signature fail → sigScore=0', () => {
    const atts = [makeAttestation({
      cryptographicResult: { signatureVerification: { status: 'FAIL' } },
    })];
    const r = _scoreVerificationControls(atts, [], null);
    expect(r.details.signatureVerification.score).toBe(0);
  });

  test('CE-22 partial signature failure (1 of 2) → sigScore=0', () => {
    const atts = [
      makeAttestation({ cryptographicResult: { signatureVerification: { status: 'PASS' } } }),
      makeAttestation({ cryptographicResult: { signatureVerification: { status: 'FAIL' } } }),
    ];
    const r = _scoreVerificationControls(atts, [], null);
    expect(r.details.signatureVerification.score).toBe(0);
  });

  test('CE-23 evidence: no packages → neutral 5', () => {
    const r = _scoreVerificationControls([makeAttestation()], [], null);
    expect(r.details.evidenceVerification.score).toBe(5);
  });

  test('CE-24 evidence: all valid → 10', () => {
    const evids = [makeEvidenceResult({ valid: true }), makeEvidenceResult({ valid: true })];
    const r = _scoreVerificationControls([makeAttestation()], evids, null);
    expect(r.details.evidenceVerification.score).toBe(10);
  });

  test('CE-25 evidence: 1 of 2 valid → floor(1/2 * 10) = 5', () => {
    const evids = [makeEvidenceResult({ valid: true }), makeEvidenceResult({ valid: false })];
    const r = _scoreVerificationControls([makeAttestation()], evids, null);
    expect(r.details.evidenceVerification.score).toBe(5);
  });

  test('CE-26 evidence: none valid → 0', () => {
    const evids = [makeEvidenceResult({ valid: false })];
    const r = _scoreVerificationControls([makeAttestation()], evids, null);
    expect(r.details.evidenceVerification.score).toBe(0);
  });

  test('CE-27 chain not requested → neutral 3', () => {
    const r = _scoreVerificationControls([makeAttestation()], [], null);
    expect(r.details.chainVerification.score).toBe(3);
  });

  test('CE-28 chain ATTESTED → 5', () => {
    const chain = makeChainResult({ attestationDecision: 'ATTESTED' });
    const r = _scoreVerificationControls([makeAttestation()], [], chain);
    expect(r.details.chainVerification.score).toBe(5);
  });

  test('CE-29 chain NOT_ATTESTED → 0', () => {
    const chain = makeChainResult({ attestationDecision: 'NOT_ATTESTED' });
    const r = _scoreVerificationControls([makeAttestation()], [], chain);
    expect(r.details.chainVerification.score).toBe(0);
  });

  test('CE-30 max field is always 40', () => {
    const r = _scoreVerificationControls([makeAttestation()], [makeEvidenceResult()], makeChainResult());
    expect(r.max).toBe(40);
  });

  test('CE-31 details structure has four control keys', () => {
    const r = _scoreVerificationControls([], [], null);
    expect(Object.keys(r.details)).toEqual([
      'artifactVerification', 'signatureVerification',
      'evidenceVerification', 'chainVerification',
    ]);
  });

  test('CE-32 each detail entry has score, max, and detail string', () => {
    const r = _scoreVerificationControls([makeAttestation()], [], null);
    for (const entry of Object.values(r.details)) {
      expect(typeof entry.score).toBe('number');
      expect(typeof entry.max).toBe('number');
      expect(typeof entry.detail).toBe('string');
    }
  });

  test('CE-33 perfect submission (all ATTESTED, all valid, chain ATTESTED) → score=40', () => {
    const r = _scoreVerificationControls(
      [makeAttestation(), makeAttestation()],
      [makeEvidenceResult(), makeEvidenceResult()],
      makeChainResult({ attestationDecision: 'ATTESTED' }),
    );
    expect(r.score).toBe(40);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-36..CE-52  _scoreOperationalControls
// ─────────────────────────────────────────────────────────────────────────────

describe('_scoreOperationalControls', () => {
  test('CE-36 empty arrays → 0+0+0=0', () => {
    const r = _scoreOperationalControls([], [], null);
    expect(r.score).toBe(0);
    expect(r.max).toBe(35);
  });

  test('CE-37 all attestations have transparencyId → transScore=10', () => {
    const atts = [makeAttestation(), makeAttestation()];
    const r = _scoreOperationalControls(atts, [], null);
    expect(r.details.transparencyRegistration.score).toBe(10);
  });

  test('CE-38 no attestations have transparencyId → transScore=0', () => {
    const atts = [makeAttestation({ transparencyReferences: { transparencyId: null } })];
    const r = _scoreOperationalControls(atts, [], null);
    expect(r.details.transparencyRegistration.score).toBe(0);
  });

  test('CE-39 partial transparencyId coverage → proportional', () => {
    const atts = [
      makeAttestation({ transparencyReferences: { transparencyId: 'trans-001' } }),
      makeAttestation({ transparencyReferences: { transparencyId: null } }),
    ];
    const r = _scoreOperationalControls(atts, [], null);
    expect(r.details.transparencyRegistration.score).toBe(Math.floor(0.5 * 10));
  });

  test('CE-40 evidence results included in transparency count', () => {
    const atts  = [makeAttestation()];
    const evids = [makeEvidenceResult()];
    const r = _scoreOperationalControls(atts, evids, null);
    expect(r.details.transparencyRegistration.score).toBe(10);
  });

  test('CE-41 no evidence → evidGenScore=0', () => {
    const r = _scoreOperationalControls([makeAttestation()], [], null);
    expect(r.details.evidenceGeneration.score).toBe(0);
  });

  test('CE-42 all evidence valid → evidGenScore=15', () => {
    const evids = [makeEvidenceResult(), makeEvidenceResult()];
    const r = _scoreOperationalControls([], evids, null);
    expect(r.details.evidenceGeneration.score).toBe(15);
  });

  test('CE-43 1 of 2 evidence valid → floor(0.5 * 15) = 7', () => {
    const evids = [makeEvidenceResult({ valid: true }), makeEvidenceResult({ valid: false })];
    const r = _scoreOperationalControls([], evids, null);
    expect(r.details.evidenceGeneration.score).toBe(7);
  });

  test('CE-44 full audit coverage (all trans + evid hashes) → auditScore=10', () => {
    const atts = [
      makeAttestation({
        transparencyReferences: { transparencyId: 'trans-001' },
        evidencePackage:        { packageHash: 'a'.repeat(64) },
      }),
    ];
    const r = _scoreOperationalControls(atts, [], null);
    expect(r.details.auditCoverage.score).toBe(10);
  });

  test('CE-45 all trans but no evid hashes → auditScore=7', () => {
    const atts = [
      makeAttestation({
        transparencyReferences: { transparencyId: 'trans-001' },
        evidencePackage:        { packageHash: null },
      }),
    ];
    const r = _scoreOperationalControls(atts, [], null);
    expect(r.details.auditCoverage.score).toBe(7);
  });

  test('CE-46 all evid hashes but no trans → auditScore=5', () => {
    const atts = [
      makeAttestation({
        transparencyReferences: { transparencyId: null },
        evidencePackage:        { packageHash: 'b'.repeat(64) },
      }),
    ];
    const r = _scoreOperationalControls(atts, [], null);
    expect(r.details.auditCoverage.score).toBe(5);
  });

  test('CE-47 perfect operational (all trans, all evid, full audit) → 35', () => {
    const atts  = [makeAttestation()];
    const evids = [makeEvidenceResult()];
    const r = _scoreOperationalControls(atts, evids, null);
    expect(r.score).toBe(35);
  });

  test('CE-48 max is always 35', () => {
    const r = _scoreOperationalControls([makeAttestation()], [makeEvidenceResult()], null);
    expect(r.max).toBe(35);
  });

  test('CE-49 details structure has three control keys', () => {
    const r = _scoreOperationalControls([], [], null);
    expect(Object.keys(r.details)).toEqual([
      'transparencyRegistration', 'evidenceGeneration', 'auditCoverage',
    ]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-53..CE-65  _scoreComplianceControls
// ─────────────────────────────────────────────────────────────────────────────

describe('_scoreComplianceControls', () => {
  test('CE-53 empty → 0+0+0=0', () => {
    const r = _scoreComplianceControls([], []);
    expect(r.score).toBe(0);
    expect(r.max).toBe(25);
  });

  test('CE-54 all COMPLIANT → policyScore=10', () => {
    const atts = [makeAttestation(), makeAttestation()];
    const r = _scoreComplianceControls(atts, []);
    expect(r.details.policyCompliance.score).toBe(10);
  });

  test('CE-55 none COMPLIANT → policyScore=0', () => {
    const atts = [makeAttestation({
      complianceResult: { policyCompliance: { status: 'NON_COMPLIANT' }, conformanceStatus: 'CONFORMS' },
    })];
    const r = _scoreComplianceControls(atts, []);
    expect(r.details.policyCompliance.score).toBe(0);
  });

  test('CE-56 partial compliance → proportional', () => {
    const atts = [
      makeAttestation({ complianceResult: { policyCompliance: { status: 'COMPLIANT' }, conformanceStatus: 'CONFORMS' } }),
      makeAttestation({ complianceResult: { policyCompliance: { status: 'NON_COMPLIANT' }, conformanceStatus: 'CONFORMS' } }),
    ];
    const r = _scoreComplianceControls(atts, []);
    expect(r.details.policyCompliance.score).toBe(Math.floor(0.5 * 10));
  });

  test('CE-57 all CONFORMS → conformScore=10', () => {
    const atts = [makeAttestation()];
    const r = _scoreComplianceControls(atts, []);
    expect(r.details.conformanceStatus.score).toBe(10);
  });

  test('CE-58 none CONFORMS → conformScore=0', () => {
    const atts = [makeAttestation({
      complianceResult: { policyCompliance: { status: 'COMPLIANT' }, conformanceStatus: 'NON_CONFORMING' },
    })];
    const r = _scoreComplianceControls(atts, []);
    expect(r.details.conformanceStatus.score).toBe(0);
  });

  test('CE-59 artifacts only (no evidence) → coverageScore=2', () => {
    const r = _scoreComplianceControls([makeAttestation()], []);
    expect(r.details.controlCoverage.score).toBe(2);
  });

  test('CE-60 evidence only (no artifacts) → coverageScore=2', () => {
    const r = _scoreComplianceControls([], [makeEvidenceResult()]);
    expect(r.details.controlCoverage.score).toBe(2);
  });

  test('CE-61 artifacts + evidence → coverageScore=5 (2+2+1 bonus)', () => {
    const r = _scoreComplianceControls([makeAttestation()], [makeEvidenceResult()]);
    expect(r.details.controlCoverage.score).toBe(5);
  });

  test('CE-62 max is always 25', () => {
    const r = _scoreComplianceControls([makeAttestation()], [makeEvidenceResult()]);
    expect(r.max).toBe(25);
  });

  test('CE-63 perfect compliance → 25', () => {
    const r = _scoreComplianceControls([makeAttestation()], [makeEvidenceResult()]);
    expect(r.score).toBe(25);
  });

  test('CE-64 details structure has three control keys', () => {
    const r = _scoreComplianceControls([], []);
    expect(Object.keys(r.details)).toEqual([
      'policyCompliance', 'conformanceStatus', 'controlCoverage',
    ]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-66..CE-72  _detectCriticalFailures
// ─────────────────────────────────────────────────────────────────────────────

describe('_detectCriticalFailures', () => {
  test('CE-66 empty artifacts → ARTIFACT_SUBMISSION failure', () => {
    const failures = _detectCriticalFailures([], []);
    expect(failures).toHaveLength(1);
    expect(failures[0].control).toBe('ARTIFACT_SUBMISSION');
    expect(failures[0].severity).toBe('CRITICAL');
  });

  test('CE-67 all ATTESTED artifacts → no failures', () => {
    const atts = [makeAttestation(), makeAttestation()];
    const failures = _detectCriticalFailures(atts, [{}]);
    expect(failures).toHaveLength(0);
  });

  test('CE-68 one NOT_ATTESTED → one critical failure', () => {
    const atts = [
      makeAttestation({ attestationDecision: 'NOT_ATTESTED', verificationResult: { failedCheck: 'SIGNATURE', failureReason: 'Bad sig' } }),
    ];
    const failures = _detectCriticalFailures(atts, [{}]);
    expect(failures).toHaveLength(1);
    expect(failures[0].severity).toBe('CRITICAL');
    expect(failures[0].control).toBe('SIGNATURE');
  });

  test('CE-69 multiple NOT_ATTESTED → multiple critical failures', () => {
    const atts = [
      makeAttestation({ attestationDecision: 'NOT_ATTESTED', verificationResult: { failedCheck: 'SCHEMA', failureReason: 'bad' } }),
      makeAttestation({ attestationDecision: 'NOT_ATTESTED', verificationResult: { failedCheck: 'TIMESTAMP', failureReason: 'bad' } }),
    ];
    const failures = _detectCriticalFailures(atts, [{}]);
    expect(failures).toHaveLength(2);
  });

  test('CE-70 ATTESTED_WITH_WARNINGS → no critical failure', () => {
    const atts = [makeAttestation({ attestationDecision: 'ATTESTED_WITH_WARNINGS' })];
    const failures = _detectCriticalFailures(atts, [{}]);
    expect(failures).toHaveLength(0);
  });

  test('CE-71 NOT_ATTESTED failure includes attestationId', () => {
    const att = makeAttestation({
      attestationDecision: 'NOT_ATTESTED',
      verificationResult:  { failedCheck: 'KEY_VALID', failureReason: 'Key not found' },
    });
    const failures = _detectCriticalFailures([att], [{}]);
    expect(failures[0].attestationId).toBe(att.attestationId);
  });

  test('CE-72 returns early with ARTIFACT_SUBMISSION for empty artifacts (no iterations)', () => {
    const atts = [makeAttestation({ attestationDecision: 'NOT_ATTESTED' })];
    // artifacts array empty — should return ARTIFACT_SUBMISSION, not iterate atts
    const failures = _detectCriticalFailures(atts, []);
    expect(failures).toHaveLength(1);
    expect(failures[0].control).toBe('ARTIFACT_SUBMISSION');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-73..CE-79  _determineCertificationLevel
// ─────────────────────────────────────────────────────────────────────────────

describe('_determineCertificationLevel', () => {
  test('CE-73 critical failure always → NOT_CERTIFIED regardless of score', () => {
    expect(_determineCertificationLevel(100, true)).toBe('NOT_CERTIFIED');
    expect(_determineCertificationLevel(95, true)).toBe('NOT_CERTIFIED');
    expect(_determineCertificationLevel(80, true)).toBe('NOT_CERTIFIED');
  });

  test('CE-74 score 95 → CERTIFIED_PREMIUM', () => {
    expect(_determineCertificationLevel(95, false)).toBe('CERTIFIED_PREMIUM');
  });

  test('CE-75 score 100 → CERTIFIED_PREMIUM', () => {
    expect(_determineCertificationLevel(100, false)).toBe('CERTIFIED_PREMIUM');
  });

  test('CE-76 score 80 → CERTIFIED_PLUS', () => {
    expect(_determineCertificationLevel(80, false)).toBe('CERTIFIED_PLUS');
  });

  test('CE-77 score 94 → CERTIFIED_PLUS', () => {
    expect(_determineCertificationLevel(94, false)).toBe('CERTIFIED_PLUS');
  });

  test('CE-78 score 60 → CERTIFIED', () => {
    expect(_determineCertificationLevel(60, false)).toBe('CERTIFIED');
  });

  test('CE-79 score 59 → NOT_CERTIFIED (no critical failure)', () => {
    expect(_determineCertificationLevel(59, false)).toBe('NOT_CERTIFIED');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-80..CE-83  _collectControls
// ─────────────────────────────────────────────────────────────────────────────

describe('_collectControls', () => {
  function makeBreakdown(vcScore, vcMax, ocScore, ocMax, ccScore, ccMax) {
    return {
      verificationControls: {
        score: vcScore, max: vcMax,
        details: { ctrl1: { score: vcScore, max: vcMax, detail: 'v' } },
      },
      operationalControls: {
        score: ocScore, max: ocMax,
        details: { ctrl2: { score: ocScore, max: ocMax, detail: 'o' } },
      },
      complianceControls: {
        score: ccScore, max: ccMax,
        details: { ctrl3: { score: ccScore, max: ccMax, detail: 'c' } },
      },
      totalScore: vcScore + ocScore + ccScore,
    };
  }

  test('CE-80 control at max → passedControls', () => {
    const bd = makeBreakdown(40, 40, 35, 35, 25, 25);
    const { passedControls, failedControls } = _collectControls(bd);
    expect(passedControls).toHaveLength(3);
    expect(failedControls).toHaveLength(0);
  });

  test('CE-81 control below max → failedControls', () => {
    const bd = makeBreakdown(30, 40, 35, 35, 20, 25);
    const { passedControls, failedControls } = _collectControls(bd);
    expect(passedControls).toHaveLength(1);
    expect(failedControls).toHaveLength(2);
  });

  test('CE-82 each entry has control, score, max, detail', () => {
    const bd = makeBreakdown(40, 40, 35, 35, 25, 25);
    const { passedControls } = _collectControls(bd);
    for (const c of passedControls) {
      expect(typeof c.control).toBe('string');
      expect(typeof c.score).toBe('number');
      expect(typeof c.max).toBe('number');
      expect(typeof c.detail).toBe('string');
    }
  });

  test('CE-83 all zeros → all in failedControls', () => {
    const bd = makeBreakdown(0, 40, 0, 35, 0, 25);
    const { passedControls, failedControls } = _collectControls(bd);
    expect(passedControls).toHaveLength(0);
    expect(failedControls).toHaveLength(3);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-84..CE-86  _computeScoreBreakdown
// ─────────────────────────────────────────────────────────────────────────────

describe('_computeScoreBreakdown', () => {
  test('CE-84 perfect submission → totalScore=100', () => {
    const atts  = [makeAttestation()];
    const evids = [makeEvidenceResult()];
    const chain = makeChainResult({ attestationDecision: 'ATTESTED' });
    const bd = _computeScoreBreakdown(atts, evids, chain);
    expect(bd.totalScore).toBe(100);
  });

  test('CE-85 empty → totalScore = neutral (5+3=8)', () => {
    const bd = _computeScoreBreakdown([], [], null);
    expect(bd.totalScore).toBe(8);
  });

  test('CE-86 has verificationControls, operationalControls, complianceControls, totalScore', () => {
    const bd = _computeScoreBreakdown([], [], null);
    expect(bd).toHaveProperty('verificationControls');
    expect(bd).toHaveProperty('operationalControls');
    expect(bd).toHaveProperty('complianceControls');
    expect(bd).toHaveProperty('totalScore');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-87..CE-93  assembleCertificationEvidence
// ─────────────────────────────────────────────────────────────────────────────

describe('assembleCertificationEvidence', () => {
  const baseData = {
    certificationId:         'cert-uuid-001',
    certificationLevel:      'CERTIFIED_PREMIUM',
    certificationDecision:   'CERTIFIED',
    totalScore:              100,
    scoreBreakdown:          {},
    criticalControlFailures: [],
    passedControls:          [],
    failedControls:          [],
    attestationReferences:   [],
    evidenceReferences:      [],
    verificationReferences:  {},
    requestedBy:             'test',
    durationMs:              42,
  };

  test('CE-87 packageType is QODIQA::CERTIFICATION_EVIDENCE::V1', () => {
    const pkg = assembleCertificationEvidence(baseData);
    expect(pkg.packageType).toBe('QODIQA::CERTIFICATION_EVIDENCE::V1');
  });

  test('CE-88 packageHash is 64-character hex string', () => {
    const pkg = assembleCertificationEvidence(baseData);
    expect(pkg.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('CE-89 packageId is 64-character hex string', () => {
    const pkg = assembleCertificationEvidence(baseData);
    expect(pkg.packageId).toMatch(/^[0-9a-f]{64}$/);
  });

  test('CE-90 has generatedAt ISO timestamp', () => {
    const pkg = assembleCertificationEvidence(baseData);
    expect(() => new Date(pkg.generatedAt)).not.toThrow();
    expect(pkg.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  test('CE-91 packageHash is reproducible from content fields (excludes packageId, generatedAt, packageHash)', () => {
    const { canonicalHash } = require('../../../../services/utils/evidencePackage');
    const pkg = assembleCertificationEvidence(baseData);
    const content = {
      packageType:             'QODIQA::CERTIFICATION_EVIDENCE::V1',
      schemaVersion:           '1.0',
      certificationId:         baseData.certificationId,
      certificationLevel:      baseData.certificationLevel,
      certificationDecision:   baseData.certificationDecision,
      score:                   baseData.totalScore,
      scoreBreakdown:          baseData.scoreBreakdown,
      criticalControlFailures: baseData.criticalControlFailures,
      passedControls:          baseData.passedControls,
      failedControls:          baseData.failedControls,
      attestationReferences:   baseData.attestationReferences,
      evidenceReferences:      baseData.evidenceReferences,
      verificationReferences:  baseData.verificationReferences,
      requestedBy:             baseData.requestedBy,
      durationMs:              baseData.durationMs,
      evaluatedAt:             pkg.evaluatedAt,
    };
    const expectedHash = canonicalHash(content);
    expect(pkg.packageHash).toBe(expectedHash);
  });

  test('CE-92 schemaVersion is 1.0', () => {
    const pkg = assembleCertificationEvidence(baseData);
    expect(pkg.schemaVersion).toBe('1.0');
  });

  test('CE-93 certificationId matches input', () => {
    const pkg = assembleCertificationEvidence(baseData);
    expect(pkg.certificationId).toBe('cert-uuid-001');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-94..CE-110  evaluate() — end-to-end with mocked dependencies
// ─────────────────────────────────────────────────────────────────────────────

describe('evaluate()', () => {
  test('CE-94b the entryType evaluate() registers is one the real registrar and tle_entry_type_valid accept', async () => {
    await evaluate({ artifacts: [{}], evidencePackages: [{}] });
    const call = registrar.register.mock.calls[0][0];
    expect(call.payload.kind).toBe('CERTIFICATION');
    const real = jest.requireActual('../../transparency/registrar');
    await expect(real.register({ entryType: 'CERTIFICATION' })).rejects.toThrow(/Unknown entryType/);
    let err = null;
    try { await real.register({ entryType: call.entryType, payload: call.payload }); } catch (e) { err = e; }
    expect(err && /Unknown entryType/.test(err.message)).toBeFalsy();
    const sql = require('fs').readFileSync(require('path').join(__dirname, '../../../infra/postgres/migrations/070_signed_checkpoints.sql'), 'utf8');
    expect(sql).toContain("'" + call.entryType + "'");
  });

  test('CE-94 returns certificationId, level, decision, score', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation());
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult());
    registrar.register.mockResolvedValue({ transparencyId: 'trans-001' });

    const result = await evaluate({ artifacts: [{}], evidencePackages: [{}] });
    expect(result.certificationId).toBeDefined();
    expect(result.certificationLevel).toBeDefined();
    expect(result.certificationDecision).toBeDefined();
    expect(typeof result.score).toBe('number');
  });

  test('CE-95 perfect submission → CERTIFIED_PREMIUM, score 100', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation({ attestationDecision: 'ATTESTED' }));
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult({ valid: true }));
    attestor.verifyChain.mockResolvedValue(makeChainResult({ attestationDecision: 'ATTESTED' }));
    registrar.register.mockResolvedValue({ transparencyId: 'trans-001' });

    const { artifact, pkg } = makeBoundPair();
    const result = await evaluate({
      artifacts:        [artifact],
      evidencePackages: [pkg],
      chain:            { evidenceIds: ['ev-001'] },
    });

    expect(result.certificationLevel).toBe('CERTIFIED_PREMIUM');
    expect(result.certificationDecision).toBe('CERTIFIED');
    expect(result.score).toBe(100);
  });

  test('CE-96 empty artifacts → NOT_CERTIFIED with critical failure', async () => {
    const result = await evaluate({ artifacts: [], evidencePackages: [] });
    expect(result.certificationLevel).toBe('NOT_CERTIFIED');
    expect(result.certificationDecision).toBe('NOT_CERTIFIED');
    expect(result.criticalControlFailures).toHaveLength(1);
    expect(result.criticalControlFailures[0].control).toBe('ARTIFACT_SUBMISSION');
  });

  test('CE-97 NOT_ATTESTED artifact → NOT_CERTIFIED with critical failure', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation({
      attestationDecision: 'NOT_ATTESTED',
      verificationResult:  { failedCheck: 'SIGNATURE', failureReason: 'Signature invalid' },
    }));
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult());

    const { artifact, pkg } = makeBoundPair();
    const result = await evaluate({ artifacts: [artifact], evidencePackages: [pkg] });
    expect(result.certificationLevel).toBe('NOT_CERTIFIED');
    // H132-B: evidence about an artifact that did not attest is not eligible, so
    // the mandatory-evidence control fails alongside the artifact's own check.
    expect(result.criticalControlFailures.map(f => f.control)).toEqual(['SIGNATURE', 'MISSING_EVIDENCE_PACKAGE']);
  });

  test('CE-98 ATTESTED_WITH_WARNINGS + evidence package → below perfect score, no critical failure', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation({
      attestationDecision: 'ATTESTED_WITH_WARNINGS',
    }));
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult());
    registrar.register.mockResolvedValue({ transparencyId: 'trans-001' });

    const { artifact, pkg } = makeBoundPair();
    const result = await evaluate({ artifacts: [artifact], evidencePackages: [pkg] });
    expect(result.certificationLevel).not.toBe('NOT_CERTIFIED');
    expect(result.criticalControlFailures).toHaveLength(0);
    expect(result.score).toBeLessThan(100);
  });

  test('CE-99 calls attestor.generateAttestation once per artifact', async () => {
    await evaluate({ artifacts: [{}, {}] });
    expect(attestor.generateAttestation).toHaveBeenCalledTimes(2);
  });

  test('CE-100 calls attestor.verifyEvidencePackage once per evidence package', async () => {
    await evaluate({ artifacts: [{}], evidencePackages: [{}, {}] });
    expect(attestor.verifyEvidencePackage).toHaveBeenCalledTimes(2);
  });

  test('CE-101 calls attestor.verifyChain when chain has evidenceIds', async () => {
    await evaluate({ artifacts: [{}], chain: { evidenceIds: ['ev-001'] } });
    expect(attestor.verifyChain).toHaveBeenCalledTimes(1);
  });

  test('CE-102 does NOT call attestor.verifyChain when chain is null', async () => {
    await evaluate({ artifacts: [{}], chain: null });
    expect(attestor.verifyChain).not.toHaveBeenCalled();
  });

  test('CE-103 does NOT call attestor.verifyChain for empty evidenceIds', async () => {
    await evaluate({ artifacts: [{}], chain: { evidenceIds: [] } });
    expect(attestor.verifyChain).not.toHaveBeenCalled();
  });

  test('CE-104 calls registrar.register', async () => {
    await evaluate({ artifacts: [{}] });
    expect(registrar.register).toHaveBeenCalledTimes(1);
  });

  test('CE-105 transparency registration failure → result still returned', async () => {
    registrar.register.mockRejectedValue(new Error('registrar down'));
    const result = await evaluate({ artifacts: [{}] });
    expect(result).toBeDefined();
    expect(result.transparencyReferences.transparencyId).toBeNull();
  });

  test('CE-106 certificationStore.recordCertification called (fire-and-forget)', async () => {
    await evaluate({ artifacts: [{}] });
    // allow microtask queue to flush
    await new Promise(resolve => setImmediate(resolve));
    expect(certificationStore.recordCertification).toHaveBeenCalledTimes(1);
  });

  test('CE-107 result contains evidencePackage with packageHash', async () => {
    const result = await evaluate({ artifacts: [{}] });
    expect(result.evidencePackage).toBeDefined();
    expect(result.evidencePackage.packageHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('CE-108 metrics.certificationsTotal.inc called with level label', async () => {
    await evaluate({ artifacts: [{}] });
    expect(metrics.certificationsTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ level: expect.any(String) }),
    );
  });

  test('CE-109 metrics.certificationFailuresTotal.inc called when NOT_CERTIFIED by low score', async () => {
    // No artifacts → critical failure → NOT_CERTIFIED
    await evaluate({ artifacts: [] });
    expect(metrics.certificationFailuresTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'CRITICAL_CONTROL' }),
    );
  });

  test('CE-110 result.metadata.requestedBy reflects opts', async () => {
    const result = await evaluate({ artifacts: [{}] }, { requestedBy: 'unit-test' });
    expect(result.metadata.requestedBy).toBe('unit-test');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-111..CE-115  certificationStore PG-disabled behaviour
// ─────────────────────────────────────────────────────────────────────────────

describe('certificationStore PG-disabled', () => {
  const realCertificationStore = jest.requireActual('../certificationStore');

  beforeEach(() => {
    pgPool.isEnabled.mockReturnValue(false);
  });

  test('CE-111 recordCertification returns null when PG disabled', async () => {
    const result = await realCertificationStore.recordCertification({
      certificationId:       'cert-001',
      certificationLevel:    'CERTIFIED',
      certificationDecision: 'CERTIFIED',
      score:                 70,
    });
    expect(result).toBeNull();
  });

  test('CE-112 getByCertificationId returns null when PG disabled', async () => {
    const result = await realCertificationStore.getByCertificationId('cert-001');
    expect(result).toBeNull();
  });

  test('CE-113 listCertifications returns empty result when PG disabled', async () => {
    const result = await realCertificationStore.listCertifications();
    expect(result.certifications).toEqual([]);
    expect(result.total).toBe(0);
    expect(result.page).toBe(1);
    expect(result.pageSize).toBe(50);
  });

  test('CE-114 listCertifications preserves page and pageSize when PG disabled', async () => {
    const result = await realCertificationStore.listCertifications({ page: 3, pageSize: 25 });
    expect(result.page).toBe(3);
    expect(result.pageSize).toBe(25);
  });

  test('CE-115 aggregateStats returns null when PG disabled', async () => {
    const result = await realCertificationStore.aggregateStats();
    expect(result).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-116..CE-120  Component #22 — Evidence Package Enforcement
// ─────────────────────────────────────────────────────────────────────────────

describe('Component #22: Evidence package enforcement', () => {
  test('CE-116 score passes + evidence exists → CERTIFIED', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation());
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult());
    attestor.verifyChain.mockResolvedValue(makeChainResult({ attestationDecision: 'ATTESTED' }));
    registrar.register.mockResolvedValue({ transparencyId: 'trans-001' });

    const { artifact, pkg } = makeBoundPair();
    const result = await evaluate({ artifacts: [artifact], evidencePackages: [pkg], chain: { evidenceIds: ['ev-001'] } });

    expect(result.certificationDecision).toBe('CERTIFIED');
    expect(result.criticalControlFailures.find(f => f.control === 'MISSING_EVIDENCE_PACKAGE')).toBeUndefined();
  });

  test('CE-117 score passes + evidencePackages empty array → NOT_CERTIFIED with MISSING_EVIDENCE_PACKAGE', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation());
    registrar.register.mockResolvedValue({ transparencyId: 'trans-001' });

    const result = await evaluate({ artifacts: [{}], evidencePackages: [] });

    expect(result.certificationDecision).toBe('NOT_CERTIFIED');
    const failure = result.criticalControlFailures.find(f => f.control === 'MISSING_EVIDENCE_PACKAGE');
    expect(failure).toBeDefined();
    expect(failure.severity).toBe('CRITICAL');
    expect(typeof failure.reason).toBe('string');
  });

  test('CE-118 evidencePackages omitted → NOT_CERTIFIED with MISSING_EVIDENCE_PACKAGE', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation());
    registrar.register.mockResolvedValue({ transparencyId: 'trans-001' });

    const result = await evaluate({ artifacts: [{}] });

    expect(result.certificationDecision).toBe('NOT_CERTIFIED');
    expect(result.criticalControlFailures.find(f => f.control === 'MISSING_EVIDENCE_PACKAGE')).toBeDefined();
  });

  test('CE-119 score fails + evidence exists → NOT_CERTIFIED, no MISSING_EVIDENCE_PACKAGE failure', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation({
      attestationDecision: 'ATTESTED_WITH_WARNINGS',
      cryptographicResult: { signatureVerification: { status: 'FAIL' } },
      complianceResult: {
        policyCompliance:  { status: 'NON_COMPLIANT' },
        conformanceStatus: 'DOES_NOT_CONFORM',
      },
      transparencyReferences: { transparencyId: null },
      evidencePackage:        { packageHash: null },
    }));
    // H132-B: this case's point is a low SCORE with eligible evidence present —
    // an invalid package no longer counts as "evidence exists" (see CE-H132-*).
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult());
    registrar.register.mockResolvedValue({ transparencyId: null });

    const { artifact, pkg } = makeBoundPair();
    const result = await evaluate({ artifacts: [artifact], evidencePackages: [pkg] });

    expect(result.certificationDecision).toBe('NOT_CERTIFIED');
    expect(result.criticalControlFailures.find(f => f.control === 'MISSING_EVIDENCE_PACKAGE')).toBeUndefined();
  });

  test('CE-120 MISSING_EVIDENCE_PACKAGE not produced by _detectCriticalFailures directly — enforced in evaluate()', () => {
    const atts = [makeAttestation()];
    const failures = _detectCriticalFailures(atts, [{}]);
    expect(failures.find(f => f.control === 'MISSING_EVIDENCE_PACKAGE')).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CE-H132-01…08  H132-B — certification evidence eligibility. The package
// verifier's `valid` proves authenticity + binding only; a genuine package of a
// FAILED / NOT_ATTESTED original, of another artifact or tenant, or repeated,
// must not satisfy the mandatory-evidence control or earn evidence points.
// 
// ─────────────────────────────────────────────────────────────────────────────

describe('CE-H132  certification evidence eligibility (H132-B)', () => {
  const certify = async ({ artifact, pkg }, evidenceResult, extraPkgs = []) => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation());
    attestor.verifyEvidencePackage.mockResolvedValue(evidenceResult);
    registrar.register.mockResolvedValue({ transparencyId: 'trans-001' });
    return evaluate({ artifacts: [artifact], evidencePackages: [pkg, ...extraPkgs] });
  };
  const gate = (r) => r.criticalControlFailures.find(f => f.control === 'MISSING_EVIDENCE_PACKAGE');

  test('CE-H132-01  positive, bound, same artifact and tenant → eligible, CERTIFIED', async () => {
    const r = await certify(makeBoundPair(), makeEvidenceResult());
    expect(r.certificationDecision).toBe('CERTIFIED');
    expect(r.evidenceReferences[0]).toEqual(expect.objectContaining({ valid: true, eligible: true, ineligibleReason: null }));
  });

  test.each([
    ['FAILED portal original', { originalResult: 'FAILED' }],
    ['NOT_ATTESTED attestation original', { originalResult: 'NOT_ATTESTED' }],
    ['unknown / null original outcome', { originalResult: null }],
  ])('CE-H132-02  genuine package of a %s → not eligible, NOT_CERTIFIED', async (_n, cv) => {
    const r = await certify(makeBoundPair(), makeEvidenceResult({ chainVerification: { originalFound: true, contentBound: true, ...cv } }));
    expect(r.certificationDecision).toBe('NOT_CERTIFIED');
    expect(gate(r)).toBeDefined();
    expect(r.evidenceReferences[0]).toEqual(expect.objectContaining({ valid: true, eligible: false, ineligibleReason: 'ORIGINAL_OUTCOME_NOT_POSITIVE' }));
    expect(r.scoreBreakdown.verificationControls.details.evidenceVerification.score).toBe(0);
  });

  test('CE-H132-03  genuine package about a DIFFERENT artifact → ARTIFACT_NOT_SUBMITTED', async () => {
    const a = makeBoundPair(); const other = makeBoundPair();
    const r = await certify({ artifact: a.artifact, pkg: other.pkg }, makeEvidenceResult());
    expect(r.certificationDecision).toBe('NOT_CERTIFIED');
    expect(r.evidenceReferences[0].ineligibleReason).toBe('ARTIFACT_NOT_SUBMITTED');
  });

  test('CE-H132-04  package naming another tenant key for the artifact → TENANT_MISMATCH', async () => {
    const { artifact, pkg } = makeBoundPair('tenant-a');
    const r = await certify({ artifact, pkg: { ...pkg, artifactPublicKeyId: 'tenant-b:key_v1' } }, makeEvidenceResult());
    expect(r.certificationDecision).toBe('NOT_CERTIFIED');
    expect(r.evidenceReferences[0].ineligibleReason).toBe('TENANT_MISMATCH');
  });

  test('CE-H132-05  not authentic / not bound (valid:false, incl. {}) → NOT_AUTHENTIC, gate fails', async () => {
    attestor.generateAttestation.mockResolvedValue(makeAttestation());
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult({ valid: false }));
    const r = await evaluate({ artifacts: [makeBoundPair().artifact], evidencePackages: [{}] });
    expect(r.certificationDecision).toBe('NOT_CERTIFIED');
    expect(gate(r)).toBeDefined();
    expect(r.evidenceReferences[0].ineligibleReason).toBe('NOT_AUTHENTIC');
  });

  test('CE-H132-06  the same original twice → counted once (DUPLICATE_EVIDENCE lowers the evidence score)', async () => {
    const pair = makeBoundPair();
    const r = await certify(pair, makeEvidenceResult(), [pair.pkg]);
    expect(r.evidenceReferences.map(e => e.ineligibleReason)).toEqual([null, 'DUPLICATE_EVIDENCE']);
    expect(r.scoreBreakdown.verificationControls.details.evidenceVerification.score).toBe(5);
    expect(gate(r)).toBeUndefined();
  });

  test('CE-H132-07  original not found → ORIGINAL_NOT_FOUND', async () => {
    const r = await certify(makeBoundPair(), makeEvidenceResult({ chainVerification: { originalFound: false, originalResult: null } }));
    expect(r.evidenceReferences[0].ineligibleReason).toBe('ORIGINAL_NOT_FOUND');
    expect(r.certificationDecision).toBe('NOT_CERTIFIED');
  });

  test('CE-H132-08  chain evidenceIds are verified against the submitted artifacts\' tenant(s)', async () => {
    const { artifact, pkg } = makeBoundPair('tenant-a');
    attestor.generateAttestation.mockResolvedValue(makeAttestation());
    attestor.verifyEvidencePackage.mockResolvedValue(makeEvidenceResult());
    attestor.verifyChain.mockResolvedValue(makeChainResult());
    await evaluate({ artifacts: [artifact], evidencePackages: [pkg], chain: { evidenceIds: ['e1'] } });
    expect(attestor.verifyChain).toHaveBeenCalledWith({ evidenceIds: ['e1'] }, expect.objectContaining({ expectedTenantIds: ['tenant-a'] }));
  });
});
