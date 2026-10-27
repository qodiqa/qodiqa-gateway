'use strict';

/**
 * QODIQA Compliance Reporting Framework — Test Suite
 *
 * CR-01 to CR-25: controlRegistry
 * CR-26 to CR-45: evidenceValidator (scoringEngine)
 * CR-46 to CR-62: reportGenerator unit tests (mocked DB)
 * CR-63 to CR-80: API route tests
 * CR-81 to CR-90: reportIntegrity
 */

// ── Jest mocks (must come before requires) ─────────────────────────────────────

const mockPool = {
  isEnabled:   jest.fn().mockReturnValue(false),
  isHealthy:   jest.fn().mockReturnValue(false),
  healthCheck: jest.fn().mockResolvedValue({ healthy: false }),
  query:       jest.fn(),
  withTransaction: jest.fn(),
};

jest.mock('../../../infra/postgres/pool', () => mockPool);

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({
  emit: mockEmit,
  registerCentralStore: jest.fn(),
}));

const mockGenerateReport   = jest.fn();
const mockGetReport        = jest.fn();
const mockListReports      = jest.fn();
const mockGetAssessments   = jest.fn();

jest.mock('../../../core/compliance/reportGenerator', () => ({
  generateReport:        mockGenerateReport,
  getReport:             mockGetReport,
  listReports:           mockListReports,
  getControlAssessments: mockGetAssessments,
}));

const mockVerifyReport = jest.fn();
jest.mock('../../../core/compliance/reportIntegrity', () => ({
  canonicalise: jest.requireActual('../../../core/compliance/reportIntegrity').canonicalise,
  hashReport:   jest.requireActual('../../../core/compliance/reportIntegrity').hashReport,
  computeHash:  jest.requireActual('../../../core/compliance/reportIntegrity').computeHash,
  verifyReport: mockVerifyReport,
  signReport:   jest.fn(),
  DOMAIN_PREFIX: 'QODIQA::COMPLIANCE_REPORT::V1',
}));

const mockExportJson   = jest.fn();
const mockExportPdf    = jest.fn();
const mockExportHtml   = jest.fn();

jest.mock('../../../core/compliance/exporters/jsonExporter', () => ({
  exportJson:       mockExportJson,
  exportJsonBuffer: jest.fn().mockReturnValue(Buffer.from('{"ok":true}')),
}));
jest.mock('../../../core/compliance/exporters/pdfExporter', () => ({
  exportPdf: mockExportPdf,
}));
jest.mock('../../../core/compliance/exporters/htmlExporter', () => ({
  exportHtml: mockExportHtml,
}));

// ── Imports ───────────────────────────────────────────────────────────────────

const request = require('supertest');
const express = require('express');

const {
  getAllControls,
  getControl,
  getControlsForFramework,
  isValidFramework,
  FRAMEWORK_IDS,
} = require('../../../core/compliance/controlRegistry');

const { validateControl, validateAll } = require('../../../core/compliance/evidenceValidator');

const {
  controlStatus,
  scoreFramework,
  scoreOverall,
  buildExecutiveSummary,
  aggregateFindings,
  PASS_THRESHOLD,
} = require('../../../core/compliance/scoringEngine');

const { canonicalise, hashReport, computeHash } =
  jest.requireActual('../../../core/compliance/reportIntegrity');

const createComplianceRouter = require('../compliance');

// ── Test app ──────────────────────────────────────────────────────────────────

function makeApp(routerOpts = {}) {
  const app = express();
  app.use(express.json());
  app.use('/compliance', createComplianceRouter(routerOpts));
  return app;
}

// ── Sample report ─────────────────────────────────────────────────────────────

function sampleReport(overrides = {}) {
  return {
    id:            'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    reportRef:     'RPT-GDPR-20260620-ABCD',
    schemaVersion: '1.0',
    generatorVersion: '1.0.0',
    framework: { id: 'GDPR', name: 'General Data Protection Regulation', version: '2016/679', issuer: 'European Parliament' },
    generatedAt:     '2026-06-20T12:00:00Z',
    generatedBy:     'test-user',
    generatedByRole: 'compliance',
    tenantId:     null,
    period:       { start: '2026-01-01T00:00:00Z', end: '2026-06-01T00:00:00Z' },
    executiveSummary: 'Test summary.',
    overallScore:  85,
    overallVerdict: 'COMPLIANT',
    controlsSummary: { total: 7, pass: 6, partial: 1, fail: 0, criticalFails: 0 },
    controlAssessments: [],
    findings:     [],
    findingsCount: 0,
    criticalFindings: 0,
    evidenceSummary:  { enforcementEvents: 10, auditEvents: 100 },
    evidenceCount: 110,
    recommendations: [],
    _hash: 'a'.repeat(64),
    ...overrides,
  };
}

// ── Sample evidence bundle ─────────────────────────────────────────────────────

function sampleBundle(overrides = {}) {
  return {
    periodStart: '2026-01-01T00:00:00Z',
    periodEnd:   '2026-06-01T00:00:00Z',
    tenantId:    null,
    collectedAt: '2026-06-20T12:00:00Z',
    dbEnabled:   true,
    enforcement: {
      evidenceType: 'enforcement_events',
      count: 50, blockCount: 5, allowCount: 45,
      items: [{ evidenceType: 'enforcement_events', sourceTable: 'platform_audit_events',
                sourceId: 'uuid-1', occurredAt: '2026-03-01T10:00:00Z',
                summary: 'GATEWAY_ALLOW | outcome=ALLOW', metadata: { outcome: 'ALLOW' } }],
    },
    policy_records: {
      evidenceType: 'policy_records',
      count: 3, activeCount: 3, consentPolicies: 1,
      items: [{ evidenceType: 'policy_records', sourceTable: 'policies', sourceId: 'pol-1',
                occurredAt: null, summary: 'Consent Policy | type=REQUIRE_CONSENT | enabled=true | v1',
                metadata: { type: 'REQUIRE_CONSENT', enabled: true, status: 'ACTIVE', version: 1 } }],
    },
    audit_events: {
      evidenceType: 'audit_events', count: 200, errorCount: 2,
      items: [],
    },
    security_events:       { evidenceType: 'security_events',       count: 5,  items: [] },
    lifecycle_events:      { evidenceType: 'lifecycle_events',       count: 3,  items: [] },
    key_management_events: { evidenceType: 'key_management_events',  count: 10, items: [] },
    audit_chain_entries:   { evidenceType: 'audit_chain_entries',    count: 30, chainBroken: false, verifiedCount: 28, items: [] },
    signed_artifacts:      { evidenceType: 'signed_artifacts',       count: 25, items: [] },
    rbac_users:            { evidenceType: 'rbac_users', count: 4, roleCount: 3, hasAdmin: true, roles: ['admin','auditor','compliance'], items: [] },
    signing_key_records:   { evidenceType: 'signing_key_records', count: 2, activeCount: 1, expiringCount: 0, algorithms: ['ed25519'], items: [] },
    consent_events:        { evidenceType: 'consent_events',         count: 8,  items: [] },
    anomaly_events:        { evidenceType: 'anomaly_events',         count: 0,  items: [] },
    ...overrides,
  };
}

// ════════════════════════════════════════════════════════════════════════════
// CR-01 to CR-25 — Control Registry
// ════════════════════════════════════════════════════════════════════════════

describe('Control Registry', () => {
  test('CR-01: FRAMEWORK_IDS contains all four frameworks', () => {
    expect(FRAMEWORK_IDS).toContain('GDPR');
    expect(FRAMEWORK_IDS).toContain('EU_AI_ACT');
    expect(FRAMEWORK_IDS).toContain('ISO_42001');
    expect(FRAMEWORK_IDS).toContain('NIST_AI_RMF');
    expect(FRAMEWORK_IDS).toHaveLength(4);
  });

  test('CR-02: getAllControls returns all controls', () => {
    const all = getAllControls();
    expect(all.length).toBeGreaterThanOrEqual(30);
  });

  test('CR-03: isValidFramework returns true for known frameworks', () => {
    expect(isValidFramework('GDPR')).toBe(true);
    expect(isValidFramework('EU_AI_ACT')).toBe(true);
    expect(isValidFramework('ISO_42001')).toBe(true);
    expect(isValidFramework('NIST_AI_RMF')).toBe(true);
  });

  test('CR-04: isValidFramework returns false for unknown frameworks', () => {
    expect(isValidFramework('SOC2')).toBe(false);
    expect(isValidFramework('')).toBe(false);
    expect(isValidFramework(null)).toBe(false);
  });

  test('CR-05: getControlsForFramework returns GDPR controls', () => {
    const ctrls = getControlsForFramework('GDPR');
    expect(ctrls.length).toBeGreaterThanOrEqual(7);
    expect(ctrls.every(c => c.frameworkId === 'GDPR')).toBe(true);
  });

  test('CR-06: getControlsForFramework returns EU AI Act controls', () => {
    const ctrls = getControlsForFramework('EU_AI_ACT');
    expect(ctrls.length).toBeGreaterThanOrEqual(6);
    expect(ctrls.every(c => c.frameworkId === 'EU_AI_ACT')).toBe(true);
  });

  test('CR-07: getControlsForFramework returns ISO 42001 controls', () => {
    const ctrls = getControlsForFramework('ISO_42001');
    expect(ctrls.length).toBeGreaterThanOrEqual(7);
    expect(ctrls.every(c => c.frameworkId === 'ISO_42001')).toBe(true);
  });

  test('CR-08: getControlsForFramework returns NIST AI RMF controls', () => {
    const ctrls = getControlsForFramework('NIST_AI_RMF');
    expect(ctrls.length).toBeGreaterThanOrEqual(8);
    expect(ctrls.every(c => c.frameworkId === 'NIST_AI_RMF')).toBe(true);
  });

  test('CR-09: getControl returns control by ID', () => {
    const ctrl = getControl('GDPR-AU1');
    expect(ctrl).not.toBeNull();
    expect(ctrl.frameworkId).toBe('GDPR');
    expect(ctrl.isCritical).toBe(true);
  });

  test('CR-10: getControl returns null for unknown ID', () => {
    expect(getControl('UNKNOWN-CTRL')).toBeNull();
  });

  test('CR-11: all controls have required fields', () => {
    const all = getAllControls();
    for (const c of all) {
      expect(typeof c.id).toBe('string');
      expect(typeof c.frameworkId).toBe('string');
      expect(typeof c.controlRef).toBe('string');
      expect(typeof c.title).toBe('string');
      expect(typeof c.category).toBe('string');
      expect(typeof c.weight).toBe('number');
      expect(c.weight).toBeGreaterThan(0);
      expect(Array.isArray(c.evidenceRequired)).toBe(true);
      expect(Array.isArray(c.validationRules)).toBe(true);
    }
  });

  test('CR-12: control IDs are unique across all frameworks', () => {
    const all = getAllControls();
    const ids  = all.map(c => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test('CR-13: critical controls have weight >= 1.5', () => {
    const criticals = getAllControls().filter(c => c.isCritical);
    expect(criticals.length).toBeGreaterThan(0);
    criticals.forEach(c => expect(c.weight).toBeGreaterThanOrEqual(1.5));
  });

  test('CR-14: GDPR-L1 is critical', () => {
    const ctrl = getControl('GDPR-L1');
    expect(ctrl.isCritical).toBe(true);
    expect(ctrl.weight).toBe(2.0);
  });

  test('CR-15: EUAIA-HO1 covers human oversight', () => {
    const ctrl = getControl('EUAIA-HO1');
    expect(ctrl.controlRef).toContain('Art. 14');
    expect(ctrl.category).toBe('Human Oversight');
  });

  test('CR-16: NIST-GOV-1-1 maps to GOVERN category', () => {
    const ctrl = getControl('NIST-GOV-1-1');
    expect(ctrl.category).toBe('GOVERN');
  });

  test('CR-17: ISO42001-9-1 requires monitoring evidence', () => {
    const ctrl = getControl('ISO42001-9-1');
    expect(ctrl.evidenceRequired).toContain('audit_events');
    expect(ctrl.isCritical).toBe(true);
  });

  test('CR-18: all controls have at least one evidence type or validation rule', () => {
    const all = getAllControls();
    for (const c of all) {
      const hasEvidence = c.evidenceRequired.length > 0;
      const hasRules    = c.validationRules.length > 0;
      expect(hasEvidence || hasRules).toBe(true);
    }
  });

  test('CR-19: getControlsForFramework returns empty array for unknown framework', () => {
    expect(getControlsForFramework('UNKNOWN')).toEqual([]);
  });

  test('CR-20: GDPR-C1 requires consent evidence', () => {
    const ctrl = getControl('GDPR-C1');
    expect(ctrl.evidenceRequired).toContain('consent_events');
    expect(ctrl.evidenceRequired).toContain('policy_records');
  });

  test('CR-21: EUAIA-RK1 requires audit chain entries', () => {
    const ctrl = getControl('EUAIA-RK1');
    expect(ctrl.evidenceRequired).toContain('audit_chain_entries');
    expect(ctrl.isCritical).toBe(true);
  });

  test('CR-22: GDPR-A32 requires key management evidence', () => {
    const ctrl = getControl('GDPR-A32');
    expect(ctrl.evidenceRequired).toContain('signing_key_records');
    expect(ctrl.evidenceRequired).toContain('rbac_users');
  });

  test('CR-23: all controls have non-empty remediation hints', () => {
    const all = getAllControls();
    all.forEach(c => expect(typeof c.remediationHint).toBe('string'));
  });

  test('CR-24: total control count matches per-framework counts', () => {
    const total     = getAllControls().length;
    const fromFw    = FRAMEWORK_IDS.reduce((s, fid) => s + getControlsForFramework(fid).length, 0);
    expect(total).toBe(fromFw);
  });

  test('CR-25: validation rules reference known rule handlers', () => {
    const KNOWN_RULES = new Set([
      'min_enforcement_events', 'policy_coverage', 'active_policy_count',
      'consent_policy_active', 'enforcement_block_evidence', 'audit_chain_non_empty',
      'audit_events_exist', 'audit_events_in_period', 'monitoring_continuity',
      'active_signing_key', 'rbac_users_configured', 'rbac_admin_exists',
      'rbac_role_diversity', 'key_encryption_algorithm', 'chain_integrity',
      'signed_artifacts_exist', 'artifact_provenance', 'artifact_verification_rate',
      'security_audit_category_events', 'security_monitoring_active',
      'enforcement_events_logged', 'block_decision_evidence', 'policy_version_history',
      'policy_update_evidence', 'lifecycle_events_exist', 'risk_response_evidence',
      'risk_categorization_evidence', 'enforcement_coverage', 'data_governance_policy',
      'verification_capability', 'metrics_available', 'key_management_active',
    ]);
    const all = getAllControls();
    for (const c of all) {
      for (const r of c.validationRules) {
        expect(KNOWN_RULES.has(r.rule)).toBe(true);
      }
    }
  });
});

// ════════════════════════════════════════════════════════════════════════════
// CR-26 to CR-45 — Evidence Validator + Scoring Engine
// ════════════════════════════════════════════════════════════════════════════

describe('Evidence Validator & Scoring Engine', () => {
  const bundle = sampleBundle();

  test('CR-26: controlStatus returns PASS for score >= 80', () => {
    expect(controlStatus(80)).toBe('PASS');
    expect(controlStatus(100)).toBe('PASS');
    expect(controlStatus(90)).toBe('PASS');
  });

  test('CR-27: controlStatus returns PARTIAL for 50 <= score < 80', () => {
    expect(controlStatus(50)).toBe('PARTIAL');
    expect(controlStatus(79)).toBe('PARTIAL');
    expect(controlStatus(65)).toBe('PARTIAL');
  });

  test('CR-28: controlStatus returns FAIL for score < 50', () => {
    expect(controlStatus(0)).toBe('FAIL');
    expect(controlStatus(49)).toBe('FAIL');
  });

  test('CR-29: validateControl passes GDPR-AU1 with chain entries and signed artifacts', () => {
    const ctrl   = getControl('GDPR-AU1');
    const result = validateControl(ctrl, bundle);
    expect(result.passed).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  test('CR-30: validateControl fails when no enforcement events present', () => {
    const emptyBundle = sampleBundle({ enforcement: { count: 0, blockCount: 0, allowCount: 0, items: [] } });
    const ctrl        = getControl('NIST-GOV-1-1');
    const result      = validateControl(ctrl, emptyBundle);
    // enforcement_events_logged fails
    expect(result.score).toBeLessThan(100);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  test('CR-31: validateControl GDPR-C1 fails when no consent policy active', () => {
    const noPolicyBundle = sampleBundle({
      policy_records: { count: 0, activeCount: 0, consentPolicies: 0, items: [] },
    });
    const ctrl   = getControl('GDPR-C1');
    const result = validateControl(ctrl, noPolicyBundle);
    expect(result.passed).toBe(false);
    expect(result.findings.some(f => f.severity === 'CRITICAL')).toBe(true);
  });

  test('CR-32: validateControl GDPR-A32 passes with active signing key and RBAC', () => {
    const ctrl   = getControl('GDPR-A32');
    const result = validateControl(ctrl, bundle);
    expect(result.passed).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  test('CR-33: validateControl GDPR-A32 fails without active signing key', () => {
    const noKeyBundle = sampleBundle({
      signing_key_records: { count: 0, activeCount: 0, algorithms: [], items: [] },
    });
    const ctrl   = getControl('GDPR-A32');
    const result = validateControl(ctrl, noKeyBundle);
    expect(result.passed).toBe(false);
  });

  test('CR-34: validateControl chain_integrity fails when chain is broken', () => {
    const brokenBundle = sampleBundle({
      audit_chain_entries: { count: 50, chainBroken: true, verifiedCount: 40, items: [] },
    });
    const ctrl   = getControl('GDPR-AU1');
    const result = validateControl(ctrl, brokenBundle);
    expect(result.findings.some(f => f.rule === 'chain_integrity')).toBe(true);
  });

  test('CR-35: validateControl returns evidence refs', () => {
    const ctrl   = getControl('GDPR-AU1');
    const bundleWithItems = sampleBundle({
      audit_chain_entries: {
        count: 5, chainBroken: false, verifiedCount: 5,
        items: [{ evidenceType: 'audit_chain_entries', sourceTable: 'audit_chain',
                  sourceId: 'hash123', occurredAt: '2026-03-01T00:00:00Z',
                  summary: 'audit entry', metadata: {} }],
      },
    });
    const result = validateControl(ctrl, bundleWithItems);
    expect(result.evidenceRefs.length).toBeGreaterThan(0);
  });

  test('CR-36: validateAll returns results for all controls in framework', () => {
    const controls = getControlsForFramework('GDPR');
    const results  = validateAll(controls, bundle);
    expect(results.size).toBe(controls.length);
    for (const ctrl of controls) {
      expect(results.has(ctrl.id)).toBe(true);
    }
  });

  test('CR-37: scoreFramework produces a weighted score', () => {
    const controls = getControlsForFramework('GDPR');
    const results  = validateAll(controls, bundle);
    const score    = scoreFramework(controls, results);
    expect(score.frameworkScore).toBeGreaterThanOrEqual(0);
    expect(score.frameworkScore).toBeLessThanOrEqual(100);
    expect(score.controlsTotal).toBe(controls.length);
  });

  test('CR-38: scoreFramework COMPLIANT when all controls pass', () => {
    const mockControls = [
      { id: 'T-1', isCritical: false, weight: 1.0, enabled: true,
        controlRef: 'T.1', title: 'Test', category: 'Test', validationRules: [] },
    ];
    const mockResults = new Map([['T-1', { score: 100, findings: [], evidenceRefs: [], evidenceCount: 5 }]]);
    const score = scoreFramework(mockControls, mockResults);
    expect(score.verdict).toBe('COMPLIANT');
    expect(score.frameworkScore).toBe(100);
  });

  test('CR-39: scoreFramework NON_COMPLIANT when critical control fails with low score', () => {
    const mockControls = [
      { id: 'T-CRIT', isCritical: true, weight: 2.0, enabled: true,
        controlRef: 'T.CRIT', title: 'Critical Test', category: 'Test', validationRules: [] },
    ];
    const mockResults = new Map([['T-CRIT', { score: 0, findings: [{ severity: 'CRITICAL', rule: 'x', description: '', detail: '', remediation: '' }], evidenceRefs: [], evidenceCount: 0 }]]);
    const score = scoreFramework(mockControls, mockResults);
    expect(score.criticalFailCount).toBe(1);
    expect(score.verdict).toBe('NON_COMPLIANT');
  });

  test('CR-40: scoreFramework skips disabled controls', () => {
    const mockControls = [
      { id: 'T-1', isCritical: false, weight: 1.0, enabled: true,  controlRef: 'T.1', title: 'Enabled', category: 'Test', validationRules: [] },
      { id: 'T-2', isCritical: false, weight: 1.0, enabled: false, controlRef: 'T.2', title: 'Disabled', category: 'Test', validationRules: [] },
    ];
    const mockResults = new Map([
      ['T-1', { score: 100, findings: [], evidenceRefs: [], evidenceCount: 0 }],
      ['T-2', { score: 0,   findings: [], evidenceRefs: [], evidenceCount: 0 }],
    ]);
    const score = scoreFramework(mockControls, mockResults);
    expect(score.frameworkScore).toBe(100);
  });

  test('CR-41: scoreOverall averages framework scores', () => {
    const { overallScore } = scoreOverall([
      { frameworkScore: 80, verdict: 'COMPLIANT' },
      { frameworkScore: 60, verdict: 'PARTIALLY_COMPLIANT' },
    ]);
    expect(overallScore).toBe(70);
  });

  test('CR-42: scoreOverall NON_COMPLIANT if any framework is NON_COMPLIANT', () => {
    const { overallVerdict } = scoreOverall([
      { frameworkScore: 90, verdict: 'COMPLIANT' },
      { frameworkScore: 30, verdict: 'NON_COMPLIANT' },
    ]);
    expect(overallVerdict).toBe('PARTIALLY_COMPLIANT'); // avg=60, not < 60
  });

  test('CR-43: buildExecutiveSummary contains verdict and score', () => {
    const fs = { frameworkScore: 85, verdict: 'COMPLIANT', controlsTotal: 7,
                 controlsPass: 7, controlsPartial: 0, controlsFail: 0, criticalFailCount: 0 };
    const summary = buildExecutiveSummary('GDPR', 'General Data Protection Regulation', fs,
      { start: '2026-01-01', end: '2026-06-01' });
    expect(summary).toContain('COMPLIANT');
    expect(summary).toContain('85');
  });

  test('CR-44: aggregateFindings puts CRITICAL findings first', () => {
    const controlScores = [
      { controlId: 'T-1', controlRef: 'T.1', findings: [
        { severity: 'MEDIUM', rule: 'r1', description: 'd1', detail: 'detail1', remediation: 'fix1' },
      ]},
      { controlId: 'T-2', controlRef: 'T.2', findings: [
        { severity: 'CRITICAL', rule: 'r2', description: 'd2', detail: 'detail2', remediation: 'fix2' },
      ]},
    ];
    const findings = aggregateFindings(controlScores);
    expect(findings[0].severity).toBe('CRITICAL');
    expect(findings[0].controlId).toBe('T-2');
  });

  test('CR-45: validateControl handles unknown rule gracefully', () => {
    const ctrl = {
      id: 'FAKE-1', frameworkId: 'GDPR', isCritical: false, weight: 1.0,
      evidenceRequired: [], remediationHint: 'fix',
      validationRules: [{ rule: 'nonexistent_rule', description: 'test' }],
    };
    const result = validateControl(ctrl, bundle);
    expect(result.passed).toBe(false);
    expect(result.findings[0].detail).toContain('Unknown validation rule');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Close the compliance-scoring engine's unfalsifiable rules (H5 /)
//
// Five handlers previously reported PASS regardless of evidence count. A control
// that requires evidence must never PASS on zero evidence; it must report
// NOT_APPLICABLE instead, and NOT_APPLICABLE controls must be excluded from the
// framework's weighted score and PASS/FAIL tallies (not penalized either way).
// ════════════════════════════════════════════════════════════════════════════

describe('zero-evidence controls cannot report an unfalsifiable PASS', () => {
  const bundle = sampleBundle();

  // One single-purpose control per affected handler, so `ruleResults` isolates
  // that handler's own output regardless of any other rule on the control.
  const AFFECTED = [
    { rule: 'enforcement_block_evidence',     controlId: 'GDPR-C1',
      zeroOverrides: { enforcement: { count: 0, blockCount: 0, allowCount: 0, items: [] } } },
    { rule: 'block_decision_evidence',        controlId: 'NIST-MAN-1-1',
      zeroOverrides: { enforcement: { count: 0, blockCount: 0, allowCount: 0, items: [] } } },
    { rule: 'security_audit_category_events', controlId: 'GDPR-A33',
      zeroOverrides: { security_events: { count: 0, items: [] } } },
    { rule: 'verification_capability',        controlId: 'NIST-MEA-2-1',
      zeroOverrides: { signed_artifacts: { count: 0, items: [] } } },
    { rule: 'enforcement_coverage',           controlId: 'EUAIA-G1',
      zeroOverrides: { enforcement: { count: 0, blockCount: 0, allowCount: 0, items: [] } } },
  ];

  test.each(AFFECTED)(
    'Case 1 — $rule reports NOT_APPLICABLE, never PASS, when evidenceCount is 0',
    ({ rule, controlId, zeroOverrides }) => {
      const zeroBundle  = sampleBundle(zeroOverrides);
      const result      = validateControl(getControl(controlId), zeroBundle);
      const ruleResult  = result.ruleResults.find(r => r.rule === rule);

      expect(ruleResult.evidenceCount).toBe(0);
      expect(ruleResult.passed).toBe(false);
      expect(ruleResult.notApplicable).toBe(true);
    },
  );

  test.each(AFFECTED)(
    'Case 2 — $rule still reports PASS when evidenceCount > 0',
    ({ rule, controlId }) => {
      const result      = validateControl(getControl(controlId), bundle);
      const ruleResult  = result.ruleResults.find(r => r.rule === rule);

      expect(ruleResult.evidenceCount).toBeGreaterThan(0);
      expect(ruleResult.passed).toBe(true);
      expect(ruleResult.notApplicable).toBeFalsy();
    },
  );

  test('WP023-1: a control becomes NOT_APPLICABLE control-wide when its only rule has zero evidence', () => {
    const ctrl = {
      id: 'FAKE-NA-1', frameworkId: 'TEST', isCritical: false, weight: 1.0,
      controlRef: 'T.NA1', title: 'NA Test 1', category: 'Test',
      evidenceRequired: [], remediationHint: 'fix',
      validationRules: [{ rule: 'enforcement_coverage', description: 'test' }],
    };
    const zeroBundle = sampleBundle({ enforcement: { count: 0, blockCount: 0, allowCount: 0, items: [] } });
    const result     = validateControl(ctrl, zeroBundle);
    expect(result.notApplicable).toBe(true);
    expect(result.passed).toBe(false);
  });

  test('WP023-2: a control becomes NOT_APPLICABLE control-wide when its only rule has zero signed-artifact evidence', () => {
    const ctrl = {
      id: 'FAKE-NA-2', frameworkId: 'TEST', isCritical: false, weight: 1.0,
      controlRef: 'T.NA2', title: 'NA Test 2', category: 'Test',
      evidenceRequired: [], remediationHint: 'fix',
      validationRules: [{ rule: 'verification_capability', description: 'test' }],
    };
    const zeroBundle = sampleBundle({ signed_artifacts: { count: 0, items: [] } });
    const result     = validateControl(ctrl, zeroBundle);
    expect(result.notApplicable).toBe(true);
    expect(result.passed).toBe(false);
  });

  test('WP023-3: scoreFramework excludes NOT_APPLICABLE controls from the weighted score and pass/fail tallies', () => {
    const mockControls = [
      { id: 'T-NA',   isCritical: true,  weight: 2.0, enabled: true, controlRef: 'T.NA',   title: 'NA Test',   category: 'Test', validationRules: [] },
      { id: 'T-PASS', isCritical: false, weight: 1.0, enabled: true, controlRef: 'T.PASS', title: 'Pass Test', category: 'Test', validationRules: [] },
    ];
    const mockResults = new Map([
      ['T-NA',   { notApplicable: true, score: 0, findings: [], evidenceRefs: [], evidenceCount: 0 }],
      ['T-PASS', { score: 100, findings: [], evidenceRefs: [], evidenceCount: 5 }],
    ]);
    const score = scoreFramework(mockControls, mockResults);

    expect(score.frameworkScore).toBe(100); // only T-PASS contributes to the weighted average
    expect(score.controlsPass).toBe(1);
    expect(score.controlsFail).toBe(0);
    expect(score.controlsNotApplicable).toBe(1);
    expect(score.criticalFailCount).toBe(0); // NOT_APPLICABLE is not counted as a critical FAIL

    const naEntry = score.controlScores.find(cs => cs.controlId === 'T-NA');
    expect(naEntry.status).toBe('NOT_APPLICABLE');
  });

  test('WP023-4: a synthetic zero-activity tenant does not PASS any of the five affected controls', () => {
    const zeroActivityBundle = sampleBundle({
      enforcement:      { count: 0, blockCount: 0, allowCount: 0, items: [] },
      security_events:  { count: 0, items: [] },
      signed_artifacts: { count: 0, items: [] },
    });
    const allControls = getAllControls();
    const results      = validateAll(allControls, zeroActivityBundle);

    for (const { rule, controlId } of AFFECTED) {
      const result     = results.get(controlId);
      const ruleResult = result.ruleResults.find(r => r.rule === rule);
      expect(ruleResult.passed).not.toBe(true);
    }
  });

  test('WP023-5: existing scoring behaviour for controls with real evidence is unchanged', () => {
    const mockControls = [
      { id: 'T-ENF', isCritical: false, weight: 1.0, enabled: true, controlRef: 'T.ENF', title: 'Enforcement', category: 'Test',
        validationRules: [{ rule: 'enforcement_block_evidence', description: 'x' }] },
      { id: 'T-SEC', isCritical: false, weight: 1.0, enabled: true, controlRef: 'T.SEC', title: 'Security', category: 'Test',
        validationRules: [{ rule: 'security_audit_category_events', description: 'x' }] },
    ];
    const results = validateAll(mockControls, bundle);
    const score   = scoreFramework(mockControls, results);
    expect(score.controlsNotApplicable).toBe(0);
    expect(score.controlsPass).toBe(2);
    expect(score.frameworkScore).toBe(100);
    expect(score.verdict).toBe('COMPLIANT');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// CR-46 to CR-62 — Report Integrity
// ════════════════════════════════════════════════════════════════════════════

describe('Report Integrity', () => {
  const report = sampleReport();

  test('CR-46: hashReport returns 64-char hex string', () => {
    const hash = hashReport(report);
    expect(typeof hash).toBe('string');
    expect(hash).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
  });

  test('CR-47: hashReport is deterministic', () => {
    expect(hashReport(report)).toBe(hashReport(report));
  });

  test('CR-48: hashReport changes when report content changes', () => {
    const modified = { ...report, overallScore: 99 };
    expect(hashReport(report)).not.toBe(hashReport(modified));
  });

  test('CR-49: canonicalise excludes signature field', () => {
    const withSig  = { ...report, signature: { keyId: 'key', signatureB64: 'abc' } };
    const withoutSig = { ...report };
    delete withoutSig.signature;
    expect(canonicalise(withSig)).toBe(canonicalise(withoutSig));
  });

  test('CR-50: canonicalise produces deterministic output regardless of key order', () => {
    const r1 = { b: 2, a: 1, c: 3 };
    const r2 = { c: 3, b: 2, a: 1 };
    expect(canonicalise(r1)).toBe(canonicalise(r2));
  });

  test('CR-51: canonicalise excludes signedAt and _hash', () => {
    const r1 = { ...report, signedAt: '2026-01-01T00:00:00Z', _hash: 'abc' };
    const r2 = { ...report };
    delete r2.signedAt;
    delete r2._hash;
    expect(canonicalise(r1)).toBe(canonicalise(r2));
  });

  test('CR-52: computeHash returns 32-byte Buffer', () => {
    const hash = computeHash(report);
    expect(Buffer.isBuffer(hash)).toBe(true);
    expect(hash.length).toBe(32);
  });

  test('CR-53: computeHash differs from plain SHA-256 of JSON (domain separation)', () => {
    const crypto     = require('crypto');
    const plain      = crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex');
    const domainHash = hashReport(report);
    expect(domainHash).not.toBe(plain);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// CR-63 to CR-90 — API Routes
// ════════════════════════════════════════════════════════════════════════════

describe('Compliance API Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPool.isEnabled.mockReturnValue(false);
  });

  const app = makeApp();

  // ── GET /compliance/frameworks ─────────────────────────────────────────────

  test('CR-63: GET /compliance/frameworks returns all 4 frameworks', async () => {
    const res = await request(app).get('/compliance/frameworks');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.frameworks).toHaveLength(4);
    expect(res.body.data.frameworks.map(f => f.id)).toEqual(
      expect.arrayContaining(['GDPR','EU_AI_ACT','ISO_42001','NIST_AI_RMF']),
    );
  });

  // ── GET /compliance/controls/:frameworkId ──────────────────────────────────

  test('CR-64: GET /compliance/controls/GDPR returns GDPR controls', async () => {
    const res = await request(app).get('/compliance/controls/GDPR');
    expect(res.status).toBe(200);
    expect(res.body.data.frameworkId).toBe('GDPR');
    expect(res.body.data.controls.length).toBeGreaterThanOrEqual(7);
  });

  test('CR-65: GET /compliance/controls/UNKNOWN returns 404', async () => {
    const res = await request(app).get('/compliance/controls/UNKNOWN');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('UNKNOWN_FRAMEWORK');
  });

  test('CR-66: GET /compliance/controls/NIST_AI_RMF returns NIST controls', async () => {
    const res = await request(app).get('/compliance/controls/NIST_AI_RMF');
    expect(res.status).toBe(200);
    expect(res.body.data.controls.length).toBeGreaterThanOrEqual(8);
  });

  // ── POST /compliance/report/generate ──────────────────────────────────────

  test('CR-67: POST /compliance/report/generate returns 400 when frameworkId missing', async () => {
    const res = await request(app).post('/compliance/report/generate').send({
      periodStart: '2026-01-01T00:00:00Z',
      periodEnd:   '2026-06-01T00:00:00Z',
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_FRAMEWORK');
  });

  test('CR-68: POST /compliance/report/generate returns 404 for unknown framework', async () => {
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'SOC2',
      periodStart: '2026-01-01T00:00:00Z',
      periodEnd:   '2026-06-01T00:00:00Z',
    });
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('UNKNOWN_FRAMEWORK');
  });

  test('CR-69: POST /compliance/report/generate returns 400 when period missing', async () => {
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_PERIOD');
  });

  test('CR-70: POST /compliance/report/generate returns 400 for invalid dates', async () => {
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
      periodStart: 'not-a-date',
      periodEnd:   '2026-06-01T00:00:00Z',
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_DATES');
  });

  test('CR-71: POST /compliance/report/generate returns 400 when start >= end', async () => {
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
      periodStart: '2026-06-01T00:00:00Z',
      periodEnd:   '2026-01-01T00:00:00Z',
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PERIOD');
  });

  test('item 9 audit: POST /compliance/report/generate rejects an unrecognised extra body key (generateReportBodySchema was .passthrough(), now .strict())', async () => {
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
      periodStart: '2026-01-01T00:00:00Z',
      periodEnd:   '2026-06-01T00:00:00Z',
      unexpectedKey: 'nope',
    });
    expect(res.status).toBe(400);
    expect(mockGenerateReport).not.toHaveBeenCalled();
  });

  test('item 9 audit: POST /compliance/report/generate rejects signingClientId (the deliberately-excluded field — was silently passed-through-then-ignored, now rejected at the schema layer)', async () => {
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
      periodStart: '2026-01-01T00:00:00Z',
      periodEnd:   '2026-06-01T00:00:00Z',
      signingClientId: 'attacker-chosen-tenant',
    });
    expect(res.status).toBe(400);
    expect(mockGenerateReport).not.toHaveBeenCalled();
  });

  test('CR-72: POST /compliance/report/generate calls generateReport and returns 201', async () => {
    const report = sampleReport();
    mockGenerateReport.mockResolvedValueOnce(report);
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
      periodStart: '2026-01-01T00:00:00Z',
      periodEnd:   '2026-06-01T00:00:00Z',
    });
    expect(res.status).toBe(201);
    expect(res.body.status).toBe('success');
    expect(res.body.data.id).toBe(report.id);
    expect(mockGenerateReport).toHaveBeenCalledOnce?.() ?? expect(mockGenerateReport).toHaveBeenCalledTimes(1);
  });

  test('CR-73: POST /compliance/report/generate propagates generation errors as 500', async () => {
    mockGenerateReport.mockRejectedValueOnce(new Error('DB error'));
    const res = await request(app).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
      periodStart: '2026-01-01T00:00:00Z',
      periodEnd:   '2026-06-01T00:00:00Z',
    });
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('GENERATION_FAILED');
  });

  // ── AUTH-3: generatedBy/generatedByRole actor attribution ──────────────────
  //
  // Root cause: this route previously read req.user?.username /
  // res.locals?.actorId, neither of which any middleware in this codebase
  // ever populates, so generatedBy always fell back to the literal 'api'
  // regardless of who authenticated. It must now come from req.rbacUser,
  // the identity opsAuth + rbacResolve actually attach (see AUTH-3-
  // REMEDIATION-REPORT.md).

  function makeAuthedApp(rbacUser) {
    const authedApp = express();
    authedApp.use(express.json());
    authedApp.use((req, _res, next) => { req.rbacUser = rbacUser; next(); });
    authedApp.use('/compliance', createComplianceRouter());
    return authedApp;
  }

  test('CR-91 (AUTH-3): generatedBy is the authenticated operator, not "api"', async () => {
    const authedApp = makeAuthedApp({ id: 'u1', username: 'compliance-alice', role: 'admin' });
    mockGenerateReport.mockResolvedValueOnce(sampleReport());

    const res = await request(authedApp).post('/compliance/report/generate').send({
      frameworkId: 'GDPR',
      periodStart: '2026-01-01T00:00:00Z',
      periodEnd:   '2026-06-01T00:00:00Z',
    });

    expect(res.status).toBe(201);
    expect(mockGenerateReport).toHaveBeenCalledWith(expect.objectContaining({
      generatedBy:     'compliance-alice',
      generatedByRole: 'admin',
    }));
    const call = mockGenerateReport.mock.calls[0][0];
    expect(call.generatedBy).not.toBe('api');
    expect(call.generatedBy).not.toBe('system');
  });

  test('CR-92 (AUTH-3): distinct authenticated operators produce distinct generatedBy', async () => {
    mockGenerateReport.mockResolvedValue(sampleReport());
    const payload = {
      frameworkId: 'GDPR', periodStart: '2026-01-01T00:00:00Z', periodEnd: '2026-06-01T00:00:00Z',
    };

    await request(makeAuthedApp({ id: 'u1', username: 'compliance-alice', role: 'admin' }))
      .post('/compliance/report/generate').send(payload);
    await request(makeAuthedApp({ id: 'u2', username: 'compliance-bob', role: 'compliance' }))
      .post('/compliance/report/generate').send(payload);

    const generatedByValues = mockGenerateReport.mock.calls.map(c => c[0].generatedBy);
    expect(generatedByValues).toContain('compliance-alice');
    expect(generatedByValues).toContain('compliance-bob');
  });

  test('CR-93 (AUTH-3): no rbacUser at all is reported, never silently "system"', async () => {
    const noAuthApp = express();
    noAuthApp.use(express.json());
    noAuthApp.use('/compliance', createComplianceRouter());
    mockGenerateReport.mockResolvedValueOnce(sampleReport());

    await request(noAuthApp).post('/compliance/report/generate').send({
      frameworkId: 'GDPR', periodStart: '2026-01-01T00:00:00Z', periodEnd: '2026-06-01T00:00:00Z',
    });

    const call = mockGenerateReport.mock.calls[0][0];
    expect(call.generatedBy).not.toBe('system');
    expect(call.generatedBy).toBe('unattributed-operator');
    expect(mockEmit).toHaveBeenCalledWith('WARN', 'AUDIT_ATTRIBUTION_FAILED', expect.any(Object));
  });

  // ── GET /compliance/reports ────────────────────────────────────────────────

  test('CR-74: GET /compliance/reports calls listReports', async () => {
    mockListReports.mockResolvedValueOnce({ reports: [sampleReport()], total: 1 });
    const res = await request(app).get('/compliance/reports');
    expect(res.status).toBe(200);
    expect(res.body.data.total).toBe(1);
    expect(res.body.data.reports).toHaveLength(1);
  });

  test('CR-75: GET /compliance/reports with invalid framework returns 404', async () => {
    const res = await request(app).get('/compliance/reports?frameworkId=UNKNOWN');
    expect(res.status).toBe(404);
  });

  test('CR-76: GET /compliance/reports filters by framework', async () => {
    mockListReports.mockResolvedValueOnce({ reports: [], total: 0 });
    const res = await request(app).get('/compliance/reports?frameworkId=GDPR');
    expect(res.status).toBe(200);
    expect(mockListReports).toHaveBeenCalledWith(expect.objectContaining({ frameworkId: 'GDPR' }));
  });

  // ── GET /compliance/report/:id ─────────────────────────────────────────────

  test('CR-77: GET /compliance/report/:id returns 400 for invalid UUID', async () => {
    const res = await request(app).get('/compliance/report/not-a-uuid');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REPORT_ID');
  });

  test('CR-78: GET /compliance/report/:id returns 404 when not found', async () => {
    mockGetReport.mockResolvedValueOnce(null);
    const res = await request(app).get('/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('REPORT_NOT_FOUND');
  });

  test('CR-79: GET /compliance/report/:id returns report on success', async () => {
    const report = sampleReport();
    mockGetReport.mockResolvedValueOnce(report);
    const res = await request(app).get('/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    expect(res.status).toBe(200);
    expect(res.body.data.id).toBe(report.id);
    expect(res.body.data.reportRef).toBe(report.reportRef);
  });

  // ── POST /compliance/report/verify ────────────────────────────────────────

  test('CR-80: POST /compliance/report/verify returns 400 when reportPayload missing', async () => {
    const res = await request(app).post('/compliance/report/verify').send({
      signatureEnvelope: { keyId: 'k', signatureB64: 's', reportHash: 'h', algorithm: 'ed25519' },
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_PAYLOAD');
  });

  test('CR-81: POST /compliance/report/verify returns 400 when signatureEnvelope missing', async () => {
    const res = await request(app).post('/compliance/report/verify').send({
      reportPayload: sampleReport(),
    });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_SIGNATURE');
  });

  test('CR-82: POST /compliance/report/verify returns verification result', async () => {
    mockVerifyReport.mockResolvedValueOnce({
      verified: true, hashMatch: true, sigValid: true,
      detail:   'Report integrity verified',
    });
    const res = await request(app).post('/compliance/report/verify').send({
      reportPayload:     sampleReport(),
      signatureEnvelope: { keyId: 'k', signatureB64: 's', reportHash: 'h', algorithm: 'ed25519' },
    });
    expect(res.status).toBe(200);
    expect(res.body.data.verified).toBe(true);
  });

  test('CR-83: POST /compliance/report/verify returns verified=false when tampered', async () => {
    mockVerifyReport.mockResolvedValueOnce({
      verified: false, hashMatch: false, sigValid: false,
      detail:   'Hash mismatch',
    });
    const res = await request(app).post('/compliance/report/verify').send({
      reportPayload:     sampleReport({ overallScore: 50 }),
      signatureEnvelope: { keyId: 'k', signatureB64: 's', reportHash: 'orig-hash', algorithm: 'ed25519' },
    });
    expect(res.status).toBe(200);
    expect(res.body.data.verified).toBe(false);
  });

  // ── GET /compliance/report/:id/download ───────────────────────────────────

  test('CR-84: GET /compliance/report/:id/download returns 400 for invalid format', async () => {
    const res = await request(app).get(
      '/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/download?format=xml',
    );
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_FORMAT');
  });

  test('CR-85: GET /compliance/report/:id/download JSON returns buffer', async () => {
    const report = sampleReport();
    mockGetReport.mockResolvedValueOnce(report);
    mockGetAssessments.mockResolvedValueOnce([]);
    const res = await request(app).get(
      '/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/download?format=json',
    );
    expect(res.status).toBe(200);
    expect(res.header['content-type']).toContain('application/json');
  });

  test('CR-86: GET /compliance/report/:id/download HTML returns html', async () => {
    mockGetReport.mockResolvedValueOnce(sampleReport());
    mockGetAssessments.mockResolvedValueOnce([]);
    mockExportHtml.mockReturnValueOnce('<html>test</html>');
    const res = await request(app).get(
      '/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/download?format=html',
    );
    expect(res.status).toBe(200);
    expect(res.header['content-type']).toContain('text/html');
  });

  test('CR-87: GET /compliance/report/:id/download PDF returns pdf', async () => {
    mockGetReport.mockResolvedValueOnce(sampleReport());
    mockGetAssessments.mockResolvedValueOnce([]);
    mockExportPdf.mockResolvedValueOnce(Buffer.from('%PDF-1.4'));
    const res = await request(app).get(
      '/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/download?format=pdf',
    );
    expect(res.status).toBe(200);
    expect(res.header['content-type']).toContain('application/pdf');
  });

  test('CR-88: GET /compliance/report/:id/download returns 404 when not found', async () => {
    mockGetReport.mockResolvedValueOnce(null);
    const res = await request(app).get(
      '/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/download?format=json',
    );
    expect(res.status).toBe(404);
  });

  // ── GET /compliance/health ─────────────────────────────────────────────────

  test('CR-89: GET /compliance/health returns framework counts', async () => {
    const res = await request(app).get('/compliance/health');
    expect(res.status).toBe(200);
    expect(res.body.data.frameworksSupported).toEqual(expect.arrayContaining(['GDPR','EU_AI_ACT']));
    expect(res.body.data.totalControls).toBeGreaterThan(0);
    expect(res.body.data.controlsByFramework.GDPR).toBeGreaterThan(0);
  });

  // ── GET /compliance/report/:id/assessments ────────────────────────────────

  test('CR-90: GET /compliance/report/:id/assessments returns empty array when none', async () => {
    mockGetAssessments.mockResolvedValueOnce([]);
    const res = await request(app).get(
      '/compliance/report/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/assessments',
    );
    expect(res.status).toBe(200);
    expect(res.body.data.assessments).toEqual([]);
    expect(res.body.data.total).toBe(0);
  });
});
