'use strict';

/**
 * QODIQA Compliance Report Generator
 *
 * Orchestrates the end-to-end compliance report generation pipeline:
 *   1. Validate inputs
 *   2. Collect evidence from all QODIQA data sources
 *   3. Validate evidence per-control
 *   4. Score each control and the overall framework
 *   5. Assemble the structured report
 *   6. Persist to compliance_reports + child tables
 *   7. Optionally sign and store signature
 *
 * One report = one framework.  Run separately for each framework.
 *
 * The report object schema (JSON) is the canonical representation.
 * All other formats (PDF, HTML) are derived from it.
 */

const { v4: uuidv4 }      = require('crypto');
const pgPool               = require('../../infra/postgres/pool');
const rolePools = require('../../infra/postgres/rolePools'); // operator compliance views run as qodiqa_reporting
const { emit }             = require('../../../services/logger');
const { getControlsForFramework, isValidFramework, getAllControls } = require('./controlRegistry');
const { collectAll }       = require('./evidenceCollector');
const { validateAll }      = require('./evidenceValidator');
const { scoreFramework, buildExecutiveSummary, aggregateFindings } = require('./scoringEngine');
const { hashReport, signReport } = require('./reportIntegrity');

const GENERATOR_VERSION = '1.0.0';
const SCHEMA_VERSION    = '1.0';

// ── Reference number generator ────────────────────────────────────────────────

function _reportRef(frameworkId) {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const rand = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `RPT-${frameworkId.replace(/_/g, '')}-${date}-${rand}`;
}

// ── Crypto UUID (no external dep) ─────────────────────────────────────────────

function _uuid() {
  const crypto = require('crypto');
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return [h.slice(0,8), h.slice(8,12), h.slice(12,16), h.slice(16,20), h.slice(20,32)].join('-');
}

// ── Main generator ────────────────────────────────────────────────────────────

/**
 * Generate a compliance report for the given framework and period.
 *
 * @param {{
 *   frameworkId:  string,
 *   periodStart:  Date | string,
 *   periodEnd:    Date | string,
 *   generatedBy:  string,
 *   generatedByRole?: string,
 *   tenantId?:    string,
 *   sign?:        boolean,
 *   signingClientId?: string,
 * }} opts
 * @returns {Promise<ComplianceReport>}
 */
async function generateReport(opts = {}) {
  const {
    frameworkId,
    periodStart,
    periodEnd,
    generatedBy,
    generatedByRole,
    tenantId      = null,
    sign          = false,
    signingClientId = process.env.QODIQA_CLIENT_ID,
  } = opts;

  if (!frameworkId)      throw new Error('generateReport: frameworkId is required');
  if (!isValidFramework(frameworkId)) {
    throw new Error(`generateReport: unknown framework "${frameworkId}"`);
  }
  if (!periodStart || !periodEnd) throw new Error('generateReport: periodStart and periodEnd are required');
  if (!generatedBy) throw new Error('generateReport: generatedBy is required');

  const start = new Date(periodStart);
  const end   = new Date(periodEnd);
  if (isNaN(start.getTime()) || isNaN(end.getTime())) {
    throw new Error('generateReport: invalid date values for periodStart or periodEnd');
  }
  if (start >= end) throw new Error('generateReport: periodStart must be before periodEnd');

  const reportId  = _uuid();
  const reportRef = _reportRef(frameworkId);
  const controls  = getControlsForFramework(frameworkId);

  emit('INFO', 'COMPLIANCE_REPORT_GENERATION_STARTED', {
    reportId, reportRef, frameworkId, generatedBy,
    periodStart: start.toISOString(), periodEnd: end.toISOString(),
  });

  // ── Persist initial record ──────────────────────────────────────────────────
  if (pgPool.isEnabled()) {
    // a tenant-scoped report's INSERT failed crp_tenant_insert's
    // WITH CHECK (tenant_id IS NULL OR tenant_id = qodiqa_current_tenant())
    // under a plain query, which never sets session tenant context -- every
    // tenant-scoped generateReport() call threw before this fix. The
    // platform-wide case (tenantId null) is unaffected -- that predicate
    // already admits it. See D1/D5.
    const insertSql = `INSERT INTO compliance_reports
         (id, report_ref, framework_id, framework_name, tenant_id, title,
          period_start, period_end, generated_by, generated_by_role,
          generator_version, schema_version, status, controls_total)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'GENERATING',$13)`;
    const insertParams = [
      reportId, reportRef, frameworkId, _frameworkName(frameworkId),
      tenantId,
      `${_frameworkName(frameworkId)} Compliance Report`,
      start, end,
      generatedBy, generatedByRole ?? null,
      GENERATOR_VERSION, SCHEMA_VERSION,
      controls.length,
    ];
    if (tenantId) {
      await pgPool.withTenantTransaction(tenantId, (tx) => tx.query(insertSql, insertParams));
    } else {
      await pgPool.query(insertSql, insertParams, 'compliance_report_insert');
    }
  }

  try {
    // ── 1. Collect evidence ─────────────────────────────────────────────────
    const bundle = await collectAll({ periodStart: start, periodEnd: end, tenantId });

    // ── 2. Validate per-control ─────────────────────────────────────────────
    const validationResults = validateAll(controls, bundle);

    // ── 3. Score ────────────────────────────────────────────────────────────
    const frameworkScore = scoreFramework(controls, validationResults);
    const findings       = aggregateFindings(frameworkScore.controlScores);
    const criticalFindings = findings.filter(f => f.severity === 'CRITICAL').length;

    // ── 4. Assemble report payload ──────────────────────────────────────────
    const period = {
      start: start.toISOString(),
      end:   end.toISOString(),
    };

    const executiveSummary = buildExecutiveSummary(
      frameworkId, _frameworkName(frameworkId), frameworkScore, period,
    );

    const report = {
      id:               reportId,
      reportRef,
      schemaVersion:    SCHEMA_VERSION,
      generatorVersion: GENERATOR_VERSION,
      framework: {
        id:      frameworkId,
        name:    _frameworkName(frameworkId),
        version: _frameworkVersion(frameworkId),
        issuer:  _frameworkIssuer(frameworkId),
      },
      generatedAt:     new Date().toISOString(),
      generatedBy,
      generatedByRole: generatedByRole ?? null,
      tenantId,
      period,
      executiveSummary,
      overallScore:    frameworkScore.frameworkScore,
      overallVerdict:  frameworkScore.verdict,
      controlsSummary: {
        total:           frameworkScore.controlsTotal,
        pass:            frameworkScore.controlsPass,
        partial:         frameworkScore.controlsPartial,
        fail:            frameworkScore.controlsFail,
        criticalFails:   frameworkScore.criticalFailCount,
      },
      controlAssessments: frameworkScore.controlScores.map(cs => ({
        controlId:     cs.controlId,
        controlRef:    cs.controlRef,
        title:         cs.title,
        category:      cs.category,
        status:        cs.status,
        score:         cs.score,
        isCritical:    cs.isCritical,
        evidenceCount: cs.evidenceCount,
        findings:      cs.findings,
      })),
      findings,
      findingsCount:   findings.length,
      criticalFindings,
      evidenceSummary: _buildEvidenceSummary(bundle),
      evidenceCount:   _countTotalEvidence(bundle),
      recommendations: _buildRecommendations(findings),
    };

    // ── 5. Hash the report ──────────────────────────────────────────────────
    const reportHash = hashReport(report);
    report._hash = reportHash;

    // ── 6. Optionally sign ──────────────────────────────────────────────────
    let signatureEnvelope = null;
    if (sign && !signingClientId) {
      throw new Error('generateReport: sign=true requires QODIQA_CLIENT_ID to be set — no default signing client is permitted');
    }
    if (sign) {
      try {
        signatureEnvelope = await signReport(report, signingClientId);
        report.signature  = {
          keyId:       signatureEnvelope.keyId,
          algorithm:   signatureEnvelope.algorithm,
          signatureB64: signatureEnvelope.signatureB64,
          signedAt:    signatureEnvelope.signedAt,
        };
      } catch (sigErr) {
        emit('WARN', 'COMPLIANCE_REPORT_SIGN_FAILED', {
          reportId, error: sigErr.message,
        });
      }
    }

    // ── 7. Persist results ──────────────────────────────────────────────────
    if (pgPool.isEnabled()) {
      await _persistResults({
        reportId, tenantId, report, frameworkScore, validationResults,
        controls, bundle, reportHash, signatureEnvelope,
      });
    }

    emit('INFO', 'COMPLIANCE_REPORT_COMPLETE', {
      reportId,
      reportRef,
      frameworkId,
      score:          frameworkScore.frameworkScore,
      verdict:        frameworkScore.verdict,
      controlsPass:   frameworkScore.controlsPass,
      controlsFail:   frameworkScore.controlsFail,
      criticalFails:  frameworkScore.criticalFailCount,
      signed:         signatureEnvelope !== null,
    });

    return report;

  } catch (err) {
    emit('ERROR', 'COMPLIANCE_REPORT_GENERATION_FAILED', {
      reportId, reportRef, frameworkId, error: err.message,
    });

    if (pgPool.isEnabled()) {
      // same tenant-context requirement as the initial INSERT above
      // -- crp_tenant_update's WITH CHECK silently failed this UPDATE (0 rows)
      // for any tenant-scoped report under a plain query.
      const failSql = `UPDATE compliance_reports
         SET status = 'FAILED', error_message = $2
         WHERE id = $1`;
      const failFn = tenantId
        ? () => pgPool.withTenantTransaction(tenantId, (tx) => tx.query(failSql, [reportId, err.message]))
        : () => pgPool.query(failSql, [reportId, err.message], 'compliance_report_fail');
      await failFn().catch(() => {});
    }

    throw err;
  }
}

// ── Persistence helpers ───────────────────────────────────────────────────────

async function _persistResults({ reportId, tenantId, report, frameworkScore, validationResults, controls, bundle, reportHash, signatureEnvelope }) {
  // the header UPDATE below targets compliance_reports itself
  // (crp_tenant_update-gated); the child-table INSERTs inside (control
  // assessments/evidence refs/signature) are all permissive USING(true)/
  // WITH CHECK(true) (migration 005) and unaffected either way. Use
  // withTenantTransaction only when tenantId is present so the header UPDATE
  // succeeds for a tenant-scoped report; the platform-wide case (tenantId
  // null) is already admitted by crp_tenant_update under plain withTransaction.
  const runPersist = tenantId
    ? (fn) => pgPool.withTenantTransaction(tenantId, fn)
    : (fn) => pgPool.withTransaction(fn);
  await runPersist(async ({ query }) => {
    // Update report header
    await query(
      `UPDATE compliance_reports SET
         status            = 'COMPLETE',
         overall_score     = $2,
         controls_total    = $3,
         controls_pass     = $4,
         controls_partial  = $5,
         controls_fail     = $6,
         evidence_count    = $7,
         findings_count    = $8,
         critical_findings = $9,
         executive_summary = $10,
         overall_verdict   = $11,
         report_hash       = $12,
         signed            = $13
       WHERE id = $1`,
      [
        reportId,
        frameworkScore.frameworkScore,
        frameworkScore.controlsTotal,
        frameworkScore.controlsPass,
        frameworkScore.controlsPartial,
        frameworkScore.controlsFail,
        report.evidenceCount,
        report.findingsCount,
        report.criticalFindings,
        report.executiveSummary,
        frameworkScore.verdict,
        reportHash,
        signatureEnvelope !== null,
      ],
    );

    // Insert control assessments
    for (const cs of frameworkScore.controlScores) {
      const vr = validationResults.get(cs.controlId) ?? {};
      await query(
        `INSERT INTO compliance_control_assessments
           (report_id, control_id, framework_id, status, score,
            evidence_count, findings, detail)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (report_id, control_id) DO UPDATE SET
           status = EXCLUDED.status, score = EXCLUDED.score,
           evidence_count = EXCLUDED.evidence_count, findings = EXCLUDED.findings,
           detail = EXCLUDED.detail`,
        [
          reportId,
          cs.controlId,
          report.framework.id,
          cs.status,
          cs.score,
          cs.evidenceCount,
          JSON.stringify(cs.findings),
          cs.findings.map(f => f.detail).join('; ').slice(0, 2000),
        ],
      );

      // Insert evidence refs for this control
      const ctrl = controls.find(c => c.id === cs.controlId);
      const refs  = vr.evidenceRefs ?? [];
      for (const ref of refs.slice(0, 10)) {
        await query(
          `INSERT INTO compliance_evidence_refs
             (report_id, control_id, evidence_type, source_table,
              source_id, occurred_at, summary, valid, integrity_ok, metadata)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            reportId, cs.controlId, ref.evidenceType, ref.sourceTable,
            ref.sourceId, ref.occurredAt ? new Date(ref.occurredAt) : null,
            ref.summary.slice(0, 500), ref.valid !== false, ref.integrityOk !== false,
            JSON.stringify(ref.metadata ?? {}),
          ],
        ).catch(() => {}); // non-fatal: evidence ref is supplemental
      }
    }

    // Insert signature
    if (signatureEnvelope) {
      await query(
        `INSERT INTO compliance_report_signatures
           (report_id, key_id, algorithm, signature_b64, report_hash, signer_id)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (report_id) DO UPDATE SET
           key_id = EXCLUDED.key_id, algorithm = EXCLUDED.algorithm,
           signature_b64 = EXCLUDED.signature_b64, report_hash = EXCLUDED.report_hash,
           signer_id = EXCLUDED.signer_id, signed_at = NOW()`,
        [
          reportId,
          signatureEnvelope.keyId,
          signatureEnvelope.algorithm,
          signatureEnvelope.signatureB64,
          signatureEnvelope.reportHash,
          signatureEnvelope.signerId,
        ],
      );
    }
  });
}

// ── Evidence summary ──────────────────────────────────────────────────────────

function _buildEvidenceSummary(bundle) {
  return {
    enforcementEvents:     bundle.enforcement?.count ?? 0,
    policyRecords:         bundle.policy_records?.count ?? 0,
    activePolicies:        bundle.policy_records?.activeCount ?? 0,
    auditEvents:           bundle.audit_events?.count ?? 0,
    securityEvents:        bundle.security_events?.count ?? 0,
    lifecycleEvents:       bundle.lifecycle_events?.count ?? 0,
    keyManagementEvents:   bundle.key_management_events?.count ?? 0,
    auditChainEntries:     bundle.audit_chain_entries?.count ?? 0,
    signedArtifacts:       bundle.signed_artifacts?.count ?? 0,
    rbacUsers:             bundle.rbac_users?.count ?? 0,
    activeSigningKeys:     bundle.signing_key_records?.activeCount ?? 0,
    consentEvents:         bundle.consent_events?.count ?? 0,
    chainIntegrityOk:      !(bundle.audit_chain_entries?.chainBroken ?? false),
  };
}

function _countTotalEvidence(bundle) {
  return (bundle.enforcement?.count ?? 0)
    + (bundle.policy_records?.count ?? 0)
    + (bundle.audit_chain_entries?.count ?? 0)
    + (bundle.rbac_users?.count ?? 0)
    + (bundle.signing_key_records?.count ?? 0);
}

function _buildRecommendations(findings) {
  const seen  = new Set();
  const recs  = [];
  for (const f of findings) {
    if (f.remediation && !seen.has(f.remediation)) {
      seen.add(f.remediation);
      recs.push({
        controlId:  f.controlId,
        severity:   f.severity,
        action:     f.remediation,
      });
    }
  }
  return recs;
}

// ── Framework metadata ────────────────────────────────────────────────────────

function _frameworkName(id) {
  return {
    GDPR:          'General Data Protection Regulation',
    EU_AI_ACT:     'EU Artificial Intelligence Act',
    ISO_42001:     'ISO/IEC 42001:2023',
    NIST_AI_RMF:   'NIST AI Risk Management Framework',
  }[id] ?? id;
}

function _frameworkVersion(id) {
  return { GDPR: '2016/679', EU_AI_ACT: '2024/1689', ISO_42001: '2023', NIST_AI_RMF: '1.0' }[id] ?? '1.0';
}

function _frameworkIssuer(id) {
  return {
    GDPR:         'European Parliament',
    EU_AI_ACT:    'European Parliament',
    ISO_42001:    'ISO/IEC JTC 1/SC 42',
    NIST_AI_RMF:  'NIST',
  }[id] ?? 'Unknown';
}

// ── Report retrieval ──────────────────────────────────────────────────────────

async function getReport(reportId) {
  if (!pgPool.isEnabled()) throw new Error('PostgreSQL not enabled');

  // GET /compliance/report/:id carries no tenant scoping at all
  // (Shape G, RBAC-gated ops console) -- a plain query's crp_tenant_select
  // restriction silently hid every tenant-scoped report from this endpoint.
  // Fixed via the SECURITY DEFINER full-read bypass (migration 053). See
  // D1/D2.
  const res = await rolePools.reporting.query(
    `SELECT r.*,
            s.key_id, s.algorithm, s.signature_b64, s.report_hash AS sig_hash,
            s.signed_at, s.signer_id, s.verified, s.verified_at
     FROM qodiqa_compliance_reports_full_read() r
     LEFT JOIN compliance_report_signatures s ON s.report_id = r.id
     WHERE r.id = $1`,
    [reportId],
    'compliance_get_report',
  );

  if (res.rows.length === 0) return null;
  return _hydrateReport(res.rows[0]);
}

async function listReports({ frameworkId, tenantId, status, limit = 20, offset = 0 } = {}) {
  if (!pgPool.isEnabled()) return { reports: [], total: 0 };

  const params  = [];
  const clauses = [];
  let   p       = 1;

  if (frameworkId) { clauses.push(`r.framework_id = $${p++}`); params.push(frameworkId); }
  if (tenantId)    { clauses.push(`r.tenant_id = $${p++}`);    params.push(tenantId);    }
  if (status)      { clauses.push(`r.status = $${p++}`);       params.push(status);      }

  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  // tenantId was already an existing WHERE filter here, but with no
  // session tenant context ever set crp_tenant_select's RLS restricted every
  // call -- filtered or not -- to platform-level rows only, so a real
  // tenantId filter was always the empty set. Mirrors AlertStore.listAlerts's
  // identical fix: withTenantTransaction when one tenantId is given (Shape T),
  // the SECURITY DEFINER full-read bypass when listing across all tenants
  // (Shape G, the ops-console default). See D1.
  const countSql = `SELECT COUNT(*) AS total FROM %FROM% r ${where}`;
  params.push(Math.min(limit, 100), offset);
  const listSql = `SELECT r.id, r.report_ref, r.framework_id, r.framework_name, r.tenant_id,
            r.title, r.period_start, r.period_end, r.generated_at, r.generated_by,
            r.status, r.overall_score, r.overall_verdict, r.controls_total,
            r.controls_pass, r.controls_fail, r.evidence_count, r.findings_count,
            r.critical_findings, r.signed, r.report_hash
     FROM %FROM% r
     ${where}
     ORDER BY r.generated_at DESC, r.id DESC
     LIMIT $${p++} OFFSET $${p}`;

  const countParams = params.slice(0, params.length - 2);
  const [countRes, listRes] = tenantId
    ? await pgPool.withTenantTransaction(tenantId, (tx) => Promise.all([
        tx.query(countSql.replace('%FROM%', 'compliance_reports'), countParams),
        tx.query(listSql.replace('%FROM%', 'compliance_reports'), params),
      ]))
    : await Promise.all([
        rolePools.reporting.query(countSql.replace('%FROM%', 'qodiqa_compliance_reports_full_read()'), countParams, 'compliance_list_count'),
        rolePools.reporting.query(listSql.replace('%FROM%', 'qodiqa_compliance_reports_full_read()'), params, 'compliance_list_reports'),
      ]);

  return {
    reports: listRes.rows,
    total:   Number(countRes.rows[0]?.total ?? 0),
  };
}

async function getControlAssessments(reportId) {
  if (!pgPool.isEnabled()) return [];

  const res = await pgPool.query(
    `SELECT cca.*, cc.title, cc.control_ref, cc.category, cc.weight, cc.is_critical,
            cc.remediation_hint
     FROM compliance_control_assessments cca
     JOIN compliance_controls cc ON cc.id = cca.control_id
     WHERE cca.report_id = $1
     ORDER BY cca.score ASC, cca.control_id ASC`,
    [reportId],
    'compliance_get_assessments',
  );
  return res.rows;
}

function _hydrateReport(row) {
  const report = { ...row };
  if (row.key_id) {
    report.signature = {
      keyId:        row.key_id,
      algorithm:    row.algorithm,
      signatureB64: row.signature_b64,
      reportHash:   row.sig_hash,
      signedAt:     row.signed_at,
      signerId:     row.signer_id,
      verified:     row.verified,
      verifiedAt:   row.verified_at,
    };
    // Clean up flattened sig fields
    ['key_id','algorithm','signature_b64','sig_hash','signed_at','signer_id','verified','verified_at'].forEach(k => delete report[k]);
  }
  return report;
}

module.exports = {
  generateReport,
  getReport,
  listReports,
  getControlAssessments,
};
