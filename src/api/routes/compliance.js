'use strict';

/**
 * QODIQA Compliance Reporting API
 *
 * Mounts at /compliance (ops-protected, RBAC-gated).
 *
 * Routes:
 *   POST /compliance/report/generate           — generate a new report
 *   GET  /compliance/reports                   — list reports
 *   GET  /compliance/report/:id                — report details
 *   GET  /compliance/report/:id/assessments    — per-control assessments
 *   POST /compliance/report/verify             — verify report integrity
 *   GET  /compliance/report/:id/download       — download (JSON|PDF|HTML)
 *   GET  /compliance/frameworks                — list supported frameworks
 *   GET  /compliance/controls/:frameworkId     — controls for a framework
 *   GET  /compliance/health                    — scoring health check
 *
 * RBAC gates:
 *   READ_COMPLIANCE  — read reports, download, list
 *   GENERATE_REPORT  — generate new reports
 *   VERIFY_REPORT    — verify report integrity (may be unauthenticated for auditors)
 */

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const express = require('express');
const { emit }     = require('../../../services/logger');
const { resolveOperatorActor } = require('../../core/audit/actorAttribution');
const {
  generateReport,
  getReport,
  listReports,
  getControlAssessments,
}                  = require('../../core/compliance/reportGenerator');
const { verifyReport } = require('../../core/compliance/reportIntegrity');
const { parsePagination, withPaginationMeta } = require('../../utils/pagination');
const { exportJson, exportJsonBuffer } = require('../../core/compliance/exporters/jsonExporter');
const { exportPdf }  = require('../../core/compliance/exporters/pdfExporter');
const { exportHtml } = require('../../core/compliance/exporters/htmlExporter');
const {
  FRAMEWORK_IDS,
  getAllControls,
  getControlsForFramework,
  isValidFramework,
} = require('../../core/compliance/controlRegistry');
const pgPool = require('../../infra/postgres/pool');
const { generateReportBodySchema } = require('../../validation/schemas/compliance.schema');
const { success, failure, internalError } = require('../response');
const { safeAttachmentHeader } = require('../../utils/contentDisposition');


// ── Response helpers ──────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (data, meta) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js. Any extra
// `meta` fields are merged into `data` rather than added as top-level
// siblings, since the canonical envelope has no such sibling slot.
function _ok(res, data, meta = {}) {
  return success(res, { ...data, ...meta });
}

function _err(res, code, detail, status = 400) {
  return failure(res, code, detail, status);
}

// ── Validate UUID ─────────────────────────────────────────────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ── Router factory ────────────────────────────────────────────────────────────

function createComplianceRouter({ requirePermission } = {}) {
  const router = express.Router();

  const _canRead     = permissionGuard(requirePermission, 'READ_COMPLIANCE', 'compliance');
  const _canGenerate = permissionGuard(requirePermission, 'GENERATE_REPORT', 'compliance');

  // ── GET /compliance/frameworks ─────────────────────────────────────────────

  router.get('/frameworks', _canRead, (_req, res) => {
    _ok(res, {
      frameworks: [
        { id: 'GDPR',        name: 'General Data Protection Regulation',     version: '2016/679',  issuer: 'European Parliament' },
        { id: 'EU_AI_ACT',   name: 'EU Artificial Intelligence Act',          version: '2024/1689', issuer: 'European Parliament' },
        { id: 'ISO_42001',   name: 'ISO/IEC 42001:2023',                      version: '2023',      issuer: 'ISO/IEC JTC 1/SC 42' },
        { id: 'NIST_AI_RMF', name: 'NIST AI Risk Management Framework',       version: '1.0',       issuer: 'NIST' },
      ],
      total: FRAMEWORK_IDS.length,
    });
  });

  // ── GET /compliance/controls/:frameworkId ──────────────────────────────────

  router.get('/controls/:frameworkId', _canRead, (req, res) => {
    const { frameworkId } = req.params;
    if (!isValidFramework(frameworkId)) {
      return _err(res, 'UNKNOWN_FRAMEWORK', `Unknown framework: "${frameworkId}"`, 404);
    }
    const controls = getControlsForFramework(frameworkId).map(c => ({
      id:          c.id,
      controlRef:  c.controlRef,
      title:       c.title,
      description: c.description,
      category:    c.category,
      weight:      c.weight,
      isCritical:  c.isCritical,
      evidenceRequired: c.evidenceRequired,
    }));
    _ok(res, { frameworkId, controls, total: controls.length });
  });

  // ── POST /compliance/report/generate ──────────────────────────────────────

  router.post('/report/generate', _canGenerate, async (req, res) => {
    const grParsed = generateReportBodySchema.safeParse(req.body ?? {});
    if (!grParsed.success) {
      const issue    = grParsed.error.issues[0];
      const msg      = issue?.message ?? 'Validation error';
      const path0    = issue?.path?.[0];
      const isUnknownFramework = issue?.params?.unknownFramework === true;
      const isPeriodOrder      = issue?.params?.complianceCode === 'INVALID_PERIOD';
      const isPeriodField      = path0 === 'periodStart' || path0 === 'periodEnd';
      const code = isUnknownFramework ? 'UNKNOWN_FRAMEWORK'
        : isPeriodOrder   ? 'INVALID_PERIOD'
        : isPeriodField && msg === 'Required' ? 'MISSING_PERIOD'
        : isPeriodField   ? 'INVALID_DATES'
        : path0 === 'frameworkId' ? 'MISSING_FRAMEWORK'
        : 'VALIDATION_ERROR';
      const status = isUnknownFramework ? 404 : 400;
      return _err(res, code, msg, status);
    }
    const { frameworkId, periodStart, periodEnd, tenantId, sign } = grParsed.data;
    const start = new Date(periodStart);
    const end   = new Date(periodEnd);

    const generatedBy     = resolveOperatorActor(req);
    const generatedByRole = req.rbacUser?.role ?? null;

    try {
      // signingClientId is intentionally NOT read from req.body — it selects
      // which tenant's private signing key produces the report signature.
      // Accepting it from an HTTP caller (even one holding GENERATE_REPORT,
      // which COMPLIANCE-role callers hold alongside ADMIN) would let a
      // non-admin caller compel an arbitrary tenant's key to sign content,
      // a tenant-isolation bypass with no legitimate compliance use case.
      // generateReport() falls back to the server's own configured
      // QODIQA_CLIENT_ID when no signingClientId is passed — the same
      // env-only, non-caller-suppliable default every other signing domain
      // in this codebase uses (certification, transparency).
      const report = await generateReport({
        frameworkId,
        periodStart:    start,
        periodEnd:      end,
        generatedBy,
        generatedByRole,
        tenantId:       tenantId || null,
        sign:           sign === true || sign === 'true',
      });

      emit('INFO', 'COMPLIANCE_REPORT_API_GENERATED', {
        reportId:    report.id,
        reportRef:   report.reportRef,
        frameworkId,
        score:       report.overallScore,
        verdict:     report.overallVerdict,
        generatedBy,
        requestId:   res.locals?.requestId,
      });

      return success(res, report, 201);
    } catch (err) {
      const known = err.message?.includes('required') || err.message?.includes('unknown framework');
      if (known) {
        return _err(res, 'VALIDATION_ERROR', err.message, 400);
      }
      return internalError(res, req, err, { label: 'COMPLIANCE_REPORT_GENERATE_FAILED', code: 'GENERATION_FAILED' });
    }
  });

  // ── GET /compliance/reports ────────────────────────────────────────────────

  router.get('/reports', _canRead, async (req, res) => {
    const { frameworkId, tenantId, status } = req.query;

    if (frameworkId && !isValidFramework(frameworkId)) {
      return _err(res, 'UNKNOWN_FRAMEWORK', `Unknown framework: "${frameworkId}"`, 404);
    }

    // Canonical page/pageSize (API-4 remediation) accepted as aliases
    // alongside this endpoint's original limit/offset; either still works.
    const { page, pageSize, limit, offset } = parsePagination(req.query, { defaultPageSize: 20, maxPageSize: 100 });

    try {
      const { reports, total } = await listReports({ frameworkId, tenantId, status, limit, offset });
      _ok(res, { reports, total, limit, offset, ...withPaginationMeta({ page, pageSize, total }) });
    } catch (err) {
      return internalError(res, req, err, { label: 'COMPLIANCE_REPORTS_LIST_FAILED', code: 'LIST_FAILED' });
    }
  });

  // ── GET /compliance/report/:id ─────────────────────────────────────────────

  router.get('/report/:id', _canRead, async (req, res) => {
    const { id } = req.params;
    if (!UUID_RE.test(id)) {
      return _err(res, 'INVALID_REPORT_ID', 'Report ID must be a valid UUID', 400);
    }
    try {
      const report = await getReport(id);
      if (!report) return _err(res, 'REPORT_NOT_FOUND', `Report "${id}" not found`, 404);
      _ok(res, report);
    } catch (err) {
      return internalError(res, req, err, { label: 'COMPLIANCE_REPORT_GET_FAILED', code: 'GET_FAILED' });
    }
  });

  // ── GET /compliance/report/:id/assessments ────────────────────────────────

  router.get('/report/:id/assessments', _canRead, async (req, res) => {
    const { id } = req.params;
    if (!UUID_RE.test(id)) {
      return _err(res, 'INVALID_REPORT_ID', 'Report ID must be a valid UUID', 400);
    }
    try {
      const assessments = await getControlAssessments(id);
      _ok(res, { reportId: id, assessments, total: assessments.length });
    } catch (err) {
      return internalError(res, req, err, { label: 'COMPLIANCE_ASSESSMENTS_FAILED', code: 'ASSESSMENTS_FAILED' });
    }
  });

  // ── POST /compliance/report/verify ────────────────────────────────────────

  // was reachable by any authenticated operator with no permission check.
  router.post('/report/verify', _canRead, async (req, res) => {
    const { reportPayload, signatureEnvelope } = req.body ?? {};

    if (!reportPayload) {
      return _err(res, 'MISSING_PAYLOAD', 'reportPayload is required');
    }
    if (!signatureEnvelope) {
      return _err(res, 'MISSING_SIGNATURE', 'signatureEnvelope is required');
    }

    try {
      const result = await verifyReport(reportPayload, signatureEnvelope);

      emit('INFO', 'COMPLIANCE_REPORT_VERIFY_API', {
        verified:  result.verified,
        hashMatch: result.hashMatch,
        sigValid:  result.sigValid,
        keyId:     signatureEnvelope.keyId,
        requestId: res.locals?.requestId,
      });

      // If DB is enabled, mark the signature as verified
      if (result.verified && signatureEnvelope.reportId && pgPool.isEnabled()) {
        await pgPool.query(
          `UPDATE compliance_report_signatures
           SET verified = true, verified_at = NOW()
           WHERE report_id = $1 AND report_hash = $2`,
          [signatureEnvelope.reportId, signatureEnvelope.reportHash],
          'compliance_mark_verified',
        ).catch(() => {});
      }

      _ok(res, result, { verified: result.verified });
    } catch (err) {
      return internalError(res, req, err, { label: 'COMPLIANCE_REPORT_VERIFY_FAILED', code: 'VERIFY_FAILED' });
    }
  });

  // ── GET /compliance/report/:id/download ───────────────────────────────────

  router.get('/report/:id/download', _canRead, async (req, res) => {
    const { id }     = req.params;
    const { format = 'json' } = req.query;

    if (!UUID_RE.test(id)) {
      return _err(res, 'INVALID_REPORT_ID', 'Report ID must be a valid UUID', 400);
    }

    // audit 2026-10-20 (Z01a R2): ?format[]=x makes `format` an array — validate the type before .toLowerCase().
    const fmt = typeof format === 'string' ? format.toLowerCase() : '';
    if (!['json', 'pdf', 'html'].includes(fmt)) {
      return _err(res, 'INVALID_FORMAT', 'format must be json, pdf, or html');
    }

    try {
      const report = await getReport(id);
      if (!report) return _err(res, 'REPORT_NOT_FOUND', `Report "${id}" not found`, 404);

      // Fetch control assessments and attach for export
      const assessments = await getControlAssessments(id).catch(() => []);
      report.controlAssessments = assessments.length > 0
        ? assessments.map(a => ({
            controlId:     a.control_id,
            controlRef:    a.control_ref,
            title:         a.title,
            category:      a.category,
            status:        a.status,
            score:         Number(a.score),
            isCritical:    a.is_critical,
            evidenceCount: a.evidence_count,
            findings:      Array.isArray(a.findings) ? a.findings : (JSON.parse(a.findings ?? '[]')),
          }))
        : (report.controlAssessments ?? []);

      const filename = `compliance-${report.report_ref ?? id}-${new Date().toISOString().slice(0,10)}`;

      // INJ-8: filename embeds report.report_ref (DB-sourced) — sanitize
      // before header interpolation for defense-in-depth even though `id`
      // itself is already UUID-validated above.
      if (fmt === 'json') {
        const buf = exportJsonBuffer(report, { pretty: true });
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', safeAttachmentHeader(`${filename}.json`));
        res.setHeader('Content-Length', buf.length);
        return res.end(buf);
      }

      if (fmt === 'html') {
        const html = exportHtml(report);
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', safeAttachmentHeader(`${filename}.html`));
        return res.end(html);
      }

      if (fmt === 'pdf') {
        const pdfBuf = await exportPdf(report);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', safeAttachmentHeader(`${filename}.pdf`));
        res.setHeader('Content-Length', pdfBuf.length);
        return res.end(pdfBuf);
      }
    } catch (err) {
      return internalError(res, req, err, { label: 'COMPLIANCE_REPORT_DOWNLOAD_FAILED', code: 'DOWNLOAD_FAILED' });
    }
  });

  // ── GET /compliance/health ─────────────────────────────────────────────────

  router.get('/health', _canRead, async (_req, res) => {
    const dbOk = pgPool.isEnabled() ? (await pgPool.healthCheck().catch(() => ({ healthy: false }))).healthy : false;
    const allControls = getAllControls();
    _ok(res, {
      dbEnabled:     pgPool.isEnabled(),
      dbHealthy:     dbOk,
      frameworksSupported: FRAMEWORK_IDS,
      totalControls: allControls.length,
      controlsByFramework: Object.fromEntries(
        FRAMEWORK_IDS.map(fid => [fid, getControlsForFramework(fid).length]),
      ),
    });
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((_req, res) => _err(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = createComplianceRouter;
