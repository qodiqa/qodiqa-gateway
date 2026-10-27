'use strict';

/**
 * QODIQA Certification Runtime API — Component #25
 *
 * Versioned external API for formal certification evaluation of QODIQA
 * implementations.  Reuses existing trust primitives — no verification
 * logic is duplicated in this layer.
 *
 * Mounted at /v1/certification in server.js.
 * Admin router must be mounted BEFORE public router so static /admin/*
 * routes take precedence over parameterized /:certificationId routes.
 *
 * createCertificationPublicRouter()
 *   — No authentication; rate-limited.
 * (POST /v1/certification/evaluate moved to the ADMIN router in it
 *    writes; see below. Header corrected 2026-10-14, launch plan R-17.)
 * — GET /v1/certification/:certificationId — retrieve full record
 *   — GET  /v1/certification/:id/summary        — regulator summary view
 *
 * createCertificationAdminRouter({ requirePermission })
 *   — Requires ops auth + RBAC (via server.js mount-level middleware).
 *   — POST /v1/certification/evaluate           — run certification evaluation (SUBMIT_BATCH_CERTIFICATION)
 *   — GET  /v1/certification/admin/history      — paginated history
 *   — GET  /v1/certification/admin/stats        — aggregate statistics
 *   — GET  /v1/certification/:id/report         — full report (JSON or PDF)
 *   — GET  /v1/certification/:id/evidence       — certification evidence package
 *   — GET  /v1/certification/:id/export         — export (JSON or PDF)
 */

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const { Router }          = require('express');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { emit }             = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const { safeAttachmentHeader } = require('../../utils/contentDisposition');
const evaluationEngine     = require('../../core/certification/evaluationEngine');
const certificationStore   = require('../../core/certification/certificationStore');
const certificateStore     = require('../../core/certification/certificateStore');
const PDFDocument          = require('pdfkit');
const {
  parsePagination, parseSortOrder, withPaginationMeta,
} = require('../../utils/pagination');
const {
  certificationIdParamSchema,
  certificationEvaluateBodySchema,
} = require('../../validation/schemas/certification.schema');

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_PAGE_SIZE     = 500;
const DEFAULT_PAGE_SIZE = 50;
const API_VERSION       = 'v1';
const MAX_ARTIFACTS     = 50;
const MAX_EVIDENCE_PKGS = 50;

// ── Response helpers ──────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (data, req, status) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js.
function _ok(res, data, req, status) {
  return success(res, { ...data, apiVersion: API_VERSION }, status || 200);
}

function _notFound(res, req, message) {
  return failure(res, 'NOT_FOUND', message, 404, { apiVersion: API_VERSION });
}

function _badRequest(res, req, message) {
  return failure(res, 'INVALID_PARAM', message, 400, { apiVersion: API_VERSION });
}

// API-2: delegates to the centralized src/api/response.js implementation.
function _internalError(res, req, err, label) {
  return internalError(res, req, err, { label: label || 'CERTIFICATION_API_ERROR', details: { apiVersion: API_VERSION } });
}

// Delegates to the canonical pagination utility (src/utils/pagination.js —
// API-4 remediation); kept as a thin local wrapper so call sites below don't
// need to change. Also accepts the legacy `limit`/`offset`/`sortDir`/`sort`
// aliases via that shared parser.
function _pagination(query) {
  const { page, pageSize } = parsePagination(query, { defaultPageSize: DEFAULT_PAGE_SIZE, maxPageSize: MAX_PAGE_SIZE });
  const sortOrder = parseSortOrder(query);
  return { page, pageSize, sortOrder };
}

const _UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function _isUUID(s) {
  return typeof s === 'string' && _UUID_RE.test(s);
}

function _clientIp(req) {
  return req.clientIp || req.ip || null;
}

function _actor(req) {
  return req.rbacUser?.username ?? 'external';
}

// ── Public router factory ─────────────────────────────────────────────────────

function createCertificationPublicRouter() {
  const router = Router();
  // T-1 / R-09: this limiter runs on THIS router's public routes only (passed first on each route below),
  // not router.use(): this router is mounted before the admin stack on the same prefix, and a prefix-wide limiter also
  // ran for the admin paths — under a burst an anonymous admin path answered 429 instead of reaching the admin plane's
  // pre-auth gate (404 when disabled, OD-3). Public routes keep exactly the same limit
  // (src/api/routes/__tests__/publicRouterLimiterScope.test.js).
  const _surfaceLimit = createRateLimitMiddleware('certification', { envelope: 'management' });

  // POST /evaluate moved to the admin router below — it writes
  // attestations and permanent transparency entries, so it now requires
  // authentication + RBAC, and requestedBy comes from the authenticated identity.

  // ── GET /:certificationId ─────────────────────────────────────────────────
  //
  // Retrieve a full certification record by its stable UUID.

  router.get('/:certificationId', _surfaceLimit, async (req, res) => {
    const { certificationId } = req.params;

    if (!certificationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `certificationId must be a valid UUID`);
    }

    try {
      const record = await certificationStore.getByCertificationId(certificationId);
      if (!record) {
        return _notFound(res, req, `Certification not found: ${certificationId}`);
      }
      // the requester address is internal audit data — withheld here;
      // the RBAC report/export/history views keep it.
      const { request_ip: _internalOnly, ...publicRecord } = record;
      return _ok(res, { certification: publicRecord }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /:certificationId/summary ─────────────────────────────────────────
  //
  // Condensed view for regulators and compliance teams.  Returns the
  // certification outcome, score, evidence reference, and transparency
  // references without the full score breakdown or control detail payloads.

  router.get('/:certificationId/summary', _surfaceLimit, async (req, res) => {
    const { certificationId } = req.params;

    if (!certificationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `certificationId must be a valid UUID`);
    }

    try {
      const record = await certificationStore.getByCertificationId(certificationId);
      if (!record) {
        return _notFound(res, req, `Certification not found: ${certificationId}`);
      }
      return _ok(res, { summary: _buildSummary(record) }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /:certificationId/certificate ─────────────────────────────────────
  //
  // Download the signed certificate artifact for a CERTIFIED certification.
  // Content-Type: application/json.  The bundle is identical to the stored
  // artifact — self-contained and independently verifiable offline.
  // Returns 404 when no certificate exists (not yet CERTIFIED, or PG disabled).

  router.get('/:certificationId/certificate', _surfaceLimit, async (req, res) => {
    const { certificationId } = req.params;

    if (!certificationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `certificationId must be a valid UUID`);
    }

    try {
      const row = await certificateStore.getByCertificationId(certificationId);
      if (!row) {
        return _notFound(res, req, `Certificate artifact not found for certification: ${certificationId}`);
      }

      emit('INFO', 'CERTIFICATE_ARTIFACT_DOWNLOADED', {
        certificationId,
        certificateId: row.certificate_id,
        requestIp:     _clientIp(req),
      });

      res.setHeader('Content-Type', 'application/json');
      return res.status(200).json(row.bundle);
    } catch (err) {
      return _internalError(res, req, err, 'CERTIFICATE_ARTIFACT_DOWNLOAD_ERROR');
    }
  });

  return router;
}

// ── Admin router factory ──────────────────────────────────────────────────────

function createCertificationAdminRouter({ requirePermission } = {}) {
  const router = Router();
  router.use(createRateLimitMiddleware('certification_admin', { envelope: 'management' }));

  const _canRead   = permissionGuard(requirePermission, 'READ_CERTIFICATIONS', 'certification');
  const _canExport = permissionGuard(requirePermission, 'EXPORT_CERTIFICATIONS', 'certification');
  // same role set that may already submit certification evaluations in batch.
  const _canEvaluate = permissionGuard(requirePermission, 'SUBMIT_BATCH_CERTIFICATION', 'certification');
  const _evaluateLimit = createRateLimitMiddleware('certification_evaluate', { envelope: 'management' });

  // ── POST /evaluate ────────────────────────
  //
  // Runs the full evaluation pipeline (attestation, evidence verification,
  // chain check, scoring, evidence assembly, transparency registration).
  // Body: { artifacts[] (required, max 50), evidencePackages[], chain, options }
  // options.requestedBy is ignored: the record names the authenticated operator.
  router.post('/evaluate', _canEvaluate, _evaluateLimit, async (req, res) => {
    const evParsed = certificationEvaluateBodySchema.safeParse(req.body ?? {});
    if (!evParsed.success) {
      return _badRequest(res, req, evParsed.error.issues[0]?.message ?? 'Invalid request body');
    }
    const { artifacts, evidencePackages, chain } = evParsed.data;
    const requestedBy = _actor(req);
    if (!req.rbacUser) {
      return _badRequest(res, req, 'No authenticated identity');
    }

    try {
      const result = await evaluationEngine.evaluate(
        { artifacts, evidencePackages, chain },
        { requestedBy, requestIp: _clientIp(req) },
      );

      return _ok(res, { certification: result }, req, 200);
    } catch (err) {
      return _internalError(res, req, err, 'CERTIFICATION_EVALUATE_ERROR');
    }
  });


  // ── GET /admin/history ────────────────────────────────────────────────────

  router.get('/admin/history', _canRead, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);
      const result = await certificationStore.listCertifications({
        certificationLevel:    req.query.certificationLevel    || undefined,
        certificationDecision: req.query.certificationDecision || undefined,
        requestedBy:           req.query.requestedBy           || undefined,
        minScore:              req.query.minScore != null ? Number(req.query.minScore) : undefined,
        maxScore:              req.query.maxScore != null ? Number(req.query.maxScore) : undefined,
        startTime:             req.query.startTime             || undefined,
        endTime:               req.query.endTime               || undefined,
        page,
        pageSize,
        sortOrder,
      });
      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err, 'CERTIFICATION_API_ERROR');
    }
  });

  // ── GET /admin/stats ──────────────────────────────────────────────────────

  router.get('/admin/stats', _canRead, async (req, res) => {
    try {
      const stats = await certificationStore.aggregateStats();
      return _ok(res, {
        stats: stats ?? {
          total:             0,
          premiumCount:      0,
          plusCount:         0,
          certifiedCount:    0,
          notCertifiedCount: 0,
        },
        pgEnabled:   stats !== null,
        generatedAt: new Date().toISOString(),
      }, req);
    } catch (err) {
      return _internalError(res, req, err, 'CERTIFICATION_API_ERROR');
    }
  });

  // ── GET /:certificationId/report ──────────────────────────────────────────
  //
  // Full certification report in JSON (default) or PDF (?format=pdf).
  // Contains metadata, score breakdown, control results, and references.

  router.get('/:certificationId/report', _canRead, async (req, res) => {
    const { certificationId } = req.params;

    if (!certificationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `certificationId must be a valid UUID`);
    }

    try {
      const record = await certificationStore.getByCertificationId(certificationId);
      if (!record) {
        return _notFound(res, req, `Certification not found: ${certificationId}`);
      }

      emit('INFO', 'CERTIFICATION_EXPORT_REQUESTED', {
        certificationId,
        format:      req.query.format || 'json',
        requestedBy: _actor(req),
      });

      if (req.query.format === 'pdf') {
        return _streamCertificationPdf(record, res);
      }

      return _ok(res, { report: _buildReport(record) }, req);
    } catch (err) {
      return _internalError(res, req, err, 'CERTIFICATION_API_ERROR');
    }
  });

  // ── GET /:certificationId/evidence ────────────────────────────────────────
  //
  // Re-assemble and return the QODIQA::CERTIFICATION_EVIDENCE::V1 package
  // from stored record fields.  The packageHash is deterministically
  // reproduced and independently verifiable offline.

  router.get('/:certificationId/evidence', _canExport, async (req, res) => {
    const { certificationId } = req.params;

    if (!certificationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `certificationId must be a valid UUID`);
    }

    try {
      const record = await certificationStore.getByCertificationId(certificationId);
      if (!record) {
        return _notFound(res, req, `Certification not found: ${certificationId}`);
      }

      const pkg = evaluationEngine.assembleCertificationEvidence({
        certificationId:        record.certification_id,
        certificationLevel:     record.certification_level,
        certificationDecision:  record.certification_decision,
        totalScore:             record.score,
        scoreBreakdown:         record.score_breakdown     ?? {},
        criticalControlFailures: record.critical_control_failures ?? [],
        passedControls:         record.passed_controls     ?? [],
        failedControls:         record.failed_controls     ?? [],
        attestationReferences:  record.attestation_references ?? [],
        evidenceReferences:     record.evidence_references    ?? [],
        verificationReferences: record.verification_references ?? {},
        requestedBy:            record.requested_by,
        durationMs:             record.duration_ms,
      });

      return _ok(res, { certificationEvidence: pkg }, req);
    } catch (err) {
      return _internalError(res, req, err, 'CERTIFICATION_API_ERROR');
    }
  });

  // ── GET /:certificationId/export ──────────────────────────────────────────
  //
  // Export the full certification record for audit and regulatory review.
  // Supports JSON (default) or PDF (?format=pdf).

  router.get('/:certificationId/export', _canExport, async (req, res) => {
    const { certificationId } = req.params;

    if (!certificationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `certificationId must be a valid UUID`);
    }

    try {
      const record = await certificationStore.getByCertificationId(certificationId);
      if (!record) {
        return _notFound(res, req, `Certification not found: ${certificationId}`);
      }

      emit('INFO', 'CERTIFICATION_EXPORT_REQUESTED', {
        certificationId,
        format:      req.query.format || 'json',
        requestedBy: _actor(req),
        endpoint:    'export',
      });

      if (req.query.format === 'pdf') {
        return _streamCertificationPdf(record, res);
      }

      return _ok(res, { certification: record }, req);
    } catch (err) {
      return _internalError(res, req, err, 'CERTIFICATION_API_ERROR');
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405, { apiVersion: API_VERSION }));

  return router;
}

// ── Summary builder ───────────────────────────────────────────────────────────

function _validityStatus(record) {
  if (record.expires_at == null) return 'NOT_APPLICABLE';
  return new Date(record.expires_at) > new Date() ? 'ACTIVE' : 'EXPIRED';
}

function _buildSummary(record) {
  const passedCount = Array.isArray(record.passed_controls) ? record.passed_controls.length : 0;
  const failedCount = Array.isArray(record.failed_controls) ? record.failed_controls.length : 0;
  const critCount   = Array.isArray(record.critical_control_failures) ? record.critical_control_failures.length : 0;

  return {
    certificationId:       record.certification_id,
    certificationLevel:    record.certification_level,
    certificationDecision: record.certification_decision,
    score:                 record.score,
    scoreSummary: {
      total:               record.score,
      verificationControls: record.score_breakdown?.verificationControls?.score ?? null,
      operationalControls:  record.score_breakdown?.operationalControls?.score  ?? null,
      complianceControls:   record.score_breakdown?.complianceControls?.score   ?? null,
    },
    controlsSummary: {
      passedControls:          passedCount,
      failedControls:          failedCount,
      criticalControlFailures: critCount,
    },
    verificationSummary: {
      artifactVerifications:  record.verification_references?.artifactVerifications ?? 0,
      evidenceVerifications:  record.verification_references?.evidenceVerifications ?? 0,
      chainVerificationRun:   record.verification_references?.chainVerificationRun  ?? false,
    },
    evidenceReference: {
      evidencePackageHash: record.evidence_package_hash ?? null,
    },
    transparencyReference: {
      transparencyId: record.transparency_id ?? null,
    },
    lifecycle: {
      expiresAt:      record.expires_at      ?? null,
      renewal:        record.renewal         ?? null,
      validityStatus: _validityStatus(record),
    },
    requestedBy:   record.requested_by,
    generatedAt:   record.generated_at,
  };
}

// ── Report builder ────────────────────────────────────────────────────────────

function _buildReport(record) {
  return {
    certificationMetadata: {
      certificationId:       record.certification_id,
      certificationLevel:    record.certification_level,
      certificationDecision: record.certification_decision,
      version:               record.evaluation_result?.version ?? '1.0',
      generatedAt:           record.generated_at,
      expiresAt:             record.expires_at      ?? null,
      renewal:               record.renewal         ?? null,
      validityStatus:        _validityStatus(record),
    },
    evaluationResults: {
      overallScore:            record.score,
      scoreBreakdown:          record.score_breakdown      ?? {},
      passedControls:          record.passed_controls      ?? [],
      failedControls:          record.failed_controls      ?? [],
      criticalControlFailures: record.critical_control_failures ?? [],
    },
    verificationResults: {
      attestationReferences:  record.attestation_references  ?? [],
      evidenceReferences:     record.evidence_references     ?? [],
      verificationReferences: record.verification_references ?? {},
    },
    complianceResults: {
      certificationDecision:   record.certification_decision,
      certificationLevel:      record.certification_level,
      conformanceScore:        record.score_breakdown?.complianceControls?.score ?? null,
    },
    evidenceReferences: {
      evidencePackageHash: record.evidence_package_hash ?? null,
      transparencyId:      record.transparency_id       ?? null,
    },
    requestMetadata: {
      requestedBy: record.requested_by,
      requestIp:   record.request_ip ?? null,
      durationMs:  record.duration_ms ?? null,
    },
  };
}

// ── PDF renderer ──────────────────────────────────────────────────────────────

// H132-A: the whole document is rendered BEFORE any header is set or the stream
// is piped to the response (the layout). A render error — e.g. a stored
// critical_control_failures value that is not an array of objects — therefore
// reaches the route's catch with nothing sent and becomes the controlled generic
// 500; previously it was thrown after doc.pipe(res), and pdfkit's pending write
// into the already-ended error response (ERR_STREAM_WRITE_AFTER_END) terminated
// the process.
function _streamCertificationPdf(record, res) {
  const doc = new PDFDocument({ bufferPages: true, size: 'A4', margin: 50 });

  const level = record.certification_level;
  const levelColor = level === 'CERTIFIED_PREMIUM' ? '#1a237e'
    : level === 'CERTIFIED_PLUS'                   ? '#2e7d32'
    : level === 'CERTIFIED'                        ? '#e65100'
    : '#c62828';

  // ── Cover ──────────────────────────────────────────────────────────────────
  doc.fontSize(20).fillColor('#1a237e')
     .text('QODIQA Certification Report', { align: 'center' });
  doc.moveDown(0.4);
  doc.fontSize(10).fillColor('#555')
     .text(`Certification ID: ${record.certification_id}`, { align: 'center' });
  doc.moveDown(0.4);
  doc.fontSize(16).fillColor(levelColor)
     .text(`Level: ${level}`, { align: 'center' });
  doc.fontSize(12).fillColor(level === 'NOT_CERTIFIED' ? '#c62828' : '#2e7d32')
     .text(`Decision: ${record.certification_decision}`, { align: 'center' });
  doc.moveDown(0.4);
  doc.fontSize(24).fillColor(levelColor)
     .text(`Score: ${record.score}/100`, { align: 'center' });
  doc.moveDown(1);

  // ── Score breakdown ────────────────────────────────────────────────────────
  doc.fontSize(12).fillColor('#000').text('Score Breakdown', { underline: true });
  doc.fontSize(10).fillColor('#333');
  const sb = record.score_breakdown ?? {};
  const vc = sb.verificationControls ?? {};
  const oc = sb.operationalControls  ?? {};
  const cc = sb.complianceControls   ?? {};
  doc.text(`Verification Controls:  ${vc.score ?? 'N/A'} / ${vc.max ?? 40}`);
  doc.text(`Operational Controls:   ${oc.score ?? 'N/A'} / ${oc.max ?? 35}`);
  doc.text(`Compliance Controls:    ${cc.score ?? 'N/A'} / ${cc.max ?? 25}`);
  doc.text(`Total Score:            ${record.score} / 100`);
  doc.moveDown(0.8);

  // ── Critical failures ──────────────────────────────────────────────────────
  const critFailures = record.critical_control_failures ?? [];
  doc.fontSize(12).fillColor('#000').text('Critical Control Failures', { underline: true });
  doc.fontSize(10).fillColor('#333');
  if (critFailures.length === 0) {
    doc.text('None');
  } else {
    for (const f of critFailures) {
      doc.text(`• [${f.control}] ${f.reason}`);
    }
  }
  doc.moveDown(0.8);

  // ── Controls summary ───────────────────────────────────────────────────────
  const passed = Array.isArray(record.passed_controls) ? record.passed_controls : [];
  const failed = Array.isArray(record.failed_controls) ? record.failed_controls : [];
  doc.fontSize(12).fillColor('#000').text('Controls Summary', { underline: true });
  doc.fontSize(10).fillColor('#2e7d32').text(`Passed: ${passed.length}`);
  doc.fillColor('#c62828').text(`Failed / Partial: ${failed.length}`);
  doc.moveDown(0.8);

  // ── Verification references ────────────────────────────────────────────────
  doc.fontSize(12).fillColor('#000').text('Verification References', { underline: true });
  doc.fontSize(10).fillColor('#333');
  const vr = record.verification_references ?? {};
  doc.text(`Artifact verifications:   ${vr.artifactVerifications ?? 0}`);
  doc.text(`Evidence verifications:   ${vr.evidenceVerifications ?? 0}`);
  doc.text(`Chain verification run:   ${vr.chainVerificationRun ? 'Yes' : 'No'}`);
  if (vr.chainDecision) doc.text(`Chain decision:           ${vr.chainDecision}`);
  doc.moveDown(0.8);

  // ── Lifecycle ──────────────────────────────────────────────────────────────
  doc.fontSize(12).fillColor('#000').text('Certification Lifecycle', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Generated At:             ${record.generated_at}`);
  doc.text(`Expires At:               ${record.expires_at ?? 'N/A'}`);
  doc.text(`Renewal:                  ${record.renewal    ?? 'N/A'}`);
  doc.text(`Validity Status:          ${_validityStatus(record)}`);
  doc.moveDown(0.8);

  // ── Compliance and transparency ────────────────────────────────────────────
  doc.fontSize(12).fillColor('#000').text('Compliance & Transparency', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Transparency ID:          ${record.transparency_id ?? 'N/A'}`);
  doc.text(`Evidence Package Hash:    ${record.evidence_package_hash ?? 'N/A'}`);
  doc.text(`Requested By:             ${record.requested_by}`);
  doc.moveDown(0.8);

  // ── Footer ─────────────────────────────────────────────────────────────────
  doc.fontSize(8).fillColor('#999')
     .text('This report was generated by QODIQA Certification Runtime v1.0', { align: 'center' });
  doc.text('Verify authenticity: compare evidence package hash against transparency log', { align: 'center' });

  res.setHeader('Content-Type', 'application/pdf');
  // INJ-8: defense-in-depth — sanitize even DB-sourced values before header
  // interpolation.
  res.setHeader(
    'Content-Disposition',
    safeAttachmentHeader(`certification-${record.certification_id}.pdf`),
  );
  doc.pipe(res);
  doc.flushPages();
  doc.end();
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  createCertificationPublicRouter,
  createCertificationAdminRouter,
};
