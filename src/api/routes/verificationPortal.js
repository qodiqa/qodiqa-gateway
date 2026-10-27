'use strict';

/**
 * QODIQA Public Verification Portal API — Component #23
 *
 * Two router factories for different trust levels:
 *
 * createVerificationPortalPublicRouter()
 *   — No authentication required; rate-limited only.
 *   — Mounted at /portal in server.js (before ops auth middleware).
 *   — POST /portal/verify                 — submit artifact for verification
 *   — GET  /portal/result/:id             — fetch a prior verification result by UUID
 *
 *   — GET  /portal/report/:id[?format=pdf] — download verification report (JSON or PDF)
 *
 * createVerificationPortalAdminRouter({ requirePermission })
 *   — Requires ops auth + RBAC (via mount-level middleware in server.js).
 *   — Mounted at /portal in server.js (after ops auth middleware).
 *   — GET  /portal/admin/history   — paginated verification history (READ_VERIFICATION_PORTAL)
 *   — GET  /portal/admin/stats     — aggregate statistics (READ_VERIFICATION_PORTAL)
 *   — GET  /portal/evidence/:id    — download QODIQA::PORTAL_EVIDENCE::V1 package
 *
 *
 *the submitter address is internal
 * audit data. It is persisted and served to RBAC operators only; no public
 * response carries it. The evidence package embeds it in its V1 hashed content
 * (contract unchanged), so the package itself is served only to operators.
 */

const { Router }         = require('express');
const { randomUUID }     = require('crypto');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const { emit }           = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const { safeAttachmentHeader } = require('../../utils/contentDisposition');
const portal             = require('../../core/verification/portal');
const portalStore        = require('../../core/verification/portalStore');
const chainStore         = require('../../core/evidence/chainStore');
const registrar          = require('../../core/transparency/registrar');
const pgPool             = require('../../infra/postgres/pool');
const metrics            = require('../../observability/metrics');
const PDFDocument        = require('pdfkit');
const {
  parsePagination, parseSortOrder, withPaginationMeta,
} = require('../../utils/pagination');

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_PAGE_SIZE     = 500;
const DEFAULT_PAGE_SIZE = 50;

// ── Response helpers ──────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (data, req, status) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js.
function _ok(res, data, req, status) {
  return success(res, data, status || 200);
}

function _notFound(res, req, message) {
  return failure(res, 'NOT_FOUND', message, 404);
}

function _badRequest(res, req, message) {
  return failure(res, 'INVALID_PARAM', message, 400);
}

// API-2: delegates to the centralized src/api/response.js implementation.
function _internalError(res, req, err, label) {
  return internalError(res, req, err, { label: label || 'PORTAL_API_ERROR' });
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
  return req.rbacUser?.username ?? 'public';
}

// ── Public router factory ─────────────────────────────────────────────────────

/**
 * Create the public-facing verification portal router.
 * All routes are accessible without authentication.
 *
 * @returns {import('express').Router}
 */
function createVerificationPortalPublicRouter({ optionalAuth } = {}) {
  const router = Router();
  // T-1 / R-09: this limiter runs on THIS router's public routes only (passed first on each route below),
  // not router.use(): this router is mounted before the admin stack on the same prefix, and a prefix-wide limiter also
  // ran for the admin paths — under a burst an anonymous admin path answered 429 instead of reaching the admin plane's
  // pre-auth gate (404 when disabled, OD-3). Public routes keep exactly the same limit
  // (src/api/routes/__tests__/publicRouterLimiterScope.test.js).
  const _surfaceLimit = createRateLimitMiddleware('portal', { envelope: 'management' });
  // (D7 → B): POST /verify persists (verification row + transparency leaf)
  // only for an authenticated caller with MANAGE_VERIFICATION_PORTAL; an
  // anonymous caller gets the full report, nothing persisted, no id.
  const _optional = optionalAuth || ((_q, _s, n) => n());
  const _verifyLimit = createRateLimitMiddleware('public_verify', { envelope: 'management' });

  // ── POST /verify ───────────────────────────────────────────────────────────
  //
  // Submit an artifact for verification.  Returns a structured report with
  // individual check results and an overall VERIFIED / VERIFIED_WITH_WARNINGS /
  // FAILED verdict.
  //
  // Body: the raw QODIQA artifact object
  // Response: { verificationId, overallResult, checks, warnings, metadata, ... }

  router.post('/verify', _surfaceLimit, _optional, _verifyLimit, async (req, res) => {
    const start    = Date.now();
    const persist  = !!req.rbacUser;
    const artifact = req.body;

    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
      return _badRequest(res, req, 'Request body must be a QODIQA artifact JSON object');
    }

    const verificationId = randomUUID();

    emit('INFO', 'PORTAL_VERIFICATION_STARTED', {
      verificationId,
      requestId: req.requestId ?? null,
    });

    try {
      // ── 1. Compute fingerprint for replay detection ─────────────────────────
      const fingerprint = portal.computeArtifactFingerprint(artifact);

      // ── 2. Replay and evidence lookups (parallel, best-effort) ─────────────
      const isPgEnabled = pgPool.isEnabled();

      let priorRecord    = null;
      let evidenceRecord = null;

      if (isPgEnabled) {
        const [priorRes, evidenceRes] = await Promise.allSettled([
          portalStore.getByFingerprint(fingerprint),
          // keyed on the signed payload.requestId (see portal.lookupEvidenceRecord).
          portal.lookupEvidenceRecord(artifact, chainStore),
        ]);

        if (priorRes.status === 'fulfilled') priorRecord    = priorRes.value;
        if (evidenceRes.status === 'fulfilled') evidenceRecord = evidenceRes.value;
      }

      // ── 3. Run check suite ─────────────────────────────────────────────────
      const checkResult = portal.runPortalChecks(artifact, {
        fingerprintSeen: !!priorRecord,
        evidenceRecord,
        pgEnabled:       isPgEnabled,
      });

      // ── 4. Assemble report ─────────────────────────────────────────────────
      const artMeta = {
        publicKeyId: typeof artifact?.publicKeyId === 'string' ? artifact.publicKeyId : null,
        timestampMs: typeof artifact?.timestamp   === 'number' ? artifact.timestamp   : null,
        expiryMs:    typeof artifact?.expiry      === 'number' ? artifact.expiry      : null,
        artifactId:  portal.evidenceArtifactId(artifact),
      };

      const report = portal.buildVerificationReport(checkResult.checks, artMeta);

      const durationMs = Date.now() - start;

      // ── 5. Emit audit event ────────────────────────────────────────────────
      emit('INFO', 'PORTAL_VERIFICATION_COMPLETE', {
        verificationId,
        overallResult:  report.overallResult,
        failedCheck:    report.failedCheck,
        durationMs,
        requestId:      req.requestId ?? null,
      });

      // ── 6. Metrics ─────────────────────────────────────────────────────────
      metrics.portalVerificationsTotal.inc({ result: report.overallResult });
      if (report.overallResult === 'FAILED') {
        metrics.portalVerificationFailuresTotal.inc({ failed_check: report.failedCheck || 'UNKNOWN' });
      }

      // ── 7. Register transparency log entry (await before persistence) ────────
      //
      // Must complete before recordVerification() so transparency_id is
      // available for the INSERT.  Errors are non-fatal: the verification
      // result is still persisted and returned.
      let transparencyId = null;
      if (persist) try {
        const tReg = await registrar.register({
          entryType:   'VERIFICATION',
          payload:     {
            verificationId,
            overallResult:  report.overallResult,
            failedCheck:    report.failedCheck,
            artifactId:     artMeta.artifactId,
            publicKeyId:    artMeta.publicKeyId,
            fingerprintSeen: !!priorRecord,
          },
          registeredBy: 'portal',
        });
        transparencyId = tReg.transparencyId ?? null;
      } catch (err) {
        emit('WARN', 'PORTAL_TRANSPARENCY_REGISTER_FAILED', {
          verificationId,
          error: err.message,
        });
      }

      // ── 8. Persist verification record (fire-and-forget) ───────────────────
      //
      // transparencyId is now set (or null on registration failure) before
      // the INSERT is issued, eliminating the previous race condition.
      if (persist) portalStore.recordVerification({
        verificationId,
        artifactFingerprint:  fingerprint,
        artifactPublicKeyId:  artMeta.publicKeyId,
        artifactTimestampMs:  artMeta.timestampMs,
        artifactExpiryMs:     artMeta.expiryMs,
        artifactId:           artMeta.artifactId,
        overallResult:        report.overallResult,
        checksPerformed:      report.checks,
        failedCheck:          report.failedCheck,
        failureReason:        report.failureReason,
        warnings:             report.warnings,
        transparencyId,
        submittedBy:          _actor(req),
        submissionIp:         _clientIp(req),
        durationMs,
      }).catch(err => {
        emit('WARN', 'PORTAL_PERSIST_FAILED', {
          verificationId,
          error: err.message,
        });
        metrics.portalPersistFailuresTotal.inc({});
      });

      return _ok(res, {
        verificationId:  persist ? verificationId : null,
        persisted:       persist,
        overallResult:   report.overallResult,
        failedCheck:     report.failedCheck,
        failureReason:   report.failureReason,
        warnings:        report.warnings,
        checks:          report.checks,
        metadata:        report.metadata,
        durationMs,
        verifiedAt:      new Date().toISOString(),
      }, req);
    } catch (err) {
      emit('ERROR', 'PORTAL_VERIFICATION_ERROR', {
        verificationId,
        requestId: req.requestId ?? null,
        error:     err.message,
      });
      metrics.portalVerificationFailuresTotal.inc({ failed_check: 'INTERNAL_ERROR' });
      return _internalError(res, req, err, 'PORTAL_VERIFICATION_ERROR');
    }
  });

  // ── GET /result/:verificationId ───────────────────────────────────────────

  router.get('/result/:verificationId', _surfaceLimit, async (req, res) => {
    const { verificationId } = req.params;

    if (!_isUUID(verificationId)) {
      return _badRequest(res, req, `verificationId must be a valid UUID, got: ${verificationId}`);
    }

    try {
      const record = await portalStore.getByVerificationId(verificationId);
      if (!record) {
        return _notFound(res, req, `Verification not found: ${verificationId}`);
      }
      // the submitter address is internal audit data — withheld here.
      const { submission_ip: _internalOnly, ...publicRecord } = record;
      return _ok(res, { verification: publicRecord }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /report/:verificationId ───────────────────────────────────────────
  //
  // Download a structured verification report.
  // ?format=pdf  — renders a PDF; default is JSON.

  router.get('/report/:verificationId', _surfaceLimit, async (req, res) => {
    const { verificationId } = req.params;

    if (!_isUUID(verificationId)) {
      return _badRequest(res, req, `verificationId must be a valid UUID, got: ${verificationId}`);
    }

    try {
      const record = await portalStore.getByVerificationId(verificationId);
      if (!record) {
        return _notFound(res, req, `Verification not found: ${verificationId}`);
      }

      if (req.query.format === 'pdf') {
        return _streamReportPdf(record, res);
      }

      return _ok(res, { report: _buildReportView(record) }, req);
    } catch (err) {
      return _internalError(res, req, err, 'PORTAL_REPORT_ERROR');
    }
  });

  return router;
}

// ── Report helpers ────────────────────────────────────────────────────────────

function _buildReportView(record) {
  return {
    verificationId:    record.verification_id,
    overallResult:     record.overall_result,
    failedCheck:       record.failed_check      ?? null,
    failureReason:     record.failure_reason    ?? null,
    warnings:          record.warnings          ?? [],
    checksPerformed:   record.checks_performed  ?? [],
    artifactPublicKeyId: record.artifact_public_key_id ?? null,
    artifactTimestampMs: record.artifact_timestamp_ms  ?? null,
    artifactExpiryMs:    record.artifact_expiry_ms     ?? null,
    artifactId:          record.artifact_id            ?? null,
    transparencyId:      record.transparency_id        ?? null,
    submittedBy:         record.submitted_by           ?? null,
    durationMs:          record.duration_ms            ?? null,
    verifiedAt:          record.verified_at            ?? null,
  };
}

// artifact_timestamp_ms / artifact_expiry_ms are BIGINT columns, which the
// pg driver returns as strings; `new Date('1790000000000')` is an Invalid Date.
// Convert epoch milliseconds explicitly (number, integer string or Date); any
// other value throws, which the caller turns into a controlled error.
function _isoFromEpochMs(v) {
  if (v == null) return 'N/A';
  const ms = v instanceof Date ? v.getTime()
    : typeof v === 'number' ? v
    : (typeof v === 'string' && /^-?\d+$/.test(v)) ? Number(v)
    : NaN;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) throw new RangeError('PDF render: invalid epoch-ms timestamp');
  return d.toISOString();
}

// the whole document is rendered BEFORE any header is set or the stream is
// piped to the response. A render error therefore reaches the route's catch with
// nothing sent, so it becomes a controlled error response — previously it was
// thrown after doc.pipe(res), and pdfkit's pending write into the already-ended
// error response (ERR_STREAM_WRITE_AFTER_END) terminated the process.
function _streamReportPdf(record, res) {
  const doc = new PDFDocument({ bufferPages: true, size: 'A4', margin: 50 });

  const result = record.overall_result;
  const resultColor = result === 'VERIFIED' ? '#2e7d32'
    : result === 'VERIFIED_WITH_WARNINGS'   ? '#e65100'
    : '#c62828';

  doc.fontSize(20).fillColor('#1a237e').text('QODIQA Verification Portal Report', { align: 'center' });
  doc.moveDown(0.5);
  doc.fontSize(11).fillColor('#555').text(`Verification ID: ${record.verification_id}`, { align: 'center' });
  doc.moveDown(0.5);
  doc.fontSize(14).fillColor(resultColor).text(`Overall Result: ${result}`, { align: 'center' });
  doc.moveDown(1);

  doc.fontSize(12).fillColor('#000');
  doc.text('Artifact Details', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Public Key ID:  ${record.artifact_public_key_id ?? 'N/A'}`);
  doc.text(`Artifact ID:    ${record.artifact_id           ?? 'N/A'}`);
  doc.text(`Timestamp:      ${_isoFromEpochMs(record.artifact_timestamp_ms)}`);
  doc.text(`Expiry:         ${_isoFromEpochMs(record.artifact_expiry_ms)}`);
  doc.moveDown(0.8);

  doc.fontSize(12).fillColor('#000').text('Check Results', { underline: true });
  const checks = record.checks_performed ?? [];
  for (const c of checks) {
    const color = c.result === 'PASS' ? '#2e7d32' : c.result === 'FAIL' ? '#c62828' : c.result === 'WARN' ? '#e65100' : '#666';
    doc.fontSize(10).fillColor(color).text(`${c.result.padEnd(5)}  ${c.check}${c.reason ? ': ' + c.reason : ''}`);
  }
  doc.moveDown(0.8);

  if (record.failed_check) {
    doc.fontSize(12).fillColor('#000').text('Failure Details', { underline: true });
    doc.fontSize(10).fillColor('#c62828');
    doc.text(`Failed Check: ${record.failed_check}`);
    if (record.failure_reason) doc.text(`Reason:       ${record.failure_reason}`);
    doc.moveDown(0.8);
  }

  doc.fontSize(12).fillColor('#000').text('Submission Info', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Submitted By:   ${record.submitted_by  ?? 'public'}`);
  doc.text(`Duration:       ${record.duration_ms   ?? 'N/A'} ms`);
  doc.text(`Transparency ID:${record.transparency_id ?? 'N/A'}`);
  doc.text(`Verified At:    ${record.verified_at   ?? 'N/A'}`);

  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    doc.fontSize(8).fillColor('#999').text(
      `QODIQA Portal Report  •  Generated ${new Date().toISOString()}  •  Page ${i + 1} of ${range.count}`,
      50, doc.page.height - 40, { align: 'center', width: doc.page.width - 100 },
    );
  }

  res.setHeader('Content-Type', 'application/pdf');
  // INJ-8: defense-in-depth — sanitize even DB-sourced values before header
  // interpolation.
  res.setHeader(
    'Content-Disposition',
    safeAttachmentHeader(`portal-report-${record.verification_id}.pdf`),
  );
  doc.pipe(res);
  doc.flushPages();
  doc.end();
}

// ── Admin router factory ──────────────────────────────────────────────────────

/**
 * Create the admin verification portal router.
 * Mounted behind ops auth + RBAC middleware in server.js.
 *
 * @param {{ requirePermission?: function(string): function }} options
 * @returns {import('express').Router}
 */
function createVerificationPortalAdminRouter({ requirePermission } = {}) {
  const router = Router();
  router.use(createRateLimitMiddleware('portal_admin', { envelope: 'management' }));

  // fail CLOSED when mounted without requirePermission (was a silent `: _noop` pass-through).
  const _canRead = permissionGuard(requirePermission, 'READ_VERIFICATION_PORTAL', 'verificationPortalAdmin');

  // ── GET /admin/history ─────────────────────────────────────────────────────

  router.get('/admin/history', _canRead, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await portalStore.listVerifications({
        overallResult: req.query.overallResult || undefined,
        artifactId:    req.query.artifactId    || undefined,
        failedCheck:   req.query.failedCheck   || undefined,
        startTime:     req.query.startTime     || undefined,
        endTime:       req.query.endTime       || undefined,
        page,
        pageSize,
        sortOrder,
      });

      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err, 'PORTAL_API_ERROR');
    }
  });

  // ── GET /admin/stats ───────────────────────────────────────────────────────

  router.get('/admin/stats', _canRead, async (req, res) => {
    try {
      const stats = await portalStore.aggregateStats();
      return _ok(res, {
        stats: stats ?? {
          total:         0,
          verifiedCount: 0,
          warningsCount: 0,
          failedCount:   0,
        },
        pgEnabled:   stats !== null,
        generatedAt: new Date().toISOString(),
      }, req);
    } catch (err) {
      return _internalError(res, req, err, 'PORTAL_API_ERROR');
    }
  });

  // ── GET /evidence/:verificationId ─────────────────────────────────────────
  //
  // Download the QODIQA::PORTAL_EVIDENCE::V1 package for a verification run.
  // moved here from the public router — the package's hashed content
  // carries the submitter address (internal audit data), so it is served under
  // the same permission as /admin/history, which already returns that address.

  router.get('/evidence/:verificationId', _canRead, async (req, res) => {
    const { verificationId } = req.params;

    if (!_isUUID(verificationId)) {
      return _badRequest(res, req, `verificationId must be a valid UUID, got: ${verificationId}`);
    }

    try {
      const record = await portalStore.getByVerificationId(verificationId);
      if (!record) {
        return _notFound(res, req, `Verification not found: ${verificationId}`);
      }

      // H129-A: mapping (incl. the F30-twin verified_at Date->ISO conversion)
      // shared with attestor.verifyEvidencePackage via portal.js.
      const pkg = portal.assembleEvidencePackageFromPortalRecord(record);
      return _ok(res, { evidencePackage: pkg }, req);
    } catch (err) {
      return _internalError(res, req, err, 'PORTAL_EVIDENCE_ERROR');
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  createVerificationPortalPublicRouter,
  createVerificationPortalAdminRouter,
};
