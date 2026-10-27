'use strict';

/**
 * QODIQA Attestation API — Component #24
 *
 * Versioned external API that allows third-party systems, auditors, regulators,
 * compliance platforms, and independent verification services to programmatically
 * verify QODIQA artifacts and attestations without internal platform access.
 *
 * Mounted at /v1/attestation in server.js.
 *
 * createAttestationPublicRouter()
 *   — No authentication required; rate-limited.
 *   — POST /v1/attestation/verify                 — generate artifact attestation
 *   — POST /v1/attestation/evidence/verify        — verify evidence package
 * — POST /v1/attestation/chain/verify moved to the admin router below
 * — GET /v1/attestation/:attestationId — fetch attestation by ID
 *
 * createAttestationAdminRouter({ requirePermission })
 *   — Requires ops auth + RBAC (via server.js mount-level middleware).
 *   — GET  /v1/attestation/:id/export             — export (JSON or PDF)
 *   — GET  /v1/attestation/:id/evidence           — evidence package
 *   — GET  /v1/attestation/:id/summary            — regulator summary
 *   — GET  /v1/attestation/admin/history          — paginated history
 * — POST /v1/attestation/chain/verify — verify evidence chain
 *   — GET  /v1/attestation/admin/stats            — aggregate statistics
 */

const { Router }          = require('express');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { permissionGuard }  = require('./permissionGuard'); // fail-closed permission wiring
const { emit }             = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const attestor             = require('../../core/attestation/attestor');
const attestationStore     = require('../../core/attestation/attestationStore');
const portal               = require('../../core/verification/portal');
const PDFDocument          = require('pdfkit');
const {
  parsePagination, parseSortOrder, withPaginationMeta,
} = require('../../utils/pagination');
const { safeAttachmentHeader } = require('../../utils/contentDisposition');
const {
  attestationIdParamSchema,
  attestationVerifyBodySchema,
  evidenceVerifyBodySchema,
  chainVerifyBodySchema,
} = require('../../validation/schemas/attestation.schema');

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_PAGE_SIZE     = 500;
const DEFAULT_PAGE_SIZE = 50;
const API_VERSION       = 'v1';

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
  return internalError(res, req, err, { label: label || 'ATTESTATION_API_ERROR', details: { apiVersion: API_VERSION } });
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

/**
 * Create the public-facing attestation router.
 * All routes are accessible without authentication (rate-limited only).
 *
 * @returns {import('express').Router}
 */
function createAttestationPublicRouter({ optionalAuth } = {}) {
  const router = Router();
  // T-1 / R-09: this limiter runs on THIS router's public routes only (passed first on each route below),
  // not router.use(): this router is mounted before the admin stack on the same prefix, and a prefix-wide limiter also
  // ran for the admin paths — under a burst an anonymous admin path answered 429 instead of reaching the admin plane's
  // pre-auth gate (404 when disabled, OD-3). Public routes keep exactly the same limit
  // (src/api/routes/__tests__/publicRouterLimiterScope.test.js).
  const _surfaceLimit = createRateLimitMiddleware('attestation');
  // (D7 → B): the three verification routes persist (attestation row,
  // transparency leaf, attestation.completed webhook) ONLY for an
  // authenticated caller with MANAGE_ATTESTATIONS (optionalAuth, wired in
  // src/app.js). An anonymous caller gets the full result, nothing persisted.
  // Without optionalAuth every call is anonymous — the safe default.
  const _optional = optionalAuth || ((_q, _s, n) => n());
  const _verifyLimit = createRateLimitMiddleware('public_verify', { envelope: 'management' });
  const _persistOpts = (req) => ({ persist: !!req.rbacUser, requestedBy: _actor(req), requestIp: _clientIp(req) });

  // ── POST /verify ───────────────────────────────────────────────────────────
  //
  // Submit a QODIQA artifact for attestation.
  // Reuses the portal check suite, evidence chain lookup, transparency log
  // registration, and evidence package assembly — no verification logic is
  // duplicated in this component.
  //
  // Body: { artifact: <QODIQA artifact>, options?: { requestedBy? } }
  // Response: full attestation object

  router.post('/verify', _surfaceLimit, _optional, _verifyLimit, async (req, res) => {
    const vParsed = attestationVerifyBodySchema.safeParse(req.body ?? {});
    if (!vParsed.success) {
      return _badRequest(res, req, vParsed.error.issues[0]?.message ?? 'Request body must contain a QODIQA artifact object');
    }
    const body = req.body;
    // Accept either { artifact } envelope or a raw artifact object
    const artifact = body?.artifact !== undefined ? body.artifact : body;

    try {
      const result = await attestor.generateAttestation(artifact, _persistOpts(req));

      return _ok(res, { attestation: result }, req, 200);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });

  // ── POST /evidence/verify ─────────────────────────────────────────────────
  //
  // Verify a QODIQA evidence package (QODIQA::PORTAL_EVIDENCE::V1).
  // Independently recomputes the packageHash to detect tampering.
  //
  // Body: { evidencePackage: <package object> }
  // Response: evidence verification result

  router.post('/evidence/verify', _surfaceLimit, _optional, _verifyLimit, async (req, res) => {
    const evParsed = evidenceVerifyBodySchema.safeParse(req.body ?? {});
    if (!evParsed.success) {
      return _badRequest(res, req, evParsed.error.issues[0]?.message ?? 'Request body must contain an evidencePackage object');
    }
    const pkg = req.body?.evidencePackage ?? req.body;

    try {
      const result = await attestor.verifyEvidencePackage(pkg, _persistOpts(req));

      return _ok(res, { attestation: result }, req, 200);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });

  // (NF-2): POST /chain/verify moved to createAttestationAdminRouter()
  // (MANAGE_ATTESTATIONS). Anonymously it was a cross-tenant evidence
  // existence/integrity oracle (up to 50 ids or a 10,000-id range) and wrote an
  // evidence_chain_verifications row on every call; an unauthenticated request
  // now falls through to the admin mount and is refused there.

  // ── GET /:attestationId ───────────────────────────────────────────────────
  //
  // Fetch a full attestation record by its stable UUID.
  // Returns the complete attestation with all verification results,
  // cryptographic references, and audit references.

  router.get('/:attestationId', _surfaceLimit, async (req, res) => {
    const { attestationId } = req.params;

    if (!attestationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `attestationId must be a valid UUID`);
    }

    try {
      const record = await attestationStore.getByAttestationId(attestationId);
      if (!record) {
        return _notFound(res, req, `Attestation not found: ${attestationId}`);
      }
      // the requester/verifier address is internal audit data — withheld
      // here; the RBAC export/history views keep it.
      const { request_ip: _internalOnly, ...publicRecord } = record;
      // H129-A: pre-binding package attestations are flagged at retrieval (never rewritten).
      return _ok(res, { attestation: attestor.withIntegrityAdvisory(publicRecord) }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  return router;
}

// ── Admin router factory ──────────────────────────────────────────────────────

/**
 * Create the admin attestation router.
 * Mounted behind ops auth + RBAC middleware in server.js.
 * Provides auditor and regulator-facing export and reporting capabilities.
 *
 * @param {{ requirePermission?: function(string): function }} options
 * @returns {import('express').Router}
 */
function createAttestationAdminRouter({ requirePermission } = {}) {
  const router = Router();
  router.use(createRateLimitMiddleware('attestation_admin'));

  // fail CLOSED when mounted without requirePermission (was a silent `: _noop` pass-through).
  const _canRead    = permissionGuard(requirePermission, 'READ_ATTESTATIONS', 'attestationAdmin');
  const _canExport  = permissionGuard(requirePermission, 'EXPORT_ATTESTATIONS', 'attestationAdmin');
  const _canManage  = permissionGuard(requirePermission, 'MANAGE_ATTESTATIONS', 'attestationAdmin');

  // ── POST /chain/verify ────────────────────────────────────────────────────
  //
  // Verify evidence chain integrity.
  // Accepts either an array of evidenceIds or a { startId, endId } range.
  // Reuses chainStore.verifyEvidence and chainStore.verifyChainRange.
  //
  // Body: { evidenceIds?: string[], range?: { startId, endId, limit? } }
  // Response: chain verification result

  router.post('/chain/verify', _canManage, async (req, res) => {
    const cParsed = chainVerifyBodySchema.safeParse(req.body ?? {});
    if (!cParsed.success) {
      return _badRequest(res, req, cParsed.error.issues[0]?.message ?? 'Invalid request body');
    }
    const { evidenceIds, range } = cParsed.data;

    try {
      const result = await attestor.verifyChain({ evidenceIds, range }, { persist: true, requestedBy: _actor(req), requestIp: _clientIp(req) });

      return _ok(res, { attestation: result }, req, 200);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });


  // ── GET /admin/history ─────────────────────────────────────────────────────

  router.get('/admin/history', _canRead, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await attestationStore.listAttestations({
        attestationDecision: req.query.attestationDecision || undefined,
        attestationType:     req.query.attestationType     || undefined,
        artifactId:          req.query.artifactId          || undefined,
        failedCheck:         req.query.failedCheck         || undefined,
        startTime:           req.query.startTime           || undefined,
        endTime:             req.query.endTime             || undefined,
        page,
        pageSize,
        sortOrder,
      });

      // H129-A: flag pre-binding package attestations at retrieval.
      if (result && Array.isArray(result.attestations)) {
        result.attestations = result.attestations.map(attestor.withIntegrityAdvisory);
      }
      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });

  // ── GET /admin/stats ───────────────────────────────────────────────────────

  router.get('/admin/stats', _canRead, async (req, res) => {
    try {
      const stats = await attestationStore.aggregateStats();
      return _ok(res, {
        stats: stats ?? {
          total:            0,
          attestedCount:    0,
          warningsCount:    0,
          notAttestedCount: 0,
        },
        pgEnabled:   stats !== null,
        generatedAt: new Date().toISOString(),
      }, req);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });

  // ── GET /:attestationId/export ─────────────────────────────────────────────
  //
  // Export attestation for audit and regulatory review.
  // ?format=pdf  — renders a structured PDF; default is JSON.

  router.get('/:attestationId/export', _canExport, async (req, res) => {
    const { attestationId } = req.params;

    if (!attestationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `attestationId must be a valid UUID`);
    }

    try {
      const record = await attestationStore.getByAttestationId(attestationId);
      if (!record) {
        return _notFound(res, req, `Attestation not found: ${attestationId}`);
      }

      emit('INFO', 'ATTESTATION_EXPORT_REQUESTED', {
        attestationId,
        format:    req.query.format || 'json',
        requestedBy: _actor(req),
      });

      // H129-A: flag pre-binding package attestations at retrieval (never rewritten).
      const flagged = attestor.withIntegrityAdvisory(record);
      if (req.query.format === 'pdf') {
        return _streamAttestationPdf(flagged, res);
      }

      return _ok(res, { attestation: flagged }, req);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });

  // ── GET /:attestationId/evidence ───────────────────────────────────────────
  //
  // Return the evidence package associated with this attestation.
  // Assembles a fresh QODIQA::PORTAL_EVIDENCE::V1 package from the stored record.

  router.get('/:attestationId/evidence', _canExport, async (req, res) => {
    const { attestationId } = req.params;

    if (!attestationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `attestationId must be a valid UUID`);
    }

    try {
      const record = await attestationStore.getByAttestationId(attestationId);
      if (!record) {
        return _notFound(res, req, `Attestation not found: ${attestationId}`);
      }

      // H129-A: the record->package mapping (including's generated_at
      // Date->ISO conversion) lives in portal.js so this issuer and the
      // package verifier (attestor.verifyEvidencePackage) share it exactly.
      const pkg = portal.assembleEvidencePackageFromAttestationRecord(record);

      return _ok(res, { evidencePackage: pkg }, req);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });

  // ── GET /:attestationId/summary ───────────────────────────────────────────
  //
  // Condensed verification summary for regulator review.
  // Returns the attestation outcome, compliance status, and key references
  // without the full check detail payloads.

  router.get('/:attestationId/summary', _canRead, async (req, res) => {
    const { attestationId } = req.params;

    if (!attestationIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `attestationId must be a valid UUID`);
    }

    try {
      const record = await attestationStore.getByAttestationId(attestationId);
      if (!record) {
        return _notFound(res, req, `Attestation not found: ${attestationId}`);
      }

      const advisory = attestor.historicalIntegrityAdvisory(record);
      return _ok(res, {
        summary: advisory ? { ..._buildSummary(record), integrityAdvisory: advisory } : _buildSummary(record),
      }, req);
    } catch (err) {
      return _internalError(res, req, err, 'ATTESTATION_API_ERROR');
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405, { apiVersion: API_VERSION }));

  return router;
}

// ── Summary builder ───────────────────────────────────────────────────────────

function _buildSummary(record) {
  return {
    attestationId:       record.attestation_id,
    attestationType:     record.attestation_type,
    version:             record.version,
    attestationDecision: record.attestation_decision,
    verificationOutcome: {
      overallResult:   record.verification_result?.overallResult ?? null,
      failedCheck:     record.failed_check  ?? null,
      failureReason:   record.failure_reason ?? null,
      warningsCount:   Array.isArray(record.warnings) ? record.warnings.length : 0,
    },
    complianceOutcome: {
      conformanceStatus: record.compliance_result?.conformanceStatus ?? null,
      policyCompliance:  record.compliance_result?.policyCompliance?.status ?? null,
    },
    cryptographicReferences: {
      publicKeyId:         record.artifact_public_key_id ?? null,
      signatureVerification: record.cryptographic_result?.signatureVerification?.status ?? null,
      algorithm:           'Ed25519',
    },
    transparencyReferences: {
      transparencyId:    record.transparency_id ?? null,
    },
    evidenceReference: {
      evidencePackageHash: record.evidence_package_hash ?? null,
    },
    artifactMetadata: {
      artifactId:          record.artifact_id          ?? null,
      artifactFingerprint: record.artifact_fingerprint ?? null,
      timestampMs:         record.artifact_timestamp_ms ?? null,
      expiryMs:            record.artifact_expiry_ms    ?? null,
    },
    requestedBy:   record.requested_by,
    generatedAt:   record.generated_at,
  };
}

// ── PDF renderer ──────────────────────────────────────────────────────────────

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
function _streamAttestationPdf(record, res) {
  const doc = new PDFDocument({ bufferPages: true, size: 'A4', margin: 50 });

  const decision = record.attestation_decision;
  const decColor = decision === 'ATTESTED'               ? '#2e7d32'
    : decision === 'ATTESTED_WITH_WARNINGS'              ? '#e65100'
    : '#c62828';

  // Cover
  doc.fontSize(20).fillColor('#1a237e')
     .text('QODIQA Attestation Report', { align: 'center' });
  doc.moveDown(0.4);
  doc.fontSize(10).fillColor('#555')
     .text(`Attestation ID: ${record.attestation_id}`, { align: 'center' });
  doc.fontSize(10).fillColor('#555')
     .text(`Type: ${record.attestation_type}  |  Version: ${record.version}`, { align: 'center' });
  doc.moveDown(0.4);
  doc.fontSize(16).fillColor(decColor)
     .text(`Decision: ${decision}`, { align: 'center' });
  if (record.integrityAdvisory) { // H129-A retrieval-time flag
    doc.moveDown(0.4);
    doc.fontSize(10).fillColor('#b71c1c')
       .text(`Integrity advisory (${record.integrityAdvisory.code}): ${record.integrityAdvisory.message}`, { align: 'center' });
  }
  doc.moveDown(1);

  // Artifact metadata
  doc.fontSize(12).fillColor('#000').text('Artifact Metadata', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Artifact ID:    ${record.artifact_id            ?? 'N/A'}`);
  doc.text(`Public Key ID:  ${record.artifact_public_key_id ?? 'N/A'}`);
  doc.text(`Fingerprint:    ${record.artifact_fingerprint   ?? 'N/A'}`);
  const tsMs = record.artifact_timestamp_ms;
  const exMs = record.artifact_expiry_ms;
  doc.text(`Timestamp:      ${_isoFromEpochMs(tsMs)}`);
  doc.text(`Expiry:         ${_isoFromEpochMs(exMs)}`);
  doc.moveDown(0.8);

  // Verification result
  const vr = record.verification_result || {};
  doc.fontSize(12).fillColor('#000').text('Verification Result', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Overall Result: ${vr.overallResult  ?? record.attestation_decision}`);
  if (record.failed_check)   doc.text(`Failed Check:   ${record.failed_check}`);
  if (record.failure_reason) doc.text(`Reason:         ${record.failure_reason}`);
  const warningsArr = record.warnings ?? vr.warnings ?? [];
  doc.text(`Warnings:       ${warningsArr.length}`);
  doc.moveDown(0.8);

  // Checks
  const checks = record.checks_performed ?? vr.checks ?? [];
  if (checks.length > 0) {
    doc.fontSize(12).fillColor('#000').text('Check Results', { underline: true });
    for (const c of checks) {
      const col = c.result === 'PASS' ? '#2e7d32'
        : c.result === 'FAIL'         ? '#c62828'
        : c.result === 'WARN'         ? '#e65100'
        : '#666';
      doc.fontSize(10).fillColor(col)
         .text(`${(c.result || '').padEnd(5)}  ${c.check}${c.reason ? ': ' + c.reason : ''}`);
    }
    doc.moveDown(0.8);
  }

  // Cryptographic references
  const cr = record.cryptographic_result || {};
  doc.fontSize(12).fillColor('#000').text('Cryptographic References', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Algorithm:   Ed25519`);
  doc.text(`Signature:   ${cr.signatureVerification?.status ?? 'N/A'}`);
  doc.text(`Key Status:  ${cr.keyVerification?.status       ?? 'N/A'}`);
  doc.moveDown(0.8);

  // Transparency + evidence
  doc.fontSize(12).fillColor('#000').text('Anchoring References', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Transparency ID:     ${record.transparency_id       ?? 'N/A'}`);
  doc.text(`Evidence Pkg Hash:   ${record.evidence_package_hash ?? 'N/A'}`);
  doc.moveDown(0.8);

  // Submission
  doc.fontSize(12).fillColor('#000').text('Submission Info', { underline: true });
  doc.fontSize(10).fillColor('#333');
  doc.text(`Requested By:   ${record.requested_by  ?? 'external'}`);
  doc.text(`Duration:       ${record.duration_ms   ?? 'N/A'} ms`);
  doc.text(`Generated At:   ${record.generated_at  ?? 'N/A'}`);

  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    doc.fontSize(8).fillColor('#999').text(
      `QODIQA Attestation Report  •  ${record.attestation_id}  •  ${new Date().toISOString()}  •  Page ${i + 1} of ${range.count}`,
      50, doc.page.height - 40, { align: 'center', width: doc.page.width - 100 },
    );
  }

  res.setHeader('Content-Type', 'application/pdf');
  // INJ-8: defense-in-depth — sanitize even DB-sourced values before header
  // interpolation.
  res.setHeader(
    'Content-Disposition',
    safeAttachmentHeader(`attestation-${record.attestation_id}.pdf`),
  );
  doc.pipe(res);
  doc.flushPages();
  doc.end();
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  createAttestationPublicRouter,
  createAttestationAdminRouter,
};
