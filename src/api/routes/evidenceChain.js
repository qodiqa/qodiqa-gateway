'use strict';

/**
 * QODIQA Evidence Chain Investigation API — Component #21
 *
 * Factory: createEvidenceChainRouter({ requirePermission })
 *
 * Mounted at /evidence-chain in server.js behind:
 *   _opsIpAllow + _opsAuth + _rbacResolve + READ_EVIDENCE_CHAIN permission
 *
 * Route summary:
 *
 *   Record access:
 *     GET  /records/:evidenceId               — fetch by evidence UUID
 *     GET  /records/by-artifact/:artifactId   — fetch by artifact ID
 *     GET  /records/search                    — paginated search with filters
 *
 *   Chain access:
 *     GET  /chain                             — ordered chain segment
 *     POST /chain/verify-range               — continuity validation over a range
 *
 *   Verification:
 *     POST /records/:evidenceId/verify        — run 7-step verification
 *     GET  /records/:evidenceId/verifications — verification history
 *
 *   Reports & export:
 *     GET  /records/:evidenceId/report        — structured evidence report
 *     GET  /export/csv                        — CSV export of a search result
 *
 *   Dashboard:
 *     GET  /dashboard                         — aggregate stats
 *
 * RBAC:
 *   All routes require READ_EVIDENCE_CHAIN.
 *   Verification runs require VERIFY_EVIDENCE_CHAIN.
 */

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const { Router }           = require('express');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { success, failure, internalError } = require('../response');
const chainStore           = require('../../core/evidence/chainStore');
const chain                = require('../../core/evidence/chain');
const { safeAttachmentHeader } = require('../../utils/contentDisposition');
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
function _internalError(res, req, err) {
  return internalError(res, req, err, { label: 'EVIDENCE_CHAIN_API_ERROR' });
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

function _actor(req) {
  return req.rbacUser?.username ?? 'system';
}

// ── UUID validation ───────────────────────────────────────────────────────────

const _UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function _isUUID(s) {
  return typeof s === 'string' && _UUID_RE.test(s);
}

// ── Router factory ────────────────────────────────────────────────────────────

/**
 * @param {{ requirePermission?: function(string): function }} options
 * @returns {import('express').Router}
 */
function createEvidenceChainRouter({ requirePermission } = {}) {
  const router = Router();

  const rateLimit   = createRateLimitMiddleware('evidence_chain', { envelope: 'legacyFailure' });
  router.use(rateLimit);

  const _canRead   = permissionGuard(requirePermission, 'READ_EVIDENCE_CHAIN', 'evidenceChain');
  const _canVerify = permissionGuard(requirePermission, 'VERIFY_EVIDENCE_CHAIN', 'evidenceChain');

  // ── GET /records/search ─────────────────────────────────────────────────────
  // Defined before /records/:evidenceId to prevent param collision.

  router.get('/records/search', _canRead, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await chainStore.searchEvidence({
        artifactId:    req.query.artifactId    || undefined,
        decision:      req.query.decision      || undefined,
        policyHash:    req.query.policyHash    || undefined,
        keyId:         req.query.keyId         || undefined,
        auditRecordId: req.query.auditRecordId || undefined,
        tenantId:      req.query.tenantId      || undefined,
        startTime:     req.query.startTime     || undefined,
        endTime:       req.query.endTime       || undefined,
        page,
        pageSize,
        sortOrder,
      });

      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /records/by-artifact/:artifactId ────────────────────────────────────

  router.get('/records/by-artifact/:artifactId', _canRead, async (req, res) => {
    const { artifactId } = req.params;
    try {
      const record = await chainStore.getByArtifactId(artifactId);
      if (!record) {
        return _notFound(res, req, `No evidence record found for artifact '${artifactId}'`);
      }
      return _ok(res, { record }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /records/:evidenceId ─────────────────────────────────────────────────

  router.get('/records/:evidenceId', _canRead, async (req, res) => {
    const { evidenceId } = req.params;

    if (!_isUUID(evidenceId)) {
      return _badRequest(res, req, `evidenceId must be a valid UUID, got: ${evidenceId}`);
    }

    try {
      const record = await chainStore.getByEvidenceId(evidenceId);
      if (!record) {
        return _notFound(res, req, `Evidence record not found: ${evidenceId}`);
      }
      return _ok(res, { record }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /chain ───────────────────────────────────────────────────────────────

  router.get('/chain', _canRead, async (req, res) => {
    const startId = req.query.startId != null ? Number(req.query.startId) : undefined;
    const endId   = req.query.endId   != null ? Number(req.query.endId)   : undefined;
    // Range read, not classic offset pagination (no stable total count) — see
    // API-4-REMEDIATION-REPORT.md "justified exceptions". Still centralizes
    // the limit clamp through the shared utility (accepts `limit`/`pageSize`).
    const limit   = parsePagination(req.query, { defaultPageSize: 100, maxPageSize: 10_000 }).pageSize;

    if (startId != null && !Number.isFinite(startId)) {
      return _badRequest(res, req, `startId must be a positive integer, got: ${req.query.startId}`);
    }
    if (endId != null && !Number.isFinite(endId)) {
      return _badRequest(res, req, `endId must be a positive integer, got: ${req.query.endId}`);
    }

    try {
      const records = await chainStore.getChain({ startId, endId, limit });
      return _ok(res, { records, count: records.length, startId: startId ?? null, endId: endId ?? null }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── POST /chain/verify-range ─────────────────────────────────────────────────

  router.post('/chain/verify-range', _canVerify, async (req, res) => {
    // H132-D: ids are taken as sent and validated strictly (previously
    // Number()-coerced, so true / "1" became 1 and malformed values reached
    // PostgreSQL).
    // (NF-14): the tenant guard below is effectively inert — operators are
    // platform-scoped by design (docs/security/RBAC_MODEL.md) and rbacUser never
    // carries a tenantId, so every verify-range is platform-wide. It is kept as a
    // defense for a future tenant-scoped operator identity, not relied on today.
    const startId    = req.body?.startId;
    const endId      = req.body?.endId;
    const limit      = req.body?.limit ?? 1_000;
    const check      = chainStore.validateRangeRequest({ startId, endId, limit });
    if (!check.ok) return _badRequest(res, req, check.reason);
    const tenantId   = req.rbacUser?.tenantId ?? undefined;
    const verifiedBy = _actor(req);

    try {
      const result = await chainStore.verifyChainRange({ startId, endId, limit, verifiedBy, tenantId });
      return _ok(res, {
        rangeVerification: result,
        startId:    startId    ?? null,
        endId:      endId      ?? null,
        verifiedBy,
        verifiedAt: new Date().toISOString(),
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── POST /records/:evidenceId/verify ─────────────────────────────────────────

  router.post('/records/:evidenceId/verify', _canVerify, async (req, res) => {
    const { evidenceId } = req.params;
    const verifiedBy     = _actor(req);

    if (!_isUUID(evidenceId)) {
      return _badRequest(res, req, `evidenceId must be a valid UUID, got: ${evidenceId}`);
    }

    try {
      const result = await chainStore.verifyEvidence(evidenceId, { verifiedBy });

      if (result.failureReason === `Evidence record not found: ${evidenceId}`) {
        return _notFound(res, req, result.failureReason);
      }

      return _ok(res, {
        evidenceId,
        verifiedBy,
        verifiedAt:  new Date().toISOString(),
        durationMs:  result.durationMs,
        result:      result.result,
        failedStep:  result.failedStep    ?? null,
        failureReason: result.failureReason ?? null,
        stepsPassed: result.stepsPassed,
        stepsFailed: result.stepsFailed,
        steps:       result.steps,
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /records/:evidenceId/verifications ───────────────────────────────────

  router.get('/records/:evidenceId/verifications', _canRead, async (req, res) => {
    const { evidenceId } = req.params;
    // Range read, not classic offset pagination (no stable total count) — see
    // API-4-REMEDIATION-REPORT.md "justified exceptions". Still centralizes
    // the limit clamp through the shared utility (accepts `limit`/`pageSize`).
    const limit = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 }).pageSize;

    if (!_isUUID(evidenceId)) {
      return _badRequest(res, req, `evidenceId must be a valid UUID, got: ${evidenceId}`);
    }

    try {
      const record        = await chainStore.getByEvidenceId(evidenceId);
      if (!record) {
        return _notFound(res, req, `Evidence record not found: ${evidenceId}`);
      }

      const verifications = await chainStore.getVerifications(evidenceId, { limit });
      return _ok(res, { evidenceId, verifications, count: verifications.length }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /records/:evidenceId/report ──────────────────────────────────────────

  router.get('/records/:evidenceId/report', _canRead, async (req, res) => {
    const { evidenceId } = req.params;

    if (!_isUUID(evidenceId)) {
      return _badRequest(res, req, `evidenceId must be a valid UUID, got: ${evidenceId}`);
    }

    try {
      const record = await chainStore.getByEvidenceId(evidenceId);
      if (!record) {
        return _notFound(res, req, `Evidence record not found: ${evidenceId}`);
      }

      const verifications  = await chainStore.getVerifications(evidenceId, { limit: 1 });
      const latestVerif    = verifications[0] ?? null;

      const verResult = latestVerif
        ? {
            result:        latestVerif.verification_result,
            failedStep:    latestVerif.failed_step,
            failureReason: latestVerif.failure_reason,
            stepsPassed:   latestVerif.steps_passed,
            stepsFailed:   latestVerif.steps_failed,
            verifiedAt:    latestVerif.verification_time,
          }
        : null;

      const report = chain.assembleEvidenceReport(record, verResult, {
        requestedBy: _actor(req),
      });

      if (req.query.format === 'json') {
        // INJ-8: evidenceId is a route param interpolated into this header.
        res.setHeader('Content-Disposition', safeAttachmentHeader(`evidence-${evidenceId}.json`));
        res.setHeader('Content-Type', 'application/json');
        return res.send(JSON.stringify(report, null, 2));
      }

      return _ok(res, { report }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /export/csv ──────────────────────────────────────────────────────────

  router.get('/export/csv', _canRead, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await chainStore.searchEvidence({
        artifactId:    req.query.artifactId    || undefined,
        decision:      req.query.decision      || undefined,
        policyHash:    req.query.policyHash    || undefined,
        keyId:         req.query.keyId         || undefined,
        tenantId:      req.query.tenantId      || undefined,
        startTime:     req.query.startTime     || undefined,
        endTime:       req.query.endTime       || undefined,
        page,
        pageSize,
        sortOrder,
      });

      const csv = chain.evidenceRecordsToCSV(result.records);

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="evidence-chain.csv"');
      return res.send(csv);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /dashboard ───────────────────────────────────────────────────────────

  router.get('/dashboard', _canRead, async (req, res) => {
    try {
      const stats = await chainStore.aggregateStats();

      return _ok(res, {
        dashboard: {
          generatedAt: new Date().toISOString(),
          pgEnabled:   stats !== null,
          stats:       stats ?? {
            totalRecords:         0,
            allowCount:           0,
            blockCount:           0,
            distinctKeys:         0,
            distinctPolicyHashes: 0,
            firstRecord:          null,
            lastRecord:           null,
            verifications:        { total: 0, valid: 0, invalid: 0, partial: 0, error: 0 },
          },
        },
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createEvidenceChainRouter };
