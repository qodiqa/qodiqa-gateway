'use strict';

/**
 * QODIQA Policy Provenance API — Component #20
 *
 * Factory: createPolicyProvenanceRouter({ requirePermission })
 *
 * Mounted at /provenance in server.js behind:
 *   _opsIpAllow + _opsAuth + _rbacResolve + READ_POLICY_PROVENANCE permission
 *
 * Route summary:
 *
 *   Historical reconstruction & version access:
 *     GET  /policies/:policyId/history
 *     GET  /policies/:policyId/version/:version
 *     GET  /policies/:policyId/reconstruct/:timestamp
 *     GET  /policies/:policyId/timeline
 *     GET  /policies/:policyId/diff/:versionA/:versionB
 *     GET  /policies/:policyId/lineage
 *
 *   Integrity:
 *     POST /policies/:policyId/integrity
 *
 *   Cross-policy investigation:
 *     GET  /policies/search/history
 *
 *   Reports & export:
 *     GET  /policies/:policyId/report
 *
 *   Dashboard views:
 *     GET  /dashboard/timeline
 *     GET  /dashboard/stats
 *     GET  /dashboard/investigator
 *
 * RBAC:
 *   All routes require READ_POLICY_PROVENANCE.
 *   Routes that expose full policy_content snapshots require INVESTIGATE_POLICIES.
 *   Integrity runs (POST) require INVESTIGATE_POLICIES.
 */

const { Router }       = require('express');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { emit }         = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const provenanceStore  = require('../../core/policy/provenanceStore');
const provenance       = require('../../core/policy/provenance');
const { getPolicy, listPolicies } = require('../../core/policy/store');
const { safeAttachmentHeader } = require('../../utils/contentDisposition');
const {
  parsePagination, parseSortOrder, withPaginationMeta, paginateArray, isPaginationRequested,
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
  return internalError(res, req, err, { label: 'PROVENANCE_API_ERROR' });
}

/**
 * Parse pagination query params with safe defaults.
 */
// Delegates to the canonical pagination utility (src/utils/pagination.js —
// API-4 remediation); kept as a thin local wrapper so call sites below don't
// need to change. Also accepts the legacy `limit`/`offset`/`sortDir`/`sort`
// aliases via that shared parser.
function _pagination(query) {
  const { page, pageSize } = parsePagination(query, { defaultPageSize: DEFAULT_PAGE_SIZE, maxPageSize: MAX_PAGE_SIZE });
  const sortOrder = parseSortOrder(query);
  return { page, pageSize, sortOrder };
}

// ── Router factory ────────────────────────────────────────────────────────────

/**
 * @param {{ requirePermission: function(string): function }} options
 * @returns {import('express').Router}
 */
function createPolicyProvenanceRouter({ requirePermission }) {
  const router = Router();

  const rateLimit  = createRateLimitMiddleware('policy_provenance', { envelope: 'legacyFailure' });
  router.use(rateLimit);

  const _canRead    = requirePermission('READ_POLICY_PROVENANCE');
  const _canInvest  = requirePermission('INVESTIGATE_POLICIES');

  // ── GET /policies/search/history ────────────────────────────────────────────
  // Must be defined before /policies/:policyId to avoid param collision.

  router.get('/policies/search/history', _canRead, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await provenanceStore.searchHistory({
        policyId:    req.query.policyId    || undefined,
        actorId:     req.query.actorId     || undefined,
        actorUsername: req.query.actorUsername || undefined,
        eventType:   req.query.eventType   || undefined,
        sourceIp:    req.query.sourceIp    || undefined,
        changeReason: req.query.changeReason || undefined,
        startTime:   req.query.startTime   || undefined,
        endTime:     req.query.endTime     || undefined,
        page,
        pageSize,
        sortOrder,
      });

      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /policies/:policyId/history ─────────────────────────────────────────

  router.get('/policies/:policyId/history', _canRead, async (req, res) => {
    const { policyId } = req.params;
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await provenanceStore.getHistory(policyId, {
        page,
        pageSize,
        sortOrder,
        startTime: req.query.startTime || undefined,
        endTime:   req.query.endTime   || undefined,
        actorId:   req.query.actorId   || undefined,
        eventType: req.query.eventType || undefined,
      });

      if (result.total === 0 && !getPolicy(policyId)) {
        return _notFound(res, req, `Policy '${policyId}' not found`);
      }

      return _ok(res, {
        policyId,
        ...withPaginationMeta(result),
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /policies/:policyId/version/:version ─────────────────────────────────

  router.get('/policies/:policyId/version/:version', _canRead, async (req, res) => {
    const { policyId, version } = req.params;
    const vNum = parseInt(version, 10);

    if (!Number.isFinite(vNum) || vNum < 1) {
      return _badRequest(res, req, `version must be a positive integer, got: ${version}`);
    }

    try {
      const record = await provenanceStore.getVersion(policyId, vNum);
      if (!record) {
        return _notFound(res, req, `Version ${vNum} of policy '${policyId}' not found in provenance ledger`);
      }

      // policy_content is included for investigators only
      const user = req.rbacUser || {};
      const isInvestigator = ['admin', 'auditor'].includes(user.role);

      const response = { ...record };
      if (!isInvestigator) {
        delete response.policy_content;
      }

      return _ok(res, { policyId, version: response }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /policies/:policyId/reconstruct/:timestamp ───────────────────────────

  router.get('/policies/:policyId/reconstruct/:timestamp', _canInvest, async (req, res) => {
    const { policyId, timestamp } = req.params;

    const ts = new Date(decodeURIComponent(timestamp));
    if (isNaN(ts.valueOf())) {
      return _badRequest(res, req, `timestamp must be a valid ISO 8601 date, got: ${timestamp}`);
    }

    try {
      const record = await provenanceStore.getVersionAtTimestamp(policyId, ts);
      if (!record) {
        return _notFound(res, req,
          `No provenance version found for policy '${policyId}' at or before ${ts.toISOString()}`
        );
      }

      return _ok(res, {
        policyId,
        requestedAt:    ts.toISOString(),
        reconstructedAt: (record.occurred_at ?? record.occurredAt)?.toISOString?.() ?? null,
        versionNumber:  record.version_number,
        eventType:      record.event_type,
        actorUsername:  record.actor_username,
        policyHash:     record.policy_hash,
        policyContent:  record.policy_content,
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /policies/:policyId/timeline ─────────────────────────────────────────

  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them slices `events` and adds canonical
  // pagination metadata.
  router.get('/policies/:policyId/timeline', _canRead, async (req, res) => {
    const { policyId } = req.params;
    try {
      const events = await provenanceStore.getTimeline(policyId, {
        startTime: req.query.startTime || undefined,
        endTime:   req.query.endTime   || undefined,
      });

      if (events.length === 0 && !getPolicy(policyId)) {
        return _notFound(res, req, `Policy '${policyId}' not found`);
      }

      if (!isPaginationRequested(req.query)) {
        return _ok(res, { policyId, eventCount: events.length, events }, req);
      }
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: MAX_PAGE_SIZE });
      const { items, ...meta } = paginateArray(events, { page, pageSize });
      return _ok(res, { policyId, eventCount: events.length, events: items, ...meta }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /policies/:policyId/diff/:versionA/:versionB ─────────────────────────

  router.get('/policies/:policyId/diff/:versionA/:versionB', _canRead, async (req, res) => {
    const { policyId, versionA, versionB } = req.params;
    const vA = parseInt(versionA, 10);
    const vB = parseInt(versionB, 10);

    if (!Number.isFinite(vA) || vA < 1) {
      return _badRequest(res, req, `versionA must be a positive integer, got: ${versionA}`);
    }
    if (!Number.isFinite(vB) || vB < 1) {
      return _badRequest(res, req, `versionB must be a positive integer, got: ${versionB}`);
    }

    try {
      const result = await provenanceStore.compareVersions(policyId, vA, vB);
      if (!result) {
        return _notFound(res, req,
          `One or both versions (${vA}, ${vB}) of policy '${policyId}' not found in provenance ledger`
        );
      }

      return _ok(res, result, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /policies/:policyId/lineage ──────────────────────────────────────────

  router.get('/policies/:policyId/lineage', _canRead, async (req, res) => {
    const { policyId } = req.params;
    try {
      const lineage = await provenanceStore.getLineage(policyId);
      if (!lineage) {
        return _notFound(res, req, `No provenance lineage found for policy '${policyId}'`);
      }

      return _ok(res, lineage, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── POST /policies/:policyId/integrity ───────────────────────────────────────

  router.post('/policies/:policyId/integrity', _canInvest, async (req, res) => {
    const { policyId } = req.params;
    const checkedBy = req.rbacUser?.username || 'system';

    try {
      const result = await provenanceStore.verifyIntegrity(policyId, checkedBy);

      emit('INFO', 'PROVENANCE_INTEGRITY_CHECK_COMPLETED', {
        policyId,
        checkedBy,
        valid:          result.valid,
        checkedCount:   result.checkedCount,
        failureVersion: result.failureVersion,
        requestId:      req.requestId ?? null,
      });

      return _ok(res, {
        policyId,
        checkedBy,
        checkedAt:       new Date().toISOString(),
        versionsChecked: result.checkedCount,
        chainValid:      result.valid,
        failureVersion:  result.failureVersion,
        failureDetail:   result.failureDetail,
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /policies/:policyId/report ───────────────────────────────────────────

  router.get('/policies/:policyId/report', _canInvest, async (req, res) => {
    const { policyId }    = req.params;
    const format          = (req.query.format || 'json').toLowerCase();
    const requestedBy     = req.rbacUser?.username || 'system';

    if (!['json', 'csv', 'pdf'].includes(format)) {
      return _badRequest(res, req, `format must be one of: json, csv, pdf — got: ${format}`);
    }

    try {
      const reportData = await provenanceStore.generateReportData(policyId, {
        startTime:   req.query.startTime   || undefined,
        endTime:     req.query.endTime     || undefined,
        requestedBy,
      });

      if (!reportData) {
        return _notFound(res, req, `No provenance data found for policy '${policyId}'`);
      }

      if (format === 'csv') {
        const csv = provenance.versionsToCSV(reportData.versions);
        res.set('Content-Type', 'text/csv');
        // INJ-8: policyId is an unvalidated route param interpolated directly
        // into this header — sanitize before use to prevent header injection.
        res.set('Content-Disposition', safeAttachmentHeader(`provenance-${policyId}.csv`));
        return res.status(200).send(csv);
      }

      if (format === 'pdf') {
        // PDF-ready structured output (caller renders to PDF)
        return _ok(res, {
          format:   'PDF_READY',
          report:   reportData,
          metadata: {
            title:       `Policy Provenance Report: ${policyId}`,
            generatedAt: reportData.generatedAt,
            requestedBy: reportData.requestedBy,
            policyId,
          },
        }, req);
      }

      // Default: JSON
      return _ok(res, { report: reportData }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /dashboard/stats ──────────────────────────────────────────────────────

  router.get('/dashboard/stats', _canRead, async (req, res) => {
    try {
      const stats = await provenanceStore.aggregateStats();
      return _ok(res, { stats }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /dashboard/timeline ───────────────────────────────────────────────────
  // Cross-policy recent activity timeline for the governance dashboard.

  router.get('/dashboard/timeline', _canRead, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await provenanceStore.searchHistory({
        startTime: req.query.startTime || undefined,
        endTime:   req.query.endTime   || undefined,
        eventType: req.query.eventType || undefined,
        actorId:   req.query.actorId   || undefined,
        page,
        pageSize,
        sortOrder,
      });

      // Strip policy_content for non-investigators
      const user = req.rbacUser || {};
      const isInvestigator = ['admin', 'auditor'].includes(user.role);
      const versions = isInvestigator
        ? result.versions
        : result.versions.map(v => { const r = { ...v }; delete r.policy_content; return r; });

      return _ok(res, {
        ...withPaginationMeta(result),
        versions,
        viewType: 'POLICY_TIMELINE',
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /dashboard/investigator ───────────────────────────────────────────────
  // Investigator view: actor activity, rollback events, integrity status per policy.

  router.get('/dashboard/investigator', _canInvest, async (req, res) => {
    try {
      const stats = await provenanceStore.aggregateStats();

      // Top 20 most-modified policies
      const recentChanges = await provenanceStore.searchHistory({
        eventType: req.query.eventType || undefined,
        actorId:   req.query.actorId   || undefined,
        startTime: req.query.startTime || undefined,
        endTime:   req.query.endTime   || undefined,
        page:      1,
        pageSize:  100,
        sortOrder: 'desc',
      });

      // Rollbacks only
      const rollbacks = await provenanceStore.searchHistory({
        eventType: 'POLICY_ROLLED_BACK',
        startTime: req.query.startTime || undefined,
        endTime:   req.query.endTime   || undefined,
        page:      1,
        pageSize:  50,
        sortOrder: 'desc',
      });

      emit('INFO', 'PROVENANCE_INVESTIGATOR_VIEW_ACCESSED', {
        actorId:   req.rbacUser?.id,
        requestId: req.requestId ?? null,
      });

      return _ok(res, {
        viewType: 'INVESTIGATOR',
        stats,
        recentChanges: recentChanges.versions,
        rollbacks:     rollbacks.versions,
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /dashboard/comparison ──────────────────────────────────────────────────
  // Version comparison view: compare any two versions of any policy.

  router.get('/dashboard/comparison', _canRead, async (req, res) => {
    const { policyId, versionA, versionB } = req.query;

    if (!policyId) {
      return _badRequest(res, req, 'policyId query parameter is required');
    }
    const vA = parseInt(versionA, 10);
    const vB = parseInt(versionB, 10);
    if (!Number.isFinite(vA) || vA < 1) {
      return _badRequest(res, req, 'versionA must be a positive integer');
    }
    if (!Number.isFinite(vB) || vB < 1) {
      return _badRequest(res, req, 'versionB must be a positive integer');
    }

    try {
      const result = await provenanceStore.compareVersions(policyId, vA, vB);
      if (!result) {
        return _notFound(res, req, `Versions ${vA} or ${vB} of policy '${policyId}' not found`);
      }

      return _ok(res, {
        viewType: 'VERSION_COMPARISON',
        ...result,
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = createPolicyProvenanceRouter;
