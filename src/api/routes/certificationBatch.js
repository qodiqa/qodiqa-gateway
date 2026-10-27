'use strict';

// Batch Certification API — Component #27
//
// Mounts at /v1/certifications (ops-protected, RBAC-gated).
//
// POST /v1/certifications/batch              — submit batch, returns 202
// GET  /v1/certifications/batch/:batchId     — batch status
// GET  /v1/certifications/batch/:batchId/results — per-item results
// POST /v1/certifications/batch/:batchId/cancel  — cancel batch
//
// RBAC gates:
//   SUBMIT_BATCH_CERTIFICATION — create a batch
//   READ_CERTIFICATIONS        — read batch status and results
//   CANCEL_BATCH_CERTIFICATION — cancel a running batch

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const { Router }   = require('express');
const { success, failure, internalError } = require('../response');
const { createBatchService } = require('../../certification/batch/index');
const { validateCreateBatch }  = require('../../certification/batch/validator');
const { createRateLimitMiddleware } = require('../../core/rateLimit');

const API_VERSION = 'v1';

// ── Response helpers ──────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (res, req, data, status) call-site ergonomics — the
// actual envelope shape is built in exactly one place, response.js.
function _ok(res, req, data, status) {
  return success(res, { ...data, apiVersion: API_VERSION }, status || 200);
}

function _notFound(res, req, message) {
  return failure(res, 'NOT_FOUND', message, 404, { apiVersion: API_VERSION });
}

function _badRequest(res, req, message) {
  return failure(res, 'INVALID_REQUEST', message, 400, { apiVersion: API_VERSION });
}

function _forbidden(res, req, message) {
  return failure(res, 'FORBIDDEN', message, 403, { apiVersion: API_VERSION });
}

// API-2: delegates to the centralized src/api/response.js implementation.
function _internalError(res, req, err, label) {
  return internalError(res, req, err, {
    label: label || 'BATCH_CERTIFICATION_API_ERROR',
    details: { apiVersion: API_VERSION },
    extra: { tenantId: req.rbacUser?.tenantId ?? null },
  });
}

function _actor(req)    { return req.rbacUser?.username ?? 'unknown'; }
function _tenantId(req) { return req.rbacUser?.tenantId ?? req.tenantId ?? null; }
function _clientIp(req) { return req.clientIp || req.ip || null; }

// ── Tenant isolation check ────────────────────────────────────────────────────

function _tenantOwns(req, batch) {
  const tenantId = _tenantId(req);
  if (!tenantId) return true;  // no tenant context → ops-level access
  return batch.tenantId === tenantId;
}

// ── Batch ID format guard ─────────────────────────────────────────────────────

const _BATCH_ID_RE = /^batch_[0-9a-f]{32}$/;
function _validBatchId(s) { return typeof s === 'string' && _BATCH_ID_RE.test(s); }

// ── Router factory ────────────────────────────────────────────────────────────

function createCertificationBatchRouter({ requirePermission, batchService } = {}) {
  const router  = Router();
  const service = batchService || createBatchService();

  router.use(createRateLimitMiddleware('certification_batch', { envelope: 'management' }));

  const _canSubmit  = permissionGuard(requirePermission, 'SUBMIT_BATCH_CERTIFICATION', 'certificationBatch');
  const _canRead    = permissionGuard(requirePermission, 'READ_CERTIFICATIONS', 'certificationBatch');
  const _canCancel  = permissionGuard(requirePermission, 'CANCEL_BATCH_CERTIFICATION', 'certificationBatch');

  // ── POST /batch ─────────────────────────────────────────────────────────────
  //
  // Submit a batch certification request.  Returns 202 immediately; processing
  // is asynchronous.  Poll GET /batch/:batchId for status.

  router.post('/batch', _canSubmit, async (req, res) => {
    const validationError = validateCreateBatch(req.body);
    if (validationError) {
      return _badRequest(res, req, validationError);
    }

    const { frameworkId, items } = req.body;
    const tenantId    = _tenantId(req);
    const requestedBy = _actor(req);
    const requestIp   = _clientIp(req);

    try {
      const batch = await service.createBatch({
        frameworkId,
        items,
        tenantId,
        requestedBy,
        requestId:  req.requestId ?? null,
        requestIp,
      });

      return _ok(res, req, {
        batchId:    batch.batchId,
        status:     batch.status,
        itemCount:  batch.items.length,
        createdAt:  batch.createdAt,
        frameworkId: batch.frameworkId,
      }, 202);
    } catch (err) {
      return _internalError(res, req, err, 'BATCH_CREATE_ERROR');
    }
  });

  // ── GET /batch/:batchId ─────────────────────────────────────────────────────
  //
  // Returns current batch status and summary counts.

  router.get('/batch/:batchId', _canRead, async (req, res) => {
    const { batchId } = req.params;
    if (!_validBatchId(batchId)) {
      return _badRequest(res, req, 'Invalid batchId format');
    }

    try {
      const batch = await service.store.get(batchId);
      if (!batch) return _notFound(res, req, `Batch not found: ${batchId}`);
      if (!_tenantOwns(req, batch)) return _forbidden(res, req, 'Access denied');

      const items     = batch.items || [];
      const counts    = items.reduce((acc, i) => {
        acc[i.status] = (acc[i.status] || 0) + 1;
        return acc;
      }, {});

      return _ok(res, req, {
        batchId:     batch.batchId,
        frameworkId: batch.frameworkId,
        status:      batch.status,
        tenantId:    batch.tenantId,
        requestedBy: batch.requestedBy,
        createdAt:   batch.createdAt,
        startedAt:   batch.startedAt,
        completedAt: batch.completedAt,
        cancelledAt: batch.cancelledAt,
        itemCount:   items.length,
        itemCounts:  counts,
      });
    } catch (err) {
      return _internalError(res, req, err, 'BATCH_STATUS_ERROR');
    }
  });

  // ── GET /batch/:batchId/results ─────────────────────────────────────────────
  //
  // Returns per-item results.  Only available once batch is not pending.

  router.get('/batch/:batchId/results', _canRead, async (req, res) => {
    const { batchId } = req.params;
    if (!_validBatchId(batchId)) {
      return _badRequest(res, req, 'Invalid batchId format');
    }

    try {
      const batch = await service.store.get(batchId);
      if (!batch) return _notFound(res, req, `Batch not found: ${batchId}`);
      if (!_tenantOwns(req, batch)) return _forbidden(res, req, 'Access denied');

      const items = (batch.items || []).map(i => ({
        itemId:          i.itemId,
        subjectId:       i.subjectId,
        status:          i.status,
        certificationId: i.certificationId,
        result:          i.result,
        error:           i.error,
        startedAt:       i.startedAt,
        completedAt:     i.completedAt,
      }));

      return _ok(res, req, {
        batchId:     batch.batchId,
        batchStatus: batch.status,
        items,
        totalItems:     items.length,
        completedItems: items.filter(i => i.status === 'completed').length,
        failedItems:    items.filter(i => i.status === 'failed').length,
        pendingItems:   items.filter(i => i.status === 'pending').length,
        runningItems:   items.filter(i => i.status === 'running').length,
      });
    } catch (err) {
      return _internalError(res, req, err, 'BATCH_RESULTS_ERROR');
    }
  });

  // ── POST /batch/:batchId/cancel ─────────────────────────────────────────────
  //
  // Cancel a pending or running batch.  Terminal batches return 409.

  router.post('/batch/:batchId/cancel', _canCancel, async (req, res) => {
    const { batchId } = req.params;
    if (!_validBatchId(batchId)) {
      return _badRequest(res, req, 'Invalid batchId format');
    }

    try {
      const batch = await service.store.get(batchId);
      if (!batch) return _notFound(res, req, `Batch not found: ${batchId}`);
      if (!_tenantOwns(req, batch)) return _forbidden(res, req, 'Access denied');

      if (['completed', 'failed', 'cancelled'].includes(batch.status)) {
        return failure(res, 'ALREADY_TERMINAL', `Batch is already in terminal state: ${batch.status}`, 409, { apiVersion: API_VERSION });
      }

      const updated = await service.cancelBatch(batchId, { requestedBy: _actor(req) });

      return _ok(res, req, {
        batchId:     updated.batchId,
        status:      updated.status,
        cancelledAt: updated.cancelledAt,
      });
    } catch (err) {
      if (err.code === 'INVALID_TRANSITION') {
        return failure(res, 'ALREADY_TERMINAL', err.message, 409, { apiVersion: API_VERSION });
      }
      return _internalError(res, req, err, 'BATCH_CANCEL_ERROR');
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405, { apiVersion: API_VERSION }));

  return router;
}

module.exports = { createCertificationBatchRouter };
