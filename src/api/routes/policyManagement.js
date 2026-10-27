'use strict';

/**
 * Policy Management UI Router
 *
 * Factory: createPolicyManagementRouter({ _reloadPolicies })
 *
 * All routes are mounted under /policy-ui in server.js and protected by
 * ops middleware (opsIpAllowlist + opsAuth + opsEnabled) applied there.
 *
 * Rate limit: 60 req/min per IP.
 *
 * (maker-checker): the five write routes below no longer mutate
 * production policy immediately. They now create a governed change
 * request (draft + auto-submit, or an auto-submitted rollback request via
 * RollbackGovernanceService) and return it — the request still requires
 * independent review/approval/publish through
 * /v1/policy/governance/* (src/api/routes/admin/policyGovernance.js)
 * before it takes effect. This closes "a single administrator can create
 * AND activate production policy" while keeping these URLs and their
 * MANAGE_POLICIES gate working for existing callers. See
 * docs/guides/policy-governance.md.
 *
 * Route summary:
 *   GET    /dashboard
 *   GET    /policies
 *   GET    /policies/validate          → 405 (POST only)
 *   POST   /policies/validate
 *   GET    /policies/:policyId
 * POST /policies — creates a governed CREATE change request
 * PUT /policies/:policyId — creates a governed UPDATE change request
 * POST /policies/:policyId/enable — creates a governed ENABLE change request
 * POST /policies/:policyId/disable — creates a governed DISABLE change request
 *   GET    /policies/:policyId/versions
 *   GET    /policies/:policyId/versions/:v
 *   GET    /policies/:policyId/diff
 * POST /policies/:policyId/rollback — creates a governed rollback request
 *   GET    /policies/:policyId/history
 */

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const { Router } = require('express');

const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { emit }              = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const {
  getDashboard,
  listPolicies,
  getPolicy,
  getVersions,
  getVersion,
  getHistory,
  validatePolicyCandidate,
} = require('../../core/policy/store');
const PolicyGovernanceService   = require('../../core/policy/governance/PolicyGovernanceService');
const RollbackGovernanceService = require('../../core/policy/governance/RollbackGovernanceService');
const metrics               = require('../../observability/metrics');
const {
  parsePagination, parseSortOrder, withPaginationMeta, paginateArray, isPaginationRequested,
} = require('../../utils/pagination');

// ── Constants ─────────────────────────────────────────────────────────────────

const VALID_STATUSES = new Set(['ACTIVE', 'DISABLED']);
const MAX_PAGE_SIZE  = 200;

// ── Helpers ───────────────────────────────────────────────────────────────────

function _actor(req) {
  const h = req.rbacUser?.username;
  return typeof h === 'string' && h.trim() ? h.trim().slice(0, 64) : 'operator';
}

/**
 * Standard success envelope.
 */
function _ok(res, data, status = 200, req) {
  return success(res, data, status);
}

/**
 * Map store error codes to HTTP status codes and return an error response.
 */
function _storeError(res, err, req) {
  const requestId = req.requestId ?? null;
  const message   = err && err.message ? err.message : 'An unexpected error occurred';

  const knownCode = err && ['POLICY_ALREADY_EXISTS', 'NOT_FOUND', 'VERSION_NOT_FOUND', 'VALIDATION_FAILED'].includes(err.code)
    ? err.code
    : null;

  if (!knownCode) {
    return internalError(res, req, err, { label: 'POLICY_MANAGEMENT_STORE_ERROR', code: 'INTERNAL_ERROR' });
  }

  const httpStatus = knownCode === 'POLICY_ALREADY_EXISTS' ? 409
    : knownCode === 'VALIDATION_FAILED' ? 422
    : 404;

  emit('WARN', 'POLICY_MANAGEMENT_STORE_ERROR', {
    code:      knownCode,
    message,
    requestId,
    path:      req.path,
    method:    req.method,
  });

  return failure(res, knownCode, message, httpStatus);
}

/**
 * Perform a flat top-level diff plus one-level-deep config diff between two
 * policy snapshots.  Returns an array of change objects.
 *
 * Fields compared at top level: id, name, description, type, priority, enabled.
 * The "config" object is compared key-by-key one level deep.
 */
function _diffSnapshots(a, b) {
  const changes = [];

  // Top-level scalar fields
  const TOP_FIELDS = ['id', 'name', 'description', 'type', 'priority', 'enabled'];

  for (const field of TOP_FIELDS) {
    const va = a[field];
    const vb = b[field];
    if (va === vb) continue;

    if (va === undefined) {
      changes.push({ path: field, op: 'ADDED',   from: undefined, to: vb });
    } else if (vb === undefined) {
      changes.push({ path: field, op: 'REMOVED', from: va, to: undefined });
    } else {
      changes.push({ path: field, op: 'MODIFIED', from: va, to: vb });
    }
  }

  // One-level-deep config diff
  const ca = (a && typeof a.config === 'object' && a.config !== null) ? a.config : {};
  const cb = (b && typeof b.config === 'object' && b.config !== null) ? b.config : {};
  const configKeys = new Set([...Object.keys(ca), ...Object.keys(cb)]);

  for (const key of configKeys) {
    const va = ca[key];
    const vb = cb[key];

    // Compare with JSON serialisation so objects/arrays are compared by value.
    if (JSON.stringify(va) === JSON.stringify(vb)) continue;

    if (!(key in ca)) {
      changes.push({ path: `config.${key}`, op: 'ADDED',    from: undefined, to: vb });
    } else if (!(key in cb)) {
      changes.push({ path: `config.${key}`, op: 'REMOVED',  from: va, to: undefined });
    } else {
      changes.push({ path: `config.${key}`, op: 'MODIFIED', from: va, to: vb });
    }
  }

  return changes;
}

/**
 * Extract full attribution context from the request.
 * Prefers req.rbacUser (resolved by RBAC middleware) over the raw header.
 * Falls back to synthetic values when RBAC is disabled.
 */
function _attribution(req) {
  const user = req.rbacUser || {};
  return {
    actorId:       user.id       || _actor(req),
    actorUsername: user.username || _actor(req),
    actorRole:     user.role     || 'operator',
    sourceIp:      req.clientIp  || req.ip || 'unknown',
  };
}

/**
 * Validate that changeReason is present and non-empty.
 * Returns a 400 response and true if invalid; returns false if valid.
 * (API-9 remediation: this is a missing-required-field/shape check, not a
 * business-rule violation, so it uses 400 — 422 is reserved for
 * VALIDATION_FAILED-class store errors below, which validate policy
 * semantics after the request has already parsed successfully.)
 * Caller checks the return value: `if (_requireReason(...)) return;`
 */
function _requireReason(res, req, changeReason) {
  if (typeof changeReason !== 'string' || !changeReason.trim()) {
    metrics.provenanceAttributionFailuresTotal.inc({});
    emit('WARN', 'PROVENANCE_REASON_REJECTED', {
      requestId: req.requestId ?? null,
      path:      req.path,
      method:    req.method,
    });
    failure(res, 'REASON_REQUIRED', 'changeReason is required and must not be empty for all policy modifications', 400);
    return true;
  }
  return false;
}

/**
 * Build an actor object shaped for the governance services
 * (PolicyGovernanceService/RollbackGovernanceService) from request
 * attribution.
 */
function _governanceActor(req) {
  const attr = _attribution(req);
  return { id: attr.actorId, username: attr.actorUsername, role: attr.actorRole, sourceIp: attr.sourceIp };
}

/**
 * Build a human-readable diff summary line.
 */
function _diffSummary(changes) {
  const counts = { ADDED: 0, MODIFIED: 0, REMOVED: 0 };
  for (const c of changes) counts[c.op] = (counts[c.op] ?? 0) + 1;

  const parts = [];
  if (counts.ADDED)    parts.push(`${counts.ADDED} field(s) added`);
  if (counts.MODIFIED) parts.push(`${counts.MODIFIED} field(s) modified`);
  if (counts.REMOVED)  parts.push(`${counts.REMOVED} field(s) removed`);

  return parts.length ? parts.join(', ') : 'no changes';
}

// ── Router factory ────────────────────────────────────────────────────────────

/**
 * @param {{ _reloadPolicies?: function(): void, requirePermission?: function(string): function }} options
 *   requirePermission — optional RBAC middleware factory; when provided, write
 *   routes require MANAGE_POLICIES and read routes require READ_POLICIES.
 *   When absent, no additional RBAC checks are applied (backwards-compatible).
 *   _reloadPolicies — accepted for call-site compatibility with server.js
 * but no longer used directly here:, the five write routes
 *   below create governed change requests instead of mutating policy
 *   immediately, so this router itself never needs to reload the live
 *   policy set. Reload happens in policyGovernance.js's publish route,
 *   the only place that still touches store.js's mutators.
 * @returns {import('express').Router}
 */
function createPolicyManagementRouter({ requirePermission } = {}) {
  const router = Router();

  // Rate limit: 60 requests per minute per IP
  const rateLimit = createRateLimitMiddleware('policy_management', { envelope: 'legacyFailure' });
  router.use(rateLimit);

  // RBAC guards — no-op when requirePermission is not injected
  const _canRead    = permissionGuard(requirePermission, 'READ_POLICIES', 'policyManagement');
  const _canManage  = permissionGuard(requirePermission, 'MANAGE_POLICIES', 'policyManagement');

  // ── GET /dashboard ──────────────────────────────────────────────────────────

  router.get('/dashboard', _canRead, async (req, res) => {
    try {
      const stats = getDashboard();
      return _ok(res, stats, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── GET /policies ───────────────────────────────────────────────────────────

  router.get('/policies', _canRead, async (req, res) => {
    const requestId = req.requestId ?? null;

    // Canonical page/pageSize via the shared utility (API-4 remediation) —
    // this also fixes a pre-existing doc/code mismatch where the OpenAPI
    // spec documented a `limit` query param that the handler never actually
    // read; `limit`/`offset` now work here exactly as they do fleet-wide.
    const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: MAX_PAGE_SIZE });

    const status  = req.query.status  || undefined;
    const search  = req.query.search  || undefined;
    const sortBy  = req.query.sortBy  || undefined;
    // `sortBy` selects the field (unique to this endpoint — no equivalent
    // elsewhere); `sortDir` is this endpoint's direction toggle, and now also
    // accepts the canonical `sortOrder` name as an alias.
    const sortDir = req.query.sortDir !== undefined || req.query.sortOrder !== undefined
      ? parseSortOrder(req.query)
      : undefined;

    if (status !== undefined && !VALID_STATUSES.has(status)) {
      return failure(res, 'INVALID_PARAM', `status must be one of: ${[...VALID_STATUSES].join(', ')}`, 400);
    }

    try {
      const result = listPolicies({ page, pageSize, status, search, sortBy, sortDir });
      return _ok(res, withPaginationMeta(result), 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── GET /policies/validate  → 405  (must be BEFORE /:policyId) ─────────────

  router.get('/policies/validate', _canRead, (req, res) => {
    res.set('Allow', 'POST');
    return failure(res, 'METHOD_NOT_ALLOWED', 'Use POST /policies/validate to validate a policy candidate', 405);
  });

  // ── POST /policies/validate  (must be BEFORE /:policyId) ───────────────────

  router.post('/policies/validate', _canRead, async (req, res) => {
    const requestId = req.requestId ?? null;
    const { id, type, priority, enabled, config, currentId } = req.body || {};

    const candidate = { id, type, priority, enabled, config };

    try {
      const result = validatePolicyCandidate(candidate, currentId ?? null);
      return _ok(res, {
        valid:    result.valid,
        errors:   result.errors,
        warnings: result.warnings,
        score:    result.score,
      }, 200, req);
    } catch (err) {
      // validatePolicyCandidate should return a result object rather than
      // throwing, but guard defensively.
      return _storeError(res, err, req);
    }
  });

  // ── GET /policies/:policyId ─────────────────────────────────────────────────

  router.get('/policies/:policyId', _canRead, async (req, res) => {
    const { policyId } = req.params;
    try {
      const policy = getPolicy(policyId);
      if (policy === null || policy === undefined) {
        return failure(res, 'NOT_FOUND', `Policy '${policyId}' not found`, 404);
      }
      return _ok(res, { policy }, 200, req);
    } catch (err) {
      if (err && err.code === 'NOT_FOUND') {
        return failure(res, 'NOT_FOUND', err.message, 404);
      }
      return _storeError(res, err, req);
    }
  });

  // ── POST /policies — creates a governed CREATE change request ────
  // No longer activates anything directly: draft() + submit() only. The
  // request still needs independent review/approval/publish via
  // /v1/policy/governance before it takes effect.

  router.post('/policies', _canManage, async (req, res) => {
    const { id, name, description, type, priority, config, changeReason } = req.body || {};
    const actor = _governanceActor(req);

    if (_requireReason(res, req, changeReason)) return;

    try {
      const draft = await PolicyGovernanceService.draft({
        policyId: id, requestType: 'CREATE',
        payload: { id, name, description, type, priority, config },
        changeReason: changeReason.trim(), actor,
      });
      const changeRequest = await PolicyGovernanceService.submit({ requestId: draft.id, actor });

      emit('INFO', 'POLICY_CHANGE_REQUEST_SUBMITTED', {
        changeRequestId: changeRequest.id, policyId: id, requestType: 'CREATE', actor: actor.username,
        requestId: req.requestId ?? null,
      });
      return _ok(res, {
        changeRequest,
        message: 'Change request submitted for review — it has not been activated. '
                + `Continue at /v1/policy/governance/${changeRequest.id}.`,
      }, 201, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── PUT /policies/:policyId — creates a governed UPDATE change request ─────
  // — see POST /policies above.

  router.put('/policies/:policyId', _canManage, async (req, res) => {
    const { policyId } = req.params;
    const { name, description, priority, config, changeReason } = req.body || {};
    const actor = _governanceActor(req);

    if (_requireReason(res, req, changeReason)) return;

    const updates = {};
    if (name        !== undefined) updates.name        = name;
    if (description !== undefined) updates.description = description;
    if (priority    !== undefined) updates.priority    = priority;
    if (config      !== undefined) updates.config      = config;

    try {
      const draft = await PolicyGovernanceService.draft({
        policyId, requestType: 'UPDATE', payload: updates, changeReason: changeReason.trim(), actor,
      });
      const changeRequest = await PolicyGovernanceService.submit({ requestId: draft.id, actor });

      emit('INFO', 'POLICY_CHANGE_REQUEST_SUBMITTED', {
        changeRequestId: changeRequest.id, policyId, requestType: 'UPDATE', actor: actor.username,
        requestId: req.requestId ?? null,
      });
      return _ok(res, {
        changeRequest,
        message: 'Change request submitted for review — the policy has not been modified yet. '
                + `Continue at /v1/policy/governance/${changeRequest.id}.`,
      }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── POST /policies/:policyId/enable — creates a governed ENABLE change
  // request. No direct activation path survives this remediation
  // — activation always requires independent review/approval/publish
  // through /v1/policy/governance (or the explicit emergency workflow).

  router.post('/policies/:policyId/enable', _canManage, async (req, res) => {
    const { policyId } = req.params;
    const { changeReason } = req.body || {};
    const actor = _governanceActor(req);

    if (_requireReason(res, req, changeReason)) return;

    try {
      const draft = await PolicyGovernanceService.draft({
        policyId, requestType: 'ENABLE', payload: {}, changeReason: changeReason.trim(), actor,
      });
      const changeRequest = await PolicyGovernanceService.submit({ requestId: draft.id, actor });

      emit('INFO', 'POLICY_CHANGE_REQUEST_SUBMITTED', {
        changeRequestId: changeRequest.id, policyId, requestType: 'ENABLE', actor: actor.username,
        requestId: req.requestId ?? null,
      });
      return _ok(res, {
        changeRequest,
        message: 'Change request submitted for review — the policy has not been enabled yet. '
                + `Continue at /v1/policy/governance/${changeRequest.id}.`,
      }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── POST /policies/:policyId/disable — creates a governed DISABLE change
  // request. See /enable above.

  router.post('/policies/:policyId/disable', _canManage, async (req, res) => {
    const { policyId } = req.params;
    const { changeReason } = req.body || {};
    const actor = _governanceActor(req);

    if (_requireReason(res, req, changeReason)) return;

    try {
      const draft = await PolicyGovernanceService.draft({
        policyId, requestType: 'DISABLE', payload: {}, changeReason: changeReason.trim(), actor,
      });
      const changeRequest = await PolicyGovernanceService.submit({ requestId: draft.id, actor });

      emit('INFO', 'POLICY_CHANGE_REQUEST_SUBMITTED', {
        changeRequestId: changeRequest.id, policyId, requestType: 'DISABLE', actor: actor.username,
        requestId: req.requestId ?? null,
      });
      return _ok(res, {
        changeRequest,
        message: 'Change request submitted for review — the policy has not been disabled yet. '
                + `Continue at /v1/policy/governance/${changeRequest.id}.`,
      }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── GET /policies/:policyId/versions ───────────────────────────────────────

  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them slices `versions` and adds
  // canonical pagination metadata.
  router.get('/policies/:policyId/versions', _canRead, async (req, res) => {
    const { policyId } = req.params;
    try {
      const versions = getVersions(policyId);
      if (versions === null || versions === undefined) {
        return failure(res, 'NOT_FOUND', `Policy '${policyId}' not found`, 404);
      }
      if (!isPaginationRequested(req.query)) {
        return _ok(res, { policyId, versions }, 200, req);
      }
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: MAX_PAGE_SIZE });
      const { items, ...meta } = paginateArray(versions, { page, pageSize });
      return _ok(res, { policyId, versions: items, ...meta }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── GET /policies/:policyId/versions/:v ────────────────────────────────────

  router.get('/policies/:policyId/versions/:v', _canRead, async (req, res) => {
    const { policyId, v } = req.params;
    const vNum = parseInt(v, 10);

    if (!Number.isFinite(vNum) || vNum < 1) {
      return failure(res, 'INVALID_PARAM', `Version must be a positive integer, got: ${v}`, 400);
    }

    try {
      const version = getVersion(policyId, vNum);
      if (version === null || version === undefined) {
        return failure(res, 'NOT_FOUND', `Version ${vNum} of policy '${policyId}' not found`, 404);
      }
      return _ok(res, { policyId, version }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── GET /policies/:policyId/diff ────────────────────────────────────────────

  router.get('/policies/:policyId/diff', _canRead, async (req, res) => {
    const { policyId }  = req.params;

    const fromNum = parseInt(req.query.from, 10);
    const toNum   = parseInt(req.query.to,   10);

    if (!Number.isFinite(fromNum) || fromNum < 1) {
      return failure(res, 'INVALID_PARAM', `Query param 'from' must be a positive integer`, 400);
    }
    if (!Number.isFinite(toNum) || toNum < 1) {
      return failure(res, 'INVALID_PARAM', `Query param 'to' must be a positive integer`, 400);
    }

    try {
      const versionA = getVersion(policyId, fromNum);
      if (versionA === null || versionA === undefined) {
        return failure(res, 'NOT_FOUND', `Version ${fromNum} of policy '${policyId}' not found`, 404);
      }

      const versionB = getVersion(policyId, toNum);
      if (versionB === null || versionB === undefined) {
        return failure(res, 'NOT_FOUND', `Version ${toNum} of policy '${policyId}' not found`, 404);
      }

      const snapshotA = versionA.snapshot ?? {};
      const snapshotB = versionB.snapshot ?? {};

      const changes = _diffSnapshots(snapshotA, snapshotB);
      const summary = _diffSummary(changes);

      return _ok(res, {
        artifactId:   policyId,
        fromVersion:  fromNum,
        toVersion:    toNum,
        changes,
        summary,
        fromSnapshot: snapshotA,
        toSnapshot:   snapshotB,
      }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── POST /policies/:policyId/rollback — creates a governed rollback
  // request. Does not apply anything yet: it must still be
  // independently approved by someone other than the requester AND other
  // than whoever originally activated the version being rolled back — see
  // POST /v1/policy/governance/:id/rollback/approve.

  router.post('/policies/:policyId/rollback', _canManage, async (req, res) => {
    const { policyId } = req.params;
    const { toVersion, changeReason } = req.body || {};
    const actor = _governanceActor(req);

    if (_requireReason(res, req, changeReason)) return;

    try {
      const result = await RollbackGovernanceService.requestRollback({
        policyId, toVersion, reason: changeReason.trim(), actor,
      });

      emit('INFO', 'POLICY_CHANGE_REQUEST_SUBMITTED', {
        changeRequestId: result.changeRequest.id, policyId, requestType: 'ROLLBACK', actor: actor.username,
        requestId: req.requestId ?? null,
      });
      return _ok(res, {
        changeRequest: result.changeRequest,
        fromVersion:   result.fromVersion,
        toVersion:     result.toVersion,
        message: 'Rollback request submitted — it has not been applied yet, and cannot be approved by the '
                + `same individual who requested it or who activated version ${result.fromVersion}. `
                + `Continue at /v1/policy/governance/${result.changeRequest.id}/rollback/approve.`,
      }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  // ── GET /policies/:policyId/history ────────────────────────────────────────

  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them slices `history` and adds
  // canonical pagination metadata.
  router.get('/policies/:policyId/history', _canRead, async (req, res) => {
    const { policyId } = req.params;
    try {
      const history = getHistory(policyId);
      if (history === null || history === undefined) {
        return failure(res, 'NOT_FOUND', `Policy '${policyId}' not found`, 404);
      }
      if (!isPaginationRequested(req.query)) {
        return _ok(res, { policyId, history }, 200, req);
      }
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: MAX_PAGE_SIZE });
      const { items, ...meta } = paginateArray(history, { page, pageSize });
      return _ok(res, { policyId, history: items, ...meta }, 200, req);
    } catch (err) {
      return _storeError(res, err, req);
    }
  });

  return router;
}

module.exports = createPolicyManagementRouter;
