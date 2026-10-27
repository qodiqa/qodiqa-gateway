'use strict';

/**
 * Per-artifact revocation administration.
 *
 *   POST /v1/admin/artifact-revocations              body { requestId, reason }   (MANAGE_ARTIFACT_REVOCATIONS, MFA step-up)
 *   GET  /v1/admin/artifact-revocations/:requestId   is it revoked?               (MANAGE_ARTIFACT_REVOCATIONS)
 *
 * Mounted behind the admin stack (operator authentication, RBAC, admin-plane gates) and the operator MFA step-up in
 * src/app.js. See src/core/artifactRevocation/index.js for the semantics.
 */

const { Router } = require('express');
const artifactRevocation = require('../../../core/artifactRevocation');
const { resolveOperatorActor } = require('../../../core/audit/actorAttribution');
const { success, failure } = require('../../response');
const { permissionGuard } = require('../permissionGuard');

function createArtifactRevocationsAdminRouter({ requirePermission } = {}) {
  const router = Router();
  const _canManage = permissionGuard(requirePermission, 'MANAGE_ARTIFACT_REVOCATIONS', 'artifactRevocationsAdmin');

  function _handle(res, fn) {
    return Promise.resolve().then(fn).catch((err) => {
      if (err && err.name === 'ArtifactRevocationError') return failure(res, err.code, err.message, err.status);
      return failure(res, 'ARTIFACT_REVOCATION_FAILED', 'The artifact revocation could not be processed.', 500);
    });
  }

  router.post('/', _canManage, (req, res) => _handle(res, async () => {
    const { requestId, reason } = req.body || {};
    const out = await artifactRevocation.revoke({ requestId, reason, operatorId: resolveOperatorActor(req) });
    return success(res, out);
  }));

  router.get('/:requestId', _canManage, (req, res) => _handle(res, async () => {
    const { requestId } = req.params;
    if (!artifactRevocation.REQUEST_ID_RE.test(requestId)) return failure(res, 'INVALID_REQUEST_ID', 'requestId must be the UUID of the artifact (payload.requestId)', 400);
    let record;
    try { record = await artifactRevocation.isRevoked(requestId); } catch { return failure(res, 'REVOCATION_STORE_UNAVAILABLE', 'The revocation store could not answer.', 503); }
    return success(res, { revoked: record !== null, record });
  }));

  return router;
}

module.exports = { createArtifactRevocationsAdminRouter };
