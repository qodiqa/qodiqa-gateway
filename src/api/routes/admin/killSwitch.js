'use strict';

/**
 * Global kill switch administration.
 *
 *   GET  /v1/admin/kill-switch           — current state          (READ_KILL_SWITCH)
 *   POST /v1/admin/kill-switch/activate  — raise it, body { reason }   (MANAGE_KILL_SWITCH, MFA step-up)
 *   POST /v1/admin/kill-switch/release   — lower it,  body { reason? } (MANAGE_KILL_SWITCH, MFA step-up)
 *
 * Mounted behind the admin stack (operator authentication, RBAC, admin-plane gates) and the operator MFA step-up
 * (src/middleware/mfaStepUp.js) in src/app.js. See src/core/killSwitch/index.js for the semantics.
 */

const { Router } = require('express');
const killSwitch = require('../../../core/killSwitch');
const { isControlPlaneError } = require('../../../core/controlPlane');
const { resolveOperatorActor } = require('../../../core/audit/actorAttribution');
const { success, failure } = require('../../response');
const { permissionGuard } = require('../permissionGuard');

function createKillSwitchAdminRouter({ requirePermission } = {}) {
  const router = Router();
  const _canRead = permissionGuard(requirePermission, 'READ_KILL_SWITCH', 'killSwitchAdmin');
  const _canManage = permissionGuard(requirePermission, 'MANAGE_KILL_SWITCH', 'killSwitchAdmin');

  function _handle(res, fn) {
    return Promise.resolve().then(fn).catch((err) => {
      if (err && err.name === 'KillSwitchError') return failure(res, err.code, err.message, err.status);
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      return failure(res, 'KILL_SWITCH_FAILED', 'The kill switch could not be changed.', 500);
    });
  }

  router.get('/', _canRead, (req, res) => _handle(res, () => success(res, killSwitch.view(killSwitch.state()))));

  router.post('/activate', _canManage, (req, res) => _handle(res, async () => {
    const out = await killSwitch.activate({ operatorId: resolveOperatorActor(req), reason: (req.body || {}).reason });
    return success(res, out);
  }));

  router.post('/release', _canManage, (req, res) => _handle(res, async () => {
    const out = await killSwitch.release({ operatorId: resolveOperatorActor(req), reason: (req.body || {}).reason });
    return success(res, out);
  }));

  return router;
}

module.exports = { createKillSwitchAdminRouter };
