'use strict';

/**
 *router factories used to write
 *   const _canX = requirePermission ? requirePermission('X') : _noop;
 * so a router mounted WITHOUT requirePermission silently served every route permission-free (fail-open). This guard
 * fails CLOSED: outside the unit-test environment, a missing requirePermission throws at mount time. Unit suites
 * (NODE_ENV=test) mount routers bare to exercise handlers in isolation and keep the pass-through; the composed
 * application (src/app.js) always injects requirePermission, which the live-route suites build for real.
 *
 * @param {Function|undefined} requirePermission  the RBAC middleware factory injected by src/app.js
 * @param {string} permission                     permission name
 * @param {string} factory                        the calling router factory (for the error message)
 * @returns {Function} Express middleware
 */
function permissionGuard(requirePermission, permission, factory) {
  if (typeof requirePermission === 'function') return requirePermission(permission);
  if (process.env.NODE_ENV === 'test') return (_req, _res, next) => next();
  throw new Error(`${factory}: requirePermission is required — refusing to mount ${permission}-gated routes without a permission check`);
}

module.exports = { permissionGuard };
