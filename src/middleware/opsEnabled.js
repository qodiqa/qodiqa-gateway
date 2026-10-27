'use strict';

// Kill-switch middleware for operational visibility endpoints.
//
// When a plane is disabled the endpoint returns 404 to an AUTHENTICATED,
// AUTHORIZED caller — the resource appears not to exist. [, independent
// audit 2026-10-04: corrected.] The gate runs AFTER opsAuth/RBAC in both stacks
// so an unauthenticated
// request still receives 401 and a low-privilege key 403: the existence of the
// route surface IS enumerable; only whether the plane is enabled is hidden from
// callers who cannot reach it. R-09 / OD-3: the
// pre-auth gates below now run FIRST, so a disabled plane is 404 for everyone.
//
// Two independent switches:
//   - createOpsDiagnosticsGate — QODIQA_DIAGNOSTICS_ENABLED — the ops-only
//     visibility surface (/metrics, /diagnostics, /diagnostics/profile) via
//     opsOnlyStack() in src/middleware/adminProtection.js.
//   - createOpsAdminGate — QODIQA_ADMIN_ENABLED — every RBAC-gated Admin
//     mount (/audit, /rbac, /key-admin, /consent, /v1/admin/*, …) via
//     adminStack(). the diagnostics switch gated both.
//
// Production default for both: false when NODE_ENV=production; the operator
// must explicitly opt in (src/infra/config/opsConfig.js).

const { emit } = require('../../services/logger');
const { failure } = require('../api/response');

function createPlaneGate(opsConfig, flag, plane) {
  return function opsPlaneGate(req, res, next) {
    if (!opsConfig[flag]) {
      emit('INFO', 'OPS_DISABLED_ACCESS_ATTEMPT', {
        plane,
        path:      req.path,
        ip:        req.clientIp ?? req.ip ?? null,
        requestId: req.requestId ?? null,
      });
      return failure(res, 'NOT_FOUND', 'Not found', 404);
    }
    next();
  };
}

// R-09 / OD-3 code option: the SAME switches, checked
// FIRST — before the rate limiter, IP allowlist, ops auth and RBAC — so a disabled plane answers 404 to every caller,
// anonymous included, and its route surface is no longer enumerable. Deliberately SILENT: running
// before the rate limiter, a per-request log line would let anonymous scanners write unthrottled log volume. An enabled
// plane is unaffected (next()), and the original post-auth gate stays in place behind it.
function createPreAuthPlaneGate(opsConfig, flag) {
  return function opsPlanePreAuthGate(req, res, next) {
    if (!opsConfig[flag]) return failure(res, 'NOT_FOUND', 'Not found', 404);
    next();
  };
}

function createOpsDiagnosticsPreAuthGate(opsConfig) { return createPreAuthPlaneGate(opsConfig, 'diagnosticsEnabled'); }
function createOpsAdminPreAuthGate(opsConfig) { return createPreAuthPlaneGate(opsConfig, 'adminEnabled'); }

function createOpsDiagnosticsGate(opsConfig) {
  return createPlaneGate(opsConfig, 'diagnosticsEnabled', 'diagnostics');
}

function createOpsAdminGate(opsConfig) {
  return createPlaneGate(opsConfig, 'adminEnabled', 'admin');
}

module.exports = { createOpsDiagnosticsGate, createOpsAdminGate, createOpsDiagnosticsPreAuthGate, createOpsAdminPreAuthGate };
