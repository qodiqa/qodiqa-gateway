'use strict';

// Kill-switch middleware for the CPU/GC/heap profiling diagnostics surface
// (GET /diagnostics/profile/*) — #4.
//
// Deliberately a SEPARATE gate from src/middleware/opsEnabled.js's
// createOpsDiagnosticsGate: profiling carries materially more performance
// impact (CPU sampling, forced GC observation) and information-disclosure
// risk (function names, file paths, timing internals) than the health-style
// /diagnostics endpoint that gate protects. A deployment can have general
// diagnostics enabled while keeping profiling off, or vice versa.
//
// Same 404-not-401 contract as opsEnabled.js: when disabled, the endpoint
// appears not to exist, so an unauthenticated or unauthorized caller cannot
// distinguish "requires auth" from "does not exist" — see that module's
// header comment for the full enumeration-resistance rationale, which
// applies identically here.
//
// Mounted AFTER ctx.opsOnlyStack() (rate limit, IP allowlist, ops auth,
// general diagnostics gate) in src/app.js — both gates must pass.

const { emit } = require('../../services/logger');
const { failure } = require('../api/response');

function createProfilingDiagnosticsGate(opsConfig) {
  return function profilingDiagnosticsGate(req, res, next) {
    if (!opsConfig.profilingDiagnosticsEnabled) {
      emit('INFO', 'OPS_DISABLED_ACCESS_ATTEMPT', {
        path:      req.path,
        ip:        req.clientIp ?? req.ip ?? null,
        requestId: req.requestId ?? null,
        surface:   'profiling',
      });
      return failure(res, 'NOT_FOUND', 'Not found', 404);
    }
    next();
  };
}

module.exports = { createProfilingDiagnosticsGate };
