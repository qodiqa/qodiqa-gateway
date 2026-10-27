'use strict';

// ── Response envelope specification ───────────
//
// This comment is the authoritative, prose specification of every distinct
// top-level JSON response shape ("envelope") used across the QODIQA REST
// API. Its machine-checked counterpart is src/api/responseEnvelopes.js
// (ENVELOPE_TYPES + ROUTE_ENVELOPES) — src/api/__tests__/
// responseEnvelopeGovernance.test.js fails the build if this comment and
// that registry ever disagree, or if a route file exists that isn't
// classified into one of the types below. There are no undocumented
// response shapes; every one is named here.
//
// success()/failure() in this module build exactly two of these types:
//
//   MANAGEMENT_SUCCESS  { status: 'success', timestamp, requestId, data }
//   MANAGEMENT_ERROR    { status: 'error',   timestamp, requestId, error }
//
// This is the default envelope for the management/admin/observability API
// surface (audit, RBAC, compliance, dashboard, keys, policy management,
// webhooks, and similar routes — see QODIQA-PROTOCOL-SPEC.md §14.7).
//
// Every other route file is classified into one of these documented
// exceptions (see responseEnvelopes.js for the exact route → type mapping):
//
//   ENFORCEMENT_DECISION  { decision, reason, requestId, ... }
//     Core protocol surface (/ai/chat, /verify) — a normative business
//     decision, not a transport error (QODIQA-PROTOCOL-SPEC.md §14.6/14.7).
//     This is a deliberate asymmetry, not an oversight — see
//'s API-1 finding.
//   SIGN_SUCCESS  { artifactId, artifact, meta }
//     POST /sign's success response; its failure paths use
//     ENFORCEMENT_DECISION instead.
//   ACTION_SUCCESS  { artifactId | planId | delegationId | valid, ..., requestId }
//     POST /v1/actions/authorize, /v1/actions/plans and /v1/delegations success responses;
//     their refusals use ENFORCEMENT_DECISION, like /sign.
//   TOOL_CALL  { decision, result?, receipt?, reason?, details?, requestId }
//     POST /v1/tools/call: EXECUTE with the screened result, or the BLOCK / ERROR decision body.
//   WELL_KNOWN_LIST  { keys, requestId }
//   WELL_KNOWN_SINGLE  { keyId, algorithm, publicKey, status, requestId }
//   WELL_KNOWN_ERROR  { decision, reason, details, requestId }
//     /.well-known/qodiqa/* JWKS-style key discovery — its own bespoke
//     shapes, predates and is independent of this module.
//   INFRA_HEALTH  { status, uptime }
//   INFRA_READY  { ready, components }
//   INFRA_HEALTH_REDIS  { status, stores }
//   INFRA_DIAGNOSTICS  { service, version, status, executionIntegrity, ... }
//   INFRA_METRICS  (Prometheus text exposition format, not JSON)
//     Infrastructure probes (/health, /ready, /health/redis, /diagnostics,
//     /metrics) — deliberately minimal, deliberately NOT this module's
//     envelope. Each shape is independently load-bearing (see
//     docs/deployment/kubernetes-probes.md and healthContentSafety.test.js) and none
//     may be silently harmonized with another or with MANAGEMENT_*.
//   ALERTS_OK  { ok: boolean, ...variable-per-endpoint }
//     src/alerting/api/alertRoutes.js — documented pre-existing exception,
//     not migrated onto MANAGEMENT_* in the pass (see
//     API-8-REMEDIATION-REPORT.md for scope notes).
//   ALERTS_ERROR  { error: { code, message } }
//     src/alerting/api/alertRoutes.js's error helper — found live but
//     undocumented during item 26's census; codified in item 27 (see
//).
//   SERVICE_SHUTTING_DOWN  { success: false, error: { code, message } }
//     src/runtime/requestDrain.js — pre-pipeline shutdown-drain middleware,
//     not owned by any route file (see src/api/responseEnvelopes.js's
//     MIDDLEWARE_ENVELOPES, governed by responseEnvelopeGovernance.test.js
//     §F rather than the route-file-keyed sections above). Normatively
//     specified and explicitly exempted from the enforcement error schema by
//     QODIQA-PROTOCOL-SPEC.md §30.13/§21.4.

const { emit } = require('../../services/logger');

function buildFailureBody(code, message, requestId, details) {
  return {
    status:    'error',
    timestamp: new Date().toISOString(),
    requestId: requestId ?? null,
    error:     { code, message, ...(details !== undefined ? { details } : {}) },
  };
}

function success(res, data, httpStatus = 200) {
  return res.status(httpStatus).json({
    status:    'success',
    timestamp: new Date().toISOString(),
    requestId: res.locals?.requestId ?? null,
    data,
  });
}

function failure(res, code, message, httpStatus = 400, details) {
  return res.status(httpStatus).json(
    buildFailureBody(code, message, res.locals?.requestId, details),
  );
}

// API-2: centralized handler for an unexpected/unclassified error — logs the
// real error server-side (never dropped) and returns a generic, client-safe
// message (never err.message, which can leak internal implementation
// details: file paths, SQL fragments, stack-adjacent text, library-specific
// wording). Every route's catch-all error handler should call this instead
// of passing err.message into failure()/res.json() directly.
//
// Originated as a pattern several route files (webhooks.js among them)
// already implemented independently and identically — centralized here so
// there's one implementation instead of N near-identical copies, and so
// every OTHER route that was still passing err.message straight through has
// a drop-in replacement.
//
// @param {import('express').Response} res
// @param {import('express').Request}  req
// @param {Error} err
// @param {{ label?: string, code?: string, message?: string, details?: object, httpStatus?: number, extra?: object }} [opts]
//   extra — additional fields merged into the server-side log event only
//   (e.g. tenantId) — never into the client-facing response.
function internalError(res, req, err, opts = {}) {
  const {
    label      = 'API_INTERNAL_ERROR',
    code       = 'INTERNAL_ERROR',
    message    = 'An unexpected error occurred',
    details,
    httpStatus = 500,
    extra,
  } = opts;

  emit('ERROR', label, {
    path:      req?.path    ?? null,
    method:    req?.method  ?? null,
    requestId: req?.requestId ?? res.locals?.requestId ?? null,
    error:     err?.message ?? String(err),
    ...(extra || {}),
  });

  return failure(res, code, message, httpStatus, details);
}

module.exports = { success, failure, buildFailureBody, internalError };
