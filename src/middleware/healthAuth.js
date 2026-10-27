'use strict';

// Authentication gate for liveness/readiness probe endpoints (/health, /ready).
//
// Root cause this exists to fix: Kubernetes httpGet probes and Docker's
// HEALTHCHECK CMD cannot supply the QODIQA_OPS_TOKEN bearer credential that
// every other operational endpoint (/metrics, /diagnostics, /audit) requires.
// Mounting /health and /ready behind the same createOpsAuthMiddleware() used
// by those endpoints made every orchestrator probe fail with 401 — a
// deploy-breaking defect, and a direct contradiction of docs/deployment/startup-and-probes.md
// and docs/deployment/kubernetes-probes.md, both of which document "Authentication: None"
// for these two routes.
//
// Secure-by-default model:
//   - QODIQA_HEALTH_PROBE_AUTH_REQUIRED=false (default): no credential is
//     required. This matches Kubernetes/Docker/ECS/Nomad probe conventions
//     and is safe ONLY because /health and /ready are contractually minimal
//     (see src/api/routes/health.js and ready.js). Neither route may ever
//     return version numbers, stack traces, configuration, environment
//     values, provider identities, cryptographic material, or secrets — this
//     contract is enforced by a regression test in
//     src/middleware/__tests__/healthAuth.test.js.
//   - QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true: delegates to the EXACT SAME
//     createOpsAuthMiddleware() used by /metrics and /diagnostics — no
//     authentication logic is duplicated here. Operators who enable this
//     must configure their orchestrator's probe to send the credential
//     (Kubernetes: httpGet.httpHeaders; Docker: change HEALTHCHECK CMD to
//     pass a header). See docs/deployment/kubernetes-probes.md for a worked example.
//
// This is the ONLY place that decides whether /health and /ready require a
// credential — server.js and other callers must not duplicate this check.

const { createOpsAuthMiddleware } = require('./opsAuth');

/**
 * @param {object} opsConfig     — result of loadOpsConfig()
 * @param {object} [rbacStore]   — the RBAC user store singleton
 * @param {object} [authLockout] — result of createAuthLockout(opsConfig); see
 *                                 src/core/authLockout (AUTH-2). Passed straight
 *                                 through to the delegated opsAuth middleware so
 *                                 /health and /ready (when auth-gated) share the
 *                                 exact same per-source lockout state as every
 *                                 other ops endpoint — one shared token, one
 *                                 shared brute-force surface, one control.
 */
function createHealthAuthMiddleware(opsConfig, rbacStore, authLockout) {
  if (!opsConfig.healthAuthRequired) {
    return function healthAuthDisabled(_req, _res, next) { next(); };
  }
  return createOpsAuthMiddleware(opsConfig, rbacStore, authLockout);
}

module.exports = { createHealthAuthMiddleware };
