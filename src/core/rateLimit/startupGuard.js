'use strict';

/**
 * Rate-Limiter Distributed-Enforcement Startup Guard — Step 5
 *
 * middleware/publicRateLimit.js is an in-memory, single-process limiter (see
 * its own header comment). In a horizontally-scaled deployment, each replica
 * enforces its own independent counter, so the effective limit becomes
 * `configured limit × replica count` instead of the configured limit — the
 * exact gap closes by migrating every production route onto
 * src/core/rateLimit/middleware.js (Redis-backed, shared across replicas).
 *
 * This guard is the fail-closed backstop for that migration: when the
 * deployment is configured for multiple instances, it refuses to start if
 * any route in the live, fully-mounted Express app still uses the legacy
 * limiter — modeled directly on src/core/audit/multiInstanceGuard.js's
 * fail-closed pattern (and reusing its ORDERING_MODE signal for "is this a
 * multi-instance deployment", rather than introducing a second, redundant
 * flag: QODIQA_AUDIT_ORDERING_MODE=distributed is already this codebase's
 * existing convention for "more than one replica may run").
 *
 * Detection: middleware/publicRateLimit.js tags every middleware function it
 * returns with `_legacyPublicRateLimiter = true`. checkNoLegacyRateLimiters()
 * walks the constructed app's router stack (Express 4's `app._router.stack`,
 * recursing into nested routers/sub-apps) looking for that tag on any layer
 * handler. No false positives: only the explicit tag triggers a match, never
 * a name or path heuristic.
 */

const { writeDiagnostic } = require('../../runtime/rawStderrDiagnostic');
const { notifyCriticalStartupFailure } = require('../../runtime/earlyCriticalNotify');
const { ORDERING_MODE } = require('../audit/multiInstanceGuard');

/**
 * Recursively collects every legacy-tagged middleware handler mounted
 * anywhere in the given Express app's router stack, returning the list of
 * route paths (best-effort — Layer.route?.path, or the layer's own regexp
 * source when it's a mounted sub-router) they were found on.
 */
function _findLegacyLayers(stack, prefix, out) {
  for (const layer of stack ?? []) {
    if (layer.handle?._legacyPublicRateLimiter === true) {
      out.push(prefix + (layer.route?.path ?? (layer.regexp ? layer.regexp.source : '<middleware>')));
    }
    // Nested router (app.use('/mount', router)) or a route with its own
    // per-method handler stack — both expose further layers to recurse into.
    if (layer.handle?.stack) {
      _findLegacyLayers(layer.handle.stack, prefix, out);
    }
    if (layer.route?.stack) {
      _findLegacyLayers(layer.route.stack, prefix + (layer.route.path ?? ''), out);
    }
  }
  return out;
}

/**
 * Fail-closed startup assertion: in a multi-instance deployment
 * (QODIQA_AUDIT_ORDERING_MODE=distributed), refuses to boot if any route in
 * `app` still uses the legacy single-process rate limiter.
 *
 * No-op (returns true) in single-node mode — a lone process can never
 * multiply its own limit, so there is nothing to enforce there.
 *
 * All parameters are injectable for testing:
 *   _app          — the constructed Express app (default: the `app` argument)
 *   _orderingMode — default: ORDERING_MODE from multiInstanceGuard.js
 *   _exit         — exit function (default: process.exit)
 *
 * @returns {boolean} true if startup may proceed.
 */
function checkNoLegacyRateLimiters(app, { _orderingMode = ORDERING_MODE, _exit = (code) => process.exit(code) } = {}) {
  if (_orderingMode !== 'distributed') return true;

  const offenders = _findLegacyLayers(app?._router?.stack, '', []);
  if (offenders.length === 0) return true;

  const eventType = 'RATE_LIMIT_LEGACY_LIMITER_IN_DISTRIBUTED_MODE';
  writeDiagnostic('FATAL', eventType, {
    reason: 'QODIQA_AUDIT_ORDERING_MODE=distributed indicates a multi-instance deployment, but ' +
            'one or more routes still use middleware/publicRateLimit.js — a single-process, ' +
            'in-memory limiter. Each replica would enforce its own independent counter, ' +
            'multiplying the effective limit by the replica count.',
    offenders,
    action: 'Migrate the offending route(s) to src/core/rateLimit/middleware.js ' +
            '(createRateLimitMiddleware) — see WP-007-REMEDIATION-REPORT.md.',
  });
  notifyCriticalStartupFailure({ eventType, deploymentMode: _orderingMode, offenders }).catch(() => {});
  _exit(1);
  return false;
}

module.exports = { checkNoLegacyRateLimiters };
