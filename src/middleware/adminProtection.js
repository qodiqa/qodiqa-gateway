'use strict';

/**
 * Centralized Admin/Ops protection stack — Task #27 (defense-in-depth remediation).
 *
 * Every Admin route in server.js was previously assembled by repeating the
 * same 4-6 middleware references inline at each `app.use(...)` call. That
 * duplication is what let `/key-admin` silently drift from every sibling
 * route (missing `_opsGate` — see docs/security/RBAC_MODEL.md §8). This
 * module is the single place that composes the stack, so every Admin route
 * gets the same layers, in the same order, with no possibility of a route
 * accidentally omitting one.
 *
 * This module does NOT change RBAC. `requirePermission` remains the exact
 * function from `src/middleware/rbac.js`; this factory only decides WHICH
 * permission (if any) to require for a given mount and in what order the
 * surrounding defense-in-depth layers run. Permissions, roles, and the
 * authorization model are unchanged.
 *
 * Order (outermost/first-run to innermost/last-run):
 *   1. Rate limit        — throttle by client IP before any auth/RBAC work
 *                           is attempted (blunts credential-stuffing and
 *                           brute-force attempts against ops credentials).
 *   2. IP allowlist       — network-layer restriction (opt-in, fail-closed).
 *   3. Ops auth           — bearer/per-operator-API-key authentication.
 *   4. RBAC resolve       — require a resolved identity (fail-closed 403).
 *   5. Permission (opt.)  — require a specific permission for this mount.
 *   6. Plane gate         — kill switch. adminStack() uses adminGate
 *                           (QODIQA_ADMIN_ENABLED); opsOnlyStack() uses opsGate
 * (QODIQA_DIAGNOSTICS_ENABLED). Independent
 * — before, opsGate gated both.
 * because the gate runs LAST, a
 *                           disabled plane answers 404 only to a caller that
 *                           passed every earlier layer (authenticated, and
 *                           holding the mount's permission). An anonymous
 *                           caller still gets 401 and an under-privileged one
 *                           403 (and a rate-limited one 429), so the surface IS
 *                           enumerable while disabled: a disabled plane is not
 *                           hidden, only unusable. R-09 / OD-3 (approved
 *                           2026-10-15): the optional adminPreGate / opsPreGate
 *                           below run FIRST, so a disabled plane is 404 to every
 *                           caller and no longer enumerable (wired in startup.js).
 *
 * Two stacks are exposed:
 *   - adminStack(permission?) — full stack, used by every RBAC-gated Admin
 *     route (audit, rbac, key-admin, consent, webhooks, etc.)
 *   - opsOnlyStack() — the intentionally coarser stack for /metrics and
 *     /diagnostics, which by design require only ops-token possession, not
 *     a specific RBAC permission (see docs/security/RBAC_MODEL.md §6).
 */
// R-09 / OD-3 code option: optional adminPreGate / opsPreGate run FIRST (before layer 1). Supplied, a disabled plane is
// 404 for every caller before any rate-limit, network or auth work; omitted, the order above is unchanged.
function createAdminProtection({ rateLimit, opsIpAllow, opsAuth, rbacResolve, requirePermission, opsGate, adminGate, adminPreGate = null, opsPreGate = null }) {
  // Fail closed at wiring time: an admin stack without its own kill switch
  // would silently expose every admin mount regardless of QODIQA_ADMIN_ENABLED.
  if (typeof adminGate !== 'function') throw new TypeError('createAdminProtection: adminGate middleware is required');
  if (typeof opsGate !== 'function') throw new TypeError('createAdminProtection: opsGate middleware is required');

  function adminStack(permission) {
    const layers = [...(adminPreGate ? [adminPreGate] : []), rateLimit, opsIpAllow, opsAuth, rbacResolve];
    if (permission) layers.push(requirePermission(permission));
    layers.push(adminGate);
    return layers;
  }

  function opsOnlyStack() {
    return [...(opsPreGate ? [opsPreGate] : []), rateLimit, opsIpAllow, opsAuth, opsGate];
  }

  return { adminStack, opsOnlyStack };
}

module.exports = { createAdminProtection };
