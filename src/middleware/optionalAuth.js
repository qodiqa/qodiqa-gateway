'use strict';

/**
 * Optional authentication — (design decision D7 → B).
 *
 * Public verification routes (attestation/portal/transparency verify) stay
 * usable by anonymous third parties, but an anonymous call no longer creates
 * permanent records: the handler persists only when `req.rbacUser` is set.
 *
 *   - No credential (neither `Authorization` nor `x-ops-token`) → next() (anonymous,
 *     ephemeral: the full verification result, nothing persisted).
 *   - A credential presented  → the given middleware layers run in order
 *     (the full admin stack: rate limit, IP allowlist, ops auth, RBAC resolve,
 *     the write permission, plane gate). Any failure answers exactly as that
 *     layer does (401/403/404/429) and the route never runs — presenting bad
 *     credentials never silently downgrades to an anonymous, ephemeral call.
 *
 * @param {Function[]} layers  e.g. ctx.adminStack('MANAGE_ATTESTATIONS')
 * @returns {Function} Express middleware
 */
function createOptionalAuth(layers) {
  if (!Array.isArray(layers) || layers.some((l) => typeof l !== 'function')) {
    throw new TypeError('createOptionalAuth: layers must be an array of middleware functions');
  }
  return function optionalAuth(req, res, next) {
    // Same credential sources opsAuth accepts: Authorization, or x-ops-token.
    const presented = (req.headers.authorization !== undefined && req.headers.authorization !== '')
      || (req.headers['x-ops-token'] !== undefined && req.headers['x-ops-token'] !== '');
    if (!presented) return next();
    let i = 0;
    const step = (err) => {
      if (err) return next(err);
      if (i >= layers.length) return next();
      const layer = layers[i++];
      try {
        const r = layer(req, res, step);
        if (r && typeof r.catch === 'function') r.catch(next);
      } catch (e) { next(e); }
      return undefined;
    };
    step();
  };
}

module.exports = { createOptionalAuth };
