'use strict';

/**
 * LDAP / Active Directory password sign-in for operators - PUBLIC by nature (no credential yet), answers 404 unless QODIQA_LDAP_CONFIG_PATH names the provider.
 *
 *   POST /auth/ldap/login   { provider, username, password } (JSON) -> an operator session token (Cache-Control: no-store)
 *
 * Every refusal (wrong password, unknown user, not linked, disabled, locked, not in the required group) is the same generic 401: the answer never tells which. A directory or store outage is 503.
 * Strictly limited per client address (10/min) on top of the per-(provider, username) lockout in src/core/identity/ldapService.js. See docs/guides/IDENTITY.md.
 */

const express = require('express');
const ldapService = require('../../core/identity/ldapService');
const rbacStore = require('../../core/rbac/store');
const { emit } = require('../../../services/logger');
const { success, failure } = require('../response');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { createLimiter } = require('./samlAuth');

function createLdapAuthRouter({ limiter = createLimiter({ max: 10 }) } = {}) {
  const router = express.Router();
  router.use(limiter);
  router.use(createRateLimitMiddleware('public_verify', { envelope: 'management' }));

  router.post('/login', express.json({ limit: '4kb', strict: true }), async (req, res) => {
    res.set('Cache-Control', 'no-store');
    const b = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    if (typeof b.provider !== 'string' || typeof b.username !== 'string' || typeof b.password !== 'string') return failure(res, 'BAD_REQUEST', 'Bad request', 400);
    try {
      const r = await ldapService.login(b.provider, b.username, b.password, { rbacStore });
      if (r.ok) return success(res, { token: r.token, tokenType: 'Bearer', expiresAt: r.expiresAt, assured: r.assured, user: r.user });
      if (r.unavailable) { res.set('Retry-After', '5'); return failure(res, 'LOGIN_UNAVAILABLE', 'The login cannot be completed right now', 503); }
      if (r.reason === 'UNKNOWN_PROVIDER') return failure(res, 'NOT_FOUND', 'Not found', 404);
      return failure(res, 'AUTHENTICATION_FAILED', 'Authentication failed', 401);
    } catch (e) {
      emit('ERROR', 'LDAP_LOGIN_FAILED', { providerId: b.provider, error: e.message });
      return failure(res, 'LOGIN_UNAVAILABLE', 'The login cannot be completed right now', 503);
    }
  });

  return router;
}

module.exports = { createLdapAuthRouter };
