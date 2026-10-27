'use strict';

/**
 * SAML 2.0 single sign-on endpoints - PUBLIC by nature (the browser arrives here before it has any credential), mounted only when QODIQA_SAML_CONFIG_PATH is set.
 *
 *   GET  /auth/saml/login?provider=<id>     redirect the browser to the identity provider (signed relay state, one AuthnRequest id)
 *   POST /auth/saml/acs?provider=<id>       the identity provider's response (form post) -> an operator session token (JSON, Cache-Control: no-store)
 *   GET  /auth/saml/metadata?provider=<id>  the service-provider metadata to give the identity provider
 *
 * Every refusal answers the same generic 401 (the reason is only in the log): the response does not tell an attacker which check failed. The ACS accepts only the form
 * content type, at most 256 KiB, and is limited per client address. See src/core/identity/samlService.js for the flow and docs/guides/IDENTITY.md.
 */

const express = require('express');
const samlService = require('../../core/identity/samlService');
const rbacStore = require('../../core/rbac/store');
const { emit } = require('../../../services/logger');
const { success, failure } = require('../response');
const { createRateLimitMiddleware } = require('../../core/rateLimit');

const ID_RE = /^[a-z][a-z0-9-]{0,30}$/;

function createLimiter({ max = 30, windowMs = 60_000, now = () => Date.now() } = {}) {
  const hits = new Map();
  return (req, res, next) => {
    const key = req.clientIp || req.ip || 'unknown';
    const t = now(); const e = hits.get(key);
    if (!e || e.reset <= t) { if (hits.size > 5000) for (const [k, v] of hits) if (v.reset <= t) hits.delete(k); hits.set(key, { n: 1, reset: t + windowMs }); return next(); }
    if (++e.n > max) { res.set('Retry-After', String(Math.ceil((e.reset - t) / 1000))); return failure(res, 'RATE_LIMITED', 'Too many requests', 429); }
    return next();
  };
}

function createSamlAuthRouter({ limiter = createLimiter() } = {}) {
  const router = express.Router();
  router.use(limiter);
  router.use(createRateLimitMiddleware('public_verify', { envelope: 'management' }));

  router.get('/login', async (req, res) => {
    const id = typeof req.query.provider === 'string' ? req.query.provider : '';
    if (!ID_RE.test(id)) return failure(res, 'NOT_FOUND', 'Not found', 404);
    try {
      const r = await samlService.login(id);
      if (!r.ok) return failure(res, 'NOT_FOUND', 'Not found', 404);
      res.set('Cache-Control', 'no-store');
      return res.redirect(302, r.url);
    } catch (e) {
      emit('ERROR', 'SAML_LOGIN_FAILED', { providerId: id, error: e.message });
      return failure(res, 'LOGIN_UNAVAILABLE', 'The login cannot be completed right now', 503);
    }
  });

  router.post('/acs', express.urlencoded({ extended: false, limit: '256kb', parameterLimit: 10 }), async (req, res) => {
    const id = typeof req.query.provider === 'string' ? req.query.provider : '';
    if (!ID_RE.test(id)) return failure(res, 'NOT_FOUND', 'Not found', 404);
    res.set('Cache-Control', 'no-store');
    const body = req.body || {};
    if (typeof body.SAMLResponse !== 'string') return failure(res, 'BAD_REQUEST', 'Bad request', 400);
    try {
      const r = await samlService.acs(id, { samlResponse: body.SAMLResponse, relayState: typeof body.RelayState === 'string' ? body.RelayState : null }, { rbacStore });
      if (r.ok) return success(res, { token: r.token, tokenType: 'Bearer', expiresAt: r.expiresAt, assured: r.assured, user: r.user });
      if (r.unavailable) { res.set('Retry-After', '5'); return failure(res, 'LOGIN_UNAVAILABLE', 'The login cannot be completed right now', 503); }
      if (r.reason === 'UNKNOWN_PROVIDER') return failure(res, 'NOT_FOUND', 'Not found', 404);
      return failure(res, 'AUTHENTICATION_FAILED', 'Authentication failed', 401);
    } catch (e) {
      emit('ERROR', 'SAML_ACS_FAILED', { providerId: id, error: e.message });
      return failure(res, 'LOGIN_UNAVAILABLE', 'The login cannot be completed right now', 503);
    }
  });

  router.get('/metadata', (req, res) => {
    const id = typeof req.query.provider === 'string' ? req.query.provider : '';
    if (!ID_RE.test(id)) return failure(res, 'NOT_FOUND', 'Not found', 404);
    const xml = samlService.metadata(id);
    if (!xml) return failure(res, 'NOT_FOUND', 'Not found', 404);
    res.set('Content-Type', 'application/samlmetadata+xml; charset=utf-8');
    return res.status(200).send(xml);
  });

  return router;
}

module.exports = { createSamlAuthRouter, createLimiter };
