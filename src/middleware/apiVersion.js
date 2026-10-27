'use strict';

/**
 * API Version Header Middleware — Component #15
 *
 * Stamps the X-QODIQA-API-Version response header on every request that
 * passes through a versioned route prefix (e.g. /v1/*).
 *
 * Mounted once at app.use('/v1', createApiVersionMiddleware()) so every
 * sub-route under /v1 receives the header without per-handler boilerplate.
 */

const CURRENT_VERSION = 'v1';

/**
 * Returns a middleware that sets X-QODIQA-API-Version on the response.
 *
 * @param {string} [version='v1']
 * @returns {import('express').RequestHandler}
 */
function createApiVersionMiddleware(version = CURRENT_VERSION) {
  return function apiVersionMiddleware(_req, res, next) {
    res.set('X-QODIQA-API-Version', version);
    next();
  };
}

module.exports = { createApiVersionMiddleware, CURRENT_VERSION };
