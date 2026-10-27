'use strict';

/**
 * OpenAPI Routes — Component #42
 *
 * Mounts three public (no auth) endpoints:
 *
 *   GET /openapi.json   — full spec as JSON
 *   GET /openapi.yaml   — full spec as YAML
 *   GET /docs           — Swagger UI explorer (HTML)
 *
 * The spec is generated once at first request and cached in memory.
 * Pass ?fresh=1 to force regeneration (useful during development).
 *
 * These endpoints are intentionally unauthenticated — the spec itself
 * contains no secrets, only schema descriptions.
 */

const { Router }             = require('express');
const { generateSpec }       = require('../../openapi/generator');
const { writeJson }          = require('../../openapi/writers/jsonWriter');
const { writeYaml }          = require('../../openapi/writers/yamlWriter');
const { renderSwaggerUiHtml, getSwaggerAsset } = require('../../openapi/swaggerUi');
const { failure, internalError } = require('../response');
const { createRateLimitMiddleware } = require('../../core/rateLimit');

/**
 * Create and return the OpenAPI router.
 *
 * @param {object} [options]
 * @param {string} [options.docsPath]   — mount path for the Swagger UI (default: '/docs')
 * @param {string} [options.jsonPath]   — mount path for JSON spec  (default: '/openapi.json')
 * @param {string} [options.yamlPath]   — mount path for YAML spec  (default: '/openapi.yaml')
 * @param {string} [options.basePath]   — base URL prefix forwarded to Swagger UI (default: '')
 * @returns {Router}
 */
function createOpenApiRouter(options) {
  const router    = Router();
  const docsPath  = (options && options.docsPath)  || '/docs';
  const jsonPath  = (options && options.jsonPath)   || '/openapi.json';
  const yamlPath  = (options && options.yamlPath)   || '/openapi.yaml';
  const basePath  = (options && options.basePath)   || '';
  // the spec and docs routes had no limiter; per-route (this router is
  // mounted at '/', so a router-level use() would throttle every request reaching it).
  const _rl       = createRateLimitMiddleware('public_docs', { envelope: 'legacyFailure' });

  // ── GET /openapi.json ───────────────────────────────────────────────────────
  router.get(jsonPath, _rl, (req, res) => {
    try {
      // the spec is generated from code and never changes at runtime in production — `fresh` (a cache bypass for
      // development hot reloads) would only let anonymous callers force regeneration there.
      const fresh = process.env.NODE_ENV !== 'production' && (req.query.fresh === '1' || req.query.fresh === 'true');
      const spec  = generateSpec(fresh ? { fresh: true } : undefined);
      const body  = writeJson(spec);

      res.set('Content-Type', 'application/json; charset=utf-8');
      res.set('Cache-Control', 'public, max-age=300');
      res.set('X-Content-Type-Options', 'nosniff');
      res.status(200).send(body);
    } catch (err) {
      internalError(res, req, err, { label: 'OPENAPI_GENERATION_FAILED', code: 'OPENAPI_GENERATION_FAILED' });
    }
  });

  // ── GET /openapi.yaml ───────────────────────────────────────────────────────
  router.get(yamlPath, _rl, (req, res) => {
    try {
      // the spec is generated from code and never changes at runtime in production — `fresh` (a cache bypass for
      // development hot reloads) would only let anonymous callers force regeneration there.
      const fresh = process.env.NODE_ENV !== 'production' && (req.query.fresh === '1' || req.query.fresh === 'true');
      const spec  = generateSpec(fresh ? { fresh: true } : undefined);
      const body  = writeYaml(spec);

      res.set('Content-Type', 'application/yaml; charset=utf-8');
      res.set('Cache-Control', 'public, max-age=300');
      res.set('X-Content-Type-Options', 'nosniff');
      res.status(200).send(body);
    } catch (err) {
      internalError(res, req, err, { label: 'OPENAPI_GENERATION_FAILED', code: 'OPENAPI_GENERATION_FAILED' });
    }
  });

  // ── GET /docs ───────────────────────────────────────────────────────────────
  router.get(docsPath, _rl, (req, res) => {
    try {
      const html = renderSwaggerUiHtml({
        specUrl:    basePath + jsonPath,
        basePath:   basePath,
        assetsPath: docsPath + '/assets',
      });

      res.set('Content-Type', 'text/html; charset=utf-8');
      res.set('Cache-Control', 'public, max-age=60');
      res.set('X-Content-Type-Options', 'nosniff');
      res.status(200).send(html);
    } catch (err) {
      internalError(res, req, err, { label: 'OPENAPI_GENERATION_FAILED', code: 'OPENAPI_GENERATION_FAILED' });
    }
  });

  // ── GET /docs/assets/:name ─────────────────────────────────────────
  // The self-hosted swagger-ui-dist files and the same-origin initializer. Only the allowlisted names resolve
  // (getSwaggerAsset never takes a path), so nothing else under src/ can be read through this route.
  router.get(docsPath + '/assets/:name', _rl, (req, res) => {
    const asset = getSwaggerAsset(req.params.name);
    if (!asset) return failure(res, 'NOT_FOUND', 'Not found', 404);
    res.set('Content-Type', asset.type);
    res.set('Cache-Control', 'public, max-age=86400');
    res.set('X-Content-Type-Options', 'nosniff');
    return res.status(200).send(asset.body);
  });

  // Convenience redirect: GET /docs/ → GET /docs
  router.get(docsPath + '/', _rl, (req, res) => res.redirect(301, basePath + docsPath));

  return router;
}

module.exports = { createOpenApiRouter };
