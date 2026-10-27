'use strict';

/**
 * OpenAPI Generator — Component #42
 *
 * Assembles the complete OpenAPI 3.1.0 specification document by combining
 * constants, components, and route definitions.
 *
 * The generator is deterministic: given the same codebase, it always produces
 * bit-for-bit identical output.  No timestamps, random values, or external I/O.
 *
 * Pure function — no state, no side effects.
 */

const { OPENAPI_VERSION, INFO, SERVERS, TAGS, EXTERNAL_DOCS } = require('./constants');
const { buildComponents } = require('./componentsBuilder');
const { buildPaths }      = require('./routeScanner');
const { ERROR_CATALOG }   = require('../errors/catalog');
const { CLASSES }         = require('../api/blockHttpStatus');

/**
 * API-09 / API-10: the error catalogue, published in the spec instead of leaving `reason` / `error.code` as
 * undocumented free strings. Generated from src/errors/catalog.js (descriptions, decision-mode status, retryability)
 * joined with src/api/blockHttpStatus.js (the class and the `status`-mode HTTP status of every BLOCK reason).
 * src/errors/__tests__/catalogCompleteness.test.js gates both sources and this projection.
 */
function buildErrorCatalog() {
  const cls = new Map();
  for (const [name, { status, reasons }] of Object.entries(CLASSES)) for (const r of reasons) cls.set(r, { blockClass: name, statusModeHttpStatus: status });
  const out = {};
  for (const code of Object.keys(ERROR_CATALOG).sort()) {
    const e = ERROR_CATALOG[code];
    out[code] = { httpStatus: e.httpStatus, category: e.category, retryable: e.retryable, description: e.description, ...(cls.get(code) || {}) };
  }
  return out;
}

// ── Cache ─────────────────────────────────────────────────────────────────────
// Generated once at first call, then frozen and reused.  Avoids rebuilding the
// large paths object on every request to /openapi.json.

let _cachedSpec = null;

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate the complete OpenAPI 3.1.0 specification.
 *
 * @param {object} [options]
 * @param {boolean} [options.fresh]  — discard cached spec and regenerate
 * @returns {object}  The OpenAPI document as a plain JS object
 */
function generateSpec(options) {
  if (_cachedSpec && !(options && options.fresh)) return _cachedSpec;

  const spec = {
    openapi:      OPENAPI_VERSION,
    info:         INFO,
    servers:      SERVERS,
    externalDocs: EXTERNAL_DOCS,
    tags:         TAGS,
    security:     [{ BearerAuth: [] }],  // default security; overridden per-operation
    paths:        buildPaths(),
    components:   buildComponents(),
    'x-qodiqa-error-catalog': buildErrorCatalog(),
  };

  _cachedSpec = Object.freeze(spec);
  return _cachedSpec;
}

/**
 * Invalidate the cached specification.
 * Useful in tests or after a hot-reload.
 */
function invalidateCache() {
  _cachedSpec = null;
}

module.exports = { generateSpec, invalidateCache, buildErrorCatalog };
