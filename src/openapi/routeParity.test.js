'use strict';

/**
 * Route Parity Test — API-3 remediation drift prevention.
 *
 * routeScanner.js is a hand-maintained static registry (see its own header
 * comment) — nothing forces it to stay in sync with the Express routers it
 * describes. This test is that missing force: it statically extracts every
 * `router.<method>('<path>', ...)` registration from the actual route-handler
 * source files, maps each one through the exact mount-prefix table server.js
 * uses (`app.use('<prefix>', ..., <router>)`), and diffs the resulting
 * ground-truth surface against `buildPaths()`.
 *
 * It deliberately parses source text rather than `require()`-ing and mounting
 * every router: several router factories have non-trivial constructor
 * dependencies (Postgres-backed stores, RBAC permission gates, live policy
 * getters) that make a faithful full-app assembly its own maintenance burden,
 * and static extraction is exactly the same "reviewed alongside the route
 * handler, cannot drift silently" model routeScanner.js already commits to.
 *
 * Fails the build if:
 *   - a route is registered in a router file but missing from routeScanner.js
 *   - routeScanner.js documents a path/method that no router file registers
 *   - the same path is registered with a different set of HTTP methods
 */

const fs   = require('fs');
const path = require('path');
const { buildPaths } = require('./routeScanner');
const { MOUNTS, EXPLICIT_ROUTES } = require('./routeMounts');

const ROOT = path.join(__dirname, '..', '..');

// Mount table and explicit-route list now live in ./routeMounts.js — shared
// with src/api/responseEnvelopes.js
// so there's one source of truth instead of a second hand-copied list.

// Registered routes that are intentionally excluded from the OpenAPI surface:
// a bare 301 redirect convenience alias with no meaningful request/response
// contract of its own (the canonical route is GET /docs); and the production
// profiling surface (src/api/routes/diagnosticsProfile.js, item 27 —
// ITEM-26-RESPONSE-ENVELOPE-DECISION-RECORD.md D26-5 point 1) — ops-only,
// gated by a second independent kill switch (see that file's own header
// comment), never documented in the public OpenAPI spec, and out of scope
// for this item to newly document.
const KNOWN_UNDOCUMENTED = new Set([
  'get /docs/',
  'get /diagnostics/profile/memory',
  'get /diagnostics/profile/gc',
  'post /diagnostics/profile/cpu',
]);

// ── Static route extraction ───────────────────────────────────────────────────

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];
// Matches router.<method>('<path>', ...) / router.<method>("<path>", ...).
// Deliberately requires a quoted string literal immediately after the method
// call — this is what excludes router.use(...) catch-alls (no method match)
// and variable-path routes like openapi.js's router.get(jsonPath, ...).
const ROUTE_RE = new RegExp(
  `router\\.(${METHODS.join('|')})\\(\\s*(['"\`])((?:(?!\\2).)*)\\2`,
  'g',
);

function _toOpenApiPath(exPath) {
  // /:id -> /{id}, /:a/:b -> /{a}/{b}
  return exPath.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}

function extractLocalRoutes(fileRelPath) {
  const src = fs.readFileSync(path.join(ROOT, fileRelPath), 'utf8');
  const routes = [];
  let m;
  ROUTE_RE.lastIndex = 0;
  while ((m = ROUTE_RE.exec(src))) {
    const [, method, , rawPath] = m;
    routes.push({ method, path: _toOpenApiPath(rawPath) });
  }
  return routes;
}

function joinPath(prefix, localPath) {
  if (localPath === '/') return prefix || '/';
  return `${prefix}${localPath}`;
}

// ── Build the ground-truth implemented-route set ──────────────────────────────

function getImplementedRoutes() {
  const set = new Set();
  const byFile = new Map();

  for (const { prefix, file } of MOUNTS) {
    if (!byFile.has(file)) byFile.set(file, extractLocalRoutes(file));
    for (const { method, path: localPath } of byFile.get(file)) {
      set.add(`${method} ${joinPath(prefix, localPath)}`);
    }
  }

  for (const { method, path: p } of EXPLICIT_ROUTES) {
    set.add(`${method} ${p}`);
  }

  return set;
}

// ── Build the documented-route set from the OpenAPI spec's static registry ────

function getDocumentedRoutes() {
  const paths = buildPaths();
  const set = new Set();
  for (const p of Object.keys(paths)) {
    for (const method of Object.keys(paths[p])) {
      set.add(`${method} ${p}`);
    }
  }
  return set;
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('OpenAPI spec vs. implementation — route parity (API-3 drift prevention)', () => {
  let implemented;
  let documented;

  beforeAll(() => {
    implemented = getImplementedRoutes();
    documented  = getDocumentedRoutes();
  });

  test('every implemented route is documented in routeScanner.js', () => {
    const missing = [...implemented]
      .filter(r => !documented.has(r) && !KNOWN_UNDOCUMENTED.has(r))
      .sort();

    expect(missing).toEqual([]);
  });

  test('every documented route corresponds to a real implementation', () => {
    const phantom = [...documented].filter(r => !implemented.has(r)).sort();

    expect(phantom).toEqual([]);
  });

  test('sanity: extraction found a substantial number of real routes', () => {
    // Guards against the regex silently matching zero routes (e.g. after a
    // refactor to router construction) and this test suite passing vacuously.
    expect(implemented.size).toBeGreaterThan(150);
  });
});
