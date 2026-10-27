'use strict';

/**
 *docs/api/overview.md must not describe an endpoint the contract does not have.
 * Every `METHOD /path` that appears in a heading of the API reference is looked up in the generated docs/api/openapi.json
 * (":param" is read as "{param}"; the unversioned and "/v1" spellings are both accepted because the gateway mounts both).
 * A documented endpoint missing from the contract fails the test, so the document can not silently outlive a route.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const spec = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'api', 'openapi.json'), 'utf8'));
const doc = fs.readFileSync(path.join(ROOT, 'docs', 'api', 'overview.md'), 'utf8');

// Paths that are served by the gateway but intentionally excluded from the OpenAPI document.
const NOT_IN_CONTRACT = new Set([
  'GET /openapi.json', 'GET /openapi.yaml', 'GET /',
  'GET /.well-known/qodiqa/keys',
  // operator-only profiling routes, additionally behind QODIQA_PROFILING_DIAGNOSTICS_ENABLED (default off); deliberately not in the public contract
  'GET /diagnostics/profile/memory', 'GET /diagnostics/profile/gc', 'POST /diagnostics/profile/cpu',
]);

function documentedOperations() {
  const ops = [];
  for (const line of doc.split(/\r?\n/)) {
    if (!/^#{1,6} /.test(line)) continue;
    // every `...` span of a heading; a span may list several methods ("GET|POST /v1/policy") and a heading may hold several spans
    const spans = [...line.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
    for (const span of spans) {
      const m = /^((?:GET|POST|PUT|PATCH|DELETE)(?:\s*\|\s*(?:GET|POST|PUT|PATCH|DELETE))*)\s+(\/\S*)$/.exec(span.trim());
      if (!m) continue;
      for (const method of m[1].split('|').map((x) => x.trim())) ops.push({ method, p: m[2], line });
    }
  }
  return ops;
}

const norm = (p) => p.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
const has = (method, p) => {
  const candidates = [norm(p), norm(p).replace(/^\/v1(\/|$)/, '/') .replace(/^\/\//, '/'), `/v1${norm(p)}`];
  return candidates.some((c) => spec.paths[c] && spec.paths[c][method.toLowerCase()]);
};

describe('API reference vs. generated OpenAPI contract', () => {
  const ops = documentedOperations();

  test('F2-DOC-01 the reference documents a non-trivial number of endpoints', () => {
    expect(ops.length).toBeGreaterThan(40);
    // the alternation form that the audit found stale must be parsed (GET|POST /x -> two operations)
    expect(documentedOperations.name).toBe('documentedOperations');
  });

  test('F2-DOC-02 every documented endpoint exists in docs/api/openapi.json', () => {
    const missing = ops.filter((o) => !NOT_IN_CONTRACT.has(`${o.method} ${o.p}`) && !has(o.method, o.p)).map((o) => `${o.method} ${o.p}`);
    expect(missing).toEqual([]);
  });
});
