#!/usr/bin/env node
'use strict';

// AUTONOMOUS-2026-10-10: generate the PUBLIC developer API document (docs/api/openapi.public.json) from the generated
// full contract (docs/api/openapi.json) and the launch allowlist (deploy/public-api/public-operations.json).
// Keeps only the allowlisted operations, prunes components to those transitively referenced, and drops the full
// contract's global BearerAuth default (every kept operation declares its own security). Deterministic output.
//
//   node scripts/openapi/public-subset.js           write docs/api/openapi.public.json
//   node scripts/openapi/public-subset.js --check   exit 1 if the committed file differs from a fresh render

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const FULL = path.join(ROOT, 'docs', 'api', 'openapi.json');
const ALLOW = path.join(ROOT, 'deploy', 'public-api', 'public-operations.json');
const OUT = path.join(ROOT, 'docs', 'api', 'openapi.public.json');

function collectRefs(node, acc) {
  if (Array.isArray(node)) { for (const x of node) collectRefs(x, acc); return acc; }
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (k === '$ref' && typeof v === 'string' && v.startsWith('#/components/')) acc.add(v);
      else collectRefs(v, acc);
    }
  }
  return acc;
}

function render(full = JSON.parse(fs.readFileSync(FULL, 'utf8')), allow = JSON.parse(fs.readFileSync(ALLOW, 'utf8'))) {
  const paths = {};
  for (const { method, path: p } of allow.operations) {
    const m = method.toLowerCase();
    const op = full.paths[p] && full.paths[p][m];
    if (!op) throw new Error(`allowlisted operation not in the contract: ${method} ${p}`);
    paths[p] = paths[p] || {};
    if (full.paths[p].parameters) paths[p].parameters = full.paths[p].parameters;
    paths[p][m] = op;
  }
  // Transitive closure of component references.
  const seen = new Set();
  let frontier = collectRefs(paths, new Set());
  while (frontier.size) {
    const next = new Set();
    for (const ref of frontier) {
      if (seen.has(ref)) continue;
      seen.add(ref);
      const [, , kind, name] = ref.split('/');
      const target = full.components[kind] && full.components[kind][name];
      if (!target) throw new Error(`dangling reference ${ref}`);
      collectRefs(target, next);
    }
    frontier = next;
  }
  const components = {};
  for (const ref of [...seen].sort()) {
    const [, , kind, name] = ref.split('/');
    components[kind] = components[kind] || {};
    components[kind][name] = full.components[kind][name];
  }
  const usedSchemes = new Set();
  for (const ops of Object.values(paths)) for (const [m, op] of Object.entries(ops)) {
    if (m === 'parameters') continue;
    for (const req of op.security || []) for (const k of Object.keys(req)) usedSchemes.add(k);
  }
  if (usedSchemes.size) {
    components.securitySchemes = {};
    for (const k of [...usedSchemes].sort()) components.securitySchemes[k] = full.components.securitySchemes[k];
  }
  const sortedPaths = Object.fromEntries(Object.keys(paths).sort().map((k) => [k, paths[k]]));
  return {
    openapi: full.openapi,
    info: {
      ...full.info,
      title: `${full.info.title} — Public API`,
      description: 'Public developer subset of the QODIQA HTTP contract, generated from docs/api/openapi.json and '
        + 'deploy/public-api/public-operations.json by scripts/openapi/public-subset.js. Administrative, operational and '
        + 'unversioned routes are not part of the public API.',
    },
    ...(full.servers ? { servers: full.servers } : {}),
    security: [],
    paths: sortedPaths,
    components,
  };
}

const serialize = (doc) => JSON.stringify(doc, null, 2) + '\n';

if (require.main === module) {
  const text = serialize(render());
  if (process.argv.includes('--check')) {
    const cur = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') : '';
    if (cur !== text) { console.error('openapi.public.json is stale — run: node scripts/openapi/public-subset.js'); process.exit(1); }
    console.log(`PASS: openapi.public.json matches (${Object.keys(JSON.parse(text).paths).length} paths)`);
  } else {
    fs.writeFileSync(OUT, text);
    console.log(`wrote ${path.relative(ROOT, OUT)}`);
  }
}

module.exports = { render, serialize, collectRefs };
