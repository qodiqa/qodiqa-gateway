'use strict';

// AUTONOMOUS-2026-10-10: the public developer API allowlist (deploy/public-api/public-operations.json) may contain only
// operations that the generated contract itself marks as public (security empty, optional, or SigningApiKey only), and
// the public document generated from it must be in sync. An admin/ops operation can never be added by mistake.

const fs = require('fs');
const path = require('path');
const { render, serialize } = require('../openapi/public-subset');

const ROOT = path.resolve(__dirname, '..', '..');
const full = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'api', 'openapi.json'), 'utf8'));
const allow = JSON.parse(fs.readFileSync(path.join(ROOT, 'deploy', 'public-api', 'public-operations.json'), 'utf8'));

const effectiveSecurity = (op) => (op.security === undefined ? full.security : op.security);
const isPublic = (sec) => sec.length === 0 || sec.some((r) => Object.keys(r).length === 0)
  || sec.every((r) => Object.keys(r).every((k) => k === 'SigningApiKey'));
const ADMIN_PREFIXES = ['/rbac', '/key-admin', '/signing-identities', '/v1/admin', '/v1/policy', '/policy-ui', '/provenance',
  '/audit', '/evidence', '/v1/evidence', '/compliance', '/consent', '/alerts', '/dashboard', '/v1/webhooks', '/v1/prq',
  '/metrics', '/diagnostics', '/__bench', '/tenant-portal'];

describe('public API allowlist', () => {
  test('entries are unique and well-formed', () => {
    const keys = allow.operations.map((o) => `${o.method} ${o.path}`);
    expect(new Set(keys).size).toBe(keys.length);
    for (const o of allow.operations) {
      expect(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).toContain(o.method);
      expect(o.path.startsWith('/')).toBe(true);
    }
  });

  test('every entry exists in the generated contract and is public by its own security', () => {
    const bad = [];
    for (const { method, path: p } of allow.operations) {
      const op = full.paths[p] && full.paths[p][method.toLowerCase()];
      if (!op) { bad.push(`${method} ${p}: not in contract`); continue; }
      if (!isPublic(effectiveSecurity(op))) bad.push(`${method} ${p}: security ${JSON.stringify(effectiveSecurity(op))}`);
    }
    expect(bad).toEqual([]);
  });

  test('no entry sits under an administrative or operational prefix', () => {
    const hits = allow.operations.filter(({ path: p }) => ADMIN_PREFIXES.some((x) => p === x || p.startsWith(`${x}/`)));
    expect(hits).toEqual([]);
  });

  test('docs/api/openapi.public.json is the current render (regenerate with scripts/openapi/public-subset.js)', () => {
    const committed = fs.readFileSync(path.join(ROOT, 'docs', 'api', 'openapi.public.json'), 'utf8').replace(/\r\n/g, '\n');
    expect(committed).toBe(serialize(render()));
  });

  test('the public document exposes exactly the allowlist and no admin security scheme', () => {
    const doc = render();
    const ops = Object.entries(doc.paths).flatMap(([p, o]) => Object.keys(o).filter((m) => m !== 'parameters').map((m) => `${m.toUpperCase()} ${p}`));
    expect(ops.sort()).toEqual(allow.operations.map((o) => `${o.method} ${o.path}`).sort());
    expect(doc.security).toEqual([]);
    expect(Object.keys(doc.components.securitySchemes || {})).toEqual(['SigningApiKey']);
  });

  test('render refuses an allowlisted operation that the contract does not have', () => {
    expect(() => render(full, { operations: [{ method: 'GET', path: '/does-not-exist' }] })).toThrow(/not in the contract/);
  });
});
