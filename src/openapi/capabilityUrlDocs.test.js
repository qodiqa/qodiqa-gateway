'use strict';

/**
 * — the documented capability-URL contract cannot drift from the
 * generated HTTP contract.
 *
 * SECURITY.md ("Public capability URLs") lists every unauthenticated, identifier-addressed GET route. This test derives
 * the same set from docs/api/openapi.json (operations whose effective security admits an anonymous caller and whose
 * path carries a parameter), excludes the public-key discovery routes (documented separately as not capability URLs),
 * and requires the documented table to equal it exactly — a new public by-id route that is not documented, or a
 * documented one that no longer exists, fails here. (openapi.json itself is held equal to the live routes by
 * liveRouteParity / contract:check.)
 *
 *   CU-01 the documented table equals the contract's unauthenticated parameterized GET routes (minus key discovery)
 *   CU-02 every documented identifier is a UUID in the contract (the "122 random bits" claim)
 */

const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const spec = JSON.parse(fs.readFileSync(path.join(REPO, 'docs', 'api', 'openapi.json'), 'utf8'));
const security = fs.readFileSync(path.join(REPO, 'SECURITY.md'), 'utf8');

function anonymousParameterizedGets() {
  const out = [];
  for (const [p, ops] of Object.entries(spec.paths)) {
    const o = ops.get;
    if (!o || !/\{/.test(p)) continue;
    const sec = o.security !== undefined ? o.security : spec.security;
    const anon = !sec || sec.length === 0 || sec.some((x) => Object.keys(x).length === 0);
    if (anon) out.push(p);
  }
  return out;
}
function documented() {
  const m = security.match(/<!-- capability-urls:begin[^>]*-->([\s\S]*?)<!-- capability-urls:end -->/);
  if (!m) throw new Error('SECURITY.md has no capability-urls block');
  const paths = [];
  for (const line of m[1].split(/\r?\n/)) {
    if (!line.startsWith('| `')) continue;
    for (const c of line.split('|')[1].matchAll(/`([^`]+)`/g)) paths.push(c[1]);
  }
  return paths;
}

describe('capability URLs are documented exactly', () => {
  test('CU-01 the documented table equals the contract (minus public-key discovery)', () => {
    const contract = anonymousParameterizedGets().filter((p) => !p.startsWith('/.well-known/')).sort();
    expect(contract.length).toBeGreaterThan(10);
    expect(documented().sort()).toEqual(contract);
  });

  test('CU-02 every capability identifier is a UUID in the contract', () => {
    for (const p of documented()) {
      const resolve = (x) => (x && x.$ref ? x.$ref.split('/').slice(1).reduce((o, k) => o[k], spec) : x);
      const params = [...(spec.paths[p].parameters || []), ...(spec.paths[p].get.parameters || [])].map(resolve).filter((x) => x.in === 'path');
      expect(params.length).toBeGreaterThan(0);
      for (const x of params) expect(x.schema && x.schema.format).toBe('uuid');
    }
  });
});
