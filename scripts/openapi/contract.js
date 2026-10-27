#!/usr/bin/env node
'use strict';

/**
 * the committed OpenAPI contract (docs/api/openapi.json) and its drift check.
 *
 *   node scripts/openapi/contract.js            write docs/api/openapi.json from the generator
 *   node scripts/openapi/contract.js --check    regenerate in memory and diff against the committed file; exit 1 on ANY
 *                                               difference (prints the operations added/removed and the first differing
 *                                               JSON pointers). Exit 0 means the diff is empty.
 *
 * The spec comes from src/openapi/generator.js generateSpec({ fresh: true }) — deterministic (no env, time or random
 * input) — serialised with the generator's own JSON writer plus a trailing newline. Which operations exist is pinned to
 * the LIVE application by src/openapi/liveRouteParity.test.js; this script pins the full document (operations,
 * parameters, schemas, responses) so any change to the API description shows up as a reviewable diff.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const REPO = path.join(__dirname, '..', '..');
const CONTRACT = path.join(REPO, 'docs', 'api', 'openapi.json');

function render() {
  const { generateSpec } = require(path.join(REPO, 'src', 'openapi', 'generator'));
  return `${JSON.stringify(generateSpec({ fresh: true }), null, 2)}\n`;
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const ops = (doc) => Object.entries(doc.paths || {}).flatMap(([p, item]) => Object.keys(item).filter((m) => /^(get|post|put|patch|delete|options|head)$/.test(m)).map((m) => `${m} ${p}`));

function diffPointers(a, b, ptr = '', out = [], limit = 20) {
  if (out.length >= limit) return out;
  if (typeof a !== typeof b || Array.isArray(a) !== Array.isArray(b) || a === null || b === null || typeof a !== 'object') {
    if (JSON.stringify(a) !== JSON.stringify(b)) out.push(ptr || '/');
    return out;
  }
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])];
  for (const k of keys) diffPointers(a[k], b[k], `${ptr}/${String(k).replace(/~/g, '~0').replace(/\//g, '~1')}`, out, limit);
  return out;
}

function check(file = CONTRACT) {
  const generated = render();
  if (!fs.existsSync(file)) return { ok: false, reason: `missing ${path.relative(REPO, file)}`, generatedSha256: sha(generated) };
  const committed = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
  if (committed === generated) return { ok: true, sha256: sha(generated), operations: ops(JSON.parse(generated)).length, bytes: Buffer.byteLength(generated) };
  const g = JSON.parse(generated); const c = JSON.parse(committed);
  const go = new Set(ops(g)); const co = new Set(ops(c));
  return { ok: false, committedSha256: sha(committed), generatedSha256: sha(generated),
    operationsAdded: [...go].filter((o) => !co.has(o)), operationsRemoved: [...co].filter((o) => !go.has(o)), firstDifferences: diffPointers(c, g) };
}

if (require.main === module) {
  if (process.argv.includes('--check')) {
    const r = check();
    process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
    if (!r.ok) process.stderr.write('[openapi-contract] DRIFT: docs/api/openapi.json differs from the generated spec. Run `npm run openapi:generate`, review the diff, and commit it.\n');
    process.exit(r.ok ? 0 : 1);
  }
  const out = render();
  fs.mkdirSync(path.dirname(CONTRACT), { recursive: true });
  fs.writeFileSync(CONTRACT, out);
  process.stdout.write(`${JSON.stringify({ wrote: path.relative(REPO, CONTRACT).split(path.sep).join('/'), sha256: sha(out), operations: ops(JSON.parse(out)).length, bytes: Buffer.byteLength(out) })}\n`);
}

module.exports = { render, check, CONTRACT };
