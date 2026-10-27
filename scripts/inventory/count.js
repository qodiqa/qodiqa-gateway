#!/usr/bin/env node
'use strict';

/**
 * Inventory counts: the single source for every figure quoted in the documentation and in claims/claims.json.
 *
 *   node scripts/inventory/count.js            print the counts as JSON
 *   node scripts/inventory/count.js --write    write docs/inventory.generated.json
 *   node scripts/inventory/count.js --check    exit 1 if docs/inventory.generated.json differs from a fresh count
 *
 * What is counted, and how (every method is a static scan or a read of a committed artifact, so the figures reproduce on any checkout):
 *   logEventTypes      distinct event names passed as the second argument of emit(LEVEL, 'NAME', ...) in non-test JavaScript under src, services, middleware, server, server.js
 *   envVariables       distinct upper-case environment variable names, reported two ways:
 *                      direct          process.env.NAME and process.env['NAME'] (src, services, middleware, enterprise, server, scripts, root entry files)
 *                      withHelpers     direct plus names passed as the first argument to env-reading helpers (envInt('NAME'), _bool('NAME'), ...) in files that read process.env[...] dynamically
 *   metrics            new Counter / Gauge / Histogram definitions in src/observability/metrics.js (by kind and total)
 *   openapiOperations  operations in docs/api/openapi.json (and paths)
 *   routes             documented operations plus the reviewed undocumented routes of the default build (src/openapi/routeExclusions.js)
 *   migrationFiles     .sql files in src/infra/postgres/migrations (first and last name)
 *   tables             distinct tables created by those migrations and not dropped by them
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const OUT = path.join(ROOT, 'docs', 'inventory.generated.json');
const SKIP = new Set(['node_modules', '.git', '__tests__', 'test', 'tests', 'evidence', 'eval', '_quarantine', 'PLAN', 'REMEDIERE', 'coverage', 'vendor', 'fixtures']);

function walk(dir, out) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name) || (e.isDirectory() && e.name.startsWith('.'))) continue;
    const f = path.join(dir, e.name);
    if (e.isDirectory()) walk(f, out);
    else if (e.name.endsWith('.js') && !/\.(test|spec)\.js$/.test(e.name)) out.push(f);
  }
  return out;
}
const read = (f) => fs.readFileSync(f, 'utf8');

function count() {
  const eventFiles = [];
  for (const d of ['src', 'services', 'middleware', 'server']) walk(path.join(ROOT, d), eventFiles);
  if (fs.existsSync(path.join(ROOT, 'server.js'))) eventFiles.push(path.join(ROOT, 'server.js'));
  const events = new Set();
  for (const f of eventFiles) {
    for (const m of read(f).matchAll(/\bemit\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([A-Z][A-Z0-9_]+)['"`]/g)) events.add(m[1]);
  }

  const envFiles = [];
  for (const d of ['src', 'services', 'middleware', 'enterprise', 'server', 'scripts']) walk(path.join(ROOT, d), envFiles);
  for (const f of ['start.js', 'server.js']) if (fs.existsSync(path.join(ROOT, f))) envFiles.push(path.join(ROOT, f));
  const direct = new Set();
  const helper = new Set();
  for (const f of envFiles) {
    const s = read(f);
    for (const m of s.matchAll(/process\.env\.([A-Z][A-Z0-9_]+)/g)) direct.add(m[1]);
    for (const m of s.matchAll(/process\.env\[\s*['"`]([A-Z][A-Z0-9_]+)['"`]\s*\]/g)) direct.add(m[1]);
    if (/process\.env\[/.test(s)) {
      for (const m of s.matchAll(/\b_?(?:env\w*|int|bool|num|str|read\w*)\(\s*['"`]([A-Z][A-Z0-9_]{2,})['"`]/gi)) helper.add(m[1]);
    }
  }
  const withHelpers = new Set([...direct, ...helper]);

  const metricsSrc = read(path.join(ROOT, 'src/observability/metrics.js'));
  const kinds = { counters: 0, gauges: 0, histograms: 0 };
  for (const m of metricsSrc.matchAll(/new (Counter|Gauge|Histogram)\(/g)) kinds[{ Counter: 'counters', Gauge: 'gauges', Histogram: 'histograms' }[m[1]]]++;

  const spec = JSON.parse(read(path.join(ROOT, 'docs/api/openapi.json')));
  let ops = 0;
  for (const p of Object.values(spec.paths)) for (const m of Object.keys(p)) if (['get', 'post', 'put', 'patch', 'delete', 'options', 'head'].includes(m)) ops++;
  const { KNOWN_UNDOCUMENTED } = require(path.join(ROOT, 'src/openapi/routeExclusions'));

  const migDir = path.join(ROOT, 'src/infra/postgres/migrations');
  const migs = fs.readdirSync(migDir).filter((f) => f.endsWith('.sql')).sort();
  const created = new Set();
  const dropped = new Set();
  for (const f of migs) {
    const s = read(path.join(migDir, f));
    for (const m of s.matchAll(/CREATE TABLE(?: IF NOT EXISTS)?\s+(?:public\.)?"?([a-z_0-9]+)"?/gi)) created.add(m[1].toLowerCase());
    for (const m of s.matchAll(/DROP TABLE(?: IF EXISTS)?\s+(?:public\.)?"?([a-z_0-9]+)"?/gi)) dropped.add(m[1].toLowerCase());
  }
  // 'list' is matched inside a comment of one migration, never a table
  const tables = [...created].filter((t) => !dropped.has(t) && t !== 'list');

  return {
    logEventTypes: events.size,
    envVariables: { direct: direct.size, withHelpers: withHelpers.size },
    metrics: { ...kinds, total: kinds.counters + kinds.gauges + kinds.histograms },
    openapi: { operations: ops, paths: Object.keys(spec.paths).length },
    routes: { documented: ops, reviewedUndocumented: KNOWN_UNDOCUMENTED.size, defaultBuild: ops + KNOWN_UNDOCUMENTED.size },
    migrations: { files: migs.length, first: migs[0], last: migs[migs.length - 1] },
    tables: tables.length,
  };
}

module.exports = { count, OUT };

if (require.main === module) {
  const fresh = count();
  const text = JSON.stringify(fresh, null, 2) + '\n';
  if (process.argv.includes('--write')) {
    fs.writeFileSync(OUT, text);
    console.log('wrote ' + path.relative(ROOT, OUT));
  } else if (process.argv.includes('--check')) {
    const committed = fs.existsSync(OUT) ? read(OUT).replace(/\r\n/g, '\n') : '';
    if (committed !== text) {
      console.error('inventory drift: docs/inventory.generated.json does not match a fresh count. Run `node scripts/inventory/count.js --write` and review.');
      console.error(text);
      process.exit(1);
    }
    console.log('inventory ok');
  } else {
    process.stdout.write(text);
  }
}
