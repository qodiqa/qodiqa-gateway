'use strict';

/**
 * phase 17 — static guard: no test or test helper may give a test process (or a child it spawns) a route to
 * the LIVE PostgreSQL (127.0.0.1:5432) / Redis (6379) on the development machine through implicit `.env` inheritance.
 *
 * Rules (each with a planted negative control below, so a broken scanner cannot pass silently):
 *   R1  no `.env` LOADING in test code: `require('dotenv').config(...)`, `dotenv.config(...)`, `require('dotenv/config')`
 *       or `import 'dotenv/config'` (comments are ignored; `dotenv.parse()` of a file is inspection, not loading, and
 *       stays allowed — the isolation helpers use it to BLANK .env keys). Approved exceptions are listed with a reason.
 *   R2  a PostgreSQL suite (a test/ file that constructs a `pg` Pool/Client or initializes src/infra/postgres/pool)
 *       must be gated: `QODIQA_PG_ENABLED === 'true'` (unreachable locally without the opt-in — test/support/jest.setup.js forces it
 *       false otherwise, test/pgIsolationGuard.test.js), `QODIQA_ALLOW_PG_INTEGRATION_TESTS`, or the disposable-target
 *       helper `pgTarget()`. The opt-in in turn requires an explicit, non-LIVE target (test/support/jest.setup.js).
 *   R3  no literal LIVE-Redis fallback: `|| 'redis://localhost:6379'` / `'redis://127.0.0.1:6379'` (or without a port).
 *   R4  test/support/jest.setup.js keeps the wiring: it requires test/helpers/liveEndpointGuard, refuses an unsafe opt-in, blanks
 *       .env targets in the worker's real env, preloads the guard into NODE_OPTIONS and installs the socket guard.
 *
 * Scope: test/** (minus test/acceptance/.local — git-ignored operator scratch tools, never run by a gate — and
 * generated logs/evidence), every __tests__/ directory and *.test.js under src/ services/ scripts/ middleware/, and the
 * root jest.*.js files.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');

// R1 approved exceptions — each loads .env deliberately and safely.
const R1_APPROVED = {
  // Its probes require test/support/jest.setup.js FIRST and then call dotenv.config() in a child, to prove the guard defeats exactly
  // that load (the regression class). Fixture .env files only (QODIQA_TEST_DOTENV_PATH).
  'test/pgIsolationGuard.test.js': 'probe child proves test/support/jest.setup.js neutralises a later dotenv.config() (fixture .env)',
  // Structural assertion over server/startup.js's source: the call appears only inside a string/regex literal.
  'test/guards/deploymentModeStartupOrdering.structural.test.js': 'string literal in a source-order assertion, never executed',
  // This file: the planted negative-control strings below (never executed).
  'test/guards/testEnvIsolation.guard.test.js': 'planted negative-control strings',
};
// R3 approved exceptions.
const R3_APPROVED = {
  'test/guards/testEnvIsolation.guard.test.js': 'planted negative-control strings',
};
// R2 approved exceptions — construct a pg object that never reaches any server.
const R2_APPROVED = {
  'test/pgEndingPoolGuard.test.js': 'Pools pointed at 127.0.0.1:1; exercises teardown guards without connecting',
  // Its child script builds a pg.Client against the suite's OWN ephemeral listener (the guard's negative control).
  'test/liveEndpointGuard.test.js': 'pg.Client aimed only at the suite-owned listener on an ephemeral port',
};

const SKIP_DIRS = new Set(['node_modules', '.git', 'quarantine', '_quarantine', 'coverage']);

function walk(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return out; }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name) || e.name.startsWith('.stryker-tmp')) continue;
      walk(path.join(dir, e.name), out);
    } else if (/\.(c|m)?js$|\.ts$/.test(e.name)) out.push(path.join(dir, e.name));
  }
  return out;
}

function inScope(rel) {
  if (rel.startsWith('test/')) return !/^tests\/acceptance\/(\.local|logs|evidence)\//.test(rel);
  if (/^jest\.[^/]+\.js$/.test(rel)) return true;
  if (/^(src|services|scripts|middleware)\//.test(rel)) return /(^|\/)__tests__\//.test(rel) || /\.test\.(c|m)?[jt]s$/.test(rel);
  return false;
}

function scopedFiles() {
  const files = [];
  for (const top of ['test', 'src', 'services', 'scripts', 'middleware']) walk(path.join(REPO, top), files);
  for (const f of fs.readdirSync(REPO)) if (/^jest\.[^/]+\.js$/.test(f)) files.push(path.join(REPO, f));
  return files.map((f) => path.relative(REPO, f).split(path.sep).join('/')).filter(inScope).sort();
}

/**
 * Removes // and /* *\/ comments, leaving string, template and regex literals intact (a small tokenizer; good enough for
 * source scans — a regex literal is recognised by the usual "previous significant character" heuristic).
 */
function stripComments(src) {
  let out = ''; let i = 0; const n = src.length;
  const prevSignificant = () => { for (let j = out.length - 1; j >= 0; j--) if (!/\s/.test(out[j])) return out[j]; return ''; };
  while (i < n) {
    const c = src[i]; const d = src[i + 1];
    if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '/' && d === '*') { i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++; i += 2; continue; }
    if (c === '/' && (prevSignificant() === '' || '(,=:[!&|?{};+-*%<>~^'.includes(prevSignificant()) || /\b(return|typeof|case|in|of)$/.test(out.trimEnd()))) {
      let inClass = false; out += src[i++];
      while (i < n && src[i] !== '\n') {
        const ch = src[i];
        if (ch === '\\') { out += src[i++]; if (i < n) out += src[i++]; continue; }
        if (ch === '[') inClass = true; else if (ch === ']') inClass = false;
        out += src[i++];
        if (ch === '/' && !inClass) break;
      }
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const q = c; out += c; i++;
      while (i < n && src[i] !== q) { if (src[i] === '\\') { out += src[i++]; } if (i < n) out += src[i++]; }
      if (i < n) out += src[i++];
      continue;
    }
    out += c; i++;
  }
  return out;
}

const R1_RE = /require\(\s*['"]dotenv['"]\s*\)\s*\.\s*config\s*\(|\bdotenv\s*\.\s*config\s*\(|require\(\s*['"]dotenv\/config['"]\s*\)|import\s+['"]dotenv\/config['"]|from\s+['"]dotenv\/config['"]/;
const PG_CONSTRUCT_RE = /new\s+(?:pg\.)?(?:Pool|Client)\s*\(|\.initialize\s*\(/;
const PG_REQUIRE_RE = /require\(\s*['"]pg['"]\s*\)|require\(\s*['"][./]*(?:\.\.\/)*src\/infra\/postgres\/pool['"]\s*\)/;
const PG_GATE_RE = /QODIQA_PG_ENABLED\s*===\s*['"]true['"]|['"]true['"]\s*===\s*process\.env\.QODIQA_PG_ENABLED|QODIQA_ALLOW_PG_INTEGRATION_TESTS|\bpgTarget\s*\(/;
const R3_RE = /\|\|\s*['"`]redis:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::6379)?\/?['"`]/;

function isPgSuite(rel, code) {
  return rel.startsWith('test/') && /\.test\.(c|m)?js$/.test(rel) && !rel.startsWith('test/acceptance/')
    && PG_REQUIRE_RE.test(code) && PG_CONSTRUCT_RE.test(code);
}

/** @returns {string[]} the rule ids a source text violates (rel decides R2's test/-only scope). */
function violations(rel, src) {
  const code = stripComments(src);
  const v = [];
  if (R1_RE.test(code) && !R1_APPROVED[rel]) v.push('R1');
  if (isPgSuite(rel, code) && !PG_GATE_RE.test(code) && !R2_APPROVED[rel]) v.push('R2');
  if (R3_RE.test(code) && !R3_APPROVED[rel]) v.push('R3');
  return v;
}

describe('testEnvIsolation static guard — planted negative controls (the scanner itself)', () => {
  test.each([
    ['R1', "try { require('dotenv').config(); } catch (_) {}"],
    ['R1', "require( 'dotenv' ).config({ quiet: true });"],
    ['R1', "const dotenv = require('dotenv');\ndotenv.config();"],
    ['R1', "require('dotenv/config');"],
    ['R1', "import 'dotenv/config';"],
    ['R2', "const { Pool } = require('pg');\nconst p = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost' });"],
    ['R2', "const pool = require('../../src/infra/postgres/pool');\npool.initialize();"],
    ['R3', "const url = process.env.REDIS_URL || 'redis://localhost:6379';"],
    ['R3', 'probe(process.env.REDIS_URL || "redis://127.0.0.1");'],
  ])('flags %s in a planted file: %s', (rule, src) => {
    expect(violations('test/zzPlanted.integration.test.js', src)).toContain(rule);
  });

  test.each([
    ["// require('dotenv').config() used to be here\nconst x = 1;", 'a comment mentioning dotenv.config()'],
    ["/* dotenv.config() */ const y = require('dotenv').parse('A=1');", 'dotenv.parse (inspection, not loading)'],
    ["const { Pool } = require('pg');\nconst d = process.env.QODIQA_PG_ENABLED === 'true' ? describe : describe.skip;\nnew Pool({});", 'a gated PG suite'],
    ["const { pgTarget } = require('../helpers/disposableTargets');\nconst { Pool } = require('pg'); const t = pgTarget(); new Pool(t);", 'a pgTarget() suite'],
    ["const url = process.env.REDIS_URL; // never 'redis://localhost:6379'", 'no fallback'],
  ])('does not flag %s (%s)', (src) => {
    expect(violations('test/zzPlanted.integration.test.js', src)).toEqual([]);
  });

  test('planted FILE on disk is found by the same file walk and flagged (end-to-end scanner control)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-iso-plant-'));
    try {
      const f = path.join(dir, 'zzPlanted.integration.test.js');
      fs.writeFileSync(f, "try { require('dotenv').config(); } catch (_) {}\nconst { Client } = require('pg');\nnew Client({});\n");
      const found = walk(dir, []);
      expect(found).toEqual([f]);
      expect(violations('test/zzPlanted.integration.test.js', fs.readFileSync(f, 'utf8')).sort()).toEqual(['R1', 'R2']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('testEnvIsolation static guard — the real tree', () => {
  const files = scopedFiles();

  test('the scan covers the tree it claims to (sanity: known files are in scope, excluded ones are not)', () => {
    expect(files.length).toBeGreaterThan(500);
    for (const f of ['test/pgIsolationGuard.test.js', 'test/helpers/liveEndpointGuard.js', 'test/support/jest.setup.js',
      'test/integration/alertStoreDedup.integration.test.js', 'test/dr/postgresFullCoverage.integration.test.js']) expect(files).toContain(f);
    expect(files.some((f) => f.startsWith('test/acceptance/.local/'))).toBe(false);
    expect(files.some((f) => f.includes('node_modules/'))).toBe(false);
  });

  test('R2 really sees the PostgreSQL suites (a scanner that matched nothing would pass vacuously)', () => {
    const pg = files.filter((rel) => isPgSuite(rel, stripComments(fs.readFileSync(path.join(REPO, rel), 'utf8'))));
    expect(pg.length).toBeGreaterThanOrEqual(55);
    for (const f of ['test/integration/alertStoreDedup.integration.test.js', 'test/dr/postgresFullCoverage.integration.test.js',
      'test/logStoreRlsVisibility.test.js', 'test/integration/consumerConsistencyPg.integration.test.js']) expect(pg).toContain(f);
  });

  test('no test or helper loads .env, no PG suite lacks the opt-in gate, no literal LIVE-Redis fallback', () => {
    const bad = [];
    for (const rel of files) {
      const v = violations(rel, fs.readFileSync(path.join(REPO, rel), 'utf8'));
      if (v.length) bad.push(`${rel}: ${v.join(',')}`);
    }
    expect(bad).toEqual([]);
  });

  test('every approved exception still exists and still needs its exemption (no stale allow-list entries)', () => {
    for (const rel of Object.keys(R1_APPROVED)) expect([rel, R1_RE.test(stripComments(fs.readFileSync(path.join(REPO, rel), 'utf8')))]).toEqual([rel, true]);
    for (const rel of Object.keys(R3_APPROVED)) expect([rel, R3_RE.test(stripComments(fs.readFileSync(path.join(REPO, rel), 'utf8')))]).toEqual([rel, true]);
    for (const rel of Object.keys(R2_APPROVED)) expect([rel, PG_CONSTRUCT_RE.test(fs.readFileSync(path.join(REPO, rel), 'utf8'))]).toEqual([rel, true]);
  });

  test('R4: test/support/jest.setup.js keeps the LIVE-endpoint wiring', () => {
    const src = stripComments(fs.readFileSync(path.join(REPO, 'test/support/jest.setup.js'), 'utf8'));
    expect(src).toMatch(/require\('\.\.\/helpers\/liveEndpointGuard'\)/);
    expect(src).toMatch(/optInProblems\(process\.env\)/);
    expect(src).toMatch(/runInThisContext\('process'\)\.env/);
    expect(src).toMatch(/neutraliseDotenvTargets\(/);
    expect(src).toMatch(/withPreload\(/);
    expect(src).toMatch(/installSocketGuard\(\)/);
  });
});

module.exports = { violations, stripComments };
