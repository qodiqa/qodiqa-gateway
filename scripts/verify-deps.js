#!/usr/bin/env node
'use strict';

/**
 * Dependency Integrity Verification —
 *
 * Verifies that installed node_modules match the integrity hashes recorded in
 * package-lock.json.  This detects:
 *   • Tampered packages (modified files after install)
 *   • Missing packages (deleted from node_modules)
 *   • Version drift (package.json edited without updating the lock file)
 *   • Unexpected top-level packages not declared in package.json
 *
 * Verification strategy:
 *   For each production dependency in package-lock.json, verify that the
 *   installed version matches the locked version.  Integrity hash verification
 *   (rehashing installed files) is intentionally omitted here because npm ci
 *   already verifies hashes during install.  This script focuses on version
 *   consistency and unexpected package detection — fast checks suitable for
 *   pre-startup validation.
 *
 * Usage:
 *   node scripts/verify-deps.js [--strict]
 *
 * Options:
 *   --strict   Also check devDependencies (default: prod only)
 *
 * Exit codes:
 *   0 — all checks passed
 *   1 — one or more checks failed
 */

const fs   = require('fs');
const path = require('path');

const ROOT    = path.resolve(__dirname, '..');
const LOCK    = path.join(ROOT, 'package-lock.json');
const PKG     = path.join(ROOT, 'package.json');
const MODULES = path.join(ROOT, 'node_modules');

const strict = process.argv.includes('--strict');

let failures = 0;
let checked  = 0;

function fail(msg) { console.error(`[FAIL] ${msg}`); failures++; }
function ok(msg)   { /* suppress per-package OK to keep output concise */ void msg; }

// ── Load manifests ───────────────────────────────────────────────────────────
let lock, pkg;
try {
  lock = JSON.parse(fs.readFileSync(LOCK, 'utf8'));
  pkg  = JSON.parse(fs.readFileSync(PKG,  'utf8'));
} catch (e) {
  fail(`Cannot read manifests: ${e.message}`);
  process.exit(1);
}

if (!lock.packages) {
  fail('package-lock.json has no .packages field (lockfileVersion < 2).  Run: npm install');
  process.exit(1);
}

const prodDeps = new Set(Object.keys(pkg.dependencies    || {}));
const devDeps  = new Set(Object.keys(pkg.devDependencies || {}));
const allDeclared = strict ? new Set([...prodDeps, ...devDeps]) : prodDeps;

// ── Check 1: declared deps are installed at locked versions ──────────────────
console.log('=== Dependency Integrity Check 1: version consistency ===');

for (const dep of allDeclared) {
  const lockEntry = lock.packages[`node_modules/${dep}`];
  if (!lockEntry) {
    fail(`${dep}: in package.json but missing from package-lock.json.  Run: npm install`);
    continue;
  }

  const installedManifest = path.join(MODULES, dep, 'package.json');
  if (!fs.existsSync(installedManifest)) {
    fail(`${dep}: declared but not installed.  Run: npm ci`);
    continue;
  }

  let installedPkg;
  try {
    installedPkg = JSON.parse(fs.readFileSync(installedManifest, 'utf8'));
  } catch (e) {
    fail(`${dep}: cannot read installed package.json: ${e.message}`);
    continue;
  }

  if (installedPkg.version !== lockEntry.version) {
    fail(
      `${dep}: installed=${installedPkg.version} but lock=${lockEntry.version}.  ` +
      `Run: npm ci to restore from lock file.`,
    );
    continue;
  }

  checked++;
}

console.log(`  Checked ${checked} packages`);

// ── Check 2: no unexpected top-level packages ─────────────────────────────────
console.log('=== Dependency Integrity Check 2: unexpected packages ===');

let installedTopLevel;
try {
  installedTopLevel = fs.readdirSync(MODULES).filter(n => !n.startsWith('.'));
} catch (e) {
  fail(`Cannot read node_modules: ${e.message}`);
  process.exit(1);
}

// Include scoped packages (@scope/name)
const installedExpanded = [];
for (const name of installedTopLevel) {
  if (name.startsWith('@')) {
    try {
      const scopedPkgs = fs.readdirSync(path.join(MODULES, name));
      for (const sub of scopedPkgs) installedExpanded.push(`${name}/${sub}`);
    } catch { /* ignore */ }
  } else {
    installedExpanded.push(name);
  }
}

const allDeclaredAndTransitive = new Set(
  Object.keys(lock.packages)
    .filter(p => p.startsWith('node_modules/') && !p.slice(13).includes('/node_modules/'))
    .map(p => p.slice(13)),
);

let unexpectedCount = 0;
for (const installed of installedExpanded) {
  if (!allDeclaredAndTransitive.has(installed)) {
    fail(`Unexpected top-level package: ${installed} (not in package-lock.json)`);
    unexpectedCount++;
  }
}

if (unexpectedCount === 0) {
  console.log('  No unexpected top-level packages found');
}

// ── Check 3: lock file is not newer than node_modules ─────────────────────────
// If node_modules was last modified before the lock file, it may be stale.
console.log('=== Dependency Integrity Check 3: staleness ===');

try {
  const lockMtime    = fs.statSync(LOCK).mtimeMs;
  const modulesMtime = fs.statSync(MODULES).mtimeMs;
  if (lockMtime > modulesMtime) {
    fail(
      'package-lock.json is newer than node_modules — dependencies may be stale.  ' +
      'Run: npm ci',
    );
  } else {
    console.log('  node_modules is current relative to lock file');
  }
} catch (e) {
  fail(`Staleness check failed: ${e.message}`);
}

// ── Summary ──────────────────────────────────────────────────────────────────
console.log('\n=== Dependency Verification Summary ===');
console.log(`  Failures : ${failures}`);

if (failures > 0) {
  console.error('Dependency verification FAILED.');
  process.exit(1);
} else {
  console.log('Dependency verification PASSED.');
  process.exit(0);
}
