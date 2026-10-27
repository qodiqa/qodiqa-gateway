#!/usr/bin/env node
'use strict';

/**
 * Supply Chain Security Verification — / 46.8
 *
 * Verifies the integrity of the Node.js dependency supply chain.
 * Run as part of CI and before production deployments.
 *
 * Checks:
 *   1. package-lock.json is present and has lockfileVersion >= 2
 *   2. All resolved packages have a non-empty `integrity` (SRI) hash
 *   3. No packages with `bundleDependencies` that could shadow verified deps
 *   4. No packages that require lifecycle scripts (preinstall/install/postinstall)
 *      unless explicitly allowed in ALLOWED_SCRIPTED_PACKAGES
 *   5. npm audit exits clean (no HIGH or CRITICAL vulnerabilities)
 *   6. No duplicate major versions of security-critical packages
 *
 * Exit codes:
 *   0 — all checks passed
 *   1 — one or more checks failed
 *
 * Environment:
 *   SUPPLY_CHAIN_FAIL_ON_WARN=true  — treat warnings as failures (default false)
 *   NPM_AUDIT_LEVEL=high            — minimum severity to fail on (default 'high')
 */

const fs           = require('fs');
const path         = require('path');
const { execSync } = require('child_process');

const ROOT      = path.resolve(__dirname, '..');
const LOCK_FILE = path.join(ROOT, 'package-lock.json');
const PKG_FILE  = path.join(ROOT, 'package.json');

const FAIL_ON_WARN  = process.env.SUPPLY_CHAIN_FAIL_ON_WARN === 'true';
const AUDIT_LEVEL   = process.env.NPM_AUDIT_LEVEL || 'high';

// Packages allowed to have lifecycle scripts (typically native addons).
// All other lifecycle-scripted packages are flagged as a supply chain risk.
const ALLOWED_SCRIPTED_PACKAGES = new Set([
  // node-gyp-based native addons that are direct or transitive dependencies
  // of production packages are assessed individually.  Add package names here
  // only after reviewing the script content.
  // Example: 'bcrypt'
]);

// Security-critical packages where multiple major versions indicate a risk
// of the wrong version being loaded at runtime.
const CRITICAL_SINGLE_VERSION = [
  'helmet',
  'cors',
  'express',
  'jsonwebtoken',
  'bcrypt',
  'argon2',
  'zod',
];

let _failures = 0;
let _warnings = 0;

function fail(msg) { console.error(`[FAIL] ${msg}`); _failures++; }
function warn(msg) {
  if (FAIL_ON_WARN) { fail(msg); }
  else { console.warn(`[WARN] ${msg}`); _warnings++; }
}
function ok(msg) { console.log(`[ OK ] ${msg}`); }

// ── Check 1: lock file exists and is v2+ ─────────────────────────────────────
console.log('\n=== Supply Chain Check 1: lock file ===');
if (!fs.existsSync(LOCK_FILE)) {
  fail('package-lock.json not found.  Run npm install to generate it.');
  process.exit(1);
}

let lock;
try {
  lock = JSON.parse(fs.readFileSync(LOCK_FILE, 'utf8'));
} catch (e) {
  fail(`Failed to parse package-lock.json: ${e.message}`);
  process.exit(1);
}

if (!lock.lockfileVersion || lock.lockfileVersion < 2) {
  fail(`package-lock.json lockfileVersion is ${lock.lockfileVersion}.  Requires >= 2 for integrity hashes.`);
} else {
  ok(`lockfileVersion: ${lock.lockfileVersion}`);
}

// ── Check 2: all packages have integrity hashes ───────────────────────────────
console.log('\n=== Supply Chain Check 2: integrity hashes ===');
const packages = lock.packages || {};
let missingIntegrity = 0;
for (const [pkgPath, pkgMeta] of Object.entries(packages)) {
  if (pkgPath === '') continue; // root package
  if (!pkgMeta.integrity) {
    warn(`Missing integrity hash: ${pkgPath}`);
    missingIntegrity++;
  }
}
if (missingIntegrity === 0) {
  ok(`All ${Object.keys(packages).length - 1} packages have integrity hashes`);
}

// ── Check 3: bundleDependencies ──────────────────────────────────────────────
console.log('\n=== Supply Chain Check 3: bundleDependencies ===');
let bundled = 0;
for (const [pkgPath, pkgMeta] of Object.entries(packages)) {
  if (pkgPath === '') continue;
  if (pkgMeta.bundleDependencies && pkgMeta.bundleDependencies.length > 0) {
    warn(`bundleDependencies present in ${pkgPath}: ${pkgMeta.bundleDependencies.join(', ')}`);
    bundled++;
  }
}
if (bundled === 0) ok('No packages with bundleDependencies');

// ── Check 4: lifecycle scripts ────────────────────────────────────────────────
console.log('\n=== Supply Chain Check 4: lifecycle scripts ===');
let scriptedCount = 0;
for (const [pkgPath, pkgMeta] of Object.entries(packages)) {
  if (pkgPath === '') continue;
  const scripts = pkgMeta.scripts || {};
  const dangerous = ['preinstall', 'install', 'postinstall'].filter(s => s in scripts);
  if (dangerous.length > 0) {
    const name = pkgPath.replace(/^node_modules\//, '').split('/node_modules/').pop();
    if (!ALLOWED_SCRIPTED_PACKAGES.has(name)) {
      warn(`Lifecycle scripts [${dangerous.join(', ')}] in ${pkgPath} — review for supply chain risk`);
      scriptedCount++;
    }
  }
}
if (scriptedCount === 0) ok('No unexpected lifecycle scripts found');

// ── Check 5: npm audit ────────────────────────────────────────────────────────
console.log('\n=== Supply Chain Check 5: npm audit ===');
{
  // the audit gate applies the documented exceptions in security/audit-exceptions.json
  const gate = require('child_process').spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'audit-gate.js')], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, AUDIT_LEVEL } });
  if (gate.status === 0) ok((gate.stdout || '').trim().split('\n').pop());
  else fail(((gate.stderr || '') + (gate.stdout || '')).trim().split('\n').slice(-3).join(' | ') || 'npm audit gate failed');
}

// ── Check 6: critical package single-version assertion ───────────────────────
console.log('\n=== Supply Chain Check 6: critical package versions ===');
const pkg = JSON.parse(fs.readFileSync(PKG_FILE, 'utf8'));
const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

for (const critPkg of CRITICAL_SINGLE_VERSION) {
  if (!(critPkg in allDeps)) continue;
  const locations = Object.keys(packages)
    .filter(p => {
      const parts = p.split('/node_modules/');
      return parts[parts.length - 1] === critPkg;
    });
  if (locations.length > 1) {
    warn(`Critical package '${critPkg}' installed at ${locations.length} locations — version conflict risk`);
  } else if (locations.length === 1) {
    ok(`${critPkg}: single installation`);
  }
}

// ── Summary ──────────────────────────────────────────────────────────────────
console.log('\n=== Supply Chain Verification Summary ===');
console.log(`  Failures : ${_failures}`);
console.log(`  Warnings : ${_warnings}${FAIL_ON_WARN ? ' (treated as failures)' : ''}`);

if (_failures > 0) {
  console.error('\nSupply chain verification FAILED.');
  process.exit(1);
} else if (_warnings > 0) {
  console.warn('\nSupply chain verification passed with warnings.  Review above.');
  process.exit(0);
} else {
  console.log('\nSupply chain verification PASSED.');
  process.exit(0);
}
