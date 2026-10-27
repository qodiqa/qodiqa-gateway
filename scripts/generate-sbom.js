#!/usr/bin/env node
'use strict';

/**
 * SBOM Generation —
 *
 * Generates a CycloneDX-compatible Software Bill of Materials from
 * package-lock.json.  Outputs a JSON file conforming to CycloneDX schema
 * version 1.5.
 *
 * The SBOM includes:
 *   • Component name, version, PURL (Package URL)
 * • License (/ LIC-07: from package-lock.json's own `license` field — the lockfile is platform-independent,
 *     so the linux-only packages the image installs (e.g. LGPL-3.0 @img/sharp-libvips-linux-x64) are no longer
 *     blank when the SBOM is generated on Windows/macOS; falls back to the installed package.json). A compound
 *     SPDX expression ("Apache-2.0 AND LGPL-3.0-or-later") is emitted as a CycloneDX `expression`, a single id as
 *     `license.id`.
 *   • Integrity hash (from package-lock.json)
 *   • Scope (required / optional / excluded)
 *   • Component type (library)
 *
 * Usage:
 *   node scripts/generate-sbom.js [--output <path>]
 *
 * Options:
 *   --output <path>   Output file path (default: sbom.cdx.json)
 *   --prod-only       Omit devDependencies (default: include all)
 *
 * Environment:
 *   SBOM_OUTPUT       Override output path
 *   SBOM_PROD_ONLY    'true' to include production deps only
 *
 * The generated SBOM can be validated with:
 *   npx @cyclonedx/cyclonedx-cli validate --input-file sbom.cdx.json
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const ROOT      = path.resolve(__dirname, '..');
const LOCK_FILE = path.join(ROOT, 'package-lock.json');
const PKG_FILE  = path.join(ROOT, 'package.json');

const args      = process.argv.slice(2);
const outIdx    = args.indexOf('--output');
const prodOnly  = args.includes('--prod-only') || process.env.SBOM_PROD_ONLY === 'true';
const outputPath = outIdx >= 0
  ? path.resolve(args[outIdx + 1])
  : path.resolve(process.env.SBOM_OUTPUT || path.join(ROOT, 'sbom.cdx.json'));

// ── Load manifests ───────────────────────────────────────────────────────────
const lock = JSON.parse(fs.readFileSync(LOCK_FILE, 'utf8'));
const pkg  = JSON.parse(fs.readFileSync(PKG_FILE,  'utf8'));

if (!lock.packages) {
  console.error('package-lock.json does not contain a packages field (lockfileVersion < 2)');
  process.exit(1);
}

// ── Build component list ─────────────────────────────────────────────────────
const components = [];
const seen       = new Set();

for (const [pkgPath, meta] of Object.entries(lock.packages)) {
  if (pkgPath === '') continue; // skip root
  if (meta.dev && prodOnly) continue;

  // Extract canonical package name from the install path.
  // node_modules/@scope/name → @scope/name
  // node_modules/name         → name
  // / LIC-07: top-level entries have no leading '/' ('node_modules/x'), so a split on '/node_modules/' alone
  // left 325 of 354 names (and every purl) carrying the 'node_modules/' prefix.
  const rawName  = pkgPath.slice(pkgPath.lastIndexOf('node_modules/') + 'node_modules/'.length);
  const version  = meta.version || '0.0.0';
  const dedupKey = `${rawName}@${version}`;

  if (seen.has(dedupKey)) continue;
  seen.add(dedupKey);

  // Build PURL (Package URL per https://github.com/package-url/purl-spec)
  const purl = _buildPurl(rawName, version);

  // Parse integrity hash (sha512 preferred, sha1 fallback)
  const hashes = _parseIntegrity(meta.integrity || '');

  // Attempt to read license from package's own package.json
  const license = typeof meta.license === 'string' && meta.license ? meta.license : _readLicense(pkgPath);

  // Scope: what `npm ci --omit=dev` installs is 'required'; optional (platform/optional deps) and
  // dev-only entries are 'optional'. Previously only DIRECT dependencies were 'required' (11 of 354).
  const scope = (!meta.dev && !meta.optional && !meta.devOptional) ? 'required' : 'optional';

  components.push({
    type:         'library',
    'bom-ref':    `pkg:npm/${encodeURIComponent(rawName)}@${version}`,
    name:         rawName,
    version,
    purl,
    scope,
    hashes,
    licenses:     _licenses(license),
    externalReferences: [
      {
        type: 'distribution',
        url:  `https://registry.npmjs.org/${encodeURIComponent(rawName)}/-/${_tarballName(rawName, version)}`,
      },
    ],
  });
}

// ── Assemble CycloneDX document ──────────────────────────────────────────────
const sbom = {
  bomFormat:   'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${_uuid()}`,
  version:     1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools:     [{ vendor: 'QODIQA', name: 'generate-sbom', version: pkg.version || '0.0.0' }],
    component: {
      type:    'application',
      'bom-ref': `pkg:npm/${encodeURIComponent(pkg.name)}@${pkg.version || '0.0.0'}`,
      name:    pkg.name,
      version: pkg.version || '0.0.0',
    },
    properties: [
      { name: 'qodiqa:generatedBy',     value: `node ${process.version} on ${os.platform()}` },
      { name: 'qodiqa:prodOnly',        value: String(prodOnly) },
      { name: 'qodiqa:lockfileVersion', value: String(lock.lockfileVersion) },
    ],
  },
  components,
};

fs.writeFileSync(outputPath, JSON.stringify(sbom, null, 2) + '\n', 'utf8');

const stats = {
  total:      components.length,
  required:   components.filter(c => c.scope === 'required').length,
  optional:   components.filter(c => c.scope === 'optional').length,
  withHashes: components.filter(c => c.hashes.length > 0).length,
  withLicense: components.filter(c => c.licenses.length > 0).length,
};

console.log(`SBOM generated: ${outputPath}`);
console.log(`  Components : ${stats.total}`);
console.log(`  Required   : ${stats.required}`);
console.log(`  Optional   : ${stats.optional}`);
console.log(`  With hash  : ${stats.withHashes}`);
console.log(`  With license: ${stats.withLicense}`);

// ── Helpers ──────────────────────────────────────────────────────────────────

function _buildPurl(name, version) {
  if (name.startsWith('@')) {
    const [scope, pkgName] = name.split('/');
    return `pkg:npm/${encodeURIComponent(scope)}/${encodeURIComponent(pkgName)}@${version}`;
  }
  return `pkg:npm/${encodeURIComponent(name)}@${version}`;
}

function _parseIntegrity(integrity) {
  if (!integrity) return [];
  return integrity.split(' ').map(s => {
    const [alg, b64] = s.split('-');
    if (!alg || !b64) return null;
    // CycloneDX uses 'SHA-512' / 'SHA-1'
    const algMap = { sha512: 'SHA-512', sha384: 'SHA-384', sha256: 'SHA-256', sha1: 'SHA-1' };
    const cdxAlg = algMap[alg.toLowerCase()];
    if (!cdxAlg) return null;
    const hex = Buffer.from(b64, 'base64').toString('hex');
    return { alg: cdxAlg, content: hex };
  }).filter(Boolean);
}

function _licenses(spdx) {
  if (!spdx) return [];
  const s = String(spdx).trim();
  if (/\s(AND|OR|WITH)\s|^\(/.test(s)) return [{ expression: s }];
  return [{ license: { id: s } }];
}

function _readLicense(pkgPath) {
  const manifestPath = path.join(ROOT, pkgPath, 'package.json');
  try {
    const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (typeof m.license === 'string') return m.license;
    // legacy array form, e.g. tv4: [{ type: 'Public Domain' }, { type: 'MIT' }] → an OR expression of its SPDX ids
    const arr = Array.isArray(m.licenses) ? m.licenses : (Array.isArray(m.license) ? m.license : null);
    if (arr) { const ids = arr.map((l) => (l && (l.type || l.name)) || '').filter((t) => /^[A-Za-z0-9.+-]+$/.test(t)); if (ids.length) return ids.length > 1 ? `(${ids.join(' OR ')})` : ids[0]; }
    return null;
  } catch {
    return null;
  }
}

function _tarballName(name, version) {
  const base = name.startsWith('@') ? name.split('/')[1] : name;
  return `${base}-${version}.tgz`;
}

function _uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}
