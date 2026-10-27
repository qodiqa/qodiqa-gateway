'use strict';

/**
 * the domain-separation tag registry, DERIVED FROM THE SOURCE (never hand-maintained).
 *
 * Scans src/ and services/ (production code; tests excluded) for every string literal of the form QODIQA::…::V<n>
 * and returns one row per distinct tag with every location that defines it, plus the ARTIFACT_DOMAINS constant name
 * when the tag is one of src/infra/crypto/hashing.js's registered domains. Consumed by the protocol vector generator
 * and by the generated registry section of docs/protocol/QODIQA-PROTOCOL.md, so a tag added, renamed or removed in
 * code changes both — and the drift checks fail until they are regenerated and reviewed.
 */

const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const ROOTS = ['src', 'services'];
const TAG_RE = /(['"`])(QODIQA::[A-Z0-9_:]+::V\d+)\1/g;

function* files(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!/^(node_modules|__tests__|\.stryker-tmp)$/.test(e.name)) yield* files(p); }
    else if (e.name.endsWith('.js') && !e.name.endsWith('.test.js')) yield p;
  }
}

function registry() {
  const { ARTIFACT_DOMAINS } = require(path.join(REPO, 'src', 'infra', 'crypto', 'hashing'));
  const byValue = Object.fromEntries(Object.entries(ARTIFACT_DOMAINS).map(([k, v]) => [v, k]));
  const tags = new Map();
  for (const root of ROOTS) {
    for (const f of files(path.join(REPO, root))) {
      const lines = fs.readFileSync(f, 'utf8').split(/\r?\n/);
      lines.forEach((l, i) => {
        if (/^\s*(\/\/|\*)/.test(l)) return;   // comments mention tags; only code defines them
        for (const m of l.matchAll(TAG_RE)) {
          const rel = `${path.relative(REPO, f).split(path.sep).join('/')}:${i + 1}`;
          if (!tags.has(m[2])) tags.set(m[2], []);
          tags.get(m[2]).push(rel);
        }
      });
    }
  }
  return [...tags.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([tag, locations]) => ({ tag, constant: byValue[tag] || null, locations: locations.sort() }));
}

module.exports = { registry };
