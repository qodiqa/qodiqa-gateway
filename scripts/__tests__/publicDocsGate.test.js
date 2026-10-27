'use strict';

/**
 * Public documentation gate.
 *
 *   PD-01 every count quoted in the public documents and in claims/claims.json equals scripts/inventory/count.js
 *   PD-02 the protocol version shown in the public documents equals the version of docs/protocol/vectors
 *   PD-03 the front-page documents contain none of the banned process words
 *   PD-04 no public document states a detection rate, a false-positive rate or an anchor count of the semantic layer
 *   PD-05 the negative controls: each rule catches a planted violation
 */
const fs = require('fs');
const path = require('path');
const { count } = require('../inventory/count');

const ROOT = path.join(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const exists = (p) => fs.existsSync(path.join(ROOT, p));

// Files that readers see first.
const PUBLIC_PAGES = ['README.md', 'SECURITY.md', 'docs/README.md', 'docs/overview.md', 'docs/limitations.md', 'docs/design-principles.md'];
const FRONT = PUBLIC_PAGES.filter(exists);
const COUNTED = [...FRONT, 'claims/claims.json', 'docs/api/REFERENCE.md', 'docs/guides/openapi-generation.md', 'docs/ROADMAP.md', 'docs/POLICY_TYPE_ENFORCEMENT.md', 'docs/deployment/persistence.md', 'docs/MIGRATION_LEDGER.md', 'docs/protocol/QODIQA-PROTOCOL.md'].filter(exists);

const BANNED_WORDS = /\b(high|pending|resolved|tested|campaign|remediation)\b/i;
const SEMANTIC_FIGURE = [
  /\b\d[\d.,]*\s*%\s*(of\s+)?(detection|detected|blocked|recall|precision|false[- ]positives?)\b/i,
  /\b(detection|recall|precision|false[- ]positive)\s+(rate\s+)?(of\s+)?\d[\d.,]*\s*%/i,
  /\b\d[\d,]*\s+(semantic\s+)?anchors?\b/i,
];

function countClaims(text, inv) {
  const bad = [];
  const rules = [
    [/(\d[\d,]*)\s+(?:documented\s+)?operations\b/gi, inv.openapi.operations, 'operations'],
    [/(\d[\d,]*)\s+metrics\b/gi, inv.metrics.total, 'metrics'],
    [/(\d[\d,]*)\s+tables\b/gi, inv.tables, 'tables'],
  ];
  for (const [re, want, label] of rules) {
    for (const m of text.matchAll(re)) {
      const got = Number(m[1].replace(/,/g, ''));
      // "369 operations" is the default build, which is counted separately
      if (got !== want && !(label === 'operations' && got === inv.routes.defaultBuild)) bad.push(`${m[0]} (counted ${want})`);
    }
  }
  return bad;
}

describe('public documentation gate', () => {
  const inv = count();

  test('PD-01 counts in public documents equal the counting script', () => {
    const bad = [];
    for (const f of COUNTED) for (const b of countClaims(read(f), inv)) bad.push(`${f}: ${b}`);
    expect(bad).toEqual([]);
  });

  test('PD-02 protocol version shown equals the vectors version', () => {
    const v = JSON.parse(read('docs/protocol/vectors/qodiqa-protocol-vectors.json')).version;
    const bad = [];
    for (const f of FRONT) for (const m of read(f).matchAll(/protocol \(V(\d+)\)/gi)) if (Number(m[1]) !== v) bad.push(`${f}: ${m[0]}`);
    expect(bad).toEqual([]);
  });

  test('PD-03 front-page documents contain no process words', () => {
    const bad = [];
    for (const f of FRONT) read(f).split(/\r?\n/).forEach((l, i) => { if (BANNED_WORDS.test(l)) bad.push(`${f}:${i + 1}: ${l.trim().slice(0, 80)}`); });
    expect(bad).toEqual([]);
  });

  test('PD-04 no semantic detection figures in public documents', () => {
    const bad = [];
    for (const f of [...COUNTED]) read(f).split(/\r?\n/).forEach((l, i) => { if (SEMANTIC_FIGURE.some((re) => re.test(l))) bad.push(`${f}:${i + 1}: ${l.trim().slice(0, 80)}`); });
    expect(bad).toEqual([]);
  });

  test('PD-05 negative controls', () => {
    expect(countClaims('The API has 999 operations and 5 metrics and 7 tables.', inv)).toHaveLength(3);
    expect(BANNED_WORDS.test('this is pending work')).toBe(true);
    expect(SEMANTIC_FIGURE.some((re) => re.test('a 88.3% detection rate'))).toBe(true);
    expect(SEMANTIC_FIGURE.some((re) => re.test('uses 65 anchors'))).toBe(true);
  });
});
