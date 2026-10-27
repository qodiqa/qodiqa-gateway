'use strict';

// step 5 — semantic drift guard. The boot validator decides, per semantic
// environment variable, whether production may set it (BOOT-RULES.md §4):
//   SEM_FORBIDDEN_IN_PROD  kill switches, classifier lists, thresholds, bands
//   SEM_GATE_DEFAULTS      gate switches — only their shipped default in prod
//   SEM_ALLOWED            tighten-only or performance-only knobs
// A NEW semantic variable added to the code without being classified here
// would be silently unguarded in production. This test scans the runtime
// source for every QODIQA_SEM*/QODIQA_SEMANTIC* name and fails on any that is
// not classified — and, the other way, on any classified name nothing reads
// (a stale entry that guards nothing).
//
// Read-only with respect to the semantic layer: it inspects source text and
// changes no threshold, anchor, classifier, model or behaviour.

const fs = require('fs');
const path = require('path');

const { SEM_FORBIDDEN_IN_PROD, SEM_GATE_DEFAULTS, SEM_ALLOWED, PROJECT_ROOT } = require('./bootValidator');

const RUNTIME_DIRS = ['src', 'services', 'server', 'middleware'];
const NAME = /QODIQA_SEM(?:ANTIC)?_[A-Z0-9_]*[A-Z0-9]\b/g;

function* runtimeFiles(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === '__tests__' || ent.name === 'node_modules') continue;
      yield* runtimeFiles(p);
    } else if (ent.name.endsWith('.js') && !ent.name.endsWith('.test.js')) {
      yield p;
    }
  }
}

function referencedNames() {
  const found = new Map();
  for (const d of RUNTIME_DIRS) {
    const root = path.join(PROJECT_ROOT, d);
    if (!fs.existsSync(root)) continue;
    for (const f of runtimeFiles(root)) {
      if (f === path.join(__dirname, 'bootValidator.js')) continue; // the classifier itself
      const text = fs.readFileSync(f, 'utf8');
      for (const m of text.matchAll(NAME)) {
        if (!found.has(m[0])) found.set(m[0], path.relative(PROJECT_ROOT, f));
      }
    }
  }
  return found;
}

const CLASSIFIED = new Set([...SEM_FORBIDDEN_IN_PROD, ...Object.keys(SEM_GATE_DEFAULTS), ...SEM_ALLOWED]);

describe('semantic environment variables — every one is classified for production', () => {
  const found = referencedNames();

  test('the scan actually sees the semantic layer (guards against a vacuous pass)', () => {
    expect(found.size).toBeGreaterThanOrEqual(40);
    expect(found.has('QODIQA_SEM_FT3_ENABLED')).toBe(true);
  });

  test('no referenced QODIQA_SEM*/QODIQA_SEMANTIC* name is unclassified', () => {
    const unclassified = [...found].filter(([n]) => !CLASSIFIED.has(n)).map(([n, f]) => `${n} (${f})`);
    expect(unclassified).toEqual([]);
  });

  test('no classified name is stale (every entry is read somewhere in runtime code)', () => {
    expect([...CLASSIFIED].filter((n) => !found.has(n))).toEqual([]);
  });

  test('the three classes are disjoint', () => {
    const lists = [SEM_FORBIDDEN_IN_PROD, Object.keys(SEM_GATE_DEFAULTS), SEM_ALLOWED];
    expect(lists.reduce((a, l) => a + l.length, 0)).toBe(CLASSIFIED.size);
  });
});
