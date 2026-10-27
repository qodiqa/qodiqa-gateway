'use strict';

// step 6: docs/configuration/boot-rules.md is GENERATED from the boot
// validator's own behaviour (scripts/config/generate-boot-rules-doc.js). If a
// rule, message, severity or guarded variable changes, this fails until the
// doc is regenerated — so the operator-facing rule table cannot drift.

const fs = require('fs');
const { generate, OUT, PROBES } = require('../../../scripts/config/generate-boot-rules-doc');

test('docs/configuration/boot-rules.md is byte-identical to a fresh generation', () => {
  const committed = fs.readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n');
  // On mismatch: node scripts/config/generate-boot-rules-doc.js
  expect(committed).toBe(generate());
});

test('every probe row produced a finding in at least one profile (no dead rows)', () => {
  const doc = generate();
  for (const [, cond] of PROBES) {
    const row = doc.split('\n').find((l) => l.startsWith(`| ${cond} |`));
    expect({ cond, row: Boolean(row) }).toEqual({ cond, row: true });
    expect({ cond, allDash: / \| — \| — \| — \| /.test(row) }).toEqual({ cond, allDash: false });
  }
});
