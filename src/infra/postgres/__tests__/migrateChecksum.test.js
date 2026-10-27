'use strict';

/**
 * Coverage for migrate.js's _sha256() line-ending normalization.
 *
 * Migration files are committed to git as LF, but a checkout with
 * core.autocrlf=true (the common Windows default) rewrites them to CRLF on
 * disk. _sha256() normalizes CRLF/CR to LF before hashing so the integrity
 * check reflects logical SQL content, not the checkout's line-ending policy —
 * see migrate.js's file-header comment and the CRLF/LF normalization inside
 * _sha256() itself.
 *
 * This must cut both ways: normalizing away line-ending noise must not also
 * normalize away a genuine content edit — a single-character change to a
 * migration's SQL must still flip the checksum.
 */

const { _sha256 } = require('../migrate');

test('CRLF and LF renderings of identical SQL content hash the same', () => {
  const lf   = 'BEGIN;\nALTER TABLE audit_chain ADD COLUMN foo TEXT;\nCOMMIT;\n';
  const crlf = lf.replace(/\n/g, '\r\n');

  expect(_sha256(crlf)).toBe(_sha256(lf));
});

test('bare CR (old Mac-style) line endings also normalize to the same hash as LF', () => {
  const lf = 'BEGIN;\nALTER TABLE audit_chain ADD COLUMN foo TEXT;\nCOMMIT;\n';
  const cr = lf.replace(/\n/g, '\r');

  expect(_sha256(cr)).toBe(_sha256(lf));
});

test('a genuine one-character content edit still changes the checksum after normalization', () => {
  const original = 'BEGIN;\nALTER TABLE audit_chain ADD COLUMN foo TEXT;\nCOMMIT;\n';
  const edited   = 'BEGIN;\nALTER TABLE audit_chain ADD COLUMN bar TEXT;\nCOMMIT;\n';

  expect(_sha256(original)).not.toBe(_sha256(edited));

  // The same edit, expressed with CRLF line endings, must be caught too —
  // normalization must not mask a real change just because it arrives via a
  // CRLF checkout.
  expect(_sha256(original.replace(/\n/g, '\r\n')))
    .not.toBe(_sha256(edited.replace(/\n/g, '\r\n')));
});

test('every currently-applied migration file on disk, normalized, hashes deterministically', () => {
  const fs   = require('fs');
  const path = require('path');
  const dir  = path.join(__dirname, '..', 'migrations');
  const files = fs.readdirSync(dir).filter(f => /^\d+_.+\.sql$/.test(f));

  expect(files.length).toBeGreaterThan(0);

  for (const f of files) {
    const content = fs.readFileSync(path.join(dir, f), 'utf8');
    // Hashing twice must be stable (pure function, no hidden state).
    expect(_sha256(content)).toBe(_sha256(content));
  }
});
