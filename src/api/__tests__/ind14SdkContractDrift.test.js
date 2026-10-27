'use strict';

/**
 * / API-02: both canonical SDKs classify an artifact rejection as
 * VerificationError — on chat.create() and chat.stream() alike, whatever status QODIQA_BLOCK_HTTP_MODE gives it. Their
 * reason lists must therefore equal the server's artifact-rejection classes in src/api/blockHttpStatus.js
 * (artifact_malformed, artifact_invalid, request_mismatch, replay). the SDKs knew 8 of these 26 reasons.
 *
 * The SDK sources are read as text (TypeScript and Python are not loadable here); the list literals are delimited by
 * their declarations.
 */

const fs = require('fs');
const path = require('path');
const { CLASSES } = require('../blockHttpStatus');

const ROOT = path.join(__dirname, '..', '..', '..');
const SERVER = new Set(['artifact_malformed', 'artifact_invalid', 'request_mismatch', 'replay'].flatMap((c) => CLASSES[c].reasons));

function literalsBetween(file, startRe, endRe) {
  const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
  const start = src.search(startRe);
  if (start < 0) throw new Error(`${file}: declaration not found`);
  const rest = src.slice(start);
  const end = rest.search(endRe);
  const body = rest.slice(0, end).replace(/(\/\/|#)[^\n]*/g, '');
  return new Set([...body.matchAll(/['"]([A-Z][A-Z0-9_]+)['"]/g)].map((m) => m[1]));
}

describe('SDK verification-reason lists == server artifact-rejection classes', () => {
  test('the server classes are non-trivial', () => {
    expect(SERVER.size).toBe(31); // 26 + the four protocol-V2 reasons + ARTIFACT_REVOKED
  });

  test('JS SDK VERIFICATION_REASONS', () => {
    const js = literalsBetween('sdk/javascript/src/errors.ts', /export const VERIFICATION_REASONS/, /\]\);/);
    expect([...js].sort()).toEqual([...SERVER].sort());
  });

  test('Python SDK VERIFICATION_REASONS', () => {
    const py = literalsBetween('sdk/python/qodiqa/exceptions.py', /^VERIFICATION_REASONS = frozenset\(/m, /^\)/m);
    expect([...py].sort()).toEqual([...SERVER].sort());
  });
});
