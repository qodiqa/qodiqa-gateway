'use strict';

/**
 * the action-binding vectors (docs/protocol/vectors/action.json, ACTION-nnn).
 *
 *   AV-01  the committed file is exactly what the production implementation produces now
 *   AV-02  at least 30 cases; every rejection class of actionHash is covered; the order-independence and escape-equality pairs are really pairs
 *   AV-03  the independent Node verifier (no src/ imports) re-derives every case
 *   AV-04  the independent Python verifier re-derives every case (skipped only when no python is installed)
 *   AV-05  the production implementation agrees with the committed vectors case by case (hash AND error code)
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { computeActionHash, computeSchemaHash, ActionHashError } = require('../../../src/core/actions/actionHash');

const REPO = path.join(__dirname, '..', '..', '..');
const FILE = path.join(REPO, 'docs', 'protocol', 'vectors', 'action.json');
const v = JSON.parse(fs.readFileSync(FILE, 'utf8'));
const python = (() => { for (const exe of ['python', 'python3']) { const r = spawnSync(exe, ['-c', 'print(1)'], { encoding: 'utf8' }); if (r.status === 0) return exe; } return null; })();

describe('action vectors', () => {
  test('AV-01 the committed file is what the generator produces', () => {
    const r = spawnSync(process.execPath, ['scripts/protocol/gen-action-vectors.js', '--check'], { cwd: REPO, encoding: 'utf8' });
    expect(r.status).toBe(0);
  });

  test('AV-02 coverage and the paired cases', () => {
    expect(v.cases.length).toBeGreaterThanOrEqual(30);
    expect(new Set(v.cases.map((c) => c.id)).size).toBe(v.cases.length);
    const codes = new Set(v.cases.filter((c) => c.expectedError).map((c) => c.expectedError.code));
    for (const code of ['ACTION_INVALID_TENANT', 'ACTION_INVALID_AGENT', 'ACTION_INVALID_SESSION', 'ACTION_INVALID_SEQ', 'ACTION_INVALID_TOOL', 'ACTION_INVALID_ARGS', 'ACTION_INVALID_PARENT', 'ACTION_INVALID_PREV', 'ACTION_ARGS_NOT_CANONICALIZABLE', 'SCHEMA_INVALID']) expect(codes.has(code)).toBe(true);
    const jcs = new Set(v.cases.filter((c) => c.expectedError && c.expectedError.jcs).map((c) => c.expectedError.jcs));
    for (const j of ['STRING_NOT_NFC', 'NUMBER_OUT_OF_RANGE', 'LONE_SURROGATE', 'FORBIDDEN_KEY', 'MAX_DEPTH_EXCEEDED']) expect(jcs.has(j)).toBe(true);
    const by = (d) => v.cases.find((c) => c.description.startsWith(d));
    expect(by('a member name written with an escape').expected.actionHash).toBe(v.cases[0].expected.actionHash);
    expect(by('argument keys given unsorted').expected.actionHash).toBe(by('same members, other textual order').expected.actionHash);
    expect(by('member order does not matter').expected.schemaHash).toBe(by('object schema with properties and required').expected.schemaHash);
    const hashes = v.cases.filter((c) => c.kind === 'action' && c.expected).map((c) => c.expected.actionHash);
    expect(new Set(hashes).size).toBe(hashes.length - 2);                     // exactly the two documented coincidences
  });

  test('AV-03 the independent Node verifier agrees on every case', () => {
    const r = spawnSync(process.execPath, ['scripts/protocol/verify-action-vectors.js'], { cwd: REPO, encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ checks: v.cases.length, failed: 0 });
  });

  (python ? test : test.skip)('AV-04 the independent Python verifier agrees on every case', () => {
    const r = spawnSync(python, ['-I', 'scripts/protocol/verify_action_vectors.py'], { cwd: REPO, encoding: 'utf8', timeout: 120_000 });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ checks: v.cases.length, failed: 0 });
  });

  test('AV-05 production agrees with the vectors', () => {
    for (const c of v.cases) {
      let got;
      try {
        got = c.kind === 'schema' ? { schemaHash: computeSchemaHash(JSON.parse(c.input.schemaText)) }
          : { actionHash: computeActionHash({ ...c.input, args: JSON.parse(c.input.argsText) }) };
      } catch (e) { if (!(e instanceof ActionHashError)) throw e; got = { code: e.code, ...(e.cause && e.cause.code ? { jcs: e.cause.code } : {}) }; }
      if (c.expectedError) expect({ id: c.id, ...got }).toEqual({ id: c.id, ...c.expectedError });
      else expect({ id: c.id, ...got }).toEqual({ id: c.id, ...(c.kind === 'schema' ? { schemaHash: c.expected.schemaHash } : { actionHash: c.expected.actionHash }) });
    }
  });
});
