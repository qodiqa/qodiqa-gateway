'use strict';

/** the generated SDK operation tables are exactly what the contract produces (and the check notices when they are not). */

const fs = require('fs');
const crypto = require('crypto');
const { collect, genTs, genPy, genJson, SPEC, TS_OUT, PY_OUT, GO_OUT, JAVA_OUT, snake } = require('../generate-operations');
const path = require('path');

const raw = fs.readFileSync(SPEC, 'utf8');
const spec = JSON.parse(raw);
const hash = crypto.createHash('sha256').update(raw).digest('hex');
const norm = (s) => s.replace(/\r\n/g, '\n');

describe('SDK operation generator', () => {
  test('GO-01 the committed TypeScript and Python tables equal what docs/api/openapi.json generates', () => {
    const ops = collect(spec);
    expect(norm(fs.readFileSync(TS_OUT, 'utf8'))).toBe(norm(genTs(ops, hash)));
    expect(norm(fs.readFileSync(PY_OUT, 'utf8'))).toBe(norm(genPy(ops, hash)));
    expect(norm(fs.readFileSync(GO_OUT, 'utf8'))).toBe(norm(genJson(ops, hash)));
    expect(norm(fs.readFileSync(JAVA_OUT, 'utf8'))).toBe(norm(genJson(ops, hash)));
  });

  test('GO-04 the Go and Java modules carry byte-identical copies of the shared protocol vectors', () => {
    const repo = path.join(__dirname, '..', '..', '..');
    for (const [src, name] of [['docs/protocol/vectors/qodiqa-protocol-vectors.json', 'qodiqa-protocol-vectors.json'], ['test-vectors/artifact-v1.json', 'artifact-v1.json']]) {
      const want = fs.readFileSync(path.join(repo, src));
      expect(fs.readFileSync(path.join(repo, 'sdk', 'go', 'testdata', name)).equals(want)).toBe(true);
      expect(fs.readFileSync(path.join(repo, 'sdk', 'java', 'src', 'test', 'resources', 'vectors', name)).equals(want)).toBe(true);
    }
  });

  test('GO-02 negative control: a contract with one more operation produces different tables', () => {
    const changed = JSON.parse(raw);
    changed.paths['/__probe__'] = { get: { operationId: 'probeOperation', summary: 'probe', responses: { 200: { description: 'ok' } } } };
    const ops = collect(changed);
    expect(norm(genTs(ops, hash))).not.toBe(norm(fs.readFileSync(TS_OUT, 'utf8')));
    expect(norm(genPy(ops, hash))).not.toBe(norm(fs.readFileSync(PY_OUT, 'utf8')));
  });

  test('GO-03 an operation without operationId, a duplicate id and a python-name collision are refused', () => {
    const noId = JSON.parse(raw); noId.paths['/__x__'] = { get: { responses: { 200: { description: 'ok' } } } };
    expect(() => collect(noId)).toThrow(/no operationId/);
    const dup = JSON.parse(raw); const first = collect(spec)[0];
    dup.paths['/__y__'] = { get: { operationId: first.id, responses: { 200: { description: 'ok' } } } };
    expect(() => collect(dup)).toThrow(/duplicate operationId/);
    const coll = JSON.parse(raw); coll.paths['/__z__'] = { get: { operationId: 'a_b', responses: { 200: { description: 'ok' } } } }; coll.paths['/__w__'] = { get: { operationId: 'aB', responses: { 200: { description: 'ok' } } } };
    expect(snake('a_b')).toBe(snake('aB'));
    expect(() => collect(coll)).toThrow(/collision/);
  });
});
