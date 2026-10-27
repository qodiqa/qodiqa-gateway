'use strict';

/**
 * — the standalone external verifiers each carry their own
 * copy of the canonicalizer (they must stay dependency-free, so they cannot import the server's). Before this fix the
 * copies had drifted: tools/verify/verify.external.js / tools/verify/verify_external.py escaped only \\ " \n \r \t (so any other control
 * character canonicalized differently), Python sorted keys by code point and printed floats Python-style, and none
 * refused what the server refuses. This suite holds EVERY copy to the server's own canonicalizer
 * (src/utils/stableStringify.js), on the normative protocol vectors plus an adversarial corpus.
 *
 *   EC-01 the three JavaScript copies equal the server on every protocol vector and every adversarial input
 *   EC-02 the Python copy (tools/verify/verify_external.py) equals the server on the same inputs
 *   EC-03 the copies refuse what the server refuses (forbidden keys; non-finite numbers in JS)
 */

const path = require('path');
const { spawnSync } = require('child_process');
const server = require('../src/utils/stableStringify');
const vectors = require('../docs/protocol/vectors/qodiqa-protocol-vectors.json');

const REPO = path.join(__dirname, '..');
const COPIES = {
  'tools/verify/verify.external.js': require('../tools/verify/verify.external.js').stableStringify,
  'tools/verify/verify.bundle.external.js': require('../tools/verify/verify.bundle.external.js').stableStringify,
  'tools/verify/verify.evidence.external.js': require('../tools/verify/verify.evidence.external.js').stableStringify,
};

// Inputs are JSON texts (what a verifier actually receives), parsed the same way by every implementation.
const ADVERSARIAL = [
  '{"ctl":"\\u0000\\u0001\\u0007\\b\\f\\u000b\\u001f\\u007f"}',
  '{"lone":"\\ud800","pair":"\\ud83d\\ude00","tail":"\\udfff"}',
  '{"\\ud83d\\ude00":1,"\\uffff":2,"\\ue000":3,"a":4,"Z":5,"é":6}',
  '{"n":[1.0,1e-7,1e16,1e21,0.30000000000000004,-0,5e-324,1.7976931348623157e308,0.00001,1.5,-12.5e-9,1152921504606846976,123456789012345678901234]}',
  '{"esc":"quote\\" backslash\\\\ slash/ tab\\t nl\\n cr\\r","u2028":"\\u2028\\u2029","nbsp":"\\u00a0"}',
  '{"nested":{"b":[{"z":null,"a":true}],"a":{"y":false,"x":[]}},"empty":{},"arr":[[],{},"",0]}',
  '{"policyHash":"0198efcd800b44a52ca570d82e3409947aabcdc637a34f718e839ec1befe9b1f","requestId":"6f1e…","body":{"prompt":"Résumé ✓ 漢字 🙂"}}',
];
const INPUTS = [...vectors.canonicalization.valid.map((v) => JSON.stringify(v.input)), ...ADVERSARIAL];

describe('external verifier canonicalization == server canonicalization', () => {
  test('EC-01 every JavaScript copy equals the server on every input', () => {
    const diffs = [];
    for (const text of INPUTS) {
      const expected = server(JSON.parse(text));
      for (const [name, fn] of Object.entries(COPIES)) {
        const got = fn(JSON.parse(text));
        if (got !== expected) diffs.push({ copy: name, input: text, expected, got });
      }
    }
    expect(diffs).toEqual([]);
    // the vectors' own canonical forms are what the server produces (sanity: this suite tests the right thing)
    for (const v of vectors.canonicalization.valid) expect(server(v.input)).toBe(v.canonical);
  });

  test('EC-02 the Python copy equals the server on every input', () => {
    const driver = [
      'import importlib.util, json, sys',
      `spec = importlib.util.spec_from_file_location("v", ${JSON.stringify(path.join(REPO, 'tools/verify/verify_external.py'))})`,
      'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
      'for line in sys.stdin.buffer.read().decode("utf-8").splitlines():',
      '    sys.stdout.buffer.write((m.stable_stringify(json.loads(line)) + "\\n").encode("utf-8"))',
    ].join('\n');
    const r = spawnSync(process.platform === 'win32' ? 'python' : 'python3', ['-c', driver], { input: INPUTS.join('\n'), encoding: 'utf8' });
    expect(r.stderr).toBe('');
    const got = r.stdout.split('\n').filter((l, i, a) => i < a.length - 1 || l);
    const diffs = INPUTS.map((t, i) => ({ input: t, expected: server(JSON.parse(t)), got: got[i] })).filter((d) => d.expected !== d.got);
    expect(diffs).toEqual([]);
  });

  test('EC-03 the copies refuse what the server refuses', () => {
    for (const bad of ['{"__proto__":1}', '{"a":{"constructor":1}}', '{"prototype":[]}']) {
      expect(() => server(JSON.parse(bad))).toThrow(/forbidden/i);
      for (const fn of Object.values(COPIES)) expect(() => fn(JSON.parse(bad))).toThrow(/FORBIDDEN_KEY/);
    }
    for (const fn of Object.values(COPIES)) {
      expect(() => fn({ n: NaN })).toThrow(/NON_FINITE_NUMBER/);
      expect(() => fn({ d: new Date(0) })).toThrow(/UNSUPPORTED_TYPE/);
    }
  });
});
