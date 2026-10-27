'use strict';

/**
 * the protocol-V2 vector families (docs/protocol/vectors/v2-canon.json, v2-request.json) and their three implementations.
 *
 *   V2V-01  the committed files are exactly what the production implementation produces now (generator --check; receipt.json by gen-receipt-vectors.js)
 *   V2V-02  counts pinned (INDEX.json): a family cannot shrink silently; every rejection class of V2-FREEZE 2.7 that text can reach has a vector
 *   V2V-03  the Node independent verifier (no src/ imports) re-derives every case
 *   V2V-04  the Python independent verifier re-derives every case (skipped only when no python is installed)
 *   V2V-05  negative controls: a vector whose verdict is changed is rejected by both verifiers
 *   V2V-06  neither verifier imports production code
 *   V2V-07  differential fuzz of the canonicalizer: production == independent verifier, and an accepted value equals the V1 canonicalizer
 *   V2V-08  Python's ECMAScript number formatting == JavaScript's, over random doubles and the awkward ones
 *   V2V-09  differential fuzz of the request binding: production == independent verifier
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const fc = require('fast-check');

const REPO = path.join(__dirname, '..', '..', '..');
const DIR = path.join(REPO, 'docs', 'protocol', 'vectors');
const { parseJcsP1: prodParse, JcsError } = require('../../../src/validation/jcsP1');
const { computeRequestHashV2, buildDocument, BindingError } = require('../../../src/validation/requestBindingV2');
const { canonicalJcsP1 } = require('../../../src/validation/jcsP1');
const stableStringify = require('../../../src/utils/stableStringify');
const indep = require('../verify-v2-vectors');

jest.setTimeout(240_000);

const canonFile = JSON.parse(fs.readFileSync(path.join(DIR, 'v2-canon.json'), 'utf8'));
const requestFile = JSON.parse(fs.readFileSync(path.join(DIR, 'v2-request.json'), 'utf8'));
const receiptFile = JSON.parse(fs.readFileSync(path.join(DIR, 'receipt.json'), 'utf8'));
const index = JSON.parse(fs.readFileSync(path.join(DIR, 'INDEX.json'), 'utf8'));
const python = (() => { for (const exe of ['python', 'python3']) { const r = spawnSync(exe, ['-c', 'print(1)'], { encoding: 'utf8' }); if (r.status === 0) return exe; } return null; })();
const runPy = (args, input) => spawnSync(python, ['-I', ...args], { cwd: REPO, encoding: 'utf8', input, timeout: 200_000 });

describe('V2V — vector files', () => {
  test('V2V-01 committed vectors == production output (byte-identical)', () => {
    const r = spawnSync(process.execPath, ['scripts/protocol/gen-v2-vectors.js', '--check'], { cwd: REPO, encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout.split(/\r?\n/).find((l) => l.startsWith('{') && l.includes('"drift"')))).toEqual({ ok: true, drift: [] });
    const rc = spawnSync(process.execPath, ['scripts/protocol/gen-receipt-vectors.js', '--check'], { cwd: REPO, encoding: 'utf8' });
    expect(rc.status).toBe(0);
  });

  test('V2V-02 pinned counts and coverage of every rejection class', () => {
    expect(canonFile.cases.length).toBeGreaterThanOrEqual(107);
    expect(requestFile.cases.length).toBeGreaterThanOrEqual(113);
    expect(canonFile.cases.length + requestFile.cases.length).toBeGreaterThanOrEqual(40);       // the plan's floor
    expect(index.files['v2-canon.json']).toMatchObject({ family: 'v2-canon', cases: canonFile.cases.length });
    expect(index.files['v2-request.json']).toMatchObject({ family: 'v2-request', cases: requestFile.cases.length });
    expect(receiptFile.cases.length).toBeGreaterThanOrEqual(48);
    expect(index.files['receipt.json']).toMatchObject({ family: 'v2-receipt', cases: receiptFile.cases.length });
    const receiptCodes = new Set(receiptFile.cases.filter((c) => c.expectedError).map((c) => c.expectedError.code));
    for (const code of ['NOT_AN_OBJECT', 'FIELD_SET', 'UNSUPPORTED_VERSION', 'INVALID_FIELD', 'UNKNOWN_KEY', 'BAD_SIGNATURE', 'REVOKED_KEY']) expect({ code, covered: receiptCodes.has(code) }).toEqual({ code, covered: true });
    expect(receiptFile.cases.filter((c) => c.expected).length).toBeGreaterThanOrEqual(8);
    expect(index.files['qodiqa-protocol-vectors.json'].cases['requestBinding.hashes']).toBeGreaterThan(0);
    for (const f of [canonFile, requestFile, receiptFile]) {
      expect(new Set(f.cases.map((c) => c.id)).size).toBe(f.cases.length);                       // ids are unique and stable
      expect(f.cases.every((c) => (c.expected === undefined) !== (c.expectedError === undefined))).toBe(true);   // exactly one of expected / expectedError
    }
    const codes = new Set(canonFile.cases.filter((c) => c.expectedError).map((c) => c.expectedError.code));
    for (const code of ['INVALID_UTF8', 'INVALID_JSON', 'DUPLICATE_KEY', 'NON_FINITE_NUMBER', 'NUMBER_OUT_OF_RANGE', 'FORBIDDEN_KEY', 'STRING_NOT_NFC', 'LONE_SURROGATE', 'MAX_DEPTH_EXCEEDED', 'MAX_SIZE_EXCEEDED']) {
      expect({ code, covered: codes.has(code) }).toEqual({ code, covered: true });
    }
    const reqCodes = new Set(requestFile.cases.filter((c) => c.expectedError).map((c) => c.expectedError.code));
    expect([...reqCodes]).toEqual(['REQUEST_MISMATCH']);
  });
});

describe('V2V — independent verifiers', () => {
  test('V2V-03 the Node independent verifier re-derives every case', () => {
    for (const f of ['v2-canon.json', 'v2-request.json', 'receipt.json']) {
      const r = indep.verifyFile(path.join(DIR, f));
      expect({ f, failed: r.failed, failures: r.failures }).toEqual({ f, failed: 0, failures: [] });
    }
    const cli = spawnSync(process.execPath, ['scripts/protocol/verify-v2-vectors.js'], { cwd: REPO, encoding: 'utf8' });
    expect(cli.status).toBe(0);
  });

  (python ? test : test.skip)('V2V-04 the Python independent verifier re-derives every case', () => {
    const r = runPy(['scripts/protocol/verify_v2_vectors.py']);
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toMatchObject({ failed: 0, checks: canonFile.cases.length + requestFile.cases.length + receiptFile.cases.length });
  });

  test('V2V-05 negative controls: a changed verdict is rejected by both verifiers', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-v2v-'));
    try {
      const mutate = (file, fn) => { const o = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8')); fn(o); const p = path.join(tmp, file); fs.writeFileSync(p, JSON.stringify(o)); return p; };
      const canon = mutate('v2-canon.json', (o) => {
        const ok = o.cases.find((c) => c.expected && c.expected.value); ok.expected.value = ok.expected.value.replace(/.$/, (d) => (d === '0' ? '1' : '0'));
        const err = o.cases.find((c) => c.expectedError && c.expectedError.code === 'DUPLICATE_KEY'); err.expectedError.code = 'INVALID_JSON';
      });
      const request = mutate('v2-request.json', (o) => {
        const ok = o.cases.find((c) => c.expected); ok.expected.value = '0'.repeat(64);
        const err = o.cases.find((c) => c.expectedError && c.expectedError.detail === 'STRING_NOT_NFC'); err.expectedError.detail = 'LONE_SURROGATE';
        const refused = o.cases.find((c) => c.expectedError && !c.expectedError.detail); delete refused.expectedError; refused.expected = { outcome: 'ok', value: 'f'.repeat(64) };
      });
      const receipt = mutate('receipt.json', (o) => {
        const ok = o.cases.find((c) => c.expected); delete ok.expected; ok.expectedError = { code: 'BAD_SIGNATURE' };
        const bad = o.cases.find((c) => c.expectedError && c.expectedError.code === 'REVOKED_KEY'); bad.expectedError.code = 'BAD_SIGNATURE';
      });
      expect(indep.verifyFile(receipt).failed).toBe(2);
      expect(indep.verifyFile(canon).failed).toBe(2);
      expect(indep.verifyFile(request).failed).toBe(3);
      if (python) {
        const r = runPy(['scripts/protocol/verify_v2_vectors.py', canon, request, receipt]);
        expect(r.status).toBe(1);
        expect(JSON.parse(r.stdout).failed).toBe(7);
      }
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });

  test('V2V-06 neither verifier imports production code', () => {
    const js = fs.readFileSync(path.join(__dirname, '..', 'verify-v2-vectors.js'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    const required = [...js.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]).sort();
    expect(required).toEqual(['crypto', 'fs', 'path']);
    expect(/\bimport\s/.test(js)).toBe(false);
    const py = fs.readFileSync(path.join(__dirname, '..', 'verify_v2_vectors.py'), 'utf8');
    const imports = [...py.matchAll(/^\s*(?:import|from)\s+([A-Za-z0-9_.]+)/gm)].map((m) => m[1]).sort();
    expect(imports).toEqual(['base64', 'hashlib', 'json', 'os', 're', 'sys', 'unicodedata']);
  });
});

// ── differential fuzzing ─────────────────────────────────────────────────────────────────────────────────────────────
const outcomeProd = (bytes) => { try { return { ok: prodParse(bytes).canonical }; } catch (e) { if (e instanceof JcsError) return { err: e.code }; throw e; } };
const outcomeInd = (bytes) => { try { return { ok: indep.canonicalOf(bytes) }; } catch (e) { if (e instanceof indep.Refusal) return { err: e.code }; throw e; } };

// JSON text built from arbitrary values and then salted with the hazards of the profile
const HAZARDS = ['\\ud800', '\\udc00', 'e\\u0301', '__proto__', '1e999', '1e17', '9007199254740993', '\\u0000', '\\ud83d\\ude00', '-0', '0.1', '1e-7', 'é', 'é', '\u{1F600}', '￿'];
const textArb = fc.oneof(
  fc.jsonValue({ maxDepth: 5 }).map((v) => JSON.stringify(v)),
  fc.tuple(fc.jsonValue({ maxDepth: 3 }), fc.constantFrom(...HAZARDS), fc.constantFrom('value', 'key', 'raw', 'number')).map(([v, h, where]) => {
    const base = JSON.stringify(v);
    if (where === 'value') return `{"k":"${h}","z":${base}}`;
    if (where === 'key') return `{"${h}":1,"z":${base}}`;
    if (where === 'number') return `[${h.startsWith('-') || /^[0-9]/.test(h) ? h : '1'},${base}]`;
    return base.slice(0, Math.max(1, base.length - 1)) + h;
  }),
  fc.string({ unit: fc.constantFrom('{', '}', '[', ']', '"', ':', ',', '\\', 'u', '0', '1', 'e', '.', '-', ' ', 'a', 'n', 'l', 't', 'r', 'f', 's', 'é', '\u{1F600}', '\ud800') }),
);

describe('V2V — differential fuzz', () => {
  test('V2V-07 canonicalization: production == independent verifier; an accepted value is byte-identical to the V1 canonicalizer', () => {
    let accepted = 0; let refused = 0;
    fc.assert(fc.property(textArb, (text) => {
      const bytes = Buffer.from(text, 'utf8');
      const a = outcomeProd(bytes); const b = outcomeInd(bytes);
      expect(b).toEqual(a);
      if (a.ok !== undefined) {
        accepted++;
        const viaV1 = stableStringify(JSON.parse(text));
        expect(a.ok).toBe(viaV1);                       // V2-FREEZE 2: for every accepted input the output equals the V1 canonicalizer
        expect(outcomeProd(Buffer.from(a.ok, 'utf8')).ok).toBe(a.ok);   // canonical text re-parses to itself
      } else refused++;
    }), { numRuns: 1500, seed: 4091 });
    expect(accepted).toBeGreaterThan(100);
    expect(refused).toBeGreaterThan(100);
  });

  (python ? test : test.skip)('V2V-08 Python ECMAScript number text == JavaScript Number::toString', () => {
    const doubles = [5e-324, 2.2250738585072014e-308, 1e-7, 1.5e-7, 0.000001, 0.00001234, 0.1, 0.30000000000000004, 1 / 3, 100, 1e5, 123456789.125, 4503599627370495.5, 9007199254740991, -9007199254740991, 1e21 / 1e6, 0.5, 2 ** -30, -1e-300, 1e-300, 7.7e-5, 1234567890123456];
    fc.assert(fc.property(fc.array(fc.double({ noNaN: true, noDefaultInfinity: true }), { minLength: 50, maxLength: 50 }), (xs) => {
      for (const x of xs) if (Math.abs(x) <= 9007199254740991) doubles.push(x);
      return true;
    }), { numRuns: 60, seed: 9 });
    const usable = doubles.filter((x) => Number.isFinite(x));
    const hexOf = (x) => { const b = Buffer.alloc(8); b.writeDoubleBE(x); return b.toString('hex'); };
    const script = [
      'import sys, struct, json', 'sys.path.insert(0, "scripts/protocol")', 'import verify_v2_vectors as m',
      'xs = json.load(sys.stdin)', 'print(json.dumps([m.es_number(struct.unpack(">d", bytes.fromhex(h))[0]) for h in xs]))',
    ].join('\n');
    const r = spawnSync(python, ['-c', script], { cwd: REPO, encoding: 'utf8', input: JSON.stringify(usable.map(hexOf)) });
    expect(r.status).toBe(0);
    const py = JSON.parse(r.stdout);
    expect(py).toHaveLength(usable.length);
    usable.forEach((x, i) => expect({ x, text: py[i] }).toEqual({ x, text: Object.is(x, -0) || x === 0 ? '0' : String(x) }));
  });

  test('V2V-09 request binding: production == independent verifier, accepted or refused (same detail)', () => {
    const hexOfBuf = (b) => Buffer.from(b);
    const targetArb = fc.tuple(
      fc.constantFrom('/p', '/v1/ai/chat', '/a//b/../c/', '/caf%C3%A9', '/a%2fb', 'x', '', '*', '/a b', '/a#f'),
      fc.array(fc.constantFrom('a=1', 'b=2', 'a=2', 'a', '=v', 'k=%C3%A9', 'k=%e9', 'k=e%CC%81', 'k=%', 'k=%zz', 'k=b+c', 'k=1;2', '', 'q=%F0%9F%98%80', 'z=%00', 'n=%ED%A0%80'), { maxLength: 5 }),
      fc.constantFrom(true, false),
    ).map(([p, qs, hasQ]) => Buffer.from(hasQ ? `${p}?${qs.join('&')}` : p, 'utf8'));
    const methodArb = fc.constantFrom('POST', 'post', 'GET', 'Put', 'TRACE', 'POST ', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', '', 'CONNECT').map((m) => Buffer.from(m, 'utf8'));
    const headerArb = fc.array(fc.tuple(fc.constantFrom('x-a', 'X-A', 'x-b', 'x-zzz'), fc.constantFrom('v', ' v ', '', 'a, b', 'café', 'é', '\u{1F600}', '\t\tx\t')), { maxLength: 4 })
      .map((l) => l.map(([n, v]) => [Buffer.from(n, 'utf8'), Buffer.from(v, 'utf8')]));
    const bindArb = fc.constantFrom([], ['x-a'], ['x-a', 'x-b'], ['x-b', 'x-a'], ['x-a', 'x-a'], ['authorization'], ['constructor'], ['X-A']);
    const bodyArb = fc.oneof(
      fc.constant(null), fc.constant(Buffer.alloc(0)),
      textArb.map((t) => Buffer.from(t, 'utf8')),
      fc.jsonValue({ maxDepth: 3 }).map((v) => Buffer.from(JSON.stringify(v && typeof v === 'object' && !Array.isArray(v) ? v : { v }), 'utf8')),
    );
    let ok = 0; let refused = 0;
    fc.assert(fc.property(methodArb, targetArb, headerArb, bindArb, bodyArb, (method, target, headers, bind, body) => {
      const rawHeaders = []; for (const [n, v] of headers) rawHeaders.push(n.toString('latin1'), v.toString('latin1'));
      let prod;
      try { prod = { hash: computeRequestHashV2({ method: method.toString('latin1'), target: target.toString('latin1'), rawHeaders, body: body === null ? Buffer.alloc(0) : body }, bind) }; } catch (e) {
        if (!(e instanceof BindingError)) throw e;
        prod = { code: e.code, detail: e.jcsCode || null };
      }
      let other;
      try { other = { hash: indep.requestBinding({ method, target, headers, bind, body }).hash }; } catch (e) { if (!(e instanceof indep.Mismatch)) throw e; other = { code: e.code, detail: e.detail || null }; }
      expect(other).toEqual(prod);
      if (prod.hash) ok++; else refused++;
      void hexOfBuf; void buildDocument; void canonicalJcsP1;
    }), { numRuns: 1500, seed: 77 });
    expect(ok).toBeGreaterThan(50);
    expect(refused).toBeGreaterThan(50);
  });
});
