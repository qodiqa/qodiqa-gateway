'use strict';

/**
 * JCS-P1 (docs/protocol/PROTOCOL-V2.md section 2): strict parsing, number range, NFC, duplicate keys, depth/size, error precedence,
 * and byte-identity with the V1 canonicalizer for every accepted value.
 */

const { parseJcsP1, canonicalJcsP1, JcsError, ERROR_ORDER } = require('../jcsP1');
const stableStringify = require('../../utils/stableStringify');

const code = (fn) => { try { fn(); return null; } catch (e) { if (e instanceof JcsError) return e.code; throw e; } };
const parse = (t) => parseJcsP1(t).canonical;

describe('accepted values', () => {
  test.each([
    ['{"b":1,"a":[true,false,null]}', '{"a":[true,false,null],"b":1}'],
    ['  { "a" : 1 }  ', '{"a":1}'],
    ['[]', '[]'], ['{}', '{}'], ['[[]]', '[[]]'],
    ['1.0', '1'], ['1e0', '1'], ['1E+0', '1'], ['-0', '0'], ['-0.0', '0'], ['0.7', '0.7'], ['0.000001', '0.000001'], ['1e-7', '1e-7'],
    ['9007199254740991', '9007199254740991'], ['-9007199254740991', '-9007199254740991'], ['1e-300', '1e-300'], ['4.5', '4.5'],
    ['"\\u00e9"', '"é"'], ['"\\ud83d\\ude00"', '"😀"'], ['"a\\/b"', '"a/b"'], ['"\\b\\f\\n\\r\\t"', '"\\b\\f\\n\\r\\t"'],
  ])('F4-JCS-01 %s', (text, canonical) => { expect(parse(text)).toBe(canonical); });

  test('F4-JCS-02 keys are sorted by UTF-16 code units (an astral key sorts before U+FFFF)', () => {
    expect(parse('{"\\uffff":1,"\\ud83d\\ude00":2}')).toBe('{"😀":2,"￿":1}');
  });

  test('F4-JCS-03 output equals the V1 canonicalizer for accepted values', () => {
    const samples = ['{"z":{"b":[1,2.5,{"y":null}],"a":"x"},"n":-7,"s":"Ünï"}', '[0.1,0.2,1e-7,123456789012345,"a\\"b"]', '{"a":{"b":{"c":[]}}}'];
    for (const t of samples) expect(parse(t)).toBe(stableStringify(JSON.parse(t)));
  });
});

describe('rejections', () => {
  test.each([
    ['{"a":1,"a":2}', 'DUPLICATE_KEY'],
    ['{"a":1,"b":{"c":1,"c":2}}', 'DUPLICATE_KEY'],
    ['1e999', 'NON_FINITE_NUMBER'],
    ['9007199254740992', 'NUMBER_OUT_OF_RANGE'], ['9007199254740993', 'NUMBER_OUT_OF_RANGE'], ['1e17', 'NUMBER_OUT_OF_RANGE'],
    ['9007199254740992.0', 'NUMBER_OUT_OF_RANGE'], ['9007199254740991.5', 'NUMBER_OUT_OF_RANGE'], ['1e300', 'NUMBER_OUT_OF_RANGE'], ['-9007199254740993', 'NUMBER_OUT_OF_RANGE'],
    ['{"__proto__":1}', 'FORBIDDEN_KEY'], ['{"constructor":1}', 'FORBIDDEN_KEY'], ['{"prototype":1}', 'FORBIDDEN_KEY'],
    ['"e\\u0301"', 'STRING_NOT_NFC'], ['{"e\\u0301":1}', 'STRING_NOT_NFC'],
    ['"\\ud800"', 'LONE_SURROGATE'], ['"\\udc00"', 'LONE_SURROGATE'], ['{"\\ud800":1}', 'LONE_SURROGATE'],
    ['', 'INVALID_JSON'], ['{', 'INVALID_JSON'], ['[1,]', 'INVALID_JSON'], ['{"a":1,}', 'INVALID_JSON'], ['01', 'INVALID_JSON'], ['+1', 'INVALID_JSON'],
    ['.5', 'INVALID_JSON'], ['1.', 'INVALID_JSON'], ["{'a':1}", 'INVALID_JSON'], ['"a\nb"', 'INVALID_JSON'], ['"\\x"', 'INVALID_JSON'], ['NaN', 'INVALID_JSON'], ['1 2', 'INVALID_JSON'],
    ['   ', 'INVALID_JSON'],
  ])('F4-JCS-04 %j -> %s', (text, expected) => { expect(code(() => parseJcsP1(text))).toBe(expected); });

  test('F4-JCS-05 bytes: invalid UTF-8 and a BOM are INVALID_UTF8; a BOM string too', () => {
    expect(code(() => parseJcsP1(Buffer.from([0x22, 0xff, 0x22])))).toBe('INVALID_UTF8');
    expect(code(() => parseJcsP1(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])))).toBe('INVALID_UTF8');
    expect(code(() => parseJcsP1('﻿{}'))).toBe('INVALID_UTF8');
    expect(parseJcsP1(Buffer.from('{"é":1}', 'utf8')).canonical).toBe('{"é":1}');
  });

  test('F4-JCS-06 depth: 64 levels pass, 65 fail; empty containers have depth 1', () => {
    const nest = (n) => '['.repeat(n) + ']'.repeat(n);
    expect(code(() => parseJcsP1(nest(64)))).toBeNull();
    expect(code(() => parseJcsP1(nest(65)))).toBe('MAX_DEPTH_EXCEEDED');
    expect(code(() => parseJcsP1('[]'))).toBeNull();
  });

  test('F4-JCS-07 size is measured on the canonical bytes', () => {
    const big = JSON.stringify({ a: 'x'.repeat(2000) });
    expect(code(() => parseJcsP1(big, { maxBytes: 1000 }))).toBe('MAX_SIZE_EXCEEDED');
    expect(code(() => parseJcsP1(big, { maxBytes: 4000 }))).toBeNull();
  });

  test('F4-JCS-08 error precedence follows V2-FREEZE 2.7', () => {
    // duplicate key + out-of-range number: DUPLICATE_KEY ranks first
    expect(code(() => parseJcsP1('{"a":1e17,"a":2}'))).toBe('DUPLICATE_KEY');
    // out-of-range number + non-NFC string: NUMBER_OUT_OF_RANGE first
    expect(code(() => parseJcsP1('["e\\u0301",1e17]'))).toBe('NUMBER_OUT_OF_RANGE');
    // non-NFC + lone surrogate: STRING_NOT_NFC first
    expect(code(() => parseJcsP1('["e\\u0301","\\ud800"]'))).toBe('STRING_NOT_NFC');
    // a syntax error anywhere beats every other violation
    expect(code(() => parseJcsP1('{"a":1,"a":2,'))).toBe('INVALID_JSON');
    expect(ERROR_ORDER[0]).toBe('INVALID_UTF8');
  });

  test('F4-JCS-09 programmatic values: undefined / functions / dates / non-finite / unsafe numbers', () => {
    expect(code(() => canonicalJcsP1({ a: undefined }))).toBe('UNSUPPORTED_TYPE');
    expect(code(() => canonicalJcsP1({ a: () => 1 }))).toBe('UNSUPPORTED_TYPE');
    expect(code(() => canonicalJcsP1({ a: new Date() }))).toBe('UNSUPPORTED_TYPE');
    expect(code(() => canonicalJcsP1({ a: 10n }))).toBe('UNSUPPORTED_TYPE');
    expect(code(() => canonicalJcsP1({ a: NaN }))).toBe('NON_FINITE_NUMBER');
    expect(code(() => canonicalJcsP1({ a: Infinity }))).toBe('NON_FINITE_NUMBER');
    expect(code(() => canonicalJcsP1({ a: 2 ** 53 }))).toBe('NUMBER_OUT_OF_RANGE');
    expect(canonicalJcsP1({ a: -0 })).toBe('{"a":0}');
    expect(canonicalJcsP1({ b: [1, 'x'], a: null })).toBe('{"a":null,"b":[1,"x"]}');
  });

  test('F4-JCS-10 the host JSON.parse hazard cannot change the result (own parser)', () => {
    // one Node release line mis-parses a key after a backslash-containing key; the strict parser is independent of it
    const out = parseJcsP1('{"z\\\\":1}').value;
    expect(Object.keys(out)).toEqual(['z\\']);
    const out2 = parseJcsP1('{"z\\"":1}').value;
    expect(Object.keys(out2)).toEqual(['z"']);
  });
});
