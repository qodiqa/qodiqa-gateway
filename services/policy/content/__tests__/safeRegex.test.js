'use strict';

/**
 * the linear-time regular-expression engine.
 *   SR-01  differential test against the built-in engine on the supported subset (patterns x inputs)
 *   SR-02  refused constructs and bounds
 *   SR-03  the ReDoS shapes cost what any pattern costs
 *   SR-04  case folding, anchors, unicode, classes
 */

const { compile, RegexError, MAX_INPUT } = require('../safeRegex');

const PATTERNS = ['abc', 'a.c', 'a*b', 'a+b', 'ab?c', '(ab)+c', '(a|b)c', 'a|b|c', '[abc]+d', '[^abc]d', '[a-f0-9]{3}', '\\d{3}-\\d{2}-\\d{4}', '\\w+@\\w+\\.com', '^abc', 'abc$', '^$', '^a*$', 'a{2,4}b', 'a{3,}', '(?:ab|cd)+e', 'x(a|b)*y', '[0-9]+(\\.[0-9]+)?', '\\s+end', '(a*)*b', '(a|aa)+b', '[a-c]{2}[d-f]{2}', 'foo.*bar', 'ba?r', '.', '..', 'a\\.b', '[.]', '\\\\', '(a+)+$', '[\\d\\s]+x'];
const INPUTS = ['', 'abc', 'xxabcxx', 'aaab', 'b', 'ab', 'abab c', 'cd', 'abcabcd', 'ffffabcdef', '123-45-6789', 'bob@mail.com', 'a.b', 'a\nb', 'aaaa', 'aaaaaaaaaaaaaaab', 'aaaaaaaaaaaaaaaa!', 'foo and bar', 'xaby', '12.5', 'word  end', 'ABC', '\\', 'ac', 'ad', 'bd', '12 x'];

describe('SR-01 differential against the built-in engine', () => {
  test('every supported pattern agrees with RegExp on every input (a yes/no answer)', () => {
    let checked = 0;
    for (const p of PATTERNS) {
      const mine = compile(p); const ref = new RegExp(p);
      for (const x of INPUTS) { expect({ p, x, got: mine.test(x) }).toEqual({ p, x, got: ref.test(x) }); checked++; }
    }
    expect(checked).toBe(PATTERNS.length * INPUTS.length);
  });
  test('random strings over a small alphabet agree too (the interesting cases are the near misses)', () => {
    let seed = 12345; const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
    const alpha = 'abc.-1 '; const gen = () => Array.from({ length: Math.floor(rnd() * 12) }, () => alpha[Math.floor(rnd() * alpha.length)]).join('');
    for (const p of ['(a|b)*c', 'a+b?c', '[ab]{2,3}c', '^(ab|a)c', 'a.c$', '(ab|b)+', 'c(a*)b']) {
      const mine = compile(p); const ref = new RegExp(p);
      for (let k = 0; k < 300; k++) { const x = gen(); expect({ p, x, got: mine.test(x) }).toEqual({ p, x, got: ref.test(x) }); }
    }
  });
});

describe('SR-02 refused constructs and bounds', () => {
  const bad = (p, re) => expect(() => compile(p)).toThrow(re || RegexError);
  test('lookaround, back-references, named groups, word boundaries, hex/unicode escapes, possessive quantifiers', () => {
    for (const p of ['a(?=b)', 'a(?!b)', '(?<=a)b', '(?<n>a)\\k<n>', '(a)\\1', '\\bword\\b', '\\x41', '\\u0041', '\\p{L}', 'a*+', '(?i)abc']) bad(p);
  });
  test('malformed patterns', () => { for (const p of ['', '(', ')', 'a)', '[abc', '*a', '+', '?', 'a{', 'a{2', 'a{3,2}', 'a{999}', '[z-a]', '\\']) bad(p); });
  test('size bounds: pattern length, state count after expansion, group nesting', () => {
    bad('a'.repeat(513), /longer than/);
    bad('(a{100}){100}', /states/);
    bad('((((((((((((((((((a))))))))))))))))))', /deeper/);
    expect(compile('a{100}').states).toBeLessThanOrEqual(500);
    expect(() => compile('x'.repeat(480))).not.toThrow();
  });
  test('text longer than the bound is refused, not silently skipped', () => {
    expect(() => compile('a').test('a'.repeat(MAX_INPUT + 1))).toThrow(/longer than/);
    expect(compile('a$').test('b'.repeat(MAX_INPUT - 1) + 'a')).toBe(true);
  });
});

describe('SR-03 no backtracking', () => {
  test('the classic ReDoS shapes on a hostile input finish in bounded time', () => {
    const hostile = 'a'.repeat(100_000) + '!';
    for (const p of ['(a+)+$', '(a|aa)+$', '(a*)*b', '(.*a){12}x', '([a-z]+)*\\d', '(a|a?)+b']) {
      const t0 = process.hrtime.bigint(); const r = compile(p).test(hostile); const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      expect({ p, r: typeof r }).toEqual({ p, r: 'boolean' }); expect(ms).toBeLessThan(5000);
    }
  });
  test('a pattern with many states on a long input stays bounded', () => {
    const p = '(' + Array.from({ length: 40 }, (_, i) => `x${i}y?`).join('|') + ')+z';
    const t0 = Date.now(); compile(p).test('x1y'.repeat(50_000)); expect(Date.now() - t0).toBeLessThan(8000);
  });
});

describe('SR-04 semantics', () => {
  test('case folding, anchors, classes, unicode', () => {
    expect(compile('HeLLo', { caseInsensitive: true }).test('say HELLO')).toBe(true); expect(compile('HeLLo').test('say HELLO')).toBe(false);
    expect(compile('[a-c]+', { caseInsensitive: true }).test('ZZBZZ')).toBe(true);
    expect(compile('^a').test('ba')).toBe(false); expect(compile('a$').test('ab')).toBe(false); expect(compile('^$').test('')).toBe(true); expect(compile('.').test('\n')).toBe(false);
    expect(compile('\\w+').test('é')).toBe(true); expect(compile('[é-ü]').test('ö')).toBe(true); expect(compile('.').test('😀')).toBe(true); expect(compile('^.$').test('😀')).toBe(true);
    expect(compile('\\d').test('٣')).toBe(false);                                               // \d is ASCII digits only, like the built-in engine without /u
  });
});
