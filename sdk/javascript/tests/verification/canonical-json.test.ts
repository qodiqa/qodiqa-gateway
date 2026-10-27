import { stableStringify, CanonicalizationError } from '../../src/verification/canonicalJson.js';

describe('stableStringify', () => {
  test('sorts object keys lexicographically at every depth', () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(stableStringify({ z: { b: 1, a: 2 }, a: 1 })).toBe('{"a":1,"z":{"a":2,"b":1}}');
  });

  test('sorts keys in UTF-16 code unit order, not codepoint order', () => {
    // U+E000 (BMP, private-use area) vs an astral character U+1F600 (an emoji).
    // In UTF-16, U+1F600 is a surrogate pair starting with 0xD83D (in the
    // 0xD800-0xDBFF range), which sorts BELOW 0xE000 — the opposite of
    // codepoint order, where 0x1F600 > 0xE000.
    const bmp = '\uE000';
    const astral = '\u{1F600}';
    const result = stableStringify({ [astral]: 1, [bmp]: 2 });
    const astralKeyIndex = result.indexOf(JSON.stringify(astral));
    const bmpKeyIndex = result.indexOf(JSON.stringify(bmp));
    expect(astralKeyIndex).toBeLessThan(bmpKeyIndex);
  });

  test('produces zero whitespace', () => {
    expect(stableStringify({ a: [1, 2, 3], b: 'x' })).toBe('{"a":[1,2,3],"b":"x"}');
  });

  test('normalizes undefined to null', () => {
    expect(stableStringify({ a: undefined })).toBe(stableStringify({ a: null }));
  });

  test('preserves array order', () => {
    expect(stableStringify([3, 1, 2])).toBe('[3,1,2]');
  });

  test('escapes control characters like JSON.stringify', () => {
    expect(stableStringify('a\nb\tc"d\\e')).toBe(JSON.stringify('a\nb\tc"d\\e'));
    expect(stableStringify('\x01\x02')).toBe('"\\u0001\\u0002"');
  });

  test('does not escape non-ASCII characters', () => {
    expect(stableStringify('héllo')).toBe('"héllo"');
  });

  test.each([NaN, Infinity, -Infinity])('rejects non-finite number %p', (n) => {
    expect(() => stableStringify({ x: n })).toThrow(CanonicalizationError);
    try {
      stableStringify({ x: n });
    } catch (err) {
      expect((err as InstanceType<typeof CanonicalizationError>).code).toBe('NON_FINITE_NUMBER');
    }
  });

  test.each(['__proto__', 'constructor', 'prototype'])('rejects forbidden key "%s"', (key) => {
    expect(() => stableStringify({ [key]: 1 })).toThrow(CanonicalizationError);
  });

  test('rejects functions', () => {
    expect(() => stableStringify({ f: () => {} })).toThrow(CanonicalizationError);
  });

  test('rejects symbols', () => {
    expect(() => stableStringify({ s: Symbol('x') })).toThrow(CanonicalizationError);
  });

  test('rejects bigint', () => {
    expect(() => stableStringify({ n: BigInt(1) })).toThrow(CanonicalizationError);
  });

  test('rejects exotic objects (Date, RegExp, Map, Set)', () => {
    expect(() => stableStringify({ d: new Date() })).toThrow(CanonicalizationError);
    expect(() => stableStringify({ r: /x/ })).toThrow(CanonicalizationError);
    expect(() => stableStringify({ m: new Map() })).toThrow(CanonicalizationError);
    expect(() => stableStringify({ s: new Set() })).toThrow(CanonicalizationError);
  });

  test('rejects circular references', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    expect(() => stableStringify(obj)).toThrow(CanonicalizationError);
  });

  test('rejects pathologically deep nesting', () => {
    let deep: unknown = 1;
    for (let i = 0; i < 1005; i++) deep = { n: deep };
    expect(() => stableStringify(deep)).toThrow(CanonicalizationError);
  });

  test('accepts nesting within the depth guard', () => {
    let deep: unknown = 1;
    for (let i = 0; i < 500; i++) deep = { n: deep };
    expect(() => stableStringify(deep)).not.toThrow();
  });

  test('is byte-identical for a realistic artifact payload across repeated calls', () => {
    const payload = {
      tenantId: 'dev-local',
      requestId: 'e5d4b3de-dddb-43c6-b424-2f2f871d69d2',
      requestHash: '5c31ef9f6cc851294dd030131f482b052811e477b78a78c2dc77680cee419e7',
      policyHash: '0cd6ec4385a972e9dec9ca3582778d5f59c86b7eada72c2a34421e9c71120fe4',
    };
    const first = stableStringify(payload);
    const second = stableStringify({ ...payload });
    expect(first).toBe(second);
    expect(first).toBe(
      '{"policyHash":"0cd6ec4385a972e9dec9ca3582778d5f59c86b7eada72c2a34421e9c71120fe4","requestHash":"5c31ef9f6cc851294dd030131f482b052811e477b78a78c2dc77680cee419e7","requestId":"e5d4b3de-dddb-43c6-b424-2f2f871d69d2","tenantId":"dev-local"}',
    );
  });
});
