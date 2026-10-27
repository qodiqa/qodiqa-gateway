'use strict';

const { sanitizeCsvCell } = require('../csvSanitize');

describe('INJ-7 — sanitizeCsvCell', () => {
  test('prefixes a leading "=" with a single quote', () => {
    expect(sanitizeCsvCell('=SUM(A1:A10)')).toBe('"\'=SUM(A1:A10)"');
  });

  test('prefixes a leading "+" with a single quote', () => {
    expect(sanitizeCsvCell('+1+1')).toBe('"\'+1+1"');
  });

  test('prefixes a leading "-" with a single quote', () => {
    expect(sanitizeCsvCell('-1+1')).toBe('"\'-1+1"');
  });

  test('prefixes a leading "@" with a single quote', () => {
    expect(sanitizeCsvCell('@SUM(1,1)')).toBe('"\'@SUM(1,1)"');
  });

  test('prefixes a leading tab or CR', () => {
    expect(sanitizeCsvCell('\t=1+1')).toBe('"\'\t=1+1"');
    expect(sanitizeCsvCell('\r=1+1')).toBe('"\'\r=1+1"');
  });

  test('a classic DDE/exec payload is neutralized', () => {
    const payload = '=cmd|\' /C calc\'!A0';
    const result = sanitizeCsvCell(payload);
    expect(result.startsWith('"\'=')).toBe(true);
  });

  test('ordinary text is unaffected beyond standard quoting', () => {
    expect(sanitizeCsvCell('hello world')).toBe('"hello world"');
  });

  test('a value with "=" NOT in leading position is untouched', () => {
    expect(sanitizeCsvCell('a=b')).toBe('"a=b"');
  });

  test('still applies standard double-quote escaping after the formula prefix', () => {
    expect(sanitizeCsvCell('=A"B')).toBe('"\'=A""B"');
  });

  test('null and undefined become an empty quoted cell', () => {
    expect(sanitizeCsvCell(null)).toBe('');
    expect(sanitizeCsvCell(undefined)).toBe('');
  });

  test('numbers and other non-string values are stringified first', () => {
    expect(sanitizeCsvCell(42)).toBe('"42"');
    expect(sanitizeCsvCell(true)).toBe('"true"');
  });
});
