'use strict';

const { sanitizeFilename, safeAttachmentHeader } = require('../contentDisposition');

describe('INJ-8 — sanitizeFilename / safeAttachmentHeader', () => {
  test('strips CRLF that would otherwise inject additional header lines', () => {
    const malicious = 'evil\r\nX-Injected: true';
    expect(sanitizeFilename(malicious)).toBe('evilX-Injected: true');
    expect(safeAttachmentHeader(malicious)).not.toMatch(/\r|\n/);
  });

  test('strips a lone CR or LF', () => {
    expect(sanitizeFilename('a\rb')).toBe('ab');
    expect(sanitizeFilename('a\nb')).toBe('ab');
  });

  test('strips embedded NUL bytes', () => {
    expect(sanitizeFilename('a\x00b')).toBe('ab');
  });

  test('escapes embedded double quotes so they cannot terminate the filename parameter early', () => {
    const malicious = 'evil"; evil-param="x';
    expect(sanitizeFilename(malicious)).toBe('evil\\"; evil-param=\\"x');
  });

  test('safeAttachmentHeader produces a well-formed attachment header for an ordinary filename', () => {
    expect(safeAttachmentHeader('report.csv')).toBe('attachment; filename="report.csv"');
  });

  test('safeAttachmentHeader neutralizes a crafted policyId-style route param', () => {
    const crafted = 'abc"\r\nSet-Cookie: session=hijacked';
    const header = safeAttachmentHeader(crafted);
    expect(header).not.toMatch(/\r|\n/);
    expect(header).toBe('attachment; filename="abc\\"Set-Cookie: session=hijacked"');
  });

  test('null/undefined become an empty filename, not "null"/"undefined"', () => {
    expect(sanitizeFilename(null)).toBe('');
    expect(sanitizeFilename(undefined)).toBe('');
  });
});

describe('safeAttachmentHeader — RFC 6266 compliance', () => {
  test('CRLF injection attempt produces a single header with no split', () => {
    const header = safeAttachmentHeader('report\r\nSet-Cookie: x=1.pdf');
    expect(header).not.toMatch(/\r|\n/);
    expect(header.split('\n')).toHaveLength(1);
    expect(header).toBe('attachment; filename="reportSet-Cookie: x=1.pdf"');
  });

  test('quote-escape attempt is escaped, not left able to terminate the parameter', () => {
    const header = safeAttachmentHeader('a".pdf');
    expect(header).toBe('attachment; filename="a\\".pdf"');
  });

  test('backslash in filename is escaped so it cannot un-escape the following quote', () => {
    const header = safeAttachmentHeader('a\\".pdf');
    expect(header).toBe('attachment; filename="a\\\\\\".pdf"');
  });

  test('non-ASCII filename gets an ASCII fallback plus a correctly percent-encoded filename*', () => {
    const header = safeAttachmentHeader('raport-ș.pdf');
    expect(header).toBe(
      'attachment; filename="raport-_.pdf"; filename*=UTF-8\'\'raport-%C8%99.pdf'
    );
    const extValue = header.match(/filename\*=UTF-8''([^;]+)/)[1];
    expect(decodeURIComponent(extValue)).toBe('raport-ș.pdf');
  });

  test('empty string filename falls back to a deterministic safe default, no crash', () => {
    expect(safeAttachmentHeader('')).toBe('attachment; filename="download"');
  });

  test('absent (undefined/null) filename falls back to the same deterministic default', () => {
    expect(safeAttachmentHeader(undefined)).toBe('attachment; filename="download"');
    expect(safeAttachmentHeader(null)).toBe('attachment; filename="download"');
  });

  test('control-characters-only filename falls back to the default rather than an empty name', () => {
    expect(safeAttachmentHeader('\r\n\x00')).toBe('attachment; filename="download"');
  });

  test('happy-path filename round-trips byte-exact, including spaces and dots', () => {
    expect(safeAttachmentHeader('Q1 2026 report.final.pdf')).toBe(
      'attachment; filename="Q1 2026 report.final.pdf"'
    );
  });
});
