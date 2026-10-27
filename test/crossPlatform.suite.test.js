'use strict';

/**
 * Cross-Platform Tests
 *
 * Proves that path handling, string encoding, and hash computation are
 * consistent regardless of OS.  No mocks — all assertions target real behavior.
 */

const crypto = require('crypto');
const path   = require('path');

const { sha256Hex, sha256Raw, sortedJSON } = require('../src/infra/crypto/hashing');
const { computeRequestHash }               = require('../src/validation/requestHash');

// ── XPLAT-01 Request hash is OS-independent ───────────────────────────────────

describe('XPLAT-01 Request hash is OS-independent', () => {
  test('forward-slash and backslash paths hash differently (byte-for-byte binding)', () => {
    const hashForward   = computeRequestHash('POST', '/ai/chat', {});
    const hashBackslash = computeRequestHash('POST', '\\ai\\chat', {});
    // Paths are bound byte-for-byte; different bytes → different hash.
    expect(hashForward).not.toBe(hashBackslash);
  });

  test('computeRequestHash("POST", "/ai/chat", {}) is deterministic across calls', () => {
    const h1 = computeRequestHash('POST', '/ai/chat', {});
    const h2 = computeRequestHash('POST', '/ai/chat', {});
    const h3 = computeRequestHash('POST', '/ai/chat', {});
    expect(h1).toBe(h2);
    expect(h2).toBe(h3);
  });

  test('body string values with \\n vs \\r\\n produce different hashes', () => {
    const hashLF   = computeRequestHash('POST', '/ai/chat', { text: 'hello\nworld' });
    const hashCRLF = computeRequestHash('POST', '/ai/chat', { text: 'hello\r\nworld' });
    // Byte-for-byte binding: \n ≠ \r\n
    expect(hashLF).not.toBe(hashCRLF);
  });

  test('result is a 64-char lowercase hex string regardless of OS', () => {
    const h = computeRequestHash('GET', '/health', {});
    expect(h).toMatch(/^[a-f0-9]{64}$/);
  });
});

// ── XPLAT-02 stableStringify is OS-independent ───────────────────────────────

describe('XPLAT-02 stableStringify is OS-independent', () => {
  test('sortedJSON({a:1}) returns \'{"a":1}\' regardless of OS', () => {
    expect(sortedJSON({ a: 1 })).toBe('{"a":1}');
  });

  test('keys are sorted by codepoint, not locale', () => {
    // Z (codepoint 90) < a (codepoint 97) in ASCII/Unicode order
    const result = sortedJSON({ z: 1, A: 2, a: 3 });
    const parsed  = JSON.parse(result);
    const keys    = Object.keys(parsed);
    // Verify codepoint order: 'A'(65) < 'a'(97) < 'z'(122)
    for (let i = 0; i < keys.length - 1; i++) {
      expect(keys[i].charCodeAt(0)).toBeLessThanOrEqual(keys[i + 1].charCodeAt(0));
    }
  });

  test('sortedJSON output never contains CRLF', () => {
    const input  = { message: 'hello', data: [1, 2, 3], nested: { x: true } };
    const result = sortedJSON(input);
    expect(result).not.toContain('\r\n');
    expect(result).not.toContain('\r');
  });

  test('sortedJSON is deterministic across multiple calls', () => {
    const obj = { gamma: 3, alpha: 1, beta: 2 };
    const r1  = sortedJSON(obj);
    const r2  = sortedJSON(obj);
    const r3  = sortedJSON(obj);
    expect(r1).toBe(r2);
    expect(r2).toBe(r3);
  });
});

// ── XPLAT-03 SHA-256 is OS-independent ───────────────────────────────────────

describe('XPLAT-03 SHA-256 is OS-independent', () => {
  test('sha256Hex("hello") matches the known RFC vector', () => {
    // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    expect(sha256Hex('hello')).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    );
  });

  test('sha256Raw returns a Buffer (not a string) regardless of OS', () => {
    const raw = sha256Raw('os-independence-test');
    expect(Buffer.isBuffer(raw)).toBe(true);
    expect(raw.length).toBe(32);
  });

  test('Buffer.from with "hex" encoding works consistently', () => {
    const hexStr = sha256Hex('consistency');
    const buf    = Buffer.from(hexStr, 'hex');
    expect(buf.length).toBe(32);
    expect(buf.toString('hex')).toBe(hexStr);
  });

  test('sha256Hex output is always 64 lowercase hex chars', () => {
    const inputs = ['', 'a', 'hello world', 'éàü'];
    for (const input of inputs) {
      expect(sha256Hex(input)).toMatch(/^[a-f0-9]{64}$/);
    }
  });
});

// ── XPLAT-04 Path-independent module loading ──────────────────────────────────

describe('XPLAT-04 Path-independent module loading', () => {
  test('src/infra/crypto/hashing.js loads without error', () => {
    expect(() => require('../src/infra/crypto/hashing')).not.toThrow();
  });

  test('src/infra/crypto/ed25519.js loads without error', () => {
    expect(() => require('../src/infra/crypto/ed25519')).not.toThrow();
  });

  test('src/validation/requestHash.js loads without error', () => {
    expect(() => require('../src/validation/requestHash')).not.toThrow();
  });

  test('src/validation/canonicalize.js loads without error', () => {
    expect(() => require('../src/validation/canonicalize')).not.toThrow();
  });

  test('src/validation/timeCheck.js loads without error', () => {
    expect(() => require('../src/validation/timeCheck')).not.toThrow();
  });

  test('src/validation/validateBoundRequest loads without error (tests Windows path in require chain)', () => {
    expect(() => require('../src/validation/validateBoundRequest')).not.toThrow();
  });

  test('src/testing/stores.js loads without error', () => {
    expect(() => require('../src/testing/stores')).not.toThrow();
  });
});

// ── XPLAT-05 Current platform detection ──────────────────────────────────────

describe('XPLAT-05 Current platform detection', () => {
  const KNOWN_PLATFORMS = ['win32', 'linux', 'darwin', 'freebsd', 'sunos', 'aix'];

  test('process.platform is a known OS identifier', () => {
    expect(KNOWN_PLATFORMS).toContain(process.platform);
  });

  test('crypto operations do not branch on process.platform', () => {
    // Verify the same sha256 result regardless of what platform we are on.
    // If the code branched on platform, one of these would produce a different result.
    const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    expect(sha256Hex('abc')).toBe(expected);
  });

  test('path.sep is either "/" or "\\" (both are valid)', () => {
    expect(['/', '\\']).toContain(path.sep);
  });

  test('stableStringify produces identical output regardless of path.sep', () => {
    // Output must be the same string on any OS
    expect(sortedJSON({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  test('hashing produces identical output regardless of path.sep', () => {
    const h = sha256Hex('platform-invariant');
    // Call a second time — must be same value
    expect(sha256Hex('platform-invariant')).toBe(h);
    // Must be 64 lowercase hex chars on every OS
    expect(h).toMatch(/^[a-f0-9]{64}$/);
  });

  test('signing produces a valid signature regardless of platform', () => {
    const { sign, verify } = require('../src/infra/crypto/ed25519');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
    const pubDer  = publicKey.export({ type: 'spki',  format: 'der' });

    const hashBuf = sha256Raw('cross-platform-sign-test');
    const sig     = sign(hashBuf, privDer);
    expect(verify(hashBuf, sig, pubDer)).toBe(true);
  });
});

// ── XPLAT-06 Encoding consistency ────────────────────────────────────────────

describe('XPLAT-06 Encoding consistency', () => {
  test('Buffer.from("hello", "utf8").toString("hex") is consistent', () => {
    const hex = Buffer.from('hello', 'utf8').toString('hex');
    // 'hello' in UTF-8 hex is always 68656c6c6f
    expect(hex).toBe('68656c6c6f');
  });

  test('JSON.stringify is deterministic for numbers (no locale effects)', () => {
    const obj = { pi: 3.14159265358979, e: 2.718281828 };
    const r1  = JSON.stringify(obj);
    const r2  = JSON.stringify(obj);
    expect(r1).toBe(r2);
    // Verify specific representation — locale-dependent formatters would alter this
    expect(r1).toContain('3.14159265358979');
    expect(r1).toContain('2.718281828');
  });

  test('Base64 encoding is consistent: Buffer.from("test").toString("base64") = "dGVzdA=="', () => {
    expect(Buffer.from('test').toString('base64')).toBe('dGVzdA==');
  });

  test('Buffer round-trip through hex is lossless', () => {
    const original = crypto.randomBytes(32);
    const hex      = original.toString('hex');
    const restored = Buffer.from(hex, 'hex');
    expect(original.equals(restored)).toBe(true);
  });

  test('UTF-8 encoding of multi-byte characters is consistent', () => {
    // U+00E9 (é) encodes to 0xc3 0xa9 in UTF-8 on all platforms
    const buf = Buffer.from('é', 'utf8');
    expect(buf.toString('hex')).toBe('c3a9');
  });
});
