'use strict';

/**
 * Compatibility Tests
 *
 * Proves that the QODIQA codebase runs correctly on Node.js >= 22 and that
 * its public API surface is stable.  No mocks — all assertions target the
 * real implementation.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ── COMPAT-01 Node.js API availability ───────────────────────────────────────

describe('COMPAT-01 Node.js API availability', () => {
  test('crypto.generateKeyPairSync("ed25519") is available', () => {
    expect(typeof crypto.generateKeyPairSync).toBe('function');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    expect(privateKey).toBeTruthy();
    expect(publicKey).toBeTruthy();
  });

  test('crypto.timingSafeEqual is available', () => {
    expect(typeof crypto.timingSafeEqual).toBe('function');
    const a = Buffer.from('abc');
    const b = Buffer.from('abc');
    expect(crypto.timingSafeEqual(a, b)).toBe(true);
  });

  test('Buffer.alloc is available', () => {
    expect(typeof Buffer.alloc).toBe('function');
    const buf = Buffer.alloc(4);
    expect(buf.length).toBe(4);
  });

  test('Buffer.from is available', () => {
    expect(typeof Buffer.from).toBe('function');
    const buf = Buffer.from('hello', 'utf8');
    expect(Buffer.isBuffer(buf)).toBe(true);
  });

  test('Buffer.isBuffer is available', () => {
    expect(typeof Buffer.isBuffer).toBe('function');
    expect(Buffer.isBuffer(Buffer.alloc(0))).toBe(true);
    expect(Buffer.isBuffer('string')).toBe(false);
  });

  test('crypto.createHash("sha256") is available', () => {
    expect(typeof crypto.createHash).toBe('function');
    const hash = crypto.createHash('sha256').update('test').digest('hex');
    expect(typeof hash).toBe('string');
    expect(hash.length).toBe(64);
  });

  test('process.hrtime.bigint is available', () => {
    expect(typeof process.hrtime.bigint).toBe('function');
    const t = process.hrtime.bigint();
    expect(typeof t).toBe('bigint');
  });

  test('fs.promises is available', () => {
    expect(typeof fs.promises).toBe('object');
    expect(typeof fs.promises.readFile).toBe('function');
    expect(typeof fs.promises.writeFile).toBe('function');
  });

  test('structuredClone or JSON.parse(JSON.stringify()) works for deep clone', () => {
    const original = { a: 1, b: { c: [2, 3] } };
    let clone;
    if (typeof structuredClone === 'function') {
      clone = structuredClone(original);
    } else {
      clone = JSON.parse(JSON.stringify(original));
    }
    expect(clone).toEqual(original);
    expect(clone).not.toBe(original);
    expect(clone.b).not.toBe(original.b);
  });

  test('parseInt is available and correct', () => {
    expect(typeof parseInt).toBe('function');
    expect(parseInt('42', 10)).toBe(42);
    expect(parseInt('0xff', 16)).toBe(255);
  });

  test('Number.isFinite is available', () => {
    expect(typeof Number.isFinite).toBe('function');
    expect(Number.isFinite(1)).toBe(true);
    expect(Number.isFinite(Infinity)).toBe(false);
    expect(Number.isFinite(NaN)).toBe(false);
  });

  test('Number.isInteger is available', () => {
    expect(typeof Number.isInteger).toBe('function');
    expect(Number.isInteger(1)).toBe(true);
    expect(Number.isInteger(1.5)).toBe(false);
  });
});

// ── COMPAT-02 Engine constraint ───────────────────────────────────────────────

describe('COMPAT-02 Engine constraint', () => {
  const pkgPath = path.resolve(__dirname, '../package.json');
  const pkg     = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

  test('package.json engines.node is set to ">=22.0.0"', () => {
    expect(pkg.engines).toBeDefined();
    expect(pkg.engines.node).toBe('>=22.0.0');
  });

  test('current Node.js version satisfies >=22.0.0', () => {
    // process.version is of the form "v22.x.y"
    expect(typeof process.version).toBe('string');
    expect(process.version).toMatch(/^v\d+\.\d+\.\d+/);
  });

  test('parsed semver major is >= 22', () => {
    // Strip leading "v", split on "."
    const versionStr = process.version.replace(/^v/, '');
    const [majorStr] = versionStr.split('.');
    const major = parseInt(majorStr, 10);
    expect(Number.isInteger(major)).toBe(true);
    expect(major).toBeGreaterThanOrEqual(22);
  });
});

// ── COMPAT-03 Core module API surface (regression guard) ─────────────────────

describe('COMPAT-03 Core module API surface', () => {
  test('src/infra/crypto/hashing.js exports all documented names', () => {
    const mod = require('../src/infra/crypto/hashing');
    const expected = [
      'sha256Hex',
      'sha256Raw',
      'sortedJSON',
      'domainSeparatedHash',
      'computeHash',
      'generateNonce',
      'generateArtifactId',
      'timingSafeCompare',
      'ARTIFACT_DOMAINS',
    ];
    for (const name of expected) {
      expect(mod).toHaveProperty(name);
    }
  });

  test('src/infra/crypto/ed25519.js exports sign and verify', () => {
    const mod = require('../src/infra/crypto/ed25519');
    expect(typeof mod.sign).toBe('function');
    expect(typeof mod.verify).toBe('function');
  });

  test('src/validation/requestHash.js exports computeRequestHash and REQUEST_DOMAIN', () => {
    const mod = require('../src/validation/requestHash');
    expect(typeof mod.computeRequestHash).toBe('function');
    expect(typeof mod.REQUEST_DOMAIN).toBe('string');
    expect(mod.REQUEST_DOMAIN.length).toBeGreaterThan(0);
  });

  test('src/validation/timeCheck.js exports all documented names', () => {
    const mod = require('../src/validation/timeCheck');
    const expected = [
      'parseTimestamp',
      'checkTimestamp',
      'checkSkew',
      'checkExpiry',
      'MAX_SKEW_MS',
    ];
    for (const name of expected) {
      expect(mod).toHaveProperty(name);
    }
  });

  test('src/validation/registerNonce.js exports registerNonce', () => {
    const mod = require('../src/validation/registerNonce');
    expect(typeof mod.registerNonce).toBe('function');
  });

  test('src/validation/verifyRequestBinding.js exports verifyRequestBinding', () => {
    const mod = require('../src/validation/verifyRequestBinding');
    expect(typeof mod.verifyRequestBinding).toBe('function');
  });

  test('src/validation/signBoundArtifact.js exports signBoundArtifact', () => {
    const mod = require('../src/validation/signBoundArtifact');
    expect(typeof mod.signBoundArtifact).toBe('function');
  });

  test('src/validation/canonicalize.js exports all documented names', () => {
    const mod = require('../src/validation/canonicalize');
    const expected = [
      'canonicalizeEnvelope',
      'envelopeHash',
      'ENVELOPE_DOMAIN',
      'SIGNED_ENVELOPE_KEYS',
    ];
    for (const name of expected) {
      expect(mod).toHaveProperty(name);
    }
  });

  test('src/testing/stores.js exports all documented factory functions', () => {
    const mod = require('../src/testing/stores');
    const expected = [
      'makeNonceStore',
      'makeOpenAnomalyStore',
      'makeCountingAnomalyStore',
      'makeDeadStore',
    ];
    for (const name of expected) {
      expect(typeof mod[name]).toBe('function');
    }
  });
});

// ── COMPAT-04 Behaviour consistency across Node versions ─────────────────────

describe('COMPAT-04 Behaviour consistency across Node versions', () => {
  const { sha256Hex, sortedJSON, generateNonce } = require('../src/infra/crypto/hashing');
  const { sign, verify }                         = require('../src/infra/crypto/ed25519');

  test('sha256Hex("abc") returns the RFC-4634 fixed vector', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  test('Ed25519 sign/verify roundtrip works with Node-generated key pair', () => {
    const { sha256Raw } = require('../src/infra/crypto/hashing');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
    const pubDer  = publicKey.export({ type: 'spki',  format: 'der' });

    const hashBuf = sha256Raw('compat-test-message');
    const sig     = sign(hashBuf, privDer);
    expect(verify(hashBuf, sig, pubDer)).toBe(true);
  });

  test('sortedJSON({b:2, a:1}) returns \'{"a":1,"b":2}\'', () => {
    expect(sortedJSON({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });

  test('generateNonce() matches /^[a-f0-9]{32}$/', () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[a-f0-9]{32}$/);
  });
});
