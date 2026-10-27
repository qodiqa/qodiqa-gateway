'use strict';

const crypto = require('crypto');
const { sign, verify } = require('./ed25519');
const { getActiveKey } = require('../../../services/artifact/keyStore');

// ── Shared test key pair ──────────────────────────────────────────────────────

let KEY;

beforeAll(() => {
  KEY = getActiveKey('default');
});

// Helper: generate a fresh Ed25519 key pair in DER format
function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { privDer: Buffer.from(privateKey), pubDer: Buffer.from(publicKey) };
}

// Helper: produce a 32-byte hash buffer
function makeHash(data) {
  return crypto.createHash('sha256').update(data).digest();
}

// ── sign() ────────────────────────────────────────────────────────────────────

describe('sign()', () => {
  test('returns a base64 string', () => {
    const hash = makeHash('test data');
    const sig = sign(hash, KEY.privDer);
    expect(typeof sig).toBe('string');
  });

  test('base64 signature decodes to exactly 64 bytes', () => {
    const hash = makeHash('decode me');
    const sig = sign(hash, KEY.privDer);
    const decoded = Buffer.from(sig, 'base64');
    expect(decoded.length).toBe(64);
  });

  test('throws TypeError for non-Buffer hashBuffer', () => {
    expect(() => sign('not a buffer', KEY.privDer)).toThrow(TypeError);
  });

  test('throws TypeError for hashBuffer that is not 32 bytes', () => {
    expect(() => sign(Buffer.alloc(16), KEY.privDer)).toThrow(TypeError);
  });

  test('throws TypeError for empty privDer', () => {
    const hash = makeHash('data');
    expect(() => sign(hash, Buffer.alloc(0))).toThrow(TypeError);
  });

  test('throws TypeError for non-Buffer privDer', () => {
    const hash = makeHash('data');
    expect(() => sign(hash, 'not a buffer')).toThrow(TypeError);
  });

  test('is deterministic for Ed25519 (deterministic signing algorithm)', () => {
    const hash = makeHash('deterministic test');
    const sig1 = sign(hash, KEY.privDer);
    const sig2 = sign(hash, KEY.privDer);
    // Ed25519 is deterministic — same key + same message = same signature
    expect(sig1).toBe(sig2);
  });
});

// ── verify() ──────────────────────────────────────────────────────────────────

describe('verify()', () => {
  test('returns true for a valid signature', () => {
    const hash = makeHash('valid message');
    const sig = sign(hash, KEY.privDer);
    expect(verify(hash, sig, KEY.pubDer)).toBe(true);
  });

  test('returns false for a bit-flipped signature', () => {
    const hash = makeHash('flip test');
    const sig = sign(hash, KEY.privDer);
    const sigBuf = Buffer.from(sig, 'base64');
    // Flip one bit
    sigBuf[0] ^= 0x01;
    const badSig = sigBuf.toString('base64');
    expect(verify(hash, badSig, KEY.pubDer)).toBe(false);
  });

  test('returns false for wrong public key', () => {
    const { pubDer: wrongPub } = generateKeyPair();
    const hash = makeHash('wrong key test');
    const sig = sign(hash, KEY.privDer);
    expect(verify(hash, sig, wrongPub)).toBe(false);
  });

  test('returns false for different hash (wrong message)', () => {
    const hash1 = makeHash('original message');
    const hash2 = makeHash('different message');
    const sig = sign(hash1, KEY.privDer);
    expect(verify(hash2, sig, KEY.pubDer)).toBe(false);
  });

  test('returns false for non-string signatureBase64', () => {
    const hash = makeHash('data');
    expect(verify(hash, null, KEY.pubDer)).toBe(false);
    expect(verify(hash, 123, KEY.pubDer)).toBe(false);
    expect(verify(hash, Buffer.alloc(64), KEY.pubDer)).toBe(false);
  });

  test('returns false for hashBuffer that is not 32 bytes', () => {
    const hash = makeHash('data');
    const sig = sign(hash, KEY.privDer);
    expect(verify(Buffer.alloc(16), sig, KEY.pubDer)).toBe(false);
  });

  test('returns false for non-Buffer pubDer', () => {
    const hash = makeHash('data');
    const sig = sign(hash, KEY.privDer);
    expect(verify(hash, sig, 'not a buffer')).toBe(false);
  });

  test('returns false for empty pubDer', () => {
    const hash = makeHash('data');
    const sig = sign(hash, KEY.privDer);
    expect(verify(hash, sig, Buffer.alloc(0))).toBe(false);
  });

  test('returns false for a signature of wrong length (decoded != 64 bytes)', () => {
    const hash = makeHash('data');
    // A random 32-byte buffer encoded as base64 — decodes to 32 bytes, not 64
    const shortSig = Buffer.alloc(32).toString('base64');
    expect(verify(hash, shortSig, KEY.pubDer)).toBe(false);
  });
});

// ── Roundtrip tests ───────────────────────────────────────────────────────────

describe('sign/verify roundtrip', () => {
  test('freshly generated key pair: sign then verify returns true', () => {
    const { privDer, pubDer } = generateKeyPair();
    const hash = makeHash('roundtrip test');
    const sig = sign(hash, privDer);
    expect(verify(hash, sig, pubDer)).toBe(true);
  });

  test('multiple messages with same key pair all verify correctly', () => {
    const { privDer, pubDer } = generateKeyPair();
    const messages = ['alpha', 'beta', 'gamma', 'delta'];
    for (const msg of messages) {
      const hash = makeHash(msg);
      const sig = sign(hash, privDer);
      expect(verify(hash, sig, pubDer)).toBe(true);
    }
  });

  test('signature from one key does not verify with another key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const hash = makeHash('cross-key test');
    const sig = sign(hash, kp1.privDer);
    // Verifies with its own key
    expect(verify(hash, sig, kp1.pubDer)).toBe(true);
    // Does NOT verify with a different key
    expect(verify(hash, sig, kp2.pubDer)).toBe(false);
  });

  test('getActiveKey("default") key pair works end-to-end', () => {
    const hash = makeHash('keystore key roundtrip');
    const sig = sign(hash, KEY.privDer);
    expect(verify(hash, sig, KEY.pubDer)).toBe(true);
  });
});
