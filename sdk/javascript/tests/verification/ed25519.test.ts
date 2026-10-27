import crypto from 'node:crypto';
import { verifyEd25519 } from '../../src/verification/ed25519.js';

function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return { privDer: privateKey as unknown as Buffer, pubDer: publicKey as unknown as Buffer };
}

function sign(hash: Buffer, privDer: Buffer): string {
  return crypto.sign(null, hash, crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' })).toString('base64');
}

describe('verifyEd25519', () => {
  const { privDer, pubDer } = generateKeyPair();
  const hash = crypto.createHash('sha256').update('message').digest();

  test('verifies a genuine signature', () => {
    const sig = sign(hash, privDer);
    expect(verifyEd25519(hash, sig, pubDer)).toBe(true);
  });

  test('rejects a signature from the wrong key', () => {
    const other = generateKeyPair();
    const sig = sign(hash, other.privDer);
    expect(verifyEd25519(hash, sig, pubDer)).toBe(false);
  });

  test('rejects a tampered signature', () => {
    const sig = Buffer.from(sign(hash, privDer), 'base64');
    sig[sig.length - 1] ^= 0x01;
    expect(verifyEd25519(hash, sig.toString('base64'), pubDer)).toBe(false);
  });

  test('rejects a tampered message hash', () => {
    const sig = sign(hash, privDer);
    const otherHash = crypto.createHash('sha256').update('different message').digest();
    expect(verifyEd25519(otherHash, sig, pubDer)).toBe(false);
  });

  test('never throws — wrong-length hash', () => {
    expect(verifyEd25519(Buffer.alloc(16), 'not-relevant', pubDer)).toBe(false);
  });

  test('never throws — truncated signature bytes', () => {
    const sig = Buffer.from(sign(hash, privDer), 'base64').subarray(0, 32).toString('base64');
    expect(verifyEd25519(hash, sig, pubDer)).toBe(false);
  });

  test('never throws — garbage signature string', () => {
    expect(verifyEd25519(hash, 'not-base64-!!!', pubDer)).toBe(false);
  });

  test('never throws — empty public key buffer', () => {
    const sig = sign(hash, privDer);
    expect(verifyEd25519(hash, sig, Buffer.alloc(0))).toBe(false);
  });

  test('never throws — malformed public key DER', () => {
    const sig = sign(hash, privDer);
    expect(verifyEd25519(hash, sig, Buffer.from([1, 2, 3, 4]))).toBe(false);
  });
});
