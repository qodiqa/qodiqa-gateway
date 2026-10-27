'use strict';

// exactly one accepted spelling of a signature.
// Every case starts from a REAL, valid signature for the artifact, so each
// rejection is caused by the spelling alone — never by a wrong signature.

const { validateArtifact, isCanonicalSignature } = require('../validateArtifact');
const { signArtifact } = require('../signArtifact');
const { getActiveKey } = require('../../../services/artifact/keyStore');

const KEY = getActiveKey('default');
const T = Date.now();
const art = signArtifact({ payload: { userId: 'sig' }, timestamp: T, expiry: T + 60_000, publicKeyId: KEY.keyId }, KEY.privDer);
const canonical = art.signature;
const withSig = (signature) => ({ ...art, signature });

/** The same 64 signature bytes, but with non-zero trailing bits in the last data character. */
function nonZeroPadBits(sig) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const last = sig[85];
  const idx = alphabet.indexOf(last);
  const bumped = alphabet[(idx & ~0x0f) | ((idx + 1) & 0x0f)] === last ? alphabet[idx ^ 1] : alphabet[(idx & ~0x0f) | ((idx + 1) & 0x0f)];
  return sig.slice(0, 85) + bumped + '==';
}

describe('canonical signature encoding', () => {
  test('SC-01 the signer emits the canonical form: 88 chars, "==" padded, round-trip exact — and it verifies', () => {
    expect(canonical).toHaveLength(88);
    expect(canonical.endsWith('==')).toBe(true);
    expect(isCanonicalSignature(canonical)).toBe(true);
    expect(validateArtifact(art).decision).toBe('EXECUTE');
  });

  const CASES = [
    ['SC-02 missing padding', canonical.slice(0, 86)],
    ['SC-03 one padding character missing', canonical.slice(0, 87)],
    ['SC-04 extra padding', `${canonical}=`],
    ['SC-05 extra padding x2', `${canonical}==`],
    ['SC-06 URL-safe alphabet (- _) with padding', canonical.replace(/\+/g, '-').replace(/\//g, '_').replace(/^(.{85}).(==)$/, (m, a, b) => (/[+/]/.test(canonical) ? m : `${a}-${b}`))],
    ['SC-07 URL-safe without padding', canonical.replace(/\+/g, '-').replace(/\//g, '_').slice(0, 86)],
    ['SC-08 leading whitespace', ` ${canonical}`],
    ['SC-09 trailing whitespace', `${canonical} `],
    ['SC-10 inner whitespace', `${canonical.slice(0, 40)} ${canonical.slice(40)}`],
    ['SC-11 trailing newline', `${canonical}\n`],
    ['SC-12 an altered character', (canonical[10] === 'A' ? 'B' : 'A').padStart(11, canonical.slice(0, 10)) + canonical.slice(11)],
    ['SC-13 wrong length (63 bytes, canonical-looking)', Buffer.alloc(63, 1).toString('base64')],
    ['SC-14 wrong length (65 bytes)', Buffer.alloc(65, 1).toString('base64')],
    ['SC-15 same 64 bytes, non-canonical trailing bits', nonZeroPadBits(canonical)],
    ['SC-16 empty string', ''],
  ];

  test.each(CASES)('%s → INVALID_SIGNATURE', (_label, spelling) => {
    expect(spelling).not.toBe(canonical);
    const r = validateArtifact(withSig(spelling));
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('SC-17 the non-canonical-bits spelling decodes to the SAME bytes (the malleability describes) and is still refused', () => {
    const alt = nonZeroPadBits(canonical);
    expect(Buffer.from(alt, 'base64').equals(Buffer.from(canonical, 'base64'))).toBe(true);
    expect(isCanonicalSignature(alt)).toBe(false);
    expect(validateArtifact(withSig(alt)).reason).toBe('INVALID_SIGNATURE');
  });

  test('SC-18 a non-string signature is a schema error, not a spelling', () => {
    expect(validateArtifact(withSig(12345)).reason).toBe('INVALID_ARTIFACT');
  });
});
