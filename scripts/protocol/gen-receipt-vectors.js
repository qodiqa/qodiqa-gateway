#!/usr/bin/env node
'use strict';

/**
 * Generates docs/protocol/vectors/receipt.json (family `v2-receipt`, ids V2-RECEIPT-nnn) — conformance vectors for the signed receipt of
 * docs/protocol/PROTOCOL-V2.md section 6.
 *
 *   receipt = { v: 1, requestId, decision, issuedAt, entryHash, leafHash, keyId, signature }
 *   signature = base64( Ed25519( SHA-256( "QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature) ) ) )
 *
 * Mode `verify`: each case gives a receipt (any JSON value) and optionally `trustedAt`; the verdict is `expected.outcome "ok"` or `expectedError.code`
 * (NOT_AN_OBJECT, FIELD_SET, UNSUPPORTED_VERSION, INVALID_FIELD, UNKNOWN_KEY, BAD_SIGNATURE, REVOKED_KEY — the first failing rule in that order).
 *
 * The keys are PUBLISHED TEST SEEDS (never a deployment key). Receipts are signed here with the PRODUCTION digest function
 * (src/core/transparency/receipt.js receiptDigest) and the verdicts are produced by the repository's independent receipt verifier
 * (scripts/audit-repro/verify/receipt.js, written from the document); the verifiers of this family — verify-v2-vectors.js, verify_v2_vectors.py
 * (pure-Python Ed25519) and the two SDKs — re-derive them.
 *
 *   node scripts/protocol/gen-receipt-vectors.js            write the file
 *   node scripts/protocol/gen-receipt-vectors.js --check    compare with the committed file (exit 1 on any difference)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { receiptDigest } = require('../../src/core/transparency/receipt');
const { verifyReceiptDocument } = require('../audit-repro/verify/receipt');

const FILE = path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors', 'receipt.json');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const seedOf = (label) => crypto.createHash('sha256').update(`QODIQA published receipt test seed: ${label}`, 'utf8').digest();
const privOf = (seed) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
const spkiB64 = (priv) => crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).toString('base64');

const KEYS = [
  { keyId: 'tr-test:key_v1', seed: seedOf('active'), status: 'active' },
  { keyId: 'tr-test:key_v0', seed: seedOf('revoked'), status: 'revoked', revokedAt: 1790000100000 },
  { keyId: 'tr-test:key_v2', seed: seedOf('deprecated'), status: 'deprecated' },
];
const byId = Object.fromEntries(KEYS.map((k) => [k.keyId, privOf(k.seed)]));
const H = (c) => c.repeat(64);
const RID = '6f1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
const BASE = { v: 1, requestId: RID, decision: 'ALLOW', issuedAt: 1790000000000, entryHash: H('a'), leafHash: H('b'), keyId: 'tr-test:key_v1' };
const sign = (over = {}, signer = null) => {
  const unsigned = { ...BASE, ...over };
  const priv = signer || byId[unsigned.keyId] || byId['tr-test:key_v1'];
  return { ...unsigned, signature: crypto.sign(null, receiptDigest(unsigned), priv).toString('base64') };
};
const good = sign();
const withKey = (keyId, over = {}) => sign({ keyId, ...over });
const other = privOf(seedOf('someone else'));

const specs = [];
const C = (description, receipt, extra = {}) => specs.push({ description, receipt, ...extra });
C('a genuine ALLOW receipt', good);
C('a genuine BLOCK receipt', sign({ decision: 'BLOCK', entryHash: H('c') }));
C('a genuine receipt signed by a deprecated key still verifies (old receipts stay verifiable)', withKey('tr-test:key_v2'));
C('requestId changed after signing', { ...good, requestId: RID.replace('6f', '7f') });
C('decision changed after signing', { ...good, decision: 'BLOCK' });
C('issuedAt changed after signing', { ...good, issuedAt: good.issuedAt + 1 });
C('entryHash changed after signing', { ...good, entryHash: H('c') });
C('leafHash changed after signing', { ...good, leafHash: H('c') });
C('keyId changed to another known key after signing', { ...good, keyId: 'tr-test:key_v2' });
C('signature byte flipped', { ...good, signature: Buffer.from(good.signature, 'base64').map((b, i) => (i === 0 ? b ^ 1 : b)).toString('base64') });
C('signature made by an unrelated key', sign({}, other));
C('signature of the right length that is not valid', { ...good, signature: Buffer.alloc(64, 7).toString('base64') });
C('signature of the wrong length', { ...good, signature: Buffer.alloc(63, 7).toString('base64') });
C('signature that is not base64', { ...good, signature: '!!!not-base64!!!' });
C('an extra field (tenantId) is not allowed', { ...good, tenantId: 't1' });
C('an extra field (reason) is not allowed', { ...good, reason: 'ALL_CHECKS_PASSED' });
C('a missing field (keyId)', (({ keyId, ...r }) => r)(good));
C('a missing field (signature)', (({ signature, ...r }) => r)(good));
C('version 2 is unsupported', { ...good, v: 2 });
C('version "1" as a string is unsupported', { ...good, v: '1' });
C('version true is unsupported', { ...good, v: true });
C('entryHash in upper case', { ...good, entryHash: H('A') });
C('entryHash too short', { ...good, entryHash: 'a'.repeat(63) });
C('leafHash not hex', { ...good, leafHash: `${'z'.repeat(64)}` });
C('issuedAt with a fraction', { ...good, issuedAt: 1790000000000.5 });
C('issuedAt negative', { ...good, issuedAt: -1 });
C('issuedAt as a string', { ...good, issuedAt: '1790000000000' });
C('issuedAt above 2^53-1 (2^53)', { ...good, issuedAt: 2 ** 53 });
C('issuedAt is the largest safe integer (signed, accepted)', sign({ issuedAt: 9007199254740991 }));
C('issuedAt zero (signed, accepted)', sign({ issuedAt: 0 }));
C('decision EXECUTE is not a receipt decision', { ...good, decision: 'EXECUTE' });
C('decision in lower case', { ...good, decision: 'allow' });
C('empty requestId', { ...good, requestId: '' });
C('a non-UUID requestId is allowed (the document does not constrain its form)', sign({ requestId: 'req-001' }));
C('an unknown key id', { ...good, keyId: 'tr-nobody:key_v9' });
C('a non-string key id', { ...good, keyId: 5 });
C('the receipt is an array', [good]);
C('the receipt is null', null);
C('the receipt is a string', 'receipt');
C('the receipt is a number', 7);
C('revoked key, no trustedAt: refused', withKey('tr-test:key_v0'));
C('revoked key, trustedAt before revokedAt: accepted (timed mode)', withKey('tr-test:key_v0'), { trustedAt: 1790000050000 });
C('revoked key, trustedAt equal to revokedAt: refused', withKey('tr-test:key_v0'), { trustedAt: 1790000100000 });
C('revoked key, trustedAt after revokedAt: refused', withKey('tr-test:key_v0'), { trustedAt: 1790000200000 });
C('an active key ignores trustedAt', good, { trustedAt: 1 });
C('a unicode requestId (signed, accepted): canonical form keeps non-ASCII characters', sign({ requestId: 'req-é-\u{1F600}' }));
C('requestId with control characters (signed, accepted): escaped in the canonical form', sign({ requestId: 'a\tb\nc\u0001' }));
C('requestId with a quote and backslash (signed, accepted)', sign({ requestId: 'a"b\\c' }));

// appended after the first publication (cases are append-only): non-canonical spellings of the same signature bytes are refused
C('signature with a newline inserted (lenient decoders ignore it)', { ...good, signature: `${good.signature.slice(0, 40)}
${good.signature.slice(40)}` });
C('signature with its padding removed', { ...good, signature: good.signature.replace(/=+$/, '') });
C('signature with non-zero trailing bits in the last character (same 64 bytes, other spelling)', (() => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const body = good.signature.replace(/=+$/, '');
  const last = A.indexOf(body[body.length - 1]);
  return { ...good, signature: body.slice(0, -1) + A[last + 1 > 63 ? last - 1 : last + 1] + '==' };
})());
C('signature with surrounding whitespace', { ...good, signature: ` ${good.signature} ` });
C('signature in the URL-safe alphabet where it differs', { ...good, signature: good.signature.replace(/[+]/g, '-').replace(/[/]/g, '_') + (/[+/]/.test(good.signature) ? '' : 'x') });

function build() {
  const keys = KEYS.map((k) => ({ keyId: k.keyId, publicKeySpkiB64: spkiB64(byId[k.keyId]), status: k.status, ...(k.revokedAt ? { revokedAt: k.revokedAt } : {}) }));
  const keyList = keys.map((k) => ({ keyId: k.keyId, publicKey: k.publicKeySpkiB64, status: k.status, ...(k.revokedAt ? { revokedAt: k.revokedAt } : {}) }));
  const cases = specs.map((c, i) => {
    const verdict = verifyReceiptDocument(c.receipt, keyList, c.trustedAt === undefined ? {} : { trustedAt: c.trustedAt });
    const input = { receipt: c.receipt, ...(c.trustedAt === undefined ? {} : { trustedAt: c.trustedAt }) };
    return { id: `V2-RECEIPT-${String(i + 1).padStart(3, '0')}`, description: c.description, input, ...(verdict.ok ? { expected: { outcome: 'ok' } } : { expectedError: { code: verdict.reason } }) };
  });
  return {
    format: 'qodiqa-vectors/1', family: 'v2-receipt', generatedBy: 'scripts/protocol/gen-receipt-vectors.js', specVersion: 'v2-freeze-1', mode: 'verify', nowMs: 0,
    inputSchema: {
      type: 'object', required: ['receipt'], properties: { receipt: { description: 'any JSON value: the receipt under test' }, trustedAt: { type: 'integer', description: 'timed mode (ms): an independently attested time, accepted for a revoked key only before its revokedAt' } },
      description: 'the verdict is expected.outcome "ok" or expectedError.code, the first failing rule of: NOT_AN_OBJECT, FIELD_SET, UNSUPPORTED_VERSION, INVALID_FIELD, UNKNOWN_KEY, BAD_SIGNATURE, REVOKED_KEY. keys[] are published test keys: publicKeySpkiB64 is the base64 SPKI DER of an Ed25519 key.',
    },
    keys, cases,
  };
}

const render = (o) => `${JSON.stringify(o, null, 1)}\n`;
const out = render(build());
if (process.argv.includes('--check')) {
  const committed = fs.existsSync(FILE) ? fs.readFileSync(FILE, 'utf8') : null;
  const ok = committed === out;
  process.stdout.write(`${JSON.stringify({ ok })}\n`);
  if (!ok) { process.stderr.write('[receipt-vectors] DRIFT: run `npm run protocol:vectors` and review the diff.\n'); process.exit(1); }
} else {
  fs.writeFileSync(FILE, out);
  process.stdout.write(`${JSON.stringify({ wrote: path.relative(process.cwd(), FILE), cases: specs.length })}\n`);
}
module.exports = { build };
