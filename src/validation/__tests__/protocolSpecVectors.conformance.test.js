'use strict';

/**
 * Protocol Specification Canonical Test Vectors — QODIQA-PROTOCOL-SPEC.md §27
 *
 * Task #28 remediation: every SHA-256 vector in §27 was independently
 * recomputed from its documented canonical input (cross-checked against both
 * Node's `crypto` module and an external `openssl dgst -sha256` invocation,
 * outside this repository's own code, to rule out a shared implementation
 * bug). Vectors 4, 5, 6, and 7 were found to be transcription errors in the
 * specification document itself — not implementation defects — and were
 * corrected in QODIQA-PROTOCOL-SPEC.md.
 *
 * This suite locks in the corrected values as golden vectors so the
 * specification can never silently drift from `stableStringify` +
 * `domainSeparatedHash` (the actual canonicalization/hashing implementation)
 * again. Each expected value below is transcribed directly from
 * QODIQA-PROTOCOL-SPEC.md §27 — if a test here fails, either the spec or the
 * implementation regressed and must be reconciled, not this test.
 */

const crypto = require('crypto');
const stableStringify = require('../../utils/stableStringify');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../infra/crypto/hashing');
const { buildNonceKey } = require('../nonceStore');

describe('§27.2 Vector 1 — Canonical Serialization', () => {
  test('sorts keys ascending at every depth, no whitespace', () => {
    const canonical = stableStringify({ z: 1, a: 2, m: { b: null, x: null } });
    expect(canonical).toBe('{"a":2,"m":{"b":null,"x":null},"z":1}');
  });
});

describe('§27.3 Vector 2 — Domain Hash (QODIQA::CANONICAL::V1)', () => {
  test('matches the documented SHA-256 output', () => {
    const canonical = stableStringify({ z: 1, a: 2, m: { b: null, x: null } });
    const hash = domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, canonical).toString('hex');
    expect(hash).toBe('9388298ff8f51ceea31d43dcc4f012069c95e6017dd900fad7d0502dc877e39b');
  });
});

describe('§27.4 Vector 3 — Request Hash', () => {
  test('matches the documented SHA-256 output', () => {
    const canonicalBody = stableStringify({ model: 'gpt-4', messages: [{ role: 'user', content: 'hello' }] });
    expect(canonicalBody).toBe('{"messages":[{"content":"hello","role":"user"}],"model":"gpt-4"}');

    const canonicalFull = stableStringify({ body: JSON.parse(canonicalBody), method: 'POST', path: '/v1/ai/chat' });
    const hash = domainSeparatedHash(ARTIFACT_DOMAINS.REQUEST, canonicalFull).toString('hex');
    expect(hash).toBe('c7fba3c637866c1b914c7d79e30e1ca907160838b9474c17199dd7fa08f55afa');
  });
});

describe('§27.5 Vector 4 — Policy Hash (corrected by Task #28)', () => {
  test('matches the corrected documented SHA-256 output', () => {
    const canonicalPolicy = stableStringify([{ effect: 'allow', action: '*', resource: '*' }]);
    expect(canonicalPolicy).toBe('[{"action":"*","effect":"allow","resource":"*"}]');

    const hash = domainSeparatedHash(ARTIFACT_DOMAINS.POLICY, canonicalPolicy).toString('hex');
    expect(hash).toBe('ac88ab8baf19c2860df6fc6b81264f4c3ec659bec23109de8ec4eb9da161af24');
  });

  test('the old (pre-Task-#28) documented value was not a real SHA-256 of the stated input', () => {
    const canonicalPolicy = stableStringify([{ effect: 'allow', action: '*', resource: '*' }]);
    const hash = domainSeparatedHash(ARTIFACT_DOMAINS.POLICY, canonicalPolicy).toString('hex');
    expect(hash).not.toBe('b04393e3a554e775b170ef818156a5a2922bd3687ade3ecee326c7245d681b9c');
  });
});

describe('§27.6 Vector 5 — Request Hash for Artifact Test Body (corrected by Task #28)', () => {
  const canonicalFull = stableStringify({ body: { message: 'Hello' }, method: 'POST', path: '/test' });
  const hash = domainSeparatedHash(ARTIFACT_DOMAINS.REQUEST, canonicalFull).toString('hex');

  test('matches the corrected documented SHA-256 output', () => {
    expect(hash).toBe('63817b2900664e2ae0742631bdf15fb6fab32ec2ae936785140e040a93579f32');
  });

  test('the old (pre-Task-#28) documented value was not a real SHA-256 of the stated input', () => {
    expect(hash).not.toBe('6ebc8fe0460c333e8e839ccc333568350e64b5dba98c32a02676584202494df7');
  });
});

describe('§27.7 Vector 6 / §27.8 Vector 7 — Complete Signed Artifact + Tampered Detection (corrected by Task #28)', () => {
  const POLICY_HASH  = 'ac88ab8baf19c2860df6fc6b81264f4c3ec659bec23109de8ec4eb9da161af24';
  const REQUEST_HASH = '63817b2900664e2ae0742631bdf15fb6fab32ec2ae936785140e040a93579f32';

  const PRIVATE_KEY_DER_HEX = '302e020100300506032b6570042204200b8a9921a7142cab10b68828202cc5267c6fd4cd6680680e7b3741be199ada0a';
  const PUBLIC_KEY_DER_HEX  = '302a300506032b6570032100d6dc1790fe95e46d74a174be392c39f289d2a1252fac60050bf4adf90aa62e9b';
  const EXPECTED_SIGNATURE_B64 = 'XbIqkxw3PjKbwIhVWxpedevF4N4W4ZkTBMHajAZFuDS19BiWi0w1zgSrI+VkR1SG+1kwa+sXwogKxwByWTPuCQ==';

  function envelopeHashHex(requestId) {
    const envelope = {
      expiry: 1751500060000,
      payload: { requestId, requestHash: REQUEST_HASH, policyHash: POLICY_HASH },
      publicKeyId: 'test-tenant:key_v1',
      timestamp: 1751500000000,
    };
    const canonical = stableStringify(envelope);
    return { canonical, hash: domainSeparatedHash(ARTIFACT_DOMAINS.ARTIFACT, canonical).toString('hex') };
  }

  test('Vector 6: canonical envelope and artifact hash match the corrected spec values', () => {
    const { canonical, hash } = envelopeHashHex('550e8400-e29b-41d4-a716-446655440000');
    expect(canonical).toBe(
      '{"expiry":1751500060000,"payload":{"policyHash":"ac88ab8baf19c2860df6fc6b81264f4c3ec659bec23109de8ec4eb9da161af24","requestHash":"63817b2900664e2ae0742631bdf15fb6fab32ec2ae936785140e040a93579f32","requestId":"550e8400-e29b-41d4-a716-446655440000"},"publicKeyId":"test-tenant:key_v1","timestamp":1751500000000}',
    );
    expect(hash).toBe('a86a86d6220881551bc4e74f9b0fc1786594f985c956a6b9627c8887b26e4abb');
  });

  test('Vector 6: the published test key pair reproduces the published signature over the artifact hash', () => {
    const { hash } = envelopeHashHex('550e8400-e29b-41d4-a716-446655440000');
    const privateKey = crypto.createPrivateKey({ key: Buffer.from(PRIVATE_KEY_DER_HEX, 'hex'), format: 'der', type: 'pkcs8' });
    const publicKey  = crypto.createPublicKey({ key: Buffer.from(PUBLIC_KEY_DER_HEX, 'hex'), format: 'der', type: 'spki' });

    const signature = crypto.sign(null, Buffer.from(hash, 'hex'), privateKey);
    expect(signature.toString('base64')).toBe(EXPECTED_SIGNATURE_B64);
    expect(crypto.verify(null, Buffer.from(hash, 'hex'), publicKey, signature)).toBe(true);
  });

  test('Vector 7: tampering requestId\'s last character produces the corrected distinct artifact hash', () => {
    const { hash } = envelopeHashHex('550e8400-e29b-41d4-a716-446655440001');
    expect(hash).toBe('4248588ce8e46be65f659b704fc4aae779d89bf65548ffc7eda38c1a96cff9bc');
  });

  test('Vector 7: the Vector 6 signature MUST NOT verify against the tampered (Vector 7) hash', () => {
    const { hash: tamperedHash } = envelopeHashHex('550e8400-e29b-41d4-a716-446655440001');
    const publicKey = crypto.createPublicKey({ key: Buffer.from(PUBLIC_KEY_DER_HEX, 'hex'), format: 'der', type: 'spki' });
    const signature = Buffer.from(EXPECTED_SIGNATURE_B64, 'base64');

    expect(crypto.verify(null, Buffer.from(tamperedHash, 'hex'), publicKey, signature)).toBe(false);
  });
});

describe('§27.9 Vector 8 — Empty Policy Array Hash', () => {
  test('matches the documented SHA-256 output', () => {
    const canonical = stableStringify([]);
    expect(canonical).toBe('[]');
    const hash = domainSeparatedHash(ARTIFACT_DOMAINS.POLICY, canonical).toString('hex');
    expect(hash).toBe('0f5e974777714b2cbf42f88d24f984e4210ec1e8f4b3db639dfe7ebc58dd28d5');
  });
});

describe('§27.10 Vector 9 — Domain Prefix Separation', () => {
  const canonicalPayload = stableStringify({ test: 'value' });
  const expected = {
    ARTIFACT:    '17ab4e73171c138a',
    REQUEST:     '0ed869cdc41cb55d',
    POLICY:      'e4c538f4e8db1db2',
    CERTIFICATE: 'd2df6ef37dd76bd0',
    EVIDENCE:    '565e93e26591052a',
    AUDIT:       '5b3b99e83f7329c7',
    CANONICAL:   '6558732cd34a0821',
  };

  test.each(Object.keys(expected))('domain %s matches its documented first-16-hex-char prefix', (domainKey) => {
    const hash = domainSeparatedHash(ARTIFACT_DOMAINS[domainKey], canonicalPayload).toString('hex');
    expect(hash.slice(0, 16)).toBe(expected[domainKey]);
  });

  test('all seven domain-prefixed hashes over the same payload are pairwise distinct', () => {
    const hashes = Object.keys(expected).map(
      d => domainSeparatedHash(ARTIFACT_DOMAINS[d], canonicalPayload).toString('hex'),
    );
    expect(new Set(hashes).size).toBe(hashes.length);
  });
});

describe('§27.11 Vector 10 — Nonce Store Key Construction', () => {
  test('with tenantId: tenantId prefixes the whole key', () => {
    expect(buildNonceKey('550e8400-e29b-41d4-a716-446655440000', 'acme-corp'))
      .toBe('acme-corp:qodiqa:req:v2:550e8400-e29b-41d4-a716-446655440000');
  });

  test('without tenantId: no tenant prefix', () => {
    expect(buildNonceKey('550e8400-e29b-41d4-a716-446655440000', undefined))
      .toBe('qodiqa:req:v2:550e8400-e29b-41d4-a716-446655440000');
  });
});
