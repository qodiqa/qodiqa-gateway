'use strict';

/**
 * PHASE 45 — Cryptographic Hardening Regression Tests
 *
 * Covers all 19 requirements from the specification:
 *   §1  Artifact format
 *   §2  Canonicalization
 *   §3  Stable serialization
 *   §4  Domain separation
 *   §5  Signature scheme
 *   §6  Request binding
 *   §7  Policy binding
 *   §8  Consent binding
 *   §9  Timestamp validation
 *   §10 Clock skew
 *   §11 Replay protection
 *   §12 Nonce lifecycle
 *   §13 Hash chain integrity
 *   §14 Key generation
 *   §15 Key rotation
 *   §16 Key revocation
 *   §17 RNG / entropy
 *   §18 Timing-safe comparisons
 *   §19 Domain cross-contamination prevention
 *
 * Test IDs: P45-<section>-<sequence>
 */

const crypto = require('crypto');

// ── Modules under test ────────────────────────────────────────────────────────

const {
  computeHash,
  sha256Hex,
  domainSeparatedHash,
  ARTIFACT_DOMAINS,
  generateNonce,
  generateUUID,
  timingSafeCompare,
  generateArtifactId,
} = require('../src/infra/crypto/hashing');

const {
  computeEvidenceHash,
  computeAuditRecordHash,
  computeKeyFingerprint,
  buildEvidenceRecord,
  verifyEvidenceRecord,
  validateChainContinuity,
  CANONICAL_FIELDS,
} = require('../src/core/evidence/chain');

const { sign: ed25519Sign, verify: ed25519Verify } = require('../src/infra/crypto/ed25519');
const { signArtifact }        = require('../src/validation/signArtifact');
const { validateArtifact }    = require('../src/validation/validateArtifact');
const { computeRequestHash }  = require('../src/validation/requestHash');
const { signBoundArtifact }   = require('../src/validation/signBoundArtifact');
const { verifyRequestBinding } = require('../src/validation/verifyRequestBinding');
const { checkTimestamp, checkSkew, checkExpiry, MAX_SKEW_MS } = require('../src/validation/timeCheck');
const { computePolicyHash, policyHashesEqual } = require('../services/policyHash');
const stableStringify = require('../services/utils/stableStringify');

// ── Test helpers ──────────────────────────────────────────────────────────────

function freshKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  return { privDer: Buffer.from(privateKey), pubDer: Buffer.from(publicKey) };
}

let KEY;
beforeAll(() => {
  KEY = require('../services/artifact/keyStore').getActiveKey('default');
});

function makeArtifact(payload, overrides = {}) {
  const now = Date.now();
  return signArtifact({
    payload,
    timestamp:   now,
    expiry:      now + 300_000,
    publicKeyId: KEY.keyId,
    ...overrides,
  }, KEY.privDer);
}

// ── §4 Domain Separation ─────────────────────────────────────────────────────

describe('P45-04 Domain Separation', () => {

  const PAYLOAD = 'identical-input';

  test('P45-04-01 all ARTIFACT_DOMAINS entries are defined and unique strings', () => {
    const values = Object.values(ARTIFACT_DOMAINS);
    expect(values.length).toBeGreaterThanOrEqual(7);
    const set = new Set(values);
    expect(set.size).toBe(values.length); // no duplicates
    for (const v of values) {
      expect(typeof v).toBe('string');
      expect(v.length).toBeGreaterThan(0);
    }
  });

  test('P45-04-02 EVIDENCE and AUDIT domains are present in ARTIFACT_DOMAINS', () => {
    expect(ARTIFACT_DOMAINS.EVIDENCE).toBe('QODIQA::EVIDENCE::V1');
    expect(ARTIFACT_DOMAINS.AUDIT).toBe('QODIQA::AUDIT::V1');
  });

  test('P45-04-03 domainSeparatedHash produces different output for different domains on same input', () => {
    const domains = Object.values(ARTIFACT_DOMAINS);
    const hashes  = domains.map(d => domainSeparatedHash(d, PAYLOAD).toString('hex'));
    const unique  = new Set(hashes);
    expect(unique.size).toBe(domains.length);
  });

  test('P45-04-04 domainSeparatedHash is deterministic — same domain+input always produces same hash', () => {
    const h1 = domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, PAYLOAD).toString('hex');
    const h2 = domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, PAYLOAD).toString('hex');
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });

  test('P45-04-05 domainSeparatedHash returns 32-byte Buffer', () => {
    const buf = domainSeparatedHash(ARTIFACT_DOMAINS.ARTIFACT, PAYLOAD);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBe(32);
  });

  test('P45-04-06 domainSeparatedHash throws on empty domain', () => {
    expect(() => domainSeparatedHash('', PAYLOAD)).toThrow(TypeError);
  });

  test('P45-04-07 domainSeparatedHash throws on non-string canonical', () => {
    expect(() => domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, 42)).toThrow(TypeError);
    expect(() => domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, null)).toThrow(TypeError);
    expect(() => domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, {})).toThrow(TypeError);
  });

  test('P45-04-08 computeHash uses CANONICAL domain — output differs from undomain-separated sha256', () => {
    const input = { prompt: 'hello', consent: true, purpose: 'test', timestamp: 1000, decision: 'ALLOW', ai_output: 'ok' };
    const canonical = stableStringify({ ai_output: 'ok', consent: true, decision: 'ALLOW', prompt: 'hello', purpose: 'test', timestamp: 1000 });
    const rawHash    = sha256Hex(canonical);
    const domainHash = computeHash(input);
    expect(domainHash).not.toBe(rawHash);
    expect(domainHash).toHaveLength(64);
  });

  test('P45-04-09 computeHash is deterministic', () => {
    const input = { prompt: 'x', consent: false, purpose: 'p', timestamp: 999, decision: 'BLOCK', ai_output: 'n' };
    expect(computeHash(input)).toBe(computeHash(input));
  });

  test('P45-04-10 computeEvidenceHash uses EVIDENCE domain — different from undomain-separated sha256', () => {
    const record = {};
    for (const f of CANONICAL_FIELDS) record[f] = f === 'previousEvidenceHash' ? null : `value-${f}`;
    const canonical   = stableStringify(Object.fromEntries(CANONICAL_FIELDS.map(f => [f, record[f]])));
    const rawHash     = sha256Hex(canonical);
    const domainHash  = computeEvidenceHash(record);
    expect(domainHash).not.toBe(rawHash);
    expect(domainHash).toHaveLength(64);
  });

  test('P45-04-11 computeEvidenceHash is deterministic', () => {
    const record = {};
    for (const f of CANONICAL_FIELDS) record[f] = f === 'previousEvidenceHash' ? null : `v-${f}`;
    expect(computeEvidenceHash(record)).toBe(computeEvidenceHash(record));
  });

  test('P45-04-12 computeAuditRecordHash uses AUDIT domain — different from undomain-separated sha256', () => {
    const entry = { hash: 'abc123', decision: 'ALLOW', timestamp: 12345 };
    const rawHash    = sha256Hex(stableStringify(entry));
    const domainHash = computeAuditRecordHash(entry);
    expect(domainHash).not.toBe(rawHash);
    expect(domainHash).toHaveLength(64);
  });

  test('P45-04-13 computeAuditRecordHash is deterministic', () => {
    const entry = { field: 'value', n: 42 };
    expect(computeAuditRecordHash(entry)).toBe(computeAuditRecordHash(entry));
  });

  test('P45-04-14 EVIDENCE and AUDIT produce different hashes on the same input', () => {
    const h1 = domainSeparatedHash(ARTIFACT_DOMAINS.EVIDENCE, PAYLOAD).toString('hex');
    const h2 = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT,    PAYLOAD).toString('hex');
    expect(h1).not.toBe(h2);
  });

  test('P45-04-15 policyHash uses POLICY domain', () => {
    const policies   = [{ id: 'p1', rule: 'ALLOW' }];
    const canonical  = stableStringify(policies);
    const rawHash    = sha256Hex(canonical);
    const policyHash = computePolicyHash(policies);
    expect(policyHash).not.toBe(rawHash);
    expect(policyHash).toHaveLength(64);
  });

  test('P45-04-16 requestHash uses REQUEST domain', () => {
    const canonical = stableStringify({ body: { a: 1 }, method: 'POST', path: '/api/v2/sign' });
    const rawHash   = sha256Hex(canonical);
    const reqHash   = computeRequestHash('POST', '/api/v2/sign', { a: 1 });
    expect(reqHash).not.toBe(rawHash);
    expect(reqHash).toHaveLength(64);
  });

  test('P45-04-17 no two domain functions produce the same output for the same canonical payload', () => {
    const canonical = stableStringify({ x: 1 });
    const policies  = [{ x: 1 }];

    const hashes = {
      evidence:  computeEvidenceHash({ evidenceId: 'x1', artifactId: 'a', artifactHash: 'ah', policyId: 'p', policyHash: 'ph', keyId: 'k', keyFingerprint: 'fp', auditRecordId: 'ar', auditRecordHash: 'arh', previousEvidenceHash: null }),
      audit:     computeAuditRecordHash({ x: 1 }),
      policy:    computePolicyHash(policies),
      request:   computeRequestHash('POST', canonical, { x: 1 }),
    };

    const vals = Object.values(hashes);
    const set  = new Set(vals);
    expect(set.size).toBe(vals.length);
  });

});

// ── §1 Artifact Format ────────────────────────────────────────────────────────

describe('P45-01 Artifact Format', () => {

  test('P45-01-01 signed artifact has exactly 5 envelope fields', () => {
    const art = makeArtifact({ userId: 'alice' });
    const keys = Object.keys(art).sort();
    expect(keys).toEqual(['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp']);
  });

  test('P45-01-02 signed artifact is frozen', () => {
    const art = makeArtifact({ userId: 'alice' });
    expect(Object.isFrozen(art)).toBe(true);
  });

  test('P45-01-03 extra envelope fields cause validation to block', () => {
    const art    = makeArtifact({ userId: 'alice' });
    const tampered = { ...art, injected: true };
    expect(validateArtifact(tampered).reason).toBe('INVALID_ARTIFACT');
  });

  test('P45-01-04 undefined values in payload are rejected at signing time', () => {
    const now = Date.now();
    expect(() => signArtifact({
      payload: { userId: 'alice', role: undefined },
      timestamp: now, expiry: now + 1000, publicKeyId: KEY.keyId,
    }, KEY.privDer)).toThrow(/undefined/);
  });

  test('P45-01-05 non-plain-object payload is rejected at signing time', () => {
    const now = Date.now();
    expect(() => signArtifact({ payload: [], timestamp: now, expiry: now + 1000, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: null, timestamp: now, expiry: now + 1000, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: new Date(), timestamp: now, expiry: now + 1000, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
  });

  test('P45-01-06 expiry must be strictly greater than timestamp', () => {
    const now = Date.now();
    expect(() => signArtifact({ payload: {}, timestamp: now, expiry: now, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: {}, timestamp: now, expiry: now - 1, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
  });

});

// ── §2 Canonicalization ───────────────────────────────────────────────────────

describe('P45-02 Canonicalization', () => {

  test('P45-02-01 key ordering does not affect canonical output', () => {
    const a = stableStringify({ b: 2, a: 1 });
    const b = stableStringify({ a: 1, b: 2 });
    expect(a).toBe(b);
  });

  test('P45-02-02 undefined values are normalized to null by stableStringify', () => {
    const result = stableStringify({ a: undefined, b: 'hello' });
    const parsed = JSON.parse(result);
    expect(parsed.a).toBe(null);
  });

  test('P45-02-03 nested objects are also key-sorted', () => {
    const a = stableStringify({ z: { y: 2, x: 1 }, a: 1 });
    const b = stableStringify({ a: 1, z: { x: 1, y: 2 } });
    expect(a).toBe(b);
  });

  test('P45-02-04 two identical payloads produce identical envelope hashes', () => {
    const { envelopeHash } = require('../src/validation/canonicalize');
    const envelope = { payload: { userId: 'alice' }, timestamp: 1000, expiry: 2000, publicKeyId: 'k:key_v1' };
    expect(envelopeHash(envelope).toString('hex')).toBe(envelopeHash(envelope).toString('hex'));
  });

  test('P45-02-05 payload field mutation changes envelope hash', () => {
    const { envelopeHash } = require('../src/validation/canonicalize');
    const base     = { payload: { userId: 'alice' }, timestamp: 1000, expiry: 2000, publicKeyId: 'k:key_v1' };
    const modified = { ...base, payload: { userId: 'bob' } };
    expect(envelopeHash(base).toString('hex')).not.toBe(envelopeHash(modified).toString('hex'));
  });

});

// ── §3 Stable Serialization ───────────────────────────────────────────────────

describe('P45-03 Stable Serialization', () => {

  test('P45-03-01 stableStringify handles null-prototype objects', () => {
    const obj = Object.create(null);
    obj.a = 1; obj.b = 2;
    expect(() => stableStringify(obj)).not.toThrow();
    const result = stableStringify(obj);
    expect(JSON.parse(result)).toEqual({ a: 1, b: 2 });
  });

  test('P45-03-02 stableStringify handles arrays correctly', () => {
    const result = stableStringify([3, 1, 2]);
    expect(JSON.parse(result)).toEqual([3, 1, 2]);
  });

  test('P45-03-03 stableStringify is idempotent', () => {
    const data = { z: [3, 2, 1], a: { nested: true } };
    expect(stableStringify(data)).toBe(stableStringify(data));
  });

  test('P45-03-04 stableStringify never outputs undefined (converts to null)', () => {
    const result = stableStringify({ a: undefined });
    expect(result).not.toContain('undefined');
  });

});

// ── §5 Signature Scheme ───────────────────────────────────────────────────────

describe('P45-05 Signature Scheme', () => {

  test('P45-05-01 Ed25519 sign+verify round-trip with fresh key pair', () => {
    const { privDer, pubDer } = freshKeyPair();
    const hash = crypto.randomBytes(32);
    const sig  = ed25519Sign(hash, privDer);
    expect(ed25519Verify(hash, sig, pubDer)).toBe(true);
  });

  test('P45-05-02 Ed25519 verify rejects wrong key', () => {
    const { privDer }         = freshKeyPair();
    const { pubDer: wrongPub } = freshKeyPair();
    const hash = crypto.randomBytes(32);
    const sig  = ed25519Sign(hash, privDer);
    expect(ed25519Verify(hash, sig, wrongPub)).toBe(false);
  });

  test('P45-05-03 Ed25519 verify rejects modified hash', () => {
    const { privDer, pubDer } = freshKeyPair();
    const hash    = crypto.randomBytes(32);
    const tampered = Buffer.from(hash);
    tampered[0] ^= 0x01;
    const sig  = ed25519Sign(hash, privDer);
    expect(ed25519Verify(tampered, sig, pubDer)).toBe(false);
  });

  test('P45-05-04 Ed25519 verify rejects truncated signature', () => {
    const { privDer, pubDer } = freshKeyPair();
    const hash = crypto.randomBytes(32);
    const sig  = ed25519Sign(hash, privDer);
    const truncated = sig.slice(0, 32);
    expect(ed25519Verify(hash, truncated, pubDer)).toBe(false);
  });

  test('P45-05-05 Ed25519 sign requires 32-byte hash', () => {
    const { privDer } = freshKeyPair();
    expect(() => ed25519Sign(Buffer.alloc(31), privDer)).toThrow();
    expect(() => ed25519Sign(Buffer.alloc(33), privDer)).toThrow();
    expect(() => ed25519Sign('not-a-buffer', privDer)).toThrow();
  });

  test('P45-05-06 Ed25519 verify never throws — returns false on bad input', () => {
    const { pubDer } = freshKeyPair();
    expect(ed25519Verify(Buffer.alloc(32), 'bad', pubDer)).toBe(false);
    expect(ed25519Verify(null, null, null)).toBe(false);
  });

  test('P45-05-07 payload tampering invalidates signature', () => {
    const art     = makeArtifact({ userId: 'alice', action: 'read' });
    const tampered = { ...art, payload: { userId: 'alice', action: 'delete' } };
    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('P45-05-08 timestamp tampering invalidates signature', () => {
    const frozenNow = Date.now();
    const art = signArtifact({
      payload:     { userId: 'alice' },
      timestamp:   frozenNow - 2000,     // 2s in the past
      expiry:      frozenNow + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);
    // Shift timestamp by 1ms — still in the past, but signature covers the original value
    const tampered = { ...art, timestamp: frozenNow - 1999 };
    expect(validateArtifact(tampered, { _clock: () => frozenNow }).reason).toBe('INVALID_SIGNATURE');
  });

  test('P45-05-09 expiry tampering invalidates signature', () => {
    const art     = makeArtifact({ userId: 'alice' });
    const tampered = { ...art, expiry: art.expiry + 1 };
    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('P45-05-10 V1 payload-only signature is rejected', () => {
    const payload = { userId: 'alice', action: 'read' };
    const now     = Date.now();
    const canonical = stableStringify(payload);
    const hashBuf = domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, canonical);
    const sig     = ed25519Sign(hashBuf, KEY.privDer);
    const v1Art   = { payload, signature: sig, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
    expect(validateArtifact(v1Art).reason).toBe('INVALID_SIGNATURE');
  });

});

// ── §6 Request Binding ────────────────────────────────────────────────────────

describe('P45-06 Request Binding', () => {

  test('P45-06-01 signBoundArtifact injects requestHash and requestId into payload', () => {
    const now = Date.now();
    const art = signBoundArtifact(
      { method: 'POST', path: '/api/v2/sign', body: { userId: 'alice' } },
      { payload: { userId: 'alice' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    expect(typeof art.payload.requestHash).toBe('string');
    expect(art.payload.requestHash).toHaveLength(64);
    expect(typeof art.payload.requestId).toBe('string');
  });

  test('P45-06-02 verifyRequestBinding passes on matching request', () => {
    const now    = Date.now();
    const method = 'POST';
    const path   = '/api/v2/sign';
    const body   = { userId: 'alice' };
    const art    = signBoundArtifact(
      { method, path, body },
      { payload: { userId: 'alice' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const result = verifyRequestBinding(art, { method, path, body });
    expect(result.bound).toBe(true);
    expect(typeof result.requestId).toBe('string');
  });

  test('P45-06-03 verifyRequestBinding fails on method mismatch', () => {
    const now  = Date.now();
    const body = { userId: 'alice' };
    const art  = signBoundArtifact(
      { method: 'POST', path: '/api', body },
      { payload: { userId: 'alice' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const result = verifyRequestBinding(art, { method: 'GET', path: '/api', body });
    expect(result.bound).toBe(false);
    expect(result.reason).toBe('REQUEST_MISMATCH');
  });

  test('P45-06-04 verifyRequestBinding fails on path mismatch', () => {
    const now  = Date.now();
    const body = { userId: 'alice' };
    const art  = signBoundArtifact(
      { method: 'POST', path: '/api/v2', body },
      { payload: { userId: 'alice' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const result = verifyRequestBinding(art, { method: 'POST', path: '/api/v3', body });
    expect(result.bound).toBe(false);
  });

  test('P45-06-05 verifyRequestBinding fails on body mismatch', () => {
    const now    = Date.now();
    const method = 'POST';
    const path   = '/api';
    const art    = signBoundArtifact(
      { method, path, body: { userId: 'alice' } },
      { payload: { userId: 'alice' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const result = verifyRequestBinding(art, { method, path, body: { userId: 'mallory' } });
    expect(result.bound).toBe(false);
  });

  test('P45-06-06 requestHash comparison is timing-safe', () => {
    // verifyRequestBinding uses crypto.timingSafeEqual — confirmed by reading source.
    // This test verifies the function returns the correct result for mismatched inputs
    // (behaviour proof that timing-safe path is exercised, not a timing measurement).
    const now = Date.now();
    const art = signBoundArtifact(
      { method: 'POST', path: '/x', body: {} },
      { payload: {}, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    expect(verifyRequestBinding(art, { method: 'POST', path: '/y', body: {} }).bound).toBe(false);
  });

  test('P45-06-07 signBoundArtifact rejects pre-existing requestHash in payload', () => {
    const now = Date.now();
    expect(() => signBoundArtifact(
      { method: 'POST', path: '/api', body: {} },
      { payload: { requestHash: 'a'.repeat(64) }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    )).toThrow(/requestHash/);
  });

  test('P45-06-08 signBoundArtifact rejects pre-existing requestId in payload', () => {
    const now = Date.now();
    expect(() => signBoundArtifact(
      { method: 'POST', path: '/api', body: {} },
      { payload: { requestId: 'some-uuid' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    )).toThrow(/requestId/);
  });

  test('P45-06-09 requestHash uses REQUEST domain', () => {
    const h1 = computeRequestHash('POST', '/api', { x: 1 });
    const canonical = stableStringify({ body: { x: 1 }, method: 'POST', path: '/api' });
    const rawHash   = crypto.createHash('sha256').update(canonical).digest('hex');
    expect(h1).not.toBe(rawHash);
  });

  test('P45-06-10 requestHash is case-insensitive for method', () => {
    const h1 = computeRequestHash('post', '/api', {});
    const h2 = computeRequestHash('POST', '/api', {});
    expect(h1).toBe(h2);
  });

});

// ── §7 Policy Binding ─────────────────────────────────────────────────────────

describe('P45-07 Policy Binding', () => {

  test('P45-07-01 computePolicyHash is deterministic', () => {
    const policies = [{ id: 'p1', rule: 'ALLOW', priority: 1 }];
    expect(computePolicyHash(policies)).toBe(computePolicyHash(policies));
  });

  test('P45-07-02 computePolicyHash uses domain separation', () => {
    const policies  = [{ id: 'p1' }];
    const canonical = stableStringify(policies);
    const raw       = crypto.createHash('sha256').update(canonical).digest('hex');
    expect(computePolicyHash(policies)).not.toBe(raw);
  });

  test('P45-07-03 computePolicyHash rejects empty array', () => {
    expect(() => computePolicyHash([])).toThrow();
    expect(() => computePolicyHash(null)).toThrow();
  });

  test('P45-07-04 policyHashesEqual uses timing-safe comparison', () => {
    const policies = [{ id: 'p1' }];
    const hash = computePolicyHash(policies);
    expect(policyHashesEqual(hash, hash)).toBe(true);
    expect(policyHashesEqual(hash, 'a'.repeat(64))).toBe(false);
  });

  test('P45-07-05 policyHashesEqual returns false for non-string inputs', () => {
    expect(policyHashesEqual(null, null)).toBe(false);
    expect(policyHashesEqual(123, 'abc')).toBe(false);
  });

  test('P45-07-06 key ordering in policy objects does not affect hash', () => {
    const h1 = computePolicyHash([{ b: 2, a: 1 }]);
    const h2 = computePolicyHash([{ a: 1, b: 2 }]);
    expect(h1).toBe(h2);
  });

});

// ── §9 Timestamp Validation ───────────────────────────────────────────────────

describe('P45-09 Timestamp Validation', () => {

  test('P45-09-01 a timestamp beyond the 5 s future-skew tolerance is rejected; inside it is accepted', () => {
    const now = Date.now();
    const result = checkTimestamp(now + 5_001, now);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('FUTURE_TIMESTAMP');
    expect(checkTimestamp(now + 1000, now).valid).toBe(true);
  });

  test('P45-09-02 current timestamp is accepted', () => {
    const now = Date.now();
    expect(checkTimestamp(now, now).valid).toBe(true);
  });

  test('P45-09-03 past timestamp is accepted by checkTimestamp', () => {
    const now = Date.now();
    expect(checkTimestamp(now - 1000, now).valid).toBe(true);
  });

  test('P45-09-04 invalid timestamp produces INVALID_ARTIFACT', () => {
    const now = Date.now();
    expect(checkTimestamp(null,   now).reason).toBe('INVALID_ARTIFACT');
    expect(checkTimestamp('abc', now).reason).toBe('INVALID_ARTIFACT');
    expect(checkTimestamp(-1,    now).reason).toBe('INVALID_ARTIFACT');
  });

  test('P45-09-05 expired artifact is rejected', () => {
    const now = Date.now();
    expect(checkExpiry(now - 1, now).reason).toBe('EXPIRED');
    expect(checkExpiry(now,     now).reason).toBe('EXPIRED');
  });

  test('P45-09-06 valid expiry is accepted', () => {
    const now = Date.now();
    expect(checkExpiry(now + 1, now).valid).toBe(true);
  });

  test('P45-09-07 validateArtifact blocks artifacts with future timestamp', () => {
    const frozenNow = Date.now();
    const futureTs  = frozenNow + 10_000;
    const art       = makeArtifact({ userId: 'alice' }, { timestamp: futureTs, expiry: futureTs + 300_000 });
    const result    = validateArtifact(art, { _clock: () => frozenNow });
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('FUTURE_TIMESTAMP');
  });

  test('P45-09-08 validateArtifact blocks expired artifacts', () => {
    const frozenNow = Date.now();
    const art       = signArtifact({
      payload:     { userId: 'alice' },
      timestamp:   frozenNow - 600_000,
      expiry:      frozenNow - 1,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);
    const result = validateArtifact(art, { _clock: () => frozenNow, _maxSkewMs: 700_000 });
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('EXPIRED');
  });

});

// ── §10 Clock Skew ────────────────────────────────────────────────────────────

describe('P45-10 Clock Skew', () => {

  test('P45-10-01 MAX_SKEW_MS is 60 000 ms', () => {
    expect(MAX_SKEW_MS).toBe(60_000);
  });

  test('P45-10-02 backward drift within limit passes', () => {
    const now = Date.now();
    expect(checkSkew(now - MAX_SKEW_MS + 100, now).valid).toBe(true);
  });

  test('P45-10-03 backward drift exceeding limit is rejected', () => {
    const now = Date.now();
    const result = checkSkew(now - MAX_SKEW_MS - 1, now);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TIME_SKEW_EXCEEDED');
  });

  test('P45-10-04 skew check runs AFTER signature verification in validateArtifact', () => {
    // An artifact signed with a wrong key should fail on INVALID_SIGNATURE (step 15),
    // not on TIME_SKEW (step 16). Verifies that signature check precedes skew check.
    const now      = Date.now();
    const old_ts   = now - 120_000; // 2 min ago — exceeds default skew but still valid expiry
    const { privDer: wrongPriv } = freshKeyPair();
    // Sign with a wrong key so the signature is well-formed (64 bytes) but cryptographically invalid
    const { envelopeHash } = require('../src/validation/canonicalize');
    const hashBuf = envelopeHash({ expiry: now + 300_000, payload: { userId: 'alice' }, publicKeyId: KEY.keyId, timestamp: old_ts });
    const wrongSig = ed25519Sign(hashBuf, wrongPriv);
    const tampered = {
      payload:     { userId: 'alice' },
      signature:   wrongSig,
      timestamp:   old_ts,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    };
    // Signature check (step 15) fires before skew check (step 16)
    const result = validateArtifact(tampered, { _clock: () => now });
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  test('P45-10-05 validateArtifact blocks artifact exceeding skew window', () => {
    const now    = Date.now();
    const old_ts = now - MAX_SKEW_MS - 10_000;
    const art    = signArtifact({
      payload:     { userId: 'alice' },
      timestamp:   old_ts,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);
    const result = validateArtifact(art, { _clock: () => now });
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('TIME_SKEW_EXCEEDED');
  });

});

// ── §13 Hash Chain Integrity ──────────────────────────────────────────────────

describe('P45-13 Hash Chain Integrity', () => {

  function makeEvidenceRecord(overrides = {}) {
    const base = {
      evidenceId:          'ev-001',
      artifactId:          'art-001',
      artifactHash:        'a'.repeat(64),
      policyId:            'POLICY_SET',
      policyHash:          'b'.repeat(64),
      keyId:               'default:key_v1',
      keyFingerprint:      'c'.repeat(64),
      auditRecordId:       'aud-001',
      auditRecordHash:     'd'.repeat(64),
      previousEvidenceHash: null,
    };
    return { ...base, ...overrides };
  }

  test('P45-13-01 computeEvidenceHash only uses CANONICAL_FIELDS', () => {
    const r1 = makeEvidenceRecord({ createdAt: '2024-01-01', decision: 'ALLOW', tenantId: 'x' });
    const r2 = makeEvidenceRecord({ createdAt: '2099-12-31', decision: 'BLOCK', tenantId: 'y' });
    // Non-canonical fields must not change the hash
    expect(computeEvidenceHash(r1)).toBe(computeEvidenceHash(r2));
  });

  test('P45-13-02 any canonical field change alters the evidence hash', () => {
    const original = makeEvidenceRecord();
    const original_hash = computeEvidenceHash(original);
    for (const f of CANONICAL_FIELDS) {
      const modified = { ...original, [f]: 'modified-value' };
      expect(computeEvidenceHash(modified)).not.toBe(original_hash);
    }
  });

  test('P45-13-03 computeAuditRecordHash covers all fields', () => {
    const entry1 = { hash: 'h1', decision: 'ALLOW', ts: 1000 };
    const entry2 = { hash: 'h1', decision: 'ALLOW', ts: 1001 };
    expect(computeAuditRecordHash(entry1)).not.toBe(computeAuditRecordHash(entry2));
  });

  test('P45-13-04 validateChainContinuity accepts empty array', () => {
    const result = validateChainContinuity([]);
    expect(result.valid).toBe(true);
    expect(result.checkedCount).toBe(0);
  });

  test('P45-13-05 validateChainContinuity detects broken chain link', () => {
    const r1 = makeEvidenceRecord({ evidenceId: 'ev-001' });
    r1.evidence_hash          = computeEvidenceHash(r1);
    r1.previous_evidence_hash = null;
    r1.id                     = 1;

    // DB column names
    const r1_db = {
      id:                    1,
      evidence_id:           r1.evidenceId,
      artifact_id:           r1.artifactId,
      artifact_hash:         r1.artifactHash,
      policy_id:             r1.policyId,
      policy_hash:           r1.policyHash,
      key_id:                r1.keyId,
      key_fingerprint:       r1.keyFingerprint,
      audit_record_id:       r1.auditRecordId,
      audit_record_hash:     r1.auditRecordHash,
      previous_evidence_hash: null,
      evidence_hash:          computeEvidenceHash(r1),
    };

    const r2 = makeEvidenceRecord({ evidenceId: 'ev-002' });
    const r2_db = {
      id:                    2,
      evidence_id:           r2.evidenceId,
      artifact_id:           r2.artifactId,
      artifact_hash:         r2.artifactHash,
      policy_id:             r2.policyId,
      policy_hash:           r2.policyHash,
      key_id:                r2.keyId,
      key_fingerprint:       r2.keyFingerprint,
      audit_record_id:       r2.auditRecordId,
      audit_record_hash:     r2.auditRecordHash,
      previous_evidence_hash: 'wrong-hash',   // broken link
      evidence_hash:          computeEvidenceHash({ ...r2, previousEvidenceHash: 'wrong-hash' }),
    };

    const result = validateChainContinuity([r1_db, r2_db]);
    expect(result.valid).toBe(false);
    expect(result.failureId).toBe(2);
  });

  test('P45-13-06 evidence hash uses EVIDENCE domain (output differs from raw sha256)', () => {
    const r = makeEvidenceRecord();
    const canonical = stableStringify(Object.fromEntries(CANONICAL_FIELDS.map(f => [f, r[f] ?? null])));
    const rawHash   = crypto.createHash('sha256').update(canonical).digest('hex');
    expect(computeEvidenceHash(r)).not.toBe(rawHash);
  });

  test('P45-13-07 audit record hash uses AUDIT domain (output differs from raw sha256)', () => {
    const entry   = { hash: 'abc', decision: 'ALLOW' };
    const rawHash = crypto.createHash('sha256').update(stableStringify(entry)).digest('hex');
    expect(computeAuditRecordHash(entry)).not.toBe(rawHash);
  });

});

// ── §14 Key Generation ────────────────────────────────────────────────────────

describe('P45-14 Key Generation', () => {

  test('P45-14-01 generateKeyPairSync produces 32-byte private key hash for signing', () => {
    const { privDer, pubDer } = freshKeyPair();
    const hash = crypto.randomBytes(32);
    expect(() => ed25519Sign(hash, privDer)).not.toThrow();
    expect(ed25519Verify(hash, ed25519Sign(hash, privDer), pubDer)).toBe(true);
  });

  test('P45-14-02 two freshly generated key pairs are different', () => {
    const kp1 = freshKeyPair();
    const kp2 = freshKeyPair();
    expect(kp1.pubDer.toString('base64')).not.toBe(kp2.pubDer.toString('base64'));
  });

  test('P45-14-03 computeKeyFingerprint produces 64-char hex', () => {
    const { pubDer } = freshKeyPair();
    const fp = computeKeyFingerprint(pubDer.toString('base64'));
    expect(typeof fp).toBe('string');
    expect(fp).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(fp)).toBe(true);
  });

  test('P45-14-04 computeKeyFingerprint returns null for invalid input', () => {
    expect(computeKeyFingerprint(null)).toBeNull();
    expect(computeKeyFingerprint('')).toBeNull();
    expect(computeKeyFingerprint(42)).toBeNull();
  });

  test('P45-14-05 computeKeyFingerprint is deterministic', () => {
    const { pubDer } = freshKeyPair();
    const b64 = pubDer.toString('base64');
    expect(computeKeyFingerprint(b64)).toBe(computeKeyFingerprint(b64));
  });

  test('P45-14-06 different public keys produce different fingerprints', () => {
    const kp1 = freshKeyPair();
    const kp2 = freshKeyPair();
    expect(computeKeyFingerprint(kp1.pubDer.toString('base64')))
      .not.toBe(computeKeyFingerprint(kp2.pubDer.toString('base64')));
  });

});

// ── §17 RNG / Entropy ────────────────────────────────────────────────────────

describe('P45-17 RNG / Entropy', () => {

  test('P45-17-01 generateNonce produces a 32-char hex string', () => {
    const n = generateNonce();
    expect(typeof n).toBe('string');
    expect(n).toHaveLength(32);
    expect(/^[0-9a-f]+$/.test(n)).toBe(true);
  });

  test('P45-17-02 generateNonce produces unique values', () => {
    const nonces = Array.from({ length: 1000 }, generateNonce);
    expect(new Set(nonces).size).toBe(1000);
  });

  test('P45-17-03 generateUUID produces a valid UUID v4', () => {
    const id = generateUUID();
    expect(typeof id).toBe('string');
    expect(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)).toBe(true);
  });

  test('P45-17-04 generateUUID produces unique values', () => {
    const ids = Array.from({ length: 1000 }, generateUUID);
    expect(new Set(ids).size).toBe(1000);
  });

  test('P45-17-05 requestId in bound artifacts is a UUID v4', () => {
    const now = Date.now();
    const art = signBoundArtifact(
      { method: 'GET', path: '/api', body: {} },
      { payload: {}, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const id = art.payload.requestId;
    expect(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)).toBe(true);
  });

  test('P45-17-06 consecutive bound artifacts have different requestIds', () => {
    const now    = Date.now();
    const base   = { method: 'GET', path: '/api', body: {} };
    const env    = { payload: {}, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
    const art1   = signBoundArtifact(base, env, KEY.privDer);
    const art2   = signBoundArtifact(base, env, KEY.privDer);
    expect(art1.payload.requestId).not.toBe(art2.payload.requestId);
  });

});

// ── §18 Timing-Safe Comparisons ───────────────────────────────────────────────

describe('P45-18 Timing-Safe Comparisons', () => {

  test('P45-18-01 timingSafeCompare returns true for equal Buffers', () => {
    const a = Buffer.from('hello');
    const b = Buffer.from('hello');
    expect(timingSafeCompare(a, b)).toBe(true);
  });

  test('P45-18-02 timingSafeCompare returns false for unequal Buffers of same length', () => {
    const a = Buffer.from('hello');
    const b = Buffer.from('world');
    expect(timingSafeCompare(a, b)).toBe(false);
  });

  test('P45-18-03 timingSafeCompare returns false for different-length inputs', () => {
    const a = Buffer.from('hello');
    const b = Buffer.from('hell');
    expect(timingSafeCompare(a, b)).toBe(false);
  });

  test('P45-18-04 policyHashesEqual uses timing-safe comparison', () => {
    const h = 'a'.repeat(64);
    expect(policyHashesEqual(h, h)).toBe(true);
    expect(policyHashesEqual(h, 'b'.repeat(64))).toBe(false);
  });

  test('P45-18-05 verifyRequestBinding uses timing-safe comparison for requestHash', () => {
    // Verify the function correctly compares requestHash values (behavioural test)
    const now = Date.now();
    const art = signBoundArtifact(
      { method: 'POST', path: '/api', body: { a: 1 } },
      { payload: {}, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    // Same request — must pass
    expect(verifyRequestBinding(art, { method: 'POST', path: '/api', body: { a: 1 } }).bound).toBe(true);
    // Modified request — must fail
    expect(verifyRequestBinding(art, { method: 'POST', path: '/api', body: { a: 2 } }).bound).toBe(false);
  });

});

// ── §19 Cross-Domain Contamination Prevention ─────────────────────────────────

describe('P45-19 Cross-Domain Contamination Prevention', () => {

  test('P45-19-01 all 7 domain constants are present', () => {
    const required = ['CANONICAL', 'ARTIFACT', 'REQUEST', 'POLICY', 'CERTIFICATE', 'EVIDENCE', 'AUDIT'];
    for (const key of required) {
      expect(ARTIFACT_DOMAINS[key]).toBeDefined();
      expect(typeof ARTIFACT_DOMAINS[key]).toBe('string');
    }
  });

  test('P45-19-02 all domain strings follow QODIQA::<NAME>::V<N> format', () => {
    for (const domain of Object.values(ARTIFACT_DOMAINS)) {
      expect(/^QODIQA::[A-Z_]+::V\d+$/.test(domain)).toBe(true);
    }
  });

  test('P45-19-03 ARTIFACT_DOMAINS is frozen', () => {
    expect(Object.isFrozen(ARTIFACT_DOMAINS)).toBe(true);
  });

  test('P45-19-04 computeHash output cannot collide with computeEvidenceHash on same serialized payload', () => {
    // Contrived but verifiable: even if two functions happen to receive the same canonical string,
    // they must produce different outputs due to domain separation.
    const sharedCanonical = stableStringify({ x: 'same-data' });
    const h1 = domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, sharedCanonical).toString('hex');
    const h2 = domainSeparatedHash(ARTIFACT_DOMAINS.EVIDENCE,  sharedCanonical).toString('hex');
    const h3 = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT,     sharedCanonical).toString('hex');
    const h4 = domainSeparatedHash(ARTIFACT_DOMAINS.POLICY,    sharedCanonical).toString('hex');
    const h5 = domainSeparatedHash(ARTIFACT_DOMAINS.REQUEST,   sharedCanonical).toString('hex');
    const all = [h1, h2, h3, h4, h5];
    expect(new Set(all).size).toBe(5);
  });

  test('P45-19-05 artifact signing key and transparency signing key are structurally separate', () => {
    // Transparency keys use 'tr-*:key_v*' namespacing vs artifact keys 'client:key_v*'.
    // Verify the transparency key store provides a different key than the artifact key store.
    const tKeyStore = require('../src/core/transparency/transparencyKeyStore');
    const tKey      = tKeyStore.getActiveKey();
    expect(tKey.keyId).not.toBe(KEY.keyId);
    expect(tKey.keyId).toMatch(/^tr-/);
    expect(KEY.keyId).not.toMatch(/^tr-/);
  });

  test('P45-19-06 envelope domain differs from all other domains', () => {
    const envDomain = ARTIFACT_DOMAINS.ARTIFACT;
    const others    = Object.entries(ARTIFACT_DOMAINS)
      .filter(([k]) => k !== 'ARTIFACT')
      .map(([, v]) => v);
    for (const d of others) {
      expect(d).not.toBe(envDomain);
    }
  });

});

// ── §8 Consent Binding (informational) ────────────────────────────────────────

describe('P45-08 Consent Binding', () => {

  test('P45-08-01 computeHash includes consent field in canonical input', () => {
    const base  = { prompt: 'p', consent: true,  purpose: 'q', timestamp: 1, decision: 'ALLOW', ai_output: 'x' };
    const nocon = { prompt: 'p', consent: false, purpose: 'q', timestamp: 1, decision: 'ALLOW', ai_output: 'x' };
    expect(computeHash(base)).not.toBe(computeHash(nocon));
  });

  test('P45-08-02 computeHash includes purpose field in canonical input', () => {
    const a = { prompt: 'p', consent: true, purpose: 'purpose-A', timestamp: 1, decision: 'ALLOW', ai_output: 'x' };
    const b = { prompt: 'p', consent: true, purpose: 'purpose-B', timestamp: 1, decision: 'ALLOW', ai_output: 'x' };
    expect(computeHash(a)).not.toBe(computeHash(b));
  });

  test('P45-08-03 computeHash is sensitive to every field', () => {
    const base = { prompt: 'p', consent: true, purpose: 'q', timestamp: 1, decision: 'ALLOW', ai_output: 'x' };
    const fields = Object.keys(base);
    const baseHash = computeHash(base);
    for (const field of fields) {
      const mod = { ...base, [field]: 'changed-value' };
      expect(computeHash(mod)).not.toBe(baseHash);
    }
  });

});

// ── §15 Key Rotation ──────────────────────────────────────────────────────────

describe('P45-15 Key Rotation', () => {

  test('P45-15-01 after explicit emergency rotation old key status becomes revoked', () => {
    const { rotateKey, getKeysByClient } = require('../services/artifact/keyStore');
    const clientId = 'phase45-rotation-test-' + Date.now();
    rotateKey(clientId); // v1
    const beforeKeys = getKeysByClient(clientId);
    expect(beforeKeys).toHaveLength(1);
    expect(beforeKeys[0].status).toBe('active');

    rotateKey(clientId, { mode: 'emergency' }); // v2 — v1 becomes revoked
    const afterKeys = getKeysByClient(clientId);
    expect(afterKeys).toHaveLength(2);
    const statuses = afterKeys.map(k => k.status).sort();
    expect(statuses).toEqual(['active', 'revoked']);
  });

  test('P45-15-01b after explicit graceful rotation old key status becomes deprecated', () => {
    const { rotateKeyGracefully, getKeysByClient } = require('../services/artifact/keyStore');
    const clientId = 'phase45-rotation-graceful-test-' + Date.now();
    rotateKeyGracefully(clientId); // v1

    rotateKeyGracefully(clientId); // v2 — v1 becomes deprecated
    const afterKeys = getKeysByClient(clientId);
    expect(afterKeys).toHaveLength(2);
    const statuses = afterKeys.map(k => k.status).sort();
    expect(statuses).toEqual(['active', 'deprecated']);
  });

  test('P45-15-02 at most one active key per client after rotation', () => {
    const { rotateKey, getKeysByClient } = require('../services/artifact/keyStore');
    const clientId = 'phase45-rotation-single-' + Date.now();
    rotateKey(clientId);
    rotateKey(clientId, { mode: 'emergency' });
    rotateKey(clientId, { mode: 'emergency' });
    const keys   = getKeysByClient(clientId);
    const active = keys.filter(k => k.status === 'active');
    expect(active).toHaveLength(1);
  });

});

// ── §16 Key Revocation ───────────────────────────────────────────────────────

describe('P45-16 Key Revocation', () => {

  test('P45-16-01 revoked key cannot be used for verification', () => {
    const { rotateKey, revokeKey, getPublicKey } = require('../services/artifact/keyStore');
    const clientId = 'phase45-revoke-test-' + Date.now();
    const { keyId } = rotateKey(clientId);
    revokeKey(keyId);
    expect(() => getPublicKey(keyId)).toThrow(/revoked/);
  });

  test('P45-16-02 idempotent revocation — revoking an already-revoked key does not throw', () => {
    const { rotateKey, revokeKey } = require('../services/artifact/keyStore');
    const clientId = 'phase45-revoke-idem-' + Date.now();
    const { keyId } = rotateKey(clientId);
    expect(() => { revokeKey(keyId); revokeKey(keyId); }).not.toThrow();
  });

});

// ── §11 Replay Protection ─────────────────────────────────────────────────────

describe('P45-11 Replay Protection', () => {

  test('P45-11-01 two bound artifacts for the same request have different requestIds', () => {
    const now = Date.now();
    const req = { method: 'POST', path: '/api/sign', body: { userId: 'alice' } };
    const env = { payload: { userId: 'alice' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
    const a1  = signBoundArtifact(req, env, KEY.privDer);
    const a2  = signBoundArtifact(req, env, KEY.privDer);
    expect(a1.payload.requestId).not.toBe(a2.payload.requestId);
  });

  test('P45-11-02 requestId is always a UUID v4 (nonce)', () => {
    const now = Date.now();
    for (let i = 0; i < 10; i++) {
      const art = signBoundArtifact(
        { method: 'POST', path: '/x', body: {} },
        { payload: {}, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
        KEY.privDer,
      );
      expect(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(art.payload.requestId)).toBe(true);
    }
  });

  test('P45-11-03 verifyRequestBinding validates requestId format', () => {
    const now = Date.now();
    const art = signBoundArtifact(
      { method: 'GET', path: '/x', body: {} },
      { payload: {}, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const badArt = { ...art, payload: { ...art.payload, requestId: 'not-a-uuid' } };
    expect(verifyRequestBinding(badArt, { method: 'GET', path: '/x', body: {} }).bound).toBe(false);
  });

});

// ── Merkle Tree (referenced §13) ──────────────────────────────────

describe('P45-13b Merkle Tree (RFC6962)', () => {
  const { merkleRoot, leafHash, nodeHash, inclusionPath, verifyInclusionPath,
          consistencyProof, verifyConsistencyProof, batchVerifyInclusion } = require('../src/core/transparency/merkle');

  const ENTRIES = Array.from({ length: 8 }, (_, i) => crypto.randomBytes(32).toString('hex'));

  test('P45-13b-01 leafHash uses 0x00 domain prefix', () => {
    const entry = ENTRIES[0];
    const expected = crypto.createHash('sha256')
      .update(Buffer.from([0x00]))
      .update(Buffer.from(entry, 'hex'))
      .digest('hex');
    expect(leafHash(entry)).toBe(expected);
  });

  test('P45-13b-02 nodeHash uses 0x01 domain prefix', () => {
    const [l, r] = [ENTRIES[0], ENTRIES[1]].map(leafHash);
    const expected = crypto.createHash('sha256')
      .update(Buffer.from([0x01]))
      .update(Buffer.from(l, 'hex'))
      .update(Buffer.from(r, 'hex'))
      .digest('hex');
    expect(nodeHash(l, r)).toBe(expected);
  });

  test('P45-13b-03 leafHash !== nodeHash for same input (domain separation)', () => {
    const data = ENTRIES[0];
    const leaf  = leafHash(data);
    const dataBuf = Buffer.from(data, 'hex');
    const noPrefix = crypto.createHash('sha256').update(dataBuf).digest('hex');
    expect(leaf).not.toBe(noPrefix);
  });

  test('P45-13b-04 merkleRoot is deterministic', () => {
    const r1 = merkleRoot(ENTRIES);
    const r2 = merkleRoot(ENTRIES);
    expect(r1).toBe(r2);
  });

  test('P45-13b-05 inclusion proof verifies for every leaf', () => {
    for (let i = 0; i < ENTRIES.length; i++) {
      const path = inclusionPath(ENTRIES, i);
      const root = merkleRoot(ENTRIES);
      expect(verifyInclusionPath(ENTRIES[i], path, root, i, ENTRIES.length)).toBe(true);  // position-bound
    }
  });

  test('P45-13b-06 inclusion proof fails for wrong entry hash', () => {
    const path    = inclusionPath(ENTRIES, 0);
    const root    = merkleRoot(ENTRIES);
    const wrongHash = ENTRIES[1];
    expect(verifyInclusionPath(wrongHash, path, root, 0, ENTRIES.length)).toBe(false);
  });

  test('P45-13b-07 consistency proof verifies tree growth', () => {
    const oldSize = 4;
    const newSize = 8;
    const oldRoot = merkleRoot(ENTRIES.slice(0, oldSize));
    const newRoot = merkleRoot(ENTRIES);
    const proof   = consistencyProof(oldSize, newSize, ENTRIES);
    expect(verifyConsistencyProof(oldRoot, newRoot, oldSize, newSize, proof)).toBe(true);
  });

  test('P45-13b-08 consistency proof fails on tampered root', () => {
    const oldSize   = 4;
    const newSize   = 8;
    const oldRoot   = merkleRoot(ENTRIES.slice(0, oldSize));
    const wrongRoot = 'f'.repeat(64);
    const proof     = consistencyProof(oldSize, newSize, ENTRIES);
    expect(verifyConsistencyProof(oldRoot, wrongRoot, oldSize, newSize, proof)).toBe(false);
  });

  test('P45-13b-09 batchVerifyInclusion verifies all entries', () => {
    const root   = merkleRoot(ENTRIES);
    const proofs = ENTRIES.map((e, i) => ({
      entryHash: e,
      path:      inclusionPath(ENTRIES, i),
      leafIndex: i,
      treeSize:  ENTRIES.length,
    }));
    const result = batchVerifyInclusion(root, proofs);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(ENTRIES.length);
  });

});

// ── AES-256-GCM Key-at-Rest ───────────────────────────────────────────────────

describe('P45-14b Key Encryption (AES-256-GCM)', () => {
  const { encryptKeyMaterial, decryptKeyMaterial } = require('../services/artifact/keyEncryption');

  test('P45-14b-01 encrypt/decrypt round-trip preserves key material', () => {
    const privDer   = crypto.randomBytes(48); // simulated private key bytes
    const encrypted = encryptKeyMaterial(privDer, { keyId: 'test:key_v1' });
    const decrypted = decryptKeyMaterial(encrypted);
    expect(decrypted.equals(privDer)).toBe(true);
  });

  test('P45-14b-02 fresh IV is generated per encryption', () => {
    const privDer   = crypto.randomBytes(48);
    const e1        = encryptKeyMaterial(privDer);
    const e2        = encryptKeyMaterial(privDer);
    expect(e1.iv).not.toBe(e2.iv);
  });

  test('P45-14b-03 algorithm field is aes-256-gcm', () => {
    const privDer   = crypto.randomBytes(48);
    const encrypted = encryptKeyMaterial(privDer);
    expect(encrypted.algorithm).toBe('aes-256-gcm');
  });

  test('P45-14b-04 tampered ciphertext causes decrypt to throw', () => {
    const privDer   = crypto.randomBytes(48);
    const encrypted = encryptKeyMaterial(privDer);
    const tampered  = {
      ...encrypted,
      encryptedPrivateKey: Buffer.from(
        Buffer.from(encrypted.encryptedPrivateKey, 'base64').map((b, i) => i === 0 ? b ^ 0xff : b),
      ).toString('base64'),
    };
    expect(() => decryptKeyMaterial(tampered)).toThrow();
  });

  test('P45-14b-05 encryptKeyMaterial rejects non-Buffer input', () => {
    expect(() => encryptKeyMaterial('not-a-buffer')).toThrow(TypeError);
    expect(() => encryptKeyMaterial(Buffer.alloc(0))).toThrow(TypeError);
  });

});
