'use strict';

/**
 * Cryptographic validation test suite for validateArtifact() — V2 signing.
 *
 * Test cases:
 *   1.  Valid artifact                          → ALLOW
 *   2.  Tampered payload                        → BLOCK / INVALID_SIGNATURE
 *   3.  Wrong key                               → BLOCK / INVALID_SIGNATURE
 *   4.  Expired artifact                        → BLOCK / EXPIRED
 *   5.  Future timestamp                        → BLOCK / FUTURE_TIMESTAMP
 *   6.  Missing required fields                 → BLOCK / MALFORMED_ARTIFACT
 *   7.  Corrupted (truncated) signature         → BLOCK / MALFORMED_ARTIFACT
 *   8.  Unknown publicKeyId                     → BLOCK / KEY_NOT_FOUND
 */

const crypto = require('crypto');

const { validateArtifact }  = require('../validateArtifact');
const { signArtifact }      = require('../signArtifact');
const { getActiveKey }      = require('../../../services/artifact/keyStore');

// ── Test helpers ──────────────────────────────────────────────────────────────

function freshKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  return { privDer: Buffer.from(privateKey), pubDer: Buffer.from(publicKey) };
}

/**
 * Build a correctly-signed V2 artifact and optionally tamper with it.
 *
 * @param {object} payload       — what to sign
 * @param {Buffer} privDer       — signing private key (PKCS8 DER)
 * @param {string} publicKeyId   — key ID to embed in the artifact
 * @param {object} [tamper]      — raw field overrides applied AFTER signing
 *                                 (intended to simulate post-signing tampering)
 */
function buildArtifact(payload, privDer, publicKeyId, tamper = {}) {
  const now = Date.now();
  const art = signArtifact({ payload, timestamp: now, expiry: now + 300_000, publicKeyId }, privDer);
  return Object.keys(tamper).length ? { ...art, ...tamper } : art;
}

// ── Suite setup ───────────────────────────────────────────────────────────────

let activeKeyId;
let activePrivDer;

beforeAll(() => {
  const key   = getActiveKey('default');
  activeKeyId = key.keyId;
  activePrivDer = key.privDer;
});

// ── Test cases ────────────────────────────────────────────────────────────────

describe('validateArtifact()', () => {

  // ── 1. Valid artifact → ALLOW ───────────────────────────────────────────────
  test('TC-01  valid artifact is allowed', () => {
    const payload  = { userId: 'alice', action: 'query', resource: 'dataset-42' };
    const artifact = buildArtifact(payload, activePrivDer, activeKeyId);

    const result = validateArtifact(artifact);

    expect(result.decision).toBe('EXECUTE');
    expect(result.reason).toBe('ALL_CHECKS_PASSED');
    expect(result.details.publicKeyId).toBe(activeKeyId);
  });

  // ── 2. Tampered payload → BLOCK / INVALID_SIGNATURE ────────────────────────
  test('TC-02  tampered payload is blocked with INVALID_SIGNATURE', () => {
    const payload  = { userId: 'alice', action: 'query' };
    const artifact = buildArtifact(payload, activePrivDer, activeKeyId);

    const tampered = { ...artifact, payload: { ...payload, action: 'admin-delete' } };

    const result = validateArtifact(tampered);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  // ── 3. Wrong key → BLOCK / INVALID_SIGNATURE ───────────────────────────────
  test('TC-03  signature from a different key is blocked with INVALID_SIGNATURE', () => {
    const { privDer: wrongPriv } = freshKeyPair();
    // buildArtifact signs with wrongPriv but artifact claims activeKeyId.
    const artifact = buildArtifact({ userId: 'bob', action: 'read' }, wrongPriv, activeKeyId);

    const result = validateArtifact(artifact);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  // ── 4. Expired artifact → BLOCK / EXPIRED ──────────────────────────────────
  test('TC-04  artifact past its expiry is blocked with EXPIRED', () => {
    const frozenNow = Date.now();
    const payload   = { userId: 'carol', action: 'write' };

    // Sign with an expiry that is already in the past.
    const artifact = signArtifact({
      payload,
      timestamp:   frozenNow - 5_000,
      expiry:      frozenNow - 1,    // expired 1ms ago
      publicKeyId: activeKeyId,
    }, activePrivDer);

    const result = validateArtifact(artifact, { _clock: () => frozenNow });

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('EXPIRED');
  });

  // ── 5. Future timestamp → BLOCK / FUTURE_TIMESTAMP ─────────────────────────
  test('TC-05  artifact with future timestamp is blocked with FUTURE_TIMESTAMP', () => {
    const frozenNow = Date.now();
    const payload   = { userId: 'dave', action: 'invoke' };

    const artifact = signArtifact({
      payload,
      timestamp:   frozenNow + 60_001,
      expiry:      frozenNow + 360_001,
      publicKeyId: activeKeyId,
    }, activePrivDer);

    const result = validateArtifact(artifact, { _clock: () => frozenNow });

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('FUTURE_TIMESTAMP');
  });

  // ── 6. Missing required fields → BLOCK / MALFORMED_ARTIFACT ────────────────
  describe('TC-06  missing required fields', () => {
    const FIELDS = ['payload', 'signature', 'timestamp', 'expiry', 'publicKeyId'];

    FIELDS.forEach(field => {
      test(`missing field: ${field}`, () => {
        const artifact = buildArtifact({ userId: 'eve', action: 'list' }, activePrivDer, activeKeyId);
        const partial  = { ...artifact };
        delete partial[field];

        const result = validateArtifact(partial);

        expect(result.decision).toBe('BLOCK');
        expect(result.reason).toBe('INVALID_ARTIFACT');
        expect(result.details.missing).toBe(field);
      });
    });

    test('null artifact', () => {
      expect(validateArtifact(null).reason).toBe('INVALID_ARTIFACT');
    });

    test('string artifact', () => {
      expect(validateArtifact('not-an-object').reason).toBe('INVALID_ARTIFACT');
    });
  });

  // ── 7. Corrupted signature → BLOCK / MALFORMED_ARTIFACT ────────────────────
  test('TC-07 truncated signature is blocked with INVALID_SIGNATURE', () => {
    const artifact  = buildArtifact({ userId: 'frank', action: 'delete' }, activePrivDer, activeKeyId);
    const corrupted = { ...artifact, signature: artifact.signature.slice(0, 40) };

    const result = validateArtifact(corrupted);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
    expect(result.details.field).toBe('signature');
  });

  // ── 8. Unknown publicKeyId → BLOCK / INVALID_SIGNATURE (CRYPTO-5) ──────────
  // CRYPTO-5/VERIFY-4: an unresolved key no longer short-circuits with its
  // own distinguishable KEY_NOT_FOUND reason — it falls through to signature
  // verification (against a null key sentinel, which always fails), so an
  // unknown key is indistinguishable from a wrong signature. See
  // fullEnvelopeSigning.test.js TC-4a for the dedicated regression test.
  test('TC-08  unregistered publicKeyId is blocked with INVALID_SIGNATURE, not a distinguishable KEY_NOT_FOUND', () => {
    const artifact = buildArtifact({ userId: 'grace', action: 'export' }, activePrivDer, 'unknown:key_v99');

    const result = validateArtifact(artifact);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  // ── 9. Time skew (backward) → BLOCK / TIME_SKEW_EXCEEDED ───────────────────
  describe('numeric strictness of timestamp / expiry (SPEC 1.0.1 S-069, S-074)', () => {
    const sign = (timestamp, expiry) => signArtifact({ payload: { userId: 'zed', action: 'read' }, timestamp, expiry, publicKeyId: activeKeyId }, activePrivDer);

    test('F2-NUM-01 a fractional timestamp is INVALID_ARTIFACT', () => {
      const now = Date.now();
      const r = validateArtifact(sign(now + 0.5, now + 300_000), { _clock: () => now });
      expect(r).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_ARTIFACT' });
    });
    test('F2-NUM-02 an expiry above 2^53-1 is INVALID_ARTIFACT', () => {
      const now = Date.now();
      const r = validateArtifact(sign(now, 2 ** 53 + 2), { _clock: () => now });
      expect(r).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_ARTIFACT' });
    });
    test('F2-NUM-03 timestamp >= expiry is refused even when both lie inside the validity window (signed by a foreign signer)', () => {
      // signArtifact() itself refuses such an envelope, so sign the envelope hash directly (a signer that does not share this check)
      const { envelopeHash } = require('../canonicalize');
      const { sign: edSign } = require('../../infra/crypto/ed25519');
      const mk = (timestamp, expiry) => {
        const payload = { userId: 'zed', action: 'read' };
        return { payload, timestamp, expiry, publicKeyId: activeKeyId, signature: edSign(envelopeHash({ expiry, payload, publicKeyId: activeKeyId, timestamp }), activePrivDer) };
      };
      const now = Date.now();
      expect(validateArtifact(mk(now + 4_000, now + 1_000), { _clock: () => now })).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_ARTIFACT' });
      expect(validateArtifact(mk(now + 1_000, now + 1_000), { _clock: () => now })).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_ARTIFACT' });
    });
    test('F2-NUM-04 a well-formed pair still passes', () => {
      const now = Date.now();
      expect(validateArtifact(sign(now, now + 300_000), { _clock: () => now }).decision).toBe('EXECUTE');
    });
  });

  describe('TC-09  backward skew enforcement', () => {

    test('TC-09a  timestamp exactly at skew window boundary → ALLOW', () => {
      const maxSkewMs = 5_000;
      const frozenNow = Date.now();
      const artifact  = signArtifact({
        payload:     { userId: 'henry', action: 'read' },
        timestamp:   frozenNow - maxSkewMs,   // exactly at the boundary
        expiry:      frozenNow + 300_000,
        publicKeyId: activeKeyId,
      }, activePrivDer);

      const result = validateArtifact(artifact, { _clock: () => frozenNow, _maxSkewMs: maxSkewMs });

      expect(result.decision).toBe('EXECUTE');
    });

    test('TC-09b  timestamp 1ms beyond skew window → BLOCK TIME_SKEW_EXCEEDED', () => {
      const maxSkewMs = 5_000;
      const frozenNow = Date.now();
      const artifact  = signArtifact({
        payload:     { userId: 'ivan', action: 'write' },
        timestamp:   frozenNow - (maxSkewMs + 1),
        expiry:      frozenNow + 300_000,
        publicKeyId: activeKeyId,
      }, activePrivDer);

      const result = validateArtifact(artifact, { _clock: () => frozenNow, _maxSkewMs: maxSkewMs });

      expect(result.decision).toBe('BLOCK');
      expect(result.reason).toBe('TIME_SKEW_EXCEEDED');
      expect(result.details.maxSkewMs).toBe(maxSkewMs);
    });

    test('TC-09c  stale artifact still within expiry but beyond skew → BLOCK', () => {
      // Demonstrates that expiry alone is not sufficient; skew check fires first.
      const maxSkewMs = 10_000;
      const frozenNow = Date.now();
      const artifact  = signArtifact({
        payload:     { userId: 'judy', action: 'invoke' },
        timestamp:   frozenNow - 60_000,   // 60s old — beyond 10s skew window
        expiry:      frozenNow + 240_000,  // still valid expiry
        publicKeyId: activeKeyId,
      }, activePrivDer);

      const result = validateArtifact(artifact, { _clock: () => frozenNow, _maxSkewMs: maxSkewMs });

      expect(result.decision).toBe('BLOCK');
      expect(result.reason).toBe('TIME_SKEW_EXCEEDED');
    });

    test('TC-09d  fresh artifact (skew = 0) always passes skew check', () => {
      const frozenNow = Date.now();
      const artifact  = signArtifact({
        payload:     { userId: 'kate', action: 'query' },
        timestamp:   frozenNow,
        expiry:      frozenNow + 300_000,
        publicKeyId: activeKeyId,
      }, activePrivDer);

      const result = validateArtifact(artifact, { _clock: () => frozenNow });

      expect(result.decision).toBe('EXECUTE');
    });

    test('TC-09e  details include skewMs and maxSkewMs on rejection', () => {
      const maxSkewMs = 1_000;
      const frozenNow = Date.now();
      const artifact  = signArtifact({
        payload:     { userId: 'leo', action: 'read' },
        timestamp:   frozenNow - 5_000,
        expiry:      frozenNow + 300_000,
        publicKeyId: activeKeyId,
      }, activePrivDer);

      const result = validateArtifact(artifact, { _clock: () => frozenNow, _maxSkewMs: maxSkewMs });

      expect(result.decision).toBe('BLOCK');
      expect(result.reason).toBe('TIME_SKEW_EXCEEDED');
      expect(typeof result.details.skewMs).toBe('number');
      expect(result.details.skewMs).toBeGreaterThan(maxSkewMs);
      expect(result.details.maxSkewMs).toBe(maxSkewMs);
    });

  });

  // ── 10. payload.tenantId must be the signing key's own tenant ───────
  describe('TC-10 payload tenant bound to the signing key', () => {

    test('a payload claiming another tenant, validly signed, is blocked with INVALID_ARTIFACT', () => {
      const artifact = buildArtifact({ userId: 'mallory', action: 'query', tenantId: 'some-other-tenant' }, activePrivDer, activeKeyId);

      const result = validateArtifact(artifact);

      expect(result.decision).toBe('BLOCK');
      expect(result.reason).toBe('INVALID_ARTIFACT');
      expect(result.details.field).toBe('payload.tenantId');
    });

    test("a payload naming the signing key's own tenant is allowed", () => {
      const ownTenant = activeKeyId.split(':')[0];
      const artifact  = buildArtifact({ userId: 'alice', action: 'query', tenantId: ownTenant }, activePrivDer, activeKeyId);

      expect(validateArtifact(artifact).decision).toBe('EXECUTE');
    });

  });

});
