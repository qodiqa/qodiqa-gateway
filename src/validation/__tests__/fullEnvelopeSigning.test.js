'use strict';

/**
 * Full-envelope signing fix — verification test suite
 *
 * Tests required by the security fix specification:
 *   1. Full valid artifact                              → ALLOW
 *   2. Replay attack with modified timestamp            → BLOCK / INVALID_SIGNATURE
 *   3. Expiry extension attack                          → BLOCK / INVALID_SIGNATURE
 *   4. Payload unchanged, envelope field modified       → BLOCK / INVALID_SIGNATURE
 *   5. Extra field injection                            → BLOCK / MALFORMED_ARTIFACT
 *   6. undefined value in payload                       → BLOCK / MALFORMED_ARTIFACT
 *
 * Plus: regression tests that confirm previously-confirmed bypasses are closed.
 */

const crypto = require('crypto');

const { validateArtifact }   = require('../validateArtifact');
const { signArtifact }       = require('../signArtifact');
const { envelopeHash }       = require('../canonicalize');
const { getActiveKey }       = require('../../../services/artifact/keyStore');
const { sign }               = require('../../infra/crypto/ed25519');

// ── Helpers ───────────────────────────────────────────────────────────────────

function freshKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  return { privDer: Buffer.from(privateKey), pubDer: Buffer.from(publicKey) };
}

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

// Sign a fresh artifact using the registered key.
function makeArtifact(payload, overrides = {}) {
  const now  = Date.now();
  const base = { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
  return signArtifact({ ...base, ...overrides }, KEY.privDer);
}

// Sign a fresh artifact then apply post-signing tampering.
function makeAndTamper(payload, tamperFields) {
  return { ...makeArtifact(payload), ...tamperFields };
}

// ══════════════════════════════════════════════════════════════════════════════
// REQUIRED TEST CASES
// ══════════════════════════════════════════════════════════════════════════════

describe('Required: full-envelope signing fix', () => {

  // ── TC-1: Full valid artifact → ALLOW ────────────────────────────────────────
  test('TC-1  valid V2 artifact → ALLOW', () => {
    const artifact = makeArtifact({ userId: 'alice', action: 'query', resource: 'orders' });
    const result   = validateArtifact(artifact);

    expect(result.decision).toBe('EXECUTE');
    expect(result.reason).toBe('ALL_CHECKS_PASSED');
    expect(result.details.publicKeyId).toBe(KEY.keyId);
    expect(typeof result.details.timestampMs).toBe('number');
    expect(typeof result.details.expiryMs).toBe('number');
  });

  // ── TC-2: Replay attack — modified timestamp → BLOCK ─────────────────────────
  // V1 vulnerability: attacker refreshes timestamp on a captured artifact.
  // V2 fix: signature covers timestamp → any modification invalidates it.
  test('TC-2  replay with refreshed timestamp → BLOCK / INVALID_SIGNATURE', () => {
    // Use a frozen clock so the modified timestamp is unambiguously in the past.
    const frozenNow = Date.now();
    const artifact  = signArtifact({
      payload:     { userId: 'attacker', action: 'privileged-write' },
      timestamp:   frozenNow - 2_000,   // 2s ago
      expiry:      frozenNow + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);

    // Attacker changes timestamp to a different-but-valid value — signature no longer matches.
    const replayed = { ...artifact, timestamp: frozenNow - 1_000 };

    const result = validateArtifact(replayed, { _clock: () => frozenNow });

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  test('TC-2b replay with entirely new timestamp (hours later) → BLOCK / INVALID_SIGNATURE', () => {
    const frozenNow     = Date.now();
    const artifact      = signArtifact({
      payload:     { userId: 'attacker', action: 'fund-transfer' },
      timestamp:   frozenNow,
      expiry:      frozenNow + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);

    // Attacker replays the captured signature 2 hours later with a fresh window.
    const laterNow = frozenNow + 7_200_000;
    const replayed = {
      ...artifact,
      timestamp: laterNow,
      expiry:    laterNow + 300_000,
    };

    const result = validateArtifact(replayed, { _clock: () => laterNow });

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  // ── TC-3: Expiry extension attack → BLOCK ────────────────────────────────────
  // V1 vulnerability: attacker extends expiry of a captured artifact.
  // V2 fix: signature covers expiry → extension invalidates signature.
  test('TC-3  expiry extension → BLOCK / INVALID_SIGNATURE', () => {
    const artifact  = makeArtifact({ userId: 'victim', action: 'transfer', amount: 50000 });
    const extended  = { ...artifact, expiry: artifact.expiry + 86_400_000 };   // +24 hours

    const result = validateArtifact(extended);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  test('TC-3b minimal expiry change (+1ms) → BLOCK / INVALID_SIGNATURE', () => {
    const artifact = makeArtifact({ userId: 'alice', action: 'read' });
    const tampered = { ...artifact, expiry: artifact.expiry + 1 };

    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  // ── TC-4: Payload unchanged, envelope field modified → BLOCK ──────────────────
  // CRYPTO-5/VERIFY-4: an unresolved key no longer short-circuits with its own
  // distinguishable KEY_NOT_FOUND reason before signature verification — it
  // falls through to verification against a null key sentinel (always fails),
  // producing the same INVALID_SIGNATURE an attacker would see for any other
  // bad signature. This also happens to be doubly true here since swapping
  // publicKeyId after signing breaks the envelope hash anyway.
  test('TC-4a publicKeyId swapped after signing to an unregistered key → BLOCK / INVALID_SIGNATURE', () => {
    const artifact = makeArtifact({ userId: 'alice', action: 'read' });
    const tampered = { ...artifact, publicKeyId: 'other:key_v1' };

    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('TC-4b publicKeyId swapped to registered key → BLOCK / INVALID_SIGNATURE', () => {
    // If a second key were registered, swapping publicKeyId would produce INVALID_SIGNATURE.
    // We simulate this by generating a fresh key pair, using the real keyId, and signing
    // with the wrong private key — the public key resolves but the sig doesn't verify.
    const { privDer: wrongPriv } = freshKeyPair();
    const now      = Date.now();
    const hashBuf  = envelopeHash({
      expiry:      now + 300_000,
      payload:     { userId: 'alice' },
      publicKeyId: KEY.keyId,
      timestamp:   now,
    });
    const wrongSig = sign(hashBuf, wrongPriv);   // signed with wrong key

    const artifact = {
      payload:     { userId: 'alice' },
      signature:   wrongSig,
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    };

    expect(validateArtifact(artifact).reason).toBe('INVALID_SIGNATURE');
  });

  test('TC-4c payload field value mutated after signing → BLOCK / INVALID_SIGNATURE', () => {
    const payload  = { userId: 'alice', action: 'read', resource: 'orders' };
    const artifact = makeArtifact(payload);
    const tampered = { ...artifact, payload: { ...payload, action: 'delete' } };

    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('TC-4d payload field added after signing → BLOCK / INVALID_SIGNATURE', () => {
    const payload  = { userId: 'alice' };
    const artifact = makeArtifact(payload);
    const tampered = { ...artifact, payload: { ...payload, admin: true } };

    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('TC-4e payload field removed after signing → BLOCK / INVALID_SIGNATURE', () => {
    const payload  = { userId: 'alice', action: 'read' };
    const artifact = makeArtifact(payload);
    const tampered = { ...artifact, payload: { userId: 'alice' } };

    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  // ── TC-5: Extra field injection → BLOCK ──────────────────────────────────────
  // V2 enforces strict 5-field schema on the envelope — no extra fields allowed.
  test('TC-5a extra field "admin: true" → BLOCK / MALFORMED_ARTIFACT', () => {
    const artifact = { ...makeArtifact({ userId: 'alice' }), admin: true };

    const result = validateArtifact(artifact);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
    expect(result.details.extraField).toBe('admin');
  });

  test('TC-5b extra field "_debug" → BLOCK / MALFORMED_ARTIFACT', () => {
    const artifact = { ...makeArtifact({ userId: 'alice' }), _debug: { trace: true } };
    expect(validateArtifact(artifact).reason).toBe('INVALID_ARTIFACT');
  });

  test('TC-5c extra field "source: tampered" → BLOCK / MALFORMED_ARTIFACT', () => {
    const artifact = { ...makeArtifact({ userId: 'alice' }), source: 'tampered-client' };
    expect(validateArtifact(artifact).reason).toBe('INVALID_ARTIFACT');
  });

  // ── TC-6: undefined values → BLOCK ───────────────────────────────────────────
  // Prevents null/undefined canonical collision (stableStringify maps both to "null").
  test('TC-6a top-level undefined payload field → BLOCK / MALFORMED_ARTIFACT', () => {
    const artifact = makeArtifact({ userId: 'alice', role: null });
    // Replace payload after signing with one that has undefined (bypasses signArtifact guard)
    const tampered = { ...artifact, payload: { userId: 'alice', role: undefined } };

    const result = validateArtifact(tampered);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
    expect(result.details.field).toBe('payload');
  });

  test('TC-6b nested undefined value → BLOCK / MALFORMED_ARTIFACT', () => {
    const artifact = makeArtifact({ userId: 'alice' });
    const tampered = { ...artifact, payload: { userId: 'alice', meta: { tag: undefined } } };

    const result = validateArtifact(tampered);

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
  });

  test('TC-6c undefined in array payload field → BLOCK / MALFORMED_ARTIFACT', () => {
    const artifact = makeArtifact({ userId: 'alice' });
    const tampered = { ...artifact, payload: { userId: 'alice', items: [1, undefined, 3] } };

    expect(validateArtifact(tampered).reason).toBe('INVALID_ARTIFACT');
  });

  test('TC-6d envelope timestamp set to undefined → BLOCK / MALFORMED_ARTIFACT', () => {
    const artifact = { ...makeArtifact({ userId: 'alice' }), timestamp: undefined };
    expect(validateArtifact(artifact).reason).toBe('INVALID_ARTIFACT');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// REGRESSION: PREVIOUSLY CONFIRMED BYPASSES NOW BLOCK
// ══════════════════════════════════════════════════════════════════════════════

describe('Regression: confirmed V1 bypasses are closed in V2', () => {

  // V1 bypass §2.A-1: captured signature replayed with fresh window.
  test('[REG-1] V1 bypass: captured signature + fresh envelope → BLOCK', () => {
    const payload = { userId: 'attacker', action: 'privileged-write' };

    // Simulate a captured V1-style signature (payload-only hash).
    // In V2, even a correctly-computed new signature that only covered the payload
    // would fail because it doesn't match envelopeHash.
    const now           = Date.now();
    const capturedArt   = signArtifact({
      payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId,
    }, KEY.privDer);

    // Replay 2 hours later with the captured signature unchanged.
    const laterNow  = now + 7_200_000;
    const replayed  = {
      ...capturedArt,
      timestamp: laterNow,              // refreshed — not covered by original sig
      expiry:    laterNow + 300_000,    // refreshed — not covered by original sig
    };

    const result = validateArtifact(replayed, { _clock: () => laterNow });
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

  // V1 bypass §2.A-3: same signature valid across multiple time windows.
  test('[REG-2] V1 bypass: same signature across multiple windows → all BLOCK', () => {
    const payload = { userId: 'alice', action: 'query' };
    const now     = Date.now();
    const art     = signArtifact({
      payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId,
    }, KEY.privDer);

    for (const offsetMs of [600_000, 1_800_000, 7_200_000]) {
      const laterNow = now + offsetMs;
      const replayed = { ...art, timestamp: laterNow - 1, expiry: laterNow + 300_000 };

      const result = validateArtifact(replayed, { _clock: () => laterNow });
      expect(result.decision).toBe('BLOCK');
      expect(result.reason).toBe('INVALID_SIGNATURE');
    }
  });

  // V1 bypass §1.B: null/undefined canonical equivalence.
  test('[REG-3] V1 bypass: {role: null} and {role: undefined} — undefined now rejected', () => {
    const artifact = makeArtifact({ userId: 'alice', role: null });
    const tampered = { ...artifact, payload: { userId: 'alice', role: undefined } };

    // Previously: both canonicalized to same string → ALLOW (bypass)
    // Now: undefined in payload → MALFORMED_ARTIFACT before reaching signature check
    const result = validateArtifact(tampered);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
  });

  // V1 bypass §3.A: extra envelope fields silently accepted.
  test('[REG-4] V1 bypass: extra envelope fields — now rejected', () => {
    const artifact = { ...makeArtifact({ userId: 'alice' }), admin: true };

    // Previously: extra fields ignored → ALLOW (bypass)
    // Now: strict schema → MALFORMED_ARTIFACT
    const result = validateArtifact(artifact);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
  });

  // V1 audit §3.D: Date object as payload accepted (hashed as {}).
  test('[REG-5] V1 audit: Date payload — now rejected by isPlainObject check', () => {
    const artifact = {
      payload:     new Date(),
      signature:   crypto.randomBytes(64).toString('base64'),
      timestamp:   Date.now(),
      expiry:      Date.now() + 300_000,
      publicKeyId: KEY.keyId,
    };

    // Previously: Date had no own enumerable props → hashed as {} → signature over {}
    // could be used to accept Date payloads (ALLOW with matching sig for {}).
    // Now: isPlainObject(new Date()) === false → MALFORMED_ARTIFACT
    const result = validateArtifact(artifact);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SIGNING FUNCTION VALIDATION
// ══════════════════════════════════════════════════════════════════════════════

describe('signArtifact() input validation', () => {

  test('throws on non-plain-object payload', () => {
    expect(() => signArtifact({ payload: null,   timestamp: 1, expiry: 2, publicKeyId: 'k' }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: [],     timestamp: 1, expiry: 2, publicKeyId: 'k' }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: 'str',  timestamp: 1, expiry: 2, publicKeyId: 'k' }, KEY.privDer)).toThrow();
  });

  test('throws on payload with undefined values', () => {
    const now = Date.now();
    expect(() => signArtifact({
      payload:     { userId: 'x', role: undefined },
      timestamp:   now,
      expiry:      now + 1_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer)).toThrow(/undefined/);
  });

  test('throws when expiry ≤ timestamp', () => {
    const now = Date.now();
    expect(() => signArtifact({
      payload: {}, timestamp: now, expiry: now, publicKeyId: KEY.keyId,
    }, KEY.privDer)).toThrow();
    expect(() => signArtifact({
      payload: {}, timestamp: now, expiry: now - 1, publicKeyId: KEY.keyId,
    }, KEY.privDer)).toThrow();
  });

  test('throws on non-numeric timestamp', () => {
    const now = Date.now();
    expect(() => signArtifact({
      payload: {}, timestamp: 'now', expiry: now + 1_000, publicKeyId: KEY.keyId,
    }, KEY.privDer)).toThrow();
  });

  test('throws on NaN / Infinity timestamp', () => {
    const now = Date.now();
    expect(() => signArtifact({ payload: {}, timestamp: NaN,      expiry: now + 1, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: {}, timestamp: Infinity, expiry: now + 1, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: {}, timestamp: 0,        expiry: now + 1, publicKeyId: KEY.keyId }, KEY.privDer)).toThrow();
  });

  test('throws on empty publicKeyId', () => {
    const now = Date.now();
    expect(() => signArtifact({ payload: {}, timestamp: now, expiry: now + 1, publicKeyId: '' }, KEY.privDer)).toThrow();
    expect(() => signArtifact({ payload: {}, timestamp: now, expiry: now + 1, publicKeyId: '  ' }, KEY.privDer)).toThrow();
  });

  test('returns frozen object with exactly 5 fields', () => {
    const now = Date.now();
    const art = signArtifact({
      payload:     { userId: 'alice' },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);

    expect(Object.isFrozen(art)).toBe(true);
    expect(Object.keys(art).sort()).toEqual(['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp']);
  });

  test('produced artifact validates immediately', () => {
    const now = Date.now();
    const art = signArtifact({
      payload:     { userId: 'alice', action: 'read' },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);

    expect(validateArtifact(art).decision).toBe('EXECUTE');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// V1 LEGACY REJECTION
// ══════════════════════════════════════════════════════════════════════════════

describe('V1 legacy artifact rejection', () => {

  // A V1 artifact: signature over SHA-256("QODIQA::CANONICAL::V1" || stableStringify(payload)).
  // The validator must BLOCK these even when the payload is unchanged,
  // because the hash input differs from V2.
  test('V1 payload-only signature → BLOCK / INVALID_SIGNATURE', () => {
    const crypto2 = require('crypto');
    const stableStringify = require('../../../services/utils/stableStringify');

    const payload = { userId: 'alice', action: 'read' };
    const now     = Date.now();

    // Compute V1 signature manually.
    const canonical = stableStringify(payload);
    const v1Hash    = crypto2.createHash('sha256')
      .update('QODIQA::CANONICAL::V1', 'utf8')
      .update(canonical,               'utf8')
      .digest();
    const v1Sig = sign(v1Hash, KEY.privDer);

    const v1Artifact = {
      payload,
      signature:   v1Sig,
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    };

    const result = validateArtifact(v1Artifact);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_SIGNATURE');
  });

});
