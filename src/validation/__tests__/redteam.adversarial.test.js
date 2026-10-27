'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════════════════╗
 * ║              RED TEAM ADVERSARIAL TEST SUITE — V2                      ║
 * ║              Target: src/validation/validateArtifact.js                ║
 * ╠══════════════════════════════════════════════════════════════════════════╣
 * ║  Legend                                                                ║
 * ║  [FIXED]   Was a confirmed bypass in V1; now BLOCK in V2               ║
 * ║  [AUDIT]   Design decision that warrants security review               ║
 * ║  All adversarial cases MUST BLOCK                                      ║
 * ╚══════════════════════════════════════════════════════════════════════════╝
 */

const crypto = require('crypto');

const { validateArtifact }    = require('../validateArtifact');
const { signArtifact }        = require('../signArtifact');
const { envelopeHash,
        canonicalizeEnvelope,
        isPlainObject,
        hasUndefined }        = require('../canonicalize');
const stableStringify          = require('../../../services/utils/stableStringify');
const { getActiveKey }         = require('../../../services/artifact/keyStore');
const { sign }                 = require('../../infra/crypto/ed25519');

// ── Shared helpers ────────────────────────────────────────────────────────────

function freshKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  return { privDer: Buffer.from(privateKey), pubDer: Buffer.from(publicKey) };
}

/** Sign a fresh artifact; post-signing `tamper` overrides simulate tampering. */
function build(payload, privDer, publicKeyId, tamper = {}) {
  const now = Date.now();
  const art = signArtifact({ payload, timestamp: now, expiry: now + 300_000, publicKeyId }, privDer);
  return Object.keys(tamper).length ? { ...art, ...tamper } : art;
}

/** Sign an artifact with a specific frozen time; post-signing overrides simulate tampering. */
function buildAt(payload, privDer, publicKeyId, frozenNow, tamper = {}) {
  const art = signArtifact({
    payload, timestamp: frozenNow, expiry: frozenNow + 300_000, publicKeyId,
  }, privDer);
  return Object.keys(tamper).length ? { ...art, ...tamper } : art;
}

/** Construct an artifact without signing (for malformed-input tests). */
function buildRaw(overrides = {}) {
  return {
    payload:     { userId: 'x' },
    signature:   crypto.randomBytes(64).toString('base64'),
    timestamp:   Date.now(),
    expiry:      Date.now() + 300_000,
    publicKeyId: KEY ? KEY.keyId : 'default:key_v1',
    ...overrides,
  };
}

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 1 — CANONICALIZATION ATTACKS
// ══════════════════════════════════════════════════════════════════════════════

describe('§1  Canonicalization Attacks', () => {

  // ── 1.A  Key-ordering invariance ─────────────────────────────────────────────

  // [AUDIT] stableStringify sorts object keys lexicographically.
  // A signature over {payload: {a:1,b:2}, ...} is VALID for {payload: {b:2,a:1}, ...}.
  // Key order in the payload still carries no semantic weight.
  test('[1.A-1] AUDIT: reordered payload keys produce identical canonical form → ALLOW', () => {
    const p1 = { action: 'read', userId: 'alice' };
    const p2 = { userId: 'alice', action: 'read' };

    expect(stableStringify(p1)).toBe(stableStringify(p2));
    // envelopeHash with p1 === envelopeHash with p2 (same canonical payload string)
    const now  = Date.now();
    const base = { timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
    expect(canonicalizeEnvelope({ ...base, payload: p1 }))
      .toBe(canonicalizeEnvelope({ ...base, payload: p2 }));

    // Sign with p1, then substitute p2 into the same envelope — timestamps are identical.
    const art1 = signArtifact({ payload: p1, ...base }, KEY.privDer);
    const art2 = { ...art1, payload: p2 };  // same envelope, same sig, different JS object
    expect(validateArtifact(art2).decision).toBe('EXECUTE');
  });

  test('[1.A-2] AUDIT: deeply nested reordered keys are still identical', () => {
    const p1 = { outer: { z: 9, a: 1 } };
    const p2 = { outer: { a: 1, z: 9 } };
    expect(stableStringify(p1)).toBe(stableStringify(p2));
  });

  // ── 1.B  null / undefined — FIXED ────────────────────────────────────────────

  // [FIXED] V1: {field: null} and {field: undefined} shared a canonical form.
  // V2: undefined is rejected before canonicalization — MALFORMED_ARTIFACT.
  test('[1.B-1] FIXED: undefined payload field → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = build({ userId: 'alice', role: null }, KEY.privDer, KEY.keyId, {
      payload: { userId: 'alice', role: undefined },
    });
    const result = validateArtifact(art);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
  });

  test('[1.B-2] FIXED: undefined-signed does not validate null payload (signature mismatch)', () => {
    // The null and undefined payloads are NOW different at the validator
    // (undefined rejected), but even if they weren't, the signature covers the
    // full envelope — a null-containing payload produces a different hash than
    // the pre-fix undefined-containing payload.
    const art = build({ userId: 'alice', role: null }, KEY.privDer, KEY.keyId);
    expect(validateArtifact(art).decision).toBe('EXECUTE'); // null payload is fine
  });

  test('[1.B-3] undefined key present vs key absent → both produce different hashes', () => {
    // {userId: 'alice', extra: undefined}  →  rejected (hasUndefined)
    // {userId: 'alice'}                    →  valid
    const withUndefined = { userId: 'alice', extra: undefined };
    const withoutKey    = { userId: 'alice' };

    // stableStringify gives different strings
    expect(stableStringify(withUndefined)).not.toBe(stableStringify(withoutKey));

    const art = build(withoutKey, KEY.privDer, KEY.keyId, { payload: withUndefined });
    const result = validateArtifact(art);
    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('INVALID_ARTIFACT');
  });

  // ── 1.C  Numeric edge cases ───────────────────────────────────────────────────

  test('[1.C-1] AUDIT: integer 1 and float 1.0 are canonically identical', () => {
    const p1 = { count: 1 };
    const p2 = { count: 1.0 };
    expect(stableStringify(p1)).toBe(stableStringify(p2));

    // Sign with p1 and validate with p2 — must use identical envelope timestamps.
    const now  = Date.now();
    const art1 = signArtifact({ payload: p1, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer);
    const art2 = { ...art1, payload: p2 };   // same envelope; only JS object identity changes
    expect(validateArtifact(art2).decision).toBe('EXECUTE');
  });

  test('[1.C-2] AUDIT: -0 and 0 are canonically identical', () => {
    expect(stableStringify({ v: -0 })).toBe(stableStringify({ v: 0 }));
  });

  test('[1.C-3] FIXED: NaN payload field is rejected — QODIQA-PROTOCOL-SPEC.md §6.1', () => {
    // Spec §6.1: "If V is a number: if NaN or Infinity: ERROR". Silently
    // mapping NaN/Infinity to null (the old fast-json-stable-stringify
    // default, matching JSON.stringify) would let two payloads that differ
    // only in a NaN vs. an explicit null field hash identically — a
    // canonicalization collision. stableStringify now throws instead.
    expect(() => stableStringify({ score: NaN })).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify({ score: Infinity })).toThrow(stableStringify.CanonicalizationError);
  });

  // ── 1.D  Unicode normalization ────────────────────────────────────────────────

  test('[1.D-1] NFC and NFD forms have different hashes → BLOCK on cross-form signature', () => {
    const nfc = { user: 'é' };    // U+00E9: é as single NFC codepoint
    const nfd = { user: 'é' };       // e + combining acute accent U+0301 (NFD)

    expect(stableStringify(nfc)).not.toBe(stableStringify(nfd));

    const now    = Date.now();
    const nfcSig = signArtifact({ payload: nfc, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId }, KEY.privDer).signature;
    const art    = build(nfd, KEY.privDer, KEY.keyId, { signature: nfcSig });

    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  // ── 1.E  Inherited properties ─────────────────────────────────────────────────

  // [AUDIT] Object.keys() excludes inherited properties — they remain invisible
  // to the canonical form.  The root payload prototype IS now checked (must be
  // Object.prototype or null), but non-own properties of accepted payloads are
  // still excluded from the hash.
  test('[1.E-1] AUDIT: inherited properties excluded from canonical form', () => {
    const proto   = { hiddenRole: 'admin' };
    const withInherited = Object.create(proto);
    withInherited.userId = 'alice';
    withInherited.action = 'read';

    const plain = { userId: 'alice', action: 'read' };

    // isPlainObject check: Object.create(proto) has proto as prototype, not
    // Object.prototype → MALFORMED_ARTIFACT.
    // Both validate the same if proto === Object.prototype; use plain for signing.
    expect(isPlainObject(withInherited)).toBe(false); // prototype is not Object.prototype

    const art = buildRaw({ payload: withInherited });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  test('[1.E-2] Object.create(null) payload is accepted (null prototype)', () => {
    const p       = Object.create(null);
    p.userId      = 'alice';
    p.action      = 'read';

    const art = build(p, KEY.privDer, KEY.keyId);
    expect(validateArtifact(art).decision).toBe('EXECUTE');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 2 — SIGNATURE CONFUSION
// ══════════════════════════════════════════════════════════════════════════════

describe('§2  Signature Confusion', () => {

  // ── 2.A  Envelope replay — FIXED ─────────────────────────────────────────────

  // [FIXED] V1: timestamp/expiry not signed → replay with fresh window worked.
  // V2: full envelope is signed → any change to timestamp/expiry invalidates sig.
  test('[2.A-1] FIXED: captured signature replayed with fresh timestamp/expiry → BLOCK', () => {
    const payload   = { userId: 'attacker', action: 'privileged-write' };
    const original  = build(payload, KEY.privDer, KEY.keyId);

    const now     = Date.now() + 3_600_000;  // 1 hour later
    const replayed = { ...original, timestamp: now, expiry: now + 300_000 };

    expect(validateArtifact(replayed, { _clock: () => now }).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.A-2] FIXED: expiry extension on captured artifact → BLOCK', () => {
    const artifact = build({ userId: 'victim', action: 'transfer' }, KEY.privDer, KEY.keyId);
    const extended = { ...artifact, expiry: artifact.expiry + 86_400_000 };

    expect(validateArtifact(extended).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.A-3] FIXED: same signature across sequential time windows → all BLOCK', () => {
    const original = build({ userId: 'alice' }, KEY.privDer, KEY.keyId);
    for (const offset of [600_000, 3_600_000, 86_400_000]) {
      const laterNow = Date.now() + offset;
      const replayed = { ...original, timestamp: laterNow - 1, expiry: laterNow + 300_000 };
      expect(validateArtifact(replayed, { _clock: () => laterNow }).reason).toBe('INVALID_SIGNATURE');
    }
  });

  // ── 2.B  Cross-payload and cross-key attacks ──────────────────────────────────

  test('[2.B-1] signature from payload A does not validate payload B', () => {
    const artA = build({ action: 'read',   userId: 'alice' }, KEY.privDer, KEY.keyId);
    const tampered = { ...artA, payload: { action: 'delete', userId: 'alice' } };

    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.B-2] signature from unregistered private key → INVALID_SIGNATURE', () => {
    const { privDer: wrongPriv } = freshKeyPair();
    const art = build({ userId: 'x' }, wrongPriv, KEY.keyId);

    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.B-3] cross-domain: sign without domain prefix → BLOCK', () => {
    const payload = { userId: 'x' };
    const now     = Date.now();
    const canonical = canonicalizeEnvelope({ expiry: now + 300_000, payload, publicKeyId: KEY.keyId, timestamp: now });
    const rawHash   = crypto.createHash('sha256').update(canonical).digest();
    const rawSig    = sign(rawHash, KEY.privDer);

    const art = buildAt(payload, KEY.privDer, KEY.keyId, now, { signature: rawSig });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.B-4] cross-domain: sign with old V1 domain → BLOCK', () => {
    const payload = { userId: 'x' };
    const now     = Date.now();
    const canonical = canonicalizeEnvelope({ expiry: now + 300_000, payload, publicKeyId: KEY.keyId, timestamp: now });
    const v1Hash    = crypto.createHash('sha256')
      .update('QODIQA::ARTIFACT::V0', 'utf8')
      .update(canonical, 'utf8')
      .digest();
    const v1Sig = sign(v1Hash, KEY.privDer);

    const art = buildAt(payload, KEY.privDer, KEY.keyId, now, { signature: v1Sig });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.B-5] V1 payload-only signature → BLOCK', () => {
    const payload = { userId: 'x' };
    const now     = Date.now();
    const v1Hash  = crypto.createHash('sha256')
      .update('QODIQA::CANONICAL::V1', 'utf8')
      .update(stableStringify(payload),   'utf8')
      .digest();
    const v1Sig = sign(v1Hash, KEY.privDer);

    const art = buildAt(payload, KEY.privDer, KEY.keyId, now, { signature: v1Sig });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  // ── 2.C  Signature bit-manipulation ──────────────────────────────────────────

  test('[2.C-1] all-zero 64-byte signature → BLOCK / INVALID_SIGNATURE', () => {
    const art = build({ userId: 'x' }, KEY.privDer, KEY.keyId, {
      signature: Buffer.alloc(64, 0x00).toString('base64'),
    });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.C-2] all-0xFF 64-byte signature → BLOCK / INVALID_SIGNATURE', () => {
    const art = build({ userId: 'x' }, KEY.privDer, KEY.keyId, {
      signature: Buffer.alloc(64, 0xff).toString('base64'),
    });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.C-3] random 64-byte signature → BLOCK / INVALID_SIGNATURE', () => {
    const art = build({ userId: 'x' }, KEY.privDer, KEY.keyId, {
      signature: crypto.randomBytes(64).toString('base64'),
    });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.C-4] single-bit flip in valid signature → BLOCK / INVALID_SIGNATURE', () => {
    const art  = build({ userId: 'alice' }, KEY.privDer, KEY.keyId);
    const buf  = Buffer.from(art.signature, 'base64');
    buf[0]    ^= 0x01;
    expect(validateArtifact({ ...art, signature: buf.toString('base64') }).reason).toBe('INVALID_SIGNATURE');
  });

  test('[2.C-5] last-byte flip → BLOCK / INVALID_SIGNATURE', () => {
    const art  = build({ userId: 'alice' }, KEY.privDer, KEY.keyId);
    const buf  = Buffer.from(art.signature, 'base64');
    buf[63]   ^= 0x80;
    expect(validateArtifact({ ...art, signature: buf.toString('base64') }).reason).toBe('INVALID_SIGNATURE');
  });

  // ── 2.D  Signature length manipulation ───────────────────────────────────────

  test('[2.D-1] 63-byte signature → BLOCK / INVALID_SIGNATURE', () => {
    const art = build({ userId: 'x' }, KEY.privDer, KEY.keyId, {
      signature: crypto.randomBytes(63).toString('base64'),
    });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE'); // every non-canonical spelling
  });

  test('[2.D-2] 65-byte signature → BLOCK / INVALID_SIGNATURE', () => {
    const art = build({ userId: 'x' }, KEY.privDer, KEY.keyId, {
      signature: crypto.randomBytes(65).toString('base64'),
    });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE'); // every non-canonical spelling
  });

  test('[2.D-3] empty signature string → BLOCK / INVALID_SIGNATURE', () => {
    const art = build({ userId: 'x' }, KEY.privDer, KEY.keyId, { signature: '' });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE'); // every non-canonical spelling
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 3 — STRUCTURAL POISONING
// ══════════════════════════════════════════════════════════════════════════════

describe('§3  Structural Poisoning', () => {

  // ── 3.A  Extra envelope fields — FIXED ───────────────────────────────────────

  // [FIXED] V1: extra fields silently accepted → ALLOW.
  // V2: strict 5-field schema → MALFORMED_ARTIFACT.
  test('[3.A-1] FIXED: extra field "admin: true" → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = { ...build({ userId: 'alice' }, KEY.privDer, KEY.keyId), admin: true };
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
    expect(validateArtifact(art).details.extraField).toBe('admin');
  });

  test('[3.A-2] FIXED: extra field "_debug" → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = { ...build({ userId: 'alice' }, KEY.privDer, KEY.keyId), _debug: true };
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  // ── 3.B  Prototype pollution via payload ──────────────────────────────────────

  test('[3.B-1] FIXED: payload with __proto__ own key is rejected at signing — QODIQA-PROTOCOL-SPEC.md §6.1', () => {
    // Spec §6.1: "if any key is __proto__, constructor, or prototype: ERROR".
    // signArtifact canonicalizes (and therefore validates) the payload before
    // ever producing a signature, so a poisoned payload is rejected before an
    // artifact can even be built — strictly stronger than merely preventing
    // Object.prototype pollution downstream.
    const raw     = '{"__proto__":{"isAdmin":true},"userId":"alice"}';
    const payload = JSON.parse(raw);

    expect(() => build(payload, KEY.privDer, KEY.keyId)).toThrow();
    expect(({}).isAdmin).toBeUndefined();
  });

  test('[3.B-2] FIXED: tampered __proto__ payload with original signature → BLOCK / INVALID_ARTIFACT', () => {
    // The __proto__ key is now rejected during canonicalization (spec §6.1)
    // before the tampered envelope ever reaches signature comparison —
    // validateArtifact's envelopeHash try/catch (step 15) converts the
    // CanonicalizationError to INVALID_ARTIFACT. This is a stronger outcome
    // than INVALID_SIGNATURE: the payload is rejected as structurally
    // invalid regardless of what signature accompanies it.
    const legitimate = { userId: 'alice' };
    const poisoned   = JSON.parse('{"__proto__":{"isAdmin":true},"userId":"alice"}');

    const art = build(legitimate, KEY.privDer, KEY.keyId, { payload: poisoned });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  // ── 3.C  Non-plain-object payload — FIXED ────────────────────────────────────

  // [FIXED] V1: Date/RegExp/etc passed isPlainObject check and hashed to {}.
  // V2: isPlainObject() checks prototype → rejects Date, RegExp, Map, Set.
  test('[3.C-1] FIXED: Date object as payload → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = buildRaw({ payload: new Date() });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  test('[3.C-2] FIXED: RegExp as payload → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = buildRaw({ payload: /exploit/gi });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  test('[3.C-3] FIXED: Map as payload → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = buildRaw({ payload: new Map([['k', 'v']]) });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  const BAD_PAYLOADS = [null, 'string', 42, true, false, [], [{ userId: 'alice' }]];
  BAD_PAYLOADS.forEach(bad => {
    test(`[3.D] payload as ${JSON.stringify(bad)} → BLOCK / MALFORMED_ARTIFACT`, () => {
      expect(validateArtifact(buildRaw({ payload: bad })).reason).toBe('INVALID_ARTIFACT');
    });
  });

  // ── 3.E  Depth and size ───────────────────────────────────────────────────────

  test('[3.E-1] deeply nested payload (200 levels) validates without crash', () => {
    let payload = { leaf: true };
    for (let i = 0; i < 200; i++) payload = { n: payload };
    expect(validateArtifact(build(payload, KEY.privDer, KEY.keyId)).decision).toBe('EXECUTE');
  });

  test('[3.E-2] circular reference in payload → BLOCK / MALFORMED_ARTIFACT', () => {
    const payload = { userId: 'alice' };
    payload.self  = payload;
    // signArtifact rejects circular references (hasUndefined traversal would loop, but
    // stableStringify throws RangeError caught by validateArtifact's try/catch)
    // Since signArtifact also checks hasUndefined, we bypass it with buildRaw.
    const art = buildRaw({ payload });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  test('[3.E-3] array artifact → BLOCK / MALFORMED_ARTIFACT', () => {
    expect(validateArtifact([]).reason).toBe('INVALID_ARTIFACT');
    expect(validateArtifact([1, 2, 3]).reason).toBe('INVALID_ARTIFACT');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 4 — TIME EDGE CASES
// ══════════════════════════════════════════════════════════════════════════════

describe('§4  Time Edge Cases', () => {

  // ── 4.A  Boundary conditions ──────────────────────────────────────────────────

  test('[4.A-1] timestamp exactly equal to now → ALLOW (strict > boundary)', () => {
    const T   = Date.now();
    const art = buildAt({ userId: 'x' }, KEY.privDer, KEY.keyId, T, { expiry: T + 1 });
    // buildAt signs with timestamp=T; then tamper sets expiry=T+1 post-signing
    // This will fail signature. Sign with both values correctly:
    const a2  = signArtifact({ payload: { userId: 'x' }, timestamp: T, expiry: T + 1, publicKeyId: KEY.keyId }, KEY.privDer);
    expect(validateArtifact(a2, { _clock: () => T }).decision).toBe('EXECUTE');
  });

  // a 5 s future-skew tolerance replaces the
  // zero tolerance that made clock drift between instances block valid artifacts.
  test('[4.A-2] timestamp 1ms in future → ALLOW', () => {
    const T   = Date.now();
    const art = signArtifact({ payload: { userId: 'x' }, timestamp: T + 1, expiry: T + 60_000, publicKeyId: KEY.keyId }, KEY.privDer);
    expect(validateArtifact(art, { _clock: () => T }).decision).toBe('EXECUTE');
  });

  test('[4.A-2b] timestamp exactly +5 s → ALLOW (tolerance boundary is inclusive)', () => {
    const T   = Date.now();
    const art = signArtifact({ payload: { userId: 'x' }, timestamp: T + 5_000, expiry: T + 60_000, publicKeyId: KEY.keyId }, KEY.privDer);
    expect(validateArtifact(art, { _clock: () => T }).decision).toBe('EXECUTE');
  });

  test('[4.A-2c] timestamp +5 s +1 ms → BLOCK / FUTURE_TIMESTAMP', () => {
    const T   = Date.now();
    const art = signArtifact({ payload: { userId: 'x' }, timestamp: T + 5_001, expiry: T + 60_000, publicKeyId: KEY.keyId }, KEY.privDer);
    const r = validateArtifact(art, { _clock: () => T });
    expect(r.reason).toBe('FUTURE_TIMESTAMP');
    expect(r.details.toleranceMs).toBe(5_000);
  });

  test('[4.A-2d] age exactly 60 s → ALLOW; 60 s + 1 ms → BLOCK / TIME_SKEW_EXCEEDED', () => {
    const T   = Date.now(); // signed now (after the key exists); the verifier's clock moves forward
    const art = signArtifact({ payload: { userId: 'x' }, timestamp: T, expiry: T + 61_000, publicKeyId: KEY.keyId }, KEY.privDer);
    expect(validateArtifact(art, { _clock: () => T + 60_000 }).decision).toBe('EXECUTE');
    expect(validateArtifact(art, { _clock: () => T + 60_001 }).reason).toBe('TIME_SKEW_EXCEEDED');
  });

  test('[4.A-3] expiry exactly equal to now → BLOCK / EXPIRED (inclusive)', () => {
    const T   = Date.now();
    const art = signArtifact({ payload: { userId: 'x' }, timestamp: T - 1_000, expiry: T, publicKeyId: KEY.keyId }, KEY.privDer);
    expect(validateArtifact(art, { _clock: () => T }).reason).toBe('EXPIRED');
  });

  test('[4.A-4] expiry 1ms in future → ALLOW', () => {
    const T   = Date.now();
    const art = signArtifact({ payload: { userId: 'x' }, timestamp: T - 1_000, expiry: T + 1, publicKeyId: KEY.keyId }, KEY.privDer);
    expect(validateArtifact(art, { _clock: () => T }).decision).toBe('EXECUTE');
  });

  // ── 4.B  Timestamp type attacks ───────────────────────────────────────────────

  const INVALID_TIMESTAMPS = [
    [0,         'zero'],
    [-1,        'negative'],
    [NaN,       'NaN'],
    [Infinity,  'Infinity'],
    [-Infinity, '-Infinity'],
    [true,      'boolean'],
    [null,      'null'],
    ['now',     'string'],
    [{},        'object'],
    [[1],       'array'],
    [new Date(),'Date'],
  ];

  INVALID_TIMESTAMPS.forEach(([val, label]) => {
    test(`[4.B] timestamp as ${label} → BLOCK / MALFORMED_ARTIFACT`, () => {
      expect(validateArtifact(buildRaw({ timestamp: val })).reason).toBe('INVALID_ARTIFACT');
    });
  });

  // ── 4.C  Expiry type attacks ──────────────────────────────────────────────────

  const INVALID_EXPIRIES = [
    [0,         'zero'],
    [-1,        'negative'],
    [NaN,       'NaN'],
    [Infinity,  'Infinity'],
    [null,      'null'],
    [true,      'boolean'],
    ['never',   'string'],
    [{},        'object'],
  ];

  INVALID_EXPIRIES.forEach(([val, label]) => {
    test(`[4.C] expiry as ${label} → BLOCK / MALFORMED_ARTIFACT`, () => {
      expect(validateArtifact(buildRaw({ expiry: val })).reason).toBe('INVALID_ARTIFACT');
    });
  });

  // ── 4.D  Far-future timestamps ────────────────────────────────────────────────
  //
  // CRYPTO-5/VERIFY-4: buildRaw()'s `signature` is always crypto.randomBytes(64)
  // — never a real signature over any hash — so with signature verification
  // now running before the timestamp/expiry checks, every buildRaw()-built
  // artifact fails at INVALID_SIGNATURE first, regardless of what timestamp/
  // expiry values it carries. This is the intended fix: an attacker without a
  // valid signature can no longer distinguish "this timestamp is in the
  // future" from "this signature is wrong".

  test('[4.D-1] timestamp = year 9999 → BLOCK / INVALID_SIGNATURE (signature checked first)', () => {
    const art = buildRaw({ timestamp: new Date('9999-12-31').getTime() });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  // ── 4.E  Swap attack ──────────────────────────────────────────────────────────

  test('[4.E-1] swapped timestamp/expiry → BLOCK / INVALID_SIGNATURE (signature checked first)', () => {
    const T   = Date.now();
    const art = buildRaw({ timestamp: T + 60_000, expiry: T - 60_000 });
    expect(validateArtifact(art, { _clock: () => T }).reason).toBe('INVALID_SIGNATURE');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — KEY RESOLUTION ATTACKS
// ══════════════════════════════════════════════════════════════════════════════

describe('§5  Key Resolution Attacks', () => {

  const MALFORMED_IDS = [
    ['',        'empty string',    'INVALID_ARTIFACT'],
    ['   ',     'whitespace',      'INVALID_ARTIFACT'],
    [null,      'null',            'INVALID_ARTIFACT'],
    [42,        'integer',         'INVALID_ARTIFACT'],
    [true,      'boolean',         'INVALID_ARTIFACT'],
    [{},        'object',          'INVALID_ARTIFACT'],
    [['key'],   'array',           'INVALID_ARTIFACT'],
  ];

  MALFORMED_IDS.forEach(([val, label, expected]) => {
    test(`[5.A] publicKeyId as ${label} → BLOCK / ${expected}`, () => {
      expect(validateArtifact(buildRaw({ publicKeyId: val })).reason).toBe(expected);
    });
  });

  const UNKNOWN_IDS = [
    'ghost:key_v1',
    'default:key_v999',
    '../../etc/passwd',
    "'; DROP TABLE k; --",
    'default:key_v1\x00evil',
    'a'.repeat(512),
    'default',
  ];

  // CRYPTO-5/VERIFY-4: an unresolved key no longer produces its own
  // distinguishable KEY_NOT_FOUND reason before signature verification — it
  // falls through to verification against a null key sentinel (always
  // fails), so an unknown publicKeyId is indistinguishable from a wrong
  // signature. buildRaw()'s signature is random garbage regardless, so every
  // case here now fails at INVALID_SIGNATURE.
  UNKNOWN_IDS.forEach(val => {
    test(`[5.B] publicKeyId "${String(val).slice(0, 30)}…" → BLOCK / INVALID_SIGNATURE`, () => {
      expect(validateArtifact(buildRaw({ publicKeyId: val })).reason).toBe('INVALID_SIGNATURE');
    });
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 6 — MALFORMED ARTIFACT STRUCTURE
// ══════════════════════════════════════════════════════════════════════════════

describe('§6  Malformed Artifact Structure', () => {

  const PRIMITIVES = [null, undefined, 42, 'string', true, false, Symbol('x')];
  PRIMITIVES.forEach(val => {
    const label = typeof val === 'symbol' ? 'Symbol' : JSON.stringify(val);
    test(`[6.A] primitive artifact (${label}) → BLOCK / MALFORMED_ARTIFACT`, () => {
      expect(validateArtifact(val).reason).toBe('INVALID_ARTIFACT');
    });
  });

  const REQUIRED = ['payload', 'signature', 'timestamp', 'expiry', 'publicKeyId'];
  REQUIRED.forEach(field => {
    test(`[6.B] missing field "${field}" → BLOCK / MALFORMED_ARTIFACT`, () => {
      const art  = build({ userId: 'x' }, KEY.privDer, KEY.keyId);
      const copy = { ...art };
      delete copy[field];
      const result = validateArtifact(copy);
      expect(result.reason).toBe('INVALID_ARTIFACT');
      expect(result.details.missing).toBe(field);
    });
  });

  test('[6.C] empty artifact {} → BLOCK / MALFORMED_ARTIFACT', () => {
    expect(validateArtifact({}).reason).toBe('INVALID_ARTIFACT');
  });

  const INVALID_SIGS = [
    [null,                  'null'],
    [42,                    'integer'],
    [true,                  'boolean'],
    [{},                    'object'],
    ['not valid base64 !!', 'invalid base64'],
    ['====',                'only padding'],
    ['',                    'empty string'],
  ];

  // a non-string is a schema error (INVALID_ARTIFACT); any
  // string that is not the canonical spelling is INVALID_SIGNATURE.
  INVALID_SIGS.forEach(([val, label]) => {
    const want = typeof val === 'string' ? 'INVALID_SIGNATURE' : 'INVALID_ARTIFACT';
    test(`[6.D] signature as ${label} → BLOCK / ${want}`, () => {
      expect(validateArtifact(buildRaw({ signature: val })).reason).toBe(want);
    });
  });

  test('[6.E] field explicitly set to undefined → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = { ...build({ userId: 'x' }, KEY.privDer, KEY.keyId), payload: undefined };
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 7 — SERIALIZATION INTEGRITY
// ══════════════════════════════════════════════════════════════════════════════

describe('§7  Serialization Integrity', () => {

  test('[7.1] canonical envelope has zero whitespace', () => {
    const now     = Date.now();
    const canon   = canonicalizeEnvelope({ expiry: now + 300_000, payload: { userId: 'alice' }, publicKeyId: KEY.keyId, timestamp: now });
    expect(canon).not.toMatch(/\s/);
  });

  test('[7.2] special characters in strings are escaped in canonical form', () => {
    const payload = { msg: 'line1\nline2\ttabbed\rcarriage' };
    const now     = Date.now();
    const canon   = canonicalizeEnvelope({ expiry: now + 300_000, payload, publicKeyId: KEY.keyId, timestamp: now });
    expect(canon).not.toMatch(/\t|\n|\r/);
    expect(canon).toContain('\\n');
    expect(canon).toContain('\\t');
    expect(canon).toContain('\\r');
  });

  test('[7.3] whitespace-padded JSON signature → BLOCK / INVALID_SIGNATURE', () => {
    const payload   = { userId: 'alice' };
    const now       = Date.now();
    const paddedEnv = JSON.stringify({ expiry: now + 300_000, payload, publicKeyId: KEY.keyId, timestamp: now }, null, 2);
    const h         = crypto.createHash('sha256')
      .update('QODIQA::ARTIFACT::V1', 'utf8')
      .update(paddedEnv,              'utf8')
      .digest();
    const paddedSig = sign(h, KEY.privDer);

    const art = buildAt(payload, KEY.privDer, KEY.keyId, now, { signature: paddedSig });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

  test('[7.4] unsorted JSON.stringify signature → BLOCK / INVALID_SIGNATURE', () => {
    const payload = { z: 1, a: 2 };
    const now     = Date.now();
    // JSON.stringify does NOT sort keys — canonical form DOES
    const unsorted = JSON.stringify({ expiry: now + 300_000, payload, publicKeyId: KEY.keyId, timestamp: now });
    const canon    = canonicalizeEnvelope({ expiry: now + 300_000, payload, publicKeyId: KEY.keyId, timestamp: now });
    if (unsorted === canon) return; // already sorted — test is vacuous

    const h   = crypto.createHash('sha256')
      .update('QODIQA::ARTIFACT::V1', 'utf8')
      .update(unsorted,              'utf8')
      .digest();
    const sig = sign(h, KEY.privDer);
    const art = buildAt(payload, KEY.privDer, KEY.keyId, now, { signature: sig });
    expect(validateArtifact(art).reason).toBe('INVALID_SIGNATURE');
  });

});

// ══════════════════════════════════════════════════════════════════════════════
// SECTION 8 — COMBINED ATTACKS
// ══════════════════════════════════════════════════════════════════════════════

describe('§8  Combined and Chained Attacks', () => {

  test('[8.1] all fields malformed → BLOCK / MALFORMED_ARTIFACT (first check fires)', () => {
    const result = validateArtifact({
      payload:     'not-an-object',
      signature:   12345,
      timestamp:   'INVALID',
      expiry:      null,
      publicKeyId: {},
    });
    expect(result.reason).toBe('INVALID_ARTIFACT');
  });

  // CRYPTO-5/VERIFY-4 regression: these two cases are the exact oracle the
  // fix closes. Previously KEY_NOT_FOUND/FUTURE_TIMESTAMP fired BEFORE
  // signature verification, so an attacker with no valid signature (and,
  // often, no real key at all) could still learn "this key doesn't exist" or
  // "this timestamp is in the future" — a distinguishable response from
  // "the signature itself is wrong". Both now collapse to the same
  // INVALID_SIGNATURE outcome, since signature verification runs first.

  test('[8.2] unknown key + expired: INVALID_SIGNATURE fires before EXPIRED (oracle closed)', () => {
    const T   = Date.now();
    const art = buildRaw({ publicKeyId: 'ghost:key_v1', expiry: T - 1 });
    expect(validateArtifact(art, { _clock: () => T }).reason).toBe('INVALID_SIGNATURE');
  });

  test('[8.3] valid key + future timestamp + wrong sig: INVALID_SIGNATURE fires before FUTURE_TIMESTAMP (oracle closed)', () => {
    const T   = Date.now();
    const art = buildRaw({ timestamp: T + 1_000, signature: crypto.randomBytes(64).toString('base64') });
    expect(validateArtifact(art, { _clock: () => T }).reason).toBe('INVALID_SIGNATURE');
  });

  test('[8.4] MALFORMED_ARTIFACT (bad payload) fires before key resolution', () => {
    const art = buildRaw({ payload: null });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

  // [FIXED] V1 combined bypass: null/undefined ambiguity + fresh envelope.
  // V2: undefined rejected → MALFORMED_ARTIFACT before reaching signature check.
  test('[8.5] FIXED: null/undefined ambiguity + replay → BLOCK / MALFORMED_ARTIFACT', () => {
    const art = build({ userId: 'alice', action: null }, KEY.privDer, KEY.keyId, {
      payload: { userId: 'alice', action: undefined },
    });
    expect(validateArtifact(art).reason).toBe('INVALID_ARTIFACT');
  });

});
