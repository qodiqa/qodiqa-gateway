'use strict';

/**
 * QODIQA Artifact Cryptographic Validator — V2 (full-envelope binding)
 *
 * V1 vulnerability: signature covered only hash(payload).  An attacker who
 * captured a valid signature could reuse it with any timestamp/expiry they
 * chose, indefinitely, without key rotation.
 *
 * V2 fix: signature covers the entire artifact envelope:
 *   SHA-256("QODIQA::ARTIFACT::V1" || stableStringify({expiry, payload, publicKeyId, timestamp}))
 *
 * Any change to payload, timestamp, expiry, or publicKeyId invalidates the
 * signature.  Old V1 artifacts are rejected unconditionally — they fail
 * signature verification because the hash input is different.
 *
 * ── Artifact schema (exactly these 5 fields, no extras, no missing) ──────────
 *   {
 *     payload:     object   — plain object, Object.prototype or null proto
 *     signature:   string   — base64-encoded Ed25519, 64 decoded bytes
 *     timestamp:   number   — positive finite Unix ms (creation time)
 *     expiry:      number   — positive finite Unix ms (expiry time)
 *     publicKeyId: string   — non-empty key identifier
 *   }
 *
 * ── Return shape ──────────────────────────────────────────────────────────────
 *   {
 *     decision: "EXECUTE" | "BLOCK"
 *     reason:   "ALL_CHECKS_PASSED" | "INVALID_SIGNATURE" | "EXPIRED" | "FUTURE_TIMESTAMP" |
 *               "INVALID_ARTIFACT"
 *               (NOT "KEY_NOT_FOUND" — CRYPTO-5/VERIFY-4 folded an unresolved
 *               key into INVALID_SIGNATURE; see §11 below)
 *     details:  object
 *   }
 *
 * ── Validation order (fail-closed at every step) ──────────────────────────────
 *   1.  artifact is a strict plain object
 *   2.  No extra fields — only the 5 schema keys are allowed
 *   3.  All 5 required fields are present
 *   4.  No field in the envelope is undefined
 *   5.  payload is a strict plain object (Object.prototype or null prototype)
 *   6.  payload contains no undefined values at any depth
 *   7.  timestamp is a positive finite number
 *   8.  expiry is a positive finite number
 *   9.  signature is the canonical spelling: padded standard base64, 88 chars,
 * round-trip exact, 64 bytes — else INVALID_SIGNATURE
 *  10.  publicKeyId is a non-empty, non-whitespace string
 *  11.  Ed25519 signature valid for envelopeHash({expiry, payload, publicKeyId, timestamp})
 *       — publicKeyId is resolved to attempt this, but an unresolved key is
 *       NOT reported separately: verification is attempted against a null
 *       key material sentinel (which always fails), so an unknown key and a
 *       genuinely wrong signature are indistinguishable (both INVALID_SIGNATURE).
 *       CRYPTO-5/VERIFY-4: closes the pre-signature key/timestamp oracle —
 *       see the note on step 13 below for why this ordering matters.
 *  12.  timestamp ≤ now + 5 s  (FUTURE_TIMESTAMP; FUTURE_SKEW_MS clock-skew allowance, timeCheck.js)
 *  13.  now < expiry     (EXPIRED, zero tolerance)
 *
 * Steps 11-13 intentionally run signature verification FIRST: an attacker
 * with no valid signature learns nothing beyond "the signature was rejected"
 * — not whether publicKeyId exists, nor the server's clock/skew tolerance —
 * generalizing the same reasoning already applied to the backward-skew check
 * below (only a cryptographically valid artifact ever reaches a check that
 * could otherwise leak timing/key-existence information).
 */

const { envelopeHash,
        isPlainObject,
        hasUndefined }  = require('./canonicalize');
const { checkTimestamp,
        checkSkew,
        checkExpiry,
        MAX_SKEW_MS }   = require('./timeCheck');
const { resolveKey }    = require('./resolveKey');
const { verify }        = require('../infra/crypto/ed25519');
const { checkExecution } = require('./keyLifecycle');
const keyStatusTimeline = require('../core/signing/keyStatusTimeline');

// The exact set of field names that an artifact envelope may contain.
const ARTIFACT_SCHEMA = Object.freeze(new Set(['expiry', 'payload', 'publicKeyId', 'signature', 'timestamp']));
const SIG_BYTE_LEN    = 64;
// 64 bytes → 86 base64 characters + "==" padding.
const CANONICAL_SIG_RE = /^[A-Za-z0-9+/]{86}==$/;

/** The canonical signature spelling: padded standard base64 of 64 bytes, round-trip exact. */
function isCanonicalSignature(s) {
  return typeof s === 'string' && CANONICAL_SIG_RE.test(s) && Buffer.from(s, 'base64').toString('base64') === s;
}

// ── Result constructors ───────────────────────────────────────────────────────

function block(reason, details) {
  return Object.freeze({ decision: 'BLOCK', reason, details: Object.freeze(details || {}) });
}

function allow(details) {
  return Object.freeze({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', details: Object.freeze(details || {}) });
}

// ── Main validation function ──────────────────────────────────────────────────

/**
 * Validate a QODIQA V2 artifact synchronously.
 *
 * @param {any} artifact
 * @param {{ _clock?: () => number, _maxSkewMs?: number }} [opts]
 *   _clock is an internal escape hatch for deterministic testing only.
 *   Production callers MUST NOT pass _clock.
 * @returns {{ decision: string, reason: string, details: object }}
 */
function validateArtifact(artifact, { _clock = Date.now, _maxSkewMs = MAX_SKEW_MS } = {}) {

  // ── 1. Artifact must be a strict plain object ───────────────────────────────
  if (!isPlainObject(artifact)) {
    return block('INVALID_ARTIFACT', { issue: 'artifact must be a plain object' });
  }

  // ── 2. Strict schema: no extra fields allowed ───────────────────────────────
  // Any field not in ARTIFACT_SCHEMA is an envelope integrity violation.
  for (const key of Object.keys(artifact)) {
    if (!ARTIFACT_SCHEMA.has(key)) {
      return block('INVALID_ARTIFACT', { extraField: key });
    }
  }

  // ── 3. All 5 required fields must be present ────────────────────────────────
  for (const field of ARTIFACT_SCHEMA) {
    if (!(field in artifact)) {
      return block('INVALID_ARTIFACT', { missing: field });
    }
  }

  const { expiry, payload, publicKeyId, signature, timestamp } = artifact;

  // ── 4. No field in the envelope may be undefined ────────────────────────────
  // `in` operator confirms key presence (step 3), but the value may still be
  // undefined if the key was explicitly set to undefined.
  for (const [name, val] of [
    ['payload',     payload],
    ['signature',   signature],
    ['timestamp',   timestamp],
    ['expiry',      expiry],
    ['publicKeyId', publicKeyId],
  ]) {
    if (val === undefined) {
      return block('INVALID_ARTIFACT', { undefinedField: name });
    }
  }

  // ── 5. payload must be a strict plain object ────────────────────────────────
  // Rejects Date, RegExp, Map, Set, arrays, and null.
  // Accepts plain objects and null-prototype objects.
  if (!isPlainObject(payload)) {
    return block('INVALID_ARTIFACT', { field: 'payload', issue: 'must be a plain object' });
  }

  // ── 6. payload must contain no undefined values at any depth ────────────────
  // Prevents null/undefined canonical collision:
  // stableStringify({x: undefined}) === stableStringify({x: null}) === '{"x":null}'
  if (hasUndefined(payload)) {
    return block('INVALID_ARTIFACT', { field: 'payload', issue: 'undefined values are not permitted; use null for absent optional fields' });
  }

  // ── 7. timestamp must be a positive finite number ───────────────────────────
  // Rejects strings, booleans, NaN, Infinity, -Infinity, 0, negative numbers.
  // (SPEC 1.0.1 S-074): an integer in [1, 2^53-1]; a float or an unsafe integer has several JSON spellings / loses precision.
  if (typeof timestamp !== 'number' || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
    return block('INVALID_ARTIFACT', { field: 'timestamp', issue: 'must be a positive safe integer (Unix ms)' });
  }

  // ── 8. expiry must be a positive finite number ──────────────────────────────
  if (typeof expiry !== 'number' || !Number.isSafeInteger(expiry) || expiry <= 0) {
    return block('INVALID_ARTIFACT', { field: 'expiry', issue: 'must be a positive safe integer (Unix ms)' });
  }

  // ── 9. signature: the ONE canonical spelling of 64 bytes ──
  // Standard base64 WITH padding: exactly 88 characters (86 + "=="), and it
  // must re-encode to the identical string — which also rejects non-zero
  // trailing bits in the last data character. missing/extra padding
  // and non-canonical trailing bits were all accepted, so one signature had
  // several accepted spellings and the recorded signature string was not a
  // unique identifier. Every other spelling is INVALID_SIGNATURE (a non-string
  // is a schema error, not a spelling).
  if (typeof signature !== 'string') {
    return block('INVALID_ARTIFACT', { field: 'signature', issue: 'must be a string' });
  }
  if (!isCanonicalSignature(signature)) {
    return block('INVALID_SIGNATURE', { field: 'signature', issue: 'not the canonical encoding (standard base64, padded, 88 characters, round-trip exact)' });
  }
  const sigBuf = Buffer.from(signature, 'base64');
  if (sigBuf.length !== SIG_BYTE_LEN) {
    return block('INVALID_SIGNATURE', {
      field: 'signature',
      issue: `decoded length must be ${SIG_BYTE_LEN} bytes`,
      got:   sigBuf.length,
    });
  }

  // ── 10. publicKeyId must be a non-empty, non-whitespace string ───────────────
  if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) {
    return block('INVALID_ARTIFACT', { field: 'publicKeyId', issue: 'must be a non-empty string' });
  }

  // ── 11. Key resolution + full-envelope signature verification (V2) ───────────
  // CRYPTO-5/VERIFY-4: key resolution no longer short-circuits with its own
  // distinguishable KEY_NOT_FOUND block — an unresolved key falls through to
  // signature verification with pubDer=null, which src/infra/crypto/ed25519.js's
  // verify() already fails closed on (returns false for a non-Buffer/empty
  // key, never throws), producing the SAME INVALID_SIGNATURE outcome as a
  // wrong signature against a real key. An attacker cannot tell "this key
  // doesn't exist" from "this signature is wrong" — both look identical.
  //
  // Signature must cover {expiry, payload, publicKeyId, timestamp} — all four
  // fields that influence the access decision. Any modification to any of
  // these fields after signing produces a different hash and fails here.
  // A V1 artifact (signed over only the payload hash) also fails here because
  // envelopeHash uses a different domain string and includes the additional
  // fields.
  const keyResult = resolveKey(publicKeyId);
  const pubDer    = keyResult.found ? keyResult.pubDer : null;

  let hashBuf;
  try {
    hashBuf = envelopeHash({ expiry, payload, publicKeyId, timestamp });
  } catch {
    return block('INVALID_ARTIFACT', { issue: 'envelope canonicalization failed' });
  }

  if (!verify(hashBuf, signature, pubDer)) {
    return block('INVALID_SIGNATURE', { publicKeyId });
  }

  // Reaching here proves the key WAS resolved: verify() can only return true
  // against real, matching key material, and pubDer is null whenever
  // keyResult.found is false — so a null pubDer can never verify successfully.
  const _resolvedClientId = /** @type {any} */ (keyResult).clientId;

  // ── 11b.: a payload tenant must be the signing key's own ────────────────
  // /sign always writes payload.tenantId from the signing key (parseKeyId(key.keyId).tenantId), so a genuine artifact
  // can never disagree. One that claims another tenant was hand-signed with tenant B's key to speak for tenant A —
  // execution already uses the key's clientId, but downstream lookups keyed on payload.tenantId (portal evidence) must
  // never see it. An artifact with no payload.tenantId is unaffected.
  if (payload.tenantId !== undefined && payload.tenantId !== null && payload.tenantId !== _resolvedClientId) {
    return block('INVALID_ARTIFACT', { field: 'payload.tenantId', publicKeyId });
  }

  // ── 12. Single trusted time source — never from the artifact ─────────────────
  const now = _clock();

  // (SPEC 1.0.1 S-069): timestamp < expiry; equal or inverted pairs (timestamp = now+4s, expiry = now+1s used to pass) are invalid.
  if (timestamp >= expiry) {
    return block('INVALID_ARTIFACT', { field: 'expiry', issue: 'must be greater than timestamp' });
  }
  // (placed after the signature check, like the other time checks: an unauthenticated caller learns nothing about a pair it could not sign)

  // ── 13. Future-timestamp check (timestamp ≤ now + 5 s clock-skew allowance, FUTURE_SKEW_MS in timeCheck.js) ──
  const tsResult = checkTimestamp(timestamp, now);
  if (!tsResult.valid) {
    return block(tsResult.reason, tsResult.details);
  }

  // ── 14. Expiry check (now < expiry, zero tolerance) ──────────────────────────
  const expResult = checkExpiry(expiry, now);
  if (!expResult.valid) {
    return block(expResult.reason, expResult.details);
  }

  // ── 15. Backward skew check — rejects stale-but-valid artifacts ──────────────
  // Runs after signature verification so that forged artifacts get INVALID_SIGNATURE
  // rather than leaking timing information via TIME_SKEW_EXCEEDED.  Only a
  // cryptographically valid artifact can reach this check.
  // Prevents pre-signed artifacts from being held and replayed within their
  // still-valid expiry window beyond the permitted clock-drift window.
  const skewResult = checkSkew(timestamp, now, _maxSkewMs);
  if (!skewResult.valid) {
    return block(skewResult.reason, skewResult.details);
  }

  // ── 16. Key lifecycle ──────────────────────
  // The key's status timeline, not just its status: a deprecated key verifies
  // only artifacts signed before its retirement and only for 65 s after it; an
  // archived or revoked key never verifies an artifact. The timeline is the
  // more advanced of this replica's keystore and the control plane, so a
  // rotation/revocation on any replica holds here within 5 s (or this replica
  // refuses: CONTROL_PLANE_STALE). Runs after signature verification, like
  // the time checks above, so only a valid signer learns the key's state.
  let timeline;
  try {
    timeline = keyStatusTimeline.effective(publicKeyId, /** @type {any} */ (keyResult).timeline || { status: /** @type {any} */ (keyResult).status });
  } catch (err) {
    if (err && err.name === 'ControlPlaneError') return block(err.code, { publicKeyId });
    throw err;
  }
  const lifecycle = checkExecution(timeline, tsResult.tsMs, now);
  if (!lifecycle.valid) {
    return block(/** @type {any} */ (lifecycle).reason, { publicKeyId, .../** @type {any} */ (lifecycle).details });
  }

  return allow({
    publicKeyId,
    // CRYPTO-6: the key store's own authoritative clientId resolution
    // (correct for legacy colon-less publicKeyIds too, unlike re-parsing
    // publicKeyId as a string downstream — see validateBoundRequest.js).
    clientId:    _resolvedClientId,
    timestampMs: tsResult.tsMs,
    expiryMs:    expResult.expiryMs,
  });
}

module.exports = { validateArtifact, isCanonicalSignature };
