'use strict';

/**
 * Parse any timestamp representation into milliseconds since epoch.
 *
 * Accepted forms:
 *   - Positive finite number           — used directly as Unix-ms
 *   - 10-digit numeric string          — treated as Unix seconds → ×1000
 *   - >10-digit numeric string         — treated as Unix milliseconds
 *   - ISO-8601 string                  — parsed via new Date()
 *
 * Returns NaN for any other input (null, object, negative finite, Infinity, …).
 *
 * @param {unknown} raw
 * @returns {number}  Milliseconds since epoch, or NaN.
 */
function parseTimestamp(raw) {
  if (typeof raw === 'number') {
    return Number.isFinite(raw) && raw > 0 ? raw : NaN;
  }
  if (typeof raw === 'string' && raw.length > 0) {
    if (/^\d+$/.test(raw)) {
      const n = parseInt(raw, 10);
      return raw.length <= 10 ? n * 1000 : n;
    }
    const ms = new Date(raw).getTime();
    return Number.isFinite(ms) ? ms : NaN;
  }
  return NaN;
}

/**
 * Future-timestamp tolerance — 5 s.
 *
 * Artifacts are signed by one instance and verified by another; a zero
 * tolerance turned any forward clock drift between them into spurious
 * FUTURE_TIMESTAMP blocks. 5 s covers NTP-synced fleets with margin while
 * keeping what a pre-dating signer gains to 5 s. The same constant bounds the
 * deprecated-key window (keyLifecycle.js) and the replay barrier (nonceStore.js).
 */
const FUTURE_SKEW_MS = 5_000;

/**
 * Validate that the artifact timestamp is not in the future beyond the
 * tolerance: up to FUTURE_SKEW_MS ahead of `now` is accepted, anything further
 * is FUTURE_TIMESTAMP. `now` is always caller-supplied (from a single trusted
 * source, never from the artifact itself) so the function is pure and testable.
 *
 * @param {unknown} timestamp  Raw timestamp from the artifact.
 * @param {number}  now        Trusted reference time in ms.
 * @returns {{ valid: boolean, reason?: string, details?: object, tsMs?: number }}
 */
function checkTimestamp(timestamp, now) {
  const ts = parseTimestamp(timestamp);
  if (!Number.isFinite(ts)) {
    return { valid: false, reason: 'INVALID_ARTIFACT', details: { field: 'timestamp', value: timestamp } };
  }
  if (ts > now + FUTURE_SKEW_MS) {
    return { valid: false, reason: 'FUTURE_TIMESTAMP', details: { timestampMs: ts, nowMs: now, skewMs: ts - now, toleranceMs: FUTURE_SKEW_MS } };
  }
  return { valid: true, tsMs: ts };
}

/**
 * Maximum accepted backward clock drift (ms) between artifact timestamp and server clock.
 *
 * An artifact whose timestamp predates now by more than this value is rejected
 * with TIME_SKEW_EXCEEDED regardless of its expiry field.  This prevents pre-signed
 * artifacts from being held and replayed later within their expiry window.
 *
 * kept at 60 s, and /sign now caps the ttl it grants at
 * this same value (ttlClamped), so an artifact's expiry never claims more life
 * than verification will give it.
 *
 * Override via validateArtifact({ _maxSkewMs }) for testing only.
 */
const MAX_SKEW_MS = 60_000;
const MAX_ARTIFACT_AGE_MS = MAX_SKEW_MS;

/**
 * Validate that the artifact timestamp is not older than MAX_SKEW_MS.
 *
 * Assumes checkTimestamp() has already passed.  Only the backward direction is
 * checked here; the forward direction is handled by checkTimestamp() (5 s
 * tolerance).
 *
 * @param {unknown} timestamp  Raw timestamp from the artifact.
 * @param {number}  now        Trusted reference time in ms.
 * @param {number}  [maxSkewMs=MAX_SKEW_MS]
 * @returns {{ valid: boolean, reason?: string, details?: object }}
 */
function checkSkew(timestamp, now, maxSkewMs = MAX_SKEW_MS) {
  const ts = parseTimestamp(timestamp);
  if (!Number.isFinite(ts)) {
    return { valid: false, reason: 'INVALID_ARTIFACT', details: { field: 'timestamp', value: timestamp } };
  }
  const backwardDrift = now - ts;
  if (backwardDrift > maxSkewMs) {
    return {
      valid:   false,
      reason:  'TIME_SKEW_EXCEEDED',
      details: { timestampMs: ts, nowMs: now, skewMs: backwardDrift, maxSkewMs },
    };
  }
  return { valid: true };
}

/**
 * Validate that the artifact has not expired.
 *
 * No tolerance window — `now >= expiry` is immediately rejected.
 *
 * @param {unknown} expiry  Raw expiry from the artifact.
 * @param {number}  now     Trusted reference time in ms.
 * @returns {{ valid: boolean, reason?: string, details?: object, expiryMs?: number }}
 */
function checkExpiry(expiry, now) {
  const exp = parseTimestamp(expiry);
  if (!Number.isFinite(exp)) {
    return { valid: false, reason: 'INVALID_ARTIFACT', details: { field: 'expiry', value: expiry } };
  }
  if (now >= exp) {
    return { valid: false, reason: 'EXPIRED', details: { expiryMs: exp, nowMs: now, expiredByMs: now - exp } };
  }
  return { valid: true, expiryMs: exp };
}

module.exports = { parseTimestamp, checkTimestamp, checkSkew, checkExpiry, MAX_SKEW_MS, MAX_ARTIFACT_AGE_MS, FUTURE_SKEW_MS };
