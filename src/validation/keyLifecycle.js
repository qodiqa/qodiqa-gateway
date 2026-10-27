'use strict';

/**
 * Signing-key lifecycle rules —.
 *
 * a 'deprecated' key verified newly signed artifacts indefinitely,
 * and an archived key verified as 'deprecated'. Verification now checks the
 * artifact's timestamp against the key's status TIMELINE:
 *
 *   EXECUTION (an artifact asking to run now — validateArtifact):
 *     active      verifies (not before the key existed, beyond the future-skew tolerance)
 *     deprecated  only an artifact signed BEFORE the retirement, and only until
 *                 deprecatedAt + DEPRECATED_WINDOW_MS (= max artifact age 60 s +
 *                 future-skew tolerance 5 s = 65 s): the artifacts in flight at
 *                 rotation, nothing new. Unknown retirement time → refused.
 *     archived    never
 *     revoked     never
 *
 *   HISTORICAL (was this validly signed when it was signed — certificates):
 *     the signing time must fall inside [activatedAt, retirement) and the key
 *     must not be revoked (compromise invalidates everything it signed).
 *
 * The timeline is the most-advanced of the local keystore view and the
 * PostgreSQL control plane (src/core/signing/keyStatusTimeline.js), so a
 * rotation or revocation on any replica holds on every replica within 5 s.
 */

const { MAX_SKEW_MS, FUTURE_SKEW_MS } = require('./timeCheck');

const DEPRECATED_WINDOW_MS = MAX_SKEW_MS + FUTURE_SKEW_MS; // 65 000 ms
const RANK = Object.freeze({ active: 0, deprecated: 1, archived: 2, revoked: 3 });

const _ms = (iso) => { const t = iso ? Date.parse(iso) : NaN; return Number.isFinite(t) ? t : null; };

/**
 * @param {{ status: string, activatedAt?: string|null, deprecatedAt?: string|null }} t
 * @param {number} tsMs   the artifact's (signature-verified) timestamp
 * @param {number} nowMs  the verifier's trusted clock
 * @returns {{ valid: true } | { valid: false, reason: string, details: object }}
 */
function checkExecution(t, tsMs, nowMs) {
  const status = t && t.status;
  if (status === 'revoked') return { valid: false, reason: 'KEY_REVOKED', details: { keyStatus: status } };
  if (status === 'archived') return { valid: false, reason: 'KEY_ARCHIVED', details: { keyStatus: status } };
  if (status === 'deprecated') {
    const dep = _ms(t.deprecatedAt);
    if (dep === null) return { valid: false, reason: 'KEY_DEPRECATED', details: { keyStatus: status, issue: 'retirement time unknown' } };
    // a genuine retirement is stamped at rotation time, so it is never in the verifier's
    // future (beyond the clock-skew tolerance). A key record is public metadata that a KEK-less writer of the key file
    // can inject; with a far-future retiredAt such a 'deprecated' key verified forged artifacts indefinitely. Refused.
    if (dep > nowMs + FUTURE_SKEW_MS) return { valid: false, reason: 'KEY_DEPRECATED', details: { keyStatus: status, issue: 'retirement time is in the future' } };
    if (tsMs >= dep) return { valid: false, reason: 'KEY_DEPRECATED', details: { keyStatus: status, issue: 'signed after the key was retired' } };
    if (nowMs >= dep + DEPRECATED_WINDOW_MS) return { valid: false, reason: 'KEY_DEPRECATED', details: { keyStatus: status, issue: 'deprecated-key window elapsed', windowMs: DEPRECATED_WINDOW_MS } };
    return { valid: true };
  }
  if (status === 'active') {
    const act = _ms(t.activatedAt);
    if (act !== null && tsMs < act - FUTURE_SKEW_MS) return { valid: false, reason: 'KEY_NOT_YET_ACTIVE', details: { keyStatus: status } };
    return { valid: true };
  }
  return { valid: false, reason: 'KEY_STATUS_UNKNOWN', details: { keyStatus: status ?? null } };
}

/**
 * @param {{ status: string, activatedAt?: string|null, deprecatedAt?: string|null, archivedAt?: string|null }} t
 * @param {number} signedAtMs
 */
function checkHistorical(t, signedAtMs) {
  const status = t && t.status;
  if (!status || !(status in RANK)) return { valid: false, reason: 'KEY_STATUS_UNKNOWN', details: {} };
  if (status === 'revoked') return { valid: false, reason: 'KEY_REVOKED', details: { keyStatus: status } };
  if (!Number.isFinite(signedAtMs)) return { valid: false, reason: 'SIGNING_TIME_UNKNOWN', details: {} };
  const act = _ms(t.activatedAt);
  if (act !== null && signedAtMs < act - FUTURE_SKEW_MS) return { valid: false, reason: 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', details: { keyStatus: status, issue: 'signed before the key existed' } };
  const end = _ms(t.deprecatedAt) ?? _ms(t.archivedAt);
  if (status !== 'active' && end === null) return { valid: false, reason: 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', details: { keyStatus: status, issue: 'retirement time unknown' } };
  if (end !== null && signedAtMs >= end) return { valid: false, reason: 'KEY_NOT_ACTIVE_AT_SIGNING_TIME', details: { keyStatus: status, issue: 'signed after the key was retired' } };
  return { valid: true };
}

/** The more-advanced of two timelines (status never moves backwards); timestamps fill in from either. */
function mergeTimelines(a, b) {
  if (!a) return b || null;
  if (!b) return a;
  const [hi, lo] = (RANK[b.status] ?? -1) > (RANK[a.status] ?? -1) ? [b, a] : [a, b];
  return {
    status:       hi.status,
    activatedAt:  hi.activatedAt  || lo.activatedAt  || null,
    deprecatedAt: hi.deprecatedAt || lo.deprecatedAt || null,
    archivedAt:   hi.archivedAt   || lo.archivedAt   || null,
    revokedAt:    hi.revokedAt    || lo.revokedAt    || null,
  };
}

module.exports = { checkExecution, checkHistorical, mergeTimelines, DEPRECATED_WINDOW_MS, RANK };
