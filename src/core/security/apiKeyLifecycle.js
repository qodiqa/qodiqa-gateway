'use strict';

/**
 * API-key lifecycle —.
 *
 * One definition of key expiry, rotation grace and the expiry warning, used by
 * BOTH credential stores (operator keys: src/core/rbac/store.js; signing
 * identity keys: src/core/signing/signingIdentityStore.js). Everything lives in
 * the store records, behind the existing store interfaces, so moves it to
 * PostgreSQL with the rest of each record.
 *
 *   expiry   QODIQA_API_KEY_TTL_DAYS              default 90  (production refuses > 365)
 *   grace    QODIQA_API_KEY_ROTATION_GRACE_HOURS  default 24  — after a rotation the
 *            previous key keeps working this long (never past its own expiry)
 *   warning  QODIQA_API_KEY_EXPIRY_WARNING_DAYS   default 14  — "expiring" status:
 *            WARN event + X-QODIQA-Key-Expires response header
 *   existing keys (no recorded expiry): max(issuedAt + TTL, firstSeen + warning),
 *            assigned once and persisted — no key dies at deploy time.
 */

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;

function _int(name, dflt, min, max) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) && v >= min && v <= max ? v : dflt;
}

function config() {
  return {
    ttlDays:    _int('QODIQA_API_KEY_TTL_DAYS', 90, 1, 3650),
    graceHours: _int('QODIQA_API_KEY_ROTATION_GRACE_HOURS', 24, 0, 720),
    warnDays:   _int('QODIQA_API_KEY_EXPIRY_WARNING_DAYS', 14, 0, 365),
  };
}

const iso = (ms) => new Date(ms).toISOString();

/** Expiry for a key issued at `issuedAtMs`. */
function expiryFor(issuedAtMs, cfg = config()) {
  return iso(issuedAtMs + cfg.ttlDays * DAY_MS);
}

/** Expiry assigned once to an earlier key that has none. */
function transitionExpiry(issuedAtIso, nowMs, cfg = config()) {
  const byIssue = Date.parse(issuedAtIso || '');
  const a = Number.isFinite(byIssue) ? byIssue + cfg.ttlDays * DAY_MS : 0;
  return iso(Math.max(a, nowMs + cfg.warnDays * DAY_MS));
}

/**
 * Fields for issuing a key over an existing record (first issue or rotation).
 * The previous key gets a grace window, capped at its own expiry; an already
 * expired previous key gets none.
 */
function issueFields(existing, newHash, nowMs, cfg = config()) {
  const prevHash = existing && existing.apiKeyHash ? existing.apiKeyHash : null;
  let prevGrace = null;
  if (prevHash && cfg.graceHours > 0) {
    const prevExp = Date.parse(existing.apiKeyExpiresAt || '') || Infinity;
    const until = Math.min(nowMs + cfg.graceHours * HOUR_MS, prevExp);
    if (until > nowMs) prevGrace = iso(until);
  }
  return {
    apiKeyHash:               newHash,
    apiKeyIssuedAt:           iso(nowMs),
    apiKeyExpiresAt:          expiryFor(nowMs, cfg),
    previousApiKeyHash:       prevGrace ? prevHash : null,
    previousApiKeyGraceUntil: prevGrace,
  };
}

/** Fields that remove every key of a record (revocation: immediate, no grace). */
function revokeFields() {
  return { apiKeyHash: null, apiKeyIssuedAt: null, apiKeyExpiresAt: null, previousApiKeyHash: null, previousApiKeyGraceUntil: null };
}

/**
 * Status of a matched key.
 * @param {'current'|'previous'} via
 * @returns {{ status: 'valid'|'expiring'|'grace'|'expired', expiresAt: string|null }}
 */
function keyStatus(record, via, nowMs = Date.now(), cfg = config()) {
  if (via === 'previous') {
    const g = Date.parse(record.previousApiKeyGraceUntil || '');
    return { status: Number.isFinite(g) && nowMs <= g ? 'grace' : 'expired', expiresAt: record.previousApiKeyGraceUntil || null };
  }
  const exp = Date.parse(record.apiKeyExpiresAt || '');
  if (!Number.isFinite(exp)) return { status: 'valid', expiresAt: null };
  if (nowMs > exp) return { status: 'expired', expiresAt: record.apiKeyExpiresAt };
  if (exp - nowMs <= cfg.warnDays * DAY_MS) return { status: 'expiring', expiresAt: record.apiKeyExpiresAt };
  return { status: 'valid', expiresAt: record.apiKeyExpiresAt };
}

module.exports = { config, expiryFor, transitionExpiry, issueFields, revokeFields, keyStatus, DAY_MS, HOUR_MS };
