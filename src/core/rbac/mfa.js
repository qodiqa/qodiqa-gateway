'use strict';

/**
 * Operator MFA — (design decision D4: TOTP + 10 recovery codes,
 * step-up on privileged mutations, required by default).
 *
 * TOTP per RFC 6238 (HMAC-SHA1, 30 s step, 6 digits, ±1 step drift), built on
 * node:crypto — no new dependency. State lives on the operator's RBAC user
 * record through the store's own interface (getMfaState / setMfaState), so
 * moves it to PostgreSQL with the record:
 *   - the TOTP secret is AES-256-GCM encrypted with the platform KEK
 *     (services/secrets/secretsProvider.js — the same KEK that protects
 *     private keys and webhook secrets); it is never returned after enrolment;
 *   - recovery codes are stored only as SHA-256(userId:code) and are single-use;
 *   - a TOTP code is accepted at most once per step (replay guard);
 *   - MAX_FAILURES failed codes within LOCK_MS lock that user's MFA for LOCK_MS.
 * Every enrolment, verification, failure, lock, recovery-code use and reset is
 * emitted as an RBAC_MFA_* event (ingested into platform_audit_events,
 * category ACCESS_CONTROL). Codes and secrets never appear in events.
 *
 * QODIQA_OPS_MFA_REQUIRED (default true; production refuses false) switches the
 * step-up requirement (src/middleware/mfaStepUp.js) — not the stored state.
 */

const crypto = require('crypto');
const { emit } = require('../../../services/logger');
const secretsProvider = require('../../../services/secrets/secretsProvider');

const STEP_S = 30;
const DIGITS = 6;
const DRIFT_STEPS = 1;
const SECRET_BYTES = 20;
const RECOVERY_CODE_COUNT = 10;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60_000;
const PENDING_TTL_MS = 10 * 60_000;
const ISSUER = 'QODIQA';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

class MfaError extends Error { constructor(message, code) { super(message); this.name = 'MfaError'; this.code = code; } }

function isRequired() { return process.env.QODIQA_OPS_MFA_REQUIRED !== 'false'; }

// ── base32 (RFC 4648, no padding) ─────────────────────────────────────────────
function base32Encode(buf) {
  let bits = 0; let value = 0; let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0; let value = 0; const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new MfaError('invalid base32', 'MFA_INVALID_SECRET');
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

// ── HOTP / TOTP ───────────────────────────────────────────────────────────────
function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', secret).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % (10 ** DIGITS)).padStart(DIGITS, '0');
}
const stepAt = (ms) => Math.floor(ms / 1000 / STEP_S);
function totp(secret, nowMs = Date.now()) { return hotp(secret, stepAt(nowMs)); }

/** @returns {number|null} the matched step, or null */
function _matchTotp(secret, code, nowMs, lastUsedStep) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const cur = stepAt(nowMs);
  for (let d = -DRIFT_STEPS; d <= DRIFT_STEPS; d++) {
    const step = cur + d;
    if (lastUsedStep != null && step <= lastUsedStep) continue; // replay guard
    const expect = Buffer.from(hotp(secret, step));
    const got = Buffer.from(code);
    if (expect.length === got.length && crypto.timingSafeEqual(expect, got)) return step;
  }
  return null;
}

// ── secret at rest ────────────────────────────────────────────────────────────
function _encrypt(plain) {
  const kek = secretsProvider.getKeyEncryptionKey();
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', kek, iv);
  const enc = Buffer.concat([c.update(plain), c.final()]);
  return { enc: enc.toString('base64'), iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64') };
}
function _decrypt({ enc, iv, tag }) {
  const kek = secretsProvider.getKeyEncryptionKey();
  const d = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(enc, 'base64')), d.final()]);
}

// ── recovery codes ────────────────────────────────────────────────────────────
function _newRecoveryCode() {
  const s = base32Encode(crypto.randomBytes(7)).slice(0, 10).toLowerCase(); // 50 bits
  return `${s.slice(0, 5)}-${s.slice(5, 10)}`;
}
const _normCode = (c) => String(c).toLowerCase().replace(/[^a-z2-7]/g, '');
const _codeHash = (userId, code) => crypto.createHash('sha256').update(`${userId}:${_normCode(code)}`).digest('hex');

// ── store access (dependency-injectable for tests) ────────────────────────────
function _store(opts) { return (opts && opts.store) || require('./store'); }

// the user store is the control plane — setMfaState() returns a
// Promise in pg mode (versioned write). Every result below is returned only
// after the state change is committed; the callers await. A concurrent
// verification of the same code on another replica loses the versioned write
// (409) and so cannot be used twice.
const { after } = require('../controlPlane');

/** Status for the operator (never secrets). */
function status(userId, opts) {
  const m = _store(opts).getMfaState(userId);
  if (!m || !m.enabled) return { enrolled: false, pending: !!(m && m.pending), remainingRecoveryCodes: 0, lockedUntil: null };
  return {
    enrolled: true, enrolledAt: m.enrolledAt, pending: false,
    remainingRecoveryCodes: (m.recoveryCodeHashes || []).length,
    lockedUntil: m.lockedUntil && Date.parse(m.lockedUntil) > Date.now() ? m.lockedUntil : null,
  };
}

/** Start enrolment (self-service while not enrolled). Returns the secret ONCE. */
function beginEnrollment(user, opts) {
  const store = _store(opts);
  const m = store.getMfaState(user.id);
  if (m && m.enabled) throw new MfaError('MFA is already enrolled; an administrator must reset it first', 'MFA_ALREADY_ENROLLED');
  const secret = crypto.randomBytes(SECRET_BYTES);
  const b32 = base32Encode(secret);
  return after(store.setMfaState(user.id, { enabled: false, pending: { secret: _encrypt(secret), createdAt: new Date().toISOString() } }, { updatedBy: user.username }), () => {
    emit('INFO', 'RBAC_MFA_ENROLLMENT_STARTED', { userId: user.id, username: user.username });
    const label = encodeURIComponent(`${ISSUER}:${user.username}`);
    return { secret: b32, otpauthUri: `otpauth://totp/${label}?secret=${b32}&issuer=${ISSUER}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_S}` };
  });
}

/** Confirm enrolment with a first code. Returns the recovery codes ONCE. */
function confirmEnrollment(user, code, opts, nowMs = Date.now()) {
  const store = _store(opts);
  const m = store.getMfaState(user.id);
  if (m && m.enabled) throw new MfaError('MFA is already enrolled', 'MFA_ALREADY_ENROLLED');
  if (!m || !m.pending) throw new MfaError('No enrolment in progress', 'MFA_NO_PENDING_ENROLLMENT');
  if (nowMs - Date.parse(m.pending.createdAt) > PENDING_TTL_MS) {
    return after(store.setMfaState(user.id, null, { updatedBy: user.username }), () => {
      throw new MfaError('Enrolment expired; start again', 'MFA_ENROLLMENT_EXPIRED');
    });
  }
  const secret = _decrypt(m.pending.secret);
  const step = _matchTotp(secret, String(code ?? ''), nowMs, null);
  if (step === null) {
    emit('WARN', 'RBAC_MFA_ENROLLMENT_FAILED', { userId: user.id, username: user.username });
    throw new MfaError('Invalid code', 'MFA_INVALID');
  }
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, _newRecoveryCode);
  return after(store.setMfaState(user.id, {
    enabled: true, enrolledAt: new Date(nowMs).toISOString(), secret: m.pending.secret,
    recoveryCodeHashes: codes.map((c) => _codeHash(user.id, c)), lastUsedStep: step,
    failedAttempts: 0, lockedUntil: null,
  }, { updatedBy: user.username }), () => {
    emit('INFO', 'RBAC_MFA_ENROLLED', { userId: user.id, username: user.username, recoveryCodes: RECOVERY_CODE_COUNT });
    return { recoveryCodes: codes };
  });
}

/**
 * Verify a step-up code (TOTP, or a single-use recovery code).
 * @returns {{ ok: true, method: 'totp'|'recovery', remainingRecoveryCodes: number }
 *          | { ok: false, reason: 'MFA_NOT_ENROLLED'|'MFA_LOCKED'|'MFA_INVALID', retryAfterSeconds?: number }}
 */
function verifyStepUp(user, code, opts, nowMs = Date.now()) {
  const store = _store(opts);
  const m = store.getMfaState(user.id);
  if (!m || !m.enabled) return { ok: false, reason: 'MFA_NOT_ENROLLED' };
  if (m.lockedUntil && Date.parse(m.lockedUntil) > nowMs) {
    return { ok: false, reason: 'MFA_LOCKED', retryAfterSeconds: Math.ceil((Date.parse(m.lockedUntil) - nowMs) / 1000) };
  }
  const secret = _decrypt(m.secret);
  const c = String(code ?? '').trim();
  const step = _matchTotp(secret, c, nowMs, m.lastUsedStep);
  if (step !== null) {
    return after(store.setMfaState(user.id, { ...m, lastUsedStep: step, failedAttempts: 0, lockedUntil: null }, { updatedBy: user.username }), () => {
      emit('INFO', 'RBAC_MFA_VERIFIED', { userId: user.id, username: user.username, method: 'totp' });
      return { ok: true, method: 'totp', remainingRecoveryCodes: (m.recoveryCodeHashes || []).length };
    });
  }
  if (!/^\d{6}$/.test(c)) {
    const h = _codeHash(user.id, c);
    const list = m.recoveryCodeHashes || [];
    const idx = list.indexOf(h);
    if (idx >= 0) {
      const remaining = list.filter((_, i) => i !== idx);
      return after(store.setMfaState(user.id, { ...m, recoveryCodeHashes: remaining, failedAttempts: 0, lockedUntil: null }, { updatedBy: user.username }), () => {
        emit('WARN', 'RBAC_MFA_RECOVERY_CODE_USED', { userId: user.id, username: user.username, remainingRecoveryCodes: remaining.length });
        return { ok: true, method: 'recovery', remainingRecoveryCodes: remaining.length };
      });
    }
  }
  // failure
  const windowStart = m.firstFailureAt && nowMs - Date.parse(m.firstFailureAt) <= LOCK_MS ? m.firstFailureAt : new Date(nowMs).toISOString();
  const failedAttempts = (windowStart === m.firstFailureAt ? (m.failedAttempts || 0) : 0) + 1;
  const lock = failedAttempts >= MAX_FAILURES;
  return after(store.setMfaState(user.id, {
    ...m, failedAttempts: lock ? 0 : failedAttempts, firstFailureAt: lock ? null : windowStart,
    lockedUntil: lock ? new Date(nowMs + LOCK_MS).toISOString() : (m.lockedUntil || null),
  }, { updatedBy: user.username }), () => {
    emit('WARN', 'RBAC_MFA_FAILED', { userId: user.id, username: user.username, failedAttempts: lock ? MAX_FAILURES : failedAttempts });
    try { require('../../observability/metrics').mfaEventsTotal.inc({ outcome: 'failed' }); } catch { /* best-effort metric */ }
    if (lock) {
      emit('WARN', 'RBAC_MFA_LOCKED', { userId: user.id, username: user.username, lockMs: LOCK_MS });
      try { require('../../observability/metrics').mfaEventsTotal.inc({ outcome: 'locked' }); } catch { /* best-effort metric */ }
      return { ok: false, reason: 'MFA_LOCKED', retryAfterSeconds: Math.ceil(LOCK_MS / 1000) };
    }
    return { ok: false, reason: 'MFA_INVALID' };
  });
}

/** Remove a user's MFA (administrator action; itself a step-up action). */
function reset(userId, { by = 'system', store } = {}) {
  const s = store || require('./store');
  return after(s.setMfaState(userId, null, { updatedBy: by }), () => {
    emit('WARN', 'RBAC_MFA_RESET', { userId, resetBy: by });
  });
}

module.exports = {
  isRequired, status, beginEnrollment, confirmEnrollment, verifyStepUp, reset,
  MfaError, totp, hotp, base32Encode, base32Decode,
  STEP_S, DIGITS, MAX_FAILURES, LOCK_MS, RECOVERY_CODE_COUNT, PENDING_TTL_MS,
};
