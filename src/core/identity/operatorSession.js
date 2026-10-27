'use strict';

/**
 * Operator session tokens: what a successful browser single-sign-on login (SAML, and any other flow that ends at the gateway) hands back, so that the operator console can
 * call the admin API with `Authorization: Bearer qos1.<payload>.<kid>.<mac>` without an API key.
 *
 *   mint({ userId, issuer, subject, providerId, assured, ttlSec, now }) -> { token, expiresAt, jti }
 *   verify(token, { now })  -> { ok: true, payload } | { ok: false, reason }
 *
 * The token carries no authority of its own: it names an RBAC user, and the user is looked up (and must still be ENABLED and still linked to the same (issuer, subject)) on every
 * request, so disabling or unlinking the user ends every session at once. It is a MAC (macKeyring purpose OPERATOR_SESSION: keys rotate with the keyring, a token minted under a
 * retired key stops verifying when the key is removed) over the payload; the lifetime defaults to 30 minutes and is capped at 8 hours. `as` records that the login was a second-factor
 * one (provider assurance): the MFA step-up accepts it exactly as it accepts an OIDC token the provider vouches for, but only until `au` (the end of the provider's maximum
 * authentication age, counted from the IdP's authentication instant): a long session does not carry a stale second factor (F10V-06).
 */

const crypto = require('crypto');
const macKeyring = require('../security/macKeyring');

const PREFIX = 'qos1.';
const DEFAULT_TTL_SEC = 1800;
const MAX_TTL_SEC = 8 * 3600;
// qos1 . payload . kid . mac  (the keyring tag is "kid.mac")
const looksLikeSession = (t) => typeof t === 'string' && t.startsWith(PREFIX) && t.length < 2048 && t.split('.').length === 4;

const linkHash = (issuer, subject) => crypto.createHash('sha256').update(`${issuer}\n${subject}`, 'utf8').digest('hex').slice(0, 32);

function mint({ userId, issuer, subject, providerId, assured = false, assuredUntilSec = null, ttlSec = DEFAULT_TTL_SEC, now = Date.now() }) {
  if (typeof userId !== 'string' || !userId) throw new TypeError('operatorSession.mint: userId');
  const ttl = Math.min(Math.max(Number.isInteger(ttlSec) ? ttlSec : DEFAULT_TTL_SEC, 60), MAX_TTL_SEC);
  const iat = Math.floor(now / 1000);
  const payload = { v: 1, sub: userId, lk: linkHash(issuer, subject), prov: String(providerId || ''), as: assured === true, ...(assured === true && Number.isFinite(assuredUntilSec) ? { au: Math.floor(assuredUntilSec) } : {}), iat, exp: iat + ttl, jti: crypto.randomBytes(12).toString('hex') };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const tag = macKeyring.sign(macKeyring.PURPOSES.OPERATOR_SESSION, body);
  return { token: `${PREFIX}${body}.${tag}`, expiresAt: payload.exp, jti: payload.jti };
}

function verify(token, { now = Date.now() } = {}) {
  if (!looksLikeSession(token)) return { ok: false, reason: 'SESSION_MALFORMED' };
  const rest = token.slice(PREFIX.length);
  const dot = rest.indexOf('.');
  const body = rest.slice(0, dot); const tag = rest.slice(dot + 1);
  let v;
  try { v = macKeyring.verify(macKeyring.PURPOSES.OPERATOR_SESSION, body, tag); } catch { return { ok: false, reason: 'SESSION_KEYRING_UNAVAILABLE', unavailable: true }; }
  if (!v.ok) return { ok: false, reason: 'SESSION_INVALID' };
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return { ok: false, reason: 'SESSION_MALFORMED' }; }
  if (!payload || payload.v !== 1 || typeof payload.sub !== 'string' || typeof payload.exp !== 'number' || typeof payload.iat !== 'number') return { ok: false, reason: 'SESSION_MALFORMED' };
  const nowSec = Math.floor(now / 1000);
  if (nowSec >= payload.exp) return { ok: false, reason: 'SESSION_EXPIRED' };
  if (payload.iat > nowSec + 60 || payload.exp - payload.iat > MAX_TTL_SEC) return { ok: false, reason: 'SESSION_MALFORMED' };
  return { ok: true, payload };
}

module.exports = { mint, verify, looksLikeSession, linkHash, PREFIX, DEFAULT_TTL_SEC, MAX_TTL_SEC };
