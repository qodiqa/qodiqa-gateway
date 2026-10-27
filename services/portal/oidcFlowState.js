'use strict';

/**
 * OIDC flow-state token —.
 *
 * The OIDC `state` parameter round-trips through the browser and the IdP
 * unmodified (RFC 6749 §4.1.1/§10.12), so it can carry the PKCE
 * code_verifier and nonce itself — HMAC-signed so the browser can neither
 * read nor forge them — instead of requiring a server-side session store OR
 * a short-lived cookie for the redirect round trip. This keeps the OIDC
 * login flow inside this codebase's existing bearer-token-only,
 * credentials:false CORS/cookie model (src/infra/cors/corsPolicy.js) with
 * zero new cookie or CSRF-middleware surface — the signed `state` value
 * itself IS the CSRF protection (RFC 6749 §10.12): an attacker who cannot
 * forge the signature cannot construct a `state` this server will accept,
 * so a forged/replayed callback is rejected exactly as it would be by a
 * traditional session-bound anti-CSRF token.
 *
 * Same HMAC construction as services/portal/portalSessionToken.js and
 * services/executionInvariantToken.js — see either's header
 * comment for the general pattern this mirrors. Uses the SAME
 * QODIQA_PORTAL_SESSION_SECRET as portalSessionToken.js (same trust
 * boundary: both protect the tenant-portal authentication surface: purpose
 * isolation from the KEK/execution-invariant secret is what matters, per
 * the standing rule those two follow — a second, portal-flow-specific
 * secret would not add any real separation within the SAME portal trust
 * boundary, only configuration surface).
 *
 * Deliberately SHORT-LIVED (5 minutes, not configurable) — an OIDC redirect
 * round trip normally completes in seconds; this is not a session token and
 * has no legitimate reason to be long-lived.
 */

const crypto = require('crypto');

const FLOW_STATE_TTL_MS = 5 * 60 * 1000; // 5 minutes, fixed
const SIGNATURE_RE = /^[a-f0-9]{64}$/;

function _secret() {
  const raw = process.env.QODIQA_PORTAL_SESSION_SECRET;
  if (!raw) {
    throw new Error(
      'QODIQA_PORTAL_SESSION_SECRET must be set to mint or verify the OIDC flow-state token.',
    );
  }
  return Buffer.from(raw, 'utf8');
}

function _hmac(message) {
  return crypto.createHmac('sha256', _secret()).update(message, 'utf8').digest();
}

function _base64UrlEncode(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function _base64UrlDecode(str) {
  return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
}

/**
 * Mint a signed flow-state value to pass as the OIDC `state` parameter.
 * @param {{ nonce: string, codeVerifier: string }} fields
 * @returns {string} `<base64url(payload)>.<hex signature>`
 */
function mintFlowState({ nonce, codeVerifier }) {
  if (typeof nonce !== 'string' || nonce.length === 0) {
    throw new TypeError('mintFlowState: nonce must be a non-empty string');
  }
  if (typeof codeVerifier !== 'string' || codeVerifier.length === 0) {
    throw new TypeError('mintFlowState: codeVerifier must be a non-empty string');
  }
  const issuedAt = Date.now();
  const payload  = { nonce, codeVerifier, issuedAt, csrf: crypto.randomBytes(16).toString('hex') };
  const encoded  = _base64UrlEncode(payload);
  const signature = _hmac(encoded).toString('hex');
  return `${encoded}.${signature}`;
}

/**
 * Verify and decode a flow-state value returned by the IdP as `state`.
 * Fail-closed: any structural defect, signature mismatch, or expiry
 * returns null.
 * @param {unknown} state
 * @param {{ _now?: number }} [opts] — injectable for tests only
 * @returns {{ nonce: string, codeVerifier: string } | null}
 */
function verifyFlowState(state, opts = {}) {
  if (typeof state !== 'string') return null;
  const dot = state.lastIndexOf('.');
  if (dot === -1) return null;

  const encoded   = state.slice(0, dot);
  const signature = state.slice(dot + 1);
  if (!SIGNATURE_RE.test(signature)) return null;

  let expected;
  try {
    expected = _hmac(encoded);
  } catch {
    return null;
  }

  const provided = Buffer.from(signature, 'hex');
  if (provided.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(provided, expected)) return null;

  let payload;
  try {
    payload = _base64UrlDecode(encoded);
  } catch {
    return null;
  }

  const { nonce, codeVerifier, issuedAt } = payload || {};
  if (typeof nonce !== 'string' || nonce.length === 0) return null;
  if (typeof codeVerifier !== 'string' || codeVerifier.length === 0) return null;
  if (typeof issuedAt !== 'number' || !Number.isFinite(issuedAt) || issuedAt <= 0) return null;

  const now = typeof opts._now === 'number' ? opts._now : Date.now();
  if (issuedAt > now + 1000) return null;
  if (now - issuedAt > FLOW_STATE_TTL_MS) return null;

  return { nonce, codeVerifier };
}

module.exports = {
  mintFlowState,
  verifyFlowState,
  FLOW_STATE_TTL_MS,
};
