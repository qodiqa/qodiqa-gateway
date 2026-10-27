'use strict';

/**
 * JWT verification for OpenID Connect bearer tokens - dependency-free (Node crypto), strict, no network.
 *
 *   verify(token, { keyFor, issuer, audience, algorithms, clockSkewSec, now, maxLifetimeSec })
 *     -> { header, claims }                    or throws JwtError(code, message)
 *
 * What it refuses (each is a distinct error code, none is a silent downgrade):
 *   JWT_MALFORMED          not three base64url segments, JSON that is not an object, a token longer than 16 KiB, a duplicate or non-string header member
 *   JWT_ALG_NOT_ALLOWED    `alg` not in the allowlist (default RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA). `none` and every HMAC algorithm (HS*) are
 *                          never allowed whatever the configuration says: a public IdP key must not be usable as an HMAC secret (the classic algorithm-confusion attack)
 *   JWT_CRIT_UNSUPPORTED   a `crit` header (we implement no critical extensions)
 *   JWT_KEY_UNKNOWN        `keyFor(header)` found no key (the caller owns key discovery; the header's jku / x5u / jwk members are NEVER used to fetch or accept a key)
 *   JWT_KEY_MISMATCH       the key's type or curve does not fit `alg` (an RSA key for ES256, a P-256 key for ES384, ...)
 *   JWT_SIGNATURE_INVALID  the signature does not verify
 *   JWT_ISSUER_MISMATCH    `iss` is not exactly the configured issuer
 *   JWT_AUDIENCE_MISMATCH  none of `aud` is a configured audience
 *   JWT_EXPIRED / JWT_NOT_YET_VALID / JWT_EXP_MISSING / JWT_LIFETIME_TOO_LONG / JWT_IAT_IN_FUTURE   time claims (exp is REQUIRED), with a bounded clock skew
 *   JWT_SUBJECT_MISSING    no non-empty string `sub` of at most 255 characters
 *
 * `keyFor` returns a Node KeyObject (public). ECDSA signatures are the JOSE r||s form (ieee-p1363), RSASSA-PSS uses salt length = hash length.
 */

const crypto = require('crypto');

class JwtError extends Error {
  constructor(code, message) { super(message || code); this.name = 'JwtError'; this.code = code; }
}

const MAX_TOKEN_BYTES = 16 * 1024;
const DEFAULT_ALGS = Object.freeze(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA']);
const ALG_INFO = Object.freeze({
  RS256: { kty: 'rsa', hash: 'sha256' }, RS384: { kty: 'rsa', hash: 'sha384' }, RS512: { kty: 'rsa', hash: 'sha512' },
  PS256: { kty: 'rsa', hash: 'sha256', pss: 32 }, PS384: { kty: 'rsa', hash: 'sha384', pss: 48 }, PS512: { kty: 'rsa', hash: 'sha512', pss: 64 },
  ES256: { kty: 'ec', hash: 'sha256', curve: 'prime256v1' }, ES384: { kty: 'ec', hash: 'sha384', curve: 'secp384r1' }, ES512: { kty: 'ec', hash: 'sha512', curve: 'secp521r1' },
  EdDSA: { kty: 'ed25519', hash: null },
});
const B64URL = /^[A-Za-z0-9_-]*$/;

function b64urlDecode(s, what) {
  if (typeof s !== 'string' || !B64URL.test(s)) throw new JwtError('JWT_MALFORMED', `${what} is not base64url`);
  return Buffer.from(s, 'base64url');
}

function parseJson(buf, what) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { throw new JwtError('JWT_MALFORMED', `${what} is not UTF-8`); }
  rejectDuplicateMembers(text, what);
  let v;
  try { v = JSON.parse(text); } catch { throw new JwtError('JWT_MALFORMED', `${what} is not JSON`); }
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new JwtError('JWT_MALFORMED', `${what} is not a JSON object`);
  return v;
}

/** JSON.parse keeps the LAST of two equal member names: a header `{"alg":"RS256","alg":"none"}` reads differently in different parsers. Refuse duplicates at the top level. */
function rejectDuplicateMembers(text, what) {
  const seen = new Set(); let depth = 0; let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1; let s = '';
      while (j < text.length && text[j] !== '"') { if (text[j] === '\\') { s += text[j] + (text[j + 1] || ''); j += 2; } else { s += text[j]; j++; } }
      if (depth === 1) {
        let k = j + 1; while (k < text.length && /\s/.test(text[k])) k++;
        if (text[k] === ':') {
          let name = s; try { name = JSON.parse(`"${s}"`); } catch { /* invalid escape: JSON.parse of the whole text fails anyway */ }   // F10V-05: "sub" is the member "sub"
          if (seen.has(name)) throw new JwtError('JWT_MALFORMED', `${what} repeats the member ${name.slice(0, 30)}`); seen.add(name);
        }
      }
      i = j + 1; continue;
    }
    if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') depth--;
    i++;
  }
}

function keyMatches(keyObject, info) {
  const t = keyObject.asymmetricKeyType;
  if (info.kty === 'rsa') return t === 'rsa' || t === 'rsa-pss';
  if (info.kty === 'ec') return t === 'ec' && keyObject.asymmetricKeyDetails && keyObject.asymmetricKeyDetails.namedCurve === info.curve;
  if (info.kty === 'ed25519') return t === 'ed25519';
  return false;
}

function verifySignature(alg, keyObject, signingInput, signature) {
  const info = ALG_INFO[alg];
  const data = Buffer.from(signingInput, 'ascii');
  if (info.kty === 'ed25519') return crypto.verify(null, data, keyObject, signature);
  if (info.kty === 'ec') return crypto.verify(info.hash, data, { key: keyObject, dsaEncoding: 'ieee-p1363' }, signature);
  if (info.pss) return crypto.verify(info.hash, data, { key: keyObject, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: info.pss }, signature);
  return crypto.verify(info.hash, data, keyObject, signature);
}

const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

/** Decode WITHOUT verifying: only to read `iss` (to pick the provider) and `kid`. Never trust the result. */
function peek(token) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_BYTES) throw new JwtError('JWT_MALFORMED', 'token too long or not a string');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) throw new JwtError('JWT_MALFORMED', 'a JWT has three non-empty segments');
  const header = parseJson(b64urlDecode(parts[0], 'header'), 'header');
  const claims = parseJson(b64urlDecode(parts[1], 'payload'), 'payload');
  return { header, claims, parts };
}

function looksLikeJwt(token) {
  return typeof token === 'string' && token.length <= MAX_TOKEN_BYTES && /^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]+$/.test(token) && token.startsWith('ey');
}

function verify(token, opts) {
  const { keyFor, issuer, audience, algorithms = DEFAULT_ALGS, clockSkewSec = 60, now = Date.now(), maxLifetimeSec = 24 * 3600 } = opts || {};
  if (typeof keyFor !== 'function') throw new TypeError('verify: keyFor is required');
  if (typeof issuer !== 'string' || !issuer) throw new TypeError('verify: issuer is required');
  const wantAud = Array.isArray(audience) ? audience : [audience];
  if (wantAud.length === 0 || wantAud.some((a) => typeof a !== 'string' || !a)) throw new TypeError('verify: audience is required');

  const { header, claims, parts } = peek(token);
  const alg = header.alg;
  if (typeof alg !== 'string' || !Object.prototype.hasOwnProperty.call(ALG_INFO, alg) || !algorithms.includes(alg)) throw new JwtError('JWT_ALG_NOT_ALLOWED', 'alg is not allowed');
  if (header.crit !== undefined) throw new JwtError('JWT_CRIT_UNSUPPORTED', 'critical header extensions are not supported');
  if (header.kid !== undefined && (typeof header.kid !== 'string' || header.kid.length > 256)) throw new JwtError('JWT_MALFORMED', 'kid is a string of at most 256 characters');

  const key = keyFor({ alg, kid: header.kid === undefined ? null : header.kid });
  if (!key) throw new JwtError('JWT_KEY_UNKNOWN', 'no key for this token');
  if (!keyMatches(key, ALG_INFO[alg])) throw new JwtError('JWT_KEY_MISMATCH', 'the key does not fit the algorithm');

  const signature = b64urlDecode(parts[2], 'signature');
  let ok = false;
  try { ok = verifySignature(alg, key, `${parts[0]}.${parts[1]}`, signature); } catch { ok = false; }
  if (!ok) throw new JwtError('JWT_SIGNATURE_INVALID', 'signature does not verify');

  // claims - only after the signature is proven
  if (claims.iss !== issuer) throw new JwtError('JWT_ISSUER_MISMATCH', 'issuer mismatch');
  const auds = typeof claims.aud === 'string' ? [claims.aud] : (Array.isArray(claims.aud) && claims.aud.every((a) => typeof a === 'string') ? claims.aud : []);
  if (!auds.some((a) => wantAud.includes(a))) throw new JwtError('JWT_AUDIENCE_MISMATCH', 'audience mismatch');
  const nowSec = Math.floor(now / 1000);
  if (!isNum(claims.exp)) throw new JwtError('JWT_EXP_MISSING', 'exp is required');
  if (nowSec > claims.exp + clockSkewSec) throw new JwtError('JWT_EXPIRED', 'token expired');
  if (claims.nbf !== undefined && (!isNum(claims.nbf) || nowSec + clockSkewSec < claims.nbf)) throw new JwtError('JWT_NOT_YET_VALID', 'token not yet valid');
  if (claims.iat !== undefined) {
    if (!isNum(claims.iat) || claims.iat > nowSec + clockSkewSec) throw new JwtError('JWT_IAT_IN_FUTURE', 'issued in the future');
    if (claims.exp - claims.iat > maxLifetimeSec) throw new JwtError('JWT_LIFETIME_TOO_LONG', 'token lifetime exceeds the allowed maximum');
  } else if (claims.exp - nowSec > maxLifetimeSec + clockSkewSec) throw new JwtError('JWT_LIFETIME_TOO_LONG', 'token lifetime exceeds the allowed maximum');
  if (typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255) throw new JwtError('JWT_SUBJECT_MISSING', 'sub is required');
  return { header, claims };
}

module.exports = { verify, peek, looksLikeJwt, JwtError, DEFAULT_ALGS, ALG_INFO, MAX_TOKEN_BYTES };
