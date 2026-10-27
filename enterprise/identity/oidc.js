'use strict';

/**
 * OpenID Connect bearer-token authenticator: turns `Authorization: Bearer <JWT>` into a verified (issuer, subject) pair - nothing more. WHAT that subject may do is decided by
 * the core, which links it to a QODIQA identity (src/core/identity); this module never grants anything.
 *
 *   const oidc = createOidcAuthenticator({ providers, fetchJson, now })
 *   await oidc.authenticate(token) -> { ok: true, providerId, issuer, subject, claims, expiresAt } | { ok: false, reason }
 *
 * providers: [{ id, issuer, audience: [..], jwksUri?, discovery?: true, algorithms?, clockSkewSec?, maxLifetimeSec? }]
 *   - `issuer` is compared EXACTLY with the token's `iss` (no normalisation, no prefix match). Two providers cannot share an issuer.
 *   - The keys come from `jwksUri`, or, with `discovery: true`, from `{issuer}/.well-known/openid-configuration` - whose `issuer` member must equal the configured issuer and whose
 *     `jwks_uri` must be https. A token header's jku / x5u / jwk members are ignored.
 *   - `algorithms` narrows the default allowlist (jwt.js DEFAULT_ALGS); it can never widen it to none / HS*.
 *
 * `reason` values: NOT_A_JWT, UNKNOWN_ISSUER, PROVIDER_UNAVAILABLE (keys could not be obtained: fail closed), or the JwtError code of jwt.js. The reason is for logs and metrics; callers
 * answer 401 with a generic body whatever it is.
 *
 * The claims returned are a minimal, bounded projection (sub, iss, exp, iat, email, name, preferred_username, groups, roles, acr, amr, azp, tid, oid) - strings capped at 256
 * characters, arrays at 100 elements - so a hostile IdP-issued token cannot smuggle a megabyte into the audit trail.
 */

const jwt = require('./jwt');
const { createJwksCache } = require('./jwks');

const COPY = ['sub', 'iss', 'exp', 'iat', 'auth_time', 'email', 'name', 'preferred_username', 'acr', 'azp', 'tid', 'oid'];
const LISTS = ['groups', 'roles', 'amr'];

function project(claims) {
  const out = {};
  for (const k of COPY) if (claims[k] !== undefined && (typeof claims[k] === 'number' || (typeof claims[k] === 'string' && claims[k].length <= 256))) out[k] = claims[k];
  for (const k of LISTS) if (Array.isArray(claims[k])) out[k] = claims[k].filter((x) => typeof x === 'string' && x.length <= 256).slice(0, 100);
  return out;
}

/** Is this (verified) claim set a second-factor authentication that is recent enough, under the provider's declared assurance? Pure. */
function isAssured(claims, assurance, nowMs = Date.now()) {
  if (!assurance || typeof assurance !== 'object') return false;
  const amr = Array.isArray(claims.amr) ? claims.amr : [];
  const okFactor = (Array.isArray(assurance.amr) && assurance.amr.some((a) => amr.includes(a))) || (Array.isArray(assurance.acr) && typeof claims.acr === 'string' && assurance.acr.includes(claims.acr));
  if (!okFactor) return false;
  const max = Number.isInteger(assurance.maxAuthAgeSec) ? assurance.maxAuthAgeSec : 900;
  return typeof claims.auth_time === 'number' && Number.isFinite(claims.auth_time) && claims.auth_time <= nowMs / 1000 + 5 && nowMs / 1000 - claims.auth_time <= max;
}

function validateProviders(providers, { allowInsecure = false } = {}) {
  const scheme = allowInsecure ? /^https?:\/\//i : /^https:\/\//i;      // plain http only for a development IdP, and only when the core says so
  if (!Array.isArray(providers) || providers.length === 0 || providers.length > 32) throw new Error('oidc: providers is a list of 1..32');
  const ids = new Set(); const issuers = new Set();
  for (const p of providers) {
    if (!p || typeof p !== 'object') throw new Error('oidc: a provider is an object');
    if (typeof p.id !== 'string' || !/^[a-z][a-z0-9-]{0,30}$/.test(p.id) || ids.has(p.id)) throw new Error(`oidc: invalid or duplicate provider id: ${String(p.id).slice(0, 40)}`);
    ids.add(p.id);
    if (typeof p.issuer !== 'string' || !scheme.test(p.issuer) || /[\s?#]/.test(p.issuer) || issuers.has(p.issuer)) throw new Error(`oidc ${p.id}: issuer must be an https URL and unique`);
    issuers.add(p.issuer);
    if (!Array.isArray(p.audience) || p.audience.length === 0 || p.audience.length > 16 || p.audience.some((a) => typeof a !== 'string' || !a || a.length > 256)) throw new Error(`oidc ${p.id}: audience is a non-empty list of strings`);
    if (!p.jwksUri && p.discovery !== true) throw new Error(`oidc ${p.id}: set jwksUri or discovery: true`);
    if (p.jwksUri !== undefined && (!scheme.test(String(p.jwksUri)) || /\s/.test(String(p.jwksUri)))) throw new Error(`oidc ${p.id}: jwksUri must be an https URL`);
    if (p.algorithms !== undefined && !(Array.isArray(p.algorithms) && p.algorithms.length > 0 && p.algorithms.every((a) => jwt.DEFAULT_ALGS.includes(a)))) throw new Error(`oidc ${p.id}: algorithms must be a subset of ${jwt.DEFAULT_ALGS.join(', ')}`);
    if (p.assurance !== undefined) {
      const a = p.assurance;
      const strs = (v) => Array.isArray(v) && v.length > 0 && v.length <= 32 && v.every((x) => typeof x === 'string' && x.length > 0 && x.length <= 256);
      if (!a || typeof a !== 'object' || Array.isArray(a) || Object.keys(a).some((k) => !['amr', 'acr', 'maxAuthAgeSec'].includes(k))) throw new Error(`oidc ${p.id}: assurance is { amr?, acr?, maxAuthAgeSec? }`);
      if (a.amr === undefined && a.acr === undefined) throw new Error(`oidc ${p.id}: assurance names amr and/or acr values`);
      if ((a.amr !== undefined && !strs(a.amr)) || (a.acr !== undefined && !strs(a.acr))) throw new Error(`oidc ${p.id}: assurance amr / acr are lists of strings`);
      if (a.maxAuthAgeSec !== undefined && !(Number.isInteger(a.maxAuthAgeSec) && a.maxAuthAgeSec >= 60 && a.maxAuthAgeSec <= 86400)) throw new Error(`oidc ${p.id}: assurance.maxAuthAgeSec is an integer between 60 and 86400`);
    }
    for (const [k, lo, hi] of [['clockSkewSec', 0, 300], ['maxLifetimeSec', 60, 7 * 24 * 3600]]) if (p[k] !== undefined && !(Number.isInteger(p[k]) && p[k] >= lo && p[k] <= hi)) throw new Error(`oidc ${p.id}: ${k} is an integer between ${lo} and ${hi}`);
  }
}

function createOidcAuthenticator({ providers, fetchJson, now = () => Date.now(), allowInsecure = false }) {
  validateProviders(providers, { allowInsecure });
  if (typeof fetchJson !== 'function') throw new TypeError('createOidcAuthenticator: fetchJson is required');
  const byIssuer = new Map(providers.map((p) => [p.issuer, p]));
  const caches = new Map();           // provider id -> { jwks, uriPromise }

  function stateFor(p) {
    if (!caches.has(p.id)) {
      let uri = p.jwksUri || null;
      const jwksFetch = async () => {
        if (!uri) {
          const doc = await fetchJson(`${p.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`);
          if (!doc || doc.issuer !== p.issuer || typeof doc.jwks_uri !== 'string' || !(allowInsecure ? /^https?:\/\//i : /^https:\/\//i).test(doc.jwks_uri)) throw new Error('discovery document invalid');
          uri = doc.jwks_uri;
        }
        return fetchJson(uri);
      };
      caches.set(p.id, { jwks: createJwksCache({ uri: p.jwksUri || `discovery:${p.issuer}`, fetchJson: jwksFetch, now }) });
    }
    return caches.get(p.id);
  }

  async function authenticate(token) {
    if (!jwt.looksLikeJwt(token)) return { ok: false, reason: 'NOT_A_JWT' };
    let peeked;
    try { peeked = jwt.peek(token); } catch (e) { return { ok: false, reason: e.code || 'JWT_MALFORMED' }; }
    const provider = typeof peeked.claims.iss === 'string' ? byIssuer.get(peeked.claims.iss) : undefined;
    if (!provider) return { ok: false, reason: 'UNKNOWN_ISSUER' };
    const { jwks } = stateFor(provider);
    try { await jwks.refreshIfNeeded(typeof peeked.header.kid === 'string' ? peeked.header.kid : null); } catch { /* the cache reports unavailability through keyFor */ }
    try {
      const { claims } = jwt.verify(token, { keyFor: (h) => jwks.keyFor(h), issuer: provider.issuer, audience: provider.audience, algorithms: provider.algorithms, clockSkewSec: provider.clockSkewSec, maxLifetimeSec: provider.maxLifetimeSec, now: now() });
      return { ok: true, providerId: provider.id, issuer: provider.issuer, subject: claims.sub, claims: project(claims), expiresAt: claims.exp, assured: isAssured(claims, provider.assurance, now()) };
    } catch (e) {
      if (e && e.code === 'JWT_KEY_UNKNOWN') return { ok: false, reason: jwks._state().keys === 0 ? 'PROVIDER_UNAVAILABLE' : 'JWT_KEY_UNKNOWN' };
      return { ok: false, reason: (e && e.code) || 'JWT_INVALID' };
    }
  }

  return { authenticate, providers: providers.map((p) => ({ id: p.id, issuer: p.issuer })) };
}

module.exports = { createOidcAuthenticator, validateProviders, project, isAssured };
