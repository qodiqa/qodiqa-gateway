'use strict';

/**
 * OIDC bearer-token authentication for the API: the core side of enterprise/identity.
 *
 * Configuration: QODIQA_OIDC_CONFIG_PATH names a JSON file `{ "providers": [ { id, issuer, audience: [..], jwksUri | discovery: true, algorithms?, clockSkewSec?, maxLifetimeSec? } ] }`
 * (validated by enterprise/identity/oidc.js). Unset = federation off (API keys only). QODIQA_OIDC_ALLOW_INSECURE=true permits a plain-http / loopback IdP for local development and
 * is ignored when NODE_ENV=production.
 *
 * How a token becomes an identity: the JWT is verified (signature against the provider's JWKS, issuer, audience, expiry, allowed algorithm), then the verified (issuer, subject) is
 * looked up in the signing-identity store (credentialType "oidc", externalIdentity {issuer, subject}). A valid token whose subject is not linked to an identity is REFUSED - being known to
 * the IdP grants nothing here. The linked identity then goes through exactly the checks an API-key identity does (enabled, not revoked, SIGN_ARTIFACT, tenant, provider scope).
 *
 *   federation = oidcService.federation(store)    -> { accepts(token), resolve(token) } for signAuth, or null when federation is off
 */

const fs = require('fs');
const ext = require('./extensionPoint');
const { fetchJson } = require('./safeFetch');
const { emit } = require('../../../services/logger');

let _state = null;       // { auth, allowInsecure } | { off: true }

const allowInsecure = (env = process.env) => env.QODIQA_OIDC_ALLOW_INSECURE === 'true' && env.NODE_ENV !== 'production';

function load(env = process.env) {
  const path = env.QODIQA_OIDC_CONFIG_PATH;
  if (!path) return { off: true };
  const mod = ext.get();
  if (!mod) throw new Error('QODIQA_OIDC_CONFIG_PATH is set but enterprise/identity is not installed');
  let cfg;
  try { cfg = JSON.parse(fs.readFileSync(path, 'utf8')); } catch (e) { throw new Error(`QODIQA_OIDC_CONFIG_PATH cannot be read as JSON: ${e.message}`); }
  if (!cfg || typeof cfg !== 'object' || !Array.isArray(cfg.providers)) throw new Error('the OIDC configuration is { "providers": [...] }');
  const insecure = allowInsecure(env);
  const auth = mod.oidc.createOidcAuthenticator({ providers: cfg.providers, allowInsecure: insecure, fetchJson: (url) => fetchJson(url, { allowInsecure: insecure }) });
  emit('INFO', 'OIDC_CONFIGURED', { providers: auth.providers.map((p) => p.id), allowInsecure: insecure });
  return { auth, allowInsecure: insecure };
}

function state() { if (_state === null) _state = load(); return _state; }
const isEnabled = () => !state().off;

/** Boot-time check (server startup): throws if the configuration is unusable, so a bad federation setup is a failed start, not a silent API-key-only gateway. */
function assertConfigured() { _state = null; return state(); }

function _make(lookup, key) {
  const st = state();
  if (st.off) return null;
  const jwt = ext.get().jwt;
  return {
    accepts: (token) => jwt.looksLikeJwt(token),
    async resolve(token) {
      let r;
      try { r = await st.auth.authenticate(token); } catch (e) { emit('ERROR', 'OIDC_AUTHENTICATE_ERROR', { error: e.message }); return { ok: false, reason: 'OIDC_ERROR' }; }
      if (!r.ok) {
        const unavailable = r.reason === 'PROVIDER_UNAVAILABLE';
        emit(unavailable ? 'ERROR' : 'WARN', 'OIDC_TOKEN_REFUSED', { reason: r.reason });
        return { ok: false, reason: r.reason, unavailable };
      }
      let identity;
      try { identity = lookup(r.issuer, r.subject); } catch (e) { return { ok: false, reason: 'IDENTITY_STORE_ERROR', unavailable: e && e.name === 'ControlPlaneError', error: e }; }
      if (!identity) { emit('WARN', 'OIDC_SUBJECT_NOT_LINKED', { providerId: r.providerId }); return { ok: false, reason: 'NOT_LINKED' }; }
      return { ok: true, [key]: identity, via: 'oidc', providerId: r.providerId, issuer: r.issuer, subject: r.subject, claims: r.claims, expiresAt: r.expiresAt, assured: r.assured === true };
    },
  };
}

/** Signing identities (API, /sign): resolve() -> { ok, identity, ... }. */
function federation(store) { return _make((i, s) => store.resolveByExternalIdentity(i, s), 'identity'); }
/** Operators (admin API): resolve() -> { ok, operator, assured, ... } where operator is the RBAC user linked to the verified (issuer, subject). */
function operatorFederation(rbacStore) { return rbacStore && typeof rbacStore.resolveByExternalIdentity === 'function' ? _make((i, s) => rbacStore.resolveByExternalIdentity(i, s), 'operator') : null; }

function _reset() { _state = null; }
module.exports = { federation, operatorFederation, isEnabled, assertConfigured, load, allowInsecure, _reset };
