'use strict';

/**
 * SAML 2.0 single sign-on for operators: the core side of enterprise/identity/saml.js.
 *
 * Configuration: QODIQA_SAML_CONFIG_PATH names a JSON file `{ "providers": [ { id, spEntityId, acsUrl, idpEntityId, ssoUrl, idpCerts: [PEM...], ... } ] }` (see
 * enterprise/identity/saml.js for every member). Unset = SAML off. A bad file fails the start of the gateway.
 *
 * Flow: GET /auth/saml/:id/login -> 302 to the IdP with a signed relay state {provider, AuthnRequest id, expiry}; POST /auth/saml/:id/acs receives the IdP's response, the relay state is
 * verified (so any replica can finish a login another one started), the response is validated and its assertion id consumed once, the verified (issuer, subject = NameID) is mapped to the
 * RBAC user linked to it (`externalIdentity`), and the user gets an operator session token (src/core/identity/operatorSession.js). An unlinked or disabled user gets nothing.
 */

const fs = require('fs');
const crypto = require('crypto');
const ext = require('./extensionPoint');
const macKeyring = require('../security/macKeyring');
const operatorSession = require('./operatorSession');
const replayStore = require('./replayStore');
const { emit } = require('../../../services/logger');

const STATE_TTL_MS = 10 * 60 * 1000;
let _state = null;          // { providers: Map<id, { sp, cfg }> } | { off: true }

function load(env = process.env) {
  const path = env.QODIQA_SAML_CONFIG_PATH;
  if (!path) return { off: true };
  const mod = ext.get();
  if (!mod) throw new Error('QODIQA_SAML_CONFIG_PATH is set but enterprise/identity is not installed');
  let cfg;
  try { cfg = JSON.parse(fs.readFileSync(path, 'utf8')); } catch (e) { throw new Error(`QODIQA_SAML_CONFIG_PATH cannot be read as JSON: ${e.message}`); }
  if (!cfg || typeof cfg !== 'object' || !Array.isArray(cfg.providers) || cfg.providers.length === 0 || cfg.providers.length > 16) throw new Error('the SAML configuration is { "providers": [1..16 providers] }');
  const providers = new Map();
  for (const p of cfg.providers) {
    mod.saml.validateConfig(p);
    if (providers.has(p.id)) throw new Error(`saml: duplicate provider id ${p.id}`);
    if ([...providers.values()].some((x) => x.cfg.idpEntityId === p.idpEntityId)) throw new Error(`saml: two providers share the IdP entity id ${p.idpEntityId}`);
    if (p.sessionTtlSec !== undefined && !(Number.isInteger(p.sessionTtlSec) && p.sessionTtlSec >= 60 && p.sessionTtlSec <= operatorSession.MAX_TTL_SEC)) throw new Error(`saml ${p.id}: sessionTtlSec is an integer between 60 and ${operatorSession.MAX_TTL_SEC}`);
    providers.set(p.id, { cfg: p, sp: mod.saml.createSamlProvider(p, { replayStore: replayStore.shared }) });
  }
  emit('INFO', 'SAML_CONFIGURED', { providers: [...providers.keys()] });
  return { providers };
}

function state() { if (_state === null) _state = load(); return _state; }
const isEnabled = () => !state().off;
function assertConfigured() { _state = null; return state(); }
function providerIds() { const s = state(); return s.off ? [] : [...s.providers.keys()]; }

// ── relay state ────────────────────────────────────────────────────
function mintState(providerId, requestId, now = Date.now()) {
  const payload = { p: providerId, r: requestId, e: now + STATE_TTL_MS, n: crypto.randomBytes(8).toString('hex') };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${macKeyring.sign(macKeyring.PURPOSES.SAML_STATE, body)}`;
}
function verifyState(raw, providerId, now = Date.now()) {
  if (typeof raw !== 'string' || raw.length > 1024) return null;
  const dot = raw.indexOf('.');
  if (dot <= 0) return null;
  const body = raw.slice(0, dot);
  let v; try { v = macKeyring.verify(macKeyring.PURPOSES.SAML_STATE, body, raw.slice(dot + 1)); } catch { return null; }
  if (!v.ok) return null;
  let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch { return null; }
  if (!p || p.p !== providerId || typeof p.r !== 'string' || typeof p.e !== 'number' || p.e < now) return null;
  return p;
}

/** Start a login: where to send the browser. */
async function login(providerId, now = Date.now()) {
  const s = state();
  const entry = s.off ? null : s.providers.get(providerId);
  if (!entry) return { ok: false, reason: 'UNKNOWN_PROVIDER' };
  // the relay state must carry the AuthnRequest id, which exists only once the request is built: the provider takes a function that is given the id
  const { url, requestId } = await entry.sp.loginUrl((id) => mintState(providerId, id, now));
  return { ok: true, url, requestId };
}

/** Finish a login: the IdP's response (POSTed by the browser) -> an operator session token. */
async function acs(providerId, { samlResponse, relayState }, { rbacStore, now = Date.now() } = {}) {
  const s = state();
  const entry = s.off ? null : s.providers.get(providerId);
  if (!entry) return { ok: false, reason: 'UNKNOWN_PROVIDER' };
  const st = verifyState(relayState, providerId, now);
  if (!st && entry.cfg.allowIdpInitiated !== true) { emit('WARN', 'SAML_ACS_REFUSED', { providerId, reason: 'RELAY_STATE_INVALID' }); return { ok: false, reason: 'SAML_RELAY_STATE' }; }
  const r = await entry.sp.consume({ samlResponse, expectedRequestId: st ? st.r : null });
  if (!r.ok) { emit('WARN', 'SAML_ACS_REFUSED', { providerId, reason: r.reason }); return { ok: false, reason: r.reason, unavailable: r.reason === 'SAML_REPLAY_STORE_UNAVAILABLE' }; }
  let user;
  try { user = rbacStore.resolveByExternalIdentity(r.issuer, r.subject); } catch { return { ok: false, reason: 'IDENTITY_STORE_ERROR', unavailable: true }; }
  if (!user) { emit('WARN', 'SAML_SUBJECT_NOT_LINKED', { providerId }); return { ok: false, reason: 'NOT_LINKED' }; }
  if (!user.enabled) { emit('WARN', 'SAML_USER_DISABLED', { providerId, userId: user.id }); return { ok: false, reason: 'USER_DISABLED' }; }
  const authnMs = r.authnInstant ? Date.parse(r.authnInstant) : NaN;
  const maxAge = ((entry.cfg.assurance && entry.cfg.assurance.maxAuthnAgeSec) || 900) * 1000;
  const sess = operatorSession.mint({ userId: user.id, issuer: r.issuer, subject: r.subject, providerId, assured: r.assured === true, assuredUntilSec: Number.isFinite(authnMs) ? (Math.min(authnMs, now) + maxAge) / 1000 : null, ttlSec: entry.cfg.sessionTtlSec, now });
  emit('INFO', 'SAML_LOGIN_OK', { providerId, userId: user.id, username: user.username, role: user.role, assured: r.assured === true });
  return { ok: true, token: sess.token, expiresAt: sess.expiresAt, assured: r.assured === true, user: { id: user.id, username: user.username, role: user.role } };
}

function metadata(providerId) { const s = state(); const e = s.off ? null : s.providers.get(providerId); return e ? e.sp.metadata() : null; }

function _reset() { _state = null; }
module.exports = { login, acs, metadata, isEnabled, assertConfigured, providerIds, mintState, verifyState, load, _reset };
