'use strict';

/**
 * LDAP / Active Directory sign-in for operators: the core side of enterprise/identity/ldap.js.
 *
 * Configuration: QODIQA_LDAP_CONFIG_PATH names a JSON file `{ "providers": [ { id, url, baseDn, bindDn, bindPasswordEnv, ... } ] }` (see enterprise/identity/ldap.js for every member).
 * Unset = LDAP off. A bad file fails the start of the gateway. The service-account password is never in the file: bindPasswordEnv names the environment variable that holds it.
 *
 * Flow: POST /auth/ldap/login { provider, username, password } -> the directory proves the password (bind as the user's own DN) -> the verified (issuer `ldap:<id>`, subject = the directory's
 * stable id) is mapped to the RBAC user linked to it (`externalIdentity`) -> an operator session token (src/core/identity/operatorSession.js). An unlinked or disabled user gets nothing;
 * there is no just-in-time account creation. Directory groups only ADMIT (a provider's `requiredGroups`); the user's role is the RBAC user's, never read from the directory.
 *
 * Guessing: after MAX_FAILURES failed attempts for one (provider, username) within LOCK_WINDOW_MS the pair is locked for the rest of the window (answered like any other refusal, the directory
 * is not asked). The counter is per process (a replica set multiplies the allowance; the per-client-address limiter of the route and the directory's own lockout policy are the other bounds).
 */

const fs = require('fs');
const ext = require('./extensionPoint');
const operatorSession = require('./operatorSession');
const { emit } = require('../../../services/logger');

const MAX_FAILURES = 5;
const LOCK_WINDOW_MS = 15 * 60 * 1000;
const MAX_TRACKED = 10_000;
let _state = null;                    // { providers: Map<id, { cfg, ldap }> } | { off: true }
const _failures = new Map();          // `${provider}\n${username}` -> { n, first }

function load(env = process.env, clientFactory) {
  const path = env.QODIQA_LDAP_CONFIG_PATH;
  if (!path) return { off: true };
  const mod = ext.get();
  if (!mod) throw new Error('QODIQA_LDAP_CONFIG_PATH is set but enterprise/identity is not installed');
  let cfg;
  try { cfg = JSON.parse(fs.readFileSync(path, 'utf8')); } catch (e) { throw new Error(`QODIQA_LDAP_CONFIG_PATH cannot be read as JSON: ${e.message}`); }
  if (!cfg || typeof cfg !== 'object' || !Array.isArray(cfg.providers) || cfg.providers.length === 0 || cfg.providers.length > 16) throw new Error('the LDAP configuration is { "providers": [1..16 providers] }');
  const providers = new Map();
  for (const p of cfg.providers) {
    if (providers.has(p.id)) throw new Error(`ldap: duplicate provider id ${p.id}`);
    if (p.sessionTtlSec !== undefined && !(Number.isInteger(p.sessionTtlSec) && p.sessionTtlSec >= 60 && p.sessionTtlSec <= operatorSession.MAX_TTL_SEC)) throw new Error(`ldap ${p.id}: sessionTtlSec is an integer between 60 and ${operatorSession.MAX_TTL_SEC}`);
    const { sessionTtlSec, ...providerCfg } = p;
    providers.set(p.id, { cfg: p, ldap: mod.ldap.createLdapProvider(providerCfg, { env, ...(clientFactory ? { clientFactory } : {}) }) });
    if (!env[p.bindPasswordEnv]) emit('WARN', 'LDAP_SERVICE_ACCOUNT_UNSET', { providerId: p.id, variable: p.bindPasswordEnv });
  }
  emit('INFO', 'LDAP_CONFIGURED', { providers: [...providers.keys()] });
  return { providers };
}

function state() { if (_state === null) _state = load(); return _state; }
const isEnabled = () => !state().off;
function assertConfigured() { _state = null; return state(); }
function providerIds() { const s = state(); return s.off ? [] : [...s.providers.keys()]; }

// one account, one counter: directories fold case, insignificant spaces and compatibility forms when they match a name, so the key does too (F10V-01)
const keyOf = (providerId, username) => `${providerId}\n${String(username).normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase()}`;
function isLocked(key, now) { const e = _failures.get(key); if (!e) return false; if (now - e.first > LOCK_WINDOW_MS) { _failures.delete(key); return false; } return e.n >= MAX_FAILURES; }
function noteFailure(key, now) {
  const e = _failures.get(key);
  if (!e || now - e.first > LOCK_WINDOW_MS) {
    if (_failures.size >= MAX_TRACKED) for (const [k, v] of _failures) if (now - v.first > LOCK_WINDOW_MS) _failures.delete(k);
    if (_failures.size >= MAX_TRACKED) _failures.delete(_failures.keys().next().value);
    _failures.set(key, { n: 1, first: now });
  } else e.n += 1;
}

/** Password login. Every refusal is { ok: false, reason } (the route answers all of them alike); a directory/store outage is { unavailable: true }. */
async function login(providerId, username, password, { rbacStore, now = Date.now() } = {}) {
  const s = state();
  const entry = s.off || typeof providerId !== 'string' ? null : s.providers.get(providerId);
  if (!entry) return { ok: false, reason: 'UNKNOWN_PROVIDER' };
  const key = keyOf(providerId, typeof username === 'string' ? username : '');
  if (typeof username === 'string' && isLocked(key, now)) { emit('WARN', 'LDAP_LOGIN_LOCKED', { providerId }); return { ok: false, reason: 'LDAP_LOCKED' }; }
  const r = await entry.ldap.authenticate(username, password);
  if (!r.ok) {
    if (!r.unavailable && typeof username === 'string') noteFailure(key, now);
    emit('WARN', 'LDAP_LOGIN_REFUSED', { providerId, reason: r.reason });
    return { ok: false, reason: r.reason, unavailable: r.unavailable === true };
  }
  let user;
  try { user = rbacStore.resolveByExternalIdentity(r.issuer, r.subject); } catch { return { ok: false, reason: 'IDENTITY_STORE_ERROR', unavailable: true }; }
  if (!user) { noteFailure(key, now); emit('WARN', 'LDAP_SUBJECT_NOT_LINKED', { providerId }); return { ok: false, reason: 'NOT_LINKED' }; }
  if (!user.enabled) { noteFailure(key, now); emit('WARN', 'LDAP_USER_DISABLED', { providerId, userId: user.id }); return { ok: false, reason: 'USER_DISABLED' }; }
  _failures.delete(key);
  const sess = operatorSession.mint({ userId: user.id, issuer: r.issuer, subject: r.subject, providerId: `ldap:${providerId}`, assured: false, ttlSec: entry.cfg.sessionTtlSec, now });
  emit('INFO', 'LDAP_LOGIN_OK', { providerId, userId: user.id, username: user.username, role: user.role });
  return { ok: true, token: sess.token, expiresAt: sess.expiresAt, assured: false, user: { id: user.id, username: user.username, role: user.role } };
}

function _reset() { _state = null; _failures.clear(); }
function _loadWith(env, clientFactory) { _state = load(env, clientFactory); return _state; }
module.exports = { login, isEnabled, assertConfigured, providerIds, load, _reset, _loadWith, MAX_FAILURES, LOCK_WINDOW_MS };
