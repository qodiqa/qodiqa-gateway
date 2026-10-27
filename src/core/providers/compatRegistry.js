'use strict';

/**
 * Registry of OpenAI-compatible providers - endpoints an operator adds at runtime (a vendor's hosted API, a gateway, a self-hosted vLLM/TGI/LiteLLM server)
 * without a deploy. Each becomes a provider named `compat-<id>` that /sign, /ai/chat, the router, failover, budgets and routing treat like any built-in provider.
 *
 * State. Control-plane store `provider_registry` (migration 107): in PostgreSQL mode every replica sees a change within the control plane's 5 s bound or refuses; in
 * development/test memory mode the records live in the process. A record is never deleted - it is DISABLED (so the audit trail and the name stay reserved).
 *
 * What an entry holds (all validated; unknown members refused):
 *   { id, displayName?, baseUrl, apiKeyEnv?, models: [..] (allowlist; empty = any model), defaultModel?, timeoutMs, maxTokens?, failoverProvider?, enabled }
 *
 * Safety properties:
 *   - The API key is NEVER stored. `apiKeyEnv` names an environment variable that must start with COMPAT_KEY_ (so an administrator can only point a provider at a variable that
 *     was provisioned for this purpose, never at DATABASE_PASSWORD or another secret); the value is read at call time. A configured entry whose variable is unset is disabled.
 *   - `baseUrl` must be https to a public DNS name (shared SSRF policy: no IP literal, no private/loopback name); the connection goes through the guarded agent, which re-checks
 *     every resolved address and every redirect hop. Plain http / private destinations only where QODIQA_COMPAT_ALLOW_LOCAL=true (never in production).
 *   - The record carries a MAC (macKeyring purpose PROVIDER_REGISTRY) over its content: a row changed in the database without the key is NOT callable (the provider reads as
 *     unavailable and the event is escalated), exactly like the kill switch's tamper rule - but fail-closed here means "do not call", not "block everything".
 *   - A key is bound to its HOSTS: COMPAT_KEY_X is sent only to hosts listed in COMPAT_KEY_X_HOSTS (comma list, exact names or `*.example.com`); unset = the key is not usable. So an operator who
 *     may register providers cannot aim a provisioned key at a host of their choosing.
 *   - The destination is judged again on EVERY use, under the policy in force then (a stored plain-http / loopback entry stops working the moment it is no longer permitted).
 *   - Names `compat-*` cannot collide with the built-in providers; ids are [a-z][a-z0-9-]{1,30}.
 */

const crypto = require('crypto');
const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const macKeyring = require('../security/macKeyring');
const { emit } = require('../../../services/logger');
const { validateProviderUrl, validateLocalProviderUrl } = require('../../../services/providers/ssrf');

const PREFIX = 'compat-';
const ID_RE = /^[a-z][a-z0-9-]{1,30}$/;
const KEY_ENV_RE = /^COMPAT_KEY_[A-Z0-9_]{1,48}$/;
const MODEL_MAX = 128;
const MAC_DOMAIN = 'qodiqa-provider-registry-v1';
const ALLOWED = new Set(['id', 'displayName', 'baseUrl', 'apiKeyEnv', 'models', 'defaultModel', 'timeoutMs', 'maxTokens', 'failoverProvider', 'enabled']);

class CompatRegistryError extends Error {
  constructor(code, message, status = 400) { super(message); this.name = 'CompatRegistryError'; this.code = code; this.status = status; }
}

const allowLocal = (env = process.env) => env.QODIQA_COMPAT_ALLOW_LOCAL === 'true' && env.NODE_ENV !== 'production';
const INVISIBLE = /[\p{Cf}\u2028\u2029]/u;
// names that are not public DNS names however they resolve (internal suffixes, wildcard-DNS services that map names to IPs)
const NOT_PUBLIC = /(^|\.)(local|localhost|localdomain|internal|intranet|private|lan|home|corp|svc|cluster|test|invalid|example)$|(^|\.)(localtest\.me|lvh\.me|nip\.io|sslip\.io|xip\.io|traefik\.me)$/i;

/** Is `host` allowed for the key variable `envName`? (COMPAT_KEY_X_HOSTS: exact names or `*.suffix`.) */
function keyAllowedFor(envName, host, env = process.env) {
  const list = String(env[`${envName}_HOSTS`] || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
  const h = String(host).toLowerCase();
  return list.some((p) => (p.startsWith('*.') ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : p === h));
}
const _col = new Collection('provider_registry');
const nameOf = (id) => `${PREFIX}${id}`;
const isCompatName = (name) => typeof name === 'string' && name.startsWith(PREFIX) && ID_RE.test(name.slice(PREFIX.length));

// ── integrity ───────────────────────────────────────────────────�
function _content(r) {
  return [MAC_DOMAIN, r.id, r.displayName || null, r.baseUrl, r.apiKeyEnv || null, [...(r.models || [])], r.defaultModel || null, r.timeoutMs, r.maxTokens ?? null, r.failoverProvider || null,
    r.enabled === true, r.createdAt, r.updatedAt, r.createdBy, r.updatedBy, r.revision];
}
const _canonical = (r) => JSON.stringify(_content(r));
const _hash = (r) => crypto.createHash('sha256').update(_canonical(r), 'utf8').digest('hex');
function _sign(r) { return macKeyring.sign(macKeyring.PURPOSES.PROVIDER_REGISTRY, _canonical(r)); }
const _announced = new Set();
function _intact(r) {
  let ok = false; let reason = 'NO_MAC';
  try {
    if (typeof r.mac === 'string' && r.mac) { const v = macKeyring.verify(macKeyring.PURPOSES.PROVIDER_REGISTRY, _canonical(r), r.mac); ok = v.ok === true; reason = ok ? null : (/** @type {any} */ (v).reason || 'BAD_MAC'); }
  } catch (e) { reason = `KEYRING_${e.code || 'ERROR'}`; }
  if (!ok && !_announced.has(`${r.id}:${r.mac}`)) {
    _announced.add(`${r.id}:${r.mac}`);
    emit('CRITICAL', 'PROVIDER_REGISTRY_RECORD_TAMPERED', { providerId: r.id, reason, message: 'A provider-registry record does not carry a valid MAC: the provider is not callable until an operator re-saves it.' });
  }
  return ok;
}

// ── validation ──────────────────────────────────────────────────�
function _bad(code, message) { return new CompatRegistryError(code, message); }

/** The base URL part of validateSpec, reusable at call time. Returns the normalised URL or throws a CompatRegistryError. */
function checkBaseUrl(raw) {
  if (typeof raw !== 'string') throw _bad('INVALID_BASE_URL', 'baseUrl is required');
  let u; try { u = new URL(raw); } catch { throw _bad('INVALID_BASE_URL', 'baseUrl is not a URL'); }
  if (u.username || u.password || u.search || u.hash) throw _bad('INVALID_BASE_URL', 'baseUrl carries no credentials, query or fragment');
  const base = u.origin + u.pathname.replace(/\/+$/, '');
  let check = u.protocol === 'https:' ? _publicHttps(u) : { valid: false, reason: 'NON_HTTPS_PROTOCOL' };
  if (check.valid && u.port && u.port !== '443') check = { valid: false, reason: 'PORT_NOT_ALLOWED' };
  if (!check.valid && allowLocal()) check = validateLocalProviderUrl(base);
  if (!check.valid) throw _bad('BASE_URL_REFUSED', `baseUrl failed the outbound policy (${check.reason})`);
  return base;
}

function validateSpec(spec, { partial = false } = {}) {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw _bad('INVALID_PROVIDER', 'the body must be an object');
  for (const k of Object.keys(spec)) if (!ALLOWED.has(k)) throw _bad('UNKNOWN_FIELD', `unknown field: ${k}`);
  const out = {};
  if (!partial || spec.id !== undefined) {
    if (typeof spec.id !== 'string' || !ID_RE.test(spec.id)) throw _bad('INVALID_ID', 'id must match [a-z][a-z0-9-]{1,30} (the provider is then named compat-<id>)');
    out.id = spec.id;
  }
  if (spec.displayName !== undefined) {
    if (typeof spec.displayName !== 'string' || spec.displayName.length > 80 || /[\u0000-\u001f\u007f]/.test(spec.displayName) || INVISIBLE.test(spec.displayName)) throw _bad('INVALID_DISPLAY_NAME', 'displayName is at most 80 characters without control characters');
    out.displayName = spec.displayName;
  }
  if (!partial || spec.baseUrl !== undefined) {
    out.baseUrl = checkBaseUrl(spec.baseUrl);
  }
  if (spec.apiKeyEnv !== undefined && spec.apiKeyEnv !== null) {
    if (typeof spec.apiKeyEnv !== 'string' || !KEY_ENV_RE.test(spec.apiKeyEnv)) throw _bad('INVALID_API_KEY_ENV', 'apiKeyEnv names an environment variable starting with COMPAT_KEY_ (the key itself is never stored)');
    out.apiKeyEnv = spec.apiKeyEnv;
  }
  if (spec.models !== undefined) {
    if (!Array.isArray(spec.models) || spec.models.length > 200 || spec.models.some((m) => typeof m !== 'string' || !m || m.length > MODEL_MAX || m.trim() !== m || /[\u0000-\u001f\u007f]/.test(m) || INVISIBLE.test(m))) throw _bad('INVALID_MODELS', 'models is a list of at most 200 model ids');
    out.models = [...new Set(spec.models)];
  }
  if (spec.defaultModel !== undefined && spec.defaultModel !== null) {
    if (typeof spec.defaultModel !== 'string' || !spec.defaultModel || spec.defaultModel.length > MODEL_MAX || spec.defaultModel.trim() !== spec.defaultModel || /[\u0000-\u001f\u007f]/.test(spec.defaultModel) || INVISIBLE.test(spec.defaultModel)) throw _bad('INVALID_DEFAULT_MODEL', 'defaultModel is a model id');
    out.defaultModel = spec.defaultModel;
  }
  if (spec.timeoutMs !== undefined) {
    if (!Number.isInteger(spec.timeoutMs) || spec.timeoutMs < 1000 || spec.timeoutMs > 300_000) throw _bad('INVALID_TIMEOUT', 'timeoutMs is an integer between 1000 and 300000');
    out.timeoutMs = spec.timeoutMs;
  }
  if (spec.maxTokens !== undefined && spec.maxTokens !== null) {
    if (!Number.isInteger(spec.maxTokens) || spec.maxTokens < 1 || spec.maxTokens > 8192) throw _bad('INVALID_MAX_TOKENS', 'maxTokens is an integer between 1 and 8192');
    out.maxTokens = spec.maxTokens;
  }
  if (spec.failoverProvider !== undefined && spec.failoverProvider !== null) {
    if (typeof spec.failoverProvider !== 'string' || !/^[a-z][a-z0-9-]{1,40}$/.test(spec.failoverProvider)) throw _bad('INVALID_FAILOVER', 'failoverProvider is a provider name');
    out.failoverProvider = spec.failoverProvider;
  }
  if (spec.enabled !== undefined) {
    if (typeof spec.enabled !== 'boolean') throw _bad('INVALID_ENABLED', 'enabled is a boolean');
    out.enabled = spec.enabled;
  }
  if (out.defaultModel && out.models && out.models.length > 0 && !out.models.includes(out.defaultModel)) throw _bad('DEFAULT_MODEL_NOT_ALLOWED', 'defaultModel must be one of models');
  return out;
}

/** https to a public DNS name: the shared strict rules minus the fixed vendor allowlist (the guarded agent re-checks every resolved address and redirect hop). */
function _publicHttps(u) {
  const probe = validateProviderUrl(`${u.origin}/`);
  if (probe.valid) return probe;
  if (probe.reason !== 'HOSTNAME_NOT_ALLOWED') return probe;                     // IP literal, private name, non-https: refused for good
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,63}$/.test(u.hostname.toLowerCase())) return { valid: false, reason: 'INVALID_HOSTNAME' };
  if (NOT_PUBLIC.test(u.hostname.toLowerCase())) return { valid: false, reason: 'NOT_A_PUBLIC_NAME' };
  return { valid: true, reason: null };
}

// ── public shape and runtime view ───────────────────────────────────────────�
function view(r) {
  if (!r) return null;
  return { id: r.id, name: nameOf(r.id), displayName: r.displayName || null, baseUrl: r.baseUrl, apiKeyEnv: r.apiKeyEnv || null, keyConfigured: r.apiKeyEnv ? !!process.env[r.apiKeyEnv] : null,
    models: [...(r.models || [])], defaultModel: r.defaultModel || null, timeoutMs: r.timeoutMs, maxTokens: r.maxTokens ?? null, failoverProvider: r.failoverProvider || null, enabled: r.enabled === true,
    revision: r.revision, createdAt: r.createdAt, createdBy: r.createdBy, updatedAt: r.updatedAt, updatedBy: r.updatedBy, configHash: _hash(r) };
}

function list() { return _col.values().map(view).sort((a, b) => a.id.localeCompare(b.id)); }
function get(id) { return view(_col.get(id)); }

/** Runtime resolution for the router: the callable record for a provider NAME, or null (unknown, disabled, key missing, tampered). Throws only the control plane's stale-snapshot error. */
function _usable(r) {
  if (!r || r.enabled !== true || !_intact(r)) return false;
  if (r.apiKeyEnv && !process.env[r.apiKeyEnv]) return false;
  try { checkBaseUrl(r.baseUrl); } catch { return false; }                                   // judged again under the policy in force NOW
  if (r.apiKeyEnv && !keyAllowedFor(r.apiKeyEnv, new URL(r.baseUrl).hostname)) return false;   // the key goes only to the hosts it is bound to
  return true;
}

function resolve(name) {
  if (!isCompatName(name)) return null;
  const r = _col.get(name.slice(PREFIX.length));
  return _usable(r) ? r : null;
}

/** The CONFIGS-shaped object (services/providers/config.js) for a dynamic provider name, or null. */
function configFor(name) {
  let r;
  try { r = isCompatName(name) ? _col.get(name.slice(PREFIX.length)) : null; } catch { return null; }
  if (!r) return null;
  const callable = _usable(r);
  return Object.freeze({ enabled: callable, apiKey: null, baseUrl: r.baseUrl, timeoutMs: r.timeoutMs, maxTokens: r.maxTokens ?? null, allowedModels: new Set(r.models || []), defaultModel: r.defaultModel || null,
    failoverProvider: r.failoverProvider || null, local: false, dynamic: true, configHash: _hash(r) });
}

function enabledNames() {
  try { return _col.values().filter(_usable).map((r) => nameOf(r.id)).sort(); } catch { return []; }
}
function allNames() { try { return _col.values().map((r) => nameOf(r.id)).sort(); } catch { return []; } }

// ── writes ───────────────────────────────────────────────────────�
function _actor(a) { if (typeof a !== 'string' || !a) throw new CompatRegistryError('OPERATOR_REQUIRED', 'an authenticated operator is required', 401); return a.slice(0, 256); }

async function register(spec, actor) {
  const who = _actor(actor);
  const v = validateSpec(spec);
  if (!v.baseUrl) throw _bad('INVALID_BASE_URL', 'baseUrl is required');
  if (_col.has(v.id)) throw new CompatRegistryError('PROVIDER_EXISTS', 'a provider with this id is already registered', 409);
  if (v.apiKeyEnv && !keyAllowedFor(v.apiKeyEnv, new URL(v.baseUrl).hostname)) throw new CompatRegistryError('KEY_HOST_NOT_ALLOWED', `${v.apiKeyEnv} is not bound to that host (set ${v.apiKeyEnv}_HOSTS)`, 400);
  const now = new Date().toISOString();
  const rec = { id: v.id, displayName: v.displayName, baseUrl: v.baseUrl, apiKeyEnv: v.apiKeyEnv || null, models: v.models || [], defaultModel: v.defaultModel || null, timeoutMs: v.timeoutMs || 30_000,
    maxTokens: v.maxTokens ?? null, failoverProvider: v.failoverProvider || null, enabled: v.enabled !== false, createdAt: now, createdBy: who, updatedAt: now, updatedBy: who, revision: 1 };
  rec.mac = _sign(rec);
  await _col.put(rec.id, rec, { create: true, updatedBy: who });
  emit('WARN', 'PROVIDER_REGISTERED', { providerId: rec.id, baseUrlHost: new URL(rec.baseUrl).host, models: rec.models.length, operator: who });
  return view(rec);
}

async function update(id, patch, actor) {
  const who = _actor(actor);
  const cur = _col.get(id);
  if (!cur) throw new CompatRegistryError('PROVIDER_NOT_FOUND', 'no such provider', 404);
  const v = validateSpec({ ...patch }, { partial: true });
  if (v.id !== undefined && v.id !== id) throw _bad('ID_IMMUTABLE', 'the id of a provider cannot change');
  const next = { ...cur };
  for (const k of ['displayName', 'baseUrl', 'apiKeyEnv', 'models', 'defaultModel', 'timeoutMs', 'maxTokens', 'failoverProvider', 'enabled']) if (patch[k] !== undefined) next[k] = patch[k] === null ? null : v[k];
  if (next.defaultModel && next.models && next.models.length > 0 && !next.models.includes(next.defaultModel)) throw _bad('DEFAULT_MODEL_NOT_ALLOWED', 'defaultModel must be one of models');
  if (next.apiKeyEnv && !keyAllowedFor(next.apiKeyEnv, new URL(next.baseUrl).hostname)) throw new CompatRegistryError('KEY_HOST_NOT_ALLOWED', `${next.apiKeyEnv} is not bound to that host (set ${next.apiKeyEnv}_HOSTS)`, 400);
  next.updatedAt = new Date().toISOString(); next.updatedBy = who; next.revision = (cur.revision || 0) + 1;
  next.mac = _sign(next);
  await _col.put(id, next, { updatedBy: who });
  emit('WARN', 'PROVIDER_UPDATED', { providerId: id, revision: next.revision, enabled: next.enabled, operator: who });
  return view(next);
}

const setEnabled = (id, enabled, actor) => update(id, { enabled }, actor);

module.exports = { keyAllowedFor, checkBaseUrl, register, update, setEnabled, list, get, resolve, configFor, enabledNames, allNames, validateSpec, isCompatName, nameOf, view, PREFIX, CompatRegistryError, _col };
