'use strict';

/**
 * Registry of MCP servers: the only destinations the tool gateway will call.
 *
 *   register(tenant, { serverId, url, identity?, description? }, actor)   validate the URL (SSRF policy), pin the identity, store with a config hash
 *   resolve(tenant, serverId)            the callable server for ONE call: registered, active, URL still acceptable, config hash intact - or the reason it is not
 *   disable / enable / rotateIdentity / recordRefresh / get / list
 *
 * Identity of a server (docs: API_REFERENCE `/v1/mcp/servers`):
 *   { kind: 'tls-spki-pin', sha256: <hex64>, trust?: 'ca-and-pin' (default) | 'pin-only' }   https; the connection is dropped unless the certificate's public key matches
 *   { kind: 'none' }                                                                          http / loopback / private - only where QODIQA_MCP_ALLOW_LOCAL=true (never in production)
 * `configHash` = SHA-256("QODIQA::MCP_SERVER_CONFIG::V1" || JCS-P1({ v, tenantId, serverId, url, transport, identity })) is recomputed and compared on every call: a
 * row whose URL or identity was changed outside the registry's own code is refused (MCP_SERVER_CONFIG_TAMPERED).
 * Disabling a server takes effect on the very next call on every replica (the registry is read at each call, no cache) and aborts what is running through it here.
 */

const crypto = require('crypto');
const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const { canonicalJcsP1 } = require('../../validation/jcsP1');
const killRegistry = require('../agents/killRegistry');
const { validateMcpServerUrl, allowLocalFromEnv, McpUrlError } = require('./serverUrl');

const CONFIG_DOMAIN = 'QODIQA::MCP_SERVER_CONFIG::V1';
const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SERVER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/;

class McpRegistryError extends Error { constructor(code, message, status = 400) { super(message || code); this.name = 'McpRegistryError'; this.code = code; this.status = status; } }

const usePg = () => pgPool.isEnabled();
const _mem = new Map();

const out = (r) => (r ? { tenantId: r.tenant_id, serverId: r.server_id, url: r.url, transport: r.transport, identity: r.identity, configHash: String(r.config_hash).trim(), status: r.status,
  localDestination: r.local_destination, description: r.description || null, createdBy: r.created_by, createdAt: new Date(r.created_at).toISOString(), updatedAt: new Date(r.updated_at).toISOString(),
  disabledAt: r.disabled_at ? new Date(r.disabled_at).toISOString() : null, disabledReason: r.disabled_reason || null, disabledBy: r.disabled_by || null,
  lastRefreshAt: r.last_refresh_at ? new Date(r.last_refresh_at).toISOString() : null, lastRefreshTools: r.last_refresh_tools ?? null, lastError: r.last_error || null } : null);

function configHash(c) {
  return crypto.createHash('sha256').update(CONFIG_DOMAIN, 'utf8').update(canonicalJcsP1({ v: 1, tenantId: c.tenantId, serverId: c.serverId, url: c.url, transport: 'streamable-http', identity: c.identity }), 'utf8').digest('hex');
}

function _ids(tenantId, serverId) {
  if (typeof tenantId !== 'string' || !TENANT_RE.test(tenantId)) throw new McpRegistryError('INVALID_TENANT', 'tenantId');
  if (typeof serverId !== 'string' || !SERVER_RE.test(serverId)) throw new McpRegistryError('INVALID_SERVER_ID', 'serverId must be 1-128 characters of [A-Za-z0-9._:-] starting with a letter or digit');
}

/** Validate and normalise an identity for a destination. */
function _identity(identity, dest, allowLocal) {
  if (dest.protocol === 'https:') {
    if (!identity || identity.kind !== 'tls-spki-pin') throw new McpRegistryError('MCP_PIN_REQUIRED', 'an https MCP server must be registered with its pinned identity { kind: "tls-spki-pin", sha256 }');
    if (typeof identity.sha256 !== 'string' || !HEX64.test(identity.sha256)) throw new McpRegistryError('MCP_PIN_INVALID', 'sha256 is 64 lower-case hex digits (SHA-256 of the certificate public key, DER SubjectPublicKeyInfo)');
    const trust = identity.trust === undefined ? 'ca-and-pin' : identity.trust;
    if (trust !== 'ca-and-pin' && trust !== 'pin-only') throw new McpRegistryError('MCP_PIN_INVALID', 'trust is "ca-and-pin" or "pin-only"');
    if (Object.keys(identity).some((k) => !['kind', 'sha256', 'trust'].includes(k))) throw new McpRegistryError('MCP_PIN_INVALID', 'unknown identity member');
    return { kind: 'tls-spki-pin', sha256: identity.sha256, trust };
  }
  if (!allowLocal || (identity && identity.kind !== 'none')) throw new McpRegistryError('MCP_IDENTITY_INVALID', 'an http server has no identity to pin');
  return { kind: 'none' };
}

async function _get(tenantId, serverId) {
  if (!usePg()) return _mem.get(`${tenantId}|${serverId}`) || null;
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM mcp_servers WHERE tenant_id=$1 AND server_id=$2', [tenantId, serverId])).rows[0] || null);
}

async function register(tenantId, spec, actor, { allowLocal = allowLocalFromEnv() } = {}) {
  _ids(tenantId, spec && spec.serverId);
  let dest;
  try { dest = validateMcpServerUrl(spec.url, { allowLocal }); } catch (e) { if (e instanceof McpUrlError) throw new McpRegistryError(e.code, e.message); throw e; }
  const identity = _identity(spec.identity, dest, allowLocal);
  if (spec.description !== undefined && !(typeof spec.description === 'string' && spec.description.length <= 500)) throw new McpRegistryError('INVALID_DESCRIPTION', 'description is at most 500 characters');
  const hash = configHash({ tenantId, serverId: spec.serverId, url: dest.url, identity });
  const row = { tenant_id: tenantId, server_id: spec.serverId, url: dest.url, transport: 'streamable-http', identity, config_hash: hash, status: 'active', local_destination: dest.local, description: spec.description || null,
    created_by: String(actor || 'unknown').slice(0, 256), created_at: new Date(), updated_at: new Date(), disabled_at: null, disabled_reason: null, disabled_by: null, last_refresh_at: null, last_refresh_tools: null, last_error: null };
  if (!usePg()) {
    if (_mem.has(`${tenantId}|${spec.serverId}`)) throw new McpRegistryError('MCP_SERVER_EXISTS', 'a server with this id is already registered', 409);
    _mem.set(`${tenantId}|${spec.serverId}`, row);
  } else {
    try {
      await pgPool.withTenantTransaction(tenantId, async (tx) => tx.query(`INSERT INTO mcp_servers (tenant_id, server_id, url, transport, identity, config_hash, local_destination, description, created_by)
        VALUES ($1,$2,$3,'streamable-http',$4::jsonb,$5,$6,$7,$8)`, [tenantId, spec.serverId, dest.url, JSON.stringify(identity), hash, dest.local, row.description, row.created_by]));
    } catch (e) { if (e && e.code === '23505') throw new McpRegistryError('MCP_SERVER_EXISTS', 'a server with this id is already registered', 409); throw e; }
  }
  emit('INFO', 'MCP_SERVER_REGISTERED', { tenantId, serverId: spec.serverId, url: dest.url, identityKind: identity.kind, local: dest.local, configHash: hash, actor: row.created_by });
  return out(await _get(tenantId, spec.serverId));
}

const get = async (tenantId, serverId) => { _ids(tenantId, serverId); return out(await _get(tenantId, serverId)); };

async function list(tenantId, { status } = {}) {
  _ids(tenantId, 'x');
  if (!usePg()) return [..._mem.values()].filter((r) => r.tenant_id === tenantId && (!status || r.status === status)).sort((a, b) => a.server_id.localeCompare(b.server_id)).map(out);
  return pgPool.withTenantTransaction(tenantId, async (tx) => (await tx.query('SELECT * FROM mcp_servers WHERE tenant_id=$1 AND ($2::text IS NULL OR status=$2) ORDER BY server_id', [tenantId, status || null])).rows.map(out));
}

/**
 * The server for ONE call. Reads the store every time (a revocation is seen by the next call on every replica) and re-applies the destination policy.
 * @returns {Promise<{ ok: true, server: { serverId, url, local, pin, pinOnly, configHash } } | { ok: false, reason: string }>}
 */
async function resolve(tenantId, serverId, { allowLocal = allowLocalFromEnv() } = {}) {
  try { _ids(tenantId, serverId); } catch { return { ok: false, reason: 'MCP_SERVER_UNKNOWN' }; }
  const r = await _get(tenantId, serverId);
  if (!r) return { ok: false, reason: 'MCP_SERVER_UNKNOWN' };
  if (r.status !== 'active') return { ok: false, reason: 'MCP_SERVER_DISABLED' };
  if (configHash({ tenantId, serverId, url: r.url, identity: r.identity }) !== String(r.config_hash).trim()) return { ok: false, reason: 'MCP_SERVER_CONFIG_TAMPERED' };
  let dest;
  try { dest = validateMcpServerUrl(r.url, { allowLocal }); } catch (e) { if (e instanceof McpUrlError) return { ok: false, reason: e.code }; throw e; }
  const pinned = r.identity && r.identity.kind === 'tls-spki-pin';
  if (dest.protocol === 'https:' && !pinned) return { ok: false, reason: 'MCP_PIN_REQUIRED' };
  return { ok: true, server: { serverId, url: dest.url, local: dest.local, pin: pinned ? r.identity.sha256 : null, pinOnly: pinned && r.identity.trust === 'pin-only', configHash: String(r.config_hash).trim() } };
}

async function _update(tenantId, serverId, patch) {
  if (!usePg()) { const r = _mem.get(`${tenantId}|${serverId}`); Object.assign(r, patch, { updated_at: new Date() }); return; }
  const cols = Object.keys(patch);
  await pgPool.withTenantTransaction(tenantId, async (tx) => tx.query(`UPDATE mcp_servers SET ${cols.map((c, i) => `${c}=$${i + 3}`).join(', ')}, updated_at=now() WHERE tenant_id=$1 AND server_id=$2`,
    [tenantId, serverId, ...cols.map((c) => (c === 'identity' ? JSON.stringify(patch[c]) : patch[c]))]));
}

async function disable(tenantId, serverId, { reason, actor } = {}) {
  _ids(tenantId, serverId);
  const r = await _get(tenantId, serverId);
  if (!r) throw new McpRegistryError('NOT_FOUND', 'no such MCP server', 404);
  if (typeof reason !== 'string' || !reason.trim() || reason.length > 256) throw new McpRegistryError('REASON_REQUIRED', 'a reason (1-256 characters) is required');
  if (r.status === 'disabled') return out(r);
  await _update(tenantId, serverId, { status: 'disabled', disabled_at: new Date(), disabled_reason: reason.trim(), disabled_by: String(actor || 'unknown').slice(0, 256) });
  const aborted = killRegistry.abortLabel(tenantId, `mcp:${serverId}`, `MCP_SERVER_DISABLED: ${reason}`);
  emit('WARN', 'MCP_SERVER_DISABLED', { tenantId, serverId, reason: reason.trim(), actor: String(actor || 'unknown'), abortedExecutions: aborted });
  return { ...out(await _get(tenantId, serverId)), abortedExecutions: aborted };
}

async function enable(tenantId, serverId, { actor } = {}) {
  _ids(tenantId, serverId);
  const r = await _get(tenantId, serverId);
  if (!r) throw new McpRegistryError('NOT_FOUND', 'no such MCP server', 404);
  if (r.status === 'active') return out(r);
  await _update(tenantId, serverId, { status: 'active', disabled_at: null, disabled_reason: null, disabled_by: null });
  emit('WARN', 'MCP_SERVER_ENABLED', { tenantId, serverId, actor: String(actor || 'unknown') });
  return out(await _get(tenantId, serverId));
}

/** Rotate the pinned identity (certificate renewal with a new key). The URL never changes - a different URL is a different server. */
async function rotateIdentity(tenantId, serverId, identity, actor, { allowLocal = allowLocalFromEnv() } = {}) {
  _ids(tenantId, serverId);
  const r = await _get(tenantId, serverId);
  if (!r) throw new McpRegistryError('NOT_FOUND', 'no such MCP server', 404);
  const dest = validateMcpServerUrl(r.url, { allowLocal: true });
  const next = _identity(identity, dest, allowLocal);
  await _update(tenantId, serverId, { identity: next, config_hash: configHash({ tenantId, serverId, url: r.url, identity: next }) });
  emit('WARN', 'MCP_SERVER_IDENTITY_ROTATED', { tenantId, serverId, identityKind: next.kind, actor: String(actor || 'unknown') });
  return out(await _get(tenantId, serverId));
}

async function recordRefresh(tenantId, serverId, { tools, error }) {
  await _update(tenantId, serverId, { last_refresh_at: new Date(), last_refresh_tools: error ? null : tools, last_error: error ? String(error).slice(0, 500) : null });
}

function _resetForTests() { _mem.clear(); }

module.exports = { CONFIG_DOMAIN, McpRegistryError, configHash, register, get, list, resolve, disable, enable, rotateIdentity, recordRefresh, _resetForTests };
