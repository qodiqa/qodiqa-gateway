'use strict';

/**
 * Per-artifact revocation: an operator can withdraw ONE signed artifact (identified by its `payload.requestId`)
 * before it is used — a leaked or mis-issued artifact is dead within milliseconds instead of living out its life.
 *
 * Revoked ids live in Redis as `artrev:v1:<requestId>` with a TTL (REVOCATION_TTL_SECONDS): an artifact cannot be presented
 * after MAX_ARTIFACT_AGE_MS (60 s) plus the accepted clock skew, so a revocation only has to outlive that; the entry then
 * disappears by itself and Redis holds nothing but the handful of artifacts an operator revoked in the last two minutes.
 *
 * The check runs in validateBoundRequest AFTER the signature and the request binding (the id is only trustworthy then) and
 * BEFORE the nonce is registered — so a revoked artifact never consumes its nonce, and a refused request leaves no trace
 * but its own BLOCK entry. If the store cannot answer, the request is refused (ARTIFACT_REVOCATION_STATE_UNAVAILABLE): "cannot
 * tell whether it was revoked" must not mean "not revoked". Without REDIS_URL (development, single-node tests) the set is
 * kept in process memory.
 */

const { emit } = require('../../../services/logger');

const REVOCATION_TTL_SECONDS = 120;       // 60 s maximum artifact age + clock skew, with margin
const KEY_PREFIX = 'artrev:v1:';
const REASON_MAX = 500;
const MEMORY_CAP = 100000;
const STORE_TIMEOUT_MS = 2000;           // a store that cannot answer in time is "cannot tell" => the request is refused
const REQUEST_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

class ArtifactRevocationError extends Error {
  constructor(code, message, status = 400) { super(message); this.name = 'ArtifactRevocationError'; this.code = code; this.status = status; }
}

// ── stores ─────────────────────────────────────────────────────────────────────
function createMemoryStore() {
  const m = new Map();      // requestId → { json, expiresAt }
  return {
    kind: 'memory',
    async isRevoked(requestId) {
      const e = m.get(requestId);
      if (!e) return null;
      if (e.expiresAt <= Date.now()) { m.delete(requestId); return null; }
      return JSON.parse(e.json);
    },
    async revoke(requestId, record, ttlSeconds) {
      const existing = m.get(requestId);
      if (existing && existing.expiresAt > Date.now()) {      // the first revocation keeps its operator and time; only the TTL is refreshed
        existing.expiresAt = Date.now() + ttlSeconds * 1000;
        return { created: false, record: JSON.parse(existing.json) };
      }
      if (m.size >= MEMORY_CAP) m.delete(m.keys().next().value);
      m.set(requestId, { json: JSON.stringify(record), expiresAt: Date.now() + ttlSeconds * 1000 });
      return { created: true, record };
    },
    _size: () => m.size,
  };
}

// ids are matched case-insensitively (UUIDs are), so one spelling is used for every key
const _norm = (requestId) => requestId.toLowerCase();

function _withTimeout(promise, ms, what) {
  let t;
  const timeout = new Promise((_, reject) => { t = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

/** @param {any} client @param {{ connecting?: Promise<any> }} [opts] connecting: the in-flight connect, awaited by the first calls instead of failing them */
function createRedisStore(client, { connecting = null } = {}) {
  const ready = async () => {
    if (!client.isReady && connecting) { try { await connecting; } catch { /* reported below */ } }
    if (!client.isReady) throw new Error('Redis not connected');
  };
  return {
    kind: 'redis',
    async isRevoked(requestId) {
      await ready();
      const raw = await client.get(KEY_PREFIX + requestId);
      return raw ? JSON.parse(raw) : null;
    },
    async revoke(requestId, record, ttlSeconds) {
      await ready();
      // NX: the first revocation keeps its operator and time; repeating it only reports { created: false }.
      const ok = await client.set(KEY_PREFIX + requestId, JSON.stringify(record), { EX: ttlSeconds, NX: true });
      if (ok === 'OK') return { created: true, record };
      await client.expire(KEY_PREFIX + requestId, ttlSeconds);
      const raw = await client.get(KEY_PREFIX + requestId);
      return { created: false, record: raw ? JSON.parse(raw) : record };
    },
    // Closes the connection this store owns (graceful shutdown; tests). Safe to call twice.
    async close() {
      if (connecting) { try { await connecting; } catch { /* the failure was reported when it happened */ } }
      try { await client.quit(); } catch { try { await client.disconnect(); } catch { /* already closed */ } }
    },
  };
}

let _default = null;
function _defaultStore() {
  if (_default) return _default;
  if (!process.env.REDIS_URL) { _default = createMemoryStore(); return _default; }
  const { createManagedRedisClient } = require('../../infra/redis/managedClient');
  const { createInfiniteReconnectStrategy } = require('../../infra/redis/reconnectStrategy');
  const client = createManagedRedisClient({
    purpose: 'artifactRevocation',
    reconnectStrategy: createInfiniteReconnectStrategy({ source: 'ARTIFACT_REVOCATION', oldMaxReconnects: 5, onRetry: () => {} }),
    connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10),
  });
  client.on('error', (err) => emit('WARN', 'ARTIFACT_REVOCATION_REDIS_ERROR', { error: err.message }));
  const connecting = client.connect().catch((err) => { emit('ERROR', 'ARTIFACT_REVOCATION_REDIS_CONNECT_FAILED', { error: err.message }); });
  _default = createRedisStore(client, { connecting });
  return _default;
}

/** Closes the default store's Redis connection, if one was opened, and forgets the store (the next call opens a new one). */
async function close() {
  const s = _default;
  _default = null;
  if (s && typeof s.close === 'function') await s.close();
}

function _metrics() { try { return require('../../observability/metrics'); } catch { return null; } }

// ── API ────────────────────────────────────────────────────────────────────────
/**
 * Is this artifact (by requestId) revoked? Resolves to the revocation record or null. Rejects when the store cannot answer
 * (the caller must refuse the request).
 */
async function isRevoked(requestId, /** @type {{ _store?: any }} */ { _store } = {}) {
  if (typeof requestId !== 'string' || !requestId) return null;
  return _withTimeout(Promise.resolve().then(() => (_store || _defaultStore()).isRevoked(_norm(requestId))), STORE_TIMEOUT_MS, 'artifact revocation lookup');
}

/**
 * Revoke one artifact. Idempotent: a second revocation of the same id reports { created: false } and keeps the first record.
 * @returns {Promise<{ created: boolean, record: object, ttlSeconds: number }>}
 */
async function revoke({ requestId, operatorId, reason, tenantId = null }, /** @type {{ _store?: any, now?: () => number }} */ { _store, now = Date.now } = {}) {
  if (typeof requestId !== 'string' || !REQUEST_ID_RE.test(requestId)) throw new ArtifactRevocationError('INVALID_REQUEST_ID', 'requestId must be the UUID of the artifact (payload.requestId)');
  if (typeof operatorId !== 'string' || !operatorId) throw new ArtifactRevocationError('OPERATOR_REQUIRED', 'an authenticated operator is required', 401);
  if (typeof reason !== 'string' || !reason.trim() || reason.length > REASON_MAX || /[\u0000-\u001f\u007f]/.test(reason)) {
    throw new ArtifactRevocationError('INVALID_REASON', `a reason of 1-${REASON_MAX} characters without control characters is required`);
  }
  requestId = _norm(requestId);
  const record = { requestId, operatorId, reason: reason.trim(), tenantId: typeof tenantId === 'string' && tenantId ? tenantId : null, revokedAt: new Date(now()).toISOString() };
  let out;
  try {
    out = await _withTimeout(Promise.resolve().then(() => (_store || _defaultStore()).revoke(requestId, record, REVOCATION_TTL_SECONDS)), STORE_TIMEOUT_MS, 'artifact revocation write');
  } catch (err) {
    emit('CRITICAL', 'ARTIFACT_REVOCATION_FAILED', { requestId, operatorId, error: err.message });
    throw new ArtifactRevocationError('REVOCATION_STORE_UNAVAILABLE', 'the revocation could not be recorded; the artifact is NOT revoked', 503);
  }
  const m = _metrics();
  if (m && m.artifactRevocationsTotal) m.artifactRevocationsTotal.inc({ outcome: out.created ? 'created' : 'repeated' });
  // Operator action audit: the central audit store ingests every emitted event; the BLOCK a
  // later presentation of this artifact produces is a normal audit-chain entry (reason ARTIFACT_REVOKED).
  emit('CRITICAL', 'ARTIFACT_REVOKED', { requestId, operatorId, reason: record.reason, tenantId: record.tenantId, created: out.created, ttlSeconds: REVOCATION_TTL_SECONDS, ...(out.created ? {} : { firstRevokedBy: out.record ? out.record.operatorId : null }) });
  return { created: out.created, record: out.record || record, ttlSeconds: REVOCATION_TTL_SECONDS };
}

module.exports = { STORE_TIMEOUT_MS, isRevoked, revoke, close, createMemoryStore, createRedisStore, ArtifactRevocationError, REVOCATION_TTL_SECONDS, REQUEST_ID_RE, KEY_PREFIX };
