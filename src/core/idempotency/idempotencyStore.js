'use strict';

/**
 * QODIQA Idempotency Store — Redis-backed, durable, multi-worker-safe (API-2).
 *
 * Reuses the exact same durability precedent this codebase already
 * established for exactly this class of problem — "exactly-once across all
 * workers and process restarts" — src/validation/nonceStore.js's
 * Redis-backed, AOF-durable replay protection. This is a deliberate design
 * choice (see API-2-REMEDIATION-REPORT.md §4): PostgreSQL is optional in
 * this deployment (QODIQA_PG_ENABLED, off by default) while Redis is
 * already a hard runtime dependency for every request via nonce/anomaly/
 * rate-limit enforcement, with its own durability guarantee already
 * enforced at startup (STRICT_REPLAY_PROTECTION — see server.js and
 * src/infra/redis/persistenceCheck.js). Reusing it means idempotency
 * inherits that same, already-operational persistence guarantee instead of
 * introducing a second storage dependency this feature alone would need.
 *
 * Key design invariants:
 *   • reserve()  — one atomic command (SET NX PX). Two workers racing the
 *     same (tenant, key) can never both win the reservation — Redis
 *     executes SET atomically regardless of which of N application
 *     processes/pods issued it (multi-worker / horizontal-scale safe).
 *   • complete() — SET XX PX: only overwrites a reservation this process
 *     itself is known to hold (a key that no longer exists — expired or
 *     released concurrently — is left alone, never resurrected).
 *   • release()  — DEL: makes the (tenant, key) pair immediately available
 *     for a fresh attempt. Used for every non-cacheable outcome (see
 *     idempotencyGate.js) so a genuine retry after a transient failure is
 *     never permanently stuck.
 *   • TTL does double duty: the short reservation TTL bounds an abandoned/
 *     crashed reservation (self-heals — no sweeper needed); the longer
 *     completion TTL implements the feature's retention/expiration policy
 *     natively via Redis expiry.
 *   • Tenant scoping is baked into the key itself (buildIdempotencyKey) —
 *     not just an application-level filter — so cross-tenant replay is
 *     structurally impossible, not merely checked.
 *   • Lazy client lifecycle, fail-closed semantics, and connection/
 *     readiness observability all mirror nonceStore.js — see that module's
 *     header for the full rationale; not re-derived here.
 */

const { EventEmitter } = require('events');
const {
  getConfigSummary,
  isAuthError,
  isTlsError,
} = require('../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../infra/redis/managedClient');
const { createInfiniteReconnectStrategy } = require('../../infra/redis/reconnectStrategy');
const { emit } = require('../../../services/logger');

const KEY_PREFIX      = 'qodiqa:idem:v1:';
// no longer a hard cap — see OLD_MAX_RECONNECTS note in storage.js.
const OLD_MAX_RECONNECTS = 5;
const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);

const _emitter = new EventEmitter();
_emitter.setMaxListeners(20);

/**
 * Single source of truth for idempotency store key construction. tenantId
 * prefixes the WHOLE key (mirrors nonceStore.buildNonceKey's convention) so
 * two tenants can never collide even if they independently choose the same
 * idempotency-key string.
 *
 * @param {string|null} tenantId
 * @param {string}      idempotencyKey
 * @returns {string}
 */
function buildIdempotencyKey(tenantId, idempotencyKey) {
  return tenantId ? `${tenantId}:${KEY_PREFIX}${idempotencyKey}` : `${KEY_PREFIX}${idempotencyKey}`;
}

// ── Connection state ──────────────────────────────────────────────────────────

let _client        = null;
let _configSummary = null;
let _hadFirstReady = false;
let _wasReady      = false;
let _hadAuthError  = false;
let _hadTlsError   = false;

// infinite retry — unlike rate-limit/nonce/anomaly, this store has no
// _reconnectCount/_checkReconnectFlapping side effects of its own (none
// existed earlier either), so onRetry only needs to re-emit the WARN.
const _reconnectStrategy = createInfiniteReconnectStrategy({
  source: 'IDEMPOTENCY_STORE',
  oldMaxReconnects: OLD_MAX_RECONNECTS,
  onRetry: ({ retries, delayMs, pastOldThreshold }) => {
    emit('WARN', 'REDIS_RECONNECTING', { source: 'IDEMPOTENCY_STORE', retries, nextDelayMs: delayMs, pastOldThreshold });
  },
});

function _getClient() {
  if (_client) return _client;

  _configSummary = getConfigSummary();

  _client = createManagedRedisClient({
    purpose:           'idempotency',
    reconnectStrategy: _reconnectStrategy,
    connectTimeout:    CONNECT_TIMEOUT,
  });

  _client.on('connect', () => {
    emit('INFO', 'REDIS_CONNECTED', { source: 'IDEMPOTENCY_STORE', url: _configSummary.urlRedacted });
  });

  _client.on('error', err => {
    emit('ERROR', 'IDEMPOTENCY_STORE_ERROR', { error: err.message });

    if (!_hadAuthError && isAuthError(err)) {
      _hadAuthError = true;
      emit('ERROR', 'REDIS_AUTH_REJECTED', { source: 'IDEMPOTENCY_STORE', error: err.message });
    }
    if (!_hadTlsError && isTlsError(err)) {
      _hadTlsError = true;
      emit('ERROR', 'REDIS_TLS_FAILED', { source: 'IDEMPOTENCY_STORE', error: err.message });
    }
    if (_wasReady) {
      _wasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', { source: 'IDEMPOTENCY_STORE', error: err.message });
      _emitter.emit('degraded', { source: 'IDEMPOTENCY_STORE', reason: err.message });
    }
  });

  _client.on('ready', () => {
    const isReconnect = _hadFirstReady;
    _hadFirstReady = true;
    _wasReady      = true;
    _hadAuthError  = false;
    _hadTlsError   = false;
    emit('INFO', 'REDIS_READY', { source: 'IDEMPOTENCY_STORE', url: _configSummary?.urlRedacted, isReconnect });
    _emitter.emit('ready', { source: 'IDEMPOTENCY_STORE', isReconnect });
  });

  _client.on('end', () => {
    if (_wasReady) {
      _wasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', { source: 'IDEMPOTENCY_STORE', reason: 'connection closed' });
    }
    _emitter.emit('degraded', { source: 'IDEMPOTENCY_STORE', reason: 'connection closed — automatic recovery in progress' });
  });

  emit('INFO', 'REDIS_CONNECTING', { source: 'IDEMPOTENCY_STORE', url: _configSummary.urlRedacted });
  _client.connect().catch(err => emit('ERROR', 'IDEMPOTENCY_STORE_CONNECT_FAILED', { error: err.message }));

  return _client;
}

function _assertReady() {
  if (!_getClient().isReady) {
    throw new Error('IDEMPOTENCY_STORE: Redis not connected — idempotency guarantee unavailable (fail-closed)');
  }
}

function _safeParse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Eagerly connect and validate the namespace. Mirrors nonceStore.initialize().
 * @returns {Promise<{ ready: true, namespace: string }>}
 */
async function initialize() {
  const client = _getClient();

  if (!client.isReady) {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        off();
        reject(new Error(`IDEMPOTENCY_STORE: startup connect timeout (${CONNECT_TIMEOUT}ms)`));
      }, CONNECT_TIMEOUT);
      function onReady() { off(); resolve(); }
      function onEnd()   { off(); reject(new Error('IDEMPOTENCY_STORE: connection ended before becoming ready')); }
      function off() { clearTimeout(timer); client.off('ready', onReady); client.off('end', onEnd); }
      client.once('ready', onReady);
      client.once('end',   onEnd);
    });
  }

  const pong = await client.ping();
  if (pong !== 'PONG') {
    throw new Error(`IDEMPOTENCY_STORE: unexpected PING response: ${pong}`);
  }
  emit('INFO', 'IDEMPOTENCY_STORE_READY', { namespace: KEY_PREFIX });
  return { ready: true, namespace: KEY_PREFIX };
}

function isReady() {
  return _client ? _client.isReady : false;
}

async function disconnect() {
  if (_client) {
    const c        = _client;
    _client        = null;
    _configSummary = null;
    _hadFirstReady = false;
    _wasReady      = false;
    _hadAuthError  = false;
    _hadTlsError   = false;
    try { await c.disconnect(); } catch { /* already closed */ }
  }
}

/**
 * Atomically reserve (tenantId, idempotencyKey) for exclusive execution.
 *
 * @param {string|null} tenantId
 * @param {string} idempotencyKey
 * @param {string} fingerprint
 * @param {number} reservationTtlMs
 * @returns {Promise<{ reserved: true } | { reserved: false, existing: object|null }>}
 * @throws  If Redis is unavailable — fail-closed.
 */
async function reserve(tenantId, idempotencyKey, fingerprint, reservationTtlMs) {
  _assertReady();
  const key = buildIdempotencyKey(tenantId, idempotencyKey);
  const record = {
    status:      'pending',
    fingerprint,
    tenantId:    tenantId || null,
    createdAt:   Date.now(),
  };

  const result = await _getClient().set(key, JSON.stringify(record), { NX: true, PX: reservationTtlMs });
  if (result === null) {
    const existingRaw = await _getClient().get(key);
    return { reserved: false, existing: existingRaw !== null ? _safeParse(existingRaw) : null };
  }
  return { reserved: true };
}

/**
 * Mark a held reservation completed and durably store its outcome.
 * Only overwrites a reservation this process actually holds (SET XX) — a
 * key that already expired or was released is left untouched, never
 * resurrected as a phantom "completed" record.
 *
 * @param {string|null} tenantId
 * @param {string} idempotencyKey
 * @param {object} record   caller-supplied outcome fields (fingerprint, httpStatus, body, ...)
 * @param {number} retentionTtlMs
 * @returns {Promise<{ completed: boolean }>}
 */
async function complete(tenantId, idempotencyKey, record, retentionTtlMs) {
  _assertReady();
  const key = buildIdempotencyKey(tenantId, idempotencyKey);
  const payload = JSON.stringify({
    ...record,
    status:      'completed',
    tenantId:    tenantId || null,
    completedAt: Date.now(),
  });
  const result = await _getClient().set(key, payload, { XX: true, PX: retentionTtlMs });
  return { completed: result === 'OK' };
}

/**
 * Release a held reservation immediately — makes (tenantId, idempotencyKey)
 * available for a fresh attempt. Safe to call on a key that no longer
 * exists (no-op).
 *
 * @param {string|null} tenantId
 * @param {string} idempotencyKey
 */
async function release(tenantId, idempotencyKey) {
  _assertReady();
  await _getClient().del(buildIdempotencyKey(tenantId, idempotencyKey));
}

/**
 * Read-only lookup — does not mutate state.
 *
 * @param {string|null} tenantId
 * @param {string} idempotencyKey
 * @returns {Promise<object|null>}
 */
async function get(tenantId, idempotencyKey) {
  _assertReady();
  const raw = await _getClient().get(buildIdempotencyKey(tenantId, idempotencyKey));
  return raw !== null ? _safeParse(raw) : null;
}

module.exports = {
  reserve,
  complete,
  release,
  get,
  initialize,
  isReady,
  disconnect,
  buildIdempotencyKey,
  emitter: _emitter,
  get _client() { return _client; },
};
