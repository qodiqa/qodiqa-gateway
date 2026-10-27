'use strict';

/**
 * OrgStatusStore — Redis-backed authoritative store for organization status
 *.
 *
 * This is the single shared source of truth for an organization's `status`
 * field across every worker in a multi-worker/multi-host deployment. It is
 * deliberately narrow in scope: it stores ONLY {status, updatedAt} per
 * organizationId — not the full organization record (name, quotas, metadata,
 * tenant assignments), which remain owned by organizationRegistry.js (control-plane-backed since PostgreSQL in production,
 * memory mode in dev/test). Only `status` (the field that gates
 * request execution) needs a bounded, cluster-wide consistency guarantee.
 *
 * Storage: a single Redis Hash `qodiqa:org:status`, field = organizationId,
 * value = JSON {status, updatedAt}. A Hash (not per-org keys) makes a full
 * reconciliation sweep a single HGETALL round trip regardless of how many
 * organizations exist, and avoids any SCAN/KEYS usage on the hot path.
 *
 * Used by:
 *   - OrgStatusPublisher (HSET on every admin-triggered status change)
 *   - OrgStatusSubscriber (HGETALL for startup load / periodic reconciliation
 *     sweep / on-reconnect resync; HGET for a single-org lookup)
 *
 * If Redis is unavailable, all methods resolve to null/false rather than
 * throwing — callers (Publisher/Subscriber) are responsible for translating
 * that into the correct fail-closed behavior (see OrgStatusSubscriber.js).
 */

const { isAuthError, isTlsError } = require('../../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../../infra/redis/managedClient');
const { emit } = require('../../../../services/logger');
const { monoNowMs } = require('../../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows
// (NF-4): every hash value is MAC-signed (OrgStatusEvent.sealRecord/openRecord);
// an unsigned or tampered value is ignored (counted), never applied.
const { sealRecord, openRecord } = require('./OrgStatusEvent');

const HASH_KEY           = 'qodiqa:org:status';
const CONNECT_TIMEOUT_MS = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const MAX_RECONNECTS     = 5;

let _client         = null;
let _connectPromise = null;
let _ready          = false;

function _buildClient() {
  const client = createManagedRedisClient({
    purpose:           'orgStatusStore',
    connectTimeout:    CONNECT_TIMEOUT_MS,
    reconnectStrategy: (attempts) => {
      if (attempts >= MAX_RECONNECTS) return new Error('ORG_STATUS_STORE_RECONNECT_EXHAUSTED');
      return Math.min(200 * Math.pow(2, attempts), 5000);
    },
  });

  client.on('ready', () => {
    _ready = true;
    emit('INFO', 'ORG_STATUS_STORE_READY', {});
  });

  client.on('error', (err) => {
    _ready = false;
    if (isAuthError(err))     emit('ERROR', 'ORG_STATUS_STORE_AUTH_ERROR', { error: err.message });
    else if (isTlsError(err)) emit('ERROR', 'ORG_STATUS_STORE_TLS_ERROR', { error: err.message });
    else                      emit('WARN',  'ORG_STATUS_STORE_ERROR',      { error: err.message });
  });

  client.on('reconnecting', () => { _ready = false; });

  return client;
}

// managedClient.js's `connect()` resolves once the underlying TCP/AUTH
// handshake completes — a network round trip earlier than its own
// `_verifyAndAnnounceReady()` PING check, which is what actually flips this
// module's `_ready` flag via the 'ready' event. Awaiting `connect()` alone
// can therefore race ahead of `_ready` becoming true on a fresh connection.
// Tolerate that short, bounded gap (client.isOpen true but not yet verified
// ready) instead of reporting "unavailable" for a client still finishing
// its handshake — but do NOT wait at all when the connection genuinely
// failed (isOpen false), where `_ready` would never become true anyway.
const READY_VERIFICATION_WAIT_MS = 1000;

function _waitForReady(timeoutMs) {
  return new Promise((resolve) => {
    const start = monoNowMs(); // monotonic (same-process)
    (function tick() {
      if (_ready || monoNowMs() - start >= timeoutMs) return resolve();
      setTimeout(tick, 20).unref?.();
    })();
  });
}

async function _getClient() {
  if (_client && _ready) return _client;
  if (!_client) {
    _client = _buildClient();
    _connectPromise = _client.connect()
      .then(() => { _connectPromise = null; })
      .catch((err) => {
        _connectPromise = null;
        emit('WARN', 'ORG_STATUS_STORE_CONNECT_FAILED', { error: err.message });
      });
  }
  if (_connectPromise) await _connectPromise;
  if (!_ready && _client.isOpen) await _waitForReady(READY_VERIFICATION_WAIT_MS);
  return _ready ? _client : null;
}

/**
 * Durably write the authoritative status for one organization.
 *
 * @param {string} organizationId
 * @param {string} status
 * @param {number} updatedAt — epoch ms
 * @returns {Promise<boolean>} true on success, false if Redis is unavailable/errored
 */
async function setStatus(organizationId, status, updatedAt) {
  try {
    const client = await _getClient();
    if (!client) return false;
    await client.hSet(HASH_KEY, organizationId, sealRecord(organizationId, { status, updatedAt }));
    return true;
  } catch (err) {
    emit('WARN', 'ORG_STATUS_STORE_WRITE_FAILED', { organizationId, error: err.message });
    return false;
  }
}

/**
 * Read the authoritative status for one organization.
 *
 * @param {string} organizationId
 * @returns {Promise<{ status: string, updatedAt: number } | null>}
 */
async function getStatus(organizationId) {
  try {
    const client = await _getClient();
    if (!client) return null;
    const raw = await client.hGet(HASH_KEY, organizationId);
    if (!raw) return null;
    return openRecord(organizationId, raw);
  } catch {
    return null;
  }
}

/**
 * Read the authoritative status for every organization known to Redis.
 * Used for the startup load and the periodic/on-reconnect reconciliation
 * sweep. A single O(N) round trip (N = organization count) — never called
 * per-request.
 *
 * @returns {Promise<Map<string, { status: string, updatedAt: number }> | null>}
 *   null if Redis is unavailable (caller must treat this as "reconciliation
 *   failed", not as "no organizations exist").
 */
async function getAllStatuses() {
  try {
    const client = await _getClient();
    if (!client) return null;
    const all = await client.hGetAll(HASH_KEY);
    const result = new Map();
    for (const [organizationId, raw] of Object.entries(all || {})) {
      const rec = openRecord(organizationId, raw); // null: unsigned/tampered/corrupt — skipped, counted
      if (rec) result.set(organizationId, rec);
    }
    return result;
  } catch {
    return null;
  }
}

function isReady() { return _ready; }

async function disconnect() {
  if (!_client) return;
  try { await _client.disconnect(); } catch { /* ignore */ }
  _client         = null;
  _connectPromise = null;
  _ready          = false;
}

module.exports = { setStatus, getStatus, getAllStatuses, isReady, disconnect, HASH_KEY };
