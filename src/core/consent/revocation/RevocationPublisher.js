'use strict';

/**
 * RevocationPublisher — Redis pub/sub publisher for instant consent revocation.
 *
 * Maintains a dedicated Redis client (separate from ConsentCache's client —
 * a Redis client in subscribe mode cannot issue regular commands).
 *
 * publish() is non-fatal: if Redis is unavailable the revocation still completes
 * against PostgreSQL and the local cache is invalidated.  Multi-node propagation
 * is degraded (other nodes rely on their negative TTL window) but enforcement is
 * never weakened — each node verifies consent independently from the DB on cache miss.
 *
 * Client lifecycle: single instance created on first publish() call; reconnects
 * are handled internally by the redis client's reconnectStrategy.
 */

const { isAuthError, isTlsError } = require('../../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../../infra/redis/managedClient');
const { emit }   = require('../../../../services/logger');
const { CHANNEL, buildEvent } = require('./RevocationEvent');
const metrics    = require('./RevocationMetrics');

const CONNECT_TIMEOUT_MS = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const MAX_RECONNECTS     = 5;

let _client         = null;
let _ready          = false;
let _connectPromise = null;

function _buildClient() {
  const client = createManagedRedisClient({
    purpose:           'revocationPublisher',
    connectTimeout:    CONNECT_TIMEOUT_MS,
    reconnectStrategy: (attempts) => {
      if (attempts >= MAX_RECONNECTS) return new Error('REVOCATION_PUBLISHER_RECONNECT_EXHAUSTED');
      return Math.min(200 * Math.pow(2, attempts), 5000);
    },
  });

  client.on('ready', () => {
    _ready = true;
    emit('INFO', 'REVOCATION_PUBLISHER_READY', {});
  });

  client.on('error', (err) => {
    _ready = false;
    metrics.subscriberReconnects.inc({ type: 'publisher' });
    if (isAuthError(err))     emit('ERROR', 'REVOCATION_PUBLISHER_AUTH_ERROR', { error: err.message });
    else if (isTlsError(err)) emit('ERROR', 'REVOCATION_PUBLISHER_TLS_ERROR', { error: err.message });
    else                      emit('WARN',  'REVOCATION_PUBLISHER_ERROR',      { error: err.message });
  });

  client.on('reconnecting', () => { _ready = false; });

  return client;
}

async function _getClient() {
  if (_client && _ready) return _client;
  if (!_client) {
    _client = _buildClient();
    _connectPromise = _client.connect()
      .then(() => { _connectPromise = null; })
      .catch((err) => {
        _connectPromise = null;
        emit('WARN', 'REVOCATION_PUBLISHER_CONNECT_FAILED', { error: err.message });
      });
  }
  if (_connectPromise) await _connectPromise;
  return _ready ? _client : null;
}

/**
 * Publish a revocation event to the Redis pub/sub channel.
 *
 * @param {object} opts
 * @param {string|null} [opts.consentId]         - specific record UUID (null for actor-level)
 * @param {string}      opts.subjectId         - actor_id being revoked
 * @param {string|null} [opts.action]            - specific action revoked (null for actor-level)
 * @param {string|null} [opts.tenantId]
 * @param {string|null} [opts.revokedBy]
 * @param {string|null} [opts.revocationReason]
 * @param {string|null} [opts.correlationId]
 * @param {number|null} [opts.consentVersion]
 * @returns {Promise<boolean>} true if published, false if Redis unavailable or error
 */
async function publish(opts) {
  const event = buildEvent(opts);

  try {
    const client = await _getClient();
    if (!client) {
      emit('WARN', 'REVOCATION_PUBLISH_SKIPPED', {
        consentId: opts.consentId ?? null,
        subjectId: opts.subjectId,
        reason:    'REDIS_UNAVAILABLE',
      });
      metrics.published.inc({ result: 'skipped' });
      return false;
    }

    const subscriberCount = await client.publish(CHANNEL, JSON.stringify(event));
    metrics.published.inc({ result: 'ok' });
    emit('INFO', 'REVOCATION_EVENT_PUBLISHED', {
      eventId:         event.eventId,
      consentId:       opts.consentId ?? null,
      subjectId:       opts.subjectId,
      subscriberCount,
    });
    return true;
  } catch (err) {
    emit('WARN', 'REVOCATION_PUBLISH_ERROR', {
      consentId: opts.consentId ?? null,
      subjectId: opts.subjectId,
      error:     err.message,
    });
    metrics.published.inc({ result: 'error' });
    return false;
  }
}

/**
 * Disconnect the publisher client (used during graceful shutdown).
 */
async function disconnect() {
  if (!_client) return;
  try { await _client.disconnect(); } catch { /* ignore */ }
  _client         = null;
  _ready          = false;
  _connectPromise = null;
}

function isReady() { return _ready; }

module.exports = { publish, disconnect, isReady };
