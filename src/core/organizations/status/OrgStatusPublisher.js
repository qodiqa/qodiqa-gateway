'use strict';

/**
 * OrgStatusPublisher — writes the authoritative Redis record for an
 * organization's status, then broadcasts an instant pub/sub notification
 *.
 *
 * Ordering matters: the authoritative Redis write (OrgStatusStore.setStatus)
 * happens FIRST and must succeed before the pub/sub broadcast is attempted.
 * This guarantees the bounded-propagation fallback (every worker's periodic
 * reconciliation sweep reads from the same authoritative store) can never
 * miss a change that the "instant" pub/sub path also missed — the two paths
 * read from the same durable fact, not two independently-fallible ones.
 *
 * publishStatusChange() is NOT best-effort: if the authoritative write fails,
 * it throws. A caller (the admin API) that cannot durably propagate a
 * suspension MUST NOT report success — silently updating only local state
 * would defeat the entire bounded-propagation guarantee this remediation
 * exists to provide. Only the pub/sub broadcast step (the "instant" half) is
 * degraded/non-fatal — its failure is absorbed by every worker's own bounded
 * reconciliation sweep instead.
 */

const { isAuthError, isTlsError } = require('../../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../../infra/redis/managedClient');
const { emit }   = require('../../../../services/logger');
const { monoNowMs } = require('../../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows
const { CHANNEL, buildEvent } = require('./OrgStatusEvent');
const store      = require('./OrgStatusStore');
const metrics    = require('./OrgStatusMetrics');

const CONNECT_TIMEOUT_MS = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const MAX_RECONNECTS     = 5;

let _client         = null;
let _ready          = false;
let _connectPromise = null;

function _buildClient() {
  const client = createManagedRedisClient({
    purpose:           'orgStatusPublisher',
    connectTimeout:    CONNECT_TIMEOUT_MS,
    reconnectStrategy: (attempts) => {
      if (attempts >= MAX_RECONNECTS) return new Error('ORG_STATUS_PUBLISHER_RECONNECT_EXHAUSTED');
      return Math.min(200 * Math.pow(2, attempts), 5000);
    },
  });

  client.on('ready', () => {
    _ready = true;
    emit('INFO', 'ORG_STATUS_PUBLISHER_READY', {});
  });

  client.on('error', (err) => {
    _ready = false;
    metrics.subscriberReconnects.inc({ type: 'publisher' });
    if (isAuthError(err))     emit('ERROR', 'ORG_STATUS_PUBLISHER_AUTH_ERROR', { error: err.message });
    else if (isTlsError(err)) emit('ERROR', 'ORG_STATUS_PUBLISHER_TLS_ERROR', { error: err.message });
    else                      emit('WARN',  'ORG_STATUS_PUBLISHER_ERROR',      { error: err.message });
  });

  client.on('reconnecting', () => { _ready = false; });

  return client;
}

// See the identical comment in OrgStatusStore.js — connect() resolving
// doesn't guarantee _ready has flipped yet (that waits on an additional PING
// round trip inside managedClient.js). Tolerate that short, bounded gap when
// the client is genuinely open; don't wait at all on a real connect failure.
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
        emit('WARN', 'ORG_STATUS_PUBLISHER_CONNECT_FAILED', { error: err.message });
      });
  }
  if (_connectPromise) await _connectPromise;
  if (!_ready && _client.isOpen) await _waitForReady(READY_VERIFICATION_WAIT_MS);
  return _ready ? _client : null;
}

/**
 * Durably record a new organization status and broadcast it cluster-wide.
 *
 * @param {object} opts
 * @param {string} opts.organizationId
 * @param {string} opts.status         — 'active' | 'suspended' | 'disabled'
 * @param {string|null} [opts.updatedBy]
 * @param {string|null} [opts.correlationId]
 * @param {number} [opts.minUpdatedAt] - floor for updatedAt. Every worker drops a
 *   status whose updatedAt is below the last one it applied, so a Date.now() that stepped back 1 ms (V8's 60 s
 *   re-sync on Windows) would make this change invisible cluster-wide. The caller passes the last applied
 *   updatedAt + 1 for this organization.
 * @returns {Promise<{ updatedAt: number, published: boolean }>}
 * @throws {Error} ORG_STATUS_PROPAGATION_UNAVAILABLE if the authoritative
 *   Redis write fails — the caller must not treat the status change as
 *   successfully applied cluster-wide.
 */
async function publishStatusChange({ organizationId, status, updatedBy = null, correlationId = null, minUpdatedAt = 0 }) {
  const updatedAt = Math.max(Date.now(), Number.isFinite(minUpdatedAt) ? minUpdatedAt : 0);

  const wrote = await store.setStatus(organizationId, status, updatedAt);
  if (!wrote) {
    metrics.published.inc({ result: 'store_write_failed' });
    throw new Error('ORG_STATUS_PROPAGATION_UNAVAILABLE');
  }

  const event = buildEvent({ organizationId, status, updatedAt, updatedBy, correlationId });

  let published = false;
  try {
    const client = await _getClient();
    if (client) {
      await client.publish(CHANNEL, JSON.stringify(event));
      published = true;
      metrics.published.inc({ result: 'ok' });
      emit('INFO', 'ORG_STATUS_EVENT_PUBLISHED', { eventId: event.eventId, organizationId, status });
    } else {
      metrics.published.inc({ result: 'skipped' });
      emit('WARN', 'ORG_STATUS_PUBLISH_SKIPPED', {
        organizationId, status, reason: 'REDIS_UNAVAILABLE',
        note: 'authoritative store write succeeded — other workers will pick this up via their bounded reconciliation sweep',
      });
    }
  } catch (err) {
    metrics.published.inc({ result: 'error' });
    emit('WARN', 'ORG_STATUS_PUBLISH_ERROR', { organizationId, status, error: err.message });
  }

  return { updatedAt, published };
}

async function disconnect() {
  if (!_client) return;
  try { await _client.disconnect(); } catch { /* ignore */ }
  _client         = null;
  _ready          = false;
  _connectPromise = null;
}

function isReady() { return _ready; }

module.exports = { publishStatusChange, disconnect, isReady };
