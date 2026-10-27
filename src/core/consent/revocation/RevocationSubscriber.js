'use strict';

/**
 * RevocationSubscriber — Redis pub/sub subscriber for instant consent revocation.
 *
 * This is a REQUIRED control-plane dependency.  A node that is not subscribed
 * to the revocation channel cannot receive revocation events and therefore
 * cannot guarantee that consent withdrawal is immediately enforced.
 *
 * Startup contract:
 *   - start() THROWS if the subscriber cannot connect within STARTUP_TIMEOUT_MS.
 *   - The caller (server.js) treats this as FATAL and exits.
 *   - The node must not accept consent-dependent traffic without an active
 *     subscriber connection.
 *
 * Runtime contract:
 *   - isReady() returns false whenever the connection is lost.
 *   - ConsentVerifier checks isReady() on every verification; any disconnection
 *     immediately causes all consent-requiring requests to be denied (fail-closed).
 *   - There is no fallback, no TTL-based degraded mode, and no eventual-consistency
 *     path.  Revocation enforcement is immediate or it does not happen.
 *
 * Processing pipeline per received message:
 *   1. Parse and validate: JSON, version, required fields, timestamp window, signature
 *   2. Deduplicate: in-memory LRU Set of recently seen eventIds (max DEDUP_MAX_SIZE)
 *   3. Cache invalidation: targeted (actor + action) or actor-level (bulk)
 *   4. Metrics + structured audit event
 */

const { isAuthError, isTlsError } = require('../../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../../infra/redis/managedClient');
const { createInfiniteReconnectStrategy } = require('../../../infra/redis/reconnectStrategy');
const { emit }   = require('../../../../services/logger');
const { CHANNEL, parseEvent } = require('./RevocationEvent');
const metrics    = require('./RevocationMetrics');
const { raceTimeout } = require('../../../utils/raceTimeout');

const CONNECT_TIMEOUT_MS = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS     || '5000',  10);
const STARTUP_TIMEOUT_MS = parseInt(process.env.REVOCATION_SUBSCRIBER_STARTUP_TIMEOUT_MS || '10000', 10);
// no longer a hard cap — see OLD_MAX_RECONNECTS note in
// src/infra/redis/reconnectStrategy.js's createInfiniteReconnectStrategy(),
// the same remediation nonceStore.js/anomalyStore.js/etc. already use.
// Kept as OLD_MAX_RECONNECTS (not MAX_RECONNECTS) so `pastOldThreshold`
// telemetry below still marks exactly where the old bounded strategy used
// to give up permanently.
const OLD_MAX_RECONNECTS = parseInt(process.env.REVOCATION_SUBSCRIBER_MAX_RECONNECTS || '10', 10);

// In-memory deduplication window (LRU-like bounded Set).
// Evicts oldest entry when capacity is reached.  Cleared on subscriber restart;
// re-processing is idempotent — cache.invalidate on an already-gone key is a no-op.
const DEDUP_MAX_SIZE = 10_000;
const _seenEventIds  = new Set();

let _client  = null;
let _ready   = false;
let _started = false;

function _deduplicate(eventId) {
  if (_seenEventIds.has(eventId)) return true;
  _seenEventIds.add(eventId);
  if (_seenEventIds.size > DEDUP_MAX_SIZE) {
    _seenEventIds.delete(_seenEventIds.values().next().value);
  }
  return false;
}

// RevocationSubscriber is a REQUIRED control-plane dependency (see
// module header) — a bounded reconnectStrategy that gives up after
// OLD_MAX_RECONNECTS attempts leaves consent enforcement permanently
// fail-closed until a full process restart, even once Redis itself has
// recovered. Converges
// onto the same infinite-retry module already proved on nonceStore.js/
// anomalyStore.js/rateLimit/storage.js/idempotencyStore.js — never returns
// false/Error, so node-redis's own reconnect loop never exits and never
// needs the managedClient.js self-healing supervisor to rescue it (that
// supervisor's own trigger, a node-redis 'end' event, is never emitted in
// this exact "reconnect-after-was-ready exhausted" path — traced directly
// against @redis/client's socket.js — so relying on it would not have
// worked either). This changes ONLY the give-up policy: `client.on(
// 'reconnecting'|'error', ...)` below are untouched, so isReady() still
// flips false immediately on disconnect and stays false for the entire
// outage — fail-closed enforcement during an outage is unaffected.
const _reconnectStrategy = createInfiniteReconnectStrategy({
  source:           'REVOCATION_SUBSCRIBER',
  oldMaxReconnects: OLD_MAX_RECONNECTS,
  onRetry: ({ retries, delayMs, pastOldThreshold }) => {
    emit('WARN', 'REVOCATION_SUBSCRIBER_RECONNECT_ATTEMPT', { retries, delayMs, pastOldThreshold });
  },
});

function _buildClient() {
  const client = createManagedRedisClient({
    purpose:           'revocationSubscriber',
    connectTimeout:    CONNECT_TIMEOUT_MS,
    reconnectStrategy: _reconnectStrategy,
  });

  client.on('ready', ({ isReconnect } = {}) => {
    if (_client !== client) return; // RD-3: a late 'ready' from a client stop() already released is ignored
    _ready = true;
    emit('INFO', 'REVOCATION_SUBSCRIBER_READY', {});

    // Finding 49: single mode now self-heals a terminal `end` by destroying
    // and recreating the underlying client (managedClient.js), which — unlike
    // an in-place socket reconnect — has no memory of the prior subscription.
    // Every `ready` that follows a reconnect (single-mode recovery OR a
    // sentinel/cluster topology change) must therefore re-subscribe, not just
    // the sentinel-specific 'topology-change' path below.
    if (isReconnect) {
      _client.subscribe(CHANNEL, _handleMessage)
        .then(() => {
          emit('INFO', 'REVOCATION_SUBSCRIBER_SUBSCRIPTION_RESTORED', { channel: CHANNEL });
          require('../../../observability/metrics').redisSubscriptionRecoveryTotal.inc({ purpose: 'revocationSubscriber' });
        })
        .catch((err) => {
          emit('WARN', 'REVOCATION_SUBSCRIBER_RESUBSCRIBE_FAILED', { channel: CHANNEL, error: err.message });
        });
    }
  });

  client.on('error', (err) => {
    _ready = false;
    metrics.subscriberReconnects.inc({ type: 'subscriber' });
    if (isAuthError(err))     emit('ERROR', 'REVOCATION_SUBSCRIBER_AUTH_ERROR', { error: err.message });
    else if (isTlsError(err)) emit('ERROR', 'REVOCATION_SUBSCRIBER_TLS_ERROR', { error: err.message });
    else                      emit('WARN',  'REVOCATION_SUBSCRIBER_ERROR',      { error: err.message });
  });

  client.on('reconnecting', () => {
    _ready = false;
    emit('WARN', 'REVOCATION_SUBSCRIBER_RECONNECTING', {
      message: 'Revocation subscriber reconnecting — consent enforcement is fail-closed until reconnected.',
    });
  });

  return client;
}

async function _handleMessage(rawMessage) {
  const parsed = parseEvent(rawMessage);
  if (!parsed.ok) {
    emit('WARN', 'REVOCATION_EVENT_INVALID', {
      reason:  /** @type {any} */ (parsed).reason,
      preview: rawMessage.slice(0, 200),
    });
    metrics.received.inc({ result: 'invalid' });
    return;
  }

  const { event } = parsed;

  if (_deduplicate(event.eventId)) {
    emit('INFO', 'REVOCATION_EVENT_DUPLICATE', { eventId: event.eventId });
    metrics.received.inc({ result: 'duplicate' });
    return;
  }

  const t0 = Date.now();

  // Lazy require avoids circular dependency at module load time.
  const cache = require('../ConsentCache');
  try {
    if (event.subjectId && event.action) {
      // Targeted invalidation: specific actor + action + tenant triple.
      // consentVersion lets the local cache CAS-guard its
      // tombstone against a verify() call already in flight on this node.
      await cache.invalidate(event.subjectId, event.action, event.tenantId ?? null, event.consentVersion ?? null);
      metrics.cacheInvalidations.inc({ scope: 'targeted' });
    } else {
      // Actor-level invalidation: all cached entries for this actor
      await cache.invalidateActor(event.subjectId);
      metrics.cacheInvalidations.inc({ scope: 'actor' });
    }

    const latencyMs = Date.now() - t0;
    metrics.propagationLatency.observe(latencyMs);
    metrics.received.inc({ result: 'ok' });

    emit('INFO', 'REVOCATION_EVENT_PROCESSED', {
      eventId:   event.eventId,
      consentId: event.consentId ?? null,
      subjectId: event.subjectId,
      action:    event.action    ?? null,
      latencyMs,
    });
  } catch (err) {
    emit('WARN', 'REVOCATION_CACHE_INVALIDATION_FAILED', {
      eventId:   event.eventId,
      subjectId: event.subjectId,
      error:     err.message,
    });
    metrics.received.inc({ result: 'error' });
  }
}

/**
 * Start the revocation event subscriber.
 *
 * THROWS if the subscriber cannot connect and subscribe within STARTUP_TIMEOUT_MS.
 * The caller is responsible for treating this as a fatal startup condition.
 *
 * Idempotent: subsequent calls are no-ops if already successfully started.
 *
 * @throws {Error} on connection failure or startup timeout
 */
async function start() {
  if (_started) return;

  const connectPromise = (async () => {
    _client = _buildClient();
    await _client.connect();
    await _client.subscribe(CHANNEL, _handleMessage);
    _started = true;

    // node-redis's Sentinel client already restores pub/sub
    // subscriptions across a master failover via its own internal
    // PubSubProxy (see src/infra/redis/managedClient.js's header). This is a
    // belt-and-suspenders measure on top of that: re-issuing subscribe() is
    // an idempotent no-op against an already-subscribed channel, so doing it
    // again here costs nothing and gives an explicit, observable guarantee
    // (metric + structured log) that this control-plane-critical
    // subscription survived every observed master change, rather than
    // silently trusting the client library. A no-op in single-instance mode
    // (a plain RedisClientType never emits 'topology-change').
    _client.on('topology-change', async (ev) => {
      if (ev?.type !== 'MASTER_CHANGE') return;
      try {
        await _client.subscribe(CHANNEL, _handleMessage);
        emit('INFO', 'REVOCATION_SUBSCRIBER_SUBSCRIPTION_RESTORED', { channel: CHANNEL });
        require('../../../observability/metrics').redisSubscriptionRecoveryTotal.inc({ purpose: 'revocationSubscriber' });
      } catch (err) {
        emit('WARN', 'REVOCATION_SUBSCRIBER_RESUBSCRIBE_FAILED', { channel: CHANNEL, error: err.message });
      }
    });
  })();

  try {
    await raceTimeout(connectPromise, STARTUP_TIMEOUT_MS, // the startup timer no longer outlives a successful start
      () => new Error(`REVOCATION_SUBSCRIBER_STARTUP_TIMEOUT after ${STARTUP_TIMEOUT_MS}ms`));
    emit('INFO', 'REVOCATION_SUBSCRIBER_STARTED', { channel: CHANNEL });
  } catch (err) {
    // Clean up partially-initialized client so start() can be retried if needed.
    _started = false;
    _ready   = false;
    if (_client) {
      try { await _client.disconnect(); } catch { /* ignore */ }
      _client = null;
    }
    throw err;
  }
}

/**
 * Stop the subscriber and disconnect the Redis client.
 * Used during graceful shutdown.
 */
async function stop() {
  // RD-3: disconnect() ALWAYS runs. Previously both calls shared one try, so an unsubscribe()
  // that failed during a Redis outage skipped disconnect(): the managed client kept its self-healing reconnect loop and
  // timers alive after shutdown (a leaked, recovering orphan client). State is cleared first so a late 'ready' from that
  // client is ignored.
  const c = _client;
  _client = null; _ready = false; _started = false;
  if (!c) return;
  try { await c.unsubscribe(CHANNEL); } catch { /* not ready during an outage */ }
  try { await c.disconnect(); } catch { /* already closed */ }
}

/**
 * Returns true when the subscriber is connected to Redis and actively
 * receiving revocation events.
 *
 * ConsentVerifier calls this on every verification request.  A false return
 * immediately causes consent to be denied (CONSENT_REVOCATION_SYNC_UNAVAILABLE).
 */
function isReady()   { return _ready; }

/**
 * Returns true once start() has successfully completed at least once.
 * ConsentVerifier uses both isStarted() and isReady() to distinguish
 * "not yet initialized" (safe during server startup) from "initialized but
 * disconnected" (fail-closed enforcement active).
 */
function isStarted() { return _started; }

module.exports = { start, stop, isReady, isStarted };
