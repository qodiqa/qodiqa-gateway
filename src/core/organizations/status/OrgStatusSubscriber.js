'use strict';

/**
 * OrgStatusSubscriber — Redis pub/sub subscriber + bounded reconciliation
 * sweep for organization-suspension propagation.
 *
 * This is a REQUIRED control-plane dependency, exactly like
 * src/core/consent/revocation/RevocationSubscriber.js. A worker that is not
 * subscribed cannot receive instant status-change notifications and cannot
 * guarantee the documented propagation bound.
 *
 * ── Consistency model ─────────────────────────────────────────────────────
 *
 *   1. INSTANT PATH (steady state): every status change is pushed to every
 *      subscribed worker via Redis pub/sub. Typical propagation latency is
 *      the Redis publish→receive round trip (single-digit to low tens of
 *      ms) — see qodiqa_org_status_propagation_latency_ms.
 *
 *   2. BOUNDED FALLBACK (belt-and-suspenders): every SWEEP_PERIOD_MS (half of
 * RECONCILE_INTERVAL_MS, default 5000ms, see ORG_STATUS_RECONCILE_INTERVAL_MS), this worker
 *      re-reads the FULL authoritative status snapshot from Redis
 *      (OrgStatusStore.getAllStatuses — a single HGETALL) and applies it.
 *      This bounds the maximum staleness of ANY missed/dropped pub/sub
 *      message to RECONCILE_INTERVAL_MS, without per-request polling and
 *      without touching PostgreSQL.
 *
 *   3. FAIL-CLOSED (no undefined propagation period): organizationRegistry's
 *      assertActiveOrganization() checks isReady() before trusting any
 *      cached status. The instant this worker's subscriber is started but
 *      not connected (Redis down, mid-reconnect, etc.), every org-scoped
 *      request is denied — there is no interval, however short, during
 *      which a worker can silently keep serving on unconfirmed state.
 *      Combined with (1)+(2), the documented guarantee is:
 *
 *        "A suspension is enforced on every healthy, connected worker within
 *         RECONCILE_INTERVAL_MS (typically far sooner, via instant push). A
 *         worker that cannot confirm current status denies immediately —
 *         there is no window in which staleness silently exceeds the bound."
 *
 *   4. RACE HANDLING: OrgStatusEvent.updatedAt is a monotonic epoch-ms
 *      timestamp. organizationRegistry._applyRemoteStatus() ignores any
 *      incoming update whose updatedAt is not strictly newer than the
 *      currently-applied one — an out-of-order pub/sub delivery or a
 *      reconciliation sweep racing a fresher push can never regress state.
 *
 *   5. WORKER RESTART: start() performs a full reconciliation sweep BEFORE
 *      resolving. Any organization present locally (from data/organizations
 *      .json) but absent from Redis is treated as this worker "founding"
 *      the authoritative record — its current local status is written
 *      through to Redis so every other worker converges on the same value.
 *      Like RevocationSubscriber, start() THROWS on connect/subscribe/
 *      reconciliation failure; the caller (server.js) treats this as FATAL.
 *
 * ── Dependency inversion (Finding 64 /) ────────────────────────────────
 *
 * This module used to require('../organizationRegistry') back, forming a
 * circular dependency with organizationRegistry.js's own lazy require of
 * this module. That cycle is now broken: organizationRegistry is never
 * require()'d here. The composition root (server.js) injects it via
 * setOrganizationRegistry() below (mirrors setKeyInfoResolver() in
 * src/infra/postgres/pg-audit-backend.js) after both modules are loaded.
 * Unlike organizationRegistry's optional, soft dependency on this module,
 * organizationRegistry is a REQUIRED dependency of this module — every
 * operational codepath (_handleMessage, _reconcile) needs it, so start()
 * fails fast with a clear error if it was never injected, rather than
 * surfacing an obscure TypeError deep inside message handling.
 */

const { isAuthError, isTlsError } = require('../../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../../infra/redis/managedClient');
const { createInfiniteReconnectStrategy } = require('../../../infra/redis/reconnectStrategy');
const _orgStatusClock = require('./orgStatusClock'); // monotonic freshness stamps
const { emit }   = require('../../../../services/logger');
const { CHANNEL, parseEvent } = require('./OrgStatusEvent');
const store      = require('./OrgStatusStore');
const { raceTimeout } = require('../../../utils/raceTimeout');
const metrics    = require('./OrgStatusMetrics');

const CONNECT_TIMEOUT_MS     = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS                     || '5000',  10);
const STARTUP_TIMEOUT_MS     = parseInt(process.env.ORG_STATUS_SUBSCRIBER_STARTUP_TIMEOUT_MS      || '10000', 10);
// no longer a hard cap — same shared-module convergence as
// RevocationSubscriber.js; see that file's own comment for the full
// rationale (identical defect, identical fix). Kept as OLD_MAX_RECONNECTS
// so `pastOldThreshold` telemetry still marks the old give-up point.
const OLD_MAX_RECONNECTS     = parseInt(process.env.ORG_STATUS_SUBSCRIBER_MAX_RECONNECTS           || '10',    10);
const RECONCILE_INTERVAL_MS  = parseInt(process.env.ORG_STATUS_RECONCILE_INTERVAL_MS               || '5000',  10);

// Documented, measurable upper bound on propagation delay while this
// worker's subscriber is healthy. organizationRegistry.js reads this same
// value to decide when locally-cached status is too stale to trust.
const MAX_PROPAGATION_WINDOW_MS = RECONCILE_INTERVAL_MS;

// the periodic sweep runs at HALF the staleness bound. Before this, the sweep period
// EQUALLED the bound, and a sweep refreshes a worker's syncedAt only after its Redis read completes — so on
// every tick, for (timer lateness + Redis round trip), a healthy, connected worker judged its own status
// stale and denied every org-assigned tenant ORG_STATUS_STALE.
// The bound itself is unchanged (a worker that cannot re-confirm within MAX_PROPAGATION_WINDOW_MS still
// denies); a healthy worker now re-confirms at least twice per bound, so a tick has half the bound as margin.
const SWEEP_PERIOD_MS = Math.max(1, Math.floor(MAX_PROPAGATION_WINDOW_MS / 2));

// grace beyond MAX_PROPAGATION_WINDOW_MS, applied ONLY while the pub/sub subscription has been
// continuously connected since the last confirmation AND no reconcile sweep has failed since — i.e. only when a
// sweep is merely LATE (event-loop saturation delaying its timer). On a live subscription every status change is
// delivered instantly by push, so the cached status is current; the sweep is the fallback for messages missed
// across a DISCONNECT, and any disconnect (connectedSince moves) or failed sweep removes the grace, restoring the
// strict bound. Default = one bound. QODIQA_ORG_STATUS_GRACE_MS (0 disables).
const GRACE_MS = (() => { const v = parseInt(process.env.QODIQA_ORG_STATUS_GRACE_MS, 10); return Number.isFinite(v) && v >= 0 ? v : MAX_PROPAGATION_WINDOW_MS; })();

const DEDUP_MAX_SIZE = 10_000;
const _seenEventIds  = new Set();

let _client        = null;
let _ready         = false;
// inputs to the org-status grace in organizationRegistry.assertActiveOrganization().
let _connectedSince     = 0; // epoch ms of the latest 'ready' (0 = not connected)
let _lastSweepFailureAt = 0; // epoch ms of the latest reconcile sweep that could not read Redis (or threw)
let _started       = false;
let _sweepTimer    = null;

function _deduplicate(eventId) {
  if (_seenEventIds.has(eventId)) return true;
  _seenEventIds.add(eventId);
  if (_seenEventIds.size > DEDUP_MAX_SIZE) {
    _seenEventIds.delete(_seenEventIds.values().next().value);
  }
  return false;
}

// Injected by the composition root (server.js) via setOrganizationRegistry(),
// AFTER both this module and organizationRegistry have been require()'d —
// replaces the former lazy require() cycle.
let _organizationRegistry = null;

/**
 * Inject the organizationRegistry instance used to apply status updates
 * (_applyRemoteStatus/_touchStatusFreshness) and list local organizations
 * during reconciliation. Called once, at startup, by the composition root.
 *
 * @param {object} instance
 */
function setOrganizationRegistry(instance) {
  _organizationRegistry = instance;
}

/**
 * Returns the injected organizationRegistry, or throws a clear, deterministic
 * error if setOrganizationRegistry() was never called. organizationRegistry
 * is a mandatory dependency of this module — there is no valid "not wired"
 * fallback the way there is on the other side of this relationship.
 */
function _requireRegistry() {
  if (!_organizationRegistry) {
    throw new Error(
      'ORG_STATUS_SUBSCRIBER_REGISTRY_NOT_INJECTED: setOrganizationRegistry() must be called ' +
      '(by the composition root) before start()'
    );
  }
  return _organizationRegistry;
}

// converges onto the same shared infinite-retry module already
// proved on nonceStore.js/anomalyStore.js/rateLimit/storage.js/
// idempotencyStore.js, and this same fix now also applies to
// RevocationSubscriber.js — see that file's own comment for the full
// rationale. Changes ONLY the give-up policy: `client.on('reconnecting'|
// 'error', ...)` below are untouched, so isReady() still flips false
// immediately on disconnect and stays false for the entire outage.
const _reconnectStrategy = createInfiniteReconnectStrategy({
  source:           'ORG_STATUS_SUBSCRIBER',
  oldMaxReconnects: OLD_MAX_RECONNECTS,
  onRetry: ({ retries, delayMs, pastOldThreshold }) => {
    emit('WARN', 'ORG_STATUS_SUBSCRIBER_RECONNECT_ATTEMPT', { retries, delayMs, pastOldThreshold });
  },
});

function _buildClient() {
  const client = createManagedRedisClient({
    purpose:           'orgStatusSubscriber',
    connectTimeout:    CONNECT_TIMEOUT_MS,
    reconnectStrategy: _reconnectStrategy,
  });

  client.on('ready', ({ isReconnect } = {}) => {
    if (_client !== client) return; // RD-3: a late 'ready' from a client stop() already released is ignored
    _ready = true;
    _connectedSince = _orgStatusClock.now(); // step 8; monotonic (compared with syncedAt in this process)
    emit('INFO', 'ORG_STATUS_SUBSCRIBER_READY', {});

    if (isReconnect) {
      _client.subscribe(CHANNEL, _handleMessage)
        .then(() => {
          emit('INFO', 'ORG_STATUS_SUBSCRIBER_SUBSCRIPTION_RESTORED', { channel: CHANNEL });
        })
        .catch((err) => {
          emit('WARN', 'ORG_STATUS_SUBSCRIBER_RESUBSCRIBE_FAILED', { channel: CHANNEL, error: err.message });
        });
      // A reconnect means an unknown number of status-change messages may
      // have been missed while disconnected. Reconcile immediately rather
      // than waiting for the next scheduled sweep — this is what keeps the
      // documented bound (RECONCILE_INTERVAL_MS) true even across outages,
      // instead of "up to RECONCILE_INTERVAL_MS after the NEXT tick".
      _reconcile('reconnect').catch(() => {});
    }
  });

  client.on('error', (err) => {
    _ready = false;
    metrics.subscriberReconnects.inc({ type: 'subscriber' });
    if (isAuthError(err))     emit('ERROR', 'ORG_STATUS_SUBSCRIBER_AUTH_ERROR', { error: err.message });
    else if (isTlsError(err)) emit('ERROR', 'ORG_STATUS_SUBSCRIBER_TLS_ERROR', { error: err.message });
    else                      emit('WARN',  'ORG_STATUS_SUBSCRIBER_ERROR',      { error: err.message });
  });

  client.on('reconnecting', () => {
    _ready = false;
    emit('WARN', 'ORG_STATUS_SUBSCRIBER_RECONNECTING', {
      message: 'Org-status subscriber reconnecting — org-scoped requests are fail-closed until reconnected.',
    });
  });

  return client;
}

async function _handleMessage(rawMessage) {
  const parsed = parseEvent(rawMessage);
  if (!parsed.ok) {
    emit('WARN', 'ORG_STATUS_EVENT_INVALID', { reason: parsed.reason, preview: rawMessage.slice(0, 200) });
    metrics.received.inc({ result: 'invalid' });
    return;
  }

  const { event } = parsed;

  if (_deduplicate(event.eventId)) {
    metrics.received.inc({ result: 'duplicate' });
    return;
  }

  const applied = _requireRegistry()._applyRemoteStatus(event.organizationId, event.status, event.updatedAt);
  const latencyMs = Date.now() - event.updatedAt;
  metrics.propagationLatency.observe(Math.max(0, latencyMs));
  metrics.statusApplied.inc({ source: applied ? 'pubsub' : 'pubsub_stale_ignored' });
  metrics.received.inc({ result: 'ok' });

  emit('INFO', 'ORG_STATUS_EVENT_PROCESSED', {
    eventId: event.eventId, organizationId: event.organizationId, status: event.status, applied, latencyMs,
  });
}

/**
 * Full reconciliation sweep: read every organization's authoritative status
 * from Redis and apply it locally. Any local org absent from Redis is
 * bootstrapped (this worker's local status becomes the seed authoritative
 * value). Used at startup, on every reconnect, and on a fixed interval.
 *
 * @param {string} trigger — 'startup' | 'reconnect' | 'interval', for metrics/logs
 * @returns {Promise<boolean>} true if the sweep completed against Redis
 */
async function _reconcile(trigger) {
  const registry = _requireRegistry();
  const remoteMap = await store.getAllStatuses();

  if (remoteMap === null) {
    _lastSweepFailureAt = _orgStatusClock.now(); // step 8; monotonic: a failed sweep disables the grace until the next success
    metrics.reconcileSweeps.inc({ result: 'redis_unavailable' });
    emit('WARN', 'ORG_STATUS_RECONCILE_FAILED', { trigger, reason: 'REDIS_UNAVAILABLE' });
    return false;
  }

  const localOrgs = registry.listOrganizations();
  for (const org of localOrgs) {
    const remote = remoteMap.get(org.organizationId);
    if (remote) {
      registry._applyRemoteStatus(org.organizationId, remote.status, remote.updatedAt);
    } else {
      // Not yet tracked in Redis — this worker seeds the authoritative
      // record from its own current local status so the cluster converges.
      const seededAt = Date.now();
      await store.setStatus(org.organizationId, org.status, seededAt);
      registry._touchStatusFreshness(org.organizationId, seededAt);
    }
  }

  metrics.reconcileSweeps.inc({ result: 'ok' });
  emit('INFO', 'ORG_STATUS_RECONCILE_COMPLETED', { trigger, organizationCount: localOrgs.length });
  return true;
}

function _scheduleSweep() {
  if (_sweepTimer) return;
  _sweepTimer = setInterval(() => {
    _reconcile('interval').catch((err) => {
      _lastSweepFailureAt = _orgStatusClock.now(); // step 8; monotonic
      emit('WARN', 'ORG_STATUS_RECONCILE_ERROR', { error: err.message });
    });
  }, SWEEP_PERIOD_MS);
  // Never keeps the process alive on its own.
  _sweepTimer.unref?.();
}

/**
 * Start the org-status subscriber: connect, subscribe, and perform an
 * initial full reconciliation sweep — all BEFORE resolving. THROWS on any
 * failure; the caller must treat this as fatal (mirrors RevocationSubscriber
 * exactly — see server.js).
 *
 * Idempotent: subsequent calls are no-ops once started.
 */
async function start() {
  if (_started) return;

  // Fail fast, before touching Redis, if the composition root never wired
  // organizationRegistry in — deterministic error instead of an obscure
  // TypeError the first time _handleMessage/_reconcile needs it.
  _requireRegistry();

  const startPromise = (async () => {
    _client = _buildClient();
    await _client.connect();
    await _client.subscribe(CHANNEL, _handleMessage);

    const reconciled = await _reconcile('startup');
    if (!reconciled) {
      throw new Error('ORG_STATUS_SUBSCRIBER_INITIAL_RECONCILE_FAILED');
    }

    _started = true;
    _scheduleSweep();

    _client.on('topology-change', async (ev) => {
      if (ev?.type !== 'MASTER_CHANGE') return;
      try {
        await _client.subscribe(CHANNEL, _handleMessage);
        emit('INFO', 'ORG_STATUS_SUBSCRIBER_SUBSCRIPTION_RESTORED', { channel: CHANNEL });
        await _reconcile('topology-change');
      } catch (err) {
        emit('WARN', 'ORG_STATUS_SUBSCRIBER_RESUBSCRIBE_FAILED', { channel: CHANNEL, error: err.message });
      }
    });
  })();

  try {
    await raceTimeout(startPromise, STARTUP_TIMEOUT_MS, // the startup timer no longer outlives a successful start
      () => new Error(`ORG_STATUS_SUBSCRIBER_STARTUP_TIMEOUT after ${STARTUP_TIMEOUT_MS}ms`));
    emit('INFO', 'ORG_STATUS_SUBSCRIBER_STARTED', { channel: CHANNEL, reconcileIntervalMs: RECONCILE_INTERVAL_MS, sweepPeriodMs: SWEEP_PERIOD_MS });
  } catch (err) {
    _started = false;
    _ready   = false;
    if (_sweepTimer) { clearInterval(_sweepTimer); _sweepTimer = null; }
    if (_client) {
      try { await _client.disconnect(); } catch { /* ignore */ }
      _client = null;
    }
    throw err;
  }
}

/**
 * Stop the subscriber, clear the reconciliation timer, and disconnect.
 */
async function stop() {
  if (_sweepTimer) { clearInterval(_sweepTimer); _sweepTimer = null; }
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
 * True when connected and actively receiving status-change events.
 * organizationRegistry.assertActiveOrganization() checks this on every
 * org-scoped verification; false immediately causes fail-closed denial.
 */
function isReady()   { return _ready; }

/**
 * True once start() has successfully completed at least once. Distinguishes
 * "never initialized" (safe during tests / minimal deployments that don't
 * wire this subscriber up — preserves 100% backward compatibility with the
 * pre-COMP-8 in-memory-only behavior) from "initialized then disconnected"
 * (fail-closed enforcement active).
 */
function isStarted() { return _started; }

/**
 * what the registry's grace needs — when this worker's subscription became (and has since
 * stayed) connected, and when a sweep last failed. See organizationRegistry.assertActiveOrganization().
 */
function graceState() { return { connectedSince: _ready ? _connectedSince : 0, lastSweepFailureAt: _lastSweepFailureAt, graceMs: GRACE_MS }; }

module.exports = {
  start, stop, isReady, isStarted, graceState,
  setOrganizationRegistry,
  MAX_PROPAGATION_WINDOW_MS,
  RECONCILE_INTERVAL_MS,
  SWEEP_PERIOD_MS,
  GRACE_MS,
  // Exported for tests only.
  _reconcile,
};
