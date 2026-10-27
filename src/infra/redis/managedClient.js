'use strict';

/**
 * Unified, HA-aware Redis client factory — (Phases 2-7).
 *
 * ROOT CAUSE: every one of
 * QODIQA's Redis-backed control planes (replay/nonce protection, anomaly
 * detection, rate limiting ×2, consent cache, consent revocation pub/sub,
 * key-rotation locking, persistence recovery queue) independently constructed
 * its own `createClient(buildClientOptions(...))` against a single
 * `REDIS_URL`. Sentinel/Cluster support was documented but never
 * implemented — every store would retry the *same* dead target and
 * eventually give up permanently (`reconnectStrategy` returning `false`),
 * requiring a manual process restart to recover from a permanent Redis
 * outage, let alone a planned failover.
 *
 * THIS MODULE is the single consolidated abstraction all 9
 * production Redis consumers now construct their client through. It resolves
 * exactly one thing — the deployment mode — from configuration alone
 * (haConfig.js's REDIS_MODE), and returns an object with the IDENTICAL
 * surface every consumer already coded against: `.isReady`, `.isOpen`,
 * `.connect()`, `.disconnect()`/`.quit()`, `.on('connect'|'ready'|'error'|
 * 'end'|'reconnecting', cb)`, and passthrough Redis commands (`.get`, `.set`,
 * `.eval`, `.multi`, `.subscribe`, `.publish`, ...).
 *
 * BACKWARD COMPATIBILITY (the load-bearing guarantee):
 *   REDIS_MODE defaults to 'single'. In that mode this factory constructs the
 *   client exactly as every consumer's own `_getClient()`/`_buildClient()`
 * did before `require('redis').createClient(buildClientOptions(...))`
 *   with the consumer's own `reconnectStrategy`/`connectTimeout` passed
 *   straight through unchanged — and every event a consumer already listens
 *   for (`connect`/`ready`/`error`/`reconnecting`/`end`) still fires with the
 *   same meaning. Every existing unit test that `jest.mock('redis', ...)`s
 *   the `createClient` export continues to intercept the exact same call,
 *   with the exact same arguments, exactly as before.
 *
 *   As of Finding 49 the RETURNED OBJECT is a stable self-healing Proxy
 *   rather than that bare client — see "SINGLE MODE SELF-HEALING" below for
 *   why that is now required. Every method/property a consumer already used
 *   (`.isReady`, `.isOpen`, `.connect()`, `.disconnect()`/`.quit()`, `.on(...)`,
 *   passthrough commands) resolves identically through the Proxy; only literal
 *   `===` identity against the raw `createClient()` return value no longer
 *   holds, because a dead client can no longer be all a consumer ever has.
 *
 * SINGLE MODE SELF-HEALING (Finding 49):
 *   Prior to this remediation, 'single' mode returned the bare object
 *   `createClient()` produced. Every consumer's own bounded `reconnectStrategy`
 *   (e.g. nonceStore's 5-attempt exponential backoff) eventually returns
 *   `false`, node-redis emits a terminal `end`, and — because nothing ever
 *   recreated the client — the store stayed permanently degraded until the
 *   process was restarted, even if Redis came back seconds later.
 *
 *   'single' mode now returns a stable Proxy (`_wrapRecoverableClient`) over a
 *   MUTABLE underlying client reference, exactly mirroring the sentinel/
 *   cluster Proxy pattern below. On terminal `end` the supervisor:
 *     1. tears down the dead client (removes all listeners, closes the socket
 *        if still open) — no leaked sockets, timers, or listeners survive a
 *        recovery cycle;
 *     2. waits on an unbounded exponential-backoff-with-jitter timer (reusing
 *        the existing REDIS_RECONNECT_* / REDIS_CIRCUIT_BREAKER_COOLDOWN_MS
 *        config — same defaults, now also governing the OUTER recovery loop,
 *        not just the per-node HA strategy below);
 *     3. constructs a completely FRESH client via the consumer's original
 *        `reconnectStrategy`/`connectTimeout` and calls `.connect()`;
 *     4. on `ready`, issues a PING before declaring the store HEALTHY again
 *        (never trusts "TCP connected" or even "AUTH complete" alone);
 *     5. on failure, goes back to step 1 — forever. There is no terminal
 *        failure state and no attempt ceiling.
 *   Every consumer keeps its exact existing `.on('ready'|'error'|'end'|
 *   'reconnecting', ...)` wiring, `.isReady` fail-closed check, and command
 *   surface (`.get`, `.set`, `.eval`, `.subscribe`, ...) — those all resolve
 *   through to whichever client is CURRENTLY live, so no consumer file needed
 *   to change to get self-healing. `.isReady` stays false for the entire
 *   RECOVERING window, so fail-closed enforcement is never weakened.
 *
 * HA MODES (REDIS_MODE=sentinel | cluster):
 *   Uses node-redis v5's own, already-implemented, already-tested
 * `createSentinel()` / `createCluster()` — deliberately does NOT
 *   hand-roll Sentinel-protocol or cluster-slot logic; that would be
 *   reinventing exactly the kind of subtle distributed-systems code a
 * maintained client library already gets right. What adds on top is
 *   the missing piece: normalizing that richer object back onto the plain
 *   RedisClientType event/method contract every consumer already
 *   understands, via `_wrapHaClient()`'s Proxy + ConnectionFacade below, plus
 *   the health/metrics/logging every phase of the remediation asks for.
 *
 *   In these modes:
 *     - Master discovery, replica tracking, and failover-driven reconnection
 *       to the newly promoted master are handled internally by node-redis's
 *       Sentinel/Cluster client — no application restart is ever required.
 *     - `topology-change` events (Sentinel: MASTER_CHANGE / SENTINEL_CHANGE /
 *       REPLICA_ADD / REPLICA_REMOVE / SENTINE_LIST_CHANGE) drive this
 *       module's health state machine, failover counter, and structured
 *       logs — see ConnectionFacade below.
 *     - Pub/sub subscriptions survive failover via node-redis's own
 *       PubSubProxy (Sentinel) / `resubscribeAllPubSubListeners()`
 *       (Cluster); RevocationSubscriber.js additionally re-issues its own
 *       `.subscribe()` call on every observed topology change as a
 *       belt-and-suspenders measure (idempotent — re-subscribing an already-
 *       subscribed channel is a safe no-op) and emits
 *       `REDIS_HA_SUBSCRIPTION_RESTORED` so operators can see it happened.
 *
 * PER-CONSUMER READ ROUTING OVERRIDE:
 *   In sentinel mode with REDIS_SENTINEL_USE_REPLICAS=true, node-redis routes
 *   every command it classifies as read-only (GET, SCAN, ...) to a replica,
 *   round-robin — see @redis/client's `RedisSentinel#_execute(isReadonly, fn)`
 *   and `sentinel/utils.js`'s `createCommand()`, which reads that flag off
 *   the command's own static definition (`GET.IS_READ_ONLY === true`),
 *   globally, with no per-call override on the plain command surface.
 *   Master→replica replication is asynchronous and unbounded — a consumer
 *   for which a GET immediately following its own committed write must never
 *   observe stale data (e.g. ConsentCache, whose `invalidate()`/`set()` CAS
 *   writes always target master because EVAL/DEL are not read-only) cannot
 *   rely on replica reads at all, regardless of how small the usual lag is.
 *   `forceMasterReads: true` overrides `haConfig.sentinel.useReplicas` for
 *   THIS client only, forcing `replicaPoolSize` to 0 so every command —
 *   read or write — targets master. This is deliberately per-consumer, not
 *   global: consumers that tolerate eventual consistency (rate limiting,
 *   anomaly detection, ...) keep distributing reads across replicas exactly
 *   as configured, so this fix trades zero throughput for any Redis consumer
 *   that doesn't need the stronger guarantee.
 */

const { EventEmitter } = require('events');
const redisPkg         = require('redis');
const { buildClientOptions } = require('./clientConfig');
const { resolveHaConfig }    = require('./haConfig');
const { createBoundedReconnectStrategy } = require('./reconnectStrategy');
const { resolveDeadlineConfig, withDeadline, isCommandMember } = require('./commandDeadline');
const healthRegistry = require('./health');
const { emit } = require('../../../services/logger');
const { monoNowMs } = require('../time/monotonicClock'); // monotonic (same-process) deadlines/windows

const HEALTH_STATE = Object.freeze({
  HEALTHY:      'HEALTHY',
  DEGRADED:     'DEGRADED',
  DISCONNECTED: 'DISCONNECTED',
  RECOVERING:   'RECOVERING',
});

function _metrics() {
  // Lazy require: keeps this module cheap to load in isolation (tests) and
  // avoids any import-order coupling with observability/metrics.js.
  return require('../../observability/metrics');
}

// qodiqa_redis_connection_state_code values (the gauge's HELP text in metrics.js).
const STATE_CODE = Object.freeze({ DISCONNECTED: 0, DEGRADED: 1, RECOVERING: 2, HEALTHY: 3 });

// phase 11 (RD-2): announcements made from this module's own ASYNC paths (the post-PING 'ready', the
// verification-failure 'error', the terminal 'end' reached from the stall watchdog) run consumer listeners inside an
// async function, so a listener that throws became an unhandled rejection, which processHardening.js treats as fatal
// (exit 1): one buggy consumer handler turned a routine Redis reconnect into a gateway crash. Measured with the real
// RevocationSubscriber, whose 'ready' handler throws after stop() (test/redisResilience RR-05). The listener's
// exception is now contained and logged; the other listeners and the state machine are unaffected.
function _announce(facade, event, payload) {
  try {
    if (payload === undefined) facade.emit(event); else facade.emit(event, payload);
  } catch (err) {
    emit('ERROR', 'REDIS_CLIENT_LISTENER_FAILED', {
      purpose: facade.purpose, mode: facade.mode, event, error: err && err.message,
      message: 'A consumer listener threw while the managed Redis client announced a state change; contained (a throw here used to crash the process).',
    });
  }
}

function _pollUntilReady(getIsReady, { timeoutMs = 10_000, intervalMs = 100 } = {}) {
  return new Promise((resolve) => {
    const start = monoNowMs(); // monotonic (same-process)
    (function tick() {
      if (getIsReady()) return resolve(true);
      if (monoNowMs() - start >= timeoutMs) return resolve(false);
      // .unref() so this background recovery poll can never keep the
      // process (or a test worker) alive on its own — it is a best-effort
      // observability/health-state poll, not something graceful shutdown
      // should have to wait out.
      setTimeout(tick, intervalMs).unref?.();
    })();
  });
}

// ── Connection health facade ──────────────────────────────────────────────────
//
// One instance per managed client. Consumers `.on(...)` against THIS object
// (via the Proxy below) rather than the raw Sentinel/Cluster instance, so
// they see the same 'connect'/'ready'/'error'/'end'/'reconnecting' vocabulary
// a plain RedisClientType emits, regardless of which mode is actually active
// underneath.

class ConnectionFacade extends EventEmitter {
  constructor({ purpose, mode }) {
    super();
    this.setMaxListeners(50);
    this.purpose         = purpose;
    this.mode            = mode;
    this._state          = null;
    this.state           = HEALTH_STATE.DISCONNECTED;
    this.master           = null;
    this.replicas         = [];
    this.reconnectCount   = 0;
    this.failoverCount    = 0;
    this.lastReconnectAt  = null;
    this.lastFailoverAt   = null;
    this.readySince       = null;
    this.latencyMs        = null;
    this._degradedSince   = null;
    this._closing         = false;

    // EventEmitter throws synchronously if 'error' is emitted with zero
    // listeners attached. Every real consumer attaches its own `.on('error',
    // ...)` immediately after construction, before any I/O — but internal
    // wiring (_wire()/_wireSentinelEvents()) runs BEFORE that attachment, so
    // a client that reports an error during that narrow window (a
    // synchronously-firing test double, in practice) would otherwise crash
    // the process instead of just being logged. This module's structured
    // `emit('WARN'|'ERROR', ...)` calls at each error call site are already
    // the authoritative record; this permanent no-op listener only prevents
    // the EventEmitter special-case from turning a reported error into an
    // unrelated crash. A consumer's own `.on('error', ...)` still fires
    // normally alongside it.
    this.on('error', () => {});
  }

  // every state transition (all modes, every call site — initial DISCONNECTED, DEGRADED on
  // error / deadline miss, RECOVERING on terminal end / stall / master switch, HEALTHY on verified ready) goes through
  // this setter, so qodiqa_redis_connection_state_code can no longer read HEALTHY while the client is degraded.
  get state() { return this._state; }
  set state(next) {
    this._state = next;
    try { _metrics().redisConnectionStateCode.set({ purpose: this.purpose }, STATE_CODE[next] ?? 0); } catch { /* metrics are best-effort */ }
  }

  health() {
    return {
      purpose:                 this.purpose,
      mode:                    this.mode,
      state:                   this.state,
      master:                  this.master,
      replicas:                this.replicas,
      reconnectCount:          this.reconnectCount,
      failoverCount:           this.failoverCount,
      lastReconnectAt:         this.lastReconnectAt,
      lastFailoverAt:          this.lastFailoverAt,
      connectionUptimeSeconds: this.readySince ? Math.floor((Date.now() - this.readySince) / 1000) : 0,
      latencyMs:               this.latencyMs,
    };
  }
}

// ── Proxy adapter ──────────────────────────────────────────────────────────────
//
// IMPORTANT: the underlying RedisSentinel/RedisCluster instances use ES
// private (`#field`) class members internally. A Proxy `get` trap that
// returns `Reflect.get(target, prop, receiver)` would invoke those methods
// with `this === receiver` (the Proxy) instead of the real instance, which
// throws ("cannot read private member from an object whose class did not
// declare it") the moment any such method runs. Every function property
// returned below is therefore explicitly `.bind(target)`ed so `this` is
// always the real underlying object — never the Proxy.

function _wrapHaClient(target, facade) {
  return new Proxy(target, {
    get(t, prop, _receiver) {
      if (prop === 'on' || prop === 'once' || prop === 'off' || prop === 'removeListener' || prop === 'emit') {
        return facade[prop].bind(facade);
      }
      if (prop === 'health') return () => facade.health();
      if (prop === '__facade') return facade;
      if (prop === 'isReady') return t.isReady;
      if (prop === 'isOpen') return t.isOpen;
      if (prop === 'connect') {
        return async () => {
          facade.emit('connect');
          await t.connect();
          facade.state     = HEALTH_STATE.HEALTHY;
          facade.readySince = Date.now();
          if (typeof t.getMasterNode === 'function') facade.master = t.getMasterNode() ?? null;
          if (typeof t.getReplicaNodes === 'function') facade.replicas = Array.from(t.getReplicaNodes().keys());
          emit('INFO', 'REDIS_HA_SENTINEL_DISCOVERY', {
            purpose: facade.purpose, mode: facade.mode, master: facade.master, replicas: facade.replicas,
          });
          facade.emit('ready', { isReconnect: false });
          return t;
        };
      }
      if (prop === 'disconnect' || prop === 'quit') {
        return async () => {
          facade._closing = true;
          if (typeof t.close === 'function')      return t.close();
          if (typeof t.destroy === 'function')     return t.destroy();
          if (typeof t.quit === 'function')        return t.quit();
          if (typeof t.disconnect === 'function')  return t.disconnect();
        };
      }
      const value = t[prop];
      if (typeof value !== 'function') return value;
      // commands fail closed after the deadline instead of hanging on a stalled node.
      // (Sentinel/Cluster failover is node-redis's own; no stall teardown here.)
      const dl = _haDeadline();
      if (dl.deadlineMs > 0 && isCommandMember(prop)) {
        return (...args) => {
          const r = value.apply(t, args);
          return r && typeof r.then === 'function' ? withDeadline(r, dl.deadlineMs, { command: String(prop) }) : r;
        };
      }
      return value.bind(t);
    },
  });
}
let _haDeadlineCfg = null;
function _haDeadline() { return _haDeadlineCfg || (_haDeadlineCfg = resolveDeadlineConfig()); }

function _wireSentinelEvents(underlying, facade) {
  const metrics = _metrics();

  underlying.on('error', (err) => {
    metrics.redisCommandFailuresTotal.inc({ purpose: facade.purpose });
    facade.emit('error', err);
    if (facade.state === HEALTH_STATE.HEALTHY) {
      facade._degradedSince = Date.now();
      facade.state = HEALTH_STATE.DEGRADED;
      emit('WARN', 'REDIS_HA_CONNECTION_LOST', { purpose: facade.purpose, mode: facade.mode, error: err.message });
    }
  });

  underlying.on('client-error', (ev) => {
    metrics.redisCommandFailuresTotal.inc({ purpose: facade.purpose });
    facade.emit('error', ev.error ?? new Error(String(ev)));
  });

  underlying.on('topology-change', (ev) => {
    facade.emit('topology-change', ev);

    if (ev.type === 'MASTER_CHANGE') {
      const recoveryStart = facade._degradedSince ?? Date.now();
      facade.failoverCount++;
      facade.lastFailoverAt = Date.now();
      facade.master         = ev.node;
      facade.state           = HEALTH_STATE.RECOVERING;
      facade.reconnectCount++;
      metrics.redisFailoverTotal.inc({ purpose: facade.purpose });
      metrics.redisReconnectTotal.inc({ purpose: facade.purpose, mode: facade.mode });
      emit('WARN', 'REDIS_HA_MASTER_SWITCH', {
        purpose: facade.purpose, mode: facade.mode, newMaster: ev.node, failoverCount: facade.failoverCount,
      });
      facade.emit('reconnecting');

      // Finding 3.6: this .then() had no trailing .catch() — if the
      // callback body threw (e.g. a metrics/emit call), the rejection had
      // nothing downstream to catch it and would surface as an unhandled
      // rejection. This event-driven notification isn't a recurring
      // scheduled task, so it doesn't go through BackgroundTaskRunner —
      // just needs its own containment.
      _pollUntilReady(() => underlying.isReady).then((recovered) => {
        if (!recovered) return;
        facade.state          = HEALTH_STATE.HEALTHY;
        facade.readySince     = Date.now();
        facade.lastReconnectAt = Date.now();
        facade._degradedSince  = null;
        const durationMs = Date.now() - recoveryStart;
        metrics.redisRecoveryDurationMs.observe({ purpose: facade.purpose }, durationMs);
        emit('INFO', 'REDIS_HA_RECOVERY_COMPLETED', { purpose: facade.purpose, mode: facade.mode, durationMs });
        facade.emit('ready', { isReconnect: true });
      }).catch((err) => {
        emit('WARN', 'REDIS_HA_RECOVERY_NOTIFY_FAILED', {
          purpose: facade.purpose, mode: facade.mode, error: err.message,
        });
      });
    } else {
      emit('INFO', 'REDIS_HA_TOPOLOGY_UPDATE', { purpose: facade.purpose, mode: facade.mode, event: ev });
    }
  });
}

// ── Single-mode self-healing supervisor (Finding 49) ──────────────────────────
//
// Wraps a mutable "current underlying client" reference behind a Proxy with
// the identical surface `_wrapHaClient` gives sentinel/cluster mode. Unlike
// that fixed-target Proxy, every trap here re-reads `state.current` at
// ACCESS time, so a client swap performed mid-recovery is invisible to
// callers holding the returned Proxy — the object identity they hold never
// changes, only what it currently forwards to.

function _wrapRecoverableClient(state, facade) {
  return new Proxy(Object.create(null), {
    get(_t, prop) {
      if (prop === 'on' || prop === 'once' || prop === 'off' || prop === 'removeListener' || prop === 'emit') {
        return facade[prop].bind(facade);
      }
      if (prop === 'health') return () => facade.health();
      if (prop === '__facade') return facade;
      if (prop === 'isReady') return state.current ? state.current.isReady === true : false;
      if (prop === 'isOpen') return state.current ? state.current.isOpen === true : false;
      if (prop === 'connect') {
        return () => state.current.connect();
      }
      if (prop === 'disconnect' || prop === 'quit') {
        return async () => {
          facade._closing = true;
          state.closing = true;
          if (state.recoveryTimer) {
            clearTimeout(state.recoveryTimer);
            state.recoveryTimer = null;
          }
          if (state.watchdog) { clearInterval(state.watchdog); state.watchdog = null; } //
          const c = state.current;
          if (!c) return;
          try {
            if (typeof c[prop] === 'function') return await c[prop]();
          } catch { /* already closed/closing — nothing further to do */ }
        };
      }
      const client = state.current;
      const value = client ? client[prop] : undefined;
      if (typeof value !== 'function') return value;
      // race every command against the deadline; misses feed the stall detector.
      if (state.deadline && state.deadline.deadlineMs > 0 && isCommandMember(prop)) {
        return (...args) => {
          const r = value.apply(client, args);
          if (!r || typeof r.then !== 'function') return r;
          return withDeadline(r, state.deadline.deadlineMs, {
            command: String(prop),
            onMiss:    () => state.noteMiss && state.noteMiss(client, 'command', String(prop)),
            onSettled: (ok) => { if (ok && state.noteSuccess) state.noteSuccess(client); },
          });
        };
      }
      return value.bind(client);
    },
  });
}

/**
 * @param {number} consecutiveFailures  0-based count of failed recovery cycles
 *                                       since the current outage began
 * @param {object} retry                haConfig.retry (baseDelayMs/maxDelayMs/jitterRatio)
 * @param {() => number} [_random]      injectable RNG for deterministic tests
 * @returns {number} delay in ms — always >= 1, capped at retry.maxDelayMs (+jitter)
 */
function _recoveryBackoffDelay(consecutiveFailures, retry, _random = Math.random) {
  const exponential = Math.min(retry.baseDelayMs * Math.pow(2, consecutiveFailures), retry.maxDelayMs);
  const jitterSpan   = exponential * retry.jitterRatio;
  const jitter       = (_random() * 2 - 1) * jitterSpan;
  return Math.max(1, Math.round(exponential + jitter));
}

// Consecutive-failure counts at/above which recovery-attempt logs are
// suppressed except every 10th attempt — bounds log volume for outages
// lasting hours without ever going silent (req. 10: rate-limited, not muted).
const _RECOVERY_LOG_FULL_THRESHOLD = 10;

function _shouldLogRecoveryAttempt(consecutiveFailures) {
  return consecutiveFailures <= _RECOVERY_LOG_FULL_THRESHOLD || consecutiveFailures % 10 === 0;
}

/**
 * Builds a self-healing single-mode client: a stable Proxy over a client
 * reference that gets destroyed and recreated from scratch on every terminal
 * `end`, forever, until Redis is reachable again. See module header
 * "SINGLE MODE SELF-HEALING (Finding 49)".
 *
 * @param {object} opts
 * @param {string} opts.purpose
 * @param {Function} [opts.reconnectStrategy]  consumer's bounded per-client strategy
 * @param {number} [opts.connectTimeout]
 * @param {object} opts.haConfig
 * @param {object} opts._redis
 */
function _createSelfHealingSingleClient({ purpose, reconnectStrategy, connectTimeout, haConfig, _redis }) {
  const facade = new ConnectionFacade({ purpose, mode: 'single' });
  const state = {
    current:             null,
    closing:             false,
    recoveryTimer:       null,
    recoveryAttempt:     0,
    consecutiveFailures: 0,
    recoveryStartedAt:   null,
    terminated:          new WeakSet(),   // clients already handled as terminal
  };

  function _makeRawClient() {
    return _redis.createClient(buildClientOptions({ reconnectStrategy, connectTimeout }));
  }

  // Every failed/replaced client is fully unwired and closed before being
  // dropped — req. 9 (no leaked sockets/listeners/timers, no orphan loops).
  function _teardown(client) {
    if (!client) return;
    try { client.removeAllListeners?.(); } catch { /* best-effort */ }
    try {
      if (client.isOpen) {
        if (typeof client.destroy === 'function') client.destroy();
        else if (typeof client.disconnect === 'function') client.disconnect().catch(() => {});
      }
    } catch { /* already closed */ }
  }

  function _wire(client) {
    const metrics = _metrics();

    client.on('connect', () => facade.emit('connect'));

    client.on('reconnecting', () => {
      facade.reconnectCount++;
      metrics.redisReconnectTotal.inc({ purpose, mode: 'single' });
      facade.emit('reconnecting');
    });

    client.on('error', (err) => {
      metrics.redisCommandFailuresTotal.inc({ purpose });
      facade.emit('error', err);
      if (facade.state === HEALTH_STATE.HEALTHY) {
        facade.state          = HEALTH_STATE.DEGRADED;
        facade._degradedSince = Date.now();
      }
      // (owner D9 = A): node-redis 5 never emits 'end' when the client's reconnectStrategy gives up — the socket
      // sets isOpen = false and then emits 'error' (@redis/client socket.js #shouldReconnect). An 'error' observed while
      // the client is no longer open is therefore terminal: recover exactly as on 'end'.
      if (client.isOpen === false) _onTerminal(client, 'reconnect_gave_up');
    });

    client.on('ready', () => { _verifyAndAnnounceReady(client); });

    client.on('end', () => { _onTerminal(client, 'end'); });
  }

  // A client reaches its terminal state at most once (WeakSet), whichever of 'end' / give-up is seen first; stale
  // (superseded) clients and a client closed by the consumer are ignored. The facade announces 'end' only on the
  // transition into RECOVERING, so a recovery attempt whose fresh client also gives up does not re-announce it.
  function _onTerminal(client, cause) {
    if (state.closing || state.current !== client || state.terminated.has(client)) return;
    state.terminated.add(client);
    if (facade.state !== HEALTH_STATE.RECOVERING) {
      facade.state = HEALTH_STATE.RECOVERING; // gauge → 2 via the facade setter
      if (cause !== 'end') emit('WARN', 'REDIS_CLIENT_RECONNECT_GAVE_UP', { purpose, mode: 'single' });
      _announce(facade, 'end');
    }
    _scheduleRecovery();
  }

  // req. 7: never declare healthy on "ready" (TCP + AUTH) alone — verify with
  // a live round trip first. If the client was superseded mid-check (a newer
  // recovery attempt already replaced it), the result is discarded.
  async function _verifyAndAnnounceReady(client) {
    const metrics = _metrics();
    let pong;
    try {
      pong = await client.ping();
    } catch (err) {
      _announce(facade, 'error', err);
      return;
    }
    // FINDING-REVOCATION-SUBSCRIBER-LIVELOCK: a client that has issued
    // .subscribe() (e.g. RevocationSubscriber/OrgStatusSubscriber) is in
    // RESP2 pub/sub subscriber context, where Redis replies to PING with a
    // lowercase two-element push-style reply ("pong", not "+PONG"), and
    // node-redis's decoder can hand that back as a Buffer instead of a
    // string depending on exactly when the reply is parsed relative to the
    // subscribe() call. A strict `pong !== 'PONG'` check therefore never
    // matches for any subscriber-purpose client, so `ready` is never
    // announced and isReady() stays false forever. Normalize both the type
    // and the case before comparing; anything that still isn't PONG after
    // normalization is a genuine failure and still falls through below.
    const pongStr = Buffer.isBuffer(pong) ? pong.toString() : pong;
    if (state.current !== client || typeof pongStr !== 'string' || pongStr.toUpperCase() !== 'PONG' || state.closing) return;

    const isReconnect = facade.readySince !== null;
    facade.state          = HEALTH_STATE.HEALTHY;
    facade.readySince     = Date.now();
    facade._degradedSince = null;
    metrics.redisRecoveryConsecutiveFailures?.set({ purpose }, 0);

    if (state.recoveryStartedAt !== null) {
      const durationMs = Date.now() - state.recoveryStartedAt;
      metrics.redisRecoveryDurationMs.observe({ purpose }, durationMs);
      metrics.redisRecoveryCompletedTotal?.inc({ purpose });
      emit('INFO', 'REDIS_RECOVERY_COMPLETED', {
        purpose, mode: 'single', durationMs, attempts: state.recoveryAttempt,
      });
      state.recoveryStartedAt   = null;
      state.recoveryAttempt     = 0;
      state.consecutiveFailures = 0;
    }

    _announce(facade, 'ready', { isReconnect });
  }

  function _scheduleRecovery() {
    if (state.closing || state.recoveryTimer) return;
    if (state.recoveryStartedAt === null) {
      state.recoveryStartedAt = Date.now();
      emit('WARN', 'REDIS_RECOVERY_STARTED', { purpose, mode: 'single' });
    }

    const delayMs = _recoveryBackoffDelay(state.consecutiveFailures, haConfig.retry);
    state.recoveryTimer = setTimeout(() => {
      state.recoveryTimer = null;
      _attemptRecovery();
    }, delayMs);
    // Never keeps the process (or a test worker) alive on its own.
    state.recoveryTimer.unref?.();
  }

  async function _attemptRecovery() {
    if (state.closing) return;
    const metrics = _metrics();
    // After a Jest environment teardown the lazy require yields undefined; as an async timer callback that is an unhandled rejection that kills the whole
    // coverage run. A process whose metrics module cannot load has nothing left to recover into.
    if (!metrics || !metrics.redisRetryTotal) return;
    state.recoveryAttempt++;
    state.consecutiveFailures++;
    metrics.redisRetryTotal.inc({ purpose });
    metrics.redisRecoveryConsecutiveFailures?.set({ purpose }, state.consecutiveFailures);

    const shouldLog = _shouldLogRecoveryAttempt(state.consecutiveFailures);
    if (shouldLog) {
      emit('WARN', 'REDIS_RECOVERY_ATTEMPT', {
        purpose, mode: 'single', attempt: state.recoveryAttempt, consecutiveFailures: state.consecutiveFailures,
      });
    }

    _teardown(state.current);
    const fresh = _makeRawClient();
    state.current = fresh;
    _wire(fresh);

    try {
      // phase 11: node-redis's connect() resolves only after the connection HANDSHAKE (HELLO/AUTH/CLIENT
      // SETINFO …) is answered, and connectTimeout bounds only the TCP connect. A recovery attempt that lands in a
      // silent partition (TCP accepted, replies dropped — e.g. NAT/conntrack state lost mid-partition) therefore hung
      // in this await forever: the client is never ready (so neither the watchdog nor a command deadline touches it)
      // and no further attempt was ever scheduled, so the connection stayed RECOVERING after the network healed.
      // Each attempt is now bounded; on a miss the half-open client is torn down and the normal backoff retries.
      const bound = state.deadline.deadlineMs > 0 ? (Number.isFinite(connectTimeout) ? connectTimeout : 5_000) + state.deadline.deadlineMs : 0;
      await withDeadline(fresh.connect(), bound, { command: 'CONNECT' });
      if (state.closing) { _teardown(fresh); return; } // shutdown requested mid-attempt
    } catch (err) {
      if (err && err.code === 'REDIS_COMMAND_DEADLINE_EXCEEDED' && state.current === fresh) {
        state.terminated.add(fresh);
        _teardown(fresh);
      }
      if (shouldLog) {
        emit('WARN', 'REDIS_RECOVERY_ATTEMPT_FAILED', {
          purpose, mode: 'single', attempt: state.recoveryAttempt, error: err.message,
        });
      }
      if (!state.closing) _scheduleRecovery();
    }
  }

  // ── silent-partition detection ────────────────────────────────────
  // node-redis 5 drops a command's timeout once the command is written, so on a
  // silent partition (socket "open", nothing comes back) every command waits forever
  // and the client never notices. Commands are raced against a deadline in the Proxy
  // (_wrapRecoverableClient); a background PING watchdog covers idle periods. After
  // `stallThreshold` consecutive misses on the CURRENT client the connection is treated
  // as stalled: it is torn down at once (pending commands are flushed with errors, isReady
  // goes false so readiness reports it) and the normal recovery path opens a FRESH socket.
  state.deadline = resolveDeadlineConfig();
  state.misses = 0;
  state.lastDeadlineLogAt = 0;
  state.noteSuccess = (client) => { if (client === state.current) state.misses = 0; };
  state.noteMiss = (client, source, command) => {
    if (state.closing || client !== state.current || state.terminated.has(client)) return;
    state.misses++;
    const now = Date.now();
    if (now - state.lastDeadlineLogAt >= 5000) {
      state.lastDeadlineLogAt = now;
      emit('WARN', 'REDIS_COMMAND_DEADLINE_EXCEEDED', {
        purpose, mode: 'single', source, command: command || null, deadlineMs: state.deadline.deadlineMs,
        consecutiveMisses: state.misses, stallThreshold: state.deadline.stallThreshold,
      });
    }
    try { _metrics().redisCommandFailuresTotal.inc({ purpose }); } catch { /* best-effort */ }
    if (facade.state === HEALTH_STATE.HEALTHY) { facade.state = HEALTH_STATE.DEGRADED; facade._degradedSince = Date.now(); }
    if (state.misses >= state.deadline.stallThreshold) _onStall(client, source);
  };
  function _onStall(client, source) {
    if (state.closing || client !== state.current || state.terminated.has(client)) return;
    emit('ERROR', 'REDIS_CONNECTION_STALLED', {
      purpose, mode: 'single', source, consecutiveMisses: state.misses, deadlineMs: state.deadline.deadlineMs,
      message: 'Redis stopped answering on an open connection (silent partition or hung server); the connection is torn down and re-established. Dependent controls fail closed meanwhile.',
    });
    state.misses = 0;
    _onTerminal(client, 'stalled');   // RECOVERING + schedule a fresh connection
    _teardown(client);                // flush hung commands now; isReady → false
  }
  if (state.deadline.deadlineMs > 0 && state.deadline.watchdogIntervalMs > 0) {
    state.watchdog = setInterval(async () => {
      const c = state.current;
      if (!c || state.closing || state.watchdogInFlight || c.isReady !== true || state.terminated.has(c)) return;
      state.watchdogInFlight = true;
      try {
        await withDeadline(c.ping(), state.deadline.deadlineMs, { command: 'PING' });
        state.noteSuccess(c);
      } catch (err) {
        if (err && err.code === 'REDIS_COMMAND_DEADLINE_EXCEEDED') state.noteMiss(c, 'watchdog', 'PING');
      } finally {
        state.watchdogInFlight = false;
      }
    }, state.deadline.watchdogIntervalMs);
    if (state.watchdog.unref) state.watchdog.unref();
  }

  // Initial construction is NOT a "recovery" — no backoff, no recovery
  // counters touched. The consumer calls `.connect()` on the returned Proxy
  // itself, exactly as it always has.
  state.current = _makeRawClient();
  _wire(state.current);

  healthRegistry.register(purpose, () => facade.health());
  return _wrapRecoverableClient(state, facade);
}

function _wireClusterEvents(underlying, facade) {
  const metrics = _metrics();
  underlying.on('error', (err) => {
    metrics.redisCommandFailuresTotal.inc({ purpose: facade.purpose });
    facade.emit('error', err);
    if (facade.state === HEALTH_STATE.HEALTHY) {
      facade.state = HEALTH_STATE.DEGRADED;
      emit('WARN', 'REDIS_HA_CONNECTION_LOST', { purpose: facade.purpose, mode: facade.mode, error: err.message });
    }
  });
}

// ── Factory ────────────────────────────────────────────────────────────────────

/**
 * @param {object} opts
 * @param {string} [opts.purpose]            stable label identifying the consumer
 *                                          (e.g. 'nonce', 'anomaly', 'rateLimit',
 *                                          'rateLimitPolicy', 'consentCache',
 *                                          'revocationPublisher',
 *                                          'revocationSubscriber',
 *                                          'keyRotationLock', 'persistenceQueue')
 * @param {Function} [opts.reconnectStrategy]  Only used in 'single' mode — the
 *                                          consumer's own existing bespoke
 *                                          strategy, passed straight through.
 * @param {number}   [opts.connectTimeout]
 * @param {boolean} [opts.forceMasterReads=false] Sentinel mode only:
 *                                          when true, this client's
 *                                          `replicaPoolSize` is forced to 0
 *                                          regardless of
 *                                          `haConfig.sentinel.useReplicas`,
 *                                          so every command — including
 *                                          ones node-redis classifies
 *                                          read-only — targets master. Use
 *                                          for any consumer that needs
 *                                          read-after-write consistency with
 *                                          its own writes (e.g. a cache
 *                                          gating an authorization decision).
 *                                          No-op in single/cluster mode.
 * @param {object}   [opts.haConfig]       injectable, defaults to resolveHaConfig()
 * @param {object}   [opts._redis]         injectable redis package (tests)
 * @returns {import('redis').RedisClientType} a stable, self-healing Proxy in
 *          every mode (single/sentinel/cluster) exposing the same
 *          `.on`/`.isReady`/`.isOpen`/`.connect`/`.disconnect`/`.quit` plus
 *          passthrough command surface as a plain RedisClientType.
 */
function createManagedRedisClient({
  purpose,
  reconnectStrategy,
  connectTimeout,
  forceMasterReads = false,
  haConfig = resolveHaConfig(),
  _redis = redisPkg,
} = {}) {
  if (!purpose || typeof purpose !== 'string') {
    throw new TypeError('createManagedRedisClient: purpose is required');
  }

  if (!haConfig.valid) {
    emit('WARN', 'REDIS_HA_CONFIG_INVALID', { purpose, errors: haConfig.validationErrors });
  }

  if (haConfig.mode === 'single') {
    // Finding 49: returns a stable, self-healing Proxy — never the bare
    // client — so a terminal `end` can be recovered from by recreating the
    // client internally without any consumer ever holding a dead reference.
    // See "SINGLE MODE SELF-HEALING" in the module header above.
    const retry = {
      baseDelayMs: haConfig.retry?.baseDelayMs ?? 100,
      maxDelayMs:  haConfig.retry?.maxDelayMs  ?? 2_000,
      jitterRatio: haConfig.retry?.jitterRatio ?? 0.2,
    };
    return _createSelfHealingSingleClient({
      purpose, reconnectStrategy, connectTimeout, _redis,
      haConfig: { ...haConfig, retry },
    });
  }

  if (haConfig.mode === 'sentinel') {
    const nodeReconnectStrategy = createBoundedReconnectStrategy({
      source: purpose,
      maxAttempts:              haConfig.retry.maxAttempts,
      baseDelayMs:              haConfig.retry.baseDelayMs,
      maxDelayMs:               haConfig.retry.maxDelayMs,
      jitterRatio:              haConfig.retry.jitterRatio,
      circuitBreakerCooldownMs: haConfig.retry.circuitBreakerCooldownMs,
      onRetry: ({ retries, delayMs }) => {
        _metrics().redisRetryTotal.inc({ purpose });
        emit('WARN', 'REDIS_HA_RECONNECT_STARTED', { purpose, mode: 'sentinel', retries, delayMs });
      },
      onExhausted: ({ retries }) => {
        emit('ERROR', 'REDIS_HA_RECONNECT_EXHAUSTED_FOR_NODE', {
          purpose, mode: 'sentinel', retries,
          note: 'this bounds retries against ONE node only — Sentinel topology rediscovery continues independently',
        });
      },
    });

    // forceMasterReads overrides the globally-configured
    // useReplicas for THIS consumer only — see module header
    // "PER-CONSUMER READ ROUTING OVERRIDE" above.
    const useReplicas = haConfig.sentinel.useReplicas && !forceMasterReads;

    if (forceMasterReads && haConfig.sentinel.useReplicas) {
      emit('INFO', 'REDIS_HA_FORCE_MASTER_READS', {
        purpose, mode: 'sentinel',
        message: 'REDIS_SENTINEL_USE_REPLICAS is enabled cluster-wide, but this consumer ' +
                 'requires read-after-write consistency and always targets master.',
      });
    }

    const nodeClientOptions = buildClientOptions({ reconnectStrategy: nodeReconnectStrategy, connectTimeout });
    const underlying = _redis.createSentinel({
      name:              haConfig.sentinel.masterName,
      sentinelRootNodes: haConfig.sentinel.rootNodes,
      nodeClientOptions,
      scanInterval:      haConfig.sentinel.scanIntervalMs,
      masterPoolSize:    1,
      replicaPoolSize:   useReplicas ? 1 : 0,
    });

    const facade = new ConnectionFacade({ purpose, mode: 'sentinel' });
    _wireSentinelEvents(underlying, facade);
    healthRegistry.register(purpose, () => facade.health());
    emit('INFO', 'REDIS_HA_CLIENT_CREATED', {
      purpose, mode: 'sentinel', masterName: haConfig.sentinel.masterName,
      sentinelNodeCount: haConfig.sentinel.rootNodes.length,
    });
    return _wrapHaClient(underlying, facade);
  }

  // mode === 'cluster'
  const nodeReconnectStrategy = createBoundedReconnectStrategy({
    source: purpose,
    maxAttempts:              haConfig.retry.maxAttempts,
    baseDelayMs:              haConfig.retry.baseDelayMs,
    maxDelayMs:               haConfig.retry.maxDelayMs,
    jitterRatio:              haConfig.retry.jitterRatio,
    circuitBreakerCooldownMs: haConfig.retry.circuitBreakerCooldownMs,
    onRetry: ({ retries, delayMs }) => {
      _metrics().redisRetryTotal.inc({ purpose });
      emit('WARN', 'REDIS_HA_RECONNECT_STARTED', { purpose, mode: 'cluster', retries, delayMs });
    },
    onExhausted: ({ retries }) => {
      emit('ERROR', 'REDIS_HA_RECONNECT_EXHAUSTED_FOR_NODE', { purpose, mode: 'cluster', retries });
    },
  });

  const underlying = _redis.createCluster({
    rootNodes: haConfig.cluster.rootNodes.map(n => ({ socket: { host: n.host, port: n.port } })),
    defaults:  buildClientOptions({ reconnectStrategy: nodeReconnectStrategy, connectTimeout }),
  });

  const facade = new ConnectionFacade({ purpose, mode: 'cluster' });
  _wireClusterEvents(underlying, facade);
  healthRegistry.register(purpose, () => facade.health());
  emit('INFO', 'REDIS_HA_CLIENT_CREATED', {
    purpose, mode: 'cluster', seedNodeCount: haConfig.cluster.rootNodes.length,
  });
  return _wrapHaClient(underlying, facade);
}

module.exports = {
  createManagedRedisClient,
  HEALTH_STATE,
  // Exported for tests / advanced callers only.
  _wrapHaClient,
  _wrapRecoverableClient,
  _recoveryBackoffDelay,
  ConnectionFacade,
};
