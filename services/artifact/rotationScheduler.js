'use strict';

/**
 * QODIQA Automatic Key Rotation Scheduler
 *
 * Automated background scheduler for periodic rotation of Ed25519 signing
 * keys across every client currently known to the key store.
 *
 * ── Rotation interval (configurable, not hardcoded) ───────────────────────────
 *
 * A key becomes due for automatic rotation when its age (now − createdAt of
 * the active key) reaches the configured rotation interval:
 *
 *   QODIQA_KEY_ROTATION_INTERVAL_MS    Explicit override, highest precedence.
 *   QODIQA_KEY_ROTATION_INTERVAL_DAYS  Explicit override in days.
 *   QODIQA_KEY_ROTATION_SCHEDULE       Preset: 'daily' | 'weekly' | 'monthly' |
 *                                      'disabled'.  Default: 'monthly'.
 *
 * This is intentionally independent of keyStore.ROTATION_DAYS (the 90-day
 * "overdue" advisory threshold used elsewhere, e.g. tenantKeyManager startup
 * warnings) — that constant continues to drive WARN-level observability
 * regardless of whether automatic rotation is enabled or how it is
 * configured.  This scheduler's interval is what actually TRIGGERS rotation.
 *
 * ── Idempotent, restart-safe by construction ──────────────────────────────────
 *
 * Due-ness is derived from the active key's own createdAt timestamp — already
 * durably persisted in keys.json — rather than from separate scheduler state.
 * After a rotation, the new key's createdAt resets the age to zero, so the
 * same key is never rotated twice for the same interval regardless of process
 * restarts, crashes mid-cycle, or how many instances are ticking concurrently.
 *
 * ── Cluster safety ────────────────────────────────────────────────────────────
 *
 * Every instance in a deployment runs this scheduler and evaluates the same
 * due-ness condition. Before rotating a given clientId, an instance must
 * acquire the distributed lock (src/infra/keys/rotationLock.js — Redis SET NX
 * PX). Only the lock holder rotates; every other instance observes the lock
 * as held and skips that client for the current tick (SKIPPED, not an error).
 * This turns the previously-manual operational rule documented in
 * docs/deployment/topology.md ("key rotation coordination: must be serialised") into a
 * structural guarantee.
 *
 * ── Fleet-wide visibility without a manual restart ────────────────────
 *
 * Trust-store reload is an INDEPENDENT lifecycle concern from automatic
 * rotation — this scheduler happens to own both timers for operational
 * convenience (one background component, one start()/stop() pair), but
 * whether reload runs is governed entirely by its own enable flag
 * (QODIQA_KEY_RELOAD_ENABLED, default true) and its own interval
 * (QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS). Disabling automatic rotation
 * (QODIQA_KEY_ROTATION_ENABLED=false or QODIQA_KEY_ROTATION_SCHEDULE=disabled)
 * NEVER disables reload — see `rotationActive` / `reloadActive` below and in
 * getStatus(). This is what guarantees revocations, externally replaced keys,
 * and metadata updates propagate fleet-wide on a bounded, deterministic
 * cadence regardless of whether this instance ever rotates a key itself.
 *
 * Every running instance (including the one that performed a rotation, and
 * every instance whether or not it rotates) periodically calls
 * keyManager.reload() to re-read keys.json, so instances that did not win the
 * rotation lock — or that never attempt rotation at all — still pick up the
 * new active key, revoked keys, and replaced keys without an
 * operator-triggered rolling restart. Reload is fail-closed: a
 * read/parse/decrypt failure leaves the in-memory store untouched and is
 * reported, never silently discarded. Reload is also synchronous and
 * replaces the store with a single assignment, so — because Node.js runs
 * synchronous code to completion without preemption — concurrent
 * verification requests always see either the fully-old or fully-new trust
 * store, never a partially-swapped one.
 *
 * ── KMS compatibility ─────────────────────────────────────────────────────────
 *
 * Rotation is performed via keyManager.rotateGracefullyAsync(), which
 * delegates to keyStore.rotateKeyAsync({ mode: 'graceful' }). For the default
 * local provider this is byte-identical to the synchronous manual graceful
 * rotation path. When QODIQA_KMS_PROVIDER is vault-transit or hsm, the new
 * key pair is generated INSIDE the external provider and the old key is
 * deprecated inside the provider too — private key material never enters
 * this process.
 *
 * ── Why this scheduler uses graceful, not emergency, rotation ────────
 *
 * keyManager.rotateAsync()'s default 'emergency' mode REVOKES the outgoing
 * key immediately — the correct behavior for an operator's manual
 * POST /key-admin/:clientId/rotate, which is the intuitive incident-response
 * action for a suspected key compromise. This scheduler is not that: it
 * rotates keys automatically on a fixed calendar cadence purely because they
 * have aged past QODIQA_KEY_ROTATION_SCHEDULE, with no signal of compromise
 * whatsoever. Defaulting a routine, unattended, fleet-wide rotation to
 * immediate revocation would make every artifact signed shortly before a
 * scheduled rotation unverifiable the instant that rotation runs — a
 * self-inflicted availability regression with no security benefit, since
 * nothing about scheduled due-ness indicates the outgoing key is compromised.
 * The scheduler therefore explicitly opts into 'graceful' mode: the outgoing
 * key can never sign again (private material is discarded immediately either
 * way) but remains verifiable for its normal retention window. An operator
 * who has actual reason to believe a key is compromised must still use
 * POST /key-admin/:clientId/rotate (or /revoke) — this scheduler never makes
 * that determination on its own.
 *
 * ── Fail-closed behavior ──────────────────────────────────────────────────────
 *
 *   • Lock unavailable (Redis down)     → skip this client this tick; retried
 *                                          next tick. Never rotates unlocked.
 *   • Rotation fails after all retries  → old key remains active; nothing is
 *                                          partially applied. keyStore never
 *                                          leaves a client without an active
 *                                          key (rotateKeyAsync only swaps the
 *                                          active pointer after the new key is
 *                                          fully generated and self-tested).
 *   • Provider-side deprecate fails     → the whole rotation throws before the
 *                                          local store is updated, so the old
 *                                          key remains the sole active key
 *                                          both locally and in the provider.
 *
 * ── Audit events emitted ──────────────────────────────────────────────────────
 *
 *   KEY_ROTATION_SCHEDULER_STARTED          INFO
 *   KEY_ROTATION_SCHEDULER_STOPPED          INFO
 *   KEY_ROTATION_SCHEDULER_TICK_STARTED     INFO
 *   KEY_ROTATION_SCHEDULER_TICK_COMPLETED   INFO
 *   KEY_ROTATION_SCHEDULER_ROTATED          INFO   (also: keyStore's own
 *                                                    KEY_ROTATED / KEY_DEPRECATED)
 *   KEY_ROTATION_SCHEDULER_SKIPPED          INFO   reason: NOT_DUE | LOCKED |
 *                                                          ALREADY_RUNNING
 *   KEY_ROTATION_SCHEDULER_RETRY            WARN
 *   KEY_ROTATION_SCHEDULER_FAILED           ERROR  all retries exhausted
 *   KEY_ROTATION_SCHEDULER_RELOAD_FAILED    WARN
 *   KEY_ROTATION_SCHEDULER_ALREADY_RUNNING  WARN   duplicate start() call
 *   KEY_RELOAD_SCHEDULER_DISABLED           INFO   reload explicitly turned off (fleet-unsafe)
 *   (also, from keyStore.reloadFromDisk() itself:)
 *   KEYSTORE_RELOADED                       INFO   every successful reload, changed or not
 *   KEYSTORE_RELOAD_FAILED                  ERROR  read/parse/decrypt failure — store untouched
 *   KEY_REVOCATION_PROPAGATED               WARN   a key transitioned to 'revoked' via reload
 *   KEY_ACTIVE_KEY_CHANGED                  INFO   a client's active key changed via reload
 *
 * ── Prometheus metrics updated ────────────────────────────────────────────────
 *
 *   See src/observability/metrics.js "Key Rotation Scheduler" section.
 *
 * ── Configuration env vars ────────────────────────────────────────────────────
 *
 *   QODIQA_KEY_ROTATION_ENABLED             'true'/'false'. Default: true. Governs
 *                                            rotation ONLY — never affects reload.
 *   QODIQA_KEY_RELOAD_ENABLED               'true'/'false'. Default: true. Governs
 *                                            trust-store reload ONLY — independent of
 *                                            rotation. Disabling this is fleet-unsafe:
 *                                            this instance stops picking up revocations,
 *                                            replaced keys, and metadata updates made by
 *                                            other instances or operators until restarted.
 *   QODIQA_KEY_ROTATION_SCHEDULE            daily|weekly|monthly|disabled. Default: monthly.
 *   QODIQA_KEY_ROTATION_INTERVAL_MS         Explicit override, highest precedence.
 *   QODIQA_KEY_ROTATION_INTERVAL_DAYS       Explicit override in days.
 *   QODIQA_KEY_ROTATION_CHECK_INTERVAL_MS   How often to scan for due clients. Default: 3600000 (1h).
 *   QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS  How often EVERY instance reloads keys.json —
 *                                            this is the deterministic upper bound on
 *                                            revocation/replacement propagation time
 *                                            fleet-wide. Default: 300000 (5m).
 *   QODIQA_KEY_ROTATION_LOCK_TTL_MS         Distributed lock TTL. Default: 30000 (30s).
 *   QODIQA_KEY_ROTATION_MAX_RETRIES         Max retry attempts per client per tick. Default: 3.
 *   QODIQA_KEY_ROTATION_RETRY_DELAY_MS      Delay between retries. Default: 5000.
 *   QODIQA_KEY_ROTATION_CLIENT_IDS          Optional comma-separated allowlist. Default: all
 *                                           clients currently in the key store.
 */

const { emit: _defaultEmit } = require('../logger');
const _defaultMetrics        = require('../../src/observability/metrics');
const _defaultLock           = require('../../src/infra/keys/rotationLock');
const _defaultKeyManager     = require('./keyManager');
const _defaultKeyStore       = require('./keyStore');
const _defaultTaskRunner     = require('../../src/runtime/backgroundTasks/BackgroundTaskRunner');

const SOURCE = 'KEY_ROTATION_SCHEDULER';

const DAY_MS   = 86_400_000;
const WEEK_MS  = 7   * DAY_MS;
const MONTH_MS = 30  * DAY_MS;

// ── Helpers ───────────────────────────────────────────────────────────────────

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function _envInt(key, fallback) {
  const raw = process.env[key];
  if (raw == null || raw === '') return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function _envBool(key, fallback) {
  const raw = process.env[key];
  if (raw == null || raw === '') return fallback;
  return raw.toLowerCase() === 'true';
}

function _unref(timer) {
  if (timer && typeof timer.unref === 'function') timer.unref();
  return timer;
}

/**
 * Resolve the configured rotation interval in milliseconds.
 * Precedence: QODIQA_KEY_ROTATION_INTERVAL_MS > QODIQA_KEY_ROTATION_INTERVAL_DAYS
 *             > QODIQA_KEY_ROTATION_SCHEDULE preset > default ('monthly').
 * Returns 0 to mean "disabled" (rotation never triggers automatically).
 * An invalid QODIQA_KEY_ROTATION_SCHEDULE value falls back to 'monthly' with
 * a WARN — a scheduler misconfiguration degrades safely rather than aborting
 * server startup.
 */
function resolveRotationIntervalMs(opts = {}, _emit = _defaultEmit) {
  const explicitMs = opts.intervalMs ?? _envInt('QODIQA_KEY_ROTATION_INTERVAL_MS', null);
  if (explicitMs != null && explicitMs > 0) return explicitMs;

  const explicitDays = opts.intervalDays ?? _envInt('QODIQA_KEY_ROTATION_INTERVAL_DAYS', null);
  if (explicitDays != null && explicitDays > 0) return explicitDays * DAY_MS;

  const schedule = (opts.schedule ?? process.env.QODIQA_KEY_ROTATION_SCHEDULE ?? 'monthly').toLowerCase();
  switch (schedule) {
    case 'daily':    return DAY_MS;
    case 'weekly':   return WEEK_MS;
    case 'monthly':  return MONTH_MS;
    case 'disabled': return 0;
    default:
      _emit('WARN', 'KEY_ROTATION_SCHEDULE_INVALID', {
        source: SOURCE,
        value:  schedule,
        message: `Unrecognized QODIQA_KEY_ROTATION_SCHEDULE "${schedule}" — falling back to "monthly". ` +
                 `Valid values: daily, weekly, monthly, disabled.`,
      });
      return MONTH_MS;
  }
}

function _parseClientAllowlist() {
  const raw = process.env.QODIQA_KEY_ROTATION_CLIENT_IDS;
  if (!raw) return null;
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

// ── Scheduler factory ─────────────────────────────────────────────────────────

/**
 * Create and return a new Key Rotation Scheduler instance.
 * All I/O dependencies are injectable for testing.
 *
 * @param {object}   [opts]
 * @param {boolean}  [opts.enabled]             Governs ROTATION only. Default: QODIQA_KEY_ROTATION_ENABLED env (default true).
 * @param {boolean}  [opts.reloadEnabled]       Governs RELOAD only — independent of `enabled`/rotation.
 *                                              Default: QODIQA_KEY_RELOAD_ENABLED env (default true).
 * @param {number}   [opts.intervalMs]          Rotation interval override.
 * @param {number}   [opts.intervalDays]        Rotation interval override, in days.
 * @param {string}   [opts.schedule]            'daily'|'weekly'|'monthly'|'disabled'.
 * @param {number}   [opts.checkIntervalMs]     Tick cadence. Default: 3600000.
 * @param {number}   [opts.reloadIntervalMs]    Follower reload cadence. Default: 300000.
 * @param {number}   [opts.lockTtlMs]           Distributed lock TTL. Default: 30000.
 * @param {number}   [opts.maxRetries]          Default: 3.
 * @param {number}   [opts.retryDelayMs]        Default: 5000.
 * @param {string[]} [opts.clientIds]           Explicit client allowlist. Default: discover all.
 * @param {Function} [opts._listKeys]           Injected for testing.
 * @param {Function} [opts._rotateAsync]        Injected for testing. Defaults to
 *                                              keyManager.rotateGracefullyAsync — see
 *                                              "Why this scheduler uses graceful, not
 * emergency, rotation" above.
 * @param {Function} [opts._reload]             Injected for testing.
 * @param {object}   [opts._lock]               Injected for testing (default: rotationLock).
 * @param {any}      [opts._emit]               Injected for testing.
 * @param {object}   [opts._metrics]            Injected for testing.
 * @param {any}      [opts._taskRunner]         Injected for testing.
 * @returns {object} Scheduler instance with start(), stop(), isRunning(), getStatus(), runOnce().
 */
function createScheduler(opts = {}) {
  const {
    enabled          = _envBool('QODIQA_KEY_ROTATION_ENABLED', true),
    reloadEnabled    = _envBool('QODIQA_KEY_RELOAD_ENABLED', true),
    checkIntervalMs  = _envInt('QODIQA_KEY_ROTATION_CHECK_INTERVAL_MS', 3_600_000),
    reloadIntervalMs = _envInt('QODIQA_KEY_ROTATION_RELOAD_INTERVAL_MS', 300_000),
    lockTtlMs        = _envInt('QODIQA_KEY_ROTATION_LOCK_TTL_MS', 30_000),
    maxRetries       = _envInt('QODIQA_KEY_ROTATION_MAX_RETRIES', 3),
    retryDelayMs     = _envInt('QODIQA_KEY_ROTATION_RETRY_DELAY_MS', 5_000),
    clientIds        = _parseClientAllowlist(),
    _listKeys        = _defaultKeyStore.listKeys,
    // scheduled rotation is planned maintenance, not incident
    // response — it must never fall back to keyManager.rotateAsync()'s
    // 'emergency' (revoke) default. See the file-header rationale above.
    _rotateAsync     = _defaultKeyManager.rotateGracefullyAsync,
    _reload          = _defaultKeyManager.reload,
    _lock            = _defaultLock,
    _emit            = _defaultEmit,
    _metrics         = _defaultMetrics,
    _taskRunner      = _defaultTaskRunner,
  } = opts;

  const intervalMs = resolveRotationIntervalMs(opts, _emit);

  // ── Independent lifecycle gates ─────────────────────────────────────
  // rotationActive and reloadActive are evaluated once at scheduler creation
  // and never influence one another. Disabling rotation (enabled=false, or an
  // effective interval of 0 via QODIQA_KEY_ROTATION_SCHEDULE=disabled) must
  // never disable reload, and vice versa — see the "Fleet-wide visibility"
  // section in the file header for why this independence is the guarantee
  // that closes (revocation/rotation not guaranteed to propagate
  // fleet-wide when automatic rotation is disabled).
  const rotationActive = enabled && intervalMs > 0;
  const reloadActive   = reloadEnabled && reloadIntervalMs > 0;

  // ── Mutable state ───────────────────────────────────────────────────────────

  let _running       = false;
  let _ticking        = false;
  let _tickTimer      = null;
  let _reloadTimer    = null;
  let _startedAt      = null;
  let _lastTickAt     = null;
  let _totalTicks     = 0;
  let _totalRotated   = 0;
  let _totalErrors    = 0;
  let _totalSkipped   = 0;

  // ── Client discovery ─────────────────────────────────────────────────────────

  function _discoverClients() {
    if (clientIds && clientIds.length > 0) return clientIds;
    const known = new Set();
    for (const rec of _listKeys()) known.add(rec.clientId);
    return [...known];
  }

  // ── Due-ness check ───────────────────────────────────────────────────────────

  function _activeKeyFor(clientId) {
    const keys   = _listKeys().filter(k => k.clientId === clientId && k.status === 'active');
    // Deterministic selection when more than one active key exists (a structural
    // anomaly elsewhere would already have raised a startup violation) —
    // pick the most recent so the scheduler never acts on a stale record.
    return keys.sort((a, b) => /** @type {any} */ (new Date(b.createdAt)) - /** @type {any} */ (new Date(a.createdAt)))[0] || null;
  }

  function _isDue(activeKey) {
    if (intervalMs <= 0) return false; // 'disabled' schedule
    if (!activeKey) return false;
    const ageMs = Date.now() - new Date(activeKey.createdAt).getTime();
    return ageMs >= intervalMs;
  }

  // ── Rotation with retry, guarded by the distributed lock ────────────────────

  async function _rotateWithRetry(clientId) {
    let lockToken = null;
    let lockFence;   // fencing token, checked by the keystore at commit
    try {
      const lockResult = await _lock.acquire(clientId, lockTtlMs);
      if (!lockResult.acquired) {
        _metrics.keyRotationSchedulerSkippedTotal.inc({ trigger: 'scheduled', reason: 'locked' });
        _metrics.keyRotationLockContentionTotal.inc({});
        _emit('INFO', 'KEY_ROTATION_SCHEDULER_SKIPPED', { source: SOURCE, clientId, reason: 'LOCKED' });
        _totalSkipped++;
        return { rotated: false, skipped: true };
      }
      lockToken = lockResult.token;
      lockFence = lockResult.fence;
    } catch (err) {
      // Redis unreachable — fail closed: skip, never rotate unlocked.
      _metrics.keyRotationSchedulerSkippedTotal.inc({ trigger: 'scheduled', reason: 'lock_unavailable' });
      _emit('WARN', 'KEY_ROTATION_SCHEDULER_SKIPPED', {
        source: SOURCE, clientId, reason: 'LOCK_UNAVAILABLE', error: err.message,
      });
      _totalSkipped++;
      return { rotated: false, skipped: true };
    }

    const startMs = Date.now();
    try {
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        if (attempt > 0) {
          _metrics.keyRotationSchedulerRetriesTotal.inc({});
          _emit('WARN', 'KEY_ROTATION_SCHEDULER_RETRY', { source: SOURCE, clientId, attempt, maxRetries });
          await _sleep(retryDelayMs);
          if (!_running) return { rotated: false, aborted: true };
        }

        try {
          const result = await _rotateAsync(clientId, { reason: 'SCHEDULED_ROTATION', triggeredBy: 'scheduler', fence: lockFence });
          const durationMs = Date.now() - startMs;

          _totalRotated++;
          _metrics.keyRotationSchedulerSuccessTotal.inc({ trigger: 'scheduled', provider: _providerLabel() });
          _metrics.keyRotationSchedulerDurationMs.observe({ trigger: 'scheduled' }, durationMs);
          _emit('INFO', 'KEY_ROTATION_SCHEDULER_ROTATED', {
            source: SOURCE, clientId, keyId: result.keyId, version: result.version,
            fingerprint: result.fingerprint, durationMs, attempt,
          });
          return { rotated: true, result };
        } catch (err) {
          // a newer rotator took the lock over while this one was paused — superseded, not a failure to retry.
          if (err && err.code === 'KEYSTORE_STALE_FENCE') {
            _metrics.keyRotationSchedulerSkippedTotal.inc({ trigger: 'scheduled', reason: 'superseded' });
            _emit('WARN', 'KEY_ROTATION_SCHEDULER_SKIPPED', { source: SOURCE, clientId, reason: 'SUPERSEDED', error: err.message });
            _totalSkipped++;
            return { rotated: false, skipped: true, superseded: true };
          }
          if (attempt === maxRetries) {
            _totalErrors++;
            _metrics.keyRotationSchedulerFailuresTotal.inc({ trigger: 'scheduled', provider: _providerLabel() });
            _emit('ERROR', 'KEY_ROTATION_SCHEDULER_FAILED', {
              source: SOURCE, clientId, attempt, maxRetries, error: err.message,
            });
            return { rotated: false, failed: true, error: err.message };
          }
          // fall through to retry
        }
      }
      return { rotated: false };
    } finally {
      if (lockToken) await _lock.release(clientId, lockToken);
    }
  }

  function _providerLabel() {
    try {
      const kpf = require('../../src/infra/keys/keyProviderFactory');
      const p   = kpf.getNativeSigningProvider();
      return p ? p.name : 'local';
    } catch {
      return 'local';
    }
  }

  // ── Tick: evaluate every known client, rotate the ones that are due ─────────

  async function _runTick() {
    if (!_running) return;

    if (_ticking) {
      _metrics.keyRotationSchedulerSkippedTotal.inc({ trigger: 'scheduled', reason: 'tick_in_progress' });
      _emit('INFO', 'KEY_ROTATION_SCHEDULER_SKIPPED', { source: SOURCE, reason: 'ALREADY_RUNNING' });
      _scheduleNextTick();
      return;
    }

    _ticking = true;
    _totalTicks++;
    _lastTickAt = new Date();
    _metrics.keyRotationSchedulerRunsTotal.inc({ trigger: 'scheduled' });
    _emit('INFO', 'KEY_ROTATION_SCHEDULER_TICK_STARTED', { source: SOURCE, intervalMs });

    let rotated = 0, skipped = 0, failed = 0;
    try {
      // Finding 3.6: the tick body runs through BackgroundTaskRunner, which
      // is the actual containment boundary — a thrown/rejected error here
      // (e.g. _discoverClients() throwing synchronously, or
      // _rotateWithRetry()'s own unguarded `finally { await _lock.release() }`
      // rejecting) is caught, logged, and metriced instead of propagating
      // out of this async function as an unhandled rejection. Classified
      // 'critical' (not 'startup-critical') in taskRegistry.js: a rotation
      // failure must be loudly alerted on but must not take the gateway
      // down — the next tick will retry. The outer catch below is
      // additional defense-in-depth; runTask() itself does not rethrow for
      // this criticality.
      await _taskRunner.runTask('key-rotation-tick', async () => {
        const targets = _discoverClients();
        for (const clientId of targets) {
          if (!_running) break;
          const activeKey = _activeKeyFor(clientId);

          if (activeKey) {
            _metrics.keyActiveAgeSeconds.set(
              { clientId },
              Math.floor((Date.now() - new Date(activeKey.createdAt).getTime()) / 1000),
            );
          }

          if (!_isDue(activeKey)) {
            skipped++;
            _totalSkipped++;
            continue;
          }

          const outcome = await _rotateWithRetry(clientId);
          if (outcome.rotated) rotated++;
          else if (outcome.failed) failed++;
          else skipped++;
        }
      });
    } catch (err) {
      // Should be unreachable in practice — see comment above.
      _emit('ERROR', 'KEY_ROTATION_SCHEDULER_TICK_ESCAPED', { source: SOURCE, error: err.message });
    } finally {
      _ticking = false;
      _metrics.keyRotationSchedulerLastRunTs.set({}, Math.floor(Date.now() / 1000));
      _emit('INFO', 'KEY_ROTATION_SCHEDULER_TICK_COMPLETED', {
        source: SOURCE, rotated, skipped, failed,
      });
      _scheduleNextTick();
    }
  }

  function _scheduleNextTick() {
    if (!_running) return;
    _tickTimer = _unref(setTimeout(_runTick, checkIntervalMs));
    _metrics.keyRotationSchedulerNextRunTs.set({}, Math.floor((Date.now() + checkIntervalMs) / 1000));
  }

  // ── Follower reload: pick up rotations performed by other instances ────────

  function _runReload() {
    if (!_running) return;
    try {
      const result = _reload();
      if (result.error) {
        _emit('WARN', 'KEY_ROTATION_SCHEDULER_RELOAD_FAILED', { source: SOURCE, error: result.error });
      }
    } catch (err) {
      _emit('WARN', 'KEY_ROTATION_SCHEDULER_RELOAD_FAILED', { source: SOURCE, error: err.message });
    }
    if (_running) {
      _reloadTimer = _unref(setTimeout(_runReload, reloadIntervalMs));
    }
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  const scheduler = {

    /**
     * Start the scheduler. Idempotent — a duplicate start() call while
     * already running emits a warning and returns without resetting state.
     *
     * Rotation and reload are started independently: disabling
     * automatic rotation via config — QODIQA_KEY_ROTATION_ENABLED=false or
     * QODIQA_KEY_ROTATION_SCHEDULE=disabled — never prevents reload from
     * starting, and disabling reload never prevents rotation from starting.
     * The scheduler only fully no-ops (never schedules any timer, isRunning()
     * stays false) when BOTH are disabled.
     */
    start() {
      if (_running) {
        _emit('WARN', 'KEY_ROTATION_SCHEDULER_ALREADY_RUNNING', { source: SOURCE });
        return this;
      }

      if (!rotationActive) {
        _emit('INFO', 'KEY_ROTATION_SCHEDULER_DISABLED', {
          source: SOURCE, enabled, intervalMs, reloadActive,
          message: 'Automatic key rotation is disabled — keys must be rotated manually via ' +
                   'POST /key-admin/:clientId/rotate or the operator CLI. Trust-store reload ' +
                   '(revocation and key-replacement propagation) is a separate concern and ' +
                   (reloadActive
                     ? 'remains active on its own schedule.'
                     : 'is ALSO disabled — see QODIQA_KEY_RELOAD_ENABLED.'),
        });
      }

      if (!reloadActive) {
        _emit('INFO', 'KEY_RELOAD_SCHEDULER_DISABLED', {
          source: SOURCE, reloadEnabled, reloadIntervalMs, rotationActive,
          message: 'Trust-store reload is disabled — this instance will NOT automatically ' +
                   'pick up revocations, replaced keys, or metadata updates made by other ' +
                   'instances or operators until restarted. Not recommended outside a ' +
                   'single-instance deployment.',
        });
      }

      if (!rotationActive && !reloadActive) {
        return this;
      }

      _running   = true;
      _startedAt = new Date();
      _metrics.keyRotationSchedulerActive.set({}, rotationActive ? 1 : 0);

      if (rotationActive) {
        _emit('INFO', 'KEY_ROTATION_SCHEDULER_STARTED', {
          source: SOURCE, intervalMs, checkIntervalMs, reloadIntervalMs, lockTtlMs,
          maxRetries, retryDelayMs,
        });
        // Run an immediate first tick, then settle into the check-interval cadence.
        _tickTimer = _unref(setTimeout(_runTick, 0));
      }

      if (reloadActive) {
        _reloadTimer = _unref(setTimeout(_runReload, reloadIntervalMs));
      }

      return this;
    },

    /**
     * Stop the scheduler. Idempotent. Any in-progress tick completes; no new
     * timers are scheduled afterward.
     */
    stop() {
      if (!_running) return this;

      _running = false;
      _metrics.keyRotationSchedulerActive.set({}, 0);
      _metrics.keyRotationSchedulerNextRunTs.set({}, 0);

      if (_tickTimer   !== null) { clearTimeout(_tickTimer);   _tickTimer   = null; }
      if (_reloadTimer !== null) { clearTimeout(_reloadTimer); _reloadTimer = null; }

      _emit('INFO', 'KEY_ROTATION_SCHEDULER_STOPPED', {
        source: SOURCE, totalTicks: _totalTicks, totalRotated: _totalRotated,
        totalErrors: _totalErrors, totalSkipped: _totalSkipped,
        startedAt: _startedAt?.toISOString() ?? null,
      });

      return this;
    },

    /** Force an immediate tick regardless of the check-interval timer — used by tests and manual triggers. */
    async runOnce() {
      await _runTick();
    },

    /** @returns {boolean} */
    isRunning() { return _running; },

    /** @returns {object} Snapshot of current scheduler state. */
    getStatus() {
      return Object.freeze({
        running:          _running,
        ticking:          _ticking,
        enabled,
        reloadEnabled,
        // Whether each concern actually schedules a timer on start() — the
        // authoritative signal for "is rotation disabling reload" (it never
        // does) since `enabled`/`reloadEnabled` alone don't account for an
        // effective interval of 0..
        rotationActive,
        reloadActive,
        intervalMs,
        checkIntervalMs,
        reloadIntervalMs,
        lockTtlMs,
        maxRetries,
        retryDelayMs,
        startedAt:        _startedAt?.toISOString()  ?? null,
        lastTickAt:       _lastTickAt?.toISOString() ?? null,
        totalTicks:       _totalTicks,
        totalRotated:     _totalRotated,
        totalErrors:      _totalErrors,
        totalSkipped:     _totalSkipped,
      });
    },
  };

  return scheduler;
}

// ── Process-wide default instance ────────────────────────────────────────────
//
// server.js starts this singleton at boot; src/api/routes/keyAdmin.js's status
// route reads it via getDefaultScheduler() so both share one running instance
// without server.js needing to thread the reference through module state.

let _defaultInstance = null;

function getDefaultScheduler() {
  if (!_defaultInstance) _defaultInstance = createScheduler();
  return _defaultInstance;
}

// Test-only: allows a fresh singleton per test file without process restart.
function _resetDefaultScheduler() {
  _defaultInstance = null;
}

module.exports = {
  createScheduler,
  getDefaultScheduler,
  _resetDefaultScheduler,
  resolveRotationIntervalMs,
  DAY_MS, WEEK_MS, MONTH_MS,
};
