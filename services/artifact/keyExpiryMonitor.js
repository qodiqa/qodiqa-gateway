'use strict';

/**
 * Periodic Key Expiry Re-Validation — #9 (finding: "key expiry approaching").
 *
 * keyManager.validateStartup() already computes and warns on expiring/
 * rotation-overdue keys (KEY_EXPIRING_SOON / KEY_ROTATION_OVERDUE,
 * keyManager.js Steps 5-6) — but only once, at process startup. A key that
 * crosses into the EXPIRY_WARNING_DAYS window mid-process-lifetime (a
 * long-running process, expiry math is date-relative) produces no further
 * signal until the next restart.
 *
 * This module re-runs the identical, already-existing, pure
 * keyStore.validateKeyStore() check on a background interval and re-emits
 * the SAME event names startup already uses — reusing the existing
 * taxonomy rather than inventing a parallel one. Modeled on
 * src/runtime/eventLoopMonitor.js's pattern (unref'd setInterval,
 * env-configurable interval, background-only, never throws).
 *
 * Environment variables:
 *   QODIQA_KEY_EXPIRY_MONITOR_ENABLED    — 'false' to disable (default: enabled)
 *   QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS  — how often to re-check, in ms
 *                                           (default: 21600000 — 6h; expiry
 *                                           windows are measured in days, so
 *                                           this does not need to be frequent)
 */

const { emit } = require('../logger');

function _envInt(name, fallback) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

const CHECK_INTERVAL_MS = _envInt('QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS', 6 * 60 * 60 * 1000);

let _timer = null;

/** True once the monitor has been initialized and its timer is active. */
function isEnabled() { return !!_timer; }

function _refreshMetrics(expiringCount, overdueCount) {
  try {
    const metrics = require('../../src/observability/metrics');
    metrics.keyExpiryMonitorRunsTotal.inc({});
    metrics.keyExpiryApproachingCount.set({}, expiringCount);
    metrics.keyRotationOverdueCount.set({}, overdueCount);
  } catch { /* metrics must never affect the monitor */ }
}

// FINAL LOCAL CLOSURE / early-warning half: the transparency and checkpoint Ed25519 stores were
// checked ONCE, at startup — a long-running gateway gave no signal at all before their day-180 expiry, and the next
// restart is then a startup FATAL (*_EXPIRED). K1: every event now names the supported rotation
// command (scripts/keys/rotate-offline.js --store <store>) as `rotateCommand`. The outage is made visible in advance
// through the SAME events and gauges the artifact store already drives
// (qodiqa_key_expiry_approaching_count → QodiqaKeyExpiryApproaching). A store whose key file does not exist is not in
// use here and is skipped, so the monitor never bootstraps (or writes) a store the process does not use.
const ED25519_STORES = [
  { store: 'transparency', module: '../../src/core/transparency/transparencyKeyStore' },
  { store: 'checkpoint', module: '../../src/core/audit/checkpoint/checkpointKeyStore' },
];

// K1: the operator-run rotation for each Ed25519 store.
function _rotateCommand(store) {
  return `node scripts/keys/rotate-offline.js --store ${store} --mode graceful --operator <id> --reason "<text>" --confirm-offline-recovery`;
}

function _checkEd25519Stores() {
  let expiring = 0; let overdue = 0;
  for (const { store, module: modPath } of ED25519_STORES) {
    try {
      const ks = require(modPath);
      if (!ks.DATA_PATH || !require('fs').existsSync(ks.DATA_PATH)) continue;
      const r = ks.validateKeyStore();
      for (const e of r.expiredKeys || []) {
        emit('ERROR', 'KEY_EXPIRED', { store, keyId: e.keyId, expiresAt: e.expiresAt, source: 'PERIODIC_MONITOR',
          rotateCommand: _rotateCommand(store),
          message: `active ${store} key has expired — the next restart fails at startup; rotate it now: ${_rotateCommand(store)}` });
      }
      for (const e of r.expiringKeys || []) {
        emit('WARN', 'KEY_EXPIRING_SOON', { store, keyId: e.keyId, daysRemaining: e.daysRemaining, source: 'PERIODIC_MONITOR', rotateCommand: _rotateCommand(store) });
      }
      for (const e of r.overdueKeys || []) {
        emit('WARN', 'KEY_ROTATION_OVERDUE', { store, keyId: e.keyId, daysOverdue: e.daysOverdue, source: 'PERIODIC_MONITOR', rotateCommand: _rotateCommand(store) });
      }
      expiring += (r.expiredKeys || []).length + (r.expiringKeys || []).length;
      overdue += (r.overdueKeys || []).length;
    } catch (err) {
      try { emit('WARN', 'KEY_EXPIRY_MONITOR_CHECK_FAILED', { store, error: err.message }); } catch { /* never throw */ }
    }
  }
  return { expiring, overdue };
}

function _tick() {
  try {
    const { validateKeyStore } = require('./keyStore');
    const ks = validateKeyStore();

    for (const e of ks.expiringKeys) {
      emit('WARN', 'KEY_EXPIRING_SOON', {
        clientId: e.clientId, keyId: e.keyId, daysRemaining: e.daysRemaining, source: 'PERIODIC_MONITOR',
      });
    }
    for (const e of ks.overdueKeys) {
      emit('WARN', 'KEY_ROTATION_OVERDUE', {
        clientId: e.clientId, keyId: e.keyId, daysOverdue: e.daysOverdue, source: 'PERIODIC_MONITOR',
      });
    }

    const ed = _checkEd25519Stores();
    _refreshMetrics(ks.expiringKeys.length + ed.expiring, ks.overdueKeys.length + ed.overdue);
  } catch (err) {
    // Background monitoring must never affect the process — a failure here
    // (e.g. key store transiently unreadable) is itself worth a log line,
    // but must not throw out of the timer callback.
    try { emit('WARN', 'KEY_EXPIRY_MONITOR_CHECK_FAILED', { error: err.message }); } catch { /* never throw */ }
  }
}

/**
 * Start periodic key expiry re-validation. Idempotent — safe to call
 * multiple times; only the first call has any effect. Call once from
 * server/startup.js, after keyManager.validateStartup() has already
 * confirmed the key store is structurally valid.
 */
function initialize() {
  if (_timer) return;
  if (process.env.QODIQA_KEY_EXPIRY_MONITOR_ENABLED === 'false') {
    emit('WARN', 'KEY_EXPIRY_MONITOR_DISABLED', {
      message: 'Periodic key expiry re-validation disabled via QODIQA_KEY_EXPIRY_MONITOR_ENABLED=false',
    });
    return;
  }

  _timer = setInterval(_tick, CHECK_INTERVAL_MS);
  if (typeof _timer.unref === 'function') _timer.unref();

  emit('INFO', 'KEY_EXPIRY_MONITOR_STARTED', { checkIntervalMs: CHECK_INTERVAL_MS });
}

/** Stop monitoring. Safe to call multiple times. */
function shutdown() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
}

module.exports = { initialize, shutdown, isEnabled, _rotateCommand };
