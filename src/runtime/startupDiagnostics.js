'use strict';

/**
 * Startup and clock diagnostics.
 *
 * Emits two structured events once during application startup:
 *
 *   STARTUP_DIAGNOSTICS — Node version, environment, PID, timestamp,
 *                         Redis configuration status, audit log configuration,
 *                         active signing key count, policy count.
 *
 *   CLOCK_DIAGNOSTICS   — UTC time, local time, timezone, UTC offset.
 *                         QODIQA relies on accurate system time for artifact
 *                         TTL enforcement and replay protection.
 *
 * Security invariants:
 *   • Never logs raw secrets, tokens, passwords, or private key material.
 *   • Redis URL is logged in redacted form (credentials replaced with [REDACTED]).
 *   • Key availability is reported as a count only — no key material is emitted.
 *   • Audit log path is logged as a filesystem path, not file contents.
 *
 * No external network calls are made.  No NTP queries are performed.
 * These are purely local diagnostic snapshots.
 */

const { getConfigSummary } = require('../infra/redis/clientConfig');
const { emit } = require('../../services/logger');

/**
 * Emit STARTUP_DIAGNOSTICS.
 *
 * Callers pass in already-computed state (active key count, policy count) so
 * this function does not re-derive values that startup has already validated.
 *
 * @param {object} [opts]
 * @param {number} [opts.activeKeys]   Number of active signing keys.
 * @param {number} [opts.policyCount]  Number of loaded policies.
 */
function emitStartupDiagnostics({ activeKeys = 0, policyCount = 0 } = {}) {
  const cfg = getConfigSummary();

  emit('INFO', 'STARTUP_DIAGNOSTICS', {
    nodeVersion:        process.version,
    environment:        process.env.NODE_ENV || 'unset',
    pid:                process.pid,
    startupTimestamp:   new Date().toISOString(),
    redisUrl:           cfg.urlRedacted,        // credentials already redacted
    redisAuthConfigured: cfg.authConfigured,
    redisTlsEnabled:    cfg.tlsEnabled,
    redisTlsVerified:   cfg.tlsVerified,
    auditLogConfigured: !!process.env.QODIQA_AUDIT_LOG,
    auditLogPath:       process.env.QODIQA_AUDIT_LOG || 'default',
    activeSigningKeys:  activeKeys,
    policiesLoaded:     policyCount,
  });
}

/**
 * Emit CLOCK_DIAGNOSTICS.
 *
 * Records a snapshot of the system clock state at startup.  QODIQA uses
 * system time for artifact timestamp validation, TTL enforcement, and replay
 * protection.  A misconfigured clock causes legitimate artifacts to be
 * rejected or expired artifacts to be accepted.
 *
 * No NTP queries are made.  This is a local diagnostic only.
 */
function emitClockDiagnostics() {
  const now      = new Date();
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  emit('INFO', 'CLOCK_DIAGNOSTICS', {
    utcTime:       now.toISOString(),
    localTime:     now.toString(),
    timezone,
    offsetMinutes: now.getTimezoneOffset(),
    timestampSource: 'system-clock',
  });
}

module.exports = { emitStartupDiagnostics, emitClockDiagnostics };
