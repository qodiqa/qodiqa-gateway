'use strict';

/**
 * Best-effort CRITICAL notification for fail-safe startup gates that run
 * before src/alerting has initialized (MON-3).
 *
 * src/core/audit/multiInstanceGuard.js's checkSingleInstance() calls
 * process.exit(1) synchronously at server.js's module top level, well before
 * alertingFramework.initialize() runs — so it structurally cannot route a
 * notification through src/alerting/notification/NotificationService.js.
 * This module is a minimal, dependency-free alternative for that one case,
 * following the exact same contract as scripts/dr/alert.js's postAlert():
 * no-op if unconfigured, never throws, never blocks or delays the caller's
 * primary action.
 *
 * Deliberately NOT awaited by callers. The multi-instance guard's exit must
 * stay synchronous and immediate — a genuine multi-instance violation must
 * not let either process continue running (even briefly) while a webhook
 * call is in flight, since further startup code does emit audit-persisted
 * events. Delivery here is therefore opportunistic: it fires the request
 * and lets the process exit, relying on the OS to keep transmitting an
 * already-flushed TCP write after the Node process dies. The always-reliable
 * signal remains the synchronous stderr FATAL line written by
 * src/runtime/rawStderrDiagnostic.js — this is a best-effort enhancement on
 * top of that, not a replacement for it.
 */

const os = require('os');

const DEFAULT_TIMEOUT_MS = 3000;

function _timeoutMs() {
  const v = parseInt(process.env.QODIQA_CRITICAL_NOTIFY_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_TIMEOUT_MS;
}

function _nodeId() {
  return process.env.NODE_APP_INSTANCE ?? process.env.HOSTNAME ?? String(process.pid);
}

/**
 * Fire a best-effort CRITICAL webhook notification for a fatal startup
 * failure. Reads ALERT_WEBHOOK_URL directly (shared generic ops webhook —
 * see deploy/env/production.env.example). No-ops if unset. Never throws, never
 * rejects — always resolves.
 *
 * @param {object} opts
 * @param {string} opts.eventType       — SCREAMING_SNAKE_CASE event name
 * @param {string} opts.reason          — why startup was aborted
 * @param {string} [opts.action]        — recommended remediation
 * @param {string} [opts.deploymentMode]— e.g. 'single-node' | 'distributed'
 * @returns {Promise<void>}
 */
async function notifyCriticalStartupFailure({ eventType, reason, action, deploymentMode, ...extra }) {
  const url = process.env.ALERT_WEBHOOK_URL;
  if (!url) return;

  const payload = {
    text: `🚨 QODIQA CRITICAL STARTUP FAILURE: ${eventType} — ${reason ?? 'no reason given'}`,
    eventType,
    reason,
    action,
    hostname: os.hostname(),
    nodeId: _nodeId(),
    deploymentMode,
    timestamp: new Date().toISOString(),
    ...extra,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), _timeoutMs());
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
  } catch {
    // Never let notification failure surface to the caller — the guard's
    // exit(1) must proceed regardless of whether this delivered.
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { notifyCriticalStartupFailure };
