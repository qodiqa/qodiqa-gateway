'use strict';

/**
 * SSE connection manager for the dashboard real-time stream.
 *
 * Subscribes to the DashboardBus instead of services/logger directly.
 * This removes the direct dependency on the logger module and makes the
 * SSE transport swappable (LocalEventBus today, RedisPubSub tomorrow).
 *
 * Each connected client receives:
 *   'log' events      — every structured log record (real-time)
 *   'snapshot' events — periodic overview + status snapshot (≤5 s)
 *   keep-alive        — SSE comment line every 25 s (prevents proxy timeout)
 *
 * Connections are tracked by a monotonically increasing numeric ID.
 * When a client disconnects, it is removed and, if it was the last client,
 * the periodic timers are cleared so they don't prevent process exit.
 */

const dashboardBus    = require('./bus');
const { getOverview } = require('./aggregator');
const { getStatus }   = require('./statusChecker');
const _defaultTaskRunner = require('../runtime/backgroundTasks/BackgroundTaskRunner');

const SNAPSHOT_INTERVAL_MS = 5_000;
const KEEP_ALIVE_MS        = 25_000;

let _nextId         = 1;
const _clients      = new Map();   // id → { res, backpressured }
let _snapshotTimer  = null;
let _keepAliveTimer = null;

// ── Internal ──────────────────────────────────────────────────────────────────

// #7: res.write() returns false (not an exception) when the
// underlying socket's internal buffer is full — a slow/stalled client that
// never throws but also never drains. Left unchecked, every periodic
// snapshot tick keeps calling write() and buffering more data for that one
// client, unbounded, until it either catches up or disconnects. 'log'
// events (the audit-adjacent signal) stay full-priority regardless — only
// 'snapshot' (a periodic convenience refresh; the client gets the next one
// in SNAPSHOT_INTERVAL_MS anyway) is droppable under backpressure.
function _isBackpressured(client) {
  return client.backpressured === true;
}

function _markBackpressured(client, res) {
  if (client.backpressured) return;
  client.backpressured = true;
  res.once('drain', () => {
    client.backpressured = false;
  });
}

function _recordBackpressureSkip(eventName) {
  try {
    require('../observability/metrics').dashboardSseBackpressureEventsTotal.inc({ eventName });
  } catch { /* metrics must never affect the broadcast */ }
}

function _send(client, eventName, data) {
  const { res } = client;
  try {
    const ok = res.write(`event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`);
    if (ok === false) _markBackpressured(client, res);
  } catch { /* client disconnected mid-write — silently discard */ }
}

function _broadcast(eventName, data) {
  for (const client of _clients.values()) {
    if (eventName === 'snapshot' && _isBackpressured(client)) {
      _recordBackpressureSkip(eventName);
      continue;
    }
    _send(client, eventName, data);
  }
}

function _startTimers({ _taskRunner = _defaultTaskRunner } = {}) {
  if (_snapshotTimer) return;

  // Finding 3.6: runs through BackgroundTaskRunner for consistent
  // isolation/logging/metrics across every background job (replaces the
  // previous local try/catch that silently skipped the tick on failure).
  _snapshotTimer = setInterval(() => {
    if (_clients.size === 0) return;
    _taskRunner.runTask('dashboard-sse-snapshot', () => {
      _broadcast('snapshot', {
        overview:  getOverview(),
        status:    getStatus(),
        timestamp: new Date().toISOString(),
      });
    }).catch(() => { /* non-critical task never rejects; belt-and-suspenders */ });
  }, SNAPSHOT_INTERVAL_MS);

  _keepAliveTimer = setInterval(() => {
    // Keep-alive is a single comment line — negligible size, always sent
    // regardless of backpressure state (it's what lets a stalled-but-still-
    // connected client's proxy avoid an idle timeout in the first place).
    for (const { res } of _clients.values()) {
      try { res.write(': keep-alive\n\n'); } catch { /* disconnected */ }
    }
  }, KEEP_ALIVE_MS);

  // Unref so these timers don't prevent process exit during testing.
  if (_snapshotTimer.unref)  _snapshotTimer.unref();
  if (_keepAliveTimer.unref) _keepAliveTimer.unref();
}

function _stopTimers() {
  if (_snapshotTimer)  { clearInterval(_snapshotTimer);  _snapshotTimer  = null; }
  if (_keepAliveTimer) { clearInterval(_keepAliveTimer); _keepAliveTimer = null; }
}

// ── DashboardBus subscription (module-level singleton) ────────────────────────
// All log records are forwarded to connected SSE clients.
// The DashboardBus bridges from services/logger so this module no longer
// depends on services/logger directly.
dashboardBus.subscribe('log', (record) => {
  if (_clients.size === 0) return;
  _broadcast('log', record);
});

// ── Public API ────────────────────────────────────────────────────────────────

function addClient(res) {
  const id = _nextId++;
  const client = { res, backpressured: false };
  _clients.set(id, client);
  _startTimers();

  // Immediate snapshot — client UI populates without waiting for the first tick.
  try {
    _send(client, 'snapshot', {
      overview:  getOverview(),
      status:    getStatus(),
      timestamp: new Date().toISOString(),
    });
  } catch { /* client disconnected before first write */ }

  return id;
}

function removeClient(id) {
  _clients.delete(id);
  if (_clients.size === 0) _stopTimers();
}

function clientCount() {
  return _clients.size;
}

module.exports = { addClient, removeClient, clientCount };
