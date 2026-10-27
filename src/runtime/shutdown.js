'use strict';

/**
 * Graceful shutdown controller.
 *
 * Registers SIGTERM and SIGINT handlers and executes a deterministic,
 * ordered shutdown sequence exactly once:
 *
 *   1. Mark service as NOT READY  (requestDrain.beginShutdown)
 *   2. Stop accepting new TCP connections  (httpServer.close)
 *   3. Wait for in-flight requests to drain
 *   4. Close Redis connections  (each store.disconnect via Promise.allSettled)
 *   5. Confirm audit writes are durable  (sync-fsynced on every append — no flush needed)
 *   5b. Disconnect any stores the audit flush itself depended on (opts.postFlushStores)
 *   6. Exit cleanly  (process.exit(0))
 *
 * postFlushStores exists for QODIQA_AUDIT_ORDERING_MODE=distributed: pending
 * appends drained in step 5 depend on PostgreSQL being reachable to commit
 * (it's the ordering authority — see distributedOrdering.js), so PG_POOL
 * must be disconnected AFTER the flush, not alongside the other stores in
 * step 4. server.js decides which stores go in which list based on the
 * active ordering mode; this module stays audit-mode-agnostic.
 *
 * Rationale for step 1 before step 2:
 *   httpServer.close() stops new TCP accepts but does NOT block requests that
 *   arrive on existing keep-alive connections.  beginShutdown() must fire first
 *   so the requestDrain middleware returns 503 for ALL new requests — including
 *   keep-alive traffic — before any request can enter the enforcement pipeline.
 *
 * If total shutdown time exceeds SHUTDOWN_TIMEOUT_MS the force-exit timer fires,
 * emits SHUTDOWN_TIMEOUT, and calls exit(1).
 *
 * Redis disconnect failures do NOT block shutdown (Promise.allSettled semantics):
 *   REDIS_SHUTDOWN_FAILED is emitted per failing store; shutdown continues.
 *
 * Env:
 *   SHUTDOWN_TIMEOUT_MS  — ms before forced exit (default: 30000)
 */

const { emit, flush } = require('../../services/logger');

const SHUTDOWN_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.SHUTDOWN_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 30_000;
})();

let _shutdownStarted = false;

/**
 * Disconnects a list of { name, store } entries via Promise.allSettled — a
 * failing disconnect never aborts the caller's shutdown sequence. Shared by
 * step 4 and step 5b of executeShutdown().
 */
async function _disconnectStores(stores) {
  await Promise.allSettled((stores || []).map(async ({ name, store }) => {
    try {
      await store.disconnect();
      emit('INFO', 'REDIS_SHUTDOWN_COMPLETED', { source: name });
    } catch (err) {
      emit('ERROR', 'REDIS_SHUTDOWN_FAILED', {
        source: name,
        error:  err.message,
        note:   'disconnect failed — shutdown continues',
      });
    }
  }));
}

/**
 * Execute the ordered shutdown sequence.
 *
 * Safe to call multiple times — only the first invocation executes; all
 * subsequent calls return immediately (single-execution guarantee).
 *
 * @param {import('http').Server|null} httpServer
 * @param {Array<{ name: string, store: { disconnect(): Promise<void> } }>} stores
 * @param {object}   [opts]
 * @param {number}   [opts.timeoutMs]        Override SHUTDOWN_TIMEOUT_MS for this run.
 * @param {Array<{ name: string, store: { disconnect(): Promise<void> } }>} [opts.postFlushStores]
 *   Stores to disconnect AFTER the audit flush (step 5) instead of alongside
 *   step 4 — see module header comment.
 * @param {object}   [opts._requestDrain]  Injected drain module (for testing).
 * @param {Function} [opts._exit]          Injected exit function (for testing).
 */
async function executeShutdown(httpServer, stores, {
  timeoutMs        = SHUTDOWN_TIMEOUT_MS,
  postFlushStores  = [],
  preStoreHooks    = [],
  streamCancelAfterMs = null,
  _streamRegistry  = null,
  _requestDrain    = null,
  _readinessState  = null,
  _exit            = process.exit,
} = {}) {
  if (_shutdownStarted) return;
  _shutdownStarted = true;

  emit('INFO', 'SHUTDOWN_STARTED', { timeoutMs });

  // Force-exit if the shutdown sequence stalls.
  const _forceTimer = setTimeout(() => {
    emit('WARN', 'SHUTDOWN_TIMEOUT', {
      timeoutMs,
      message: 'Shutdown exceeded configured timeout — forcing process termination',
    });
    _exit(1);
  }, timeoutMs);

  // Allow the event loop to exit naturally if this becomes the only active handle.
  if (typeof _forceTimer.unref === 'function') _forceTimer.unref();

  try {
    // ── Step 1: Mark service as NOT READY ─────────────────────────────────────
    // Must happen before httpServer.close() so requests on keep-alive connections
    // receive 503 immediately — before any enforcement logic can execute.
    if (_readinessState) _readinessState.setReady(false);
    if (_requestDrain)   _requestDrain.beginShutdown();
    emit('INFO', 'SHUTDOWN_READY_FALSE');

    // ── Step 2: Stop accepting new TCP connections ────────────────────────────
    emit('INFO', 'SHUTDOWN_HTTP_CLOSE_STARTED');
    await new Promise(resolve => {
      if (!httpServer || typeof httpServer.close !== 'function') return resolve();
      httpServer.close(resolve);
    });
    emit('INFO', 'SHUTDOWN_HTTP_CLOSED');

    // ── Step 3: Wait for in-flight requests to drain ──────────────────────────
    emit('INFO', 'SHUTDOWN_DRAIN_STARTED', {
      active: _requestDrain ? _requestDrain.activeCount() : 0,
    });
    // an SSE stream may legitimately run STREAM_MAX_DURATION_MS (default 300 s),
    // far past this sequence's force-exit timer (SHUTDOWN_TIMEOUT_MS, default 30 s). Left alone, the force exit kills
    // it with its audit lifecycle open (INTENT + STREAM_OPENED, no closing DECISION). Streams get the first half of
    // the window to finish naturally; then every still-open stream is cancelled through its normal cancelled path
    // (terminationReason SERVER_SHUTDOWN, closing DECISION BLOCK written, terminal SSE event sent), leaving the
    // second half for those writes and the rest of this sequence. Best effort, like the pre-stream abandon path.
    const _streams = _streamRegistry || (() => { try { return require('../streaming/streamRegistry'); } catch { return null; } })();
    const _cancelAfter = Number.isFinite(streamCancelAfterMs) && streamCancelAfterMs >= 0 ? streamCancelAfterMs : Math.floor(timeoutMs / 2);
    const _streamCancelTimer = _streams && typeof _streams.cancelAll === 'function'
      ? setTimeout(() => {
        const active = typeof _streams.activeCount === 'function' ? _streams.activeCount() : null;
        const cancelled = _streams.cancelAll('server_shutdown');
        emit('WARN', 'SHUTDOWN_STREAMS_CANCELLED', { active, cancelled, afterMs: _cancelAfter });
      }, _cancelAfter)
      : null;
    if (_streamCancelTimer && typeof _streamCancelTimer.unref === 'function') _streamCancelTimer.unref();
    try {
      if (_requestDrain) await _requestDrain.drain();
    } finally {
      if (_streamCancelTimer) clearTimeout(_streamCancelTimer);
    }
    emit('INFO', 'SHUTDOWN_DRAIN_COMPLETE', {
      active: _requestDrain ? _requestDrain.activeCount() : 0,
    });

    // ── Step 3a: one last try at the transparency leaves still buffered in memory; whatever is left is lost with the process, and says so ──
    try { await require('../core/transparency/journalHealth').flushOnShutdown(); } catch { /* never blocks shutdown */ }

    // ── Step 3b: Pre-store hooks ───────────────────
    // Work that needs every store still connected, after in-flight requests have drained and their audit writes have
    // settled: the final signed audit checkpoint (it persists to PostgreSQL and the sidecar). Each hook bounds itself
    // and never aborts shutdown.
    if (preStoreHooks.length > 0) {
      try { const { drainPendingWrites } = require('../core/audit/audit-log'); await drainPendingWrites(); } catch { /* step 5 reports */ }
      for (const { name, run } of preStoreHooks) {
        try { await run(); } catch (err) { emit('ERROR', 'SHUTDOWN_HOOK_FAILED', { hook: name, error: err.message }); }
      }
    }

    // ── Step 4: Close Redis connections ───────────────────────────────────────
    // Promise.allSettled: a failing disconnect does NOT abort shutdown.
    emit('INFO', 'REDIS_SHUTDOWN_STARTED');
    await _disconnectStores(stores);

    // ── Step 5: Drain in-flight audit writes ──────────────────────────────────
    // audit-log.js serializes appends through an async FIFO queue (fsynced on
    // the libuv threadpool, not the event loop) so a request can still have a
    // durable write in flight at shutdown time. Wait for it to settle before
    // exiting so no audit entry is lost or left partially committed.
    emit('INFO', 'SHUTDOWN_AUDIT_FLUSH_STARTED');
    try {
      const { drainPendingWrites } = require('../core/audit/audit-log');
      await drainPendingWrites();
    } catch (err) {
      emit('ERROR', 'SHUTDOWN_AUDIT_FLUSH_FAILED', { error: err.message });
    }
    emit('INFO', 'SHUTDOWN_AUDIT_FLUSH_COMPLETE');

    // ── Step 5b: Disconnect stores the audit flush depended on ────────────────
    // See module header comment / opts.postFlushStores doc above.
    if (postFlushStores.length > 0) {
      await _disconnectStores(postFlushStores);
    }

    // ── Step 6: Clean exit ────────────────────────────────────────────────────
    clearTimeout(_forceTimer);
    emit('INFO', 'SHUTDOWN_COMPLETE');
    // Operational log records are batched (see services/logger.js) — drain
    // the buffer explicitly here so nothing is left pending when _exit is a
    // test double that doesn't trigger the real process 'exit' safety net.
    await flush();
    _exit(0);
  } catch (err) {
    emit('ERROR', 'SHUTDOWN_ERROR', { error: err.message });
    clearTimeout(_forceTimer);
    await flush();
    _exit(1);
  }
}

/**
 * Register SIGTERM and SIGINT handlers.
 *
 * Both signals invoke the same ordered shutdown sequence.  The sequence
 * executes exactly once regardless of how many signals are received.
 *
 * @param {import('http').Server}  httpServer
 * @param {Array<{ name: string, store: { disconnect(): Promise<void> } }>} stores
 * @param {object}   [opts]
 * @param {number}   [opts.timeoutMs]        Override SHUTDOWN_TIMEOUT_MS.
 * @param {Array<{ name: string, store: { disconnect(): Promise<void> } }>} [opts.postFlushStores]
 *   Forwarded to executeShutdown() — see its doc comment.
 * @param {object}   [opts.requestDrain] Request drain module.
 * @param {Function} [opts._exit]        Override process.exit (for testing).
 */
function registerHandlers(httpServer, stores, {
  timeoutMs       = SHUTDOWN_TIMEOUT_MS,
  postFlushStores = [],
  preStoreHooks   = [],
  requestDrain    = null,
  readinessState  = null,
  _exit           = process.exit,
} = {}) {
  function _doShutdown(signal) {
    emit('INFO', 'SHUTDOWN_SIGNAL_RECEIVED', { signal });
    executeShutdown(httpServer, stores, {
      timeoutMs,
      postFlushStores,
      preStoreHooks,
      _requestDrain:   requestDrain,
      _readinessState: readinessState,
      _exit,
    });
  }

  process.on('SIGTERM', () => _doShutdown('SIGTERM'));
  process.on('SIGINT',  () => _doShutdown('SIGINT'));
}

/** Reset module state. Only for use in test environments. */
function _reset() {
  _shutdownStarted = false;
}

module.exports = {
  registerHandlers,
  executeShutdown,
  SHUTDOWN_TIMEOUT_MS,
  _reset,
};
