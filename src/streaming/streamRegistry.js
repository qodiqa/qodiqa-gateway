'use strict';

/**
 * Stream Registry — in-memory tracker for active streaming sessions.
 *
 * Design properties:
 *   • Pure in-memory.  No I/O.  Module-level singleton.
 *   • All public methods are infallible — they never throw.
 *   • Single-threaded Node.js guarantee: no atomicity primitives needed.
 *   • No payload content, no secrets stored.
 */

const crypto = require('crypto');

const _active = new Map();
// per-stream cancel callbacks (set by streamEnforcer once its AbortController exists) so graceful shutdown
// can end every still-open stream through its normal cancelled path — which writes the closing DECISION — instead
// of the force-exit timer killing the process with the lifecycle left open.
const _cancellers = new Map();
let _cancelAllReason = null;

/**
 * Register a new active stream and return its unique ID.
 */
function createStream({ requestId, artifactId, provider, model, tenantId, organizationId }) {
  try {
    const streamId  = crypto.randomUUID();
    const startTime = Date.now();

    _active.set(streamId, {
      streamId,
      requestId:         typeof requestId      === 'string' ? requestId      : null,
      artifactId:        typeof artifactId     === 'string' ? artifactId     : null,
      provider:          typeof provider       === 'string' ? provider       : null,
      model:             typeof model          === 'string' ? model          : null,
      tenantId:          typeof tenantId       === 'string' ? tenantId       : null,
      organizationId:    typeof organizationId === 'string' ? organizationId : null,
      startTime,
      completionTime:    null,
      bytesStreamed:     0,
      chunksStreamed:    0,
      terminationReason: null,
      status:            'active',
    });

    return streamId;
  } catch {
    return crypto.randomUUID();
  }
}

/**
 * Return a snapshot copy of the stream state, or null if not found.
 */
function getStream(streamId) {
  try {
    const s = _active.get(streamId);
    return s ? { ...s } : null;
  } catch {
    return null;
  }
}

/**
 * Increment byte and chunk counters for an active stream.
 */
function recordChunk(streamId, byteCount) {
  try {
    const state = _active.get(streamId);
    if (!state) return;
    state.bytesStreamed  += (typeof byteCount === 'number' && byteCount > 0) ? byteCount : 0;
    state.chunksStreamed += 1;
  } catch { /* infallible */ }
}

/**
 * Finalize a stream: record completion metadata and remove it from the active set.
 *
 * @returns {object|null}  Final snapshot, or null if the streamId was not found.
 */
function finalizeStream(streamId, { terminationReason, status }) {
  try {
    const state = _active.get(streamId);
    if (!state) return null;

    state.completionTime    = Date.now();
    state.terminationReason = typeof terminationReason === 'string' ? terminationReason : 'UNKNOWN';
    state.status            = typeof status === 'string' ? status : 'unknown';

    _active.delete(streamId);
    _cancellers.delete(streamId);
    return { ...state };
  } catch {
    return null;
  }
}

/**
 * Number of currently active streaming sessions.
 */
function activeCount() {
  try { return _active.size; } catch { return 0; }
}

/**
 * register the cancel callback for an active stream. If cancelAll() already ran (shutdown in progress), the
 * callback is invoked immediately — a stream that reaches dispatch after shutdown began is cancelled, not started.
 */
function setCanceller(streamId, fn) {
  try {
    if (typeof fn !== 'function' || !_active.has(streamId)) return;
    if (_cancelAllReason !== null) { fn(_cancelAllReason); return; }
    _cancellers.set(streamId, fn);
  } catch { /* infallible */ }
}

/**
 * cancel every active stream that has a registered canceller (graceful shutdown). Returns the number of
 * cancel callbacks invoked. Latches, so later setCanceller() calls cancel immediately.
 */
function cancelAll(reason = 'server_shutdown') {
  let n = 0;
  try {
    _cancelAllReason = reason;
    for (const fn of [..._cancellers.values()]) { try { fn(reason); n++; } catch { /* one stream never blocks the rest */ } }
  } catch { /* infallible */ }
  return n;
}

function _resetForTests() { _active.clear(); _cancellers.clear(); _cancelAllReason = null; }

module.exports = { createStream, getStream, recordChunk, finalizeStream, activeCount, setCanceller, cancelAll, _resetForTests };
