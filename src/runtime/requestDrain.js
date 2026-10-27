'use strict';

/**
 * In-flight request tracker with shutdown drain support.
 *
 * Middleware increments a counter when a request enters the pipeline and
 * decrements it exactly once when the response finishes or the connection
 * closes.  During shutdown, new requests are rejected with HTTP 503 before
 * they enter any enforcement logic.
 *
 * Design invariants:
 *   • Counter never goes negative — _decrement is idempotent per-response.
 *   • No request is counted after beginShutdown() is called.
 *   • drain() resolves only when the counter reaches zero.
 *   • Module state is isolated; _reset() restores it for test environments.
 */

let _active       = 0;
let _shuttingDown = false;

/**
 * Express middleware.
 *
 * Returns HTTP 503 SERVICE_SHUTTING_DOWN if shutdown has begun.
 * Otherwise increments the active-request counter and schedules a decrement
 * on response finish or connection close.
 */
function middleware(req, res, next) {
  if (_shuttingDown) {
    return res.status(503).json({
      success: false,
      error: {
        code:    'SERVICE_SHUTTING_DOWN',
        message: 'Service unavailable',
      },
    });
  }

  _active++;

  let _done = false;
  function _decrement() {
    if (!_done) {
      _done = true;
      if (_active > 0) _active--;
    }
  }

  res.on('finish', _decrement);
  res.on('close',  _decrement);
  next();
}

/**
 * Mark the service as shutting down.  After this call, all new requests
 * receive HTTP 503 and are not counted.
 */
function beginShutdown() {
  _shuttingDown = true;
}

/** @returns {boolean} */
function isShuttingDown() {
  return _shuttingDown;
}

/** @returns {number} Current number of active (in-flight) requests. */
function activeCount() {
  return _active;
}

/**
 * Resolves when the active-request counter reaches zero.
 *
 * Polls via setImmediate so the event loop continues processing responses
 * while waiting.  The caller is responsible for enforcing an outer timeout
 * (e.g. the SHUTDOWN_TIMEOUT force-exit timer in shutdown.js).
 *
 * @returns {Promise<void>}
 */
function drain() {
  return new Promise(resolve => {
    (function check() {
      if (_active === 0) return resolve();
      setImmediate(check);
    }());
  });
}

/** Reset module state.  Only for use in test environments. */
function _reset() {
  _active       = 0;
  _shuttingDown = false;
}

module.exports = { middleware, beginShutdown, isShuttingDown, activeCount, drain, _reset };
