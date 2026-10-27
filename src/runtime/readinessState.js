'use strict';

/**
 * Centralized readiness state.
 *
 * Tracks one boolean: is QODIQA safe to receive traffic?
 *
 * Starts false.  Set to true by server.js after successful startup (keys
 * validated, policies loaded, Redis stores initialised).  Set to false
 * immediately when shutdown begins so that /ready returns 503 before any
 * in-flight request completes or any TCP connection is closed.
 *
 * Readiness is intentionally separated from liveness.  /health answers
 * "is the process alive?" (always true while the process runs).  /ready
 * answers "is it safe to send new enforcement traffic here?" — that
 * answer is false during startup and shutdown.
 *
 * Design invariants:
 *   • Starts false — never ready until explicitly set.
 *   • Set to true only after all startup invariants are confirmed.
 *   • Set to false before requestDrain.beginShutdown() in the shutdown sequence.
 *   • No lock needed — Node.js event loop is single-threaded.
 *   • _reset() restores initial state; only for test environments.
 */

let _ready = false;

/**
 * Set the readiness state.
 * @param {boolean} value
 */
function setReady(value) {
  _ready = Boolean(value);
}

/**
 * Return current readiness state.
 * @returns {boolean}
 */
function isReady() {
  return _ready;
}

/** Reset to initial state. Only for use in test environments. */
function _reset() {
  _ready = false;
}

module.exports = { setReady, isReady, _reset };
