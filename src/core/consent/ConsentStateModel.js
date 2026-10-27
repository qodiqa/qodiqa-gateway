'use strict';

/**
 * ConsentStateModel — consent lifecycle state machine.
 *
 * Valid states: PENDING → ACTIVE ↔ SUSPENDED → REVOKED | EXPIRED
 * REVOKED and EXPIRED are terminal.
 *
 * Transitions:
 *   PENDING   → ACTIVE      (grant activated)
 *   PENDING   → REVOKED     (revoked before activation)
 *   ACTIVE    → REVOKED     (explicit revocation)
 *   ACTIVE    → EXPIRED     (expires_at reached — enforced at lookup time)
 *   ACTIVE    → SUSPENDED   (temporary hold)
 *   SUSPENDED → ACTIVE      (suspension lifted or suspended_until reached)
 *   SUSPENDED → REVOKED     (revoked while suspended)
 */

const STATE = Object.freeze({
  PENDING:   'PENDING',
  ACTIVE:    'ACTIVE',
  REVOKED:   'REVOKED',
  EXPIRED:   'EXPIRED',
  SUSPENDED: 'SUSPENDED',
});

// Valid transition map: state → Set of reachable states
const TRANSITIONS = Object.freeze({
  [STATE.PENDING]:   new Set([STATE.ACTIVE, STATE.REVOKED]),
  [STATE.ACTIVE]:    new Set([STATE.REVOKED, STATE.EXPIRED, STATE.SUSPENDED]),
  [STATE.SUSPENDED]: new Set([STATE.ACTIVE, STATE.REVOKED]),
  [STATE.REVOKED]:   new Set(),   // terminal
  [STATE.EXPIRED]:   new Set(),   // terminal
});

const TERMINAL_STATES = new Set([STATE.REVOKED, STATE.EXPIRED]);

/**
 * @param {string} from
 * @param {string} to
 * @returns {boolean}
 */
function isValidTransition(from, to) {
  return !!(TRANSITIONS[from] && TRANSITIONS[from].has(to));
}

/**
 * @param {any} state
 * @returns {boolean}
 */
function isTerminal(state) {
  return TERMINAL_STATES.has(state);
}

/**
 * @param {string} state
 * @returns {boolean}
 */
function isValid(state) {
  return Object.prototype.hasOwnProperty.call(TRANSITIONS, state);
}

/**
 * Determine the effective state of a record at the current instant.
 * A record with state=ACTIVE and a past expires_at is effectively EXPIRED.
 * A record with state=SUSPENDED and a passed suspended_until auto-resumes to ACTIVE.
 *
 * @param {{ state: string, expires_at: Date|null, suspended_until: Date|null }} record
 * @param {Date} [now] - override for testing
 * @returns {string} effective state
 */
function effectiveState(record, now = new Date()) {
  const { state, expires_at, suspended_until } = record;

  if (state === STATE.ACTIVE && expires_at && expires_at <= now) {
    return STATE.EXPIRED;
  }

  if (state === STATE.SUSPENDED && suspended_until && suspended_until <= now) {
    return STATE.ACTIVE;
  }

  return state;
}

/**
 * Return true if the record's effective state is ACTIVE right now.
 *
 * @param {object} record
 * @param {Date}   [now]
 * @returns {boolean}
 */
function isActiveNow(record, now = new Date()) {
  return effectiveState(record, now) === STATE.ACTIVE;
}

module.exports = { STATE, TRANSITIONS, isValidTransition, isTerminal, isValid, effectiveState, isActiveNow };
