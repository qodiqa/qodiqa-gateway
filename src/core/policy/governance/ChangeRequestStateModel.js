'use strict';

/**
 * ChangeRequestStateModel — policy change-request lifecycle state machine.
 *
 * Mirrors src/core/consent/ConsentStateModel.js's shape exactly: a pure,
 * frozen, no-I/O module with an explicit transition map and guard
 * functions. This is the mechanism that makes "no direct Draft -> Active
 * transition may ever exist" a structural guarantee rather than
 * a convention — DRAFT and PUBLISHED are never adjacent in either mode.
 *
 * Strict mode (default — POLICY_GOVERNANCE_STRICT_MODE=false to relax):
 *   DRAFT -> SUBMITTED -> IN_REVIEW -> REVIEWED -> APPROVED -> [SCHEDULED] -> PUBLISHED
 *
 * Relaxed mode ("if enterprise mode requires" merge,'s own
 * qualifier): SUBMITTED may go straight to APPROVED, merging the reviewer
 * stage into the approver stage. This is the ONLY difference between the
 * two modes — DRAFT can still never reach PUBLISHED directly, and every
 * other transition is identical. Explicitly a reduced-assurance option;
 * documented in docs/guides/policy-governance.md.
 *
 * IN_REVIEW -> DRAFT models "changes requested": the reviewer sends the
 * proposal back to the author for rework rather than rejecting it outright.
 */

const STATE = Object.freeze({
  DRAFT:     'DRAFT',
  SUBMITTED: 'SUBMITTED',
  IN_REVIEW: 'IN_REVIEW',
  REVIEWED:  'REVIEWED',
  APPROVED:  'APPROVED',
  SCHEDULED: 'SCHEDULED',
  PUBLISHED: 'PUBLISHED',
  REJECTED:  'REJECTED',
  WITHDRAWN: 'WITHDRAWN',
  EXPIRED:   'EXPIRED',
});

const TERMINAL_STATES = new Set([STATE.PUBLISHED, STATE.REJECTED, STATE.WITHDRAWN, STATE.EXPIRED]);

const STRICT_TRANSITIONS = Object.freeze({
  [STATE.DRAFT]:     new Set([STATE.SUBMITTED, STATE.WITHDRAWN]),
  [STATE.SUBMITTED]: new Set([STATE.IN_REVIEW, STATE.WITHDRAWN]),
  [STATE.IN_REVIEW]: new Set([STATE.REVIEWED, STATE.DRAFT, STATE.WITHDRAWN]),
  [STATE.REVIEWED]:  new Set([STATE.APPROVED, STATE.REJECTED, STATE.WITHDRAWN]),
  [STATE.APPROVED]:  new Set([STATE.SCHEDULED, STATE.PUBLISHED, STATE.WITHDRAWN]),
  [STATE.SCHEDULED]: new Set([STATE.PUBLISHED, STATE.WITHDRAWN, STATE.EXPIRED]),
  [STATE.PUBLISHED]: new Set(),
  [STATE.REJECTED]:  new Set(),
  [STATE.WITHDRAWN]: new Set(),
  [STATE.EXPIRED]:   new Set(),
});

const RELAXED_TRANSITIONS = Object.freeze({
  ...STRICT_TRANSITIONS,
  [STATE.SUBMITTED]: new Set([STATE.IN_REVIEW, STATE.APPROVED, STATE.WITHDRAWN]),
});

/**
 * @param {string} from
 * @param {string} to
 * @param {boolean} [strict=true]
 * @returns {boolean}
 */
function isValidTransition(from, to, strict = true) {
  const map = strict ? STRICT_TRANSITIONS : RELAXED_TRANSITIONS;
  return !!(map[from] && map[from].has(to));
}

/**
 * @param {string} state
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
  return Object.prototype.hasOwnProperty.call(STRICT_TRANSITIONS, state);
}

module.exports = {
  STATE,
  TERMINAL_STATES,
  STRICT_TRANSITIONS,
  RELAXED_TRANSITIONS,
  isValidTransition,
  isTerminal,
  isValid,
};
