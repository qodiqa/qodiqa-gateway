'use strict';

// a published key set must say WHEN each key was activated and retired, otherwise an offline verifier
// cannot tell whether a signature made at time T was made by a key that was valid at T. The dates are public lifecycle facts a
// verifier needs; the earlier "omit createdAt to avoid timing-based correlation of rotation events" note (well-known.js) is
// kept as an opt-out: QODIQA_PUBLIC_KEY_DATES=false restores the previous dateless shape.
function publicKeyDatesEnabled() {
  return String(process.env.QODIQA_PUBLIC_KEY_DATES || 'true').toLowerCase() !== 'false';
}

/** @returns {{activatedAt: string|null, retiredAt: string|null}|{}} */
function keyDates(k) {
  if (!publicKeyDatesEnabled()) return {};
  return {
    activatedAt: k.createdAt || null,
    // 'retiredAt' is set when a key stops being the signing key (deprecated); null while active.
    retiredAt:   k.status === 'active' ? null : (k.retiredAt || null),
  };
}

module.exports = { keyDates, publicKeyDatesEnabled };
