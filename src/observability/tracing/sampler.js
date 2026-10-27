'use strict';

// Deterministic head-based sampler.
//
// Sampling decision is made once per trace (at root span creation) based on
// the first 8 hex digits of the traceId, which are mapped to a float in
// [0, 1).  This produces stable sampling: the same traceId always yields
// the same decision regardless of which service or replica is evaluating it.
//
//   rate 1.0 → 100% sampled
//   rate 0.5 → ~50% sampled  (first 8 hex < 0x80000000)
//   rate 0.0 → 0%  sampled

/**
 * @param {number} rate  — float in [0, 1], defaults to 1.0
 * @returns {{ shouldSample(traceId: string): boolean, rate: number }}
 */
function createSampler(rate) {
  const _rate = (typeof rate === 'number' && rate >= 0 && rate <= 1) ? rate : 1.0;

  function shouldSample(traceId) {
    if (_rate >= 1.0) return true;
    if (_rate <= 0.0) return false;
    const n = parseInt((traceId || '').slice(0, 8), 16);
    if (isNaN(n)) return false;
    return n / 0xFFFFFFFF < _rate;
  }

  return { shouldSample, rate: _rate };
}

module.exports = { createSampler };
