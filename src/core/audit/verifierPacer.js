'use strict';

/**
 * — the chain verifier's cooperative yield.
 *
 * Everywhere, pace() is exactly the previous `new Promise((r) => setImmediate(r))` — unchanged behaviour. Inside the
 * verifier worker thread, setDutyCycle(0.5) turns each yield into a pause as long as the code worked since the
 * previous yield (capped at 1 s), so the worker uses at most about half of one core however long a run is.
 */

const { monoNowMs } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

let _duty = 0;
let _last = 0;

function setDutyCycle(fraction) {
  _duty = Number.isFinite(fraction) && fraction > 0 && fraction < 1 ? fraction : 0;
  _last = monoNowMs(); // monotonic (same-process)
}

function pace() {
  if (!_duty) return new Promise((resolve) => setImmediate(resolve));
  const worked = monoNowMs() - _last; // monotonic (same-process)
  const pause = Math.min(1000, Math.max(0, Math.round((worked * (1 - _duty)) / _duty)));
  return new Promise((resolve) => setTimeout(() => { _last = monoNowMs(); resolve(); }, pause)); // monotonic (same-process)
}

function dutyCycle() { return _duty; }

module.exports = { pace, setDutyCycle, dutyCycle };
