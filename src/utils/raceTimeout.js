'use strict';

/**
 *`Promise.race([work, new Promise(... setTimeout(reject) ...)])` left its timer
 * armed after the work won (an unref-less timer kept the event loop alive and fired a stray rejection into a settled
 * race) at several call sites. This is the one shape they share: the timer is unref'd and ALWAYS cleared once the
 * race settles, whichever side wins. It does not cancel the losing work — a caller that can stop its work passes an
 * AbortSignal to it as well (see aiChat.js).
 *
 * @param {Promise} work
 * @param {number} ms
 * @param {() => Error} makeError  the rejection when the timer wins
 */
function raceTimeout(work, ms, makeError) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => { timer = null; reject(makeError()); }, ms);
    if (timer.unref) timer.unref();
  });
  return Promise.race([work, timeout]).finally(() => { if (timer) { clearTimeout(timer); timer = null; } });
}

module.exports = { raceTimeout };
