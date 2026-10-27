'use strict';

/**
 * a process-local MONOTONIC millisecond clock, for comparisons between two readings taken in the SAME
 * process lifetime (deadlines, windows, a token minted and verified here).
 *
 * Why not Date.now(): on Windows V8 re-syncs Date.now() to the system time every 60 s of process uptime and can step
 * it back 1 ms, so a later reading can
 * be SMALLER than an earlier one.
 *
 * monoNowMs() = floor(performance.timeOrigin + performance.now()): timeOrigin is fixed at process start and
 * performance.now() never goes backwards, so the value never decreases. It is epoch-anchored (same magnitude as
 * Date.now()), but it does not follow system-time corrections, so it may drift from wall time over a long uptime:
 * never persist it, send it to another process, or compare it with a wall-clock timestamp. Cross-process or persisted
 * times stay on the wall clock (or database time) with their skew tolerance.
 */

const { performance } = require('perf_hooks');

function monoNowMs() {
  return Math.floor(performance.timeOrigin + performance.now());
}

/**
 *the WALL-clock equivalent of a monotonic stamp, for display only (status / health objects).
 * A monotonic stamp must never be exposed as an epoch time (it does not follow wall-clock corrections); this reports
 * the wall time that is the same elapsed interval ago. null/0 stays null.
 */
function wallFromMono(monoStamp) {
  if (!monoStamp) return null;
  return Date.now() - (monoNowMs() - monoStamp);
}

module.exports = { monoNowMs, wallFromMono };
