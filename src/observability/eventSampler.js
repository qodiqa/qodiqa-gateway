'use strict';

/**
 * Per-key log sampler —.
 *
 * Every WARN event is ingested into platform_audit_events (centralStore), so an
 * event emitted once per rejected request turns an unauthenticated flood into
 * one database row per request. Events on such paths are sampled per key
 * (e.g. surface + client identity): the first `first` per window, then every
 * `every`-th. Suppressed volume is reported once per window by `summaryEvent`.
 * Tracking is bounded (`maxKeys`); keys beyond it are counted, not stored.
 * Metrics are NOT sampled — counters still see every request.
 */

const { emit } = require('../../services/logger');

/** @param {{ first?: number, every?: number, windowMs?: number, maxKeys?: number, summaryEvent?: string, now?: () => number }} [opts] */
function createEventSampler({ first = 10, every = 100, windowMs = 60_000, maxKeys = 10_000, summaryEvent, now = Date.now } = {}) {
  if (!summaryEvent) throw new TypeError('createEventSampler: summaryEvent is required');
  let win = { start: now(), counts: new Map(), suppressed: 0 };
  function roll(t) {
    if (t - win.start < windowMs) return;
    if (win.suppressed > 0) emit('WARN', summaryEvent, { suppressed: win.suppressed, windowMs, distinctKeys: win.counts.size });
    win = { start: t, counts: new Map(), suppressed: 0 };
  }
  /** @returns {{ log: boolean, countThisWindow: number }} */
  function sample(key) {
    roll(now());
    if (!win.counts.has(key) && win.counts.size >= maxKeys) { win.suppressed++; return { log: false, countThisWindow: 0 }; }
    const n = (win.counts.get(key) || 0) + 1;
    win.counts.set(key, n);
    const log = n <= first || n % every === 0;
    if (!log) win.suppressed++;
    return { log, countThisWindow: n };
  }
  function reset() { win = { start: now(), counts: new Map(), suppressed: 0 }; }
  return { sample, reset };
}

module.exports = { createEventSampler };
