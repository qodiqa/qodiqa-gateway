'use strict';

/**
 * — a silent Redis partition must not hang requests.
 *
 * Root cause (verified in node_modules/@redis/client 5.12.1, commands-queue.js:392-394): a
 * command's `timeout` is REMOVED the moment the command is written to the socket. In a silent
 * partition (no RST — packets are simply dropped) the socket stays "open" and "ready", every
 * command is written immediately, and then waits for a reply that never comes: no error, no
 * event, no timeout. The audit observed exactly that: every request hung until the CLIENT gave
 * up (20 s), the server logged nothing, and /health and /ready stayed 200.
 *
 * This module supplies the two missing pieces, applied by managedClient.js:
 *   1. a DEADLINE on every command promise — a command that has not settled within
 *      REDIS_COMMAND_DEADLINE_MS rejects with code REDIS_COMMAND_DEADLINE_EXCEEDED, so every
 *      caller (nonce store, rate limiter, lockout, idempotency, consent cache …) fails CLOSED
 *      promptly instead of hanging;
 *   2. STALL accounting — consecutive deadline misses (from traffic or from the watchdog PING)
 *      mark the connection stuck; managedClient then tears the socket down (pending commands are
 *      flushed with errors, isReady → false so /ready reports it) and its existing self-healing
 *      recovery opens a FRESH connection. A late reply on the old socket can no longer desync a
 *      new command: that socket is gone.
 *
 * A late reply to a deadline-missed command on a still-live socket is harmless: node-redis keeps
 * the command in its waiting-for-reply queue (only toWrite.remove() runs on timeout), so replies
 * stay aligned; the already-rejected promise simply ignores the late resolution.
 */

const DEFAULTS = Object.freeze({ deadlineMs: 2000, watchdogIntervalMs: 2000, stallThreshold: 2 });

function _int(env, name, dflt, min, max) {
  const raw = env[name];
  if (raw === undefined || raw === '') return dflt;
  const v = Number(raw);
  return Number.isInteger(v) && v >= min && v <= max ? v : dflt;
}

/** Effective configuration. 0 disables a mechanism (refused in production by the boot validator). */
function resolveDeadlineConfig(env = process.env) {
  return {
    deadlineMs:         _int(env, 'REDIS_COMMAND_DEADLINE_MS', DEFAULTS.deadlineMs, 0, 60_000),
    watchdogIntervalMs: _int(env, 'REDIS_WATCHDOG_INTERVAL_MS', DEFAULTS.watchdogIntervalMs, 0, 60_000),
    stallThreshold:     _int(env, 'REDIS_STALL_THRESHOLD', DEFAULTS.stallThreshold, 1, 100),
  };
}

class RedisCommandDeadlineError extends Error {
  constructor(ms, command) {
    super(`Redis command ${command || ''} did not complete within ${ms} ms (connection stalled or partitioned)`.replace('  ', ' '));
    this.name = 'RedisCommandDeadlineError';
    this.code = 'REDIS_COMMAND_DEADLINE_EXCEEDED';
  }
}

/** Race `p` against a deadline. The timer is cleared on settle and never holds the process open. */
/** @param {any} p @param {number} ms @param {{ command?: string, onMiss?: Function, onSettled?: Function }} [opts] */
function withDeadline(p, ms, { command, onMiss, onSettled } = {}) {
  if (!ms || !p || typeof p.then !== 'function') return p;
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try { if (onMiss) onMiss(command); } catch { /* accounting never affects the caller */ }
      reject(new RedisCommandDeadlineError(ms, command));
    }, ms);
    if (timer.unref) timer.unref();
  });
  return Promise.race([
    Promise.resolve(p).then((v) => { clearTimeout(timer); try { if (onSettled) onSettled(true); } catch { /* */ } return v; },
      (e) => { clearTimeout(timer); try { if (onSettled) onSettled(false, e); } catch { /* */ } throw e; }),
    deadline,
  ]);
}

// Members of a node-redis client that are not "a command awaiting a reply": lifecycle,
// builders and long-lived/handle-returning calls. Everything else that returns a promise is
// raced against the deadline.
const NOT_COMMANDS = new Set([
  'connect', 'disconnect', 'quit', 'close', 'destroy', 'duplicate', 'multi', 'MULTI', 'executeIsolated',
  'on', 'once', 'off', 'removeListener', 'removeAllListeners', 'addListener', 'emit', 'listeners', 'listenerCount',
  'withCommandOptions', 'withTypeMapping', 'withAbortSignal', 'asap', 'legacy', 'createPool', 'unref', 'ref',
]);

function isCommandMember(prop) {
  return typeof prop === 'string' && !NOT_COMMANDS.has(prop) && !prop.startsWith('_');
}

module.exports = { DEFAULTS, resolveDeadlineConfig, RedisCommandDeadlineError, withDeadline, isCommandMember, NOT_COMMANDS };
