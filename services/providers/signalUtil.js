'use strict';

/**
 * Shared AbortSignal composition helper.
 *
 * Provider adapters need to combine two independent cancellation sources —
 * the caller's signal (route-level timeout / client disconnect) and the
 * adapter's own per-call network timeout — into a single signal that aborts
 * when either fires.  Node 18 does not have AbortSignal.any(), so this is
 * implemented manually and shared across every adapter that needs it
 * (openai/anthropic/gemini non-streaming and streaming variants) instead of
 * being duplicated per file.
 */

/**
 * Compose two AbortSignals into one. The returned signal aborts as soon as
 * either input signal aborts, carrying that signal's abort reason.
 *
 * @param {AbortSignal} [a]
 * @param {AbortSignal} [b]
 * @returns {AbortSignal|undefined}
 */
function composeSignals(a, b) {
  if (!a) return b;
  if (!b) return a;

  const ac = new AbortController();

  function _abort(reason) {
    if (!ac.signal.aborted) ac.abort(reason);
  }

  if (a.aborted) { _abort(a.reason); return ac.signal; }
  if (b.aborted) { _abort(b.reason); return ac.signal; }

  a.addEventListener('abort', () => _abort(a.reason), { once: true });
  b.addEventListener('abort', () => _abort(b.reason), { once: true });

  return ac.signal;
}

module.exports = { composeSignals };
