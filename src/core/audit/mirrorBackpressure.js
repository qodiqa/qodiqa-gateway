'use strict';

/**
 * 2026-10-06 — hysteresis latch for the audit mirror backlog (used by audit-log.js).
 *
 * update(depth) engages the latch when depth reaches maxDepth and releases it only once depth has drained to
 * resumeDepth (half of maxDepth), so admission does not flap at the boundary. Returns 'engaged' / 'released' on a
 * transition and null otherwise; engaged() reads the current state.
 */

const DEFAULT_MAX_DEPTH = 20_000;
const MIN_MAX_DEPTH = 100;

function maxDepthFromEnv(env = process.env) {
  const v = Number(env.QODIQA_AUDIT_MIRROR_MAX_DEPTH);
  return Number.isInteger(v) && v >= MIN_MAX_DEPTH ? v : DEFAULT_MAX_DEPTH;
}

function createLatch(maxDepth = maxDepthFromEnv()) {
  const resumeDepth = Math.floor(maxDepth / 2);
  let engaged = false;
  return {
    maxDepth,
    resumeDepth,
    engaged: () => engaged,
    update(depth) {
      if (!engaged && depth >= maxDepth) { engaged = true; return 'engaged'; }
      if (engaged && depth <= resumeDepth) { engaged = false; return 'released'; }
      return null;
    },
  };
}

module.exports = { createLatch, maxDepthFromEnv, DEFAULT_MAX_DEPTH, MIN_MAX_DEPTH };
