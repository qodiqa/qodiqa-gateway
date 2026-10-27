'use strict';

/**
 * Transparency Gap Policy — Component #14
 *
 * Configurable failure modes for detected transparency gaps.
 *
 * Modes (TRANSPARENCY_GAP_MODE env var):
 *
 *   WARN        — Emit structured log event only.  No metrics, no alert, no block.
 *   ALERT       — Log + increment Prometheus metrics + fire alert.  Default.
 *   FAIL_CLOSED — Log + metrics + alert + throw GapError to block the caller.
 *
 * FAIL_CLOSED block conditions:
 *   Gaps classified as CRITICAL or WARNING are blocked.
 *   INFO gaps are logged and alerted but never block (transient / self-healing).
 *
 * The default mode is ALERT rather than WARN because WARN-only was explicitly
 * identified as insufficient for production (see Component #14 spec).
 */

// ── Mode constants ────────────────────────────────────────────────────────────

const MODE = Object.freeze({
  WARN:        'WARN',
  ALERT:       'ALERT',
  FAIL_CLOSED: 'FAIL_CLOSED',
});

const _VALID_MODES = new Set(Object.values(MODE));

// ── Mode resolution ───────────────────────────────────────────────────────────

/**
 * Read the current policy mode.
 * Defaults to ALERT when env var is absent or unrecognized.
 *
 * @param {object} [_env]  — injectable for tests; defaults to process.env
 * @returns {'WARN'|'ALERT'|'FAIL_CLOSED'}
 */
function getMode(_env) {
  const raw = ((_env ?? process.env).TRANSPARENCY_GAP_MODE ?? 'ALERT').toUpperCase().trim();
  return _VALID_MODES.has(raw) ? raw : MODE.ALERT;
}

// ── GapError ──────────────────────────────────────────────────────────────────

class GapError extends Error {
  constructor(gap) {
    super(
      `Transparency gap detected: ${gap.gapType} [${gap.severity}] ` +
      `(gapId: ${gap.gapId}, service: ${gap.service})`
    );
    this.name      = 'GapError';
    this.gapId     = gap.gapId;
    this.gapType   = gap.gapType;
    this.severity  = gap.severity;
    this.service   = gap.service;
    this.artifactId = gap.artifactId ?? null;
  }
}

// ── Block decision ────────────────────────────────────────────────────────────

/**
 * Determine whether a gap should block its caller.
 *
 * @param {object} gap   — classified gap record (includes severity)
 * @param {string} mode  — one of MODE values
 * @returns {boolean}
 */
function shouldBlock(gap, mode) {
  if (mode !== MODE.FAIL_CLOSED) return false;
  // INFO gaps are self-healing; only WARNING and CRITICAL block.
  return gap.severity === 'CRITICAL' || gap.severity === 'WARNING';
}

/**
 * Determine whether alerting should fire.
 *
 * @param {string} mode
 * @returns {boolean}
 */
function shouldAlert(mode) {
  return mode === MODE.ALERT || mode === MODE.FAIL_CLOSED;
}

module.exports = {
  MODE,
  getMode,
  GapError,
  shouldBlock,
  shouldAlert,
};
