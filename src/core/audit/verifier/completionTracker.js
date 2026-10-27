'use strict';

/**
 * — no silent loss of verification.
 *
 *   record(mode, outcome)   outcome 'COMPLETE' | 'TIMEOUT' | 'FAILED'. Every non-complete run emits
 *                           WARN AUDIT_CHAIN_VERIFIER_RUN_INCOMPLETE; after `notCompletingAfter` consecutive ones of the
 *                           SAME mode, CRITICAL AUDIT_CHAIN_VERIFIER_NOT_COMPLETING (once per episode), and INFO
 *                           AUDIT_CHAIN_VERIFIER_COMPLETING_AGAIN when that mode completes again.
 *   recordWatermark(index)  verifier lag = appended entries (the serving process's count) − verified watermark →
 *                           gauge qodiqa_audit_chain_verifier_lag_entries; WARN AUDIT_CHAIN_VERIFIER_LAGGING when it
 *                           exceeds `lagWarnEntries` (edge-triggered), INFO AUDIT_CHAIN_VERIFIER_LAG_RECOVERED below it —
 *                           so the per-tick catch-up cap can never hide a growing backlog.
 */

const SOURCE = 'AUDIT_CHAIN_VERIFIER';

function createCompletionTracker({ emit, metrics = {}, notCompletingAfter = 3, lagWarnEntries = 60_000, getAppendedCount = () => null } = {}) {
  const consecutive = { INCREMENTAL: 0, FULL: 0, PG_DIVERGENCE: 0, PG_INCREMENTAL: 0 };   // S3: + PG_INCREMENTAL
  const escalated = { INCREMENTAL: false, FULL: false, PG_DIVERGENCE: false, PG_INCREMENTAL: false };
  let lagging = false;
  let lastLag = null;

  function record(mode, outcome, detail = {}) {
    if (!(mode in consecutive)) return;
    if (outcome === 'COMPLETE') {
      if (escalated[mode]) emit('INFO', 'AUDIT_CHAIN_VERIFIER_COMPLETING_AGAIN', { source: SOURCE, mode, afterIncompleteRuns: consecutive[mode] });
      consecutive[mode] = 0;
      escalated[mode] = false;
    } else {
      consecutive[mode]++;
      emit('WARN', 'AUDIT_CHAIN_VERIFIER_RUN_INCOMPLETE', { source: SOURCE, mode, outcome, consecutive: consecutive[mode], ...detail });
      if (consecutive[mode] >= notCompletingAfter && !escalated[mode]) {
        escalated[mode] = true;
        emit('CRITICAL', 'AUDIT_CHAIN_VERIFIER_NOT_COMPLETING', { source: SOURCE, mode, consecutive: consecutive[mode], lastOutcome: outcome, ...detail,
          message: `The ${mode} audit chain verification has not completed ${consecutive[mode]} times in a row: the chain is not being verified.` });
      }
    }
    try { metrics.auditChainVerifierConsecutiveIncomplete?.set({ mode }, consecutive[mode]); } catch { /* metrics never affect verification */ }
  }

  function recordWatermark(index) {
    const appended = getAppendedCount();
    if (!Number.isFinite(appended) || !Number.isFinite(index)) return null;
    const lag = Math.max(0, appended - index);
    lastLag = lag;
    try { metrics.auditChainVerifierLagEntries?.set({}, lag); } catch { /* metrics never affect verification */ }
    if (lag > lagWarnEntries && !lagging) {
      lagging = true;
      emit('WARN', 'AUDIT_CHAIN_VERIFIER_LAGGING', { source: SOURCE, lag, threshold: lagWarnEntries, appended, verified: index });
    } else if (lag <= lagWarnEntries && lagging) {
      lagging = false;
      emit('INFO', 'AUDIT_CHAIN_VERIFIER_LAG_RECOVERED', { source: SOURCE, lag, threshold: lagWarnEntries });
    }
    return lag;
  }

  function state() { return { consecutive: { ...consecutive }, escalated: { ...escalated }, lag: lastLag, lagging }; }

  return { record, recordWatermark, state };
}

module.exports = { createCompletionTracker };
