'use strict';

/**
 * Audit Chain restore probe — runs as a CHILD PROCESS (see validate.js) so
 * that QODIQA_AUDIT_LOG can point at a restored file without touching the
 * parent process's own module state. Exercises the REAL production module
 * (src/core/audit/audit-log.js) exactly as a live server startup would —
 * including its own WAL-replay and checksum verification — rather than
 * reimplementing chain verification here.
 */

// Contract: this probe ALWAYS prints an object with at least
// { valid, tamperingDetected, chainLength, reason } — audit-log.js throws at
// require() time (not just from validateChainIntegrity()) when the chain is
// broken, malformed, or fails its anti-deletion checksum, so both the
// require() and the validateChainIntegrity() call sites must normalize to
// the same shape. A load-time throw from this module is, by construction,
// always evidence of corruption/tampering (that's the only reason it throws).

// THROUGHPUT-12: services/logger.js batches INFO/WARN/ERROR stdout writes and
// flushes them asynchronously — this probe's own result line below is parsed
// positionally by validate.js's _lastJsonLine(), so any not-yet-flushed
// structured log line must be drained BEFORE that print (flush() does its
// actual work synchronously — see that file's header comment).
const _flushLogger = () => require('../../../services/logger').flush();

let AuditLog;
try {
  AuditLog = require('../../../src/core/audit/audit-log.js');
} catch (err) {
  _flushLogger();
  console.log(JSON.stringify({
    valid: false,
    chainValid: false,
    tamperingDetected: true,
    chainLength: null,
    reason: `MODULE_LOAD_FAILED: ${err.message}`,
  }));
  process.exit(1);
}

// the in-memory chain is now a bounded tail window, so the synchronous
// validateChainIntegrity() only proves the window. A restore probe must prove
// the ENTIRE restored file, so it uses the durable-store full scan (re-reads
// audit.log fresh, walks every entry hash-by-hash).
(async () => {
  try {
    const report = await AuditLog.validateChainIntegrityFromDurableStoreChunked();
    _flushLogger();
    // M3: where the restored chain starts (none / rebased on a signed base record / full-file).
    const cs = typeof AuditLog.getChainStart === 'function' ? AuditLog.getChainStart() : null;
    const chainStart = cs && { state: cs.state, startCount: cs.startCount, checkpointId: cs.checkpoint ? cs.checkpoint.payload.checkpointId : null };
    console.log(JSON.stringify({ valid: report.chainValid, ...report, chainStart }));
    process.exit(report.chainValid ? 0 : 1);
  } catch (err) {
    _flushLogger();
    console.log(JSON.stringify({
      valid: false,
      chainValid: false,
      tamperingDetected: true,
      chainLength: null,
      reason: `VALIDATION_THREW: ${err.message}`,
    }));
    process.exit(1);
  }
})();
