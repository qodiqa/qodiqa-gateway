'use strict';

/**
 * PostgreSQL-authoritative Audit Chain restore probe.
 *
 * Sibling to auditChainProbe.js (the file-authoritative / single-node probe)
 * — this one proves the restored audit chain's cryptographic hash-chain
 * linkage when PostgreSQL, not a local audit.log file, is the authoritative
 * source (QODIQA_DEPLOYMENT_MODE=distributed).
 *
 * Reuses the SAME production verification function both probes ultimately
 * call — src/core/audit/audit-log.js's validateChainIntegrityFromDurableStoreChunked()
 * already internally dispatches on ORDERING_MODE: when it is 'distributed'
 * it reads via pgAuditBackend.loadChainFromPg() and walks the chain
 * hash-by-hash exactly as this same function does at real production
 * startup (server/startup.js's own distributed-mode boot path) and exactly
 * as hydrateFromPgIfDistributed() does on every replica's first append. No
 * new cryptographic verification logic is introduced by this probe — it is
 * a thin bootstrap (initialize the PG connection pool, set the ordering
 * mode, require the real module) around code that already exists and is
 * already exercised in production.
 *
 * Runs as a CHILD PROCESS (see validate.js) for the same isolation reason
 * auditChainProbe.js does — QODIQA_AUDIT_ORDERING_MODE and QODIQA_PG_URL
 * must not leak into or be inherited from the parent restore process's own
 * module state.
 *
 * SAFETY-CRITICAL: pgAuditBackend.loadChainFromPg() returns [] (an EMPTY
 * array, not a thrown error) when the PG connection pool was never
 * initialized or is disabled — silently reporting "valid: true, 0 entries"
 * in that case would be a textbook fail-OPEN bug (a probe that "passes"
 * because it never actually looked at anything). This probe therefore:
 *   1. Requires QODIQA_PG_ENABLED=true and a real QODIQA_PG_URL to even
 *      attempt initialization, and confirms pgPool.isEnabled() actually
 *      became true afterward — fails closed immediately if not.
 *   2. Cross-checks the number of rows actually loaded from PostgreSQL
 *      (report.chainLength — validateChainIntegrityFromDurableStoreChunked()'s
 *      top-level entry count, equal to loadChainFromPg()'s returned row
 *      count; NOT report.entriesVerified, which only appears nested inside
 *      integrityFailures[] on a FAILED walk, never as a top-level count of a
 *      successful one — using that field here would always read 0 and this
 *      cross-check would never fire) against QODIQA_DR_EXPECTED_AUDIT_ROW_COUNT
 *      (set by validate.js from the backup manifest's own recorded
 *      audit_chain row count) — fails closed if the restored chain has FEWER
 *      rows than the backup recorded, which is the exact "vacuous pass"
 *      scenario this cross-check exists to catch. More rows than expected is
 *      not itself a failure (the restore target may have received newer
 *      writes since the backup was taken in a real operational sequence),
 *      but is still reported for visibility.
 */

const _flushLogger = () => require('../../../services/logger').flush();

function _fail(reason, extra = {}) {
  _flushLogger();
  console.log(JSON.stringify({
    valid: false,
    chainValid: false,
    tamperingDetected: false,
    chainLength: null,
    reason,
    ...extra,
  }));
  process.exit(1);
}

(async () => {
  if (process.env.QODIQA_PG_ENABLED !== 'true' || !process.env.QODIQA_PG_URL) {
    _fail('PG_CONNECTION_NOT_CONFIGURED');
    return;
  }

  // Force distributed ordering mode for this isolated probe process,
  // regardless of whatever QODIQA_DEPLOYMENT_MODE the caller's own
  // environment might otherwise resolve to — this probe's whole purpose is
  // to check the PG-authoritative path specifically.
  process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';

  let pgPool;
  try {
    pgPool = require('../../../src/infra/postgres/pool');
    pgPool.initialize();
  } catch (err) {
    _fail(`PG_POOL_INIT_FAILED: ${err.message}`);
    return;
  }

  if (!pgPool.isEnabled()) {
    // initialize() itself never throws on a bad connection — the pool is
    // lazy — so this is the earliest point a misconfigured/unreachable
    // target is detectable without issuing a query. Belt-and-suspenders
    // with the query-level failure handling below.
    _fail('PG_POOL_NOT_ENABLED_AFTER_INIT');
    return;
  }

  let AuditLog;
  try {
    AuditLog = require('../../../src/core/audit/audit-log.js');
  } catch (err) {
    _fail(`MODULE_LOAD_FAILED: ${err.message}`, { tamperingDetected: true });
    return;
  }

  let report;
  try {
    report = await AuditLog.validateChainIntegrityFromDurableStoreChunked();
  } catch (err) {
    _fail(`VALIDATION_THREW: ${err.message}`, { tamperingDetected: true });
    return;
  }

  const rowsLoaded  = typeof report.chainLength === 'number' ? report.chainLength : 0;
  const expectedRaw = process.env.QODIQA_DR_EXPECTED_AUDIT_ROW_COUNT;
  const expected    = expectedRaw !== undefined ? parseInt(expectedRaw, 10) : null;

  if (expected !== null && Number.isFinite(expected) && rowsLoaded < expected) {
    // `...report` spreads FIRST so the explicit fail fields below (chainValid,
    // rowsLoaded, expectedFromManifest) always win — the underlying walk may
    // itself report chainValid:true (the rows that DID load were internally
    // consistent), but this probe must still report the CROSS-CHECK failure,
    // not let a passing sub-result silently override it via key ordering.
    _fail('RESTORED_CHAIN_SHORTER_THAN_BACKUP', {
      ...report,
      chainValid: false,
      rowsLoaded,
      expectedFromManifest: expected,
    });
    return;
  }

  _flushLogger();
  console.log(JSON.stringify({
    valid: report.chainValid === true,
    ...report,
    rowsLoaded,
    expectedFromManifest: expected,
  }));
  process.exit(report.chainValid === true ? 0 : 1);
})();
