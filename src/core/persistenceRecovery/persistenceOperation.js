'use strict';

/**
 * Persistence Operation Model — Component #13
 *
 * Defines:
 *   - The operation data model (fields every queued operation must carry)
 *   - PostgreSQL error classification (what is a persistence failure vs. a data error)
 *   - Phantom record construction (synthetic return values during PG unavailability)
 *
 * CRITICAL CLASSIFICATION RULE:
 *   isPersistenceFailure() MUST correctly distinguish:
 *     • Transient connectivity failures (connection refused, timeout, pool exhaustion)
 *       → return true → enqueue for retry
 *     • Data/business/validation errors (constraint violations, syntax, auth failures)
 *       → return false → propagate error, do NOT enqueue
 *
 *   Queuing a data error would retry forever and move to DLQ with no useful result.
 *   Failing to queue a connectivity error would lose data permanently.
 */

'use strict';

// ── PG error code sets ────────────────────────────────────────────────────────

// PostgreSQL error codes: class 08 (connection), 53 (resources), 57 (operator),
// 40 (transaction rollback — includes deadlock which is safe to retry).
// Source: https://www.postgresql.org/docs/current/errcodes-appendix.html
const RETRYABLE_PG_CODES = new Set([
  '08000', '08001', '08003', '08004', '08006', '08007', // Connection exceptions
  '53000', '53100', '53200', '53300',                   // Insufficient resources
  '57000', '57014', '57P01', '57P02', '57P03',         // Operator intervention
  '40001', '40P01',                                     // Serialization / deadlock
]);

// Node.js network-level error codes (before TCP reaches PG)
const RETRYABLE_NET_CODES = new Set([
  'ECONNREFUSED', 'ETIMEDOUT', 'ECONNRESET',
  'ENOTFOUND', 'EAI_AGAIN', 'EPIPE', 'EHOSTUNREACH',
]);

// PG error code class prefixes that are always retryable
const RETRYABLE_PG_CLASS_PREFIXES = new Set(['08', '53', '57']);

// ── canonical codeless connection-layer messages ─────────────────────────
//
// `pg`/`pg-pool` throw a handful of conditions as a bare `new Error(string)`
// with no SQLSTATE `.code` at all (confirmed by reading node_modules/pg-pool/
// index.js and node_modules/pg/lib/*.js directly, not guessed) — every one of
// them happens BEFORE PostgreSQL ever parses a query, so by construction none
// of them can be a business-logic/data error (those always carry a real
// SQLSTATE once PG has actually processed something). This is the canonical,
// single source of truth for that set — src/infra/postgres/pgCircuitBreaker.js
// (Infrastructure) imports this Core-owned set instead of maintaining its own
// independent copy, per the target layered architecture's own documented
// exception (Infrastructure -> Core is the one sanctioned cross-layer edge in
// that pair — see .dependency-cruiser.js's `no-core-to-infra` comment; the
// reverse, Core -> Infrastructure, is what Layer 1's own STOP rejected for
// option C).
//
// this set used to be pgCircuitBreaker.js's own private copy, checked
// there for circuit-breaker-failure counting but never consulted here for
// retry-queue classification — 'timeout exceeded when trying to connect'
// (real pg-pool pool-exhaustion message) was correctly counted against the
// breaker but silently NOT enqueued for retry, permanently dropping the
// write. That is exactly the "two independently-drifting copies" shape
// already retired elsewhere in this codebase (Redis reconnect strategies) —
// converging onto one canonical set here closes it the same way, rather than
// patching one more string into a second private list.
//
// Two more real, previously-unclassified-by-either-list messages were found
// during the remediation's own diagnosis pass (grep of node_modules/pg/
// lib/client.js) and added here at the same time, since they share the
// identical root cause and are equally reachable in production:
//   - 'Client has encountered a connection error and is not queryable'
//   - 'Client was closed and is not queryable'
//
// Deliberately NOT extended to include every codeless error pg/pg-pool can
// throw — node_modules/pg/lib/utils.js throws a codeless
// 'circular reference detected while preparing "..." for query' for a
// genuine caller/data bug (malformed query parameters), which must stay
// classified non-retryable; a blanket "codeless == retryable" policy would
// misclassify it and hand the original caller a phantom-success response for
// a write that can never actually land. Only the messages above are known,
// specifically, to originate from the connection-establishment/liveness
// layer, never from query preparation or execution.
const CODELESS_CONNECTION_MESSAGES = new Set([
  'timeout exceeded when trying to connect',
  'Connection terminated due to connection timeout',
  'Client has encountered a connection error and is not queryable',
  'Client was closed and is not queryable',
]);

// Synthetic error codes this codebase itself assigns to signal transient,
// self-clearing unavailability that never reached a real PG/libpq error at
// all — distinct from both the SQLSTATE classes and Node network codes above.
// pool.js's _circuitOpenError() (code 'PG_CIRCUIT_OPEN') is thrown by
// query()/withTransaction()/withAdvisoryLock() whenever the query circuit
// breaker is OPEN and fast-fails without ever contacting the database. That
// condition is the textbook definition of retryable — a temporary pause that
// clears on its own once the breaker's recovery check succeeds — but its code
// matched none of the classification rules below and fell through to
// non-retryable, so persistEntry() (pg-audit-backend.js) silently dropped the
// write instead of queuing it for retry. Any future synthetic code this
// codebase adds for the same "known transient, not a real PG error" shape
// belongs in this set, not threaded through message-heuristics below.
// AUDIT_MIRROR_PARENT_MISSING — a mirror row whose parent is not
// committed yet (pg-audit-backend.js insertMirrorRow). Transient by
// construction: it succeeds once the parent lands.
const RETRYABLE_SYNTHETIC_CODES = new Set(['PG_CIRCUIT_OPEN', 'AUDIT_MIRROR_PARENT_MISSING']);

// PG error code class prefixes that are NEVER retryable (data/logic errors)
const NON_RETRYABLE_PG_CLASS_PREFIXES = new Set([
  '22', // Data exception (e.g., invalid input syntax)
  '23', // Integrity constraint violation (unique, FK, not-null, check)
  '25', // Invalid transaction state
  '26', // Invalid SQL statement name
  '28', // Invalid authorization spec (auth failures)
  '2B', // Dependent privilege descriptors still exist
  '2D', // Invalid transaction termination
  '2F', // SQL routine exception
  '42', // Syntax error / wrong object type
  '44', // WITH CHECK OPTION violation
]);

/**
 * Classify a PostgreSQL or network error as a persistence failure (retryable)
 * or a data/logic error (non-retryable).
 *
 * @param {any} err
 * @returns {boolean}  true → queue for retry;  false → propagate to caller
 */
function isPersistenceFailure(err) {
  if (!err) return false;

  const code = (err.code ?? '').toString().toUpperCase();

  // Node network-layer errors (cannot reach PG at all)
  if (RETRYABLE_NET_CODES.has(code)) return true;

  // Exact PG error code match
  if (RETRYABLE_PG_CODES.has(code)) return true;

  // Codebase-synthetic transient-unavailability codes — see the set's
  // own comment above for why these must be checked before the PG-class-
  // prefix logic below (their "code" is not a 5-char SQLSTATE at all).
  if (RETRYABLE_SYNTHETIC_CODES.has(code)) return true;

  // PG error class prefix — two-character prefix of the 5-char code
  const pgClass = code.slice(0, 2);
  if (NON_RETRYABLE_PG_CLASS_PREFIXES.has(pgClass)) return false;
  if (RETRYABLE_PG_CLASS_PREFIXES.has(pgClass))     return true;

  // Error message heuristics for cases where code is not set
  const msg = (err.message ?? '').toLowerCase();

  // the canonical codeless-connection-message set (see its own comment
  // above) — checked first so any future addition there applies here too
  // without needing a second, independently-maintained substring list.
  for (const codelessMsg of CODELESS_CONNECTION_MESSAGES) {
    if (msg.includes(codelessMsg.toLowerCase())) return true;
  }

  if (msg.includes('connection refused'))            return true;
  if (msg.includes('connection terminated'))         return true;
  if (msg.includes('connection reset'))              return true;
  if (msg.includes('connect etimedout'))             return true;
  if (msg.includes('connect econnrefused'))          return true;
  if (msg.includes('pool exhausted'))                return true;
  if (msg.includes('client checkout timeout'))       return true;
  if (msg.includes('query read timeout'))            return true;
  if (msg.includes('ssl connection has been closed')) return true;
  if (msg.includes('the database system is'))        return true; // PG restart msg
  if (msg.includes('server closed the connection')) return true;
  if (msg.includes('read econnreset'))               return true;

  return false;
}

// ── Operation types ───────────────────────────────────────────────────────────

const OPERATION_TYPES = Object.freeze({
  ATTESTATION_SAVE:         'ATTESTATION_SAVE',
  CERTIFICATION_SAVE:       'CERTIFICATION_SAVE',
  PORTAL_VERIFICATION_SAVE: 'PORTAL_VERIFICATION_SAVE',
  WEBHOOK_DELIVERY:         'WEBHOOK_DELIVERY',
  AUDIT_CHAIN_PG_SAVE:      'AUDIT_CHAIN_PG_SAVE',
  EVIDENCE_CHAIN_SAVE:      'EVIDENCE_CHAIN_SAVE',
  // (D3): an enforcement-decision transparency leaf whose synchronous
  // registration failed on PostgreSQL persistence; replayed by the worker.
  TRANSPARENCY_SAVE:        'TRANSPARENCY_SAVE',
  // a COMMIT audit entry the audit store refused; replayed by the worker (or the file journal) so it survives a crash.
  AUDIT_COMMIT_WRITE:       'AUDIT_COMMIT_WRITE',
});

// ── Phantom record construction ───────────────────────────────────────────────

/**
 * Build a synthetic DB row for use when a write is queued instead of persisted.
 *
 * This allows upstream callers (route handlers, service layers) to return a
 * response immediately while persistence is deferred.  The synthetic record
 * matches the shape of what pgPool.query().rows[0] would have returned.
 *
 * Differences from a real persisted row:
 *   - id:         null  (the auto-increment sequence number from PG)
 *   - timestamps: approximate (current time, not the DB-generated value)
 *
 * @param {string} operationType  One of OPERATION_TYPES
 * @param {object} payload        The original record payload
 * @returns {object}
 */
function buildPhantomRecord(operationType, payload) {
  const now = new Date().toISOString();

  switch (operationType) {
    case OPERATION_TYPES.ATTESTATION_SAVE:
      return {
        id:                     null,
        attestation_id:         payload.attestationId,
        attestation_type:       payload.attestationType ?? 'ARTIFACT_VERIFICATION',
        version:                payload.version ?? '1.0',
        artifact_fingerprint:   payload.artifactFingerprint ?? null,
        artifact_public_key_id: payload.artifactPublicKeyId ?? null,
        artifact_timestamp_ms:  payload.artifactTimestampMs ?? null,
        artifact_expiry_ms:     payload.artifactExpiryMs ?? null,
        artifact_id:            payload.artifactId ?? null,
        attestation_decision:   payload.attestationDecision,
        verification_result:    payload.verificationResult ?? {},
        cryptographic_result:   payload.cryptographicResult ?? {},
        compliance_result:      payload.complianceResult ?? {},
        chain_result:           payload.chainResult ?? {},
        checks_performed:       payload.checksPerformed ?? [],
        warnings:               payload.warnings ?? [],
        failed_check:           payload.failedCheck ?? null,
        failure_reason:         payload.failureReason ?? null,
        transparency_id:        payload.transparencyId ?? null,
        evidence_package_hash:  payload.evidencePackageHash ?? null,
        requested_by:           payload.requestedBy ?? 'external',
        request_ip:             payload.requestIp ?? null,
        duration_ms:            payload.durationMs ?? null,
        generated_at:           now,
      };

    case OPERATION_TYPES.CERTIFICATION_SAVE:
      return {
        id:                        null,
        certification_id:          payload.certificationId,
        certification_level:       payload.certificationLevel,
        certification_decision:    payload.certificationDecision,
        score:                     payload.score,
        score_breakdown:           payload.scoreBreakdown ?? {},
        critical_control_failures: payload.criticalControlFailures ?? [],
        passed_controls:           payload.passedControls ?? [],
        failed_controls:           payload.failedControls ?? [],
        evaluation_result:         payload.evaluationResult ?? {},
        attestation_references:    payload.attestationReferences ?? [],
        evidence_references:       payload.evidenceReferences ?? [],
        verification_references:   payload.verificationReferences ?? {},
        transparency_id:           payload.transparencyId ?? null,
        evidence_package_hash:     payload.evidencePackageHash ?? null,
        artifacts_count:           payload.artifactsCount ?? 0,
        evidence_packages_count:   payload.evidencePackagesCount ?? 0,
        requested_by:              payload.requestedBy ?? 'external',
        request_ip:                payload.requestIp ?? null,
        duration_ms:               payload.durationMs ?? null,
        generated_at:              now,
      };

    case OPERATION_TYPES.PORTAL_VERIFICATION_SAVE:
      return {
        id:                    null,
        verification_id:       payload.verificationId,
        artifact_fingerprint:  payload.artifactFingerprint,
        artifact_public_key_id: payload.artifactPublicKeyId ?? null,
        artifact_timestamp_ms: payload.artifactTimestampMs ?? null,
        artifact_expiry_ms:    payload.artifactExpiryMs ?? null,
        artifact_id:           payload.artifactId ?? null,
        overall_result:        payload.overallResult,
        checks_performed:      payload.checksPerformed ?? [],
        failed_check:          payload.failedCheck ?? null,
        failure_reason:        payload.failureReason ?? null,
        warnings:              payload.warnings ?? [],
        transparency_id:       payload.transparencyId ?? null,
        submitted_by:          payload.submittedBy ?? 'public',
        submission_ip:         payload.submissionIp ?? null,
        duration_ms:           payload.durationMs ?? null,
        verified_at:           now,
      };

    case OPERATION_TYPES.WEBHOOK_DELIVERY:
      // Webhook delivery is not a PG write — no phantom record needed.
      return null;

    case OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE:
    case OPERATION_TYPES.EVIDENCE_CHAIN_SAVE:
    case OPERATION_TYPES.TRANSPARENCY_SAVE:
    case OPERATION_TYPES.AUDIT_COMMIT_WRITE:
      // The file-based audit chain (audit-log.js) is already the durable,
      // authoritative record by the time either of these is enqueued — the
      // caller (pg-audit-backend.js) never consumes a return value from
      // persistEntry(), so no synthetic row is needed here.
      // TRANSPARENCY_SAVE: enforcementBridge.js builds its own "pending"
      // result from the pre-assigned transparencyId; no row is synthesized.
      return null;

    default:
      throw new Error(`buildPhantomRecord: unknown operationType: "${operationType}"`);
  }
}

module.exports = {
  isPersistenceFailure,
  buildPhantomRecord,
  OPERATION_TYPES,
  RETRYABLE_PG_CODES,
  RETRYABLE_NET_CODES,
  RETRYABLE_SYNTHETIC_CODES,
  CODELESS_CONNECTION_MESSAGES,
};
