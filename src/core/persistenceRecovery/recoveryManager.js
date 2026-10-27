'use strict';

/**
 * Persistence Recovery Manager — Component #13 (CHAIN-3 remediation)
 *
 * Singleton facade: wires the queue, worker, and metrics together.
 * Used by attestationStore, certificationStore, and portalStore.
 *
 * MODE:
 *   Enabled when PostgreSQL is enabled (QODIQA_PG_ENABLED=true) — the
 *   queue's durable store (migration 032) requires nothing else. Disabled
 *   (no-op) when PostgreSQL is not enabled — stores behave as before.
 *   PRQ_ENABLED=false forces disabled mode even with PostgreSQL enabled;
 *   PRQ_ENABLED=true forces enabled mode regardless (useful for exercising
 *   the queue against a PG instance that recoveryManager itself doesn't
 *   otherwise need). Redis is not read from, written to, or required by
 *   this module or by queue.js — see docs/protocol/AUDIT-SCHEMA-V8.md,
 *   "Decision Update: Durable Postgres-Backed Persistence Recovery Queue
 *   (CHAIN-3)".
 *
 * ENQUEUE CONTRACT:
 *   - Returns a phantom record matching the PG schema shape.
 *   - Never throws — if the durable PG enqueue itself fails, falls back to
 *     the filesystem journal (journal.js) and returns phantom.
 *   - Caller gets a usable response regardless of the outcome.
 *   - FAILOVER-1 (see docs/protocol/AUDIT-SCHEMA-V8.md): CHAIN-3 left
 *     one disclosed residual risk — if PostgreSQL itself is unavailable at
 *     the exact moment both the original write AND this durable enqueue are
 *     attempted, there is no third independent durable store, and the retry
 *     cannot be recorded anywhere. That gap is now closed: when
 *     queue.enqueue() itself throws, the operation falls back to a local,
 *     disk-backed, crash-safe journal (journal.js) instead of being logged
 *     and dropped. journalWorker.js replays journal entries back into this
 *     same PG-backed queue as soon as PostgreSQL is reachable again, so the
 *     existing retry/backoff/DLQ machinery in worker.js still applies
 *     end-to-end. Only a simultaneous PostgreSQL outage AND local-disk
 *     failure (e.g. ENOSPC, unwritable volume) remains unrecoverable — both
 *     conditions holding at once, observable via
 *     qodiqa_prq_journal_write_failed_total (should be ~0 in normal
 *     operation, since the two failure domains are independent).
 */

const fs = require('fs');
const queue         = require('./queue');
const worker        = require('./worker');
const journal       = require('./journal');
const journalWorker = require('./journalWorker');
const metrics       = require('./metrics');
const { buildPhantomRecord, OPERATION_TYPES, isPersistenceFailure } = require('./persistenceOperation');
const pgPool   = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');

// Webhook delivery handler — loaded lazily to avoid circular deps at module load
let _webhookRetryHandler = null;
function _getWebhookRetryHandler() {
  if (!_webhookRetryHandler) {
    _webhookRetryHandler = require('../webhooks/webhookDelivery').retryHandler;
  }
  return _webhookRetryHandler;
}

// Dependency inversion (rule no-circular): the audit COMMIT writer registers itself here (src/core/audit/commitEntry.js) instead of this module requiring it.
let _commitWriter = null;
function setCommitWriter(fn) { _commitWriter = fn; }

const SOURCE = 'PERSISTENCE_RECOVERY_MANAGER';

// ── Mode detection ────────────────────────────────────────────────────────────

function _isEnabled() {
  if (process.env.PRQ_ENABLED === 'false') return false;
  if (process.env.PRQ_ENABLED === 'true')  return true;
  return pgPool.isEnabled();
}

// ── Initialization ────────────────────────────────────────────────────────────

let _initialized = false;
let _handlers    = null; // set by registerStoreHandlers()

// ── Built-in retry handlers ───────────────────────────────────────────────────
// Each handler calls pgPool.query() directly to avoid recursive recovery wrapping.
// ON CONFLICT DO NOTHING: if the row was already inserted on a prior attempt,
// the re-insert is a no-op and we treat it as success.

const _builtinHandlers = {
  [OPERATION_TYPES.ATTESTATION_SAVE]: async (op) => {
    if (!pgPool.isEnabled()) return { success: false, error: 'PG disabled' };
    try {
      const p = op.payload;
      await pgPool.query(`
        INSERT INTO attestations (
          attestation_id, attestation_type, version,
          artifact_fingerprint, artifact_public_key_id,
          artifact_timestamp_ms, artifact_expiry_ms, artifact_id,
          attestation_decision, verification_result, cryptographic_result,
          compliance_result, chain_result, checks_performed, warnings,
          failed_check, failure_reason, transparency_id, evidence_package_hash,
          requested_by, request_ip, duration_ms
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22
        ) ON CONFLICT (attestation_id) DO NOTHING
      `, [
        p.attestationId, p.attestationType ?? 'ARTIFACT_VERIFICATION', p.version ?? '1.0',
        p.artifactFingerprint ?? null, p.artifactPublicKeyId ?? null,
        p.artifactTimestampMs != null ? Number(p.artifactTimestampMs) : null,
        p.artifactExpiryMs    != null ? Number(p.artifactExpiryMs)    : null,
        p.artifactId ?? null, p.attestationDecision,
        JSON.stringify(p.verificationResult  ?? {}),
        JSON.stringify(p.cryptographicResult ?? {}),
        JSON.stringify(p.complianceResult    ?? {}),
        JSON.stringify(p.chainResult         ?? {}),
        JSON.stringify(p.checksPerformed     ?? []),
        JSON.stringify(p.warnings            ?? []),
        p.failedCheck ?? null, p.failureReason ?? null,
        p.transparencyId ?? null, p.evidencePackageHash ?? null,
        p.requestedBy ?? 'external', p.requestIp ?? null,
        p.durationMs  != null ? Number(p.durationMs) : null,
      ], 'recovery_attestation_insert');
      return { success: true };
    } catch (err) {
      if (isPersistenceFailure(err)) return { success: false, error: err.message };
      return { success: false, error: `non-retryable: ${err.message}` };
    }
  },

  [OPERATION_TYPES.CERTIFICATION_SAVE]: async (op) => {
    if (!pgPool.isEnabled()) return { success: false, error: 'PG disabled' };
    try {
      const p = op.payload;
      await pgPool.query(`
        INSERT INTO certifications (
          certification_id, certification_level, certification_decision, score,
          score_breakdown, critical_control_failures, passed_controls, failed_controls,
          evaluation_result, attestation_references, evidence_references,
          verification_references, transparency_id, evidence_package_hash,
          artifacts_count, evidence_packages_count, requested_by, request_ip, duration_ms
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
        ) ON CONFLICT (certification_id) DO NOTHING
      `, [
        p.certificationId, p.certificationLevel, p.certificationDecision, p.score,
        JSON.stringify(p.scoreBreakdown          ?? {}),
        JSON.stringify(p.criticalControlFailures ?? []),
        JSON.stringify(p.passedControls          ?? []),
        JSON.stringify(p.failedControls          ?? []),
        JSON.stringify(p.evaluationResult        ?? {}),
        JSON.stringify(p.attestationReferences   ?? []),
        JSON.stringify(p.evidenceReferences      ?? []),
        JSON.stringify(p.verificationReferences  ?? {}),
        p.transparencyId ?? null, p.evidencePackageHash ?? null,
        p.artifactsCount ?? 0, p.evidencePackagesCount ?? 0,
        p.requestedBy ?? 'external', p.requestIp ?? null,
        p.durationMs != null ? Number(p.durationMs) : null,
      ], 'recovery_certification_insert');
      return { success: true };
    } catch (err) {
      if (isPersistenceFailure(err)) return { success: false, error: err.message };
      return { success: false, error: `non-retryable: ${err.message}` };
    }
  },

  [OPERATION_TYPES.WEBHOOK_DELIVERY]: async (op) => {
    try {
      return await _getWebhookRetryHandler()(op);
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  [OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE]: async (op) => {
    if (!pgPool.isEnabled()) return { success: false, error: 'PG disabled' };
    try {
      const entry = op.payload;
      // same FINDING-PG-TENANT-CONTEXT-WRITE-PATH construct as
      // pg-audit-backend.js persistEntry() — ON CONFLICT evaluates the
      // ac_tenant_select RLS policy against the proposed row, so a
      // tenant-scoped row written as qodiqa_app without matching
      // qodiqa.tenant_id context is rejected ("new row violates row-level
      // security policy"), and the recovered entry never reaches the mirror.
      // the SAME guarded INSERT persistEntry() uses — one INSERT,
      // one column set (the round-trip contract lives there now), and the
      // parent guard that keeps seq order equal to hash-chain order. A replay
      // whose parent is still queued fails retryable (AUDIT_MIRROR_PARENT_MISSING)
      // and is retried after its parent lands.
      await pgPool.withTransaction(
        (tx) => require('../../infra/postgres/pg-audit-backend').insertMirrorRow(tx, entry, { label: 'recovery_audit_chain_insert' }),
        { isolationLevel: 'READ COMMITTED' },
      );
      return { success: true };
    } catch (err) {
      if (isPersistenceFailure(err)) return { success: false, error: err.message };
      return { success: false, error: `non-retryable: ${err.message}` };
    }
  },

  [OPERATION_TYPES.EVIDENCE_CHAIN_SAVE]: async (op) => {
    if (!pgPool.isEnabled()) return { success: false, error: 'PG disabled' };
    try {
      const { auditEntry, keyInfo, opts } = op.payload;
      const chainStore = require('../evidence/chainStore');
      await chainStore._recordEvidenceFromAuditEntryOrThrow(auditEntry, keyInfo, opts);
      return { success: true };
    } catch (err) {
      if (isPersistenceFailure(err)) return { success: false, error: err.message };
      return { success: false, error: `non-retryable: ${err.message}` };
    }
  },

  // (D3): replay an enforcement-decision transparency leaf. Idempotent on
  // the pre-assigned transparencyId (UNIQUE in transparency_log_entries): an
  // entry that already landed — e.g. the original INSERT committed but its
  // acknowledgement was lost — is success, never a second leaf. The replay
  // goes through registrar.register(), so the leaf is chained under the head
  // lock and signed exactly like a synchronous registration; nothing about
  // the entry format or its integrity is relaxed.
  [OPERATION_TYPES.TRANSPARENCY_SAVE]: async (op) => {
    if (!pgPool.isEnabled()) return { success: false, error: 'PG disabled' };
    const logStore  = require('../transparency/logStore');
    const registrar = require('../transparency/registrar');
    const args = op.payload?.registration;
    if (!args || !args.transparencyId) return { success: false, error: 'non-retryable: TRANSPARENCY_SAVE payload has no registration.transparencyId' };
    try {
      if (await logStore.getByTransparencyId(args.transparencyId)) return { success: true };
      const reg = await registrar.register(args);
      if (reg.persisted !== true) return { success: false, error: 'transparency entry not persisted' };
      return { success: true };
    } catch (err) {
      if (err && err.code === '23505') {
        // A concurrent writer committed this transparencyId first.
        try { if (await logStore.getByTransparencyId(args.transparencyId)) return { success: true }; } catch { /* fall through */ }
      }
      if (isPersistenceFailure(err)) return { success: false, error: err.message };
      return { success: false, error: `non-retryable: ${err.message}` };
    }
  },

  // replay a COMMIT the audit store refused. recordCommit() is idempotent per request (appendMandatory refuses a second COMMIT with
  // already_executed, counted as done), so a replay after a lost acknowledgement is harmless; a flag-off process (audit schema v8 off) has nothing to write.
  [OPERATION_TYPES.AUDIT_COMMIT_WRITE]: async (op) => {
    const { c, outcome } = op.payload || {};
    if (!c || typeof c.requestId !== 'string' || !outcome) return { success: false, error: 'non-retryable: AUDIT_COMMIT_WRITE payload has no commit context' };
    try {
      if (typeof _commitWriter !== 'function') return { success: false, error: 'COMMIT writer is not registered yet' };
      const r = await _commitWriter(c, outcome, { _reconcile: true });
      if (r.recorded || r.duplicate || r.skipped) return { success: true };
      return { success: false, error: 'COMMIT not accepted by the audit store' };
    } catch (err) {
      return { success: false, error: err.message };
    }
  },

  [OPERATION_TYPES.PORTAL_VERIFICATION_SAVE]: async (op) => {
    if (!pgPool.isEnabled()) return { success: false, error: 'PG disabled' };
    try {
      const p = op.payload;
      await pgPool.query(`
        INSERT INTO portal_verifications (
          verification_id, artifact_fingerprint, artifact_public_key_id,
          artifact_timestamp_ms, artifact_expiry_ms, artifact_id,
          overall_result, checks_performed, failed_check, failure_reason,
          warnings, transparency_id, submitted_by, submission_ip, duration_ms
        ) VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
        ) ON CONFLICT (verification_id) DO NOTHING
      `, [
        p.verificationId, p.artifactFingerprint, p.artifactPublicKeyId ?? null,
        p.artifactTimestampMs != null ? Number(p.artifactTimestampMs) : null,
        p.artifactExpiryMs    != null ? Number(p.artifactExpiryMs)    : null,
        p.artifactId ?? null, p.overallResult,
        JSON.stringify(p.checksPerformed ?? []),
        p.failedCheck ?? null, p.failureReason ?? null,
        JSON.stringify(p.warnings ?? []),
        p.transparencyId ?? null, p.submittedBy ?? 'public',
        p.submissionIp ?? null,
        p.durationMs != null ? Number(p.durationMs) : null,
      ], 'recovery_portal_insert');
      return { success: true };
    } catch (err) {
      if (isPersistenceFailure(err)) return { success: false, error: err.message };
      return { success: false, error: `non-retryable: ${err.message}` };
    }
  },
};

/**
 * Verify PostgreSQL is available and start the worker.
 * Called once from server.js during startup.
 */
async function initialize({ handlers } = {}) {
  if (!_isEnabled()) {
    emit('INFO', 'RECOVERY_QUEUE_DISABLED', { source: SOURCE, reason: 'QODIQA_PG_ENABLED not set' });
    return;
  }
  if (_initialized) return;

  try {
    await queue._connect();
    _initialized = true;

    // Register built-in handlers then allow caller overrides
    for (const [opType, fn] of Object.entries(_builtinHandlers)) {
      worker.registerHandler(opType, fn);
    }
    if (handlers) {
      for (const [opType, fn] of Object.entries(handlers)) {
        worker.registerHandler(opType, fn);
      }
    }

    worker.start();
    journalWorker.start();
    emit('INFO', 'RECOVERY_QUEUE_INITIALIZED', { source: SOURCE });
  } catch (err) {
    emit('ERROR', 'RECOVERY_QUEUE_INIT_FAILED', { source: SOURCE, error: err.message });
  }
}

/**
 * Stop the worker. Called during graceful shutdown.
 * The shared PostgreSQL pool is owned and shut down separately by
 * server.js (after this, per the shutdown ordering documented there).
 */
async function shutdown() {
  worker.stop();
  journalWorker.stop();
  await queue._disconnect();
  _initialized = false;
  emit('INFO', 'RECOVERY_QUEUE_SHUTDOWN', { source: SOURCE });
}

// ── Enqueue ───────────────────────────────────────────────────────────────────

/**
 * Attempt to enqueue a failed persistence operation.
 * Returns a phantom record for immediate use by the caller.
 *
 * @param {string} operationType  One of OPERATION_TYPES
 * @param {object} payload        Original record payload
 * @param {Error}  err            The PG error that triggered the enqueue
 * @returns {object}  phantom record (synthetic PG row)
 */
async function enqueue(operationType, payload, err) {
  return (await enqueueWithOutcome(operationType, payload, err)).phantom;
}

/**
 * enqueue(), plus WHERE the operation was durably recorded:
 * 'queue' (PostgreSQL recovery queue), 'journal' (filesystem journal,
 * replayed into the queue by journalWorker.js), or false (not recorded
 * anywhere — queue disabled, or PostgreSQL and the journal both failed).
 * A caller that may only acknowledge its request once the operation is
 * durable (enforcementBridge.js) must check `durable`.
 *
 * @returns {Promise<{ phantom: object|null, durable: 'queue'|'journal'|false }>}
 */
async function enqueueWithOutcome(operationType, payload, err) {
  metrics.inc('recovery_queue_depth_total', { operationType });

  const phantom = buildPhantomRecord(operationType, payload);

  if (!_isEnabled() || !queue._isReady()) {
    emit('ERROR', 'RECOVERY_QUEUE_UNAVAILABLE', {
      source:        SOURCE,
      operationType,
      pgError:       err?.message,
      reason:        _isEnabled() ? 'PostgreSQL not ready' : 'recovery queue disabled',
    });
    return { phantom, durable: false };
  }

  const operationId = _deriveOperationId(operationType, payload);
  let durable = false;

  try {
    await queue.enqueue({
      operationId,
      operationType,
      service:  _serviceForType(operationType),
      payload,
    });
    metrics.inc('recovery_enqueued_total', { operationType });
    durable = 'queue';
  } catch (enqueueErr) {
    // The durable PG enqueue itself failed — PostgreSQL was unavailable at
    // the exact moment both the original write and this retry attempt were
    // made (see this module's header comment, FAILOVER-1). Fall back to the
    // filesystem journal — the third, independent durable store CHAIN-3
    // disclosed as missing — instead of just logging and dropping the
    // operation. journalWorker.js replays it back into this same queue once
    // PostgreSQL recovers.
    const obsMetrics = require('../../observability/metrics');
    obsMetrics.prqPersistFailedTotal.inc({ operationType });
    // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit) — the operation itself is kept by the file journal below
    require('../../observability/aggregatedEmit').failureEmit(emit, 'WARN', 'RECOVERY_ENQUEUE_FAILED', {
      source:        SOURCE,
      operationId,
      operationType,
      error:         enqueueErr.message,
      pgError:       err?.message,
    });

    try {
      await journal.appendEntry({
        operationId,
        operationType,
        service: _serviceForType(operationType),
        payload,
        originalError: enqueueErr.message,
      });
      metrics.inc('journal_write_total', { operationType, result: 'success' });
      obsMetrics.prqJournalWriteTotal.inc({ result: 'success' });
      durable = 'journal';
    } catch (journalErr) {
      // Both PostgreSQL AND local disk are unavailable at once — the one
      // scenario this remediation cannot cover (see header comment). Loudly
      // surfaced, never silently swallowed.
      metrics.inc('journal_write_total', { operationType, result: 'failure' });
      obsMetrics.prqJournalWriteTotal.inc({ result: 'failure' });
      obsMetrics.prqJournalWriteFailedTotal.inc({ operationType });
      emit('ERROR', 'JOURNAL_WRITE_FAILED', {
        source:        SOURCE,
        operationId,
        operationType,
        error:         journalErr.message,
        pgError:       err?.message,
        enqueueError:  enqueueErr.message,
      });
    }
  }

  return { phantom, durable };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _deriveOperationId(operationType, payload) {
  switch (operationType) {
    case OPERATION_TYPES.ATTESTATION_SAVE:
      return `att:${payload.attestationId}`;
    case OPERATION_TYPES.CERTIFICATION_SAVE:
      return `cert:${payload.certificationId}`;
    case OPERATION_TYPES.PORTAL_VERIFICATION_SAVE:
      return `pv:${payload.verificationId}`;
    case OPERATION_TYPES.WEBHOOK_DELIVERY:
      return `whd:${payload.endpointId}:${payload.eventId}`;
    case OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE:
      return `acpg:${payload.artifactId}`;
    case OPERATION_TYPES.EVIDENCE_CHAIN_SAVE:
      return `evch:${payload.auditEntry?.artifactId}`;
    case OPERATION_TYPES.TRANSPARENCY_SAVE:
      return `tlog:${payload.registration?.transparencyId}`;
    case OPERATION_TYPES.AUDIT_COMMIT_WRITE:
      return `commit:${payload.c?.requestId}`;
    default:
      return `unknown:${Date.now()}`;
  }
}

function _serviceForType(operationType) {
  switch (operationType) {
    case OPERATION_TYPES.ATTESTATION_SAVE:         return 'attestation';
    case OPERATION_TYPES.CERTIFICATION_SAVE:       return 'certification';
    case OPERATION_TYPES.PORTAL_VERIFICATION_SAVE: return 'portal';
    case OPERATION_TYPES.WEBHOOK_DELIVERY:         return 'webhooks';
    case OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE:      return 'audit';
    case OPERATION_TYPES.EVIDENCE_CHAIN_SAVE:      return 'evidence';
    case OPERATION_TYPES.TRANSPARENCY_SAVE:        return 'transparency';
    case OPERATION_TYPES.AUDIT_COMMIT_WRITE:       return 'audit';
    default:                                        return 'unknown';
  }
}

/**
 * Enqueue a webhook delivery operation.
 * Unlike enqueue(), this does not return a phantom record — webhook delivery
 * is not a PG write and requires no synthetic response for the caller.
 *
 * @param {object} opts
 * @param {string} opts.operationId  Stable ID: 'whd:<endpointId>:<eventId>'
 * @param {object} opts.payload      { endpointId, eventId, eventType, eventPayload }
 * @returns {Promise<void>}
 */
async function enqueueWebhookDelivery({ operationId, payload }) {
  if (!_isEnabled() || !queue._isReady()) {
    emit('WARN', 'WEBHOOK_QUEUE_UNAVAILABLE', {
      source:      SOURCE,
      operationId,
      reason:      _isEnabled() ? 'PostgreSQL not ready' : 'recovery queue disabled',
    });
    return;
  }

  try {
    await queue.enqueue({
      operationId,
      operationType: OPERATION_TYPES.WEBHOOK_DELIVERY,
      service:       'webhooks',
      payload,
    });
    metrics.inc('recovery_enqueued_total', { operationType: OPERATION_TYPES.WEBHOOK_DELIVERY });
  } catch (err) {
    const obsMetrics = require('../../observability/metrics');
    obsMetrics.prqPersistFailedTotal.inc({ operationType: OPERATION_TYPES.WEBHOOK_DELIVERY });
    emit('WARN', 'WEBHOOK_ENQUEUE_FAILED', {
      source:      SOURCE,
      operationId,
      error:       err.message,
    });

    try {
      await journal.appendEntry({
        operationId,
        operationType: OPERATION_TYPES.WEBHOOK_DELIVERY,
        service:       'webhooks',
        payload,
        originalError: err.message,
      });
      metrics.inc('journal_write_total', { operationType: OPERATION_TYPES.WEBHOOK_DELIVERY, result: 'success' });
      obsMetrics.prqJournalWriteTotal.inc({ result: 'success' });
    } catch (journalErr) {
      metrics.inc('journal_write_total', { operationType: OPERATION_TYPES.WEBHOOK_DELIVERY, result: 'failure' });
      obsMetrics.prqJournalWriteTotal.inc({ result: 'failure' });
      obsMetrics.prqJournalWriteFailedTotal.inc({ operationType: OPERATION_TYPES.WEBHOOK_DELIVERY });
      emit('ERROR', 'JOURNAL_WRITE_FAILED', {
        source:       SOURCE,
        operationId,
        operationType: OPERATION_TYPES.WEBHOOK_DELIVERY,
        error:        journalErr.message,
        pgError:      err.message,
      });
    }
  }
}

/**
 * @returns {{ queueDepth: number, dlqDepth: number, journalDepth: number,
 *   journalOldestEntryAgeMs: number, journalBytes: number, metricsSnapshot: object }}
 */
async function getStats() {
  const [qStats, jStats] = await Promise.all([
    queue.getStats(),
    journal.getStats(),
  ]);
  return {
    ...qStats,
    journalDepth:            jStats.depth,
    journalOldestEntryAgeMs: jStats.oldestEntryAgeMs,
    journalBytes:            jStats.totalBytes,
    metricsSnapshot: metrics.snapshot(),
  };
}

/**
 * is a COMMIT for this request already waiting in the durable recovery queue or the file journal? (The boot reconciler leaves such a request to the
 * replay, which carries the TRUE outcome, instead of writing OUTCOME_UNKNOWN over it.)
 */
async function hasPendingCommit(requestId) {
  const operationId = `commit:${requestId}`;
  try { if (fs.existsSync(journal._entryPath(operationId))) return true; } catch { /* journal unreadable: fall through */ }
  if (!pgPool.isEnabled()) return false;
  try {
    const r = await pgPool.query("SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1 AND status = 'PENDING'", [operationId], 'recovery_has_pending_commit');
    return r.rows.length > 0;
  } catch { return false; }
}

module.exports = {
  setCommitWriter,
  initialize,
  shutdown,
  enqueue,
  enqueueWithOutcome,
  hasPendingCommit,
  enqueueWebhookDelivery,
  isEnabled:   _isEnabled,
  getStats,
  listDlq:     queue.listDlq,
  isPersistenceFailure,
  OPERATION_TYPES,
  // Test-only: exposes the retry handlers registered with the worker so unit
  // tests can exercise them directly without a live database connection.
  _builtinHandlers,
};
