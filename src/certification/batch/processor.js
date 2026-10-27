'use strict';

// Batch processor — concurrency-controlled execution of certification items.
//
// createBatchProcessor({ store, evaluationEngine, concurrency? })
//   Wraps evaluationEngine.evaluate() with per-item isolation, cancellation
//   checks, and store status updates.  Never duplicates certification logic.

const crypto                        = require('crypto');
const { append: _auditAppend }      = require('../../core/audit/audit-log');
const { EMPTY_OUTPUT_HASH }          = require('../../core/audit/entryBuilder');   // v7 R-5
const { emit }                      = require('../../../services/logger');

// ── Audit-chain helpers ───────────────────────────────────────────────────────

function _sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// Stable policy hash for all batch certification audit events.
const _BATCH_POLICY_HASH = _sha256('BATCH_CERTIFICATION_AUDIT_POLICY:v1');

// Positive lifecycle events use ALLOW; terminal-failure events use BLOCK.
const _ALLOW_EVENTS = new Set(['BATCH_STARTED', 'BATCH_COMPLETED']);

async function _appendBatchAuditEvent(eventType, batch, extra = {}) {
  try {
    const timestamp  = new Date().toISOString();
    const payload    = JSON.stringify({
      batchId:    batch.batchId,
      eventType,
      tenantId:   batch.tenantId || null,
      frameworkId: batch.frameworkId,
      itemCount:  Array.isArray(batch.items) ? batch.items.length : 0,
      timestamp,
      ...extra,
    });
    const inputHash  = _sha256(payload);
    const isPositive = _ALLOW_EVENTS.has(eventType);

    await _auditAppend({
      artifactId:         `${batch.batchId}:${eventType}`,
      inputHash,
      decision:           isPositive ? 'ALLOW' : 'BLOCK',
      signature:          _sha256(`${inputHash}:batch_audit`),
      requestHash:        inputHash,
      policyHash:         _BATCH_POLICY_HASH,
      verificationResult: isPositive,
      tenantId:           batch.tenantId || undefined,
      // v7 (R-3/R-5): a batch lifecycle record is a DECISION entry that delivers no output content, so its
      // outputHash is the hash of the empty byte string — stated explicitly, since a v7 ALLOW must name it.
      entryType:          'DECISION',
      outputHash:         EMPTY_OUTPUT_HASH,
      executionContext: {
        stage:       'BATCH_LIFECYCLE',
        event:       eventType,
        batchId:     batch.batchId,
        frameworkId: batch.frameworkId,
        itemCount:   Array.isArray(batch.items) ? batch.items.length : 0,
        ...extra,
      },
    });
  } catch (err) {
    // Audit failure must never corrupt batch processing.
    emit('ERROR', 'BATCH_AUDIT_APPEND_FAILED', {
      batchId: batch.batchId,
      event:   eventType,
      error:   err?.message,
    });
  }
}

const DEFAULT_CONCURRENCY = (() => {
  const v = parseInt(process.env.QODIQA_BATCH_MAX_CONCURRENCY, 10);
  return Number.isFinite(v) && v > 0 ? v : 5;
})();

function createBatchProcessor({ store, evaluationEngine, concurrency } = {}) {
  const _limit = (typeof concurrency === 'number' && concurrency > 0)
    ? concurrency
    : DEFAULT_CONCURRENCY;

  // ── Semaphore ───────────────────────────────────────────────────────────────

  let _running = 0;
  const _queue = [];

  function _acquire() {
    return new Promise(resolve => {
      if (_running < _limit) { _running++; resolve(); }
      else { _queue.push(resolve); }
    });
  }

  function _release() {
    if (_queue.length > 0) {
      const next = _queue.shift();
      next();
    } else {
      _running--;
    }
  }

  // ── Single item execution ───────────────────────────────────────────────────

  async function _processItem(batchId, item, { requestedBy, requestIp } = {}) {
    await store.updateItem(batchId, item.itemId, {
      status:    'running',
      startedAt: new Date().toISOString(),
    });

    try {
      const result = await evaluationEngine.evaluate(
        {
          artifacts:        item.artifacts       || [],
          evidencePackages: item.evidencePackages || [],
          controls:         item.controls        || {},
        },
        { requestedBy: requestedBy || null, requestIp: requestIp || null },
      );

      // evaluationEngine.evaluate() returns camelCase fields (certificationId, certificationDecision,
      // certificationLevel, generatedAt). This code read snake_case names (and the unit test mocked snake_case, hiding it), so a
      // completed item recorded certificationId null and lost decision/level/generatedAt. snake_case is still accepted as a fallback.
      const certificationId = result.certificationId ?? result.certification_id ?? null;
      await store.updateItem(batchId, item.itemId, {
        status:          'completed',
        certificationId,
        result: {
          certificationDecision: result.certificationDecision ?? result.certification_decision,
          certificationLevel:    result.certificationLevel    ?? result.certification_level,
          score:                 result.score,
          generatedAt:           result.generatedAt           ?? result.generated_at,
        },
        error:       null,
        completedAt: new Date().toISOString(),
      });

      return { success: true, itemId: item.itemId, certificationId };
    } catch (err) {
      await store.updateItem(batchId, item.itemId, {
        status:      'failed',
        error:       err?.message || 'Unknown error',
        completedAt: new Date().toISOString(),
      });

      return { success: false, itemId: item.itemId, error: err?.message };
    }
  }

  // ── Batch execution ─────────────────────────────────────────────────────────

  async function processBatch(batchId, { requestedBy, requestIp } = {}) {
    const batch = await store.get(batchId);
    if (!batch) {
      const e = new Error(`Batch not found: ${batchId}`);
      e.code = 'NOT_FOUND';
      throw e;
    }

    await store.update(batchId, {
      status:    'running',
      startedAt: new Date().toISOString(),
    });

    emit('INFO', 'BATCH_PROCESSING_STARTED', {
      batchId,
      itemCount: batch.items.length,
      tenantId:  batch.tenantId,
    });

    _appendBatchAuditEvent('BATCH_STARTED', batch);

    const pendingItems = batch.items.filter(i => i.status === 'pending');
    const results = [];

    await Promise.all(pendingItems.map(async item => {
      await _acquire();
      try {
        // Re-check cancellation before each item
        const current = await store.get(batchId);
        if (current && current.status === 'cancelled') {
          await store.updateItem(batchId, item.itemId, {
            status: 'cancelled',
            error:  'Batch was cancelled',
          });
          results.push({ success: false, itemId: item.itemId, cancelled: true });
          return;
        }

        const r = await _processItem(batchId, item, { requestedBy, requestIp });
        results.push(r);
      } finally {
        _release();
      }
    }));

    // Determine final batch status
    const finalBatch = await store.get(batchId);
    if (!finalBatch || finalBatch.status === 'cancelled') return finalBatch;

    const allItems    = finalBatch.items;
    const anyFailed   = allItems.some(i => i.status === 'failed');
    const anyPending  = allItems.some(i => i.status === 'pending');
    const finalStatus = anyPending ? 'failed' : (anyFailed ? 'failed' : 'completed');

    const updated = await store.update(batchId, {
      status:      finalStatus,
      completedAt: new Date().toISOString(),
    });

    const succeeded = results.filter(r => r.success).length;
    const failed    = results.filter(r => !r.success && !r.cancelled).length;
    const cancelled = results.filter(r => r.cancelled).length;

    emit('INFO', 'BATCH_PROCESSING_FINISHED', {
      batchId,
      status:     finalStatus,
      tenantId:   batch.tenantId,
      succeeded,
      failed,
      cancelled,
    });

    // Use the final batch record (with updated item count data) for audit
    const auditEvent = finalStatus === 'completed' ? 'BATCH_COMPLETED' : 'BATCH_FAILED';
    _appendBatchAuditEvent(auditEvent, batch, { succeeded, failed, cancelled });

    return updated;
  }

  return { processBatch };
}

module.exports = { createBatchProcessor };
