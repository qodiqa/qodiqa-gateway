'use strict';

// Public factory for the batch certification service.
//
// createBatchService({ store?, evaluationEngine?, concurrency? })
//   Returns { store, processor, createBatch, cancelBatch }

const crypto                        = require('crypto');
const { append: _auditAppend }      = require('../../core/audit/audit-log');
const { EMPTY_OUTPUT_HASH }          = require('../../core/audit/entryBuilder');   // v7 R-5
const evaluationEngineDefault       = require('../../core/certification/evaluationEngine');
const { createBatchStore, buildBatch } = require('./store');
const { createBatchProcessor }         = require('./processor');
const { emit }                         = require('../../../services/logger');

// ── Audit-chain helpers ───────────────────────────────────────────────────────

function _sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

const _BATCH_POLICY_HASH = _sha256('BATCH_CERTIFICATION_AUDIT_POLICY:v1');

// Positive lifecycle events use ALLOW; terminal-failure events use BLOCK.
const _ALLOW_EVENTS = new Set(['BATCH_CREATED']);

async function _appendBatchAuditEvent(eventType, batch, extra = {}) {
  try {
    const timestamp  = new Date().toISOString();
    const payload    = JSON.stringify({
      batchId:     batch.batchId,
      eventType,
      tenantId:    batch.tenantId || null,
      frameworkId: batch.frameworkId,
      itemCount:   Array.isArray(batch.items) ? batch.items.length : 0,
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

// Metrics
const _metrics = {
  batches_created_total:    0,
  batches_completed_total:  0,
  batches_failed_total:     0,
  batches_cancelled_total:  0,
  items_processed_total:    0,
};

function getMetrics() { return Object.assign({}, _metrics); }

function createBatchService(deps = {}) {
  const store           = deps.store           || createBatchStore();
  const evaluationEngine = deps.evaluationEngine || evaluationEngineDefault;
  const concurrency      = deps.concurrency;

  const processor = createBatchProcessor({ store, evaluationEngine, concurrency });

  async function createBatch({ frameworkId, items, tenantId, requestedBy, requestId, requestIp }) {
    const batch = buildBatch({ frameworkId, items, tenantId, requestedBy, requestId });
    await store.save(batch);
    _metrics.batches_created_total++;

    emit('INFO', 'BATCH_CREATED', {
      batchId:     batch.batchId,
      frameworkId,
      itemCount:   items.length,
      tenantId:    tenantId || null,
      requestedBy: requestedBy || null,
    });

    _appendBatchAuditEvent('BATCH_CREATED', batch);

    // Fire-and-forget execution
    setImmediate(() => {
      processor.processBatch(batch.batchId, { requestedBy, requestIp })
        .then(result => {
          if (result && result.status === 'completed') _metrics.batches_completed_total++;
          else if (result && result.status === 'failed')    _metrics.batches_failed_total++;
          _metrics.items_processed_total += (batch.items.length);
        })
        .catch(err => {
          _metrics.batches_failed_total++;
          emit('ERROR', 'BATCH_PROCESSING_ERROR', {
            batchId: batch.batchId,
            error:   err?.message,
          });
        });
    });

    return batch;
  }

  async function cancelBatch(batchId, { requestedBy } = {}) {
    const batch = await store.get(batchId);
    if (!batch) {
      const e = new Error(`Batch not found: ${batchId}`);
      e.code = 'NOT_FOUND';
      throw e;
    }

    const updated = await store.update(batchId, {
      status:      'cancelled',
      cancelledAt: new Date().toISOString(),
    });

    _metrics.batches_cancelled_total++;

    emit('INFO', 'BATCH_CANCELLED', {
      batchId,
      tenantId:    batch.tenantId,
      requestedBy: requestedBy || null,
    });

    _appendBatchAuditEvent('BATCH_CANCELLED', batch, { requestedBy: requestedBy || null });

    return updated;
  }

  return { store, processor, createBatch, cancelBatch, getMetrics };
}

module.exports = { createBatchService, getMetrics };
