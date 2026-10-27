'use strict';

/**
 * Webhook Dispatcher — Component #28
 *
 * Fire-and-forget fan-out: when a supported event occurs, this module
 * finds all matching enabled endpoints and enqueues one delivery operation
 * per endpoint.  The triggering operation never waits for HTTP delivery.
 *
 * SUPPORTED EVENTS:
 *   certification.completed — emitted after each certification evaluation
 *   attestation.completed   — emitted after each attestation verification
 * approval.requested | approval.decided | approval.expired | approval.cancelled - human approval of an agent action
 *
 * DELIVERY FLOW:
 *   1. dispatchEvent() is called synchronously by the domain module.
 *   2. listByEventType() looks up matching endpoints (requires PG).
 *   3. One WEBHOOK_DELIVERY operation is enqueued per endpoint.
 *   4. The persistence recovery worker picks up and delivers asynchronously.
 *   5. Failed deliveries are retried with exponential backoff (max 5 attempts).
 *   6. After max retries, the operation moves to the Dead Letter Queue.
 *
 * IDEMPOTENCY:
 *   Each event has a globally unique eventId.  The queue operationId is
 *   derived as `whd:<endpointId>:<eventId>`.  Duplicate enqueue calls
 *   for the same (endpoint, event) pair are rejected by the queue's
 *   atomic claim script.
 *
 * RATE LIMITING:
 *   The queue is single-worker by default — natural per-endpoint serialization.
 *   Concurrent delivery to distinct endpoints is limited by queue throughput.
 */

const crypto    = require('crypto');
const { emit }  = require('../../../services/logger');
const metrics   = require('./webhookMetrics');
const store     = require('./webhookStore');
const pgPool    = require('../../infra/postgres/pool');

// Loaded lazily to avoid circular-dependency issues at module load time.
let _recovery = null;
function _getRecovery() {
  if (!_recovery) _recovery = require('../persistenceRecovery');
  return _recovery;
}

// ── Supported event types ─────────────────────────────────────────────────────

const SUPPORTED_EVENTS = Object.freeze(new Set([
  'certification.completed',
  'attestation.completed',
  'approval.requested',
  'approval.decided',
  'approval.expired',
  'approval.cancelled',
]));

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build a certification.completed event payload.
 *
 * @param {object} record  Certification row or evaluation result
 * @returns {{ eventId: string, eventType: string, timestamp: string, ...fields }}
 */
function buildCertificationCompletedPayload(record) {
  return {
    eventId:         crypto.randomUUID(),
    eventType:       'certification.completed',
    timestamp:       new Date().toISOString(),
    certificationId: record.certification_id ?? record.certificationId,
    tenantId:        record.tenant_id        ?? record.tenantId        ?? null,
    level:           record.certification_level   ?? record.level,
    score:           record.score,
    status:          record.certification_decision ?? record.status,
  };
}

/**
 * Build an attestation.completed event payload.
 *
 * @param {object} record  Attestation row or result
 * @returns {{ eventId: string, eventType: string, timestamp: string, ...fields }}
 */
function buildAttestationCompletedPayload(record) {
  return {
    eventId:        crypto.randomUUID(),
    eventType:      'attestation.completed',
    timestamp:      new Date().toISOString(),
    attestationId:  record.attestation_id ?? record.attestationId,
    tenantId:       record.tenant_id      ?? record.tenantId ?? null,
    decision:       record.attestation_decision ?? record.decision,
    policyVersion:  record.policy_version  ?? record.policyVersion ?? null,
  };
}

/**
 * Build an approval.* event payload. It names the action by hash and tool - never its arguments, which may be sensitive.
 * @param {string} eventType  approval.requested | approval.decided | approval.expired | approval.cancelled
 * @param {object} a          an approval (src/core/approvals/approvalStore.js)
 */
function buildApprovalPayload(eventType, a) {
  return {
    eventId:     crypto.randomUUID(),
    eventType,
    timestamp:   new Date().toISOString(),
    tenantId:    a.tenantId,
    approvalId:  a.approvalId,
    status:      a.status,
    actionHash:  a.actionHash,
    tool:        `${a.tool.server}/${a.tool.name}`,
    actionClass: a.actionClass,
    agentId:     a.agentId,
    sessionId:   a.sessionId,
    seq:         a.seq,
    requesterId: a.requesterId,
    approverId:  a.approverId || null,
    expiresAt:   a.status === 'APPROVED' ? a.approvalExpiresAt : a.expiresAt,
  };
}

/**
 * Dispatch an event to all subscribed enabled endpoints.
 * This function is non-blocking: it schedules work and returns immediately.
 * It must never be awaited on the hot delivery path.
 *
 * @param {string} eventType  e.g. 'certification.completed'
 * @param {object} payload    Event payload object (must include eventId)
 */
function dispatchEvent(eventType, payload) {
  if (!SUPPORTED_EVENTS.has(eventType)) {
    emit('WARN', 'WEBHOOK_UNSUPPORTED_EVENT', { eventType });
    return;
  }

  // Schedule the async work without blocking the caller
  setImmediate(() => {
    _fanOut(eventType, payload).catch(err => {
      emit('ERROR', 'WEBHOOK_DISPATCH_ERROR', { eventType, eventId: payload?.eventId, error: err.message });
    });
  });
}

// ── Fan-out ───────────────────────────────────────────────────────────────────

async function _fanOut(eventType, payload) {
  const tenantId = payload?.tenantId ?? null;
  let endpoints;
  try {
    // Use tenant context when available so RLS restricts fan-out to the
    // tenant whose event fired.  This is correct: tenant A's certification
    // should only notify tenant A's webhook endpoints, never tenant B's.
    if (tenantId && pgPool.isEnabled()) {
      endpoints = await pgPool.withTenantTransaction(tenantId, (tx) =>
        store.listByEventType(eventType, { tx }),
      );
    } else {
      endpoints = await store.listByEventType(eventType);
    }
  } catch (err) {
    emit('ERROR', 'WEBHOOK_FANOUT_LOOKUP_FAILED', { eventType, error: err.message });
    return;
  }

  if (!endpoints || endpoints.length === 0) return;

  const recovery = _getRecovery();
  const { OPERATION_TYPES } = recovery;

  for (const endpoint of endpoints) {
    const operationId = `whd:${endpoint.id}:${payload.eventId}`;

    try {
      await recovery.enqueueWebhookDelivery({
        operationId,
        payload: {
          endpointId:   endpoint.id,
          eventId:      payload.eventId,
          eventType,
          eventPayload: payload,
          // Explicit opt-in to safe retries (Component 44.6).
          // Webhook deliveries carry X-QODIQA-Event-ID so receiving endpoints
          // can deduplicate; the delivery is therefore safe to retry.
          isIdempotent: true,
          httpMethod:   'POST',
        },
      });
      metrics.inc('webhook_queue_depth_total', { eventType });
    } catch (err) {
      emit('ERROR', 'WEBHOOK_ENQUEUE_FAILED', {
        endpointId:  endpoint.id,
        eventId:     payload.eventId,
        eventType,
        error:       err.message,
      });
    }
  }

  emit('INFO', 'WEBHOOK_DISPATCH_QUEUED', {
    eventType,
    eventId:       payload.eventId,
    endpointCount: endpoints.length,
  });
}

module.exports = {
  dispatchEvent,
  buildCertificationCompletedPayload,
  buildAttestationCompletedPayload,
  buildApprovalPayload,
  SUPPORTED_EVENTS,
};
