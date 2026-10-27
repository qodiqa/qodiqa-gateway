'use strict';

/**
 * Elastic Common Schema (ECS) field mapper — #6.
 *
 * Deterministic, pure mapping from the QODIQA standard outbound log schema
 * (src/observability/logShipping/schema.js's normalizeEvent() output —
 * {timestamp, service, environment, tenantId, tenantSlug, eventType,
 * severity, requestId, traceId, message, metadata}) to a flat ECS-shaped
 * object, targeting ECS version 8.11.
 *
 * This is additive: the existing CEF/raw export (src/observability/siem/
 * cef.js, destinations/elk.js's default 'raw' mode) is unchanged and remains
 * available — ECS is an opt-in alternate schema for the ELK destination
 * (config.elk.schema = 'ecs').
 *
 * Mapping table (documented here — mirrored in
 * docs/operations/SIEM_EXPORT_SCHEMA.md):
 *
 *   ECS field            Source                          Notes
 *   -------------------- ------------------------------- --------------------------------
 *   @timestamp            event.timestamp                 ISO 8601, unchanged
 *   ecs.version            (constant)                      pinned to '8.11'
 *   event.action           event.eventType (lowercased)    e.g. 'audit_chain_corrupted'
 *   event.category         derived from event.metadata.category  see CATEGORY_MAP below
 *   event.severity         derived from event.severity     numeric, 0 (INFO) – 10 (FATAL/CRITICAL)
 *   event.outcome          derived from event.severity     'success'|'unknown'|'failure'
 *   trace.id               event.traceId                   omitted if absent
 *   service.name           event.service
 *   service.environment    event.environment
 *   message                event.message
 *   qodiqa.event_type      event.eventType                 raw, unmodified — exact-match reference
 *   qodiqa.tenant.id       event.tenantId
 *   qodiqa.tenant.slug     event.tenantSlug
 *   qodiqa.request.id      event.requestId
 *   qodiqa.metadata        event.metadata                  vendor-namespaced, avoids polluting ECS's own reserved fields
 *
 * event.category is a best-effort mapping from QODIQA's 3-value category
 * taxonomy (SECURITY/AUDIT/OPERATIONAL, services/logClassifier.js) onto
 * ECS's fixed controlled vocabulary, which has no single value that maps
 * 1:1 onto any of the three — this is a defensible approximation for SIEM
 * routing/search, not an authoritative categorization.
 */

const ECS_VERSION = '8.11';

const SEVERITY_MAP = Object.freeze({
  INFO:     0,
  WARN:     5,
  ERROR:    8,
  CRITICAL: 10,
  FATAL:    10,
});

const OUTCOME_MAP = Object.freeze({
  INFO:     'success',
  WARN:     'unknown',
  ERROR:    'failure',
  CRITICAL: 'failure',
  FATAL:    'failure',
});

const CATEGORY_MAP = Object.freeze({
  SECURITY:    ['intrusion_detection'],
  AUDIT:       ['iam'],
  OPERATIONAL: ['process'],
});

function _actionFromEventType(eventType) {
  return String(eventType || 'unknown').toLowerCase();
}

/**
 * Map a normalized QODIQA log event to an ECS-shaped object.
 *
 * @param {object} event — output of logShipping/schema.js's normalizeEvent()
 * @returns {object}
 */
function mapToEcs(event) {
  const src = event || {};
  const severity = src.severity || 'INFO';
  const rawCategory = src.metadata?.category;

  return {
    '@timestamp': src.timestamp,
    ecs: { version: ECS_VERSION },
    event: {
      action:   _actionFromEventType(src.eventType),
      category: CATEGORY_MAP[rawCategory] || ['process'],
      severity: SEVERITY_MAP[severity] ?? 3,
      outcome:  OUTCOME_MAP[severity] ?? 'unknown',
    },
    ...(src.traceId ? { trace: { id: src.traceId } } : {}),
    service: {
      name:        src.service || 'qodiqa',
      environment: src.environment || 'development',
    },
    message: src.message || '',
    qodiqa: {
      event_type: src.eventType || 'LOG',
      tenant:     { id: src.tenantId || null, slug: src.tenantSlug || null },
      request:    { id: src.requestId || null },
      metadata:   src.metadata || {},
    },
  };
}

module.exports = { mapToEcs, ECS_VERSION, SEVERITY_MAP, OUTCOME_MAP, CATEGORY_MAP };
