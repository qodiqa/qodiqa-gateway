'use strict';

/**
 * Splunk Common Information Model (CIM) field mapper — #6.
 *
 * Deterministic, pure mapping from the QODIQA standard outbound log schema
 * (src/observability/logShipping/schema.js's normalizeEvent() output) to a
 * flat object using Splunk CIM field names, scoped to the "Alerts" data
 * model (the closest fit for QODIQA's operational/security/audit event
 * stream) rather than attempting full coverage of every CIM data model.
 *
 * This is additive: the existing raw HEC export (destinations/splunk.js's
 * default 'raw' mode) is unchanged and remains available — CIM is an
 * opt-in alternate schema (config.splunk.schema = 'cim').
 *
 * Mapping table (documented here — mirrored in
 * docs/operations/SIEM_EXPORT_SCHEMA.md), per the CIM "Alerts" model:
 *
 *   CIM field      Source                          Notes
 *   -------------- ------------------------------- --------------------------------
 *   _time          event.timestamp                  epoch seconds
 *   signature      event.eventType                   raw, unmodified — the alert/event name
 *   severity       derived from event.severity       CIM string enum, see SEVERITY_MAP
 *   severity_id    derived from event.severity       numeric, 1 (informational) – 5 (critical)
 *   dest           event.service                     the QODIQA instance/service name
 *   vendor_product (constant)                        'QODIQA Platform'
 *   app            (constant)                        'qodiqa'
 *   tenant         event.tenantId
 *   request_id     event.requestId
 *   trace_id       event.traceId                     omitted if absent
 *   description    event.message
 *
 * CIM's `user`/`src` fields are intentionally omitted — the normalized
 * QODIQA event schema does not carry an acting-user identity or source IP
 * at this layer (that data lives in the audit chain itself, not the
 * operational log stream), and populating them with a placeholder would be
 * misleading in Splunk's Alerts searches.
 */

const SEVERITY_MAP = Object.freeze({
  INFO:     'informational',
  WARN:     'low',
  ERROR:    'high',
  CRITICAL: 'critical',
  FATAL:    'critical',
});

const SEVERITY_ID_MAP = Object.freeze({
  INFO:     1,
  WARN:     2,
  ERROR:    4,
  CRITICAL: 5,
  FATAL:    5,
});

/**
 * Map a normalized QODIQA log event to a Splunk CIM (Alerts model)-shaped object.
 *
 * @param {object} event — output of logShipping/schema.js's normalizeEvent()
 * @returns {object}
 */
function mapToCim(event) {
  const src = event || {};
  const severity = src.severity || 'INFO';

  return {
    _time:          Math.floor(new Date(src.timestamp || Date.now()).getTime() / 1000),
    signature:      src.eventType || 'LOG',
    severity:       SEVERITY_MAP[severity] || 'informational',
    severity_id:    SEVERITY_ID_MAP[severity] ?? 1,
    dest:           src.service || 'qodiqa',
    vendor_product: 'QODIQA Platform',
    app:            'qodiqa',
    tenant:         src.tenantId || null,
    request_id:     src.requestId || null,
    ...(src.traceId ? { trace_id: src.traceId } : {}),
    description:    (src.message || '').slice(0, 500),
  };
}

module.exports = { mapToCim, SEVERITY_MAP, SEVERITY_ID_MAP };
