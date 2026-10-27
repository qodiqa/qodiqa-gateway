'use strict';

/**
 * Audit Event Dispatcher — remediation.
 *
 * Root cause of src/observability/logShipping/ is a complete,
 * production-ready bulk log-shipping subsystem (ELK/Datadog/Splunk/SIEM
 * destinations, retry/backoff, redaction, health/metrics) that nothing ever
 * called — createLogShipper()/loadLogShipConfig() had zero call sites
 * outside their own module and tests. Separately,
 * src/alerting/notification/channels/SIEMChannel.js's CEF/syslog export only
 * ever saw the narrow, filtered subset of events that make it through
 * DetectionEngine's detector pipeline into an Alert object — never the full
 * audit/log stream.
 *
 * This module closes both gaps by subscribing once to services/logger.js's
 * `eventBus` — the same central fan-out point DetectionEngine already uses
 * for alerting (`eventBus.on('log', ...)`), reached by every emit() call in
 * the process — and forwarding every record to the log shipper. Alerts are
 * unaffected: they continue to flow through their existing path (
 * DetectionEngine -> AlertEngine -> NotificationService -> SIEMChannel) and
 * simply become one more category visible within the complete exported
 * stream, since the audit event(s) that triggered them were already exported
 * here as themselves.
 *
 * Architecture (informational — matches the required shape from the
 * remediation spec):
 *
 *   Audit Event (emit())
 *     |
 *     +-- Local audit log (stdout/stderr + centralStore.ingest() -- existing,
 *     |   unaffected by this module: services/logger.js writes both at the
 *     |   same emit() call, independent of eventBus)
 *     +-- Transparency log (existing, independent write path at enforcement
 *     |   call sites -- see src/core/transparency/enforcementBridge.js)
 *     +-- eventBus.emit('log', record)          <- existing fan-out point
 *           +-- DetectionEngine (existing: alert detection)
 *           +-- auditEventDispatcher (NEW: this module)
 *                 +-- logShipper.ship(record) -> elk / datadog / splunk / siem
 *                     (future connectors: subscribe here the same way)
 *
 * Each destination is independent (queue.js dispatches per-destination) and
 * failures never propagate back to emit() -- see ship()'s try/catch below
 * and logShipping/queue.js's own failure-isolation invariants.
 */

const { eventBus } = require('../../services/logger');

// The 'log-shipping-dispatch' background task (src/observability/logShipping/
// queue.js, run via BackgroundTaskRunner) itself emits BACKGROUND_TASK_
// COMPLETED/FAILED through services/logger.js on every dispatch. Forwarding
// those specific records back into the shipper would ship an event that
// itself completes a dispatch, which emits another such record, forwarded
// again -- an unconditional, unbounded feedback loop (confirmed: caused a
// heap OOM in testing). This is the *only* exclusion needed: it is narrowly
// scoped to the exporter's own self-referential telemetry about the
// log-shipping-dispatch task specifically, not a general noise filter --
// every other event, including BACKGROUND_TASK_COMPLETED/FAILED for every
// *other* background task, is exported as part of the complete audit stream.
// The excluded records remain fully observable via the qodiqa_background_task_*
// and qodiqa_logship_* Prometheus metrics (src/observability/metrics.js).
function _isSelfReferential(record) {
  return (record.eventType === 'BACKGROUND_TASK_COMPLETED' || record.eventType === 'BACKGROUND_TASK_FAILED')
    && record.task === 'log-shipping-dispatch';
}

let _attached = false;
let _shipper  = null;

/**
 * Subscribe the given log shipper to the audit/log event stream.
 * Idempotent — safe to call more than once (e.g. re-required in tests);
 * only the first call attaches a listener.
 *
 * @param {{ ship: Function }} shipper — a createLogShipper() instance (or the no-op)
 */
function attach(shipper) {
  if (_attached) return;
  _shipper = shipper;
  eventBus.on('log', _onLogRecord);
  _attached = true;
}

function _onLogRecord(record) {
  if (_isSelfReferential(record)) return;
  try {
    _shipper.ship(record);
  } catch {
    // Exporter failures must never affect the emit() call path -- ship()
    // itself already never throws (see logShipping/index.js), this is a
    // defensive second layer.
  }
}

/** Unsubscribe. Used by graceful shutdown and by tests. */
function detach() {
  if (!_attached) return;
  eventBus.removeListener('log', _onLogRecord);
  _attached = false;
  _shipper  = null;
}

/** @returns {boolean} whether a shipper is currently attached */
function isAttached() {
  return _attached;
}

module.exports = { attach, detach, isAttached };
