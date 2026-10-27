'use strict';

/**
 * QODIQA Log Shipping Subsystem — Component #24
 *
 * Public API:
 *
 *   createLogShipper(config, deps?)
 *     Instantiate a log shipper from a loaded config object.
 *     Returns { ship, getHealth, getMetrics, shutdown } or a no-op instance
 *     if no destinations are active.
 *
 *   ship(event)
 *     Normalize, redact, and enqueue a log event for async export.
 *     Non-blocking — returns immediately.
 *
 *   getHealth()
 *     Per-destination health: status, lastSuccess, lastFailure, queuedEvents.
 *
 *   getMetrics()
 *     Per-destination export counters and latency samples.
 *
 *   shutdown(timeoutMs?)
 *     Await in-flight dispatches (bounded), for graceful process shutdown.
 *
 * Destinations: elk, datadog, splunk (structured JSON/NDJSON), and siem
 *. Every audit/log event normalized here (see
 * schema.js) is fed by src/observability/auditEventDispatcher.js, which
 * subscribes to services/logger.js's eventBus — the same central point
 * every emit() call already reaches — so this module now receives the
 * *complete* audit event stream, not just alert-derived events.
 *
 * Failure isolation: no error from any destination ever propagates to callers.
 * The shipper is a secondary system — core trust workflows are unaffected.
 */

const { normalizeEvent }           = require('./schema');
const { createQueue }              = require('./queue');
const { createElkDestination }     = require('./destinations/elk');
const { createDatadogDestination } = require('./destinations/datadog');
const { createSplunkDestination }  = require('./destinations/splunk');
const { createSiemDestination }    = require('./destinations/siem');

// ── No-op instance returned when no destinations are configured ───────────────

const _NOOP = Object.freeze({
  ship:       () => {},
  getHealth:  () => ({}),
  getMetrics: () => ({}),
  shutdown:   async () => {},
});

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create a log shipper instance.
 *
 * @param {object} config   — result of loadLogShipConfig()
 * @param {object} [deps]   — injectable dependencies (for testing)
 * @param {Function} [deps.elkHttpsPost]
 * @param {Function} [deps.datadogHttpsPost]
 * @param {Function} [deps.splunkHttpsPost]
 * @returns {{ ship, getHealth, getMetrics }}
 */
function createLogShipper(config, deps = {}) {
  const destinations = [];

  if (config.elk?.enabled && config.elk?.valid) {
    destinations.push(
      createElkDestination(config, { httpsPost: deps.elkHttpsPost }),
    );
  }

  if (config.datadog?.enabled && config.datadog?.valid) {
    destinations.push(
      createDatadogDestination(config, { httpsPost: deps.datadogHttpsPost }),
    );
  }

  if (config.splunk?.enabled && config.splunk?.valid) {
    destinations.push(
      createSplunkDestination(config, { httpsPost: deps.splunkHttpsPost }),
    );
  }

  if (config.siem?.enabled && config.siem?.valid) {
    destinations.push(
      createSiemDestination(config, { httpsPost: deps.siemHttpsPost, sendSyslog: deps.siemSendSyslog }),
    );
  }

  if (destinations.length === 0) return _NOOP;

  const defaults = {
    service:     config.service,
    environment: config.environment,
  };

  const queue = createQueue(destinations, config);

  return Object.freeze({
    /**
     * Normalize, redact, and enqueue a log event.
     * Non-blocking — fire-and-forget.
     *
     * @param {object} rawEvent
     */
    ship(rawEvent) {
      try {
        const normalized = normalizeEvent(rawEvent, defaults);
        queue.ship(normalized);
      } catch {
        // Schema normalization failure must never propagate
      }
    },

    /** @returns {object} per-destination health status */
    getHealth: () => queue.getHealth(),

    /** @returns {object} per-destination export metrics */
    getMetrics: () => queue.getMetrics(),

    /**
     * Graceful shutdown: wait for in-flight dispatches to settle, bounded by
     * timeoutMs so shutdown never hangs indefinitely on an unreachable
     * destination. Never throws.
     *
     * @param {number} [timeoutMs=5000]
     */
    shutdown: (timeoutMs) => queue.drain(timeoutMs),
  });
}

module.exports = { createLogShipper };
