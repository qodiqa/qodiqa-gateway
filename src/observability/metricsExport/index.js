'use strict';

const { loadMetricsExportConfig }   = require('./config');
const { createOtlpMetricsExporter } = require('./otlpExporter');
const { createMetricsExportBridge } = require('./bridge');
const metrics                       = require('../metrics');

const _NOOP_STATS = Object.freeze({
  exported_total:        0,
  failed_total:          0,
  skipped_overlap_total: 0,
});

const _NOOP_HEALTH = Object.freeze({
  component:   'otlp_metrics_export',
  status:      'disabled',
  exporter:    'noop',
  lastExport:  null,
  lastFailure: null,
  inFlight:    false,
});

const _NOOP = Object.freeze({
  getHealth: () => Object.assign({}, _NOOP_HEALTH),
  getStats:  () => Object.assign({}, _NOOP_STATS),
  shutdown:  async () => {},
});

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initialise the optional metrics OTLP export bridge.
 *
 * Returns a no-op subsystem when disabled or misconfigured, so callers
 * never need to guard on the return value — mirrors
 * src/observability/tracing/index.js's initTracing() exactly.
 *
 * The EXISTING /metrics scrape endpoint (src/api/routes/metrics.js) is
 * completely unaffected either way: this bridge only ever READS the
 * registry (metrics.getRegistrySnapshot()), on its own timer, and pushes a
 * translated copy elsewhere — it never mutates, replaces, or gates
 * anything collect()/format() do.
 *
 * @param {object}  [config]              — result of loadMetricsExportConfig(); loaded from env if omitted
 * @param {object}  [deps]
 * @param {object}  [deps.exporter]       — override the OTLP exporter (for testing)
 * @param {Function}[deps.httpsPost]      — override the HTTP transport (for testing)
 * @param {Function}[deps.getRegistrySnapshot] — override the registry accessor (for testing)
 * @returns {{ getHealth, getStats, shutdown }}
 */
function initMetricsOtlpBridge(config, deps = {}) {
  if (!config) config = loadMetricsExportConfig();
  if (!config.enabled || !config.valid) return _NOOP;

  const exporter = deps.exporter || createOtlpMetricsExporter(config, { httpsPost: deps.httpsPost });
  const getRegistrySnapshot = deps.getRegistrySnapshot || metrics.getRegistrySnapshot;
  const bridge = createMetricsExportBridge(config, { exporter, getRegistrySnapshot });

  bridge.start();

  return {
    getHealth: () => bridge.getHealth(),
    getStats:  () => bridge.getStats(),
    shutdown:  () => bridge.shutdown(),
  };
}

module.exports = { initMetricsOtlpBridge, loadMetricsExportConfig };
