'use strict';

// Configuration loading and startup validation for the log shipping subsystem.
//
// loadLogShipConfig() reads environment variables and returns a frozen config
// object.  Invalid destination configuration generates explicit startup errors
// via emit() and marks the destination as invalid (valid=false), preventing
// silent misconfiguration.
//
// A destination that is enabled=true but valid=false is NOT silently disabled —
// the ERROR event is emitted at startup to surface the misconfiguration.

const { emit } = require('../../../services/logger');

// ── Destination loaders ───────────────────────────────────────────────────────

// #6: shared 'raw'|schema-name validator — an unrecognized value
// degrades to 'raw' (the pre-existing, always-safe default) rather than
// hard-failing startup, matching this file's established posture for every
// other misconfigured-but-recoverable value.
function _loadSchema(envVar, destination, allowed) {
  const raw = (process.env[envVar] || 'raw').trim().toLowerCase();
  if (raw === 'raw' || allowed.includes(raw)) return raw;
  emit('ERROR', 'LOGSHIP_CONFIG_INVALID', {
    destination,
    message: `${envVar}="${raw}" is not a recognized schema — falling back to 'raw'. Valid values: raw, ${allowed.join(', ')}`,
  });
  return 'raw';
}

function _loadElk() {
  const enabled = process.env.QODIQA_LOGSHIP_ELK_ENABLED === 'true';
  if (!enabled) return Object.freeze({ enabled: false, valid: false });

  const url = (process.env.QODIQA_LOGSHIP_ELK_URL || '').trim();
  const valid = Boolean(url && url.startsWith('https://'));
  const schema = _loadSchema('QODIQA_LOGSHIP_ELK_SCHEMA', 'elk', ['ecs']);

  if (!valid) {
    emit('ERROR', 'LOGSHIP_CONFIG_INVALID', {
      destination: 'elk',
      message:     'QODIQA_LOGSHIP_ELK_URL must be set to a valid HTTPS URL',
      hint:        'Example: QODIQA_LOGSHIP_ELK_URL=https://logstash.company.com',
    });
  }

  return Object.freeze({ enabled, url, schema, valid });
}

function _loadDatadog() {
  const enabled = process.env.QODIQA_LOGSHIP_DATADOG_ENABLED === 'true';
  if (!enabled) return Object.freeze({ enabled: false, valid: false });

  const apiKey = (process.env.QODIQA_LOGSHIP_DATADOG_API_KEY || '').trim();
  const site   = (process.env.QODIQA_LOGSHIP_DATADOG_SITE   || 'datadoghq.com').trim();
  const valid  = Boolean(apiKey);

  if (!valid) {
    emit('ERROR', 'LOGSHIP_CONFIG_INVALID', {
      destination: 'datadog',
      message:     'QODIQA_LOGSHIP_DATADOG_API_KEY is required when Datadog shipping is enabled',
    });
  }

  return Object.freeze({ enabled, apiKey, site, valid });
}

function _loadSplunk() {
  const enabled = process.env.QODIQA_LOGSHIP_SPLUNK_ENABLED === 'true';
  if (!enabled) return Object.freeze({ enabled: false, valid: false });

  const url   = (process.env.QODIQA_LOGSHIP_SPLUNK_URL   || '').trim();
  const token = (process.env.QODIQA_LOGSHIP_SPLUNK_TOKEN || '').trim();

  const urlValid   = Boolean(url && url.startsWith('https://'));
  const tokenValid = Boolean(token);
  const valid      = urlValid && tokenValid;
  const schema     = _loadSchema('QODIQA_LOGSHIP_SPLUNK_SCHEMA', 'splunk', ['cim']);

  if (!valid) {
    emit('ERROR', 'LOGSHIP_CONFIG_INVALID', {
      destination: 'splunk',
      missingUrl:   !urlValid,
      missingToken: !tokenValid,
      message:      'QODIQA_LOGSHIP_SPLUNK_URL (HTTPS) and QODIQA_LOGSHIP_SPLUNK_TOKEN are both required',
    });
  }

  return Object.freeze({ enabled, url, token, schema, valid });
}

function _loadSiem() {
  const enabled = process.env.QODIQA_LOGSHIP_SIEM_ENABLED === 'true';
  if (!enabled) return Object.freeze({ enabled: false, valid: false });

  // Falls back to the existing alert-scoped ALERT_SIEM_* variables so an
  // operator who already pointed alerting at a SIEM gets full audit-stream
  // export by flipping QODIQA_LOGSHIP_SIEM_ENABLED=true, with no duplicate
  // endpoint configuration required. See src/alerting/notification/channels/
  // SIEMChannel.js, whose CEF/syslog formatting and transport this
  // destination reuses via src/observability/siem/cef.js.
  const mode  = (process.env.QODIQA_LOGSHIP_SIEM_MODE  || process.env.ALERT_SIEM_MODE  || 'http').trim();
  const url   = (process.env.QODIQA_LOGSHIP_SIEM_URL   || process.env.ALERT_SIEM_URL   || '').trim();
  const token = (process.env.QODIQA_LOGSHIP_SIEM_TOKEN || process.env.ALERT_SIEM_TOKEN || '').trim();

  const syslogHost  = (process.env.QODIQA_LOGSHIP_SIEM_SYSLOG_HOST  || process.env.ALERT_SIEM_SYSLOG_HOST  || '').trim();
  const syslogPort  = parseInt(process.env.QODIQA_LOGSHIP_SIEM_SYSLOG_PORT  || process.env.ALERT_SIEM_SYSLOG_PORT  || '514', 10);
  const syslogProto = (process.env.QODIQA_LOGSHIP_SIEM_SYSLOG_PROTO || process.env.ALERT_SIEM_SYSLOG_PROTO || 'udp').trim();

  const valid = mode === 'syslog'
    ? Boolean(syslogHost)
    : Boolean(url && url.startsWith('https://'));

  if (!valid) {
    emit('ERROR', 'LOGSHIP_CONFIG_INVALID', {
      destination: 'siem',
      mode,
      message: mode === 'syslog'
        ? 'QODIQA_LOGSHIP_SIEM_SYSLOG_HOST (or ALERT_SIEM_SYSLOG_HOST) is required when SIEM syslog shipping is enabled'
        : 'QODIQA_LOGSHIP_SIEM_URL (or ALERT_SIEM_URL) must be set to a valid HTTPS URL when SIEM http shipping is enabled',
    });
  }

  return Object.freeze({ enabled, mode, url, token, syslogHost, syslogPort, syslogProto, valid });
}

// ── Main loader ───────────────────────────────────────────────────────────────

/**
 * Load and validate all log shipping configuration from environment variables.
 * Emits ERROR for each misconfigured (enabled but invalid) destination.
 *
 * @returns {object} Frozen config object
 */
function loadLogShipConfig() {
  const elk     = _loadElk();
  const datadog = _loadDatadog();
  const splunk  = _loadSplunk();
  const siem    = _loadSiem();

  const maxRetries = (() => {
    const v = parseInt(process.env.QODIQA_LOGSHIP_MAX_RETRIES, 10);
    return Number.isFinite(v) && v >= 0 ? v : 3;
  })();

  const batchSize = (() => {
    const v = parseInt(process.env.QODIQA_LOGSHIP_BATCH_SIZE, 10);
    return Number.isFinite(v) && v > 0 ? v : 50;
  })();

  // Per-destination in-flight cap. Protects against unbounded memory growth
  // if a destination is persistently slow/unreachable; events beyond the cap
  // are dropped (counted via logs_dropped_total / qodiqa_logship_dropped_total)
  // rather than queued without limit.
  const maxQueueDepth = (() => {
    const v = parseInt(process.env.QODIQA_LOGSHIP_MAX_QUEUE_DEPTH, 10);
    return Number.isFinite(v) && v > 0 ? v : 10_000;
  })();

  return Object.freeze({
    elk,
    datadog,
    splunk,
    siem,
    service:     (process.env.QODIQA_SERVICE_NAME || 'qodiqa').trim(),
    environment: (process.env.NODE_ENV             || 'development').trim(),
    maxRetries,
    batchSize,
    maxQueueDepth,
  });
}

module.exports = { loadLogShipConfig };
