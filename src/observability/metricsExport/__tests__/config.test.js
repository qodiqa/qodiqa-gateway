'use strict';

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit } = require('../../../../services/logger');
const { loadMetricsExportConfig, MIN_EXPORT_INTERVAL_MS } = require('../config');

const ENV_KEYS = [
  'QODIQA_OTEL_METRICS_ENABLED',
  'QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT',
  'QODIQA_OTEL_SERVICE_NAME',
  'QODIQA_OTEL_METRICS_EXPORT_INTERVAL_MS',
];

function resetEnv() {
  for (const k of ENV_KEYS) delete process.env[k];
  jest.clearAllMocks();
}

describe('loadMetricsExportConfig — disabled state (default)', () => {
  let savedEnv;
  beforeEach(() => { savedEnv = { ...process.env }; resetEnv(); });
  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('returns enabled=false when QODIQA_OTEL_METRICS_ENABLED is absent', () => {
    expect(loadMetricsExportConfig().enabled).toBe(false);
  });

  it('returns enabled=false when QODIQA_OTEL_METRICS_ENABLED=false', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED = 'false';
    expect(loadMetricsExportConfig().enabled).toBe(false);
  });

  it('returns valid=false when disabled', () => {
    expect(loadMetricsExportConfig().valid).toBe(false);
  });

  it('does not emit errors when simply disabled', () => {
    loadMetricsExportConfig();
    expect(emit).not.toHaveBeenCalled();
  });

  it('returns a frozen object', () => {
    expect(Object.isFrozen(loadMetricsExportConfig())).toBe(true);
  });

  it('QODIQA_OTEL_ENABLED (the tracing flag) alone does NOT enable metrics export', () => {
    process.env.QODIQA_OTEL_ENABLED = 'true'; // a different, tracing-only flag
    expect(loadMetricsExportConfig().enabled).toBe(false);
  });
});

describe('loadMetricsExportConfig — valid enabled config', () => {
  let savedEnv;
  beforeEach(() => { savedEnv = { ...process.env }; resetEnv(); });
  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('enabled=true and valid=true with HTTPS endpoint', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED        = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'https://otel.company.com';
    const cfg = loadMetricsExportConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.valid).toBe(true);
    expect(cfg.endpoint).toBe('https://otel.company.com');
  });

  it('serviceName reads from QODIQA_OTEL_SERVICE_NAME (shared with tracing)', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED        = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'https://otel.company.com';
    process.env.QODIQA_OTEL_SERVICE_NAME           = 'my-service';
    expect(loadMetricsExportConfig().serviceName).toBe('my-service');
  });

  it('serviceName defaults to "qodiqa"', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED        = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'https://otel.company.com';
    expect(loadMetricsExportConfig().serviceName).toBe('qodiqa');
  });

  it('exportIntervalMs reads from QODIQA_OTEL_METRICS_EXPORT_INTERVAL_MS', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED             = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT      = 'https://otel.company.com';
    process.env.QODIQA_OTEL_METRICS_EXPORT_INTERVAL_MS  = '30000';
    expect(loadMetricsExportConfig().exportIntervalMs).toBe(30000);
  });

  it('exportIntervalMs defaults to 60000', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED        = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'https://otel.company.com';
    expect(loadMetricsExportConfig().exportIntervalMs).toBe(60000);
  });

  it('exportIntervalMs below the floor falls back to the default (60000), never a sub-floor value', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED             = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT      = 'https://otel.company.com';
    process.env.QODIQA_OTEL_METRICS_EXPORT_INTERVAL_MS  = '100'; // below MIN_EXPORT_INTERVAL_MS
    expect(loadMetricsExportConfig().exportIntervalMs).toBe(60000);
    expect(loadMetricsExportConfig().exportIntervalMs).toBeGreaterThanOrEqual(MIN_EXPORT_INTERVAL_MS);
  });

  it('returned config is frozen', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED        = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'https://otel.company.com';
    expect(Object.isFrozen(loadMetricsExportConfig())).toBe(true);
  });
});

describe('loadMetricsExportConfig — misconfiguration', () => {
  let savedEnv;
  beforeEach(() => { savedEnv = { ...process.env }; resetEnv(); });
  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('valid=false + ERROR emitted when enabled but endpoint missing', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED = 'true';
    const cfg = loadMetricsExportConfig();
    expect(cfg.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'METRICS_EXPORT_CONFIG_INVALID', expect.any(Object));
  });

  it('valid=false + ERROR emitted when endpoint is HTTP (not HTTPS)', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED        = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'http://otel.company.com';
    const cfg = loadMetricsExportConfig();
    expect(cfg.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'METRICS_EXPORT_CONFIG_INVALID', expect.any(Object));
  });

  it('valid=false for a malformed/unparseable endpoint string', () => {
    process.env.QODIQA_OTEL_METRICS_ENABLED        = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'not a url at all';
    expect(loadMetricsExportConfig().valid).toBe(false);
  });
});
