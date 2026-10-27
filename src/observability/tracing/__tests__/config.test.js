'use strict';

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit }          = require('../../../../services/logger');
const { loadTracingConfig } = require('../config');

describe('loadTracingConfig — disabled state', () => {
  let savedEnv;
  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_OTEL_ENABLED;
    jest.clearAllMocks();
  });
  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('returns enabled=false when QODIQA_OTEL_ENABLED is absent', () => {
    expect(loadTracingConfig().enabled).toBe(false);
  });

  it('returns enabled=false when QODIQA_OTEL_ENABLED=false', () => {
    process.env.QODIQA_OTEL_ENABLED = 'false';
    expect(loadTracingConfig().enabled).toBe(false);
  });

  it('returns valid=false when disabled', () => {
    expect(loadTracingConfig().valid).toBe(false);
  });

  it('does not emit errors when simply disabled', () => {
    loadTracingConfig();
    expect(emit).not.toHaveBeenCalled();
  });

  it('returns a frozen object', () => {
    expect(Object.isFrozen(loadTracingConfig())).toBe(true);
  });
});

describe('loadTracingConfig — valid enabled config', () => {
  let savedEnv;
  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_OTEL_ENABLED;
    delete process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT;
    delete process.env.QODIQA_OTEL_SERVICE_NAME;
    delete process.env.QODIQA_OTEL_SAMPLE_RATE;
    delete process.env.QODIQA_OTEL_MAX_RETRIES;
    delete process.env.QODIQA_OTEL_BATCH_SIZE;
    jest.clearAllMocks();
  });
  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('enabled=true and valid=true with HTTPS endpoint', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    const cfg = loadTracingConfig();
    expect(cfg.enabled).toBe(true);
    expect(cfg.valid).toBe(true);
    expect(cfg.endpoint).toBe('https://otel.company.com');
  });

  it('serviceName reads from QODIQA_OTEL_SERVICE_NAME', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    process.env.QODIQA_OTEL_SERVICE_NAME               = 'my-service';
    expect(loadTracingConfig().serviceName).toBe('my-service');
  });

  it('serviceName defaults to "qodiqa"', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    expect(loadTracingConfig().serviceName).toBe('qodiqa');
  });

  it('sampleRate reads from QODIQA_OTEL_SAMPLE_RATE', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    process.env.QODIQA_OTEL_SAMPLE_RATE               = '0.5';
    expect(loadTracingConfig().sampleRate).toBe(0.5);
  });

  it('sampleRate defaults to 1.0', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    expect(loadTracingConfig().sampleRate).toBe(1.0);
  });

  it('maxRetries reads from QODIQA_OTEL_MAX_RETRIES', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    process.env.QODIQA_OTEL_MAX_RETRIES               = '5';
    expect(loadTracingConfig().maxRetries).toBe(5);
  });

  it('maxRetries defaults to 3', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    expect(loadTracingConfig().maxRetries).toBe(3);
  });

  it('batchSize defaults to 100', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    expect(loadTracingConfig().batchSize).toBe(100);
  });

  it('returned config is frozen', () => {
    process.env.QODIQA_OTEL_ENABLED                    = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT     = 'https://otel.company.com';
    expect(Object.isFrozen(loadTracingConfig())).toBe(true);
  });
});

describe('loadTracingConfig — misconfiguration', () => {
  let savedEnv;
  beforeEach(() => {
    savedEnv = { ...process.env };
    delete process.env.QODIQA_OTEL_ENABLED;
    delete process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT;
    jest.clearAllMocks();
  });
  afterEach(() => {
    Object.keys(process.env).forEach(k => { if (!(k in savedEnv)) delete process.env[k]; });
    Object.assign(process.env, savedEnv);
  });

  it('valid=false + ERROR emitted when enabled but endpoint missing', () => {
    process.env.QODIQA_OTEL_ENABLED = 'true';
    const cfg = loadTracingConfig();
    expect(cfg.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'TRACING_CONFIG_INVALID', expect.any(Object));
  });

  it('valid=false + ERROR emitted when endpoint is HTTP (not HTTPS)', () => {
    process.env.QODIQA_OTEL_ENABLED                = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'http://otel.company.com';
    const cfg = loadTracingConfig();
    expect(cfg.valid).toBe(false);
    expect(emit).toHaveBeenCalledWith('ERROR', 'TRACING_CONFIG_INVALID', expect.any(Object));
  });

  it('sampleRate clamps to 1.0 for out-of-range values', () => {
    process.env.QODIQA_OTEL_ENABLED                = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'https://otel.company.com';
    process.env.QODIQA_OTEL_SAMPLE_RATE            = '2.5';
    expect(loadTracingConfig().sampleRate).toBe(1.0);
  });

  it('sampleRate clamps to 1.0 for non-numeric values', () => {
    process.env.QODIQA_OTEL_ENABLED                = 'true';
    process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT = 'https://otel.company.com';
    process.env.QODIQA_OTEL_SAMPLE_RATE            = 'banana';
    expect(loadTracingConfig().sampleRate).toBe(1.0);
  });
});
