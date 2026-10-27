'use strict';

const { initMetricsOtlpBridge } = require('../index');

describe('initMetricsOtlpBridge — disabled/misconfigured (no-op)', () => {
  it('returns a no-op subsystem when config.enabled=false', () => {
    const bridge = initMetricsOtlpBridge({ enabled: false, valid: false });
    expect(bridge.getHealth().status).toBe('disabled');
    expect(bridge.getHealth().exporter).toBe('noop');
  });

  it('returns a no-op subsystem when enabled but invalid (bad config)', () => {
    const bridge = initMetricsOtlpBridge({ enabled: true, valid: false });
    expect(bridge.getHealth().status).toBe('disabled');
  });

  it('no-op getStats() reports all zeros', () => {
    const bridge = initMetricsOtlpBridge({ enabled: false, valid: false });
    expect(bridge.getStats()).toEqual({ exported_total: 0, failed_total: 0, skipped_overlap_total: 0 });
  });

  it('no-op shutdown() resolves cleanly and never throws', async () => {
    const bridge = initMetricsOtlpBridge({ enabled: false, valid: false });
    await expect(bridge.shutdown()).resolves.toBeUndefined();
  });

  it('loads config from env when none is passed, and env has no QODIQA_OTEL_METRICS_ENABLED set', () => {
    const saved = process.env.QODIQA_OTEL_METRICS_ENABLED;
    delete process.env.QODIQA_OTEL_METRICS_ENABLED;
    const bridge = initMetricsOtlpBridge();
    expect(bridge.getHealth().status).toBe('disabled');
    if (saved !== undefined) process.env.QODIQA_OTEL_METRICS_ENABLED = saved;
  });

  it('every call returns a fresh object, not a shared mutable reference', () => {
    const bridge = initMetricsOtlpBridge({ enabled: false, valid: false });
    const h1 = bridge.getHealth();
    const h2 = bridge.getHealth();
    expect(h1).not.toBe(h2);
    expect(h1).toEqual(h2);
  });
});

describe('initMetricsOtlpBridge — enabled with valid config', () => {
  it('starts a real (mocked-transport) bridge and exports on the interval', async () => {
    const httpsPost = jest.fn().mockResolvedValue({ status: 200, body: '' });
    const config = {
      enabled: true, valid: true,
      endpoint: 'https://otel.company.com', serviceName: 'qodiqa-test', environment: 'test',
      exportIntervalMs: 20,
    };
    const bridge = initMetricsOtlpBridge(config, { httpsPost });
    await new Promise(r => setTimeout(r, 45));
    await bridge.shutdown();
    expect(httpsPost).toHaveBeenCalled();
    expect(bridge.getHealth().exporter).toBe('otlp');
  });

  it('accepts a fully-injected exporter override (bypassing config-driven construction)', async () => {
    const exporter = { name: 'otlp', exportMetrics: jest.fn().mockResolvedValue(undefined) };
    const config = { enabled: true, valid: true, exportIntervalMs: 1_000_000 };
    const bridge = initMetricsOtlpBridge(config, { exporter, getRegistrySnapshot: () => [] });
    await bridge.shutdown(); // forces exactly one export attempt via the final-flush path
    expect(exporter.exportMetrics).toHaveBeenCalledTimes(1);
  });

  it('defaults getRegistrySnapshot to the REAL metrics.getRegistrySnapshot when not overridden', async () => {
    const metrics = require('../../metrics');
    const exporter = { name: 'otlp', exportMetrics: jest.fn().mockResolvedValue(undefined) };
    const config = { enabled: true, valid: true, exportIntervalMs: 1_000_000 };
    const bridge = initMetricsOtlpBridge(config, { exporter });
    await bridge.shutdown();
    const [passedRegistry] = exporter.exportMetrics.mock.calls[0];
    expect(passedRegistry.length).toBe(metrics.getRegistrySnapshot().length);
  });
});
