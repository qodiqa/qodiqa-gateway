'use strict';

const { createMetricsExportBridge } = require('../bridge');

function makeConfig(overrides = {}) {
  return { exportIntervalMs: 20, ...overrides };
}

function makeExporter(impl) {
  return { name: 'otlp', exportMetrics: jest.fn(impl) };
}

const REGISTRY = () => [{ toOtlpMetric: () => ({ name: 'x' }) }];

describe('createMetricsExportBridge — happy path', () => {
  it('start() triggers periodic exports at the configured interval', async () => {
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await new Promise(r => setTimeout(r, 65)); // ~3 ticks at 20ms
    await bridge.shutdown();
    expect(exporter.exportMetrics.mock.calls.length).toBeGreaterThanOrEqual(3);
  });

  it('getHealth() reports healthy after a successful export', async () => {
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await bridge.shutdown();
    expect(bridge.getHealth().status).toBe('healthy');
    expect(bridge.getHealth().lastExport).not.toBeNull();
  });

  it('getStats() counts exported_total correctly', async () => {
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await new Promise(r => setTimeout(r, 45));
    await bridge.shutdown();
    expect(bridge.getStats().exported_total).toBeGreaterThan(0);
    expect(bridge.getStats().failed_total).toBe(0);
  });

  it('start() is idempotent — calling it twice does not create two timers', async () => {
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    bridge.start();
    await new Promise(r => setTimeout(r, 45));
    await bridge.shutdown();
    // 45ms / 20ms ≈ 2 ticks from ONE timer; a doubled timer would show ~4
    expect(exporter.exportMetrics.mock.calls.length).toBeLessThan(4);
  });
});

describe('createMetricsExportBridge — collector unavailable / export failure', () => {
  it('a rejected export is caught — never thrown into the caller', async () => {
    const exporter = makeExporter(async () => { throw new Error('ECONNREFUSED'); });
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await new Promise(r => setTimeout(r, 25));
    await expect(bridge.shutdown()).resolves.toBeUndefined();
  });

  it('getHealth() reports degraded after a failed export', async () => {
    const exporter = makeExporter(async () => { throw new Error('network error'); });
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await bridge.shutdown();
    expect(bridge.getHealth().status).toBe('degraded');
    expect(bridge.getStats().failed_total).toBeGreaterThan(0);
  });

  it('process/caller remains responsive across repeated failures — no hang, no throw', async () => {
    const exporter = makeExporter(async () => { throw new Error('down'); });
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    const start = Date.now();
    bridge.start();
    await new Promise(r => setTimeout(r, 60));
    await bridge.shutdown();
    expect(Date.now() - start).toBeLessThan(1000); // bounded, not hung
  });
});

describe('createMetricsExportBridge — exporter timeout / slow collector', () => {
  it('a slow (but eventually resolving) export completes without special-casing', async () => {
    const exporter = makeExporter(() => new Promise(r => setTimeout(() => r(), 30)));
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    // Generous margin (not a tight race): first tick at ~20ms, export resolves
    // ~30ms later (~50ms). Wait well past that before asserting, rather than
    // waiting exactly as long as the slowest step takes.
    await new Promise(r => setTimeout(r, 150));
    await bridge.shutdown();
    expect(bridge.getStats().exported_total).toBeGreaterThan(0);
  });

  it('a permanently-hanging export never resolves getHealth()/getStats() into an inconsistent state (bridge itself stays responsive)', async () => {
    const exporter = makeExporter(() => new Promise(() => {})); // never resolves
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await new Promise(r => setTimeout(r, 25));
    // getHealth/getStats must be synchronous and never block on the hung export
    expect(() => bridge.getHealth()).not.toThrow();
    expect(bridge.getHealth().inFlight).toBe(true);
  });
});

describe('createMetricsExportBridge — bounded concurrency / backpressure', () => {
  it('never runs more than one export concurrently, even when ticks fire faster than exports complete', async () => {
    let concurrent = 0;
    let maxConcurrent = 0;
    const exporter = makeExporter(async () => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise(r => setTimeout(r, 60)); // slower than the 20ms tick interval
      concurrent--;
    });
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await new Promise(r => setTimeout(r, 150));
    await bridge.shutdown();
    expect(maxConcurrent).toBe(1);
  });

  it('overlapping ticks are counted as skipped, not silently dropped without a trace', async () => {
    const exporter = makeExporter(() => new Promise(r => setTimeout(r, 60)));
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await new Promise(r => setTimeout(r, 150));
    await bridge.shutdown();
    expect(bridge.getStats().skipped_overlap_total).toBeGreaterThan(0);
  });

  it('registry snapshot is re-read fresh on every export (not cached/stale)', async () => {
    let counter = 0;
    const getRegistrySnapshot = jest.fn(() => [{ toOtlpMetric: () => ({ name: 'x', value: counter++ }) }]);
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot });
    bridge.start();
    await new Promise(r => setTimeout(r, 45));
    await bridge.shutdown();
    expect(getRegistrySnapshot.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});

describe('createMetricsExportBridge — shutdown', () => {
  it('shutdown() stops the timer — no further exports fire afterward', async () => {
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await new Promise(r => setTimeout(r, 25));
    await bridge.shutdown();
    const countAtShutdown = exporter.exportMetrics.mock.calls.length;
    await new Promise(r => setTimeout(r, 60));
    expect(exporter.exportMetrics.mock.calls.length).toBe(countAtShutdown);
  });

  it('shutdown() makes one final export attempt', async () => {
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig({ exportIntervalMs: 1_000_000 }), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start(); // interval far in the future — no natural tick will fire
    await bridge.shutdown();
    expect(exporter.exportMetrics).toHaveBeenCalledTimes(1);
  });

  it('shutdown() never throws even when the final export fails', async () => {
    const exporter = makeExporter(async () => { throw new Error('down'); });
    const bridge = createMetricsExportBridge(makeConfig({ exportIntervalMs: 1_000_000 }), { exporter, getRegistrySnapshot: REGISTRY });
    bridge.start();
    await expect(bridge.shutdown()).resolves.toBeUndefined();
  });

  it('shutdown() is safe to call before start()', async () => {
    const exporter = makeExporter(async () => {});
    const bridge = createMetricsExportBridge(makeConfig(), { exporter, getRegistrySnapshot: REGISTRY });
    await expect(bridge.shutdown()).resolves.toBeUndefined();
  });
});
