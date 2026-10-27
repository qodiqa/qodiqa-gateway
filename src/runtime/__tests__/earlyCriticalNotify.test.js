'use strict';

/**
 * MON-3 — src/runtime/earlyCriticalNotify.js is the best-effort CRITICAL
 * notifier used by the multi-instance HA startup guard (the one fail-safe
 * gate that runs before src/alerting has initialized). Contract mirrors
 * scripts/dr/alert.js's postAlert(): no-op if unconfigured, never throws.
 */

const { notifyCriticalStartupFailure } = require('../earlyCriticalNotify');

describe('earlyCriticalNotify', () => {
  const ORIGINAL_ENV = { ...process.env };
  let fetchSpy;

  beforeEach(() => {
    fetchSpy = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    process.env = { ...ORIGINAL_ENV };
  });

  test('no-ops when ALERT_WEBHOOK_URL is unset', async () => {
    delete process.env.ALERT_WEBHOOK_URL;
    await notifyCriticalStartupFailure({ eventType: 'TEST_EVENT', reason: 'test' });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test('posts a payload with the required fields when configured', async () => {
    process.env.ALERT_WEBHOOK_URL = 'https://example.com/hook';
    fetchSpy.mockResolvedValue({ ok: true });

    await notifyCriticalStartupFailure({
      eventType: 'AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN',
      reason: 'two instances detected',
      action: 'run as a single process',
      deploymentMode: 'single-node',
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe('https://example.com/hook');
    expect(options.method).toBe('POST');
    expect(options.headers['Content-Type']).toBe('application/json');

    const payload = JSON.parse(options.body);
    expect(payload.eventType).toBe('AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN');
    expect(payload.reason).toBe('two instances detected');
    expect(payload.action).toBe('run as a single process');
    expect(payload.deploymentMode).toBe('single-node');
    expect(typeof payload.hostname).toBe('string');
    expect(payload.hostname.length).toBeGreaterThan(0);
    expect(typeof payload.nodeId).toBe('string');
    expect(typeof payload.timestamp).toBe('string');
    expect(() => new Date(payload.timestamp).toISOString()).not.toThrow();
    expect(payload.text).toContain('AUDIT_CHAIN_MULTI_INSTANCE_FORBIDDEN');
  });

  test('never throws when fetch rejects', async () => {
    process.env.ALERT_WEBHOOK_URL = 'https://example.com/hook';
    fetchSpy.mockRejectedValue(new Error('ECONNREFUSED'));

    await expect(
      notifyCriticalStartupFailure({ eventType: 'X', reason: 'y' })
    ).resolves.toBeUndefined();
  });

  test('never throws when fetch hangs past the internal timeout', async () => {
    process.env.ALERT_WEBHOOK_URL = 'https://example.com/hook';
    process.env.QODIQA_CRITICAL_NOTIFY_TIMEOUT_MS = '50';
    fetchSpy.mockImplementation((url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('aborted')));
    }));

    await expect(
      notifyCriticalStartupFailure({ eventType: 'X', reason: 'y' })
    ).resolves.toBeUndefined();
  });

  test('nodeId falls back to NODE_APP_INSTANCE, then HOSTNAME, then pid', async () => {
    process.env.ALERT_WEBHOOK_URL = 'https://example.com/hook';
    fetchSpy.mockResolvedValue({ ok: true });

    process.env.NODE_APP_INSTANCE = '2';
    await notifyCriticalStartupFailure({ eventType: 'X', reason: 'y' });
    expect(JSON.parse(fetchSpy.mock.calls[0][1].body).nodeId).toBe('2');
  });
});
