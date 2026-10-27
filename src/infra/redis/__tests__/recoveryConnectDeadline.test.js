'use strict';

/**
 * phase 11 — a single-mode recovery
 * attempt whose connect() never settles (TCP accepted, handshake replies dropped: a silent partition at reconnect time)
 * must not stall recovery forever. Found by test/redisResilience RR-06 against a real Redis behind a fault proxy.
 *
 *   RC-01 a hung recovery connect() is abandoned after connectTimeout + REDIS_COMMAND_DEADLINE_MS, the half-open client
 *         is torn down, and the next attempt recovers the connection to HEALTHY
 *   RC-03 (RD-2) a consumer 'ready' listener that throws during a reconnect announcement is contained and logged
 *         (REDIS_CLIENT_LISTENER_FAILED) instead of escaping as an unhandled rejection (fatal under processHardening.js)
 *   RC-02 with the deadline mechanism disabled (REDIS_COMMAND_DEADLINE_MS=0) no bound is applied (documented opt-out)
 */

const { EventEmitter } = require('events');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
const { emit } = require('../../../../services/logger');
const { createManagedRedisClient, HEALTH_STATE } = require('../managedClient');

class Fake extends EventEmitter {
  constructor({ hangConnect = false } = {}) { super(); this.isReady = false; this.isOpen = false; this.hang = hangConnect; this.destroyed = false; }
  async connect() {
    this.isOpen = true;
    if (this.hang) return new Promise(() => {});           // handshake never answered
    this.isReady = true; this.emit('connect'); this.emit('ready');
    return this;
  }
  ping() { return Promise.resolve('PONG'); }
  destroy() { this.destroyed = true; this.isOpen = false; this.isReady = false; }
}
const settle = (ms) => new Promise((r) => setTimeout(r, ms));

function make(purpose, clients) {
  const createClient = jest.fn();
  for (const c of clients) createClient.mockReturnValueOnce(c);
  const client = createManagedRedisClient({
    purpose, connectTimeout: 30,
    haConfig: { mode: 'single', valid: true, validationErrors: [], sentinel: {}, cluster: {}, retry: { baseDelayMs: 1, maxDelayMs: 1, jitterRatio: 0 } },
    _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
  });
  client.on('error', () => {});
  return { client, createClient };
}

describe('RD-1 bounded recovery connect', () => {
  const saved = {};
  beforeEach(() => { for (const k of ['REDIS_COMMAND_DEADLINE_MS', 'REDIS_WATCHDOG_INTERVAL_MS']) saved[k] = process.env[k]; process.env.REDIS_WATCHDOG_INTERVAL_MS = '0'; });
  afterEach(() => { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

  test('RC-01 a hung recovery connect is abandoned and the next attempt recovers', async () => {
    process.env.REDIS_COMMAND_DEADLINE_MS = '20';
    const a = new Fake(); const b = new Fake({ hangConnect: true }); const c = new Fake();
    const { client, createClient } = make('rc01', [a, b, c]);
    await client.connect(); await settle(10);
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
    a.isOpen = false; a.isReady = false; a.emit('end');          // terminal: recovery starts, b's connect hangs
    await settle(300);
    expect(b.destroyed).toBe(true);                               // the half-open client was torn down
    expect(createClient).toHaveBeenCalledTimes(3);
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(client.isReady).toBe(true);
    expect(emit.mock.calls.some(([, t]) => t === 'REDIS_RECOVERY_COMPLETED')).toBe(true);
    await client.disconnect();
  });

  test('RC-03 (RD-2) a consumer ready-listener that throws on a reconnect is contained: no unhandled rejection, HEALTHY', async () => {
    process.env.REDIS_COMMAND_DEADLINE_MS = '20';
    const escaped = [];
    const onUnhandled = (r) => escaped.push(r);
    process.on('unhandledRejection', onUnhandled);
    try {
      const a = new Fake(); const b = new Fake();
      const { client } = make('rc03', [a, b]);
      client.on('ready', ({ isReconnect } = {}) => { if (isReconnect) throw new TypeError("Cannot read properties of null (reading 'subscribe')"); });
      await client.connect(); await settle(10);
      a.isOpen = false; a.isReady = false; a.emit('end');
      await settle(100);
      expect(escaped).toEqual([]);
      expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
      expect(emit.mock.calls.some(([s, t, d]) => s === 'ERROR' && t === 'REDIS_CLIENT_LISTENER_FAILED' && d.event === 'ready' && d.purpose === 'rc03')).toBe(true);
      await client.disconnect();
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  test('RC-02 REDIS_COMMAND_DEADLINE_MS=0 disables the bound (no teardown of a pending connect)', async () => {
    process.env.REDIS_COMMAND_DEADLINE_MS = '0';
    const a = new Fake(); const b = new Fake({ hangConnect: true });
    const { client, createClient } = make('rc02', [a, b]);
    await client.connect(); await settle(10);
    a.isOpen = false; a.isReady = false; a.emit('end');
    await settle(200);
    expect(b.destroyed).toBe(false);
    expect(createClient).toHaveBeenCalledTimes(2);
    expect(client.health().state).toBe(HEALTH_STATE.RECOVERING);
    await client.disconnect();
  });
});
