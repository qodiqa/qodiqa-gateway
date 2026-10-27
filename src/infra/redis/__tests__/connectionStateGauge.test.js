'use strict';

/**
 * qodiqa_redis_connection_state_code (0=DISCONNECTED, 1=DEGRADED, 2=RECOVERING, 3=HEALTHY)
 * must follow EVERY managed-client state transition. Before the fix it was written only on RECOVERING (2) and
 * HEALTHY (3), so it read 3 while a client was DEGRADED and had no series at all before the first ready.
 *
 *   CS-01  single mode: the series exists at 0 (DISCONNECTED) as soon as the client is constructed
 *   CS-02  single mode: verified ready → 3; transient error on an open client → 1; recovered → 3
 *   CS-03  single mode: terminal end → 2; recovery → 3
 *   CS-04  single mode: a command-deadline miss (silent partition) → 1; the stall threshold → 2
 *   CS-05  sentinel mode: connect → 3; error → 1; MASTER_CHANGE → 2; master ready → 3
 *   CS-06  cluster mode: connect → 3; error → 1
 *   CS-07  the gauge value always equals the code of health().state (no transition bypasses the gauge)
 *   CS-08  a throwing metrics registry never breaks a state transition
 */

const { EventEmitter } = require('events');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const metrics = require('../../../observability/metrics');
const { createManagedRedisClient, HEALTH_STATE } = require('../managedClient');

const CODE = { DISCONNECTED: 0, DEGRADED: 1, RECOVERING: 2, HEALTHY: 3 };

function gauge(purpose) {
  const line = metrics.redisConnectionStateCode.format().split('\n').find((l) => l.includes(`purpose="${purpose}"`));
  if (!line) return undefined;
  return Number(line.split(' ').pop());
}

const settle = (ms = 30) => new Promise((r) => setTimeout(r, ms));

class FakeSingleClient extends EventEmitter {
  constructor({ hangPing = false } = {}) {
    super();
    this.isReady = false;
    this.isOpen = false;
    this._hangPing = hangPing;
  }
  async connect() {
    this.isOpen = true; this.isReady = true;
    this.emit('connect'); this.emit('ready');
    return this;
  }
  ping() {
    if (this._hangPing) return new Promise(() => {});
    return Promise.resolve('PONG');
  }
  get(k) { return this._hangGet ? new Promise(() => {}) : Promise.resolve(`v:${k}`); }
  destroy() { this.isOpen = false; this.isReady = false; }
}

function singleCfg() {
  return { mode: 'single', valid: true, validationErrors: [], sentinel: {}, cluster: {}, retry: { baseDelayMs: 1, maxDelayMs: 1, jitterRatio: 0 } };
}

function makeSingle(purpose, clients) {
  const createClient = jest.fn();
  for (const c of clients) createClient.mockReturnValueOnce(c);
  const client = createManagedRedisClient({ purpose, haConfig: singleCfg(), _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() } });
  client.on('error', () => {});
  return { client, createClient };
}

class FakeHa extends EventEmitter {
  constructor() { super(); this._ready = false; }
  get isReady() { return this._ready; }
  get isOpen() { return this._ready; }
  async connect() { this._ready = true; return this; }
  async close() { this._ready = false; }
}

function haCfg(mode) {
  return {
    mode, valid: true, validationErrors: [],
    sentinel: { masterName: 'm', rootNodes: [{ host: 'h', port: 26379 }], scanIntervalMs: 1000, useReplicas: false },
    cluster: { rootNodes: [{ host: 'h', port: 7000 }] },
    retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1, jitterRatio: 0, circuitBreakerCooldownMs: 10 },
  };
}

describe('redis connection-state gauge', () => {
  const savedEnv = { ...process.env };
  afterEach(() => {
    for (const k of ['REDIS_COMMAND_DEADLINE_MS', 'REDIS_WATCHDOG_INTERVAL_MS', 'REDIS_STALL_THRESHOLD']) {
      if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k];
    }
  });

  test('CS-01 the series exists at 0 (DISCONNECTED) as soon as the client is constructed', () => {
    makeSingle('cs01', [new FakeSingleClient()]);
    expect(gauge('cs01')).toBe(CODE.DISCONNECTED);
  });

  test('CS-02 verified ready → 3; transient error on an open client → 1; reconnected → 3', async () => {
    const a = new FakeSingleClient();
    const { client } = makeSingle('cs02', [a]);
    await client.connect(); await settle();
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(gauge('cs02')).toBe(CODE.HEALTHY);

    a.isReady = false; a.emit('error', new Error('ECONNRESET'));          // node-redis is reconnecting: still open
    expect(client.health().state).toBe(HEALTH_STATE.DEGRADED);
    expect(gauge('cs02')).toBe(CODE.DEGRADED);

    a.isReady = true; a.emit('ready'); await settle();                     // node-redis's own reconnect succeeded
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(gauge('cs02')).toBe(CODE.HEALTHY);
  });

  test('CS-03 terminal end → 2 (RECOVERING); recovery → 3', async () => {
    const a = new FakeSingleClient(); const b = new FakeSingleClient({ hangPing: true }); const c = new FakeSingleClient();
    const { client } = makeSingle('cs03', [a, b, c]);
    await client.connect(); await settle();
    a.isOpen = false; a.isReady = false; a.emit('end');
    expect(gauge('cs03')).toBe(CODE.RECOVERING);
    await settle();
    // b connected but its verification PING never answers: still RECOVERING, never HEALTHY
    expect(client.health().state).toBe(HEALTH_STATE.RECOVERING);
    expect(gauge('cs03')).toBe(CODE.RECOVERING);
    b.isOpen = false; b.isReady = false; b.emit('end');
    await settle();
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(gauge('cs03')).toBe(CODE.HEALTHY);
  });

  test('CS-04 a command-deadline miss → 1 (DEGRADED); the stall threshold → 2 (RECOVERING)', async () => {
    process.env.REDIS_COMMAND_DEADLINE_MS = '20';
    process.env.REDIS_WATCHDOG_INTERVAL_MS = '0';
    process.env.REDIS_STALL_THRESHOLD = '2';
    const a = new FakeSingleClient(); const b = new FakeSingleClient({ hangPing: true });
    const { client } = makeSingle('cs04', [a, b]);
    await client.connect(); await settle();
    expect(gauge('cs04')).toBe(CODE.HEALTHY);
    a._hangGet = true;
    await expect(client.get('k1')).rejects.toMatchObject({ code: 'REDIS_COMMAND_DEADLINE_EXCEEDED' });
    expect(client.health().state).toBe(HEALTH_STATE.DEGRADED);
    expect(gauge('cs04')).toBe(CODE.DEGRADED);
    await expect(client.get('k2')).rejects.toMatchObject({ code: 'REDIS_COMMAND_DEADLINE_EXCEEDED' });
    expect(client.health().state).toBe(HEALTH_STATE.RECOVERING);
    expect(gauge('cs04')).toBe(CODE.RECOVERING);
    await client.disconnect();
  });

  test('CS-05 sentinel: connect → 3; error → 1; MASTER_CHANGE → 2; new master ready → 3', async () => {
    const s = new FakeHa();
    const client = createManagedRedisClient({ purpose: 'cs05', haConfig: haCfg('sentinel'), _redis: { createClient: jest.fn(), createSentinel: jest.fn(() => s), createCluster: jest.fn() } });
    client.on('error', () => {});
    expect(gauge('cs05')).toBe(CODE.DISCONNECTED);
    await client.connect();
    expect(gauge('cs05')).toBe(CODE.HEALTHY);
    s.emit('error', new Error('node down'));
    expect(gauge('cs05')).toBe(CODE.DEGRADED);
    s._ready = false;
    s.emit('topology-change', { type: 'MASTER_CHANGE', node: { host: 'h2', port: 6379 } });
    expect(gauge('cs05')).toBe(CODE.RECOVERING);
    s._ready = true;
    await settle(250);
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(gauge('cs05')).toBe(CODE.HEALTHY);
  });

  test('CS-06 cluster: connect → 3; error → 1', async () => {
    const c = new FakeHa();
    const client = createManagedRedisClient({ purpose: 'cs06', haConfig: haCfg('cluster'), _redis: { createClient: jest.fn(), createSentinel: jest.fn(), createCluster: jest.fn(() => c) } });
    client.on('error', () => {});
    await client.connect();
    expect(gauge('cs06')).toBe(CODE.HEALTHY);
    c.emit('error', new Error('slot owner down'));
    expect(client.health().state).toBe(HEALTH_STATE.DEGRADED);
    expect(gauge('cs06')).toBe(CODE.DEGRADED);
  });

  test('CS-07 the gauge always equals the code of health().state across a full outage/recovery cycle', async () => {
    const a = new FakeSingleClient(); const b = new FakeSingleClient();
    const { client } = makeSingle('cs07', [a, b]);
    const check = () => expect(gauge('cs07')).toBe(CODE[client.health().state]);
    check();
    await client.connect(); await settle(); check();
    a.isReady = false; a.emit('error', new Error('x')); check();
    a.isOpen = false; a.emit('error', new Error('gave up')); check();   // give-up path
    await settle(); check();
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
  });

  test('CS-08 a throwing metrics registry never breaks a state transition', async () => {
    const spy = jest.spyOn(metrics.redisConnectionStateCode, 'set').mockImplementation(() => { throw new Error('registry down'); });
    try {
      const a = new FakeSingleClient();
      const { client } = makeSingle('cs08', [a]);
      await client.connect(); await settle();
      expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
      a.isReady = false; a.emit('error', new Error('x'));
      expect(client.health().state).toBe(HEALTH_STATE.DEGRADED);
    } finally {
      spy.mockRestore();
    }
  });
});
