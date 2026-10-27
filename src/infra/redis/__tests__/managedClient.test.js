'use strict';

/**
 * managedClient.js coverage.
 *
 *   MC-01  Single mode returns the exact object createClient() produced (zero wrapping)
 *   MC-02  Single mode passes reconnectStrategy/connectTimeout straight through to buildClientOptions
 *   MC-03  Single mode registers health in the shared registry
 *   MC-04  Sentinel mode calls createSentinel with the resolved topology config
 *   MC-05  Sentinel mode's Proxy correctly binds methods against classes with #private fields
 *   MC-06  Sentinel mode connect() emits 'connect' then 'ready', updates health to HEALTHY
 *   MC-07  Sentinel mode forwards 'error' events and marks health DEGRADED
 *   MC-08  Sentinel MASTER_CHANGE topology-change increments failoverCount and emits 'reconnecting'
 *   MC-09  Sentinel MASTER_CHANGE followed by isReady becoming true emits 'ready' (isReconnect) and RECOVERING->HEALTHY
 *   MC-10  Sentinel mode's disconnect()/quit() normalize onto the underlying close()/destroy()
 *   MC-11  Cluster mode calls createCluster with the resolved seed nodes
 *   MC-12  purpose is required
 *   MC-13  Invalid haConfig logs a warning but still constructs a client (fail-open on config validation itself)
 *   MC-14  health() reflects reconnectCount/failoverCount/mode/purpose accurately
 */

const { createManagedRedisClient, HEALTH_STATE } = require('../managedClient');
const healthRegistry = require('../health');

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
const { emit } = require('../../../../services/logger');

beforeEach(() => {
  jest.clearAllMocks();
});

describe('managedClient (single mode / backward compatibility)', () => {
  test('MC-01 single mode wraps createClient()\'s result behind a stable self-healing Proxy (Finding 49)', () => {
    // Prior to Finding 49 this returned the bare createClient() object with
    // literal identity — that guarantee is deliberately gone now: a client
    // that can die permanently can no longer be all a consumer ever holds.
    // What must still hold is that every property/method a consumer already
    // used resolves through live, and does so against the CURRENT client.
    const fakeClient = { isReady: false, isOpen: false, on: jest.fn(), connect: jest.fn() };
    const createClient = jest.fn().mockReturnValue(fakeClient);
    const fakeRedis = { createClient, createSentinel: jest.fn(), createCluster: jest.fn() };

    const result = createManagedRedisClient({
      purpose: 'testSingle',
      haConfig: { mode: 'single', valid: true, validationErrors: [], sentinel: {}, cluster: {}, retry: {} },
      _redis: fakeRedis,
    });

    expect(result).not.toBe(fakeClient);
    expect(createClient).toHaveBeenCalledTimes(1);
    expect(result.isReady).toBe(false);
    fakeClient.isReady = true;
    expect(result.isReady).toBe(true); // live delegation, not a snapshot taken at construction
  });

  test('MC-02 single mode passes reconnectStrategy/connectTimeout through to buildClientOptions', () => {
    const fakeClient = { isReady: false, on: jest.fn(), connect: jest.fn() };
    const createClient = jest.fn().mockReturnValue(fakeClient);
    const reconnectStrategy = jest.fn();

    createManagedRedisClient({
      purpose: 'testSingle2',
      reconnectStrategy,
      connectTimeout: 1234,
      haConfig: { mode: 'single', valid: true, validationErrors: [], sentinel: {}, cluster: {}, retry: {} },
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });

    const passedOpts = createClient.mock.calls[0][0];
    expect(passedOpts.socket.reconnectStrategy).toBe(reconnectStrategy);
    expect(passedOpts.socket.connectTimeout).toBe(1234);
  });

  test('MC-03 single mode registers health in the shared registry', () => {
    const fakeClient = { isReady: false, on: jest.fn(), connect: jest.fn() };
    createManagedRedisClient({
      purpose: 'testSingleHealth',
      haConfig: { mode: 'single', valid: true, validationErrors: [], sentinel: {}, cluster: {}, retry: {} },
      _redis: { createClient: jest.fn().mockReturnValue(fakeClient), createSentinel: jest.fn(), createCluster: jest.fn() },
    });

    const health = healthRegistry.getAllHealth();
    expect(health.testSingleHealth).toBeDefined();
    expect(health.testSingleHealth.mode).toBe('single');
  });

  test('MC-13 invalid haConfig logs a warning but still constructs a client', () => {
    const fakeClient = { isReady: false, on: jest.fn(), connect: jest.fn() };
    createManagedRedisClient({
      purpose: 'testInvalidCfg',
      haConfig: { mode: 'single', valid: false, validationErrors: ['bad config'], sentinel: {}, cluster: {}, retry: {} },
      _redis: { createClient: jest.fn().mockReturnValue(fakeClient), createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    expect(emit).toHaveBeenCalledWith('WARN', 'REDIS_HA_CONFIG_INVALID', expect.objectContaining({ purpose: 'testInvalidCfg' }));
  });

  test('MC-12 purpose is required', () => {
    expect(() => createManagedRedisClient({})).toThrow(/purpose is required/);
  });
});

// ── Fake Sentinel-like EventEmitter with #private fields ─────────────────────
//
// Mirrors node-redis's real RedisSentinel: uses a private class field
// internally, so any Proxy that invokes its methods with `this` bound to the
// Proxy itself (rather than the real instance) would throw a TypeError. This
// class exists specifically to prove _wrapHaClient()'s Proxy binds correctly
// (MC-05) — the same failure mode the module's header comment warns about.
const { EventEmitter } = require('events');

class FakeSentinel extends EventEmitter {
  #secret = 'private-state';
  #ready = false;

  constructor() { super(); }

  get isReady() { return this.#ready; }
  get isOpen()  { return this.#ready; }

  async connect() {
    this.#ready = true;
    return this;
  }

  revealSecret() {
    // Only works if `this` is the real FakeSentinel instance.
    return this.#secret;
  }

  getMasterNode() { return { host: 'master1', port: 6379 }; }
  getReplicaNodes() { return new Map([[{ host: 'replica1', port: 6379 }, 1]]); }

  async close() { this.#ready = false; }
  async destroy() { this.#ready = false; }

  async get(key) { return `value-for-${key}`; }
}

function buildSentinelHaConfig(overrides = {}) {
  return {
    mode: 'sentinel',
    valid: true,
    validationErrors: [],
    sentinel: {
      masterName: 'mymaster',
      rootNodes: [{ host: 'sentinel1', port: 26379 }],
      scanIntervalMs: 10_000,
      useReplicas: false,
    },
    cluster: { rootNodes: [] },
    retry: { maxAttempts: 5, baseDelayMs: 100, maxDelayMs: 2000, jitterRatio: 0, circuitBreakerCooldownMs: 30_000 },
    ...overrides,
  };
}

describe('managedClient (sentinel mode)', () => {
  test('MC-04 sentinel mode calls createSentinel with the resolved topology config', () => {
    const fakeSentinel = new FakeSentinel();
    const createSentinel = jest.fn().mockReturnValue(fakeSentinel);

    createManagedRedisClient({
      purpose: 'testSentinel',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel, createCluster: jest.fn() },
    });

    expect(createSentinel).toHaveBeenCalledTimes(1);
    const args = createSentinel.mock.calls[0][0];
    expect(args.name).toBe('mymaster');
    expect(args.sentinelRootNodes).toEqual([{ host: 'sentinel1', port: 26379 }]);
    expect(args.scanInterval).toBe(10_000);
  });

  test('MC-05 Proxy correctly binds methods against classes with #private fields', async () => {
    const fakeSentinel = new FakeSentinel();
    const client = createManagedRedisClient({
      purpose: 'testPrivateFields',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });

    // Would throw "Cannot read private member" if the Proxy's get-trap used
    // Reflect.get(target, prop, receiver) instead of binding to the real target.
    expect(() => client.revealSecret()).not.toThrow();
    expect(client.revealSecret()).toBe('private-state');
    await expect(client.get('foo')).resolves.toBe('value-for-foo');
  });

  test('MC-06 connect() emits connect then ready, updates health to HEALTHY', async () => {
    const fakeSentinel = new FakeSentinel();
    const client = createManagedRedisClient({
      purpose: 'testConnectFlow',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });

    const events = [];
    client.on('connect', () => events.push('connect'));
    client.on('ready',   () => events.push('ready'));

    await client.connect();

    expect(events).toEqual(['connect', 'ready']);
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(client.health().master).toEqual({ host: 'master1', port: 6379 });
  });

  test('MC-07 forwards error events and marks health DEGRADED', async () => {
    const fakeSentinel = new FakeSentinel();
    const client = createManagedRedisClient({
      purpose: 'testErrorFlow',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });
    await client.connect();

    const errors = [];
    client.on('error', (err) => errors.push(err.message));
    fakeSentinel.emit('error', new Error('boom'));

    expect(errors).toEqual(['boom']);
    expect(client.health().state).toBe(HEALTH_STATE.DEGRADED);
  });

  test('MC-08 MASTER_CHANGE topology-change increments failoverCount and emits reconnecting', async () => {
    const fakeSentinel = new FakeSentinel();
    const client = createManagedRedisClient({
      purpose: 'testFailover',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });
    await client.connect();

    const reconnecting = jest.fn();
    client.on('reconnecting', reconnecting);

    fakeSentinel.emit('topology-change', { type: 'MASTER_CHANGE', node: { host: 'master2', port: 6379 } });

    expect(reconnecting).toHaveBeenCalledTimes(1);
    expect(client.health().failoverCount).toBe(1);
    expect(client.health().master).toEqual({ host: 'master2', port: 6379 });
    expect(client.health().state).toBe(HEALTH_STATE.RECOVERING);
  });

  test('MC-09 MASTER_CHANGE followed by isReady becoming true emits ready (isReconnect) and recovers to HEALTHY', async () => {
    const fakeSentinel = new FakeSentinel();
    const client = createManagedRedisClient({
      purpose: 'testRecovery',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });
    await client.connect(); // fakeSentinel.#ready = true already

    const readyEvents = [];
    client.on('ready', (info) => readyEvents.push(info));

    fakeSentinel.emit('topology-change', { type: 'MASTER_CHANGE', node: { host: 'master2', port: 6379 } });
    expect(client.health().state).toBe(HEALTH_STATE.RECOVERING);

    // isReady is already true on the fake (connect() sets #ready=true and
    // MASTER_CHANGE doesn't flip it back down in this fake) — the managed
    // client's poll loop should observe that and announce recovery.
    await new Promise((resolve) => setTimeout(resolve, 150));

    expect(readyEvents.some(e => e?.isReconnect === true)).toBe(true);
    expect(client.health().state).toBe(HEALTH_STATE.HEALTHY);
  });

  test('Finding 3.6: a listener throwing inside the recovery-notify .then() is contained, not an unhandled rejection', async () => {
    // Before this remediation, _pollUntilReady(...).then(recovered => {...})
    // had no trailing .catch() — if the callback body threw (e.g. a
    // downstream 'ready' listener throwing synchronously, since
    // EventEmitter.emit() re-throws listener exceptions into its caller),
    // the rejection had nothing downstream to catch it.
    const fakeSentinel = new FakeSentinel();
    const client = createManagedRedisClient({
      purpose: 'testRecoveryNotifyFailure',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });
    await client.connect();

    client.on('ready', () => { throw new Error('listener-blew-up'); });

    const unhandled = jest.fn();
    process.on('unhandledRejection', unhandled);
    try {
      fakeSentinel.emit('topology-change', { type: 'MASTER_CHANGE', node: { host: 'master2', port: 6379 } });

      // Let the recovery poll resolve and the .then()/.catch() chain settle.
      await new Promise((resolve) => setTimeout(resolve, 150));
      await Promise.resolve(); // flush any pending microtasks from the .catch()

      expect(unhandled).not.toHaveBeenCalled();
      const failedLog = emit.mock.calls.find(c => c[1] === 'REDIS_HA_RECOVERY_NOTIFY_FAILED');
      expect(failedLog).toBeDefined();
      expect(failedLog[2].error).toBe('listener-blew-up');
    } finally {
      process.removeListener('unhandledRejection', unhandled);
    }
  });

  test('MC-10 disconnect()/quit() normalize onto the underlying close()/destroy()', async () => {
    const fakeSentinel = new FakeSentinel();
    jest.spyOn(fakeSentinel, 'close');
    const client = createManagedRedisClient({
      purpose: 'testDisconnect',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });
    await client.connect();
    await client.disconnect();
    expect(fakeSentinel.close).toHaveBeenCalledTimes(1);
  });

  test('MC-14 health() reflects reconnectCount/failoverCount/mode/purpose accurately', async () => {
    const fakeSentinel = new FakeSentinel();
    const client = createManagedRedisClient({
      purpose: 'testHealthShape',
      haConfig: buildSentinelHaConfig(),
      _redis: { createClient: jest.fn(), createSentinel: jest.fn().mockReturnValue(fakeSentinel), createCluster: jest.fn() },
    });
    await client.connect();
    fakeSentinel.emit('topology-change', { type: 'MASTER_CHANGE', node: { host: 'm2', port: 1 } });

    const health = client.health();
    expect(health.purpose).toBe('testHealthShape');
    expect(health.mode).toBe('sentinel');
    expect(health.failoverCount).toBe(1);
    expect(health.reconnectCount).toBe(1);
    expect(typeof health.connectionUptimeSeconds).toBe('number');
  });
});

// ── per-consumer forced master reads ────────────────────────────────
//
// The consent-cache race is closed entirely at this layer: a
// consumer that needs read-after-write consistency with its own writes
// passes forceMasterReads:true, which must override the globally-configured
// useReplicas for THAT client only, regardless of how the global flag is set.
describe('managedClient (forceMasterReads)', () => {
  test('MC-15 forceMasterReads:true forces replicaPoolSize to 0 even when useReplicas is true', () => {
    const fakeSentinel = new FakeSentinel();
    const createSentinel = jest.fn().mockReturnValue(fakeSentinel);

    createManagedRedisClient({
      purpose: 'testForceMaster',
      forceMasterReads: true,
      haConfig: buildSentinelHaConfig({
        sentinel: { ...buildSentinelHaConfig().sentinel, useReplicas: true },
      }),
      _redis: { createClient: jest.fn(), createSentinel, createCluster: jest.fn() },
    });

    expect(createSentinel).toHaveBeenCalledTimes(1);
    const args = createSentinel.mock.calls[0][0];
    expect(args.replicaPoolSize).toBe(0);
    expect(args.masterPoolSize).toBe(1);
  });

  test('MC-16 forceMasterReads omitted/false preserves prior behavior — useReplicas:true still yields replicaPoolSize 1', () => {
    const fakeSentinel = new FakeSentinel();
    const createSentinel = jest.fn().mockReturnValue(fakeSentinel);

    createManagedRedisClient({
      purpose: 'testNoForce',
      haConfig: buildSentinelHaConfig({
        sentinel: { ...buildSentinelHaConfig().sentinel, useReplicas: true },
      }),
      _redis: { createClient: jest.fn(), createSentinel, createCluster: jest.fn() },
    });

    const args = createSentinel.mock.calls[0][0];
    expect(args.replicaPoolSize).toBe(1);
  });

  test('MC-17 forceMasterReads:true is a no-op when useReplicas is already false', () => {
    const fakeSentinel = new FakeSentinel();
    const createSentinel = jest.fn().mockReturnValue(fakeSentinel);

    createManagedRedisClient({
      purpose: 'testForceMasterNoop',
      forceMasterReads: true,
      haConfig: buildSentinelHaConfig(), // useReplicas: false by default
      _redis: { createClient: jest.fn(), createSentinel, createCluster: jest.fn() },
    });

    const args = createSentinel.mock.calls[0][0];
    expect(args.replicaPoolSize).toBe(0);
    // No override log — nothing was actually overridden.
    expect(emit).not.toHaveBeenCalledWith('INFO', 'REDIS_HA_FORCE_MASTER_READS', expect.anything());
  });

  test('MC-18 forceMasterReads:true with useReplicas:true logs the override for observability', () => {
    const fakeSentinel = new FakeSentinel();
    const createSentinel = jest.fn().mockReturnValue(fakeSentinel);

    createManagedRedisClient({
      purpose: 'testForceMasterLog',
      forceMasterReads: true,
      haConfig: buildSentinelHaConfig({
        sentinel: { ...buildSentinelHaConfig().sentinel, useReplicas: true },
      }),
      _redis: { createClient: jest.fn(), createSentinel, createCluster: jest.fn() },
    });

    expect(emit).toHaveBeenCalledWith('INFO', 'REDIS_HA_FORCE_MASTER_READS', expect.objectContaining({ purpose: 'testForceMasterLog' }));
  });
});

describe('managedClient (cluster mode)', () => {
  test('MC-11 cluster mode calls createCluster with the resolved seed nodes', () => {
    const fakeCluster = new FakeSentinel(); // reuse — same on/connect/isReady shape
    const createCluster = jest.fn().mockReturnValue(fakeCluster);

    createManagedRedisClient({
      purpose: 'testCluster',
      haConfig: {
        mode: 'cluster', valid: true, validationErrors: [],
        sentinel: {}, cluster: { rootNodes: [{ host: 'node1', port: 7000 }] },
        retry: { maxAttempts: 5, baseDelayMs: 100, maxDelayMs: 2000, jitterRatio: 0, circuitBreakerCooldownMs: 30_000 },
      },
      _redis: { createClient: jest.fn(), createSentinel: jest.fn(), createCluster },
    });

    expect(createCluster).toHaveBeenCalledTimes(1);
    const args = createCluster.mock.calls[0][0];
    expect(args.rootNodes).toEqual([{ socket: { host: 'node1', port: 7000 } }]);
  });
});

// ── Finding 49 — single-mode self-healing recovery ───────────────────────────
//
// A minimal fake client that behaves enough like node-redis's RedisClientType
// for the supervisor in managedClient.js to drive it: EventEmitter-based,
// connect()/ping()/destroy(), and a simulateDeath() helper standing in for
// "this client's bounded reconnectStrategy exhausted and node-redis emitted a
// terminal 'end'" — the exact scenario Finding 49 requires recovery from.
class FakeSingleClient extends EventEmitter {
  constructor({ failConnect = false, failPing = false, pingReply = 'PONG' } = {}) {
    super();
    this.isReady        = false;
    this.isOpen         = false;
    this.destroyed       = false;
    this.listenersRemoved = false;
    this._failConnect    = failConnect;
    this._failPing       = failPing;
    this._pingReply      = pingReply;
  }

  async connect() {
    if (this._failConnect) {
      const err = new Error('ECONNREFUSED');
      this.emit('error', err);
      this.emit('end');
      throw err;
    }
    this.isOpen  = true;
    this.isReady = true;
    this.emit('connect');
    this.emit('ready');
    return this;
  }

  async ping() {
    if (this._failPing) throw new Error('PING_FAILED');
    return this._pingReply;
  }

  destroy() {
    this.destroyed = true;
    this.isOpen    = false;
    this.isReady   = false;
  }

  removeAllListeners(...args) {
    this.listenersRemoved = true;
    return super.removeAllListeners(...args);
  }

  simulateDeath() {
    this.isOpen  = false;
    this.isReady = false;
    this.emit('end');
  }

  // what node-redis 5 actually does when the client's reconnectStrategy gives up (@redis/client socket.js
  // #shouldReconnect): isOpen flips to false and 'error' is emitted — and NO 'end' ever follows.
  simulateGiveUp(message = 'ORG_STATUS_STORE_RECONNECT_EXHAUSTED') {
    this.isOpen  = false;
    this.isReady = false;
    this.emit('error', new Error(message));
  }

  // A transient error while node-redis is still reconnecting: the client stays open.
  simulateTransientError(message = 'ECONNRESET') {
    this.isReady = false;
    this.emit('error', new Error(message));
  }
}

function buildFastSingleHaConfig() {
  return {
    mode: 'single',
    valid: true,
    validationErrors: [],
    sentinel: {},
    cluster: {},
    // 1ms/no-jitter backoff so recovery cycles run near-instantly in tests.
    retry: { baseDelayMs: 1, maxDelayMs: 1, jitterRatio: 0 },
  };
}

async function settle(ms = 30) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

describe('managedClient (single mode self-healing, Finding 49)', () => {
  test('SH-01 a terminal end recreates the client and restores readiness once Redis is reachable again', async () => {
    const clientA = new FakeSingleClient();
    const clientB = new FakeSingleClient();
    const createClient = jest.fn()
      .mockReturnValueOnce(clientA)
      .mockReturnValueOnce(clientB);

    const result = createManagedRedisClient({
      purpose: 'sh01',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });

    const readyEvents = [];
    const endEvents   = [];
    result.on('error', () => {}); // every real consumer attaches this immediately — see module tests
    result.on('ready', (info) => readyEvents.push(info));
    result.on('end',   () => endEvents.push(1));

    await result.connect();
    await settle();
    expect(result.isReady).toBe(true);
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);

    clientA.simulateDeath();

    // Fail-closed during the recovery window — req. 6.
    expect(result.isReady).toBe(false);
    expect(result.health().state).toBe(HEALTH_STATE.RECOVERING);
    expect(endEvents.length).toBe(1);

    await settle();

    expect(createClient).toHaveBeenCalledTimes(2); // fresh client instance, not reuse — req. 2
    expect(result.isReady).toBe(true);
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(readyEvents.some((e) => e.isReconnect === true)).toBe(true);
  });

  test('SH-02 resource cleanup: the dead client has its listeners removed and is destroyed before a fresh one is created', async () => {
    const clientA = new FakeSingleClient();
    const clientB = new FakeSingleClient();
    const createClient = jest.fn().mockReturnValueOnce(clientA).mockReturnValueOnce(clientB);

    const result = createManagedRedisClient({
      purpose: 'sh02',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});

    await result.connect();
    await settle();

    clientA.simulateDeath();
    await settle();

    expect(clientA.listenersRemoved).toBe(true);
    expect(clientA.listenerCount('ready')).toBe(0);
    expect(clientA.listenerCount('end')).toBe(0);
  });

  test('SH-03 repeated outage/recovery cycles all succeed without leaking listeners across cycles', async () => {
    const clients = [new FakeSingleClient(), new FakeSingleClient(), new FakeSingleClient()];
    const createClient = jest.fn()
      .mockReturnValueOnce(clients[0])
      .mockReturnValueOnce(clients[1])
      .mockReturnValueOnce(clients[2]);

    const result = createManagedRedisClient({
      purpose: 'sh03',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});

    await result.connect();
    await settle();
    expect(result.isReady).toBe(true);

    // Cycle 1
    clients[0].simulateDeath();
    await settle();
    expect(result.isReady).toBe(true);
    expect(clients[0].listenerCount('end')).toBe(0);

    // Cycle 2
    clients[1].simulateDeath();
    await settle();
    expect(result.isReady).toBe(true);
    expect(clients[1].listenerCount('end')).toBe(0);

    expect(createClient).toHaveBeenCalledTimes(3);
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
  });

  test('SH-04 recovery keeps retrying (never gives up) across multiple failed connect attempts, staying fail-closed throughout', async () => {
    const dead1 = new FakeSingleClient({ failConnect: true });
    const dead2 = new FakeSingleClient({ failConnect: true });
    const alive = new FakeSingleClient();
    const createClient = jest.fn()
      .mockReturnValueOnce(dead1)
      .mockReturnValueOnce(dead2)
      .mockReturnValueOnce(alive);

    const result = createManagedRedisClient({
      purpose: 'sh04',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});

    // dead1 is the INITIAL client — its own connect() rejects immediately.
    await expect(result.connect()).rejects.toThrow('ECONNREFUSED');
    expect(result.isReady).toBe(false);

    // Supervisor keeps recreating (dead2, then alive) until one succeeds.
    await settle(150);

    expect(createClient).toHaveBeenCalledTimes(3);
    expect(result.isReady).toBe(true);
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
  });

  test('SH-05 recovery does not mark the store healthy on a failed PING even after ready fires', async () => {
    const badPing = new FakeSingleClient({ failPing: true });
    const createClient = jest.fn().mockReturnValueOnce(badPing);

    const result = createManagedRedisClient({
      purpose: 'sh05',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});

    await result.connect();
    await settle();

    // node-redis's own 'ready' fired (badPing.isReady === true), but our
    // supervisor's health-verification PING failed — req. 7: TCP/AUTH ready
    // alone must never be enough to declare the store healthy.
    expect(result.health().state).not.toBe(HEALTH_STATE.HEALTHY);
  });

  test('SH-06 disconnect() stops the recovery loop — no orphan reconnect loop survives a deliberate shutdown', async () => {
    const clientA = new FakeSingleClient();
    const clientB = new FakeSingleClient();
    const createClient = jest.fn().mockReturnValueOnce(clientA).mockReturnValueOnce(clientB);

    const result = createManagedRedisClient({
      purpose: 'sh06',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});

    await result.connect();
    await settle();

    clientA.simulateDeath();
    await result.disconnect();
    await settle(50);

    // The scheduled recovery must not run after a deliberate shutdown.
    expect(createClient).toHaveBeenCalledTimes(1);
  });

  // ── (owner D9 = A): give-up detected on the 'error' path (isOpen === false), no 'end' ──────────────────────
  const giveUpRig = (purpose, clients) => {
    const createClient = jest.fn();
    for (const c of clients) createClient.mockReturnValueOnce(c);
    const result = createManagedRedisClient({ purpose, haConfig: buildFastSingleHaConfig(), _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() } });
    const ends = []; const readies = [];
    result.on('error', () => {});
    result.on('end', () => ends.push(1));
    result.on('ready', (info) => readies.push(info));
    return { result, createClient, ends, readies };
  };

  test('GU-01 a reconnect give-up (error with isOpen=false, NO end) rebuilds the client and restores readiness', async () => {
    const clientA = new FakeSingleClient(); const clientB = new FakeSingleClient();
    const { result, createClient, ends, readies } = giveUpRig('gu01', [clientA, clientB]);
    await result.connect(); await settle();
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);

    clientA.simulateGiveUp();
    expect(result.isReady).toBe(false);                               // fail-closed during recovery
    expect(result.health().state).toBe(HEALTH_STATE.RECOVERING);
    expect(ends.length).toBe(1);
    await settle();

    expect(createClient).toHaveBeenCalledTimes(2);                    // a fresh client, not the dead one
    expect(clientA.listenersRemoved).toBe(true);
    expect(result.isReady).toBe(true);
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(readies.some((e) => e.isReconnect === true)).toBe(true);
  });

  test('GU-02 idempotent: give-up followed by repeated errors and a late end triggers exactly ONE rebuild and one end', async () => {
    const clientA = new FakeSingleClient(); const clientB = new FakeSingleClient();
    const { result, createClient, ends } = giveUpRig('gu02', [clientA, clientB]);
    await result.connect(); await settle();

    clientA.simulateGiveUp();
    clientA.emit('error', new Error('again'));
    clientA.emit('end');
    await settle();

    expect(createClient).toHaveBeenCalledTimes(2);
    expect(ends.length).toBe(1);
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
  });

  test('GU-03 a transient error while the client is still open (node-redis reconnecting) does NOT rebuild', async () => {
    const clientA = new FakeSingleClient();
    const { result, createClient, ends } = giveUpRig('gu03', [clientA]);
    await result.connect(); await settle();

    clientA.simulateTransientError();
    await settle();

    expect(createClient).toHaveBeenCalledTimes(1);
    expect(ends.length).toBe(0);
    expect(result.health().state).toBe(HEALTH_STATE.DEGRADED);
  });

  test('GU-04 a give-up after the consumer disconnected does not start a recovery loop', async () => {
    const clientA = new FakeSingleClient(); const clientB = new FakeSingleClient();
    const { result, createClient } = giveUpRig('gu04', [clientA, clientB]);
    await result.connect(); await settle();

    await result.disconnect();
    clientA.simulateGiveUp();
    await settle(50);

    expect(createClient).toHaveBeenCalledTimes(1);
  });

  test('GU-05 recovery keeps trying when the rebuilt client also gives up; end is announced once; readiness returns', async () => {
    const clientA = new FakeSingleClient();
    const clientB = new FakeSingleClient({ failConnect: true });       // Redis still down at the first attempt
    const clientC = new FakeSingleClient();
    const { result, createClient, ends } = giveUpRig('gu05', [clientA, clientB, clientC]);
    await result.connect(); await settle();

    clientA.simulateGiveUp();
    await settle(60);

    expect(createClient).toHaveBeenCalledTimes(3);
    expect(ends.length).toBe(1);
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
  });

  // FINDING-REVOCATION-SUBSCRIBER-LIVELOCK: Redis replies to PING differently
  // while a connection is in RESP2 pub/sub subscriber context (a lowercase
  // "pong", or — depending on exactly when the reply is parsed relative to
  // the subscribe() call — a raw Buffer instead of a string). A subscriber
  // client (RevocationSubscriber, OrgStatusSubscriber) always calls
  // .subscribe() immediately after connect(), so its readiness PING is
  // always answered this way. Confirmed against the real 'redis' package
  // (v5.12.1) and real Redis/Memurai — see
  //.
  test('SH-07 a subscriber-context lowercase "pong" PING reply still announces ready', async () => {
    const subscriberClient = new FakeSingleClient({ pingReply: 'pong' });
    const createClient = jest.fn().mockReturnValueOnce(subscriberClient);

    const result = createManagedRedisClient({
      purpose: 'sh07',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});
    const readyEvents = [];
    result.on('ready', (info) => readyEvents.push(info));

    await result.connect();
    await settle();

    // Note: result.isReady mirrors the RAW client's own isReady flag
    // (TCP+AUTH complete), independent of our ping-based health check — see
    // SH-05, which likewise never asserts on it. What RevocationSubscriber/
    // OrgStatusSubscriber actually gate consent/org enforcement on is the
    // facade 'ready' event (client.on('ready', ...)), which only fires from
    // _verifyAndAnnounceReady after a successful ping.
    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(readyEvents.length).toBe(1);
  });

  test('SH-08 a subscriber-context Buffer-typed PING reply still announces ready', async () => {
    const subscriberClient = new FakeSingleClient({ pingReply: Buffer.from('PONG') });
    const createClient = jest.fn().mockReturnValueOnce(subscriberClient);

    const result = createManagedRedisClient({
      purpose: 'sh08',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});
    const readyEvents = [];
    result.on('ready', (info) => readyEvents.push(info));

    await result.connect();
    await settle();

    expect(result.health().state).toBe(HEALTH_STATE.HEALTHY);
    expect(readyEvents.length).toBe(1);
  });

  test('SH-09 a genuinely wrong PING reply still fails closed (fail-closed semantics preserved)', async () => {
    const wrongReply = new FakeSingleClient({ pingReply: 'NOT_A_PONG' });
    const createClient = jest.fn().mockReturnValueOnce(wrongReply);

    const result = createManagedRedisClient({
      purpose: 'sh09',
      haConfig: buildFastSingleHaConfig(),
      _redis: { createClient, createSentinel: jest.fn(), createCluster: jest.fn() },
    });
    result.on('error', () => {});
    const readyEvents = [];
    result.on('ready', (info) => readyEvents.push(info));

    await result.connect();
    await settle();

    expect(result.health().state).not.toBe(HEALTH_STATE.HEALTHY);
    expect(readyEvents.length).toBe(0);
  });
});
