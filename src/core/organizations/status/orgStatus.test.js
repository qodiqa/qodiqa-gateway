'use strict';

/**
 * Bounded organization-suspension propagation test suite.
 *
 * Tests: OrgStatusEvent, OrgStatusMetrics, OrgStatusStore, OrgStatusPublisher,
 * OrgStatusSubscriber, organizationRegistry's bounded-staleness/fail-closed
 * gate, monotonic race handling, and multi-worker propagation convergence.
 */

// ── Shared mocks ──────────────────────────────────────────────────────────────

jest.mock('redis', () => {
  const EventEmitter = require('events');

  function makeMockClient(overrides = {}) {
    const emitter = new EventEmitter();
    const client  = {
      connect:     jest.fn().mockResolvedValue(undefined),
      disconnect:  jest.fn().mockResolvedValue(undefined),
      subscribe:   jest.fn().mockResolvedValue(undefined),
      unsubscribe: jest.fn().mockResolvedValue(undefined),
      publish:     jest.fn().mockResolvedValue(1),
      hSet:        jest.fn().mockResolvedValue(1),
      hGet:        jest.fn().mockResolvedValue(null),
      hGetAll:     jest.fn().mockResolvedValue({}),
      ping:        jest.fn().mockResolvedValue('PONG'),
      on:          (ev, fn) => emitter.on(ev, fn),
      off:         (ev, fn) => emitter.off(ev, fn),
      emit:        (ev, ...args) => emitter.emit(ev, ...args),
      _emitter:    emitter,
    };
    Object.assign(client, overrides);
    return client;
  }

  return {
    createClient: jest.fn().mockImplementation(() => makeMockClient()),
    __makeMockClient: makeMockClient,
  };
});

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
// these freshness tests simulate stalls/ageing with jest.setSystemTime, which moves Date only; the production
// org-status clock is monotonic (performance.now), so they read Date.now through it. test/orgStatusMonotonic covers the real clock.
jest.mock('./orgStatusClock', () => ({ now: () => Date.now() }));

jest.mock('../../../infra/redis/clientConfig', () => ({
  buildClientOptions: jest.fn().mockReturnValue({}),
  isAuthError:        jest.fn().mockReturnValue(false),
  isTlsError:         jest.fn().mockReturnValue(false),
}));

// jest.doMock() registrations are NOT cleared by jest.resetModules() (that
// only clears the require cache) — they persist until explicitly undone.
// Several describe blocks below doMock './OrgStatusStore' and
// './OrgStatusPublisher' to isolate the module under test; without this
// global afterEach, whichever describe ran last would leak its fake into
// every subsequent describe that needs the REAL module.
//
// organizationRegistry and OrgStatusSubscriber are no longer require()'d by
// each other (Finding 64 / dependency-inversion remediation) — tests
// below wire them together explicitly via setOrgStatusSubscriber()/
// setOrganizationRegistry() instead of jest.doMock()'ing one from the other.
afterEach(() => {
  jest.dontMock('./OrgStatusStore');
  jest.dontMock('./OrgStatusPublisher');
});

function makeRedisClient(overrides = {}) {
  const EventEmitter = require('events');
  const emitter = new EventEmitter();
  return {
    connect:     jest.fn().mockResolvedValue(undefined),
    disconnect:  jest.fn().mockResolvedValue(undefined),
    subscribe:   jest.fn().mockResolvedValue(undefined),
    unsubscribe: jest.fn().mockResolvedValue(undefined),
    publish:     jest.fn().mockResolvedValue(1),
    hSet:        jest.fn().mockResolvedValue(1),
    hGet:        jest.fn().mockResolvedValue(null),
    hGetAll:     jest.fn().mockResolvedValue({}),
    ping:        jest.fn().mockResolvedValue('PONG'),
    on:          (ev, fn) => emitter.on(ev, fn),
    off:         (ev, fn) => emitter.off(ev, fn),
    _emit:       (ev, ...args) => emitter.emit(ev, ...args),
    ...overrides,
  };
}

function autoReadyClient(overrides = {}) {
  const client = makeRedisClient(overrides);
  const originalConnect = client.connect;
  client.connect = jest.fn().mockImplementation(async (...args) => {
    const r = await originalConnect(...args);
    client._emit('ready');
    return r;
  });
  return client;
}

// ── 1. OrgStatusEvent ─────────────────────────────────────────────────────────

describe('OrgStatusEvent', () => {
  let OrgStatusEvent;

  beforeEach(() => {
    jest.resetModules();
    delete process.env.ORG_STATUS_SIGNING_KEY;
    OrgStatusEvent = require('./OrgStatusEvent');
  });

  test('buildEvent produces required fields', () => {
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-1', status: 'suspended' });
    expect(event.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(event.version).toBe(OrgStatusEvent.EVENT_VERSION);
    expect(event.organizationId).toBe('org-1');
    expect(event.status).toBe('suspended');
    expect(typeof event.updatedAt).toBe('number');
    expect(event.sourceSystem).toBe('qodiqa-organization-registry');
    // every event is signed with the keystore MAC keyring — no unsigned mode.
    expect(event.signature).toMatch(/^mk_[0-9]{8}_[0-9a-f]{8}\.[A-Za-z0-9_-]{43}$/);
  });

  test('parseEvent rejects invalid JSON / non-object / wrong version', () => {
    expect(OrgStatusEvent.parseEvent('not-json{').reason).toBe('INVALID_JSON');
    expect(OrgStatusEvent.parseEvent('"str"').reason).toBe('NOT_OBJECT');
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-1', status: 'active' });
    const mutated = { ...event, version: '99' };
    expect(OrgStatusEvent.parseEvent(JSON.stringify(mutated)).reason).toBe('VERSION_MISMATCH');
  });

  test('parseEvent rejects missing organizationId / status / timestamp', () => {
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-1', status: 'active' });
    const { organizationId: _a, ...noOrg } = event;
    expect(OrgStatusEvent.parseEvent(JSON.stringify(noOrg)).reason).toBe('MISSING_ORGANIZATION_ID');
    const { status: _b, ...noStatus } = event;
    expect(OrgStatusEvent.parseEvent(JSON.stringify(noStatus)).reason).toBe('MISSING_STATUS');
    const { updatedAt: _c, ...noTs } = event;
    expect(OrgStatusEvent.parseEvent(JSON.stringify(noTs)).reason).toBe('MISSING_TIMESTAMP');
  });

  test('parseEvent rejects stale (expired) events — replay protection', () => {
    jest.resetModules();
    process.env.ORG_STATUS_MAX_EVENT_AGE_MS = '1000';
    OrgStatusEvent = require('./OrgStatusEvent');
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-1', status: 'active', updatedAt: Date.now() - 5000 });
    const r = OrgStatusEvent.parseEvent(JSON.stringify(event));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('EVENT_EXPIRED');
    delete process.env.ORG_STATUS_MAX_EVENT_AGE_MS;
  });

  test('accepts a valid signed event', () => {
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-1', status: 'suspended' });
    const r = OrgStatusEvent.parseEvent(JSON.stringify(event));
    expect(r.ok).toBe(true);
    expect(r.event.organizationId).toBe('org-1');
  });

  test('REJECTS an unsigned event (was accepted fail-open when no key was set)', () => {
    const { signature: _, ...unsigned } = OrgStatusEvent.buildEvent({ organizationId: 'org-1', status: 'active' });
    expect(OrgStatusEvent.parseEvent(JSON.stringify(unsigned))).toEqual({ ok: false, reason: 'MISSING_SIGNATURE' });
  });

  test('signs and verifies events with the keyring (ORG_STATUS_SIGNING_KEY ignored); rejects tampering', () => {
    jest.resetModules();
    process.env.ORG_STATUS_SIGNING_KEY = 'test-secret-key-32-chars-padding!!';
    OrgStatusEvent = require('./OrgStatusEvent');
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-1', status: 'active' });
    expect(event.signature).toMatch(/^mk_[0-9]{8}_[0-9a-f]{8}\.[A-Za-z0-9_-]{43}$/);
    expect(OrgStatusEvent.parseEvent(JSON.stringify(event)).ok).toBe(true);

    const tampered = { ...event, status: 'suspended' };
    const r = OrgStatusEvent.parseEvent(JSON.stringify(tampered));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^INVALID_SIGNATURE:/);
    delete process.env.ORG_STATUS_SIGNING_KEY;
  });

  test('(NF-4): sealRecord/openRecord round-trip; a record bound to another org, tampered, or unsigned is ignored', () => {
    const sealed = OrgStatusEvent.sealRecord('org-1', { status: 'suspended', updatedAt: 7 });
    expect(OrgStatusEvent.openRecord('org-1', sealed)).toEqual({ status: 'suspended', updatedAt: 7 });
    expect(OrgStatusEvent.openRecord('org-2', sealed)).toBeNull(); // copied into another org's field
    const outer = JSON.parse(sealed);
    expect(OrgStatusEvent.openRecord('org-1', JSON.stringify({ ...outer, r: outer.r.replace('suspended', 'active') }))).toBeNull();
    expect(OrgStatusEvent.openRecord('org-1', JSON.stringify({ status: 'active', updatedAt: 9 }))).toBeNull(); // earlier / forged plain write
    expect(OrgStatusEvent.openRecord('org-1', 'not-json{')).toBeNull();
  });
});

// ── 2. OrgStatusMetrics ───────────────────────────────────────────────────────

describe('OrgStatusMetrics', () => {
  test('exports required metric objects and they do not throw', () => {
    jest.resetModules();
    const metrics = require('./OrgStatusMetrics');
    expect(metrics.published).toBeDefined();
    expect(metrics.received).toBeDefined();
    expect(metrics.statusApplied).toBeDefined();
    expect(metrics.propagationLatency).toBeDefined();
    expect(metrics.reconcileSweeps).toBeDefined();
    expect(metrics.staleDenials).toBeDefined();
    expect(metrics.subscriberReconnects).toBeDefined();
    expect(() => metrics.staleDenials.inc({ reason: 'stale' })).not.toThrow();
    expect(() => metrics.propagationLatency.observe(12)).not.toThrow();
  });
});

// ── 3. OrgStatusStore ─────────────────────────────────────────────────────────

describe('OrgStatusStore', () => {
  let store, mockClient, createClient;

  beforeEach(() => {
    jest.resetModules();
    createClient = require('redis').createClient;
    mockClient = autoReadyClient();
    createClient.mockReturnValue(mockClient);
    store = require('./OrgStatusStore');
  });

  afterEach(async () => { await store.disconnect().catch(() => {}); });

  test('setStatus writes to the Redis hash and returns true', async () => {
    const ok = await store.setStatus('org-1', 'suspended', 123456);
    expect(ok).toBe(true);
    // (NF-4): the hash value is a keyring-sealed record bound to its org id.
    const [hash, field, value] = mockClient.hSet.mock.calls[0];
    expect([hash, field]).toEqual(['qodiqa:org:status', 'org-1']);
    expect(require('./OrgStatusEvent').openRecord('org-1', value)).toEqual({ status: 'suspended', updatedAt: 123456 });
  });

  test('getStatus returns null on miss and parses on hit', async () => {
    const { sealRecord } = require('./OrgStatusEvent');
    expect(await store.getStatus('org-none')).toBeNull();
    mockClient.hGet.mockResolvedValueOnce(sealRecord('org-1', { status: 'active', updatedAt: 999 }));
    expect(await store.getStatus('org-1')).toEqual({ status: 'active', updatedAt: 999 });
  });

  test('(NF-4): getStatus ignores an unsigned (directly written) hash value', async () => {
    mockClient.hGet.mockResolvedValueOnce(JSON.stringify({ status: 'active', updatedAt: 999 }));
    expect(await store.getStatus('org-1')).toBeNull();
  });

  test('getAllStatuses parses every hash field; unsigned or mis-bound fields are dropped', async () => {
    const { sealRecord } = require('./OrgStatusEvent');
    mockClient.hGetAll.mockResolvedValueOnce({
      'org-1': sealRecord('org-1', { status: 'active', updatedAt: 1 }),
      'org-2': sealRecord('org-2', { status: 'suspended', updatedAt: 2 }),
      'org-3': JSON.stringify({ status: 'active', updatedAt: 3 }),
      'org-4': sealRecord('org-2', { status: 'active', updatedAt: 4 }),
    });
    const all = await store.getAllStatuses();
    expect(all.get('org-1')).toEqual({ status: 'active', updatedAt: 1 });
    expect(all.get('org-2')).toEqual({ status: 'suspended', updatedAt: 2 });
    expect(all.has('org-3')).toBe(false);
    expect(all.has('org-4')).toBe(false);
  });

  test('returns null/false (never throws) when Redis is unavailable', async () => {
    mockClient.connect.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    expect(await store.setStatus('org-1', 'active', 1)).toBe(false);
  });

  test('getAllStatuses returns null when Redis is unavailable (distinguishable from "no orgs")', async () => {
    jest.resetModules();
    const failClient = makeRedisClient({ connect: jest.fn().mockRejectedValue(new Error('down')) });
    require('redis').createClient.mockReturnValue(failClient);
    const store2 = require('./OrgStatusStore');
    expect(await store2.getAllStatuses()).toBeNull();
  });
});

// ── 4. OrgStatusPublisher ─────────────────────────────────────────────────────

describe('OrgStatusPublisher', () => {
  let publisher, mockStore, mockClient, createClient;

  beforeEach(() => {
    jest.resetModules();
    mockStore = { setStatus: jest.fn().mockResolvedValue(true) };
    jest.doMock('./OrgStatusStore', () => mockStore);

    createClient = require('redis').createClient;
    mockClient = autoReadyClient();
    createClient.mockReturnValue(mockClient);

    publisher = require('./OrgStatusPublisher');
  });

  afterEach(async () => { await publisher.disconnect().catch(() => {}); });

  test('writes authoritative store THEN publishes, in that order', async () => {
    const callOrder = [];
    mockStore.setStatus.mockImplementation(async () => { callOrder.push('store'); return true; });
    mockClient.publish.mockImplementation(async () => { callOrder.push('publish'); return 1; });

    const result = await publisher.publishStatusChange({ organizationId: 'org-1', status: 'suspended' });
    expect(callOrder).toEqual(['store', 'publish']);
    expect(result.published).toBe(true);
    expect(typeof result.updatedAt).toBe('number');
  });

  test('H1: updatedAt is never below minUpdatedAt, even when Date.now() has stepped back', async () => {
    const spy = jest.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000);
    try {
      const floored = await publisher.publishStatusChange({ organizationId: 'org-1', status: 'suspended', minUpdatedAt: 1_800_000_000_001 });
      expect(floored.updatedAt).toBe(1_800_000_000_001);
      expect(mockStore.setStatus).toHaveBeenLastCalledWith('org-1', 'suspended', 1_800_000_000_001);
      const plain = await publisher.publishStatusChange({ organizationId: 'org-1', status: 'active' });
      expect(plain.updatedAt).toBe(1_800_000_000_000);
    } finally { spy.mockRestore(); }
  });

  test('throws ORG_STATUS_PROPAGATION_UNAVAILABLE when the authoritative write fails — publish is never attempted', async () => {
    mockStore.setStatus.mockResolvedValue(false);
    await expect(publisher.publishStatusChange({ organizationId: 'org-1', status: 'suspended' }))
      .rejects.toThrow('ORG_STATUS_PROPAGATION_UNAVAILABLE');
    expect(mockClient.publish).not.toHaveBeenCalled();
  });

  test('resolves with published:false (non-fatal) when the store write succeeded but Redis pub/sub is unavailable', async () => {
    jest.resetModules();
    jest.doMock('./OrgStatusStore', () => ({ setStatus: jest.fn().mockResolvedValue(true) }));
    const failClient = makeRedisClient({ connect: jest.fn().mockRejectedValue(new Error('down')) });
    require('redis').createClient.mockReturnValue(failClient);
    const publisher2 = require('./OrgStatusPublisher');

    const result = await publisher2.publishStatusChange({ organizationId: 'org-1', status: 'active' });
    expect(result.published).toBe(false);
  });

  test('publish() event payload includes organizationId/status/updatedBy/correlationId', async () => {
    await publisher.publishStatusChange({
      organizationId: 'org-9', status: 'disabled', updatedBy: 'admin-1', correlationId: 'req-42',
    });
    const [, payload] = mockClient.publish.mock.calls[0];
    const event = JSON.parse(payload);
    expect(event.organizationId).toBe('org-9');
    expect(event.status).toBe('disabled');
    expect(event.updatedBy).toBe('admin-1');
    expect(event.correlationId).toBe('req-42');
  });
});

// ── 5. OrgStatusSubscriber ────────────────────────────────────────────────────

describe('OrgStatusSubscriber', () => {
  let subscriber, mockStore, mockRegistry, mockClient, createClient;

  function setup({ localOrgs = [], remoteMap = new Map() } = {}) {
    jest.resetModules();

    mockStore = {
      getAllStatuses: jest.fn().mockResolvedValue(remoteMap),
      setStatus:      jest.fn().mockResolvedValue(true),
      getStatus:      jest.fn().mockResolvedValue(null),
    };
    mockRegistry = {
      listOrganizations:    jest.fn().mockReturnValue(localOrgs),
      _applyRemoteStatus:   jest.fn().mockReturnValue(true),
      _touchStatusFreshness: jest.fn(),
    };
    jest.doMock('./OrgStatusStore', () => mockStore);

    createClient = require('redis').createClient;
    mockClient = autoReadyClient();
    createClient.mockReturnValue(mockClient);

    subscriber = require('./OrgStatusSubscriber');
    subscriber.setOrganizationRegistry(mockRegistry);
    return { subscriber, mockStore, mockRegistry, mockClient };
  }

  afterEach(async () => { await subscriber.stop().catch(() => {}); });

  test('isReady()/isStarted() are false before start()', () => {
    setup();
    expect(subscriber.isReady()).toBe(false);
    expect(subscriber.isStarted()).toBe(false);
  });

  test('start() subscribes and performs an initial reconciliation sweep before resolving', async () => {
    setup({ localOrgs: [{ organizationId: 'org-1', status: 'active' }] });
    await subscriber.start();
    expect(subscriber.isStarted()).toBe(true);
    expect(mockClient.subscribe).toHaveBeenCalledWith('qodiqa:org:status:change', expect.any(Function));
    expect(mockStore.getAllStatuses).toHaveBeenCalled();
  });

  test('start() seeds Redis from local status when an org is missing from the authoritative store', async () => {
    setup({ localOrgs: [{ organizationId: 'org-1', status: 'active' }], remoteMap: new Map() });
    await subscriber.start();
    expect(mockStore.setStatus).toHaveBeenCalledWith('org-1', 'active', expect.any(Number));
    expect(mockRegistry._touchStatusFreshness).toHaveBeenCalledWith('org-1', expect.any(Number));
  });

  test('start() applies the Redis-authoritative value when it disagrees with local state', async () => {
    setup({
      localOrgs: [{ organizationId: 'org-1', status: 'active' }],
      remoteMap: new Map([['org-1', { status: 'suspended', updatedAt: 555 }]]),
    });
    await subscriber.start();
    expect(mockRegistry._applyRemoteStatus).toHaveBeenCalledWith('org-1', 'suspended', 555);
  });

  test('start() throws (fail-closed) when the initial reconciliation cannot reach Redis', async () => {
    setup();
    mockStore.getAllStatuses.mockResolvedValue(null);
    await expect(subscriber.start()).rejects.toThrow('ORG_STATUS_SUBSCRIBER_INITIAL_RECONCILE_FAILED');
    expect(subscriber.isStarted()).toBe(false);
  });

  test('start() throws when Redis connect fails', async () => {
    jest.resetModules();
    mockStore = { getAllStatuses: jest.fn().mockResolvedValue(new Map()) };
    mockRegistry = { listOrganizations: jest.fn().mockReturnValue([]), _applyRemoteStatus: jest.fn(), _touchStatusFreshness: jest.fn() };
    jest.doMock('./OrgStatusStore', () => mockStore);
    const failClient = makeRedisClient({ connect: jest.fn().mockRejectedValue(new Error('ECONNREFUSED')) });
    require('redis').createClient.mockReturnValue(failClient);
    const sub2 = require('./OrgStatusSubscriber');
    sub2.setOrganizationRegistry(mockRegistry);
    await expect(sub2.start()).rejects.toThrow('ECONNREFUSED');
  });

  test('start() throws a clear ORG_STATUS_SUBSCRIBER_REGISTRY_NOT_INJECTED error when setOrganizationRegistry() was never called', async () => {
    jest.resetModules();
    jest.doMock('./OrgStatusStore', () => ({ getAllStatuses: jest.fn().mockResolvedValue(new Map()) }));
    createClient = require('redis').createClient;
    mockClient = autoReadyClient();
    createClient.mockReturnValue(mockClient);
    const sub2 = require('./OrgStatusSubscriber');
    await expect(sub2.start()).rejects.toThrow('ORG_STATUS_SUBSCRIBER_REGISTRY_NOT_INJECTED');
    expect(mockClient.connect).not.toHaveBeenCalled();
  });

  test('processes a valid status-change event and applies it via the registry', async () => {
    let messageHandler;
    setup({ localOrgs: [] });
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => { messageHandler = fn; return Promise.resolve(); });
    await subscriber.start();

    const OrgStatusEvent = require('./OrgStatusEvent');
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-7', status: 'suspended' });
    await messageHandler(JSON.stringify(event));

    expect(mockRegistry._applyRemoteStatus).toHaveBeenCalledWith('org-7', 'suspended', event.updatedAt);
  });

  test('deduplicates events with the same eventId', async () => {
    let messageHandler;
    setup({ localOrgs: [] });
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => { messageHandler = fn; return Promise.resolve(); });
    await subscriber.start();

    const OrgStatusEvent = require('./OrgStatusEvent');
    const event = OrgStatusEvent.buildEvent({ organizationId: 'org-7', status: 'suspended' });
    const raw = JSON.stringify(event);
    await messageHandler(raw);
    await messageHandler(raw);

    expect(mockRegistry._applyRemoteStatus).toHaveBeenCalledTimes(1);
  });

  test('ignores invalid messages without crashing', async () => {
    let messageHandler;
    setup({ localOrgs: [] });
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => { messageHandler = fn; return Promise.resolve(); });
    await subscriber.start();
    await expect(messageHandler('not-json{')).resolves.not.toThrow();
  });

  test('isReady() becomes false immediately on reconnecting — fail-closed gate signal', async () => {
    setup({ localOrgs: [] });
    await subscriber.start();
    expect(subscriber.isReady()).toBe(true);
    mockClient._emit('reconnecting');
    expect(subscriber.isReady()).toBe(false);
  });

  test('a reconnect (ready with isReconnect) triggers an immediate reconciliation sweep', async () => {
    setup({ localOrgs: [{ organizationId: 'org-1', status: 'active' }] });
    await subscriber.start();
    mockStore.getAllStatuses.mockClear();

    mockClient._emit('ready', { isReconnect: true });
    // reconcile runs asynchronously (fire-and-forget in the 'ready' handler)
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    expect(mockStore.getAllStatuses).toHaveBeenCalled();
  });

  test('stop() clears the reconciliation timer and disconnects', async () => {
    setup({ localOrgs: [] });
    await subscriber.start();
    await subscriber.stop();
    expect(subscriber.isStarted()).toBe(false);
    expect(subscriber.isReady()).toBe(false);
    expect(mockClient.disconnect).toHaveBeenCalled();
  });

  test('MAX_PROPAGATION_WINDOW_MS is a positive, finite, documented bound', () => {
    setup();
    expect(subscriber.MAX_PROPAGATION_WINDOW_MS).toBeGreaterThan(0);
    expect(Number.isFinite(subscriber.MAX_PROPAGATION_WINDOW_MS)).toBe(true);
  });
});

// ── 6. organizationRegistry — fail-closed / bounded-staleness gate ────

describe('organizationRegistry — assertActiveOrganization gate', () => {
  let registry, mockSubscriber;

  beforeEach(() => {
    jest.resetModules();
    mockSubscriber = {
      isStarted: jest.fn().mockReturnValue(false),
      isReady:   jest.fn().mockReturnValue(false),
      MAX_PROPAGATION_WINDOW_MS: 5000,
    };
    registry = require('../organizationRegistry');
    registry.setOrgStatusSubscriber(mockSubscriber);
    registry._reset();
  });

  test('subscriber never started — preserves exact pre-COMP-8 behavior (backward compatibility)', () => {
    const { organizationId } = registry.registerOrganization({ organizationName: 'Legacy' });
    registry.assignTenantToOrg('tenant-x', organizationId);
    expect(registry.assertActiveOrganization('tenant-x')).toEqual({ valid: true, organizationId });
  });

  test('subscriber never injected (setOrgStatusSubscriber never called) — same backward-compatible skip behavior', () => {
    jest.resetModules();
    const freshRegistry = require('../organizationRegistry');
    freshRegistry._reset();

    const { organizationId } = freshRegistry.registerOrganization({ organizationName: 'Uninjected' });
    freshRegistry.assignTenantToOrg('tenant-uninjected', organizationId);
    expect(freshRegistry.assertActiveOrganization('tenant-uninjected')).toEqual({ valid: true, organizationId });
  });

  test('subscriber started but not ready — fail-closed regardless of cached status', () => {
    mockSubscriber.isStarted.mockReturnValue(true);
    mockSubscriber.isReady.mockReturnValue(false);

    const { organizationId } = registry.registerOrganization({ organizationName: 'Active Org' });
    registry.assignTenantToOrg('tenant-y', organizationId);
    registry._applyRemoteStatus(organizationId, 'active', Date.now());

    const result = registry.assertActiveOrganization('tenant-y');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ORG_STATUS_SYNC_UNAVAILABLE');
  });

  test('subscriber ready but never synced for this org — stale, fail-closed', () => {
    mockSubscriber.isStarted.mockReturnValue(true);
    mockSubscriber.isReady.mockReturnValue(true);

    const { organizationId } = registry.registerOrganization({ organizationName: 'Never Synced' });
    registry.assignTenantToOrg('tenant-z', organizationId);
    // No _applyRemoteStatus/_touchStatusFreshness call — syncedAt stays 0.

    const result = registry.assertActiveOrganization('tenant-z');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ORG_STATUS_STALE');
  });

  test('subscriber ready and freshly synced — active org passes', () => {
    mockSubscriber.isStarted.mockReturnValue(true);
    mockSubscriber.isReady.mockReturnValue(true);

    const { organizationId } = registry.registerOrganization({ organizationName: 'Fresh Org' });
    registry.assignTenantToOrg('tenant-fresh', organizationId);
    registry._applyRemoteStatus(organizationId, 'active', Date.now());

    expect(registry.assertActiveOrganization('tenant-fresh')).toEqual({ valid: true, organizationId });
  });

  test('subscriber ready and freshly synced — suspension is enforced', () => {
    mockSubscriber.isStarted.mockReturnValue(true);
    mockSubscriber.isReady.mockReturnValue(true);

    const { organizationId } = registry.registerOrganization({ organizationName: 'Soon Suspended' });
    registry.assignTenantToOrg('tenant-susp', organizationId);
    registry._applyRemoteStatus(organizationId, 'suspended', Date.now());

    const result = registry.assertActiveOrganization('tenant-susp');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ORG_SUSPENDED');
  });

  test('sync older than MAX_PROPAGATION_WINDOW_MS is treated as stale even if subscriber reports ready', () => {
    mockSubscriber.isStarted.mockReturnValue(true);
    mockSubscriber.isReady.mockReturnValue(true);
    mockSubscriber.MAX_PROPAGATION_WINDOW_MS = 1000;

    jest.useFakeTimers();
    try {
      const t0 = Date.now();
      jest.setSystemTime(t0);

      const { organizationId } = registry.registerOrganization({ organizationName: 'Old Sync' });
      registry.assignTenantToOrg('tenant-old', organizationId);
      registry._applyRemoteStatus(organizationId, 'active', t0);

      // Immediately after sync — within the bound, trusted.
      expect(registry.assertActiveOrganization('tenant-old').valid).toBe(true);

      // Advance the clock past the documented bound with no further sync.
      jest.setSystemTime(t0 + 2000);
      const result = registry.assertActiveOrganization('tenant-old');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('ORG_STATUS_STALE');
    } finally {
      jest.useRealTimers();
    }
  });

  test('monotonic guard — an older event never overwrites a newer applied status (race condition)', () => {
    const { organizationId } = registry.registerOrganization({ organizationName: 'Race Org' });

    const newer = Date.now();
    const older = newer - 10_000;

    expect(registry._applyRemoteStatus(organizationId, 'suspended', newer)).toBe(true);
    expect(registry._applyRemoteStatus(organizationId, 'active', older)).toBe(false);
    expect(registry.getOrganization(organizationId).status).toBe('suspended');
  });

  test('_applyRemoteStatus ignores an invalid status value', () => {
    const { organizationId } = registry.registerOrganization({ organizationName: 'Bad Status' });
    expect(registry._applyRemoteStatus(organizationId, 'archived', Date.now())).toBe(false);
    expect(registry.getOrganization(organizationId).status).toBe('active');
  });
});

// ── 7. publishOrganizationStatus — write path ────────────────────────────────

describe('organizationRegistry.publishOrganizationStatus', () => {
  let registry, mockPublisher;

  beforeEach(() => {
    jest.resetModules();
    mockPublisher = { publishStatusChange: jest.fn().mockResolvedValue({ updatedAt: Date.now(), published: true }) };
    jest.doMock('./OrgStatusPublisher', () => mockPublisher);
    registry = require('../organizationRegistry');
    registry._reset();
  });

  test('propagates first, then applies locally, and touches freshness so the originator is not immediately stale', async () => {
    const { organizationId } = registry.registerOrganization({ organizationName: 'Origin Worker' });
    const updated = await registry.publishOrganizationStatus(organizationId, 'suspended', { updatedBy: 'admin' });

    expect(mockPublisher.publishStatusChange).toHaveBeenCalledWith(expect.objectContaining({
      organizationId, status: 'suspended', updatedBy: 'admin',
    }));
    expect(updated.status).toBe('suspended');
    expect(registry._statusSyncedAt(organizationId)).toBeGreaterThan(0);
  });

  test('H1: a status change after a 1 ms backward Date.now() step is still newer than the previous one', async () => {
    let clock = 1_800_000_000_000;
    // The mock applies the real publisher's rule (updatedAt = max(Date.now(), minUpdatedAt)) on a controlled clock.
    mockPublisher.publishStatusChange.mockImplementation(async ({ minUpdatedAt = 0 }) => ({ updatedAt: Math.max(clock, minUpdatedAt), published: true }));
    const { organizationId } = registry.registerOrganization({ organizationName: 'Clock Step Org' });
    await registry.publishOrganizationStatus(organizationId, 'suspended');
    const first = mockPublisher.publishStatusChange.mock.results[0].value;
    clock -= 1;                                                   // V8's 60 s re-sync steps Date.now() back 1 ms
    await registry.publishOrganizationStatus(organizationId, 'active');
    expect(mockPublisher.publishStatusChange.mock.calls[1][0].minUpdatedAt).toBe((await first).updatedAt + 1);
    const second = await mockPublisher.publishStatusChange.mock.results[1].value;
    expect(second.updatedAt).toBeGreaterThan((await first).updatedAt);
    // Every worker (including this one) applies it rather than dropping it as stale.
    expect(registry._applyRemoteStatus(organizationId, 'active', second.updatedAt)).toBe(true);
  });

  test('throws ORG_STATUS_PROPAGATION_UNAVAILABLE without mutating local state when propagation fails', async () => {
    mockPublisher.publishStatusChange.mockRejectedValue(new Error('ORG_STATUS_PROPAGATION_UNAVAILABLE'));
    const { organizationId } = registry.registerOrganization({ organizationName: 'Blocked Worker' });

    await expect(registry.publishOrganizationStatus(organizationId, 'suspended'))
      .rejects.toThrow('ORG_STATUS_PROPAGATION_UNAVAILABLE');
    expect(registry.getOrganization(organizationId).status).toBe('active');
  });

  test('rejects invalid status before attempting propagation', async () => {
    const { organizationId } = registry.registerOrganization({ organizationName: 'Invalid Status Org' });
    await expect(registry.publishOrganizationStatus(organizationId, 'archived'))
      .rejects.toThrow('INVALID_ORG_STATUS');
    expect(mockPublisher.publishStatusChange).not.toHaveBeenCalled();
  });

  test('throws ORG_NOT_FOUND for unknown organization', async () => {
    await expect(registry.publishOrganizationStatus('00000000-0000-4000-8000-000000000000', 'suspended'))
      .rejects.toThrow('ORG_NOT_FOUND');
  });
});

// ── 8. Multi-worker propagation convergence (2 / 4 / N workers) ──────────────

describe('Multi-worker suspension propagation convergence', () => {
  // Simulates N independent worker processes, each with its own isolated
  // organizationRegistry module instance (separate in-memory state — exactly
  // like N real Node processes). "Worker A" suspends the org; the resulting
  // event is applied to every other worker via _applyRemoteStatus, exactly
  // as OrgStatusSubscriber's message handler would on message receipt. This
  // demonstrates that the SAME code path used by the real pub/sub subscriber
  // converges every worker to the same status.
  function bootWorker() {
    let mod;
    jest.isolateModules(() => {
      mod = require('../organizationRegistry');
      mod.setOrgStatusSubscriber({
        isStarted: () => true, isReady: () => true, MAX_PROPAGATION_WINDOW_MS: 5000,
      });
    });
    mod._reset();
    return mod;
  }

  test.each([2, 4, 8])('an organization suspension propagates to all %i workers', (workerCount) => {
    const workers = Array.from({ length: workerCount }, () => bootWorker());
    const organizationId = '11111111-1111-4111-8111-111111111111';

    // Provisioning is out of scope for (see docs/architecture/multi-tenancy.md
    // "Remaining limitations") — simulate that every worker already knows
    // about this org and its tenant, as they would post-reconciliation.
    for (const w of workers) {
      w.registerOrganization({ organizationId, organizationName: 'Shared Org' });
      w.assignTenantToOrg('tenant-shared', organizationId);
      w._applyRemoteStatus(organizationId, 'active', Date.now());
    }
    for (const w of workers) {
      expect(w.assertActiveOrganization('tenant-shared').valid).toBe(true);
    }

    // Worker 0 suspends; broadcast the resulting event to every OTHER worker
    // (worker 0 already applied it locally via publishOrganizationStatus in
    // production — here we apply it directly since the Redis plumbing is
    // covered by the OrgStatusPublisher/Subscriber suites above).
    const suspendedAt = Date.now();
    workers[0]._applyRemoteStatus(organizationId, 'suspended', suspendedAt);
    for (const w of workers.slice(1)) {
      w._applyRemoteStatus(organizationId, 'suspended', suspendedAt);
    }

    for (const w of workers) {
      const result = w.assertActiveOrganization('tenant-shared');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('ORG_SUSPENDED');
    }
  });

  test('out-of-order delivery across workers cannot resurrect a suspended org (monotonic guard holds per-worker)', () => {
    const [workerA, workerB] = [bootWorker(), bootWorker()];
    const organizationId = '22222222-2222-4222-8222-222222222222';

    for (const w of [workerA, workerB]) {
      w.registerOrganization({ organizationId, organizationName: 'Reorder Org' });
      w.assignTenantToOrg('tenant-reorder', organizationId);
    }

    const t1 = Date.now();
    const t2 = t1 + 1000;

    // Worker B receives the newer (suspend) event first, then a delayed,
    // older (active) event arrives out of order — must not un-suspend.
    workerB._applyRemoteStatus(organizationId, 'suspended', t2);
    workerB._applyRemoteStatus(organizationId, 'active', t1);
    expect(workerB.getOrganization(organizationId).status).toBe('suspended');

    // Worker A receives them in order — same end state either way.
    workerA._applyRemoteStatus(organizationId, 'active', t1);
    workerA._applyRemoteStatus(organizationId, 'suspended', t2);
    expect(workerA.getOrganization(organizationId).status).toBe('suspended');
  });
});

// ── 9. Module load-order independence (Finding 64 /) ─────────────────
//
// organizationRegistry.js and OrgStatusSubscriber.js formerly required each
// other via lazy in-function require() calls, which happened to avoid a
// deadlock at load time regardless of require order, but was still a real
// circular dependency (flagged by .dependency-cruiser.js's no-circular rule).
// Now that both modules use injected setters instead, neither module ever
// require()s the other, so load order genuinely cannot matter. These tests
// require the REAL modules (not mocked) in both orders and confirm each
// exposes a fully-formed, callable API with no partial initialization.
describe('Module load-order independence — organizationRegistry <-> OrgStatusSubscriber', () => {
  function assertFullyInitialized(organizationRegistry, orgStatusSubscriber) {
    // Neither module should throw on being required, and every exported
    // member used by the other side must be a real function, not undefined
    // (which would surface later as "X is not a function" TypeErrors).
    expect(typeof organizationRegistry.assertActiveOrganization).toBe('function');
    expect(typeof organizationRegistry.setOrgStatusSubscriber).toBe('function');
    expect(typeof organizationRegistry.listOrganizations).toBe('function');
    expect(typeof organizationRegistry._applyRemoteStatus).toBe('function');
    expect(typeof organizationRegistry._touchStatusFreshness).toBe('function');

    expect(typeof orgStatusSubscriber.start).toBe('function');
    expect(typeof orgStatusSubscriber.isReady).toBe('function');
    expect(typeof orgStatusSubscriber.isStarted).toBe('function');
    expect(typeof orgStatusSubscriber.setOrganizationRegistry).toBe('function');

    // Wiring the two together and exercising both directions must not throw,
    // and neither module's fields may be left in a half-initialized state
    // (e.g. isStarted() returning undefined instead of a boolean).
    expect(() => {
      organizationRegistry.setOrgStatusSubscriber(orgStatusSubscriber);
      orgStatusSubscriber.setOrganizationRegistry(organizationRegistry);
    }).not.toThrow();

    expect(orgStatusSubscriber.isStarted()).toBe(false);
    expect(orgStatusSubscriber.isReady()).toBe(false);

    organizationRegistry._reset();
    const { organizationId } = organizationRegistry.registerOrganization({ organizationName: 'Load Order Org' });
    organizationRegistry.assignTenantToOrg('tenant-load-order', organizationId);
    // Subscriber wired but never started() — must fall back to the
    // documented backward-compatible skip behavior, not throw or hang.
    expect(organizationRegistry.assertActiveOrganization('tenant-load-order'))
      .toEqual({ valid: true, organizationId });
  }

  test('Scenario A: require(OrgStatusSubscriber) before require(organizationRegistry)', () => {
    jest.isolateModules(() => {
      const orgStatusSubscriber  = require('./OrgStatusSubscriber');
      const organizationRegistry = require('../organizationRegistry');
      assertFullyInitialized(organizationRegistry, orgStatusSubscriber);
    });
  });

  test('Scenario B: require(organizationRegistry) before require(OrgStatusSubscriber)', () => {
    jest.isolateModules(() => {
      const organizationRegistry = require('../organizationRegistry');
      const orgStatusSubscriber  = require('./OrgStatusSubscriber');
      assertFullyInitialized(organizationRegistry, orgStatusSubscriber);
    });
  });
});
