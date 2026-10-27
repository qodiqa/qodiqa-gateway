'use strict';

/**
 * Component #19 — Instant Consent Revocation test suite.
 *
 * Tests: RevocationEvent, RevocationMetrics, RevocationPublisher,
 *        RevocationSubscriber, ConsentVerifier subscriber gate,
 *        ConsentRegistry propagation, API routes (status/history/revoked).
 */

// ── Mocks ─────────────────────────────────────────────────────────────────────

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
      ping:        jest.fn().mockResolvedValue('PONG'),
      on:          (ev, fn) => emitter.on(ev, fn),
      off:         (ev, fn) => emitter.off(ev, fn),
      emit:        (ev, ...args) => emitter.emit(ev, ...args),
      _emitter:    emitter,
    };
    Object.assign(client, overrides);
    return client;
  }

  return { createClient: jest.fn().mockImplementation(() => makeMockClient()) };
});

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
}));

jest.mock('../../../infra/redis/clientConfig', () => ({
  buildClientOptions: jest.fn().mockReturnValue({}),
  isAuthError:        jest.fn().mockReturnValue(false),
  isTlsError:         jest.fn().mockReturnValue(false),
}));

jest.mock('../ConsentCache', () => ({
  get:             jest.fn().mockResolvedValue(null),
  set:             jest.fn().mockResolvedValue(undefined),
  invalidate:      jest.fn().mockResolvedValue(undefined),
  invalidateActor: jest.fn().mockResolvedValue(undefined),
  isReady:         jest.fn().mockReturnValue(true),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

function freshModules() {
  jest.resetModules();
  return {
    RevocationEvent:     require('./RevocationEvent'),
    RevocationMetrics:   require('./RevocationMetrics'),
    RevocationPublisher: require('./RevocationPublisher'),
    RevocationSubscriber:require('./RevocationSubscriber'),
  };
}

function makeRedisClient(overrides = {}) {
  const EventEmitter = require('events');
  const emitter = new EventEmitter();
  return {
    connect:     jest.fn().mockResolvedValue(undefined),
    disconnect:  jest.fn().mockResolvedValue(undefined),
    subscribe:   jest.fn().mockResolvedValue(undefined),
    unsubscribe: jest.fn().mockResolvedValue(undefined),
    publish:     jest.fn().mockResolvedValue(1),
    ping:        jest.fn().mockResolvedValue('PONG'),
    on:          (ev, fn) => emitter.on(ev, fn),
    off:         (ev, fn) => emitter.off(ev, fn),
    _emit:       (ev, ...args) => emitter.emit(ev, ...args),
    ...overrides,
  };
}

// ── 1. RevocationEvent ────────────────────────────────────────────────────────

describe('RevocationEvent', () => {
  let RevocationEvent;

  beforeEach(() => {
    jest.resetModules();
    delete process.env.REVOCATION_SIGNING_KEY;
    RevocationEvent = require('./RevocationEvent');
  });

  test('buildEvent produces required fields', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run' });
    expect(event.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(event.version).toBe(RevocationEvent.EVENT_VERSION);
    expect(event.subjectId).toBe('actor1');
    expect(event.action).toBe('run');
    expect(event.sourceSystem).toBe('qodiqa-consent-registry');
    expect(event.revocationTimestamp).toBeTruthy();
    // every event is signed with the keystore MAC keyring — no unsigned mode.
    expect(event.signature).toMatch(/^mk_[0-9]{8}_[0-9a-f]{8}.[A-Za-z0-9_-]{43}$/);
  });

  test('buildEvent includes optional fields when provided', () => {
    const event = RevocationEvent.buildEvent({
      consentId:        'abc-123',
      subjectId:        'actor2',
      action:           'write',
      tenantId:         'tenant-x',
      revokedBy:        'admin',
      revocationReason: 'POLICY_VIOLATION',
      correlationId:    'req-999',
    });
    expect(event.consentId).toBe('abc-123');
    expect(event.tenantId).toBe('tenant-x');
    expect(event.revokedBy).toBe('admin');
    expect(event.revocationReason).toBe('POLICY_VIOLATION');
    expect(event.correlationId).toBe('req-999');
  });

  test('REVOCATION_SIGNING_KEY is ignored — the signature is a keyring tag either way', () => {
    jest.resetModules();
    process.env.REVOCATION_SIGNING_KEY = 'test-secret-key-32-chars-padding!!';
    RevocationEvent = require('./RevocationEvent');
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    expect(event.signature).toMatch(/^mk_[0-9]{8}_[0-9a-f]{8}.[A-Za-z0-9_-]{43}$/);
    delete process.env.REVOCATION_SIGNING_KEY;
  });

  test('parseEvent rejects invalid JSON', () => {
    const r = RevocationEvent.parseEvent('not-json{');
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('INVALID_JSON');
  });

  test('parseEvent rejects non-object', () => {
    const r = RevocationEvent.parseEvent('"a string"');
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('NOT_OBJECT');
  });

  test('parseEvent rejects wrong version', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    const mutated = { ...event, version: '99' };
    const r = RevocationEvent.parseEvent(JSON.stringify(mutated));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('VERSION_MISMATCH');
  });

  test('parseEvent rejects missing eventId', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    const { eventId: _, ...noId } = event;
    const r = RevocationEvent.parseEvent(JSON.stringify(noId));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('MISSING_EVENT_ID');
  });

  test('parseEvent rejects missing subjectId', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    const { subjectId: _, ...noSubject } = event;
    const r = RevocationEvent.parseEvent(JSON.stringify(noSubject));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('MISSING_SUBJECT_ID');
  });

  test('parseEvent rejects stale events', () => {
    jest.resetModules();
    process.env.REVOCATION_MAX_EVENT_AGE_MS = '1000';
    RevocationEvent = require('./RevocationEvent');
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    // Back-date the timestamp
    const old = { ...event, revocationTimestamp: new Date(Date.now() - 5000).toISOString() };
    const r = RevocationEvent.parseEvent(JSON.stringify(old));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('EVENT_EXPIRED');
    delete process.env.REVOCATION_MAX_EVENT_AGE_MS;
  });

  test('parseEvent REJECTS an unsigned event (was accepted fail-open when no key was set)', () => {
    const { signature: _, ...unsigned } = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run' });
    const r = RevocationEvent.parseEvent(JSON.stringify(unsigned));
    expect(r).toEqual({ ok: false, reason: 'MISSING_SIGNATURE' });
  });

  test('parseEvent rejects a v1 message even when well-formed (rolling upgrade: bounded by cache TTL)', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run' });
    const r = RevocationEvent.parseEvent(JSON.stringify({ ...event, version: '1', signature: 'a'.repeat(64) }));
    expect(r).toEqual({ ok: false, reason: 'VERSION_MISMATCH' });
  });

  test('parseEvent rejects event with tampered signature', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    const tampered = { ...event, signature: 'a'.repeat(64) };
    const r = RevocationEvent.parseEvent(JSON.stringify(tampered));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^INVALID_SIGNATURE:/);
  });

  test('an unsigned or forged message increments qodiqa_pubsub_signature_rejects_total', async () => {
    const metrics = require('../../../observability/metrics');
    const read = async () => [...metrics.pubsubSignatureRejectsTotal._labelsByKey]
      .filter(([, l]) => l.channel === RevocationEvent.CHANNEL)
      .reduce((a, [k]) => a + metrics.pubsubSignatureRejectsTotal._values.get(k), 0);
    const before = await read();
    const { signature: _, ...unsigned } = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    RevocationEvent.parseEvent(JSON.stringify(unsigned));
    RevocationEvent.parseEvent(JSON.stringify({ ...RevocationEvent.buildEvent({ subjectId: 'actor1' }), subjectId: 'actor2' }));
    expect(await read()).toBe(before + 2);
  });

  test('parseEvent accepts valid signed event', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run' });
    const r = RevocationEvent.parseEvent(JSON.stringify(event));
    expect(r.ok).toBe(true);
    expect(r.event.subjectId).toBe('actor1');
  });

  test('(NF-5): revokedBy and revocationReason are covered by the signature', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', revokedBy: 'admin', revocationReason: 'POLICY_VIOLATION' });
    for (const tampered of [{ ...event, revokedBy: 'someone-else' }, { ...event, revocationReason: 'USER_REQUEST' }]) {
      const r = RevocationEvent.parseEvent(JSON.stringify(tampered));
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/^INVALID_SIGNATURE:/);
    }
  });

  test('buildEvent includes consentVersion', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run', consentVersion: 9 });
    expect(event.consentVersion).toBe(9);
  });

  test('buildEvent defaults consentVersion to null when omitted', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run' });
    expect(event.consentVersion).toBeNull();
  });

  test('parseEvent rejects a signed event with a tampered consentVersion', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run', consentVersion: 5 });
    // Downgrade the version an attacker would need to defeat the CAS guard,
    // without touching the signature.
    const tampered = { ...event, consentVersion: 1 };
    const r = RevocationEvent.parseEvent(JSON.stringify(tampered));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^INVALID_SIGNATURE:/);
  });

  test('actor-level event (no consentId, no action) is valid', () => {
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1' });
    expect(event.consentId).toBeNull();
    expect(event.action).toBeNull();
    const r = RevocationEvent.parseEvent(JSON.stringify(event));
    expect(r.ok).toBe(true);
  });
});

// ── 2. RevocationMetrics ──────────────────────────────────────────────────────

describe('RevocationMetrics', () => {
  let metrics;

  beforeEach(() => {
    jest.resetModules();
    metrics = require('./RevocationMetrics');
  });

  test('exports required metric objects', () => {
    expect(metrics.published).toBeDefined();
    expect(metrics.received).toBeDefined();
    expect(metrics.cacheInvalidations).toBeDefined();
    expect(metrics.propagationLatency).toBeDefined();
    expect(metrics.subscriberReconnects).toBeDefined();
  });

  test('counter inc() does not throw', () => {
    expect(() => metrics.published.inc({ result: 'ok' })).not.toThrow();
    expect(() => metrics.received.inc({ result: 'invalid' })).not.toThrow();
    expect(() => metrics.cacheInvalidations.inc({ scope: 'targeted' })).not.toThrow();
    expect(() => metrics.subscriberReconnects.inc({ type: 'publisher' })).not.toThrow();
  });

  test('histogram observe() does not throw', () => {
    expect(() => metrics.propagationLatency.observe(42)).not.toThrow();
  });
});

// ── 3. RevocationPublisher ───────────────────────────────────────────────────

describe('RevocationPublisher', () => {
  let publisher;
  let mockClient;
  let createClient;

  beforeEach(() => {
    jest.resetModules();
    createClient = require('redis').createClient;
    mockClient = makeRedisClient();
    createClient.mockReturnValue(mockClient);
    publisher = require('./RevocationPublisher');
  });

  afterEach(async () => {
    await publisher.disconnect().catch(() => {});
  });

  test('isReady() returns false before connect', () => {
    expect(publisher.isReady()).toBe(false);
  });

  test('publish() returns true when Redis is available', async () => {
    mockClient.connect.mockImplementationOnce(async () => {
      mockClient._emit('ready');
    });
    const result = await publisher.publish({ subjectId: 'actor1', action: 'run' });
    expect(result).toBe(true);
    expect(mockClient.publish).toHaveBeenCalledWith(
      'qodiqa:consent:revocation',
      expect.stringContaining('"subjectId":"actor1"'),
    );
  });

  test('publish() returns false when Redis connect fails', async () => {
    mockClient.connect.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    const result = await publisher.publish({ subjectId: 'actor1' });
    expect(result).toBe(false);
  });

  test('publish() returns false when Redis is not ready after connect', async () => {
    // connect resolves but 'ready' event never fires → _ready stays false
    mockClient.connect.mockResolvedValueOnce(undefined);
    const result = await publisher.publish({ subjectId: 'actor1' });
    expect(result).toBe(false);
  });

  test('disconnect() is idempotent when never connected', async () => {
    await expect(publisher.disconnect()).resolves.not.toThrow();
    await expect(publisher.disconnect()).resolves.not.toThrow();
  });

  test('publish() builds event with correct fields', async () => {
    mockClient.connect.mockImplementationOnce(async () => {
      mockClient._emit('ready');
    });
    await publisher.publish({
      consentId:        'cid-123',
      subjectId:        'actor2',
      action:           'write',
      tenantId:         'tenant-a',
      revokedBy:        'admin',
      revocationReason: 'POLICY_VIOLATION',
      correlationId:    'req-abc',
    });
    const [, payload] = mockClient.publish.mock.calls[0];
    const event = JSON.parse(payload);
    expect(event.consentId).toBe('cid-123');
    expect(event.tenantId).toBe('tenant-a');
    expect(event.revokedBy).toBe('admin');
    expect(event.sourceSystem).toBe('qodiqa-consent-registry');
    expect(event.version).toBe('2'); // v2 — mandatory keyring signature
  });
});

// ── 4. RevocationSubscriber ──────────────────────────────────────────────────

describe('RevocationSubscriber', () => {
  let subscriber;
  let mockClient;
  let createClient;

  beforeEach(() => {
    jest.resetModules();
    createClient = require('redis').createClient;
    mockClient = makeRedisClient();
    // Override connect with a closure that emits 'ready', keeping spy identity intact
    const mc = mockClient;
    mockClient.connect = jest.fn().mockImplementationOnce(async () => {
      mc._emit('ready');
    });
    createClient.mockReturnValue(mockClient);
    subscriber = require('./RevocationSubscriber');
  });

  afterEach(async () => {
    await subscriber.stop().catch(() => {});
  });

  test('isReady() and isStarted() are false before start()', () => {
    expect(subscriber.isReady()).toBe(false);
    expect(subscriber.isStarted()).toBe(false);
  });

  test('start() resolves when Redis connects and subscribes', async () => {
    await expect(subscriber.start()).resolves.not.toThrow();
    expect(subscriber.isStarted()).toBe(true);
    expect(mockClient.subscribe).toHaveBeenCalledWith(
      'qodiqa:consent:revocation',
      expect.any(Function),
    );
  });

  test('start() throws when Redis connect fails', async () => {
    jest.resetModules();
    const failClient = makeRedisClient({
      connect: jest.fn().mockRejectedValue(new Error('ECONNREFUSED')),
    });
    require('redis').createClient.mockReturnValue(failClient);
    const sub2 = require('./RevocationSubscriber');
    await expect(sub2.start()).rejects.toThrow('ECONNREFUSED');
    expect(sub2.isStarted()).toBe(false);
    expect(sub2.isReady()).toBe(false);
  });

  test('start() throws on startup timeout', async () => {
    jest.resetModules();
    process.env.REVOCATION_SUBSCRIBER_STARTUP_TIMEOUT_MS = '10';
    const slowClient = makeRedisClient({
      connect: jest.fn().mockImplementation(() => new Promise(() => {})), // never resolves
    });
    require('redis').createClient.mockReturnValue(slowClient);
    const sub2 = require('./RevocationSubscriber');
    await expect(sub2.start()).rejects.toThrow('REVOCATION_SUBSCRIBER_STARTUP_TIMEOUT');
    delete process.env.REVOCATION_SUBSCRIBER_STARTUP_TIMEOUT_MS;
  });

  test('start() is idempotent when called twice', async () => {
    await subscriber.start();
    await subscriber.start();
    expect(mockClient.connect).toHaveBeenCalledTimes(1);
  });

  test('stop() disconnects and resets state', async () => {
    await subscriber.start();
    await subscriber.stop();
    expect(subscriber.isStarted()).toBe(false);
    expect(subscriber.isReady()).toBe(false);
    expect(mockClient.unsubscribe).toHaveBeenCalled();
    expect(mockClient.disconnect).toHaveBeenCalled();
  });

  test('processes valid revocation event and invalidates targeted cache', async () => {
    let messageHandler;
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => {
      messageHandler = fn;
      return Promise.resolve();
    });

    await subscriber.start();

    const cache = require('../ConsentCache');
    const RevocationEvent = require('./RevocationEvent');
    const event = RevocationEvent.buildEvent({
      subjectId: 'actor-xyz',
      action:    'run',
      tenantId:  'tenant-1',
    });
    await messageHandler(JSON.stringify(event));

    expect(cache.invalidate).toHaveBeenCalledWith('actor-xyz', 'run', 'tenant-1', null);
  });

  test('propagates consentVersion from the event into cache.invalidate for cross-node CAS', async () => {
    let messageHandler;
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => {
      messageHandler = fn;
      return Promise.resolve();
    });

    await subscriber.start();

    const cache = require('../ConsentCache');
    const RevocationEvent = require('./RevocationEvent');
    const event = RevocationEvent.buildEvent({
      subjectId:      'actor-xyz',
      action:         'run',
      tenantId:       'tenant-1',
      consentVersion: 42,
    });
    await messageHandler(JSON.stringify(event));

    expect(cache.invalidate).toHaveBeenCalledWith('actor-xyz', 'run', 'tenant-1', 42);
  });

  test('processes actor-level event and calls invalidateActor', async () => {
    let messageHandler;
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => {
      messageHandler = fn;
      return Promise.resolve();
    });

    await subscriber.start();

    const cache = require('../ConsentCache');
    const RevocationEvent = require('./RevocationEvent');
    const event = RevocationEvent.buildEvent({ subjectId: 'actor-bulk' }); // no action
    await messageHandler(JSON.stringify(event));

    expect(cache.invalidateActor).toHaveBeenCalledWith('actor-bulk');
  });

  test('deduplicates events with same eventId', async () => {
    let messageHandler;
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => {
      messageHandler = fn;
      return Promise.resolve();
    });

    await subscriber.start();

    const cache = require('../ConsentCache');
    const RevocationEvent = require('./RevocationEvent');
    const event = RevocationEvent.buildEvent({ subjectId: 'actor1', action: 'run' });
    const raw = JSON.stringify(event);

    await messageHandler(raw);
    await messageHandler(raw); // duplicate

    expect(cache.invalidate).toHaveBeenCalledTimes(1);
  });

  test('ignores invalid messages without crashing', async () => {
    let messageHandler;
    mockClient.subscribe = jest.fn().mockImplementation((_ch, fn) => {
      messageHandler = fn;
      return Promise.resolve();
    });

    await subscriber.start();

    await expect(messageHandler('not-json{')).resolves.not.toThrow();
    await expect(messageHandler(JSON.stringify({ version: '99' }))).resolves.not.toThrow();
  });

  test('isReady() returns false when client reconnecting', async () => {
    await subscriber.start();
    expect(subscriber.isReady()).toBe(true);
    mockClient._emit('reconnecting');
    expect(subscriber.isReady()).toBe(false);
  });
});

// ── 5. ConsentVerifier subscriber gate ───────────────────────────────────────

describe('ConsentVerifier — subscriber readiness gate', () => {
  let ConsentVerifier;
  let mockSubscriber;
  let mockPool;
  let mockCache;
  let mockStore;

  beforeEach(() => {
    jest.resetModules();

    mockSubscriber = { isStarted: jest.fn().mockReturnValue(true), isReady: jest.fn().mockReturnValue(true) };
    mockPool  = { isEnabled: jest.fn().mockReturnValue(true), isHealthy: jest.fn().mockReturnValue(true) };
    mockCache = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue(undefined),
    };
    mockStore = {
      findByKey:       jest.fn().mockResolvedValue(null),
      logVerification: jest.fn().mockResolvedValue(undefined),
    };

    jest.mock('../../../infra/postgres/pool', () => mockPool);
    jest.mock('../ConsentCache', () => mockCache);
    jest.mock('../ConsentStore', () => mockStore);
    jest.mock('./RevocationSubscriber', () => mockSubscriber);

    ConsentVerifier = require('../ConsentVerifier');
  });

  test('returns CONSENT_REVOCATION_SYNC_UNAVAILABLE when subscriber started but not ready', async () => {
    mockSubscriber.isStarted.mockReturnValue(true);
    mockSubscriber.isReady.mockReturnValue(false);

    const result = await ConsentVerifier.verify({ actor_id: 'actor1', action: 'run' });
    expect(result.pass).toBe(false);
    expect(result.reason).toBe('CONSENT_REVOCATION_SYNC_UNAVAILABLE');
  });

  test('skips subscriber check when subscriber not yet started', async () => {
    mockSubscriber.isStarted.mockReturnValue(false);
    mockSubscriber.isReady.mockReturnValue(false);

    // Store returns null → CONSENT_NOT_FOUND (not the subscriber error)
    const result = await ConsentVerifier.verify({ actor_id: 'actor1', action: 'run' });
    expect(result.reason).toBe('CONSENT_NOT_FOUND');
  });

  test('proceeds to DB check when subscriber is ready', async () => {
    mockSubscriber.isStarted.mockReturnValue(true);
    mockSubscriber.isReady.mockReturnValue(true);
    mockStore.findByKey.mockResolvedValue(null);

    const result = await ConsentVerifier.verify({ actor_id: 'actor1', action: 'run' });
    expect(result.reason).toBe('CONSENT_NOT_FOUND');
    expect(mockStore.findByKey).toHaveBeenCalled();
  });
});

// ── 6. ConsentRegistry propagation ───────────────────────────────────────────

describe('ConsentRegistry — revocation propagation', () => {
  let ConsentRegistry;
  let mockStore;
  let mockCache;
  let mockPublisher;
  let mockEmit;

  const fakeRecord = {
    id: 'rec-uuid-1',
    actor_id: 'actor1',
    action: 'run',
    tenant_id: 'tenant-a',
    state: 'REVOKED',
    revocation_reason: 'TEST',
    revoked_by: 'admin',
    version: 4,
  };

  const fakeSuspendedRecord = {
    id: 'rec-uuid-2',
    actor_id: 'actor1',
    action: 'run',
    tenant_id: 'tenant-a',
    state: 'SUSPENDED',
    suspension_reason: 'TEST',
    suspended_by: 'admin',
    version: 4,
  };

  beforeEach(() => {
    jest.resetModules();

    mockEmit    = jest.fn();
    mockStore   = { revoke: jest.fn().mockResolvedValue(fakeRecord), list: jest.fn().mockResolvedValue({ records: [] }), resume: jest.fn(), suspend: jest.fn().mockResolvedValue(fakeSuspendedRecord), create: jest.fn(), findByKey: jest.fn(), findById: jest.fn(), getAuditLog: jest.fn(), logVerification: jest.fn() };
    mockCache   = { invalidate: jest.fn().mockResolvedValue(undefined), invalidateActor: jest.fn().mockResolvedValue(undefined), isReady: jest.fn().mockReturnValue(true) };
    mockPublisher = { publish: jest.fn().mockResolvedValue(true), disconnect: jest.fn(), isReady: jest.fn().mockReturnValue(true) };

    jest.mock('../ConsentStore', () => mockStore);
    jest.mock('../ConsentCache', () => mockCache);
    jest.mock('./RevocationPublisher', () => mockPublisher);
    jest.mock('../../../../services/logger', () => ({ emit: mockEmit }));
    jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn().mockReturnValue(true), isHealthy: jest.fn().mockReturnValue(true) }));
    jest.mock('../ConsentVerifier', () => ({ verify: jest.fn() }));
    jest.mock('../ConsentStateModel', () => ({
      STATE: { PENDING: 'PENDING', ACTIVE: 'ACTIVE', REVOKED: 'REVOKED', EXPIRED: 'EXPIRED', SUSPENDED: 'SUSPENDED' },
      effectiveState: jest.fn(r => r.state),
      isValidTransition: jest.fn().mockReturnValue(true),
      isTerminal: jest.fn(s => ['REVOKED', 'EXPIRED'].includes(s)),
    }));

    ConsentRegistry = require('../ConsentRegistry');
  });

  test('revoke() awaits publish and returns record on success', async () => {
    const result = await ConsentRegistry.revoke({
      id: 'rec-uuid-1', revoked_by: 'admin', request_id: 'req-1',
    });
    expect(mockPublisher.publish).toHaveBeenCalledWith(expect.objectContaining({
      consentId: 'rec-uuid-1',
      subjectId: 'actor1',
      action:    'run',
      revokedBy: 'admin',
      consentVersion: 4,
    }));
    expect(result).toEqual(fakeRecord);
  });

  test('(NF-6): grant() publishes a signed cross-node invalidation carrying the new version', async () => {
    mockStore.create.mockResolvedValue({ id: 'rec-new', actor_id: 'actor1', action: 'run', tenant_id: 'tenant-a', version: 1 });
    const r = await ConsentRegistry.grant({ actor_id: 'actor1', action: 'run' });
    expect(r.id).toBe('rec-new');
    expect(mockCache.invalidate).toHaveBeenCalledWith('actor1', 'run', 'tenant-a', 1);
    expect(mockPublisher.publish).toHaveBeenCalledWith(expect.objectContaining({
      consentId: 'rec-new', subjectId: 'actor1', action: 'run', tenantId: 'tenant-a',
      consentVersion: 1, revocationReason: 'CONSENT_GRANTED_INVALIDATE',
    }));
  });

  test('(NF-6): grant() still succeeds when the invalidation publish fails or throws (best-effort, logged)', async () => {
    mockStore.create.mockResolvedValue({ id: 'rec-new', actor_id: 'actor1', action: 'run', tenant_id: null, version: 1 });
    mockPublisher.publish.mockResolvedValueOnce(false).mockRejectedValueOnce(new Error('redis down'));
    await expect(ConsentRegistry.grant({ actor_id: 'actor1', action: 'run' })).resolves.toMatchObject({ id: 'rec-new' });
    await expect(ConsentRegistry.grant({ actor_id: 'actor1', action: 'run' })).resolves.toMatchObject({ id: 'rec-new' });
    expect(mockEmit.mock.calls.filter(([, t]) => t === 'CONSENT_GRANT_INVALIDATION_PUBLISH_FAILED')).toHaveLength(2);
  });

  test('revoke() invalidates the local cache with the post-revoke version', async () => {
    await ConsentRegistry.revoke({ id: 'rec-uuid-1', revoked_by: 'admin' });
    expect(mockCache.invalidate).toHaveBeenCalledWith('actor1', 'run', 'tenant-a', 4);
  });

  test('suspend() invalidates the local cache with the post-suspend version', async () => {
    await ConsentRegistry.suspend({ id: 'rec-uuid-2', suspended_by: 'admin' });
    expect(mockCache.invalidate).toHaveBeenCalledWith('actor1', 'run', 'tenant-a', 4);
  });

  test('suspend() publishes a propagation event', async () => {
    await ConsentRegistry.suspend({ id: 'rec-uuid-2', suspended_by: 'admin', request_id: 'req-2' });
    expect(mockPublisher.publish).toHaveBeenCalledWith(expect.objectContaining({
      consentId: 'rec-uuid-2',
      subjectId: 'actor1',
      action:    'run',
      consentVersion: 4,
    }));
  });

  test('suspend() emits CRITICAL when propagation publish fails', async () => {
    mockPublisher.publish.mockResolvedValue(false);
    await ConsentRegistry.suspend({ id: 'rec-uuid-2', suspended_by: 'admin' });
    expect(mockEmit).toHaveBeenCalledWith(
      'CRITICAL',
      'CONSENT_SUSPENSION_PROPAGATION_FAILED',
      expect.objectContaining({ consentId: 'rec-uuid-2' }),
    );
  });

  test('suspend() still returns the record even when publish fails', async () => {
    mockPublisher.publish.mockResolvedValue(false);
    const result = await ConsentRegistry.suspend({ id: 'rec-uuid-2', suspended_by: 'admin' });
    expect(result).toEqual(fakeSuspendedRecord);
  });

  test('revoke() emits CRITICAL when publish fails', async () => {
    mockPublisher.publish.mockResolvedValue(false);
    await ConsentRegistry.revoke({ id: 'rec-uuid-1', revoked_by: 'admin' });
    expect(mockEmit).toHaveBeenCalledWith(
      'CRITICAL',
      'CONSENT_REVOCATION_PROPAGATION_FAILED',
      expect.objectContaining({ consentId: 'rec-uuid-1' }),
    );
  });

  test('revoke() still returns record even when publish fails', async () => {
    mockPublisher.publish.mockResolvedValue(false);
    const result = await ConsentRegistry.revoke({ id: 'rec-uuid-1', revoked_by: 'admin' });
    expect(result).toEqual(fakeRecord);
  });

  test('revokeAll() publishes actor-level event', async () => {
    mockStore.list.mockResolvedValue({
      records: [{ ...fakeRecord, state: 'ACTIVE' }],
    });
    mockStore.revoke.mockResolvedValue(fakeRecord);

    await ConsentRegistry.revokeAll('actor1', 'admin', 'DECOMMISSIONED');

    expect(mockPublisher.publish).toHaveBeenCalledWith(expect.objectContaining({
      consentId:        null,
      subjectId:        'actor1',
      revocationReason: 'DECOMMISSIONED',
      revokedBy:        'admin',
    }));
  });

  test('revokeAll() CAS-guards each record locally with its post-revoke version ahead of the actor-level sweep', async () => {
    mockStore.list.mockResolvedValue({
      records: [{ ...fakeRecord, id: 'rec-a', state: 'ACTIVE' }, { ...fakeRecord, id: 'rec-b', action: 'write', state: 'ACTIVE' }],
    });
    mockStore.revoke
      .mockResolvedValueOnce({ ...fakeRecord, id: 'rec-a', version: 9 })
      .mockResolvedValueOnce({ ...fakeRecord, id: 'rec-b', action: 'write', version: 3 });

    await ConsentRegistry.revokeAll('actor1', 'admin');

    expect(mockCache.invalidate).toHaveBeenCalledWith('actor1', 'run', 'tenant-a', 9);
    expect(mockCache.invalidate).toHaveBeenCalledWith('actor1', 'write', 'tenant-a', 3);
    expect(mockCache.invalidateActor).toHaveBeenCalledWith('actor1');
  });

  test('revokeAll() emits CRITICAL when actor publish fails', async () => {
    mockPublisher.publish.mockResolvedValue(false);
    mockStore.list.mockResolvedValue({ records: [] });

    await ConsentRegistry.revokeAll('actor1', 'admin');

    expect(mockEmit).toHaveBeenCalledWith(
      'CRITICAL',
      'CONSENT_REVOCATION_ACTOR_PROPAGATION_FAILED',
      expect.objectContaining({ actorId: 'actor1' }),
    );
  });
});

// ── 7. API routes ─────────────────────────────────────────────────────────────

describe('Consent API routes — revocation endpoints', () => {
  let request;
  let app;
  let mockRegistry;
  let mockPublisher;
  let mockSubscriber;

  beforeEach(() => {
    jest.resetModules();

    mockRegistry = {
      list:        jest.fn().mockResolvedValue({ records: [], total: 0 }),
      getById:     jest.fn().mockResolvedValue(null),
      getAuditLog: jest.fn().mockResolvedValue([]),
      health:      jest.fn().mockReturnValue({ pgEnabled: true, pgHealthy: true, cacheReady: true }),
      grant:       jest.fn(),
      revoke:      jest.fn(),
      suspend:     jest.fn(),
      resume:      jest.fn(),
      revokeAll:   jest.fn(),
      verify:      jest.fn(),
    };
    mockPublisher  = { isReady: jest.fn().mockReturnValue(true) };
    mockSubscriber = { isReady: jest.fn().mockReturnValue(true), isStarted: jest.fn().mockReturnValue(true) };

    jest.mock('..', () => mockRegistry);
    jest.mock('./RevocationPublisher',  () => mockPublisher);
    jest.mock('./RevocationSubscriber', () => mockSubscriber);
    jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

    const express = require('express');
    const { createConsentRouter } = require('../../../api/routes/consent');
    app = express();
    app.use(express.json());
    app.use('/consent', createConsentRouter());
    request = require('supertest');
  });

  // ── /health includes propagation fields ────────────────────────────────────

  test('GET /consent/health includes revocation propagation status', async () => {
    const res = await request(app).get('/consent/health');
    expect(res.status).toBe(200);
    expect(res.body.data.revocationPublisherReady).toBe(true);
    expect(res.body.data.revocationSubscriberReady).toBe(true);
  });

  test('GET /consent/health reflects degraded propagation state', async () => {
    mockPublisher.isReady.mockReturnValue(false);
    mockSubscriber.isReady.mockReturnValue(false);
    const res = await request(app).get('/consent/health');
    expect(res.body.data.revocationPublisherReady).toBe(false);
    expect(res.body.data.revocationSubscriberReady).toBe(false);
  });

  // ── GET /consent/revoked ───────────────────────────────────────────────────

  test('GET /consent/revoked calls list with state=REVOKED', async () => {
    mockRegistry.list.mockResolvedValue({ records: [{ id: 'x', state: 'REVOKED' }], total: 1 });
    const res = await request(app).get('/consent/revoked');
    expect(res.status).toBe(200);
    expect(mockRegistry.list).toHaveBeenCalledWith(expect.objectContaining({ state: 'REVOKED' }));
    expect(res.body.data.records).toHaveLength(1);
  });

  test('GET /consent/revoked accepts actor_id filter', async () => {
    await request(app).get('/consent/revoked?actor_id=actor1');
    expect(mockRegistry.list).toHaveBeenCalledWith(expect.objectContaining({
      actor_id: 'actor1',
      state:    'REVOKED',
    }));
  });

  // ── GET /consent/:id/status ────────────────────────────────────────────────

  test('GET /consent/:id/status returns 404 for unknown id', async () => {
    mockRegistry.getById.mockResolvedValue(null);
    const res = await request(app).get('/consent/00000000-0000-0000-0000-000000000001/status');
    expect(res.status).toBe(404);
  });

  test('GET /consent/:id/status returns revocation status with propagation fields', async () => {
    mockRegistry.getById.mockResolvedValue({
      id: '00000000-0000-0000-0000-000000000001',
      state: 'REVOKED',
      revoked_at: '2026-01-01T00:00:00.000Z',
      revoked_by: 'admin',
      revocation_reason: 'TEST',
    });
    const res = await request(app).get('/consent/00000000-0000-0000-0000-000000000001/status');
    expect(res.status).toBe(200);
    expect(res.body.data.state).toBe('REVOKED');
    expect(res.body.data.propagation.publisherReady).toBe(true);
    expect(res.body.data.propagation.subscriberReady).toBe(true);
  });

  test('GET /consent/:id/status rejects invalid UUID', async () => {
    const res = await request(app).get('/consent/not-a-uuid/status');
    expect(res.status).toBe(400);
  });

  // ── GET /consent/:id/history ───────────────────────────────────────────────

  test('GET /consent/:id/history returns only revocation-related audit events', async () => {
    const allEntries = [
      { event_type: 'CONSENT_GRANTED',   id: 1 },
      { event_type: 'CONSENT_REVOKED',   id: 2 },
      { event_type: 'CONSENT_VERIFIED',  id: 3 },
      { event_type: 'CONSENT_SUSPENDED', id: 4 },
      { event_type: 'CONSENT_RESUMED',   id: 5 },
    ];
    mockRegistry.getAuditLog.mockResolvedValue(allEntries);
    const res = await request(app).get('/consent/00000000-0000-0000-0000-000000000001/history');
    expect(res.status).toBe(200);
    expect(res.body.data.entries).toHaveLength(3); // REVOKED, SUSPENDED, RESUMED
    expect(res.body.data.entries.map(e => e.event_type)).not.toContain('CONSENT_GRANTED');
    expect(res.body.data.entries.map(e => e.event_type)).not.toContain('CONSENT_VERIFIED');
  });

  test('GET /consent/:id/history rejects invalid UUID', async () => {
    const res = await request(app).get('/consent/bad-id/history');
    expect(res.status).toBe(400);
  });
});

// ── 8. Fail-closed integration ────────────────────────────────────────────────

describe('Fail-closed behavior — subscriber disconnection', () => {
  let ConsentVerifier;
  let mockSub;

  beforeEach(() => {
    jest.resetModules();
    // ConsentRegistry describe mocks ../ConsentVerifier; undo that here
    // so we load the real ConsentVerifier module under test.
    jest.unmock('../ConsentVerifier');

    mockSub = { isStarted: jest.fn().mockReturnValue(true), isReady: jest.fn().mockReturnValue(false) };

    jest.mock('../../../infra/postgres/pool', () => ({
      isEnabled: jest.fn().mockReturnValue(true),
    }));
    jest.mock('../ConsentCache', () => ({
      get: jest.fn().mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED', cached: true }),
      set: jest.fn(),
    }));
    jest.mock('../ConsentStore', () => ({
      findByKey:       jest.fn(),
      logVerification: jest.fn().mockResolvedValue(undefined),
    }));
    jest.mock('./RevocationSubscriber', () => mockSub);
    jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

    ConsentVerifier = require('../ConsentVerifier');
  });

  test('ConsentVerifier blocks ALL consent when subscriber disconnects at runtime', async () => {
    // Even with a warm cache hit, subscriber being down must block
    const result = await ConsentVerifier.verify({ actor_id: 'actor1', action: 'run' });
    expect(result.pass).toBe(false);
    expect(result.reason).toBe('CONSENT_REVOCATION_SYNC_UNAVAILABLE');
  });
});
