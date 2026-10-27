'use strict';

/**
 * idempotencyStore.js — talks to the module directly with a mocked Redis
 * client so the exact commands/options sent over the wire can be inspected.
 * Mirrors src/validation/__tests__/nonceStore.test.js's mocking approach.
 */

jest.mock('redis', () => ({ createClient: jest.fn() }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { createClient } = require('redis');
const idempotencyStore = require('../idempotencyStore');

function makeFakeRedisClient() {
  const map = new Map();
  return {
    isReady: true,
    on:   jest.fn(),
    once: jest.fn(),
    off:  jest.fn(),
    connect:    jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    ping: jest.fn().mockResolvedValue('PONG'),
    set: jest.fn(async (key, value, opts) => {
      if (opts?.NX && map.has(key)) return null;
      if (opts?.XX && !map.has(key)) return null;
      map.set(key, value);
      return 'OK';
    }),
    get: jest.fn(async (key) => (map.has(key) ? map.get(key) : null)),
    del: jest.fn(async (key) => { const had = map.has(key); map.delete(key); return had ? 1 : 0; }),
    _map: map,
  };
}

let fakeClient;

beforeEach(() => {
  fakeClient = makeFakeRedisClient();
  createClient.mockReturnValue(fakeClient);
});

afterEach(async () => {
  await idempotencyStore.disconnect();
});

describe('buildIdempotencyKey', () => {
  test('tenant-scoped key: tenantId prefixes the whole key', () => {
    expect(idempotencyStore.buildIdempotencyKey('acme-corp', 'my-key'))
      .toBe('acme-corp:qodiqa:idem:v1:my-key');
  });

  test('no tenantId: key has no tenant prefix', () => {
    expect(idempotencyStore.buildIdempotencyKey(null, 'my-key')).toBe('qodiqa:idem:v1:my-key');
  });

  test('two tenants with the identical idempotencyKey never collide', () => {
    const a = idempotencyStore.buildIdempotencyKey('tenant-a', 'shared-key');
    const b = idempotencyStore.buildIdempotencyKey('tenant-b', 'shared-key');
    expect(a).not.toBe(b);
  });
});

describe('reserve / complete / release / get', () => {
  test('reserve() on a fresh key succeeds and stores a pending record', async () => {
    const result = await idempotencyStore.reserve('acme', 'k1', 'fp-1', 60_000);
    expect(result).toEqual({ reserved: true });

    const stored = await idempotencyStore.get('acme', 'k1');
    expect(stored).toMatchObject({ status: 'pending', fingerprint: 'fp-1', tenantId: 'acme' });
  });

  test('reserve() on an already-reserved key fails and returns the existing record', async () => {
    await idempotencyStore.reserve('acme', 'k1', 'fp-1', 60_000);
    const second = await idempotencyStore.reserve('acme', 'k1', 'fp-2', 60_000);
    expect(second.reserved).toBe(false);
    expect(second.existing).toMatchObject({ status: 'pending', fingerprint: 'fp-1' });
  });

  test('reserve() uses SET with NX and the reservation TTL as PX', async () => {
    await idempotencyStore.reserve('acme', 'k1', 'fp-1', 12_345);
    expect(fakeClient.set).toHaveBeenCalledWith(
      'acme:qodiqa:idem:v1:k1',
      expect.any(String),
      { NX: true, PX: 12_345 },
    );
  });

  test('complete() overwrites a held reservation with a completed record (SET XX)', async () => {
    await idempotencyStore.reserve('acme', 'k1', 'fp-1', 60_000);
    const result = await idempotencyStore.complete('acme', 'k1', { fingerprint: 'fp-1', httpStatus: 200, body: { ok: true } }, 86_400_000);
    expect(result).toEqual({ completed: true });

    const stored = await idempotencyStore.get('acme', 'k1');
    expect(stored).toMatchObject({ status: 'completed', httpStatus: 200, body: { ok: true } });
  });

  test('complete() never resurrects a key that was never reserved (SET XX fails)', async () => {
    const result = await idempotencyStore.complete('acme', 'never-reserved', { fingerprint: 'fp-1', httpStatus: 200, body: {} }, 86_400_000);
    expect(result).toEqual({ completed: false });
    expect(await idempotencyStore.get('acme', 'never-reserved')).toBeNull();
  });

  test('release() deletes the key, freeing it for a fresh reservation', async () => {
    await idempotencyStore.reserve('acme', 'k1', 'fp-1', 60_000);
    await idempotencyStore.release('acme', 'k1');
    expect(await idempotencyStore.get('acme', 'k1')).toBeNull();

    const fresh = await idempotencyStore.reserve('acme', 'k1', 'fp-2', 60_000);
    expect(fresh).toEqual({ reserved: true });
  });

  test('release() on a non-existent key is a safe no-op', async () => {
    await expect(idempotencyStore.release('acme', 'nope')).resolves.toBeUndefined();
  });

  test('get() returns null for a non-existent key', async () => {
    expect(await idempotencyStore.get('acme', 'nope')).toBeNull();
  });

  test('tenant isolation: a completed record under one tenant is invisible to another', async () => {
    await idempotencyStore.reserve('tenant-a', 'shared-key', 'fp-1', 60_000);
    await idempotencyStore.complete('tenant-a', 'shared-key', { fingerprint: 'fp-1', httpStatus: 200, body: {} }, 86_400_000);

    expect(await idempotencyStore.get('tenant-b', 'shared-key')).toBeNull();
    const b = await idempotencyStore.reserve('tenant-b', 'shared-key', 'fp-1', 60_000);
    expect(b).toEqual({ reserved: true }); // tenant-b gets its own independent reservation
  });
});

describe('fail-closed behavior', () => {
  test('reserve() throws when Redis is not ready', async () => {
    fakeClient.isReady = false;
    await expect(idempotencyStore.reserve('acme', 'k1', 'fp-1', 60_000)).rejects.toThrow(/not connected/);
  });

  test('get() throws when Redis is not ready', async () => {
    fakeClient.isReady = false;
    await expect(idempotencyStore.get('acme', 'k1')).rejects.toThrow(/not connected/);
  });
});
