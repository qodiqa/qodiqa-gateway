'use strict';

/**
 * Distributed Key Rotation Lock — Tests
 *
 * RL-01…05  Acquire semantics (NX/PX, contention)
 * RL-06…10  Release semantics (compare-and-delete safety)
 * RL-11…14  Fail-closed behavior when Redis is unavailable
 * RL-15…16  Key namespacing
 */

jest.mock('redis', () => ({ createClient: jest.fn() }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { createClient } = require('redis');

function makeFakeRedisClient() {
  const map = new Map();
  const ttl = new Map(); // key -> PX of the last SET/PEXPIRE (no real expiry in this fake)
  return {
    isReady: true,
    on:         jest.fn(),
    connect:    jest.fn().mockResolvedValue(undefined),
    disconnect: jest.fn().mockResolvedValue(undefined),
    set: jest.fn(async (key, value, opts) => {
      if (opts && opts.NX && map.has(key)) return null;
      map.set(key, value);
      if (opts && opts.PX) ttl.set(key, opts.PX);
      return 'OK';
    }),
    get: jest.fn(async (key) => (map.has(key) ? map.get(key) : null)),
    // Minimal Lua interpreter for exactly the scripts this module uses — not a
    // general EVAL implementation. added the fence (INCR), ownership
    // re-check (PTTL) and renew (PEXPIRE) scripts; before it, every EVAL was the
    // compare-and-delete release, so this double treated all scripts as that.
    eval: jest.fn(async (script, { keys, arguments: args }) => {
      const [key]   = keys;
      const [token] = args;
      const held = map.get(key) === token;
      if (script.includes('INCR')) {
        if (!held) return null;
        const fenceKey = keys[1];
        if (!map.has(fenceKey)) map.set(fenceKey, String(args[1]));
        map.set(fenceKey, String(Number(map.get(fenceKey)) + 1));
        return Number(map.get(fenceKey));
      }
      if (script.includes('PTTL')) return held ? (ttl.get(key) ?? -1) : -3;
      if (script.includes('PEXPIRE')) {
        if (!held) return 0;
        ttl.set(key, Number(args[1]));
        return 1;
      }
      if (held) {
        map.delete(key);
        return 1;
      }
      return 0;
    }),
    _map: map,
  };
}

const rotationLock = require('../rotationLock');
let fakeClient;

beforeEach(() => {
  fakeClient = makeFakeRedisClient();
  createClient.mockReturnValue(fakeClient);
});

afterEach(async () => {
  await rotationLock.disconnect();
  jest.clearAllMocks();
});

// ═════════════════════════════════════════════════════════════════════════════
// RL-01…05  Acquire semantics
// ═════════════════════════════════════════════════════════════════════════════

describe('Acquire semantics', () => {
  test('RL-01: first acquire for a clientId succeeds and returns a token', async () => {
    const result = await rotationLock.acquire('acme', 30_000);
    expect(result.acquired).toBe(true);
    expect(typeof result.token).toBe('string');
    expect(result.token.length).toBeGreaterThan(0);
  });

  test('RL-02: second concurrent acquire for the same clientId fails while the first is held', async () => {
    const first  = await rotationLock.acquire('acme', 30_000);
    const second = await rotationLock.acquire('acme', 30_000);
    expect(first.acquired).toBe(true);
    expect(second.acquired).toBe(false);
  });

  test('RL-03: acquire uses SET with NX and PX matching the requested TTL', async () => {
    await rotationLock.acquire('acme', 12_345);
    expect(fakeClient.set).toHaveBeenCalledWith(
      expect.stringContaining('acme'),
      expect.any(String),
      { NX: true, PX: 12_345 },
    );
  });

  test('RL-04: different clientIds acquire independently', async () => {
    const a = await rotationLock.acquire('acme', 30_000);
    const b = await rotationLock.acquire('globex', 30_000);
    expect(a.acquired).toBe(true);
    expect(b.acquired).toBe(true);
  });

  test('RL-05: acquire throws on missing clientId', async () => {
    await expect(rotationLock.acquire('', 30_000)).rejects.toThrow(TypeError);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RL-06…10  Release semantics
// ═════════════════════════════════════════════════════════════════════════════

describe('Release semantics', () => {
  test('RL-06: release with the correct token removes the lock', async () => {
    const { token } = await rotationLock.acquire('acme', 30_000);
    const released = await rotationLock.release('acme', token);
    expect(released).toBe(true);
  });

  test('RL-07: after release, another instance can acquire the lock', async () => {
    const { token } = await rotationLock.acquire('acme', 30_000);
    await rotationLock.release('acme', token);
    const second = await rotationLock.acquire('acme', 30_000);
    expect(second.acquired).toBe(true);
  });

  test('RL-08: release with a stale/wrong token does NOT remove a lock held by someone else', async () => {
    await rotationLock.acquire('acme', 30_000); // holder A
    const releasedByWrongToken = await rotationLock.release('acme', 'not-the-real-token');
    expect(releasedByWrongToken).toBe(false);
    // The real holder's lock must still be in effect.
    const attempt = await rotationLock.acquire('acme', 30_000);
    expect(attempt.acquired).toBe(false);
  });

  test('RL-09: releasing a lock that was never acquired is a safe no-op', async () => {
    const released = await rotationLock.release('never-acquired', 'some-token');
    expect(released).toBe(false);
  });

  test('RL-10: release with a falsy token returns false without contacting Redis', async () => {
    const released = await rotationLock.release('acme', null);
    expect(released).toBe(false);
    expect(fakeClient.eval).not.toHaveBeenCalled();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RL-11…14  Fail-closed behavior
// ═════════════════════════════════════════════════════════════════════════════

describe('Fail-closed behavior', () => {
  test('RL-11: acquire rejects when Redis client is not ready', async () => {
    fakeClient.isReady = false;
    await expect(rotationLock.acquire('acme', 30_000)).rejects.toThrow(/Redis not connected/);
  });

  test('RL-12: release returns false (never throws) when Redis client is not ready', async () => {
    fakeClient.isReady = false;
    await expect(rotationLock.release('acme', 'tok')).resolves.toBe(false);
  });

  test('RL-13: release catches an EVAL error and reports false rather than throwing', async () => {
    await rotationLock.acquire('acme', 30_000);
    fakeClient.eval.mockRejectedValueOnce(new Error('script error'));
    await expect(rotationLock.release('acme', 'whatever-token')).resolves.toBe(false);
  });

  test('RL-14: isReady() reflects the underlying client readiness', async () => {
    expect(rotationLock.isReady()).toBe(false); // lazy client not yet created
    await rotationLock.acquire('acme', 30_000); // triggers lazy client creation
    expect(rotationLock.isReady()).toBe(true);
    fakeClient.isReady = false;
    expect(rotationLock.isReady()).toBe(false);
  });

  // the real client starts !isReady and connect() was never awaited, so
  // the FIRST acquire() in a process's lifetime always failed closed even
  // with Redis fully reachable (every key-admin rotation 503'd once, then
  // succeeded on retry). These two tests pin the fix from both sides; the
  // pre-existing RL-01 could not catch it because this suite's fake client is
  // born isReady=true, which a real client never is.
  test('RL-17: first acquire after client creation succeeds when Redis is up — the in-flight connect is awaited', async () => {
    fakeClient.isReady = false; // real clients start not-ready
    fakeClient.connect.mockImplementation(async () => { fakeClient.isReady = true; });
    const result = await rotationLock.acquire('acme', 30_000);
    expect(result.acquired).toBe(true);
    expect(fakeClient.connect).toHaveBeenCalled();
  });

  test('RL-18: acquire still fails closed when Redis is genuinely down — a failed connect leaves the client not-ready', async () => {
    fakeClient.isReady = false;
    fakeClient.connect.mockRejectedValue(new Error('ECONNREFUSED'));
    await expect(rotationLock.acquire('acme', 30_000)).rejects.toThrow(/Redis not connected/);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RL-15…16  Key namespacing
// ═════════════════════════════════════════════════════════════════════════════

describe('Key namespacing', () => {
  test('RL-15: buildLockKey namespaces under qodiqa:key-rotation-lock:', () => {
    expect(rotationLock.buildLockKey('acme')).toBe('qodiqa:key-rotation-lock:acme');
  });

  test('RL-16: two different clientIds never collide in the underlying key space', async () => {
    await rotationLock.acquire('acme', 30_000);
    await rotationLock.acquire('globex', 30_000);
    expect(fakeClient._map.has('qodiqa:key-rotation-lock:acme')).toBe(true);
    expect(fakeClient._map.has('qodiqa:key-rotation-lock:globex')).toBe(true);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RL-19…26 Fencing, ownership re-check, renewal and cluster-slot colocation
//
// A lease alone lets a holder that outlives its TTL (pause, slow FS/KMS) commit
// after a second rotator was let in. The real multi-process proof against a real
// Redis is test/distributed/rotationLockFencing.integration.test.js; these pin
// the module contract.
// ═════════════════════════════════════════════════════════════════════════════

describe('Fencing token, ownership re-check and renewal', () => {
  test('RL-19: acquire returns a numeric fencing token', async () => {
    const r = await rotationLock.acquire('acme', 30_000);
    expect(r.acquired).toBe(true);
    expect(Number.isSafeInteger(r.fence)).toBe(true);
    expect(r.fence).toBeGreaterThan(0);
  });

  test('RL-20: fences strictly increase across successive ownership periods of the same client', async () => {
    const fences = [];
    for (let i = 0; i < 5; i++) {
      const r = await rotationLock.acquire('acme', 30_000);
      fences.push(r.fence);
      await rotationLock.release('acme', r.token);
    }
    for (let i = 1; i < fences.length; i++) expect(fences[i]).toBeGreaterThan(fences[i - 1]);
  });

  test('RL-21: the fence counter is seeded from wall-clock ms, so a Redis that lost it restarts ABOVE earlier fences', async () => {
    const before = Date.now();
    const r = await rotationLock.acquire('fresh-client', 30_000);
    expect(r.fence).toBeGreaterThan(before);
    expect(fakeClient._map.get(rotationLock.buildFenceKey('fresh-client'))).toBe(String(r.fence));
  });

  test('RL-22: no fence (and no lock) is issued if ownership was lost between the SET and the fence step', async () => {
    // Model a holder that stalled past its TTL right after SET NX: someone else
    // owns the key by the time the fence script runs.
    const origSet = fakeClient.set.getMockImplementation();
    fakeClient.set.mockImplementationOnce(async (key, value, opts) => {
      const res = await origSet(key, value, opts);
      fakeClient._map.set(key, 'someone-else');
      return res;
    });
    const r = await rotationLock.acquire('acme', 30_000);
    expect(r).toEqual({ acquired: false });
    expect(fakeClient._map.has(rotationLock.buildFenceKey('acme'))).toBe(false);
  });

  test('RL-23: a fence-script failure fails closed and frees the lock', async () => {
    fakeClient.eval.mockRejectedValueOnce(new Error('NOSCRIPT boom'));
    await expect(rotationLock.acquire('acme', 30_000)).rejects.toThrow(/fencing token could not be issued/);
    expect(fakeClient._map.has(rotationLock.buildLockKey('acme'))).toBe(false);
  });

  test('RL-24: assertHeld passes for the holder and throws KEY_ROTATION_LOCK_LOST for a stale token or a short lease', async () => {
    const r = await rotationLock.acquire('acme', 30_000);
    await expect(rotationLock.assertHeld('acme', r.token)).resolves.toBe(30_000);
    await expect(rotationLock.assertHeld('acme', 'stale')).rejects.toMatchObject({ code: 'KEY_ROTATION_LOCK_LOST' });
    await expect(rotationLock.assertHeld('acme', r.token, { minRemainingMs: 60_000 }))
      .rejects.toMatchObject({ code: 'KEY_ROTATION_LOCK_LOST' });
    await rotationLock.release('acme', r.token);
    await expect(rotationLock.assertHeld('acme', r.token)).rejects.toMatchObject({ code: 'KEY_ROTATION_LOCK_LOST' });
    fakeClient.isReady = false;
    await expect(rotationLock.assertHeld('acme', r.token)).rejects.toMatchObject({ code: 'KEY_ROTATION_LOCK_LOST' });
  });

  test('RL-25: renew extends only the caller\'s own lease and never resurrects or steals another holder\'s lock', async () => {
    const r = await rotationLock.acquire('acme', 1_000);
    await expect(rotationLock.renew('acme', r.token, 45_000)).resolves.toBe(true);
    await expect(rotationLock.assertHeld('acme', r.token)).resolves.toBe(45_000);
    await expect(rotationLock.renew('acme', 'not-the-holder', 45_000)).resolves.toBe(false);
    await rotationLock.release('acme', r.token);
    await expect(rotationLock.renew('acme', r.token, 45_000)).resolves.toBe(false);
    expect(fakeClient._map.has(rotationLock.buildLockKey('acme'))).toBe(false);
  });

  test('RL-26: the fence key hashes to the lock key\'s cluster slot (one EVAL touches both; REDIS_MODE=cluster would refuse CROSSSLOT)', () => {
    // Redis Cluster key slot: CRC16-XMODEM of the key (or of its first non-empty {hash tag}) mod 16384.
    const crc16 = (buf) => {
      let crc = 0;
      for (const b of buf) {
        crc ^= b << 8;
        for (let i = 0; i < 8; i++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
      }
      return crc;
    };
    const slot = (key) => {
      const s = key.indexOf('{'); const e = s >= 0 ? key.indexOf('}', s + 1) : -1;
      const tagged = s >= 0 && e > s + 1 ? key.slice(s + 1, e) : key;
      return crc16(Buffer.from(tagged)) % 16384;
    };
    expect(crc16(Buffer.from('123456789'))).toBe(0x31c3); // the reference check value of CRC16-XMODEM
    for (const id of ['acme', 'globex', 'client-A', 'client_B', 'x'.repeat(64)]) {
      const lockKey = rotationLock.buildLockKey(id);
      const fenceKey = rotationLock.buildFenceKey(id);
      expect(fenceKey).not.toBe(lockKey);
      expect(slot(fenceKey)).toBe(slot(lockKey));
    }
  });
});
