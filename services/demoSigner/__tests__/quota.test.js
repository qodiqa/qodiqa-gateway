'use strict';

const { createQuota, hashClient, QuotaUnavailableError, QUOTA_LUA } = require('../quota');

// In-memory emulation of exactly what QUOTA_LUA does (check all, then increment all), so the JS wrapper can be
// tested without Redis. The script itself runs against real Redis.
function fakeRedis() {
  const store = new Map();
  const calls = [];
  return {
    store, calls,
    async sendCommand(args) {
      calls.push(args);
      expect(args[0]).toBe('EVAL');
      expect(args[1]).toBe(QUOTA_LUA);
      const keys = args.slice(3, 6);
      const limits = args.slice(6, 9).map(Number);
      for (let i = 0; i < 3; i++) if ((store.get(keys[i]) || 0) >= limits[i]) return [0, i + 1];
      for (const k of keys) store.set(k, (store.get(k) || 0) + 1);
      return [1, 0];
    },
  };
}

describe('demo signer quota (R-02)', () => {
  const T0 = Date.UTC(2026, 9, 14, 12, 0, 30); // 30 s into a minute

  test('per-client minute limit; a refusal consumes no budget', async () => {
    const r = fakeRedis();
    const q = createQuota(r, { perIpPerMin: 2, perIpPerDay: 50, globalPerMin: 30, now: () => T0 });
    expect(await q.check('a')).toEqual({ allowed: true });
    expect(await q.check('a')).toEqual({ allowed: true });
    const refused = await q.check('a');
    expect(refused).toMatchObject({ allowed: false, scope: 'per_client_minute' });
    expect(refused.retryAfterSeconds).toBe(30);
    const globalKey = [...r.store.keys()].find((k) => k.includes(':global:'));
    expect(r.store.get(globalKey)).toBe(2);
    expect(await q.check('b')).toEqual({ allowed: true }); // other clients unaffected
  });

  test('per-client day limit with retry-after to the end of the UTC day', async () => {
    const r = fakeRedis();
    const q = createQuota(r, { perIpPerMin: 10, perIpPerDay: 1, globalPerMin: 30, now: () => T0 });
    await q.check('a');
    const refused = await q.check('a');
    expect(refused).toMatchObject({ allowed: false, scope: 'per_client_day' });
    expect(refused.retryAfterSeconds).toBe(12 * 3600 - 30);
  });

  test('global limit across clients', async () => {
    const r = fakeRedis();
    const q = createQuota(r, { perIpPerMin: 10, perIpPerDay: 50, globalPerMin: 3, now: () => T0 });
    for (const c of ['a', 'b', 'c']) expect((await q.check(c)).allowed).toBe(true);
    expect(await q.check('d')).toMatchObject({ allowed: false, scope: 'global_minute' });
  });

  test('Redis failure is fail-closed (QuotaUnavailableError), never a silent allow', async () => {
    const q = createQuota({ sendCommand: async () => { throw new Error('ECONNREFUSED'); } }, { perIpPerMin: 1, perIpPerDay: 1, globalPerMin: 1 });
    await expect(q.check('a')).rejects.toBeInstanceOf(QuotaUnavailableError);
    const q2 = createQuota({ sendCommand: async () => 'OK' }, { perIpPerMin: 1, perIpPerDay: 1, globalPerMin: 1 });
    await expect(q2.check('a')).rejects.toBeInstanceOf(QuotaUnavailableError);
  });

  test('keys use the client hash only (never a raw IP) and windows roll over', async () => {
    const r = fakeRedis();
    let t = T0;
    const q = createQuota(r, { perIpPerMin: 1, perIpPerDay: 50, globalPerMin: 30, now: () => t });
    const h = hashClient('203.0.113.7', 's'.repeat(32));
    expect(h).toMatch(/^[0-9a-f]{32}$/);
    await q.check(h);
    expect((await q.check(h)).allowed).toBe(false);
    t += 60_000;
    expect((await q.check(h)).allowed).toBe(true);
    expect(r.calls.flat().join(' ')).not.toContain('203.0.113.7');
  });
});
