'use strict';

// the budget counters' Lua scripts (weighted atomic charge, signed adjustment) against a REAL Redis.
//   BR-01  charge admits up to the maximum, refuses the overshoot without changing the counter, sets the TTL on the first write
//   BR-02  adjust refunds / corrects, never below zero, and gives a key without TTL one
//   BR-03  50 parallel clients (two connections): exactly max/amount charges win

const crypto = require('crypto');

const REDIS_URL = process.env.REDIS_URL;
const describeOrSkip = REDIS_URL && process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true' ? describe : describe.skip;
jest.setTimeout(60_000);

describeOrSkip('budget counters on real Redis', () => {
  const { createClient } = require('redis');
  const { CHARGE_BY_SCRIPT, ADJUST_SCRIPT } = require('../../services/policy/store')._scripts;
  let a; let b;
  const key = () => `test:budget:${crypto.randomUUID()}`;
  const charge = (c, k, win, amount, max) => c.eval(CHARGE_BY_SCRIPT, { keys: [k], arguments: [String(win), String(amount), String(max)] }).then((r) => ({ allowed: Number(r[0]) === 1, count: Number(r[1]) }));
  const adjust = (c, k, win, delta) => c.eval(ADJUST_SCRIPT, { keys: [k], arguments: [String(win), String(delta)] }).then(Number);

  beforeAll(async () => { a = createClient({ url: REDIS_URL }); b = createClient({ url: REDIS_URL }); a.on('error', () => {}); b.on('error', () => {}); await Promise.all([a.connect(), b.connect()]); });
  afterAll(async () => { await Promise.all([a.quit(), b.quit()].map((p) => p.catch(() => {}))); });

  test('BR-01 admits up to the maximum, refuses the overshoot unchanged, TTL on first write', async () => {
    const k = key();
    expect(await charge(a, k, 60, 400, 1000)).toEqual({ allowed: true, count: 400 });
    expect(await charge(a, k, 60, 600, 1000)).toEqual({ allowed: true, count: 1000 });
    expect(await charge(a, k, 60, 1, 1000)).toEqual({ allowed: false, count: 1000 });
    expect(await a.get(k)).toBe('1000');
    const ttl = await a.ttl(k); expect(ttl).toBeGreaterThan(0); expect(ttl).toBeLessThanOrEqual(60);
    await a.del(k);
  });
  test('BR-02 adjust: refund, correction, floor at zero, TTL for a key without one', async () => {
    const k = key();
    await charge(a, k, 60, 500, 1000);
    expect(await adjust(a, k, 60, -200)).toBe(300); expect(await adjust(a, k, 60, 50)).toBe(350); expect(await adjust(a, k, 60, -9999)).toBe(0);
    expect(await a.ttl(k)).toBeGreaterThan(0);
    const bare = key(); await a.set(bare, '10'); expect(await a.ttl(bare)).toBe(-1);
    expect(await adjust(a, bare, 60, 5)).toBe(15); expect(await a.ttl(bare)).toBeGreaterThan(0);
    await a.del([k, bare]);
  });
  test('BR-03 exactly max/amount of 50 parallel charges win, across two connections', async () => {
    const k = key();
    const results = await Promise.all(Array.from({ length: 50 }, (_, i) => charge(i % 2 ? a : b, k, 60, 10, 200)));
    expect(results.filter((r) => r.allowed)).toHaveLength(20);
    expect(await a.get(k)).toBe('200');
    await a.del(k);
  });
});
