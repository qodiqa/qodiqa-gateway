'use strict';

// per-artifact revocation against a REAL Redis.
// Two independent clients stand for two gateway replicas sharing Redis.
//
//   ARR-01  a revocation made through replica A is seen by replica B at once; the key has a TTL (<= REVOCATION_TTL_SECONDS)
//   ARR-02  repeating it keeps the first record (NX) and refreshes the TTL
//   ARR-03  the revocation disappears on its own (TTL elapses) — and nothing else of the artifact is stored
//   ARR-04  a replica whose Redis connection is down refuses to answer (the check rejects, it never reports "not revoked")

const crypto = require('crypto');

const REDIS_URL = process.env.REDIS_URL;
const describeOrSkip = REDIS_URL && process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true' ? describe : describe.skip;
jest.setTimeout(60_000);

describeOrSkip('artifact revocation on real Redis', () => {
  const { createClient } = require('redis');
  const ar = require('../../src/core/artifactRevocation');
  let a; let b; let storeA; let storeB;
  const id = () => crypto.randomUUID();

  beforeAll(async () => {
    a = createClient({ url: REDIS_URL }); b = createClient({ url: REDIS_URL });
    a.on('error', () => {}); b.on('error', () => {});
    await Promise.all([a.connect(), b.connect()]);
    storeA = ar.createRedisStore(a); storeB = ar.createRedisStore(b);
  });
  afterAll(async () => { await Promise.all([a.quit(), b.quit()].map((p) => p.catch(() => {}))); });

  test('ARR-01 revoked on A, seen on B immediately, with a bounded TTL', async () => {
    const rid = id();
    expect(await ar.isRevoked(rid, { _store: storeB })).toBeNull();
    const out = await ar.revoke({ requestId: rid, operatorId: 'op-alice', reason: 'leaked' }, { _store: storeA });
    expect(out.created).toBe(true);
    const seen = await ar.isRevoked(rid, { _store: storeB });
    expect(seen).toMatchObject({ requestId: rid, operatorId: 'op-alice', reason: 'leaked' });
    const ttl = await a.ttl(`${ar.KEY_PREFIX}${rid}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(ar.REVOCATION_TTL_SECONDS);
  });

  test('ARR-02 a repeated revocation keeps the first record and refreshes the TTL', async () => {
    const rid = id();
    await ar.revoke({ requestId: rid, operatorId: 'op-alice', reason: 'first' }, { _store: storeA });
    await a.expire(`${ar.KEY_PREFIX}${rid}`, 5);
    const again = await ar.revoke({ requestId: rid, operatorId: 'op-bob', reason: 'second' }, { _store: storeB });
    expect(again.created).toBe(false);
    expect(again.record.operatorId).toBe('op-alice');
    expect((await ar.isRevoked(rid, { _store: storeA })).operatorId).toBe('op-alice');
    expect(await a.ttl(`${ar.KEY_PREFIX}${rid}`)).toBeGreaterThan(5);
  });

  test('ARR-03 the revocation expires on its own, and the keyspace holds only the artifact id', async () => {
    const rid = id();
    await ar.revoke({ requestId: rid, operatorId: 'op-alice', reason: 'r' }, { _store: storeA });
    await a.pExpire(`${ar.KEY_PREFIX}${rid}`, 300);
    await new Promise((r) => setTimeout(r, 500));
    expect(await ar.isRevoked(rid, { _store: storeB })).toBeNull();
    expect(await a.keys(`${ar.KEY_PREFIX}${rid}*`)).toEqual([]);
  });

  test('ARR-04 a replica whose connection is down refuses: the check rejects instead of answering "not revoked"', async () => {
    const down = createClient({ url: 'redis://127.0.0.1:1', socket: { reconnectStrategy: false } });
    down.on('error', () => {});
    const store = ar.createRedisStore(down);               // never connected: isReady is false
    await expect(ar.isRevoked(id(), { _store: store })).rejects.toThrow(/not connected/);
    await expect(ar.revoke({ requestId: id(), operatorId: 'op', reason: 'r' }, { _store: store })).rejects.toMatchObject({ code: 'REVOCATION_STORE_UNAVAILABLE' });
  });
});
