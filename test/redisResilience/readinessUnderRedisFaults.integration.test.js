'use strict';

/**
 * — does READINESS reflect the
 * state of Redis, end to end, under real faults?
 *
 * The suite (test/integration/ind03RedisPartition.integration.test.js) proves the managed client itself fails closed and
 * recovers. This suite proves what an operator and a load balancer SEE: the four Redis-backed readiness components
 * (nonceStore, anomalyStore, rateLimitStore, consentSubscriber) are started exactly as server startup starts them,
 * against a REAL Redis reached through a TCP proxy this test owns, and GET /ready, GET /health/redis and the
 * qodiqa_redis_connection_state_code gauge are read through the real routers while the proxy injects:
 *
 *   RR-01 baseline                    /ready 200, every component true, gauge 3, /health/redis healthy
 *   RR-02 outage (connection refused) /ready 503 with the Redis components false, replay check fails closed,
 *                                     gauge < 3; dependency back → /ready 200, gauge 3, replay check works
 *   RR-03 silent partition (no RST)   watchdog detects it → /ready 503; /ready never flaps back to 200 while the
 *                                     partition lasts (several recovery cycles); heal → /ready 200
 *   RR-04 timeout (replies slower than the command deadline) commands fail closed with
 *                                     REDIS_COMMAND_DEADLINE_EXCEEDED, /ready 503; latency back to normal → 200
 *   RR-05 reconnect (every socket reset once, dependency stays up) /ready returns to 200, the replay check works
 *   RR-06 partition healed WITHOUT the stuck flows ever being released or reset (a middlebox that silently dropped
 *                                     them) — recovery must still complete on its own
 *
 * SAFETY: Redis 6379 hosts LIVE data on this machine and is never used — the target comes from REDIS_URL only, and a
 * 6379 or absent REDIS_URL is treated as "no disposable Redis". Run through
 * bash npx jest test/redisResilience
 * (qodiqa-er-redis, 127.0.0.1:56510). Keys are namespaced by the stores' own prefixes; the suite writes nonces only.
 */

const net = require('net');
const http = require('http');
const express = require('express');
const crypto = require('crypto');
const { probeRedisReachable } = require('../../scripts/lib/redisProbe');

jest.setTimeout(90_000);

const DEADLINE = 400; const WATCHDOG = 250; const THRESHOLD = 2;

function target() {
  const raw = process.env.REDIS_URL;
  if (!raw) return null;
  const u = new URL(raw);
  const port = parseInt(u.port || '6379', 10);
  if (port === 6379) return null; // LIVE — never
  return { host: u.hostname === 'localhost' ? '127.0.0.1' : u.hostname, port, url: `redis://${u.hostname}:${port}` };
}
const TARGET = target();

// pass | refuse | blackhole (accept, hold every byte) | slow (forward after delayMs)
function proxy(t) {
  let mode = 'pass'; let delayMs = 0;
  const pairs = new Set();
  const srv = net.createServer((c) => {
    if (mode === 'refuse') { c.destroy(); return; }
    const u = net.connect(t.port, t.host);
    const pair = { c, u, held: [] };
    pairs.add(pair);
    const fwd = (from, to) => from.on('data', (d) => {
      if (mode === 'blackhole') { pair.held.push([to, d]); return; }
      if (mode === 'slow') { setTimeout(() => { if (!to.destroyed) to.write(d); }, delayMs); return; }
      if (!to.destroyed) to.write(d);
    });
    fwd(c, u); fwd(u, c);
    const kill = () => { pairs.delete(pair); c.destroy(); u.destroy(); };
    c.on('error', kill); u.on('error', kill); c.on('close', kill); u.on('close', kill);
  });
  return new Promise((res) => srv.listen(0, '127.0.0.1', () => res({
    port: srv.address().port,
    set(m, opts = {}) {
      mode = m; delayMs = opts.delayMs || 0;
      if (m === 'refuse') for (const p of pairs) { p.c.destroy(); p.u.destroy(); }
    },
    resetAll() { for (const p of pairs) { p.c.destroy(); p.u.destroy(); } },
    healResume() { mode = 'pass'; for (const p of pairs) { for (const [to, d] of p.held) if (!to.destroyed) to.write(d); p.held = []; } },
    healReset() { for (const p of pairs) { p.c.destroy(); p.u.destroy(); } mode = 'pass'; },
    // forward NEW traffic again but never release (or reset) what was held: the old flows stay silently stuck
    healDropHeld() { mode = 'pass'; for (const p of pairs) p.held = []; },
    flows: () => pairs.size,
    close: () => new Promise((r) => { for (const p of pairs) { p.c.destroy(); p.u.destroy(); } srv.close(() => r()); }),
  })));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms, step = 50) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (await fn()) return Date.now() - t0; await sleep(step); }
  return -1;
}

function get(server, p) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: server.address().port, path: p }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(b) }));
    }).on('error', reject);
  });
}

const REDIS_COMPONENTS = ['nonceStore', 'anomalyStore', 'rateLimitStore', 'consentSubscriber'];
const PURPOSES = ['nonce', 'anomaly', 'rateLimitPolicy', 'revocationSubscriber'];

let reachable = false;
beforeAll(async () => { reachable = TARGET ? await probeRedisReachable(TARGET.url) : false; });

describe('readiness and health reflect real Redis faults (disposable Redis through an owned TCP proxy)', () => {
  let px; let server; let m; const saved = {};
  let created = []; // every managed Redis client the stores create in this test (teardown sweep, RD-3)

  beforeEach(async () => {
    if (!reachable) return;
    for (const k of ['REDIS_URL', 'REDIS_COMMAND_DEADLINE_MS', 'REDIS_WATCHDOG_INTERVAL_MS', 'REDIS_STALL_THRESHOLD', 'REDIS_HA_MODE', 'REDIS_MODE', 'QODIQA_PG_ENABLED']) saved[k] = process.env[k];
    px = await proxy(TARGET);
    Object.assign(process.env, {
      REDIS_URL: `redis://127.0.0.1:${px.port}`, REDIS_COMMAND_DEADLINE_MS: String(DEADLINE),
      REDIS_WATCHDOG_INTERVAL_MS: String(WATCHDOG), REDIS_STALL_THRESHOLD: String(THRESHOLD), QODIQA_PG_ENABLED: 'false',
    });
    delete process.env.REDIS_HA_MODE; delete process.env.REDIS_MODE;
    jest.resetModules();
    // Record every managed client (wrapped BEFORE the stores are required, so their destructured import is the wrapper).
    created = [];
    const mc = require('../../src/infra/redis/managedClient');
    const origCreate = mc.createManagedRedisClient;
    mc.createManagedRedisClient = (opts) => { const c = origCreate(opts); created.push({ purpose: opts.purpose, c }); return c; };
    m = {
      nonce: require('../../src/validation/nonceStore'),
      anomaly: require('../../src/validation/anomalyStore'),
      rl: require('../../services/policy/store'),
      sub: require('../../src/core/consent/revocation/RevocationSubscriber'),
      state: require('../../src/runtime/readinessState'),
      metrics: require('../../src/observability/metrics'),
    };
    await Promise.all([m.nonce.initialize(), m.anomaly.initialize(), m.rl.initialize(), m.sub.start()]);
    m.state.setReady(true);
    const app = express();
    app.use('/ready', require('../../src/api/routes/ready'));
    app.use('/health/redis', require('../../src/api/routes/healthRedis'));
    await new Promise((r) => { server = app.listen(0, '127.0.0.1', r); });
    expect(await until(async () => (await get(server, '/ready')).status === 200, 10_000)).toBeGreaterThanOrEqual(0);
  });

  afterEach(async () => {
    if (!reachable) return;
    try { m.state.setReady(false); } catch { /* */ }
    for (const fn of [() => m.sub.stop(), () => m.nonce.disconnect(), () => m.anomaly.disconnect(), () => m.rl.disconnect()]) {
      try { await fn(); } catch { /* */ }
    }
    // Regression guard: RevocationSubscriber/OrgStatusSubscriber.stop() must ALWAYS disconnect, even when
    // unsubscribe() rejects during an outage. Every managed client must have been closed by its owner; any leftover is
    // closed first (so a regression cannot hang Jest) and then FAILS the test.
    const leaked = created.filter(({ c }) => !c.__facade._closing);
    for (const { c } of leaked) { try { await c.disconnect(); } catch { /* */ } }
    expect(leaked.map((l) => l.purpose)).toEqual([]);
    await new Promise((r) => server.close(() => r()));
    await px.close();
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });

  const REDIS_REQUIRED = process.env.CI === 'true' || process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true';
  const t = (name, fn, ms = 60_000) => test(name, async () => {
    if (!reachable) {
      if (REDIS_REQUIRED) throw new Error('redisResilience requires a DISPOSABLE Redis in REDIS_URL (never 6379): run through a disposable PostgreSQL/Redis environment');
      console.warn('redisResilience: no disposable Redis (REDIS_URL unset or 6379) — skipped locally'); return;
    }
    await fn();
  }, ms);

  const gauge = (purpose) => {
    const line = m.metrics.redisConnectionStateCode.format().split('\n').find((l) => l.includes(`purpose="${purpose}"`));
    return line ? Number(line.split(' ').pop()) : undefined;
  };
  // a real replay-protection write: a fresh UUID nonce with a 60 s TTL (self-expiring)
  const replayCheck = () => m.nonce.register(crypto.randomUUID(), Date.now() + 60_000, 'redis-resilience');

  t('RR-01 baseline: /ready 200, every Redis component true, gauge 3 for every purpose, /health/redis healthy', async () => {
    const r = await get(server, '/ready');
    expect(r.status).toBe(200);
    for (const c of REDIS_COMPONENTS) expect(r.body.components[c]).toBe(true);
    for (const p of PURPOSES) expect(gauge(p)).toBe(3);
    const h = await get(server, '/health/redis');
    expect(h.status).toBe(200);
    expect(h.body.status).toBe('healthy');
    await expect(replayCheck()).resolves.toBeDefined();
  });

  t('RR-02 outage (refused): /ready 503 with the Redis components false, replay check fails closed, gauge < 3; recovery', async () => {
    px.set('refuse');
    const down = await until(async () => (await get(server, '/ready')).status === 503, 5_000);
    expect(down).toBeGreaterThanOrEqual(0);
    const r = await get(server, '/ready');
    expect(REDIS_COMPONENTS.filter((c) => r.body.components[c] === true)).toEqual([]);
    await expect(replayCheck()).rejects.toBeDefined();
    expect(await until(() => PURPOSES.every((p) => gauge(p) < 3), 5_000)).toBeGreaterThanOrEqual(0);
    const h = await get(server, '/health/redis');
    expect(h.body.status).not.toBe('healthy');

    px.set('pass');
    const up = await until(async () => (await get(server, '/ready')).status === 200, 20_000, 100);
    expect(up).toBeGreaterThanOrEqual(0);
    expect(await until(() => PURPOSES.every((p) => gauge(p) === 3), 5_000)).toBeGreaterThanOrEqual(0);
    await expect(replayCheck()).resolves.toBeDefined();
    expect((await get(server, '/health/redis')).body.status).toBe('healthy');
  });

  t('RR-03 silent partition: detected without traffic, /ready never flaps to 200 while it lasts, recovery after heal', async () => {
    px.set('blackhole');
    const detected = await until(async () => (await get(server, '/ready')).status === 503, 8_000);
    expect(detected).toBeGreaterThanOrEqual(0);
    // hold the partition through several recovery cycles and sample readiness every 100 ms
    const samples = []; const t0 = Date.now();
    while (Date.now() - t0 < 8_000) { const r = await get(server, '/ready'); samples.push(r.status); await sleep(100); }
    expect(samples.filter((s) => s === 200)).toEqual([]);
    expect(PURPOSES.filter((p) => gauge(p) === 3)).toEqual([]);
    await expect(replayCheck()).rejects.toBeDefined();
    px.healReset();
    expect(await until(async () => (await get(server, '/ready')).status === 200, 20_000, 100)).toBeGreaterThanOrEqual(0);
    await expect(replayCheck()).resolves.toBeDefined();
  });

  t('RR-04 timeout (replies slower than the deadline): fail closed with REDIS_COMMAND_DEADLINE_EXCEEDED, /ready 503, recovery', async () => {
    px.set('slow', { delayMs: DEADLINE * 3 });
    await expect(replayCheck()).rejects.toMatchObject({ code: 'REDIS_COMMAND_DEADLINE_EXCEEDED' });
    expect(await until(async () => (await get(server, '/ready')).status === 503, 8_000)).toBeGreaterThanOrEqual(0);
    px.set('pass');
    expect(await until(async () => (await get(server, '/ready')).status === 200, 20_000, 100)).toBeGreaterThanOrEqual(0);
    await expect(replayCheck()).resolves.toBeDefined();
  });

  t('RR-05 reconnect: every socket reset once while Redis stays up → /ready back to 200, replay check works', async () => {
    px.resetAll();
    expect(await until(async () => (await get(server, '/ready')).status === 200 && PURPOSES.every((p) => gauge(p) === 3), 15_000, 100)).toBeGreaterThanOrEqual(0);
    await expect(replayCheck()).resolves.toBeDefined();
  });

  t('RR-06 partition healed while the stuck flows are silently dropped (never released, never reset) → recovery still completes', async () => {
    px.set('blackhole');
    expect(await until(async () => (await get(server, '/ready')).status === 503, 8_000)).toBeGreaterThanOrEqual(0);
    await sleep(3_000); // let recovery attempts open fresh connections INTO the partition
    px.healDropHeld();
    const up = await until(async () => (await get(server, '/ready')).status === 200, 30_000, 100);
    expect(up).toBeGreaterThanOrEqual(0);
    await expect(replayCheck()).resolves.toBeDefined();
  }, 60_000);
});
