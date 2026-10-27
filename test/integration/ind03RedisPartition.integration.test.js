'use strict';

/**
 * — a silent Redis partition must not hang callers forever,
 * must become observable (isReady false + REDIS_CONNECTION_STALLED), and must recover automatically.
 *
 * Real Redis (the qodiqa-redis container on 6379), reached through a local TCP proxy owned by this
 * test, driving the PRODUCTION managed client (src/infra/redis/managedClient.js, single mode) exactly
 * as nonceStore/rate limiter/lockout create it. Faults (no shared service is ever stopped):
 *   refuse     close every socket + refuse new connections (dependency down)
 *   blackhole  keep sockets open but never forward a byte (silent partition — the audit's case)
 *   heal by RESUMING the same flows, and heal by RESET; delayed responses below the deadline.
 * Keys are namespaced ind03:<hex> and deleted at the end.
 */

const net = require('net');
const crypto = require('crypto');

const DEADLINE = 400; const WATCHDOG = 250; const THRESHOLD = 2;

const REDIS = require('../helpers/redisTarget');

function proxy(targetPort) {
  let mode = 'pass'; let delayMs = 0;
  const pairs = new Set();
  const srv = net.createServer((c) => {
    if (mode === 'refuse') { c.destroy(); return; }
    const u = net.connect(targetPort, REDIS.host);
    const pair = { c, u, held: [] };
    pairs.add(pair);
    const fwd = (from, to) => from.on('data', (d) => {
      if (mode === 'blackhole') { pair.held.push([to, d]); return; }
      if (delayMs) setTimeout(() => { if (!to.destroyed) to.write(d); }, delayMs); else if (!to.destroyed) to.write(d);
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
    healResume() { mode = 'pass'; for (const p of pairs) { for (const [to, d] of p.held) if (!to.destroyed) to.write(d); p.held = []; } },
    healReset() { for (const p of pairs) { p.c.destroy(); p.u.destroy(); } mode = 'pass'; },
    close: () => new Promise((r) => { for (const p of pairs) { p.c.destroy(); p.u.destroy(); } srv.close(() => r()); }),
  })));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms, step = 50) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return Date.now() - t0; await sleep(step); } return -1; }

let reachable = false;
beforeAll(async () => { reachable = await REDIS.reachable(); }); // phase 17: explicit REDIS_URL only, never a default

describe('silent Redis partition, real Redis via an owned TCP proxy', () => {
  let px; let client; let events; const saved = {};
  const NS = `ind03:${crypto.randomBytes(4).toString('hex')}`;

  beforeEach(async () => {
    if (!reachable) return;
    for (const k of ['REDIS_URL', 'REDIS_COMMAND_DEADLINE_MS', 'REDIS_WATCHDOG_INTERVAL_MS', 'REDIS_STALL_THRESHOLD', 'REDIS_HA_MODE']) saved[k] = process.env[k];
    px = await proxy(REDIS.port);
    Object.assign(process.env, { REDIS_URL: `redis://127.0.0.1:${px.port}`, REDIS_COMMAND_DEADLINE_MS: String(DEADLINE),
      REDIS_WATCHDOG_INTERVAL_MS: String(WATCHDOG), REDIS_STALL_THRESHOLD: String(THRESHOLD) });
    delete process.env.REDIS_HA_MODE;
    jest.resetModules();
    events = [];
    jest.doMock('../../services/logger', () => ({ ...jest.requireActual('../../services/logger'), emit: (sev, type, f) => events.push({ sev, type, f }) }));
    const { createManagedRedisClient } = require('../../src/infra/redis/managedClient');
    client = createManagedRedisClient({ purpose: `ind03-${crypto.randomBytes(2).toString('hex')}`, reconnectStrategy: () => 100, connectTimeout: 1000 });
    client.on('error', () => {});
    await client.connect();
    await until(() => client.isReady, 3000);
  });
  afterEach(async () => {
    if (!reachable) return;
    try { await client.disconnect(); } catch { /* */ }
    await px.close();
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    jest.dontMock('../../services/logger');
  });
  afterAll(async () => {
    if (!reachable) return;
    const { createClient } = require('redis');
    const c = createClient({ url: REDIS.url }); c.on('error', () => {}); await c.connect();
    for await (const keys of c.scanIterator({ MATCH: `${NS}:*` })) for (const k of [].concat(keys)) await c.del(k);
    await c.quit();
  });

  // in a gate run (component opt-in or CI) an unreachable Redis is a FAILURE, never a silent pass with zero
  // assertions; only an ad-hoc local run without the opt-in degrades to a warning.
  const REDIS_REQUIRED = process.env.CI === 'true' || process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true';
  // with no Redis target configured and no gate opt-in, report the cases as SKIPPED (visible in
  // the Jest summary) instead of passing with zero assertions. A configured-but-unreachable target still goes through
  // the runtime branch below (warning locally, failure in a gate run).
  const t = (name, fn, ms = 20000) => ((!REDIS.configured && !REDIS_REQUIRED) ? test.skip : test)(name, async () => {
    if (!reachable) {
      if (REDIS_REQUIRED) throw new Error(`suite requires an explicit, reachable REDIS_URL (got ${REDIS.url}; run via a disposable PostgreSQL/Redis environment)`);
      console.warn('No explicit reachable REDIS_URL — skipping'); return;
    }
    await fn();
  }, ms);

  t('baseline: commands work through the proxy', async () => {
    await client.set(`${NS}:a`, '1');
    expect(await client.get(`${NS}:a`)).toBe('1');
  });

  t('blackhole: a command fails CLOSED within the deadline (no hang) with REDIS_COMMAND_DEADLINE_EXCEEDED', async () => {
    px.set('blackhole');
    const t0 = Date.now();
    await expect(client.get(`${NS}:a`)).rejects.toMatchObject({ code: 'REDIS_COMMAND_DEADLINE_EXCEEDED' });
    expect(Date.now() - t0).toBeLessThan(DEADLINE + 600);
  });

  t('blackhole with NO traffic: the watchdog detects the stall → REDIS_CONNECTION_STALLED and isReady false (readiness can see it)', async () => {
    px.set('blackhole');
    const ms = await until(() => client.isReady === false, 8000);
    expect(ms).toBeGreaterThanOrEqual(0);
    expect(events.some((e) => e.type === 'REDIS_CONNECTION_STALLED' && e.f.source === 'watchdog')).toBe(true);
  });

  t('heal by RESUMING the same flows: automatic recovery on a fresh connection, commands work again', async () => {
    px.set('blackhole');
    await until(() => client.isReady === false, 8000);
    px.healResume();
    const ms = await until(() => client.isReady === true, 10000);
    expect(ms).toBeGreaterThanOrEqual(0);
    await client.set(`${NS}:b`, '2');
    expect(await client.get(`${NS}:b`)).toBe('2');
    expect(events.some((e) => e.type === 'REDIS_RECOVERY_COMPLETED')).toBe(true);
  });

  t('heal by RESET: automatic recovery, commands work again', async () => {
    px.set('blackhole');
    await expect(client.get(`${NS}:a`)).rejects.toMatchObject({ code: 'REDIS_COMMAND_DEADLINE_EXCEEDED' });
    px.healReset();
    // A command issued while the reset connection is being re-established fails closed ("Socket
    // closed unexpectedly") — correct. Recovery = the client answers again, automatically.
    const answered = await until(async () => { try { return (await client.ping()) === 'PONG'; } catch { return false; } }, 10000, 100);
    expect(answered).toBeGreaterThanOrEqual(0);
    await client.set(`${NS}:c`, '3');
    expect(await client.get(`${NS}:c`)).toBe('3');
  });

  t('refused (dependency down): commands fail fast, never hang; recovery after the dependency returns', async () => {
    px.set('refuse');
    const t0 = Date.now();
    await expect(client.get(`${NS}:a`)).rejects.toBeDefined();
    expect(Date.now() - t0).toBeLessThan(DEADLINE + 600);
    px.set('pass');
    expect(await until(() => client.isReady === true, 10000)).toBeGreaterThanOrEqual(0);
    expect(await client.set(`${NS}:d`, '4')).toBe('OK');
  });

  t('delayed responses BELOW the deadline are served normally (no false stall)', async () => {
    px.set('pass', { delayMs: DEADLINE / 4 });
    for (let i = 0; i < 5; i++) await client.set(`${NS}:e${i}`, String(i));
    expect(await client.get(`${NS}:e4`)).toBe('4');
    expect(events.some((e) => e.type === 'REDIS_CONNECTION_STALLED')).toBe(false);
    expect(client.isReady).toBe(true);
  });

  t('repeat: blackhole → stall → resume → recovered, three times in a row', async () => {
    for (let i = 0; i < 3; i++) {
      px.set('blackhole');
      expect(await until(() => client.isReady === false, 8000)).toBeGreaterThanOrEqual(0);
      px.healResume();
      expect(await until(() => client.isReady === true, 10000)).toBeGreaterThanOrEqual(0);
      await client.set(`${NS}:r${i}`, 'ok');
    }
  }, 60000);
});
