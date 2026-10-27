'use strict';

/**
 * phase 8 — one "server instance" process for test/distributed/redisReplayIdempotencyTwoProcess.*: the REAL
 * src/validation/nonceStore.js (replay protection) and src/core/idempotency/idempotencyStore.js, each with its own
 * Redis client, against the Redis named by REDIS_URL (explicit env from the parent; never .env, never a default port).
 * Driven over IPC (test/helpers/ipcWorker.js). Every reply is { id, ok, ... } or { id, ok:false, error }.
 */

const nonceStore = require('../../../src/validation/nonceStore');
const idem = require('../../../src/core/idempotency/idempotencyStore');

const sleepUntil = (t) => new Promise((r) => setTimeout(r, Math.max(0, t - Date.now())));

const handlers = {
  async init() {
    await nonceStore.initialize();
    await idem.initialize();
    return { pid: process.pid };
  },
  // `ids` registered concurrently from inside this process (Promise.all) — the parent races two processes doing this.
  // `startAt` (epoch ms) is a start barrier shared by the racing processes, so their bursts genuinely overlap.
  // `sequential` awaits each registration before the next (one request = one round trip, as a server handles it), so
  // two processes walking the same ids contend key by key instead of one pipelined burst landing before the other.
  async registerMany({ ids, tenantId, ttlMs, startAt, sequential }) {
    if (startAt) await sleepUntil(startAt);
    const expiry = Date.now() + (ttlMs || 60_000);
    const one = (r) => nonceStore.register(r, expiry, tenantId).then((x) => x.registered);
    let res;
    if (sequential) { res = []; for (const r of ids) res.push(await one(r)); } else res = await Promise.all(ids.map(one));
    return { won: ids.filter((_, i) => res[i]) };
  },
  async isRegistered({ requestId, tenantId }) {
    return { registered: await nonceStore.isRegistered(requestId, tenantId) };
  },
  async reserveMany({ keys, tenantId, fingerprint, startAt, sequential }) {
    if (startAt) await sleepUntil(startAt);
    const one = (k) => idem.reserve(tenantId, k, fingerprint, 60_000);
    let res;
    if (sequential) { res = []; for (const k of keys) res.push(await one(k)); } else res = await Promise.all(keys.map(one));
    return { results: res.map((r, i) => ({ key: keys[i], reserved: r.reserved, existing: r.existing || null })) };
  },
  async complete({ key, tenantId, record }) {
    return await idem.complete(tenantId, key, record, 60_000);
  },
  async get({ key, tenantId }) {
    return { record: await idem.get(tenantId, key) };
  },
};

process.on('message', async (msg) => {
  const { id, cmd, args = {} } = msg || {};
  if (cmd === 'exit') {
    await Promise.allSettled([nonceStore.disconnect(), idem.disconnect()]);
    process.exit(0);
  }
  const h = handlers[cmd];
  if (!h) { process.send({ id, ok: false, error: `unknown ${cmd}` }); return; }
  try {
    process.send({ id, ok: true, ...(await h(args)) });
  } catch (err) {
    process.send({ id, ok: false, code: err.code || null, error: err.message });
  }
});

process.send({ id: 'boot', ok: true, pid: process.pid });
