'use strict';

/**
 * phase 8 — one "rotator" OS process for
 * test/distributed/rotationLockFencing.integration.test.js and the matching evidence experiment.
 *
 * A genuinely separate process (child_process.fork, own JS heap, own Redis client) driving the REAL
 * src/infra/keys/rotationLock.js against the Redis named by REDIS_URL, and committing to a shared scratch
 * "keystore" through test/helpers/fencedKeystoreCommit.js. The parent drives it step by step over IPC so every
 * interleaving is deterministic (no timing races are left to chance except the lease expiry being tested).
 *
 * `freeze` blocks this process's event loop SYNCHRONOUSLY (Atomics.wait) — the portable stand-in for SIGSTOP / a
 * stop-the-world GC pause / a VM steal: while frozen the process can neither renew its lease nor observe that it
 * lost it. (Windows has no SIGSTOP, so the audit's "SIGSTOP the child" design is realised this way.)
 *
 * Every reply is { id, ok, ...result } or { id, ok:false, code, error }.
 */

const lock = require('../../src/infra/keys/rotationLock');
const { fencedCommit } = require('./fencedKeystoreCommit');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const handlers = {
  async acquire({ clientId, ttlMs }) {
    return await lock.acquire(clientId, ttlMs);
  },
  async assertHeld({ clientId, token, minRemainingMs }) {
    return { remaining: await lock.assertHeld(clientId, token, { minRemainingMs: minRemainingMs || 0 }) };
  },
  async commit({ file, clientId, fence, by, enforceFence }) {
    return fencedCommit(file, clientId, fence, by, { enforceFence: enforceFence !== false });
  },
  async release({ clientId, token }) {
    return { released: await lock.release(clientId, token) };
  },
  // A slow-but-alive rotation (e.g. a slow KMS round-trip): the event loop keeps running, and a heartbeat renews
  // the lease every `everyMs` while the "work" takes `durationMs`.
  async slowRotationWithHeartbeat({ clientId, token, ttlMs, everyMs, durationMs }) {
    let renewals = 0; let failedRenewals = 0;
    const hb = setInterval(() => {
      lock.renew(clientId, token, ttlMs).then((ok) => { if (ok) renewals++; else failedRenewals++; });
    }, everyMs);
    try { await sleep(durationMs); } finally { clearInterval(hb); }
    return { renewals, failedRenewals };
  },
};

process.on('message', async (msg) => {
  const { id, cmd, args = {} } = msg || {};
  if (cmd === 'exit') {
    await lock.disconnect().catch(() => {});
    process.exit(0);
  }
  if (cmd === 'freeze') {
    // Acknowledge first (the ack must leave the process before the loop stops), then block synchronously.
    process.send({ id, ok: true, frozenAt: Date.now() }, () => {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, args.ms);
      process.send({ id: `${id}:thawed`, ok: true, thawedAt: Date.now() });
    });
    return;
  }
  const h = handlers[cmd];
  if (!h) { process.send({ id, ok: false, code: 'UNKNOWN_CMD', error: cmd }); return; }
  try {
    process.send({ id, ok: true, ...(await h(args)) });
  } catch (err) {
    process.send({ id, ok: false, code: err.code || null, error: err.message });
  }
});

process.send({ id: 'boot', ok: true, pid: process.pid });
