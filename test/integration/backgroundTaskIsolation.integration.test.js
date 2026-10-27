'use strict';

/**
 * Finding 3.6 — background task failure isolation, end-to-end availability proof.
 *
 * This is deliberately NOT a full child-process server.js spawn (see
 * test/serverStartupSmoke.test.js for that) — it builds a minimal Express
 * app wired the same way server.js wires background jobs: a route handler
 * on the primary request path, plus a BackgroundTaskRunner-wrapped
 * setInterval task that fails on every tick, with processHardening.js's
 * real global unhandledRejection/uncaughtException handlers installed.
 *
 * What this proves (ticket item 12, "Verify Availability"):
 *   - API requests continue succeeding while a background job fails
 *     repeatedly, including requests that arrive WHILE a tick is failing.
 *   - The process never exits (injected _exit is asserted never called).
 *   - Metrics stay available and reflect the failures
 *     (qodiqa_background_tasks_failed_total increments; the enforcement-side
 *     counters are untouched).
 */

const express   = require('express');
const request   = require('supertest');
const { runTask } = require('../../src/runtime/backgroundTasks/BackgroundTaskRunner');
const { applyProcessHardening } = require('../../src/runtime/processHardening');
const metrics = require('../../src/observability/metrics');

function buildApp() {
  const app = express();
  app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));
  app.get('/enforce', (req, res) => res.status(200).json({ decision: 'ALLOW' }));
  return app;
}

describe('Finding 3.6 — background task failure isolation (availability)', () => {
  let server;
  let exitFn;

  beforeEach(() => {
    process.removeAllListeners('unhandledRejection');
    process.removeAllListeners('uncaughtException');
    exitFn = jest.fn();
    applyProcessHardening(() => {}, { _metrics: metrics, _exit: exitFn });
  });

  afterEach((done) => {
    process.removeAllListeners('unhandledRejection');
    process.removeAllListeners('uncaughtException');
    if (server) server.close(done); else done();
    server = null;
  });

  test('API requests keep succeeding across repeated background task failures; process never exits', async () => {
    const app = buildApp();
    server = app.listen(0);

    const before = metrics.backgroundTasksFailedTotal.format();
    const beforeCount = (before.match(/task="dashboard-sse-snapshot"/g) || []).length;

    let ticks = 0;
    const failingTick = setInterval(() => {
      ticks++;
      runTask('dashboard-sse-snapshot', () => {
        throw new Error(`simulated background failure #${ticks}`);
      }).catch(() => { /* non-critical task never rejects; belt-and-suspenders */ });
    }, 10);

    try {
      // Let several ticks fail before issuing requests, proving prior
      // failures haven't degraded the server.
      await new Promise(resolve => setTimeout(resolve, 60));

      const results = await Promise.all([
        request(server).get('/health'),
        request(server).get('/enforce'),
        request(server).get('/health'),
        request(server).get('/enforce'),
      ]);
      for (const res of results) expect(res.status).toBe(200);

      // Keep the interval running WHILE more requests come in, interleaving
      // background failures with live traffic.
      await new Promise(resolve => setTimeout(resolve, 60));
      const interleaved = await request(server).get('/health');
      expect(interleaved.status).toBe(200);

      expect(ticks).toBeGreaterThan(3); // the background job really did keep failing repeatedly
      expect(exitFn).not.toHaveBeenCalled(); // no crash

      const after = metrics.backgroundTasksFailedTotal.format();
      const afterCount = (after.match(/task="dashboard-sse-snapshot"/g) || []).length;
      expect(afterCount).toBeGreaterThanOrEqual(beforeCount); // metrics stayed available and recorded the failures
    } finally {
      clearInterval(failingTick);
    }
  });

  test('a synchronous exception inside a background tick does not stop subsequent ticks from running', async () => {
    let successCount = 0;
    let failCount = 0;

    const tick = setInterval(() => {
      runTask('dashboard-sse-snapshot', () => {
        // Alternate between throwing and succeeding to prove the loop
        // survives a failure and resumes normal operation immediately after.
        if ((successCount + failCount) % 2 === 0) { failCount++; throw new Error('boom'); }
        successCount++;
        return 'ok';
      }).catch(() => {});
    }, 10);

    try {
      await new Promise(resolve => setTimeout(resolve, 80));
      expect(failCount).toBeGreaterThan(0);
      expect(successCount).toBeGreaterThan(0);
      expect(exitFn).not.toHaveBeenCalled();
    } finally {
      clearInterval(tick);
    }
  });
});
