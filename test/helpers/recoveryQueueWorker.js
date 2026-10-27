'use strict';

/**
 * phase 8 — one persistence-recovery WORKER process for test/distributed/recoveryQueueTwoProcess.*.
 * Drives the REAL src/core/persistenceRecovery/queue.js (claimNext = UPDATE … WHERE operation_id = (SELECT … FOR UPDATE
 * SKIP LOCKED), 30 s claim lease; markComplete = DELETE) against the disposable PostgreSQL in its environment.
 */

const pgPool = require('../../src/infra/postgres/pool');
pgPool.initialize();
const queue = require('../../src/core/persistenceRecovery/queue');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

process.on('message', async (msg) => {
  const { id, cmd, args = {} } = msg || {};
  try {
    if (cmd === 'exit') { await pgPool.shutdown().catch(() => {}); process.exit(0); }
    if (cmd === 'enqueueMany') {
      for (const operationId of args.ids) {
        await queue.enqueue({ operationId, operationType: 'ATTESTATION_SAVE', service: 'attestation', payload: { attestationId: operationId } });
      }
      process.send({ id, ok: true, n: args.ids.length });
      return;
    }
    if (cmd === 'claimOne') { const op = await queue.claimNext(); process.send({ id, ok: true, operationId: op ? op.operationId : null }); return; }
    if (cmd === 'claimLoop') {
      // Claim until the queue yields nothing `idleRounds` times in a row; "process" each item for handlerMs, then complete.
      const claimed = []; let idle = 0;
      while (idle < (args.idleRounds || 3)) {
        const op = await queue.claimNext();
        if (!op) { idle++; await sleep(20); continue; }
        idle = 0;
        claimed.push(op.operationId);
        if (args.handlerMs) await sleep(args.handlerMs);
        await queue.markComplete(op.operationId);
      }
      process.send({ id, ok: true, claimed, pid: process.pid });
      return;
    }
    process.send({ id, ok: false, error: `unknown ${cmd}` });
  } catch (err) {
    process.send({ id, ok: false, error: err.message });
  }
});

process.send({ id: 'boot', ok: true, pid: process.pid });
