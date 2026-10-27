'use strict';

/**
 * phase 8 — one audit-chain WRITER process for test/distributed/distributedOrderingCrashFailover.*.
 *
 * Drives the REAL src/core/audit/distributedOrdering.appendEntry() (QODIQA_AUDIT_ORDERING_MODE=distributed ordering
 * authority: `SELECT … FROM audit_chain_head FOR UPDATE` → INSERT audit_chain → UPDATE head, one READ COMMITTED
 * transaction) against the disposable PostgreSQL in its environment, step by step over IPC.
 *
 * `appendHolding` arms a one-shot hook on the real pool's withTransaction: the transaction runs the real head lock
 * and the real INSERT, then announces `<id>:holding` and never proceeds to the head UPDATE / COMMIT. The parent then
 * SIGKILLs this process — a writer crashing mid-append while it HOLDS the chain-head row lock with an uncommitted row.
 */

const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder');
const pgPool = require('../../src/infra/postgres/pool');

pgPool.initialize();

let _hold = null; // { id } while armed
const _origWithTransaction = pgPool.withTransaction;
pgPool.withTransaction = function heldWithTransaction(fn, opts) {
  if (!_hold) return _origWithTransaction.call(pgPool, fn, opts);
  const hold = _hold; _hold = null;
  return _origWithTransaction.call(pgPool, async (tx) => fn({
    query: async (sql, params) => {
      const r = await tx.query(sql, params);
      if (/INSERT INTO audit_chain\b/.test(sql)) {
        process.send({ id: `${hold.id}:holding`, ok: true, pid: process.pid });
        await new Promise(() => {}); // never resolves: the transaction stays open, head row locked
      }
      return r;
    },
  }), opts);
};

const { appendEntry } = require('../../src/core/audit/distributedOrdering');

function fields(artifactId, nonce) {
  const h = (s) => crypto.createHash('sha256').update(s).digest('hex');
  return {
    artifactId, inputHash: h(artifactId), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH, signature: 'p8-test-signature',
    requestHash: h(`${artifactId}:req`), policyHash: h('p8-policy'), verificationResult: true,
    ...(nonce ? { nonce } : {}),
  };
}

async function one(artifactId, nonce) {
  try {
    const e = await appendEntry(fields(artifactId, nonce));
    return { ok: true, artifactId, hash: e.hash, prevHash: e.prevHash };
  } catch (err) {
    return { ok: false, artifactId, error: err.message };
  }
}

process.on('message', async (msg) => {
  const { id, cmd, args = {} } = msg || {};
  try {
    if (cmd === 'exit') { await pgPool.shutdown().catch(() => {}); process.exit(0); }
    if (cmd === 'append') { process.send({ id, ...(await one(args.artifactId, args.nonce)) }); return; }
    if (cmd === 'appendMany') {
      const results = [];
      for (let i = 0; i < args.count; i++) results.push(await one(`${args.prefix}-${(args.from || 0) + i}`));
      process.send({ id, ok: true, results });
      return;
    }
    if (cmd === 'verify') {
      // The same verification single-node boot uses, over the chain hydrated from PostgreSQL (ADC-05's path).
      // Requires QODIQA_AUDIT_LOG to point at a scratch path (audit-log.js does WAL/tail recovery at require time).
      const { loadChainFromPg } = require('../../src/infra/postgres/pg-audit-backend');
      const { verifyAuditChainDetailed } = require('../../src/core/audit/audit-log');
      const chain = await loadChainFromPg();
      const d = verifyAuditChainDetailed(chain);
      process.send({ id, ok: true, length: chain.length, valid: d.valid, reason: d.reason, tamperingDetected: d.tamperingDetected });
      return;
    }
    if (cmd === 'appendHolding') { _hold = { id }; const r = await one(args.artifactId); process.send({ id, ...r }); return; }
    process.send({ id, ok: false, error: `unknown ${cmd}` });
  } catch (err) {
    process.send({ id, ok: false, error: err.message });
  }
});

process.send({ id: 'boot', ok: true, pid: process.pid });
