'use strict';

/**
 * phase 8 — one process writing the PostgreSQL checksum anchor (audit_checksum_anchor, migration 036 +
 * migration 062's forward-only trigger) through the REAL src/core/audit/checksumAnchor.saveChecksumPg(), as the app
 * role, for test/distributed/checksumAnchorTwoProcess.*. Logger events of interest are captured so the parent can
 * assert how each refusal was CLASSIFIED (stale-own vs failure), not only that it happened.
 */

const crypto = require('crypto');
const logger = require('../../../services/logger');

const events = [];
const _emit = logger.emit;
// checksumAnchor resolves `require(...logger).emit` at call time, so this wrapper sees its events.
logger.emit = function capture(sev, type, data) {
  if (/^AUDIT_CHECKSUM_ANCHOR_PG_/.test(type)) events.push({ sev, type, error: data && data.error, incomingCount: data && data.incomingCount });
  return _emit.apply(this, arguments);
};

const pgPool = require('../../../src/infra/postgres/pool');
pgPool.initialize();
const anchor = require('../../../src/core/audit/checksumAnchor');

const hash = (by, n) => crypto.createHash('sha256').update(`${by}:entry-${n}`).digest('hex');
const sleepUntil = (t) => new Promise((r) => setTimeout(r, Math.max(0, t - Date.now())));

const handlers = {
  async write({ count, by }) {
    const before = events.length;
    await anchor.saveChecksumPg(count, hash(by, count));
    return { status: anchor.getBackendStatus(), events: events.slice(before) };
  },
  // From `startAt`: fire every count without awaiting in between (the hot append path's fire-and-forget shape; the
  // module's own queue coalesces it), or, with `sequential`, await each write before the next (one write per
  // committed batch), so two processes walking interleaved counts overtake each other write by write.
  // `jitterMs`: a random 0..jitterMs pause after each sequential write, so the lead between two lock-step writers keeps
  // changing hands instead of one staying a constant half-step ahead.
  async burst({ counts, by, startAt, sequential, jitterMs = 0 }) {
    if (startAt) await sleepUntil(startAt);
    const before = events.length;
    let accepted = 0;
    if (sequential) {
      for (const n of counts) {
        await anchor.saveChecksumPg(n, hash(by, n));
        if (anchor.getBackendStatus().pgHighestWrittenCount === n) accepted++;
        if (jitterMs) await new Promise((r) => setTimeout(r, Math.random() * jitterMs));
      }
      return { status: anchor.getBackendStatus(), events: events.slice(before), accepted };
    }
    else await Promise.all(counts.map((n) => anchor.saveChecksumPg(n, hash(by, n))));
    return { status: anchor.getBackendStatus(), events: events.slice(before) };
  },
};

process.on('message', async (msg) => {
  const { id, cmd, args = {} } = msg || {};
  if (cmd === 'exit') { await pgPool.shutdown().catch(() => {}); process.exit(0); }
  const h = handlers[cmd];
  if (!h) { process.send({ id, ok: false, error: `unknown ${cmd}` }); return; }
  try {
    process.send({ id, ok: true, ...(await h(args)) });
  } catch (err) {
    process.send({ id, ok: false, error: err.message });
  }
});

process.send({ id: 'boot', ok: true, pid: process.pid });
