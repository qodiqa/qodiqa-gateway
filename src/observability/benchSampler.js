'use strict';

/**
 * closure diagnostic — bench-only time-series sampler.
 *
 * Active ONLY when QODIQA_BENCH_STAGE_TIMING=true (refused in production by bootValidator rule
 * bench.stage_timing) AND QODIQA_BENCH_SAMPLER_PATH names an output file. Every 100 ms it appends one JSON line of
 * in-process counters that pg_stat_activity cannot show: the pg.Pool's own total/idle/waiting counts, the cumulative
 * withTransaction() connect-wait stats, the transparency registrations in flight, the audit group-commit queue,
 * the PG mirror writer depth and the checksum-anchor writer state. Read-only over those modules; never throws into
 * the server; the timer is unref()'d so it never holds the process open.
 */

const fs = require('fs');
const ST = require('./stageTimer');

let _timer = null;

function start() {
  const out = process.env.QODIQA_BENCH_SAMPLER_PATH;
  if (!ST.ON || !out || _timer) return false;
  const stream = fs.createWriteStream(out, { flags: 'a' });
  stream.on('error', () => {});
  const safe = (fn) => { try { return fn(); } catch { return null; } };
  _timer = setInterval(() => {
    const pool = require('../infra/postgres/pool');
    const line = {
      t: Date.now(),
      pool: safe(() => { const s = pool.poolStats(); return { size: s.size, idle: s.idle, waiting: s.waiting }; }),
      acq: safe(() => pool._benchAcquireStats()),
      tr: safe(() => require('../core/transparency/registrar')._benchStats()),
      audit: safe(() => { const a = require('../core/audit/audit-log'); return { ...a.groupCommitStats(), mirrorDepth: a.mirrorWriterDepth() }; }),
      anchor: safe(() => require('../core/audit/checksumAnchor').getBackendStatus()),
    };
    stream.write(JSON.stringify(line) + '\n');
  }, 100);
  _timer.unref();
  return true;
}

module.exports = { start };
