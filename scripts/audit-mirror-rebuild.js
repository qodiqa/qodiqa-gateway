#!/usr/bin/env node
'use strict';

/**
 * audit-mirror-rebuild — re-sequence a single-node PG audit mirror so seq order
 * equals hash-chain order.
 *
 * WHY: the single-node mirror write was fired per entry without
 * awaiting or serialization, so concurrent INSERTs drew seq = nextval() out of
 * chain order (auditor: 7 link breaks per 500 concurrent real appends), and
 * recovery replays landed later still. every mirror INSERT is
 * parent-guarded (pg-audit-backend.js insertMirrorRow), so NEW rows can never
 * be inverted — but a mirror written keeps its historical
 * inversions. Reads follow hash links now (loadChainFromPg, ChainVerifier),
 * yet seq-positional consumers (distributed-mode lookups by seq, the
 * verifier's resumable watermark) still need seq == chain order before a
 * deployment switches to QODIQA_AUDIT_ORDERING_MODE=distributed.
 *
 * WHAT IT DOES (and does not):
 *   --check (default, READ-ONLY) — distributed-readiness check for the mirror:
 *     every row forms ONE linear chain from 'GENESIS', count of seq
 *     inversions, and (if audit_chain_head exists) whether its tail matches
 *     the link-defined tail. Exit 0 only when ready (0 inversions, head OK).
 *   --apply --confirm-database <name> — in ONE transaction, under
 *     LOCK TABLE audit_chain IN ACCESS EXCLUSIVE MODE, re-derives the link
 *     order and reassigns the EXISTING set of seq values in link order (the
 *     set, min and max are unchanged, so the BIGSERIAL sequence needs no
 *     reset), then sets audit_chain_head (if present) to the true tail.
 *     Only the `seq` column changes: hash, prev_hash, canonical and every
 *     hash-protected field are untouched (seq is ordering metadata, not part
 *     of any hash). Refuses unless the rows form one linear chain from
 *     GENESIS, and refuses unless --confirm-database equals the connected
 *     database (no accidental target).
 *
 * CONNECTION: audit_chain has FORCE ROW LEVEL SECURITY, which binds even the
 * table owner, so this needs a BYPASSRLS (or superuser) role. Credentials come
 * from QODIQA_PG_ADMIN_USER/QODIQA_PG_ADMIN_PASSWORD (falling back to
 * QODIQA_PG_TEST_USER/QODIQA_PG_TEST_PASSWORD for local development) and are
 * never printed. Host/port/database from QODIQA_PG_HOST/_PORT/_DATABASE or
 * --database.
 *
 * Usage:
 *   node scripts/audit-mirror-rebuild.js [--database <db>]                     # check
 *   node scripts/audit-mirror-rebuild.js --database <db> --apply --confirm-database <db>
 */

const { orderByHashLinks } = require('../src/utils/hashLinkOrder');

async function _loadRows(client) {
  const res = await client.query('SELECT seq, hash, prev_hash FROM audit_chain ORDER BY seq ASC');
  return res.rows.map((r) => ({ seq: Number(r.seq), hash: String(r.hash).trim(), prevHash: String(r.prev_hash).trim() }));
}

async function _headRow(client) {
  const exists = await client.query("SELECT to_regclass('public.audit_chain_head') IS NOT NULL AS e");
  if (!exists.rows[0].e) return null;
  const r = await client.query('SELECT tail_hash, tail_seq FROM audit_chain_head LIMIT 1');
  return r.rows[0] ? { tailHash: String(r.rows[0].tail_hash).trim(), tailSeq: Number(r.rows[0].tail_seq) } : null;
}

function _analyse(rows) {
  const linked = orderByHashLinks(rows);
  if (!linked.linked) return { linear: false, rows: rows.length };
  const ordered = linked.rows;
  let inversions = 0;       // rows whose parent has a HIGHER seq than they do
  const seqOf = new Map(ordered.map((r) => [r.hash, r.seq]));
  for (const r of ordered) if (r.prevHash !== 'GENESIS' && seqOf.get(r.prevHash) > r.seq) inversions++;
  let seqBreaks = 0;        // adjacent pairs in seq order whose link does not hold
  for (let i = 1; i < rows.length; i++) if (rows[i].prevHash !== rows[i - 1].hash) seqBreaks++;
  if (rows.length > 0 && rows[0].prevHash !== 'GENESIS') seqBreaks++;
  const tail = ordered.length ? ordered[ordered.length - 1] : null;
  return { linear: true, rows: rows.length, ordered, inversions, seqBreaks, reordered: linked.reordered, tail };
}

/**
 * @param {import('pg').Client} client  connected, BYPASSRLS/superuser
 * @param {{ apply?: boolean }} opts
 */
async function rebuild(client, { apply = false } = {}) {
  const role = await client.query('SELECT current_user AS u, current_database() AS db, (SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user) AS ok');
  const { db, ok } = role.rows[0];
  if (!ok) throw Object.assign(new Error('REBUILD_ROLE_NOT_BYPASSRLS: audit_chain has FORCE ROW LEVEL SECURITY; connect with a BYPASSRLS or superuser role'), { code: 'REBUILD_ROLE_NOT_BYPASSRLS' });

  const before = _analyse(await _loadRows(client));
  const head = await _headRow(client);
  const report = {
    database: db,
    rows: before.rows,
    linearChainFromGenesis: before.linear,
    inversions: before.linear ? before.inversions : null,
    seqBreaks: before.linear ? before.seqBreaks : null,
    headTable: head ? { tailHash: head.tailHash, tailSeq: head.tailSeq, matchesLinkTail: !!before.tail && head.tailHash === before.tail.hash } : null,
    applied: false,
  };
  report.readyForDistributed = before.linear && before.inversions === 0 && before.seqBreaks === 0 && (!head || report.headTable.matchesLinkTail || before.rows === 0);
  if (!apply) return report;

  if (!before.linear) throw Object.assign(new Error('REBUILD_REFUSED_NOT_LINEAR: rows do not form one linear chain from GENESIS — this tool re-sequences only; investigate orphans/forks first'), { code: 'REBUILD_REFUSED_NOT_LINEAR' });

  await client.query('BEGIN');
  try {
    // DB-05 (migration 076): audit_chain refuses UPDATE unless the transaction declares this maintenance intent.
    await client.query("SET LOCAL qodiqa.audit_maintenance = 'rebuild'");
    await client.query('LOCK TABLE audit_chain IN ACCESS EXCLUSIVE MODE');
    const locked = _analyse(await _loadRows(client)); // re-derive under the lock
    if (!locked.linear) throw Object.assign(new Error('REBUILD_REFUSED_NOT_LINEAR (under lock)'), { code: 'REBUILD_REFUSED_NOT_LINEAR' });
    const seqs = locked.ordered.map((r) => r.seq).sort((a, b) => a - b);
    const changes = [];
    locked.ordered.forEach((r, i) => { if (r.seq !== seqs[i]) changes.push([r.hash, seqs[i]]); });
    for (let i = 0; i < changes.length; i += 1000) {
      const chunk = changes.slice(i, i + 1000);
      const params = []; const values = [];
      chunk.forEach(([hash, seq], j) => { values.push(`($${2 * j + 1}::char(64), $${2 * j + 2}::bigint)`); params.push(hash, seq); });
      await client.query(`UPDATE audit_chain a SET seq = v.seq FROM (VALUES ${values.join(',')}) AS v(hash, seq) WHERE a.hash = v.hash`, params);
    }
    if (head && locked.tail) {
      // (migration 098): the head also carries the schema version of the tail entry (a database not yet at 098 has no column)
      const hasVersion = (await client.query("SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_chain_head' AND column_name = 'tail_schema_version'")).rows.length > 0;
      if (hasVersion) {
        const v = await client.query('SELECT schema_version FROM audit_chain WHERE hash = $1 LIMIT 1', [locked.tail.hash]);
        await client.query('UPDATE audit_chain_head SET tail_hash = $1, tail_seq = $2, tail_schema_version = $3', [locked.tail.hash, seqs[seqs.length - 1], Number(v.rows[0] ? v.rows[0].schema_version : 0)]);
      } else {
        await client.query('UPDATE audit_chain_head SET tail_hash = $1, tail_seq = $2', [locked.tail.hash, seqs[seqs.length - 1]]);
      }
    }
    await client.query('COMMIT');
    report.applied = true;
    report.rowsResequenced = changes.length;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  }

  const after = _analyse(await _loadRows(client));
  const headAfter = await _headRow(client);
  report.after = {
    inversions: after.inversions, seqBreaks: after.seqBreaks,
    headMatchesLinkTail: headAfter ? (!!after.tail && headAfter.tailHash === after.tail.hash) : null,
  };
  report.readyForDistributed = after.linear && after.inversions === 0 && after.seqBreaks === 0 && (!headAfter || report.after.headMatchesLinkTail);
  return report;
}

module.exports = { rebuild, _analyse };

if (require.main === module) {
  require('dotenv').config();
  const { Client } = require('pg');
  const args = process.argv.slice(2);
  const opt = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
  const database = opt('--database') || process.env.QODIQA_PG_DATABASE || 'qodiqa';
  const apply = args.includes('--apply');
  if (apply && opt('--confirm-database') !== database) {
    console.error(`refusing --apply: pass --confirm-database ${database} (must equal the target database)`);
    process.exit(2);
  }
  require('./lib/liveTargetGuard').assertOrExit('audit-mirror-rebuild.js'); // audit 2026-10-20 (3.4)
  const client = new Client({
    host: process.env.QODIQA_PG_HOST || 'localhost',
    port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database,
    user: process.env.QODIQA_PG_ADMIN_USER || process.env.QODIQA_PG_TEST_USER,
    password: process.env.QODIQA_PG_ADMIN_PASSWORD || process.env.QODIQA_PG_TEST_PASSWORD,
  });
  (async () => {
    await client.connect();
    try {
      const r = await rebuild(client, { apply });
      console.log(JSON.stringify(r, null, 2));
      process.exit(r.readyForDistributed ? 0 : 1);
    } finally { await client.end(); }
  })().catch((e) => { console.error(e.message); process.exit(3); });
}
