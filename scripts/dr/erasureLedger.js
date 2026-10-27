#!/usr/bin/env node
'use strict';
/**
 * export the GDPR erasure ledger for off-host
 * retention, so erasures made after the last backup can be replayed by
 * scripts/dr/restore.js (--erasure-ledger <file>).
 *
 *   node scripts/dr/erasureLedger.js export --out <file.jsonl>
 *
 * Reads through qodiqa_erasure_ledger_list as qodiqa_reporting (rolePools); the
 * export holds tenant ids, keyed subject references, run/request ids and
 * timestamps — no subject identifier. Ship it with the WAL archive.
 */
const fs = require('fs');
const path = require('path');

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const out = rest.includes('--out') ? path.resolve(rest[rest.indexOf('--out') + 1]) : null;
  if (cmd !== 'export' || !out) { console.error('usage: erasureLedger.js export --out <file.jsonl>'); process.exit(2); }
  require('dotenv').config({ quiet: true });
  const rolePools = require('../../src/infra/postgres/rolePools');
  const lines = [];
  try {
    for (let after = 0; ;) {
      const r = await rolePools.reporting.query('SELECT * FROM qodiqa_erasure_ledger_list($1, $2)', [after, 1000], 'erasure_ledger_export');
      for (const row of r.rows) lines.push(JSON.stringify(row));
      if (r.rows.length < 1000) break;
      after = Number(r.rows[r.rows.length - 1].id);
    }
  } finally {
    await rolePools.shutdownAll();
  }
  fs.writeFileSync(out, lines.join('\n') + (lines.length ? '\n' : ''));
  console.log(JSON.stringify({ event: 'ERASURE_LEDGER_EXPORTED', rows: lines.length, out }));
}

main().catch((e) => { console.error(`erasureLedger export failed: ${e.code || ''} ${e.message}`); process.exit(1); });
