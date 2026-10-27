#!/usr/bin/env node
'use strict';

/**
 * Seeds or repairs audit_chain_head (migration 026) from the current tail
 * of audit_chain in PostgreSQL.
 *
 * Migration 026 seeds audit_chain_head automatically at apply time, from
 * whatever audit_chain already contains at that moment. This script exists
 * for the case where audit_chain rows are backfilled AFTER migration 026
 * has already run — e.g. scripts/migrate-files-to-pg.js migrating a
 * previously file-only deployment's NDJSON history into PostgreSQL before
 * switching that deployment to QODIQA_AUDIT_ORDERING_MODE=distributed.
 * Without this step, audit_chain_head would be left pointing at
 * GENESIS/seq 0 even though audit_chain now has real history, and the first
 * distributed-mode append would compute a prevHash that doesn't chain onto
 * the backfilled data.
 *
 * Idempotent and safe to run any time: always re-derives from audit_chain's
 * actual current tail (by seq), never invents state. Run it as the last
 * step before flipping a deployment to distributed mode:
 *
 *   node scripts/migrate-files-to-pg.js         # backfill audit_chain (existing script)
 *   node src/infra/postgres/migrate.js          # apply migration 026 if not already applied
 *   node scripts/seed-audit-chain-head.js       # this script
 *
 * Usage:
 *   QODIQA_PG_URL=postgres://... node scripts/seed-audit-chain-head.js
 *   QODIQA_PG_URL=postgres://... node scripts/seed-audit-chain-head.js --dry-run
 */

require('dotenv').config();

const { Pool } = require('pg');

const DRY_RUN = process.argv.includes('--dry-run');

// no implicit localhost:5432 / LIVE target.
require('./lib/liveTargetGuard').assertOrExit('seed-audit-chain-head.js');

const pool = new Pool({
  connectionString: process.env.QODIQA_PG_URL,
  host:     process.env.QODIQA_PG_HOST      || 'localhost',
  port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database: process.env.QODIQA_PG_DATABASE   || 'qodiqa',
  user:     process.env.QODIQA_PG_MIG_USER    || 'qodiqa_mig',
  password: process.env.QODIQA_PG_MIG_PASSWORD || process.env.QODIQA_PG_PASSWORD,
  ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
});

function log(level, msg, data = {}) {
  const prefix = { INFO: '✓', WARN: '⚠', ERROR: '✗' }[level] ?? '·';
  const extra  = Object.keys(data).length ? `  ${JSON.stringify(data)}` : '';
  console.log(`${prefix} ${msg}${extra}`);
}

async function main() {
  const client = await pool.connect();
  try {
    // Same pre-flight integrity check migration 026 runs before adding its
    // UNIQUE(prev_hash) index — repeated here because this script can run
    // long after that migration (e.g. immediately after a fresh backfill
    // whose source data might itself be corrupt).
    const dupes = await client.query(`
      SELECT count(*) AS n FROM (
        SELECT prev_hash FROM audit_chain GROUP BY prev_hash HAVING count(*) > 1
      ) forked
    `);
    const dupeCount = Number(dupes.rows[0].n);
    if (dupeCount > 0) {
      log('ERROR', `AUDIT_CHAIN_INTEGRITY_VIOLATION: ${dupeCount} duplicate prev_hash value(s) in audit_chain — refusing to seed audit_chain_head. Investigate before retrying.`);
      process.exitCode = 1;
      return;
    }

    const tail = await client.query(
      `SELECT hash, seq, schema_version FROM audit_chain ORDER BY seq DESC LIMIT 1`
    );
    const tailHash = tail.rows[0]?.hash ?? 'GENESIS';
    const tailSeq  = tail.rows[0]?.seq  ?? 0;
    const tailSchemaVersion = Number(tail.rows[0]?.schema_version ?? 0);    // the head carries the tail entry's schema version

    log('INFO', DRY_RUN ? 'DRY RUN — no writes will occur' : 'Seeding audit_chain_head', {
      tailHash, tailSeq: Number(tailSeq),
    });

    if (!DRY_RUN) {
      await client.query(`
        INSERT INTO audit_chain_head (id, tail_hash, tail_seq, tail_schema_version)
        VALUES (TRUE, $1, $2, $3)
        ON CONFLICT (id) DO UPDATE SET tail_hash = EXCLUDED.tail_hash, tail_seq = EXCLUDED.tail_seq, tail_schema_version = EXCLUDED.tail_schema_version
      `, [tailHash, tailSeq, tailSchemaVersion]);
    }

    log('INFO', 'audit_chain_head seeded');
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(e => {
  log('ERROR', `Seeding FAILED: ${e.message}`);
  console.error(e.stack);
  process.exit(1);
});
