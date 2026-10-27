'use strict';

// phase 8 — run the real migration chain against QODIQA_PG_DATABASE in a child process (see distributedPg.js).
// Its environment is set explicitly by the parent; nothing here reads .env.

(async () => {
  const pool = require('../../src/infra/postgres/pool');
  pool.initialize();
  try {
    await pool.runMigrations();
    process.stdout.write('MIGRATED\n');
  } finally {
    await pool.shutdown().catch(() => {});
  }
  process.exit(0);
})().catch((e) => { process.stderr.write(`MIGRATE_FAILED: ${e && e.stack || e}\n`); process.exit(1); });
