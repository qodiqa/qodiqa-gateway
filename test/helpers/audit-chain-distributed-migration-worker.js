'use strict';

/**
 * Worker process for the remediation concurrent-auto-migrate race
 * test (test/integration/audit-chain-distributed-migration.integration.test.js — audit
 * finding #2).
 *
 * Runs as a genuinely separate OS process (spawned via child_process.fork),
 * exercising the REAL, unmocked production code path — deployment mode
 * resolution, PostgreSQL pool initialization, and
 * multiInstanceGuard.js's checkDistributedPreconditions() — against a real
 * PostgreSQL database whose target database name is passed in via
 * QODIQA_PG_DATABASE (set by the parent before forking). No mocks anywhere
 * in this file: this is the same code server/startup.js runs at real
 * process boot, invoked multiple times concurrently by the parent test to
 * prove the migration advisory lock (src/infra/postgres/pool.js's
 * withAdvisoryLock()/runMigrations()) actually serializes concurrent
 * replicas racing to auto-apply a pending migration, rather than merely
 * being documented as unsafe to attempt.
 *
 * QODIQA_DEPLOYMENT_MODE=distributed and QODIQA_PG_AUTO_MIGRATE=true are set
 * here (rather than by the parent) so every worker's own require of
 * src/infra/config/deploymentMode.js resolves and applies them before
 * anything else runs — mirroring server/startup.js's own require order
 * exactly (see that file's header comment).
 *
 * Prints exactly one tagged result line to stdout: `WORKER_RESULT:{"ok":
 * boolean}`. The `WORKER_RESULT:` prefix is required, not cosmetic —
 * services/logger.js's emit() (used throughout the production code this
 * worker exercises, including pgPool.shutdown() below, which itself emits a
 * PG_POOL_SHUTDOWN event) ALSO writes structured JSON lines to stdout, both
 * before and after this worker's own result line. A parent that naively
 * took "the last line of stdout" would sometimes capture an unrelated log
 * event instead of this result — the tag lets the parent find the right
 * line unambiguously regardless of what else was logged around it.
 *
 * A worker that hits a FATAL precondition failure calls the real
 * process.exit(1) from inside checkDistributedPreconditions() itself and
 * never reaches its own stdout.write() below — the parent test observes
 * that as a non-zero child exit code, which is sufficient; no special-casing
 * needed here.
 */

process.env.QODIQA_DEPLOYMENT_MODE = 'distributed';
process.env.QODIQA_PG_AUTO_MIGRATE = 'true';

async function main() {
  const { applyDeploymentMode } = require('../../src/infra/config/deploymentMode');
  applyDeploymentMode();

  const pgPool = require('../../src/infra/postgres/pool');
  pgPool.initialize();

  const { checkDistributedPreconditions } = require('../../src/core/audit/multiInstanceGuard');
  const ok = await checkDistributedPreconditions();

  process.stdout.write(`WORKER_RESULT:${JSON.stringify({ ok })}\n`);
  await pgPool.shutdown();
  process.exit(ok ? 0 : 1);
}

main().catch((err) => {
  process.stdout.write(`WORKER_RESULT:${JSON.stringify({ ok: false, error: err.message })}\n`);
  process.exit(1);
});
