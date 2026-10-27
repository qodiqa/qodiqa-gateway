'use strict';

/**
 * Worker process for SCAL-11 multi-process integration tests
 * (test/integration/audit-chain-distributed.integration.test.js).
 *
 * Runs as a genuinely separate OS process (spawned via child_process.fork)
 * with no shared JS heap with the parent test or with sibling workers — the
 * strongest available proof, in this environment, that ordering correctness
 * does not depend on process-local memory (see distributedOrdering.js).
 *
 * Connects to PostgreSQL itself (inherits QODIQA_PG_* env vars from the
 * parent) and calls distributedOrdering.appendEntry() directly, one entry
 * at a time, printing one JSON line per attempt to stdout as it completes:
 *   { ok: true,  artifactId, hash, prevHash }
 *   { ok: false, artifactId, error }
 * so the parent can collect results even if this process is killed
 * mid-batch (a truncated/partial final line is simply discarded by the
 * parent's line parser).
 *
 * Argv: node audit-chain-distributed-worker.js <artifactIdPrefix> <count> [delayMs]
 *   delayMs (default 0) — await this many ms before each append, so a crash
 *   test has a wider window to SIGKILL mid-batch.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const artifactIdPrefix = process.argv[2];
const count            = parseInt(process.argv[3], 10);
const delayMs          = parseInt(process.argv[4] || '0', 10);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  const pgPool = require('../../src/infra/postgres/pool');
  pgPool.initialize();

  const { appendEntry } = require('../../src/core/audit/distributedOrdering');

  for (let i = 0; i < count; i++) {
    if (delayMs > 0) await sleep(delayMs);

    const artifactId = `${artifactIdPrefix}-${i}`;
    try {
      const entry = await appendEntry({
        artifactId,
        inputHash:  require('crypto').createHash('sha256').update(artifactId).digest('hex'),
        decision:   'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
        signature:  'test-signature',
        requestHash: require('crypto').createHash('sha256').update(artifactId + ':req').digest('hex'),
        policyHash:  require('crypto').createHash('sha256').update('test-policy').digest('hex'),
        verificationResult: true,
      });
      process.stdout.write(JSON.stringify({ ok: true, artifactId, hash: entry.hash, prevHash: entry.prevHash }) + '\n');
    } catch (err) {
      process.stdout.write(JSON.stringify({ ok: false, artifactId, error: err.message }) + '\n');
    }
  }

  await pgPool.shutdown();
  process.exit(0);
}

main().catch(err => {
  process.stderr.write(`WORKER_FATAL: ${err.message}\n`);
  process.exit(1);
});
