'use strict';

/**
 * SCAL-11 — Distributed Audit Chain Ordering: Integration Tests
 *
 * Requires real PostgreSQL (QODIQA_PG_ENABLED=true) with CREATEDB/CREATEROLE/
 * BYPASSRLS privilege on the connecting role — skipped entirely otherwise,
 * same convention as test/integration/audit-chain-verifier-pg.integration.test.js and
 * src/infra/postgres/__tests__/rls.test.js's RLS-91..100 — except every test
 * below has a real body (no empty stubs).
 *
 * Database lifecycle (FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md §8,
 * prevention layer 1): creates its own uniquely-named, disposable database
 * in beforeAll (migrating it fresh), and drops that exact same database in
 * afterAll — this suite used to reuse the already-configured
 * QODIQA_PG_DATABASE (the real, ambient database), which is what caused the
 * recurring file/PG audit-mirror divergence that report investigated. Never
 * touches any pre-existing database.
 *
 * ADC-01  50+ concurrent appendEntry() calls (Promise.all, real PostgreSQL,
 *         no mocked locking) produce one unbroken, fork-free, deterministically
 *         ordered chain — no duplicate/conflicting prevHash, no duplicate
 * seq. This is Finding B's required permanent regression test
 *         for the audit_chain_head row-lock serialization primitive
 *         (distributedOrdering.js) under concurrent load.
 * ADC-02  True multi-process concurrent appends (child_process.fork, no
 *         shared JS memory) produce one unbroken, fork-free chain
 * ADC-03  A killed writer never corrupts the chain, and the lock is not left
 *         stuck — a fresh writer started immediately after continues cleanly
 * ADC-04  Rolling-deployment simulation: killing one writer and starting its
 *         replacement mid-run produces uninterrupted, unbroken ordering
 * ADC-05  verifyAuditChainDetailed() (the same function single-node mode
 *         uses) validates a chain hydrated from PostgreSQL via
 *         loadChainFromPg() — proves the historical-chain-verification path
 *         audit-log.js already had works unmodified against distributed
 *         mode's data
 *
 * Note on "50+ replicas" vs "50+ concurrent writers": this environment
 * cannot practically launch 50 real OS processes per test run, but
 * Finding B's actual requirement — no duplicate sequence numbers, no chain
 * forks, no broken hashes, deterministic ordering, consistent final chain
 * under >= 50 concurrent appendEntry() operations against real PostgreSQL
 * with no mocked locking — does not require 50 separate processes to prove:
 * the serialization primitive under test is the audit_chain_head row lock
 * itself (distributedOrdering.js), which every appendEntry() call acquires
 * identically regardless of which OS process or JS callframe issued it.
 * ADC-01 below drives 50 concurrent in-process appendEntry() calls via
 * Promise.all — each is an independent async call into the real,
 * unmocked module, each opens/uses a real connection from the real
 * PostgreSQL connection pool, and each genuinely races every other one for
 * the row lock (Promise.all provides no ordering guarantee between the
 * calls — the database is the only thing serializing them). ADC-02/03/04
 * additionally prove the SAME primitive holds with 2-5 true, separate OS
 * processes (no shared JS heap at all) — the strongest available proof in
 * this environment that correctness comes from the PostgreSQL row lock, not
 * from any in-process coordination — so the two test styles are
 * complementary, not redundant: ADC-01 supplies the required concurrency
 * volume (50+), ADC-02..04 supply true process isolation at a volume this
 * environment can practically fork.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { fork } = require('child_process');
const path      = require('path');
const crypto    = require('crypto');
const { Pool }  = require('pg');
// REL-06: reassigned in beforeAll to the SAME post-jest.resetModules()
// registry instance audit-log.js/distributedOrdering.js resolve to below —
// this top-of-file require happens in a different (pre-reset) registry and
// would otherwise silently observe a different, un-instrumented instance.
let metrics = require('../../src/observability/metrics');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const WORKER_PATH = path.resolve(__dirname, '..', 'helpers', 'audit-chain-distributed-worker.js');
const { trackInFlight } = require('../helpers/inFlight');
let evidenceWrites = null;

// FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md §8 prevention layer 1: this
// suite used to reuse the already-configured QODIQA_PG_DATABASE (the real,
// ambient dev database) with no isolation and no cleanup, which is exactly
// what caused the recurring file/PG audit-mirror divergence documented in
// that report. Now creates and drops its own uniquely-named, disposable
// database per run, matching the pattern its sibling
// test/integration/audit-chain-verifier-pg.integration.test.js already uses correctly.
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_adc_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

let _maintenancePool;
let _originalDatabaseEnv;
let _originalUserEnv;
let _originalPasswordEnv;

// ── Helpers ───────────────────────────────────────────────────────────────────

function uniquePrefix(label) {
  return `adc-${label}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * Spawns a worker process (see helpers/audit-chain-distributed-worker.js),
 * collecting one parsed JSON result object per completed append from its
 * stdout. Resolves with { results, proc } once the process exits — results
 * reflects however many appends actually completed before exit, including
 * an early kill (a truncated final stdout line is discarded, not parsed).
 */
function spawnWorker(prefix, count, delayMs = 0) {
  const proc = fork(WORKER_PATH, [prefix, String(count), String(delayMs)], {
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    env: process.env,
  });

  const results = [];
  let buffer = '';
  proc.stdout.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    const lines = buffer.split('\n');
    buffer = lines.pop(); // last element may be incomplete — keep buffering
    for (const line of lines) {
      if (!line.trim()) continue;
      let parsed;
      try { parsed = JSON.parse(line); } catch { continue; } // truncated by a kill — discard
      // The worker process also initializes a PG pool, which emits its own
      // structured app log lines (PG_POOL_INITIALIZED, PG_POOL_CONNECT, ...)
      // to the SAME stdout stream via services/logger.js — those have `ts`/
      // `level`/`event` shape, never `ok`. Only the worker's own explicit
      // per-append result lines (`{ok, artifactId, ...}` — see
      // helpers/audit-chain-distributed-worker.js) count as a result; anything
      // else is log noise and must not be mistaken for append progress
      // (this was silently inflating result counts before the fix).
      if (typeof parsed.ok !== 'boolean') continue;
      results.push(parsed);
    }
  });
  proc.stderr.on('data', (chunk) => {
    process.stderr.write(`[worker ${prefix} stderr] ${chunk}`);
  });

  const exited = new Promise((resolve) => {
    proc.on('exit', () => resolve());
  });

  return { proc, results, exited };
}

/**
 * Resolves once a worker's `results` array has at least `n` entries, or
 * rejects on timeout. Used instead of a fixed sleep before killing a worker
 * mid-batch (ADC-03) — a fixed delay is inherently racy against process
 * spawn/PG-connect time, which varies by machine/load; polling for actual
 * confirmed progress is deterministic regardless of startup latency.
 */
function waitForResultCount(worker, n, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = setInterval(() => {
      if (worker.results.length >= n) {
        clearInterval(check);
        resolve();
      } else if (Date.now() - start > timeoutMs) {
        clearInterval(check);
        reject(new Error(`waitForResultCount: only ${worker.results.length}/${n} results after ${timeoutMs}ms`));
      }
    }, 10);
  });
}

/**
 * Walks the audit_chain hash-chain forward from startHash, one prev_hash
 * lookup at a time. Throws immediately if more than one row shares the same
 * prev_hash (a fork) — the direct, DB-level check for "no conflicting
 * sequence assignments." Stops when no row references the current hash as
 * its prev_hash (end of this lineage) or maxSteps is reached.
 */
async function traceChainForward(pgPool, startHash, maxSteps) {
  const visited = [];
  let current = startHash;
  for (let i = 0; i < maxSteps; i++) {
    const res = await pgPool.query(
      'SELECT hash, prev_hash, artifact_id, seq FROM audit_chain WHERE prev_hash = $1',
      [current]
    );
    if (res.rows.length === 0) break;
    if (res.rows.length > 1) {
      throw new Error(
        `FORK DETECTED: ${res.rows.length} entries share prev_hash=${current}: ` +
        res.rows.map(r => r.artifact_id).join(', ')
      );
    }
    const row = res.rows[0];
    visited.push({ hash: row.hash, artifactId: row.artifact_id, seq: Number(row.seq) });
    current = row.hash;
  }
  return visited;
}

async function getHead(pgPool) {
  const res = await pgPool.query('SELECT tail_hash, tail_seq FROM audit_chain_head');
  return { tailHash: res.rows[0].tail_hash, tailSeq: Number(res.rows[0].tail_seq) };
}

// ── Suite ─────────────────────────────────────────────────────────────────────

describeOrSkip('SCAL-11 — Distributed Audit Chain Ordering (real PostgreSQL)', () => {
  let pgPool;
  let distributedOrdering;
  let auditLog;
  let _originalOrderingModeEnv;

  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) {
      throw new Error(`Generated test DB name "${TEST_DB_NAME}" failed identifier validation — refusing to proceed.`);
    }

    ///prevention layer 1: prefer the dedicated qodiqa_test role (CREATEDB/
    // CREATEROLE/BYPASSRLS) for CREATE DATABASE and running migrations on it
    // — falls back to the pre-existing chain so CI's ephemeral
    // postgres:17-alpine superuser container (QODIQA_PG_USER=qodiqa there,
    // which already migrates this same database via a separate CI step) is
    // unaffected.
    _maintenancePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    // Elevate only for migrating the fresh database (002/018 require
    // CREATEROLE+BYPASSRLS) — restored below, before any test or forked
    // worker runs, so both the parent pool and every worker (which inherits
    // process.env via spawnWorker()'s `env: process.env`) append entries as
    // the same ambient, least-privilege role production actually uses.
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    // REL-06 (ADC-06/07/08): audit-log.js reads QODIQA_AUDIT_ORDERING_MODE
    // once, at its own module-load time — must be set before its first
    // require() below so its dispatch to distributedOrdering.js (and the
    // instrumentation wrapped around that dispatch) actually activates.
    _originalOrderingModeEnv = process.env.QODIQA_AUDIT_ORDERING_MODE;
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';

    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();

    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;

    distributedOrdering = require('../../src/core/audit/distributedOrdering');
    // distributed appends start their evidence write without
    // awaiting it; afterAll waits for those before shutting the pool.
    evidenceWrites = trackInFlight(require('../../src/infra/postgres/pg-audit-backend'), 'recordEvidenceForEntry');
    auditLog = require('../../src/core/audit/audit-log');
    // Same registry as the requires above (post-resetModules) — the instance
    // audit-log.js's own internal require('../../observability/metrics')
    // resolves to, so assertions below observe the same counters/gauges the
    // instrumented append path actually increments.
    metrics = require('../../src/observability/metrics');
  }, 60_000);

  test('ADC-01 50+ concurrent in-process appendEntry() calls against real PostgreSQL produce one unbroken, fork-free, deterministically-ordered chain with no duplicate sequence numbers', async () => {
    const prefix = uniquePrefix('inproc');
    const N = 50; // Finding B: minimum 50 concurrent appendEntry() operations.

    const before = await getHead(pgPool);

    const submissions = Array.from({ length: N }, (_, i) => ({
      artifactId: `${prefix}-${i}`,
      inputHash:  crypto.createHash('sha256').update(`${prefix}-${i}`).digest('hex'),
      decision:   'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:  'test-signature',
      requestHash: crypto.createHash('sha256').update(`${prefix}-${i}:req`).digest('hex'),
      policyHash:  crypto.createHash('sha256').update('test-policy').digest('hex'),
      verificationResult: true,
    }));

    // No mocked locking anywhere in this path: distributedOrdering.js is the
    // real module, pgPool is a real connection pool against a real
    // PostgreSQL instance, and Promise.all gives no ordering guarantee
    // between the 50 calls — only the audit_chain_head row lock inside
    // appendEntry()'s transaction can be what serializes them correctly.
    const entries = await Promise.all(submissions.map(f => distributedOrdering.appendEntry(f)));
    expect(entries).toHaveLength(N);

    const after = await getHead(pgPool);
    expect(after.tailSeq).toBe(before.tailSeq + N);

    // traceChainForward() throws FORK DETECTED if any prev_hash is shared by
    // more than one row — the direct DB-level "no chain forks" check.
    const chain = await traceChainForward(pgPool, before.tailHash, N + 5);
    expect(chain).toHaveLength(N);
    expect(chain[chain.length - 1].hash).toBe(after.tailHash);

    const submittedIds = new Set(submissions.map(s => s.artifactId));
    const chainedIds   = new Set(chain.map(c => c.artifactId));
    expect(chainedIds).toEqual(submittedIds);

    // No duplicate sequence numbers: 50 distinct, monotonically increasing
    // integers with no repeats and no gaps across exactly this batch —
    // gaps or repeats would mean two concurrent transactions both believed
    // they held the next seq, which the row lock must prevent.
    const seqs = chain.map(c => c.seq);
    const uniqueSeqs = new Set(seqs);
    expect(uniqueSeqs.size).toBe(N);
    const sortedSeqs = [...seqs].sort((a, b) => a - b);
    expect(seqs).toEqual(sortedSeqs); // deterministic ordering: commit order == seq order
    for (let i = 1; i < sortedSeqs.length; i++) {
      expect(sortedSeqs[i]).toBe(sortedSeqs[i - 1] + 1); // no gaps
    }

    // No broken hashes / no forks: traceChainForward() above only found a
    // row for each step by matching WHERE prev_hash = <previous row's hash>
    // (throwing FORK DETECTED if more than one row ever matched) — reaching
    // exactly N rows and ending at the real current tail_hash (asserted
    // above) is only possible if every one of the 50 concurrently-inserted
    // rows is correctly and uniquely hash-linked to its predecessor.
  }, 30000);

  test('ADC-02 true multi-process concurrent appends (no shared JS memory) produce one unbroken, fork-free chain', async () => {
    const before = await getHead(pgPool);

    const NUM_WORKERS   = 4;
    const PER_WORKER    = 10;
    const workers = Array.from({ length: NUM_WORKERS }, (_, i) =>
      spawnWorker(uniquePrefix(`mp${i}`), PER_WORKER)
    );

    await Promise.all(workers.map(w => w.exited));

    const allResults = workers.flatMap(w => w.results);
    const succeeded   = allResults.filter(r => r.ok);
    expect(succeeded).toHaveLength(NUM_WORKERS * PER_WORKER);

    const after = await getHead(pgPool);
    expect(after.tailSeq).toBe(before.tailSeq + succeeded.length);

    const chain = await traceChainForward(pgPool, before.tailHash, succeeded.length + 5);
    expect(chain).toHaveLength(succeeded.length);
    expect(chain[chain.length - 1].hash).toBe(after.tailHash);

    const submittedIds = new Set(succeeded.map(r => r.artifactId));
    const chainedIds   = new Set(chain.map(c => c.artifactId));
    expect(chainedIds).toEqual(submittedIds);
  }, 30000);

  test('ADC-03 a killed writer never corrupts the chain; a fresh writer continues cleanly afterward', async () => {
    const before = await getHead(pgPool);

    // Slow worker (50ms between appends) so there's a wide window to kill it
    // mid-batch rather than after it has already finished. Wait for actual
    // confirmed progress (not a fixed sleep) before killing — a fixed delay
    // is racy against process spawn/PG-connect time, which varies by
    // machine/load; this guarantees the kill lands mid-batch deterministically.
    const victimPrefix = uniquePrefix('victim');
    const victim = spawnWorker(victimPrefix, 20, 50);

    await waitForResultCount(victim, 2);
    victim.proc.kill('SIGKILL');
    await victim.exited;

    const victimSucceeded = victim.results.filter(r => r.ok);
    // The kill should land mid-batch, not after everything already finished —
    // otherwise this test isn't actually exercising a crash mid-write.
    expect(victimSucceeded.length).toBeGreaterThan(0);
    expect(victimSucceeded.length).toBeLessThan(20);

    const afterKill = await getHead(pgPool);
    expect(afterKill.tailSeq).toBe(before.tailSeq + victimSucceeded.length);

    // Chain up to the kill point must still be unbroken and fork-free —
    // proves a crash mid-write (SIGKILL, connection dropped mid-transaction)
    // never left a partial/corrupt entry: PostgreSQL rolled back whatever
    // the victim's transaction hadn't committed, and released its head-row
    // lock automatically on connection loss.
    const chainAfterKill = await traceChainForward(pgPool, before.tailHash, victimSucceeded.length + 5);
    expect(chainAfterKill).toHaveLength(victimSucceeded.length);
    expect(chainAfterKill[chainAfterKill.length - 1].hash).toBe(afterKill.tailHash);

    // A brand-new writer, started after the kill, must be able to continue
    // immediately — proves the head-row lock was NOT left stuck by the
    // killed connection.
    const survivorPrefix = uniquePrefix('survivor');
    const survivor = spawnWorker(survivorPrefix, 5, 0);
    await survivor.exited;
    const survivorSucceeded = survivor.results.filter(r => r.ok);
    expect(survivorSucceeded).toHaveLength(5);

    const afterSurvivor = await getHead(pgPool);
    expect(afterSurvivor.tailSeq).toBe(afterKill.tailSeq + 5);

    const fullChain = await traceChainForward(pgPool, before.tailHash, victimSucceeded.length + 10);
    expect(fullChain).toHaveLength(victimSucceeded.length + 5);
    expect(fullChain[fullChain.length - 1].hash).toBe(afterSurvivor.tailHash);
  }, 30000);

  test('ADC-04 rolling-deployment simulation: killing one writer and starting its replacement mid-run stays uninterrupted', async () => {
    const before = await getHead(pgPool);

    // Writer A: the "old pod" being rolled. Writer B: an unrelated peer
    // that keeps writing throughout, simulating steady traffic on other
    // replicas during the rollout.
    const aPrefix = uniquePrefix('rollA');
    const a = spawnWorker(aPrefix, 30, 15);
    const b = spawnWorker(uniquePrefix('rollB'), 30, 15);

    await new Promise(resolve => setTimeout(resolve, 150)); // let both get going
    a.proc.kill('SIGKILL'); // "old pod" terminated by the rollout
    await a.exited;

    // "New pod" replacing A, started immediately, while B is still writing.
    const c = spawnWorker(uniquePrefix('rollC'), 15, 15);

    await Promise.all([b.exited, c.exited]);

    const aSucceeded = a.results.filter(r => r.ok);
    const bSucceeded = b.results.filter(r => r.ok);
    const cSucceeded = c.results.filter(r => r.ok);
    expect(bSucceeded).toHaveLength(30); // B was never interrupted
    expect(cSucceeded).toHaveLength(15); // C's full batch completed

    // A is SIGKILLed mid-run, so its last append can COMMIT in
    // PostgreSQL before A prints the result line the parent counts (observed
    // twice on 2026-09-28: expected tailSeq 143, received 144). A's commits are
    // therefore taken from the chain itself; every append A reported must be
    // there, and at most ONE more — the single append in flight at the kill.
    const after = await getHead(pgPool);
    const chain = await traceChainForward(pgPool, before.tailHash, (after.tailSeq - before.tailSeq) + 5);
    expect(chain).toHaveLength(after.tailSeq - before.tailSeq); // unbroken from `before` to `after`
    expect(chain[chain.length - 1].hash).toBe(after.tailHash);

    const aCommittedIds = chain.map(c2 => c2.artifactId).filter(id => id.startsWith(`${aPrefix}-`));
    const aReportedIds  = aSucceeded.map(r => r.artifactId);
    expect(aCommittedIds).toEqual(expect.arrayContaining(aReportedIds));
    expect(aCommittedIds.length - aReportedIds.length).toBeGreaterThanOrEqual(0);
    expect(aCommittedIds.length - aReportedIds.length).toBeLessThanOrEqual(1);
    expect(after.tailSeq).toBe(before.tailSeq + aCommittedIds.length + bSucceeded.length + cSucceeded.length);

    const expectedIds = new Set([...aCommittedIds, ...bSucceeded.map(r => r.artifactId), ...cSucceeded.map(r => r.artifactId)]);
    const chainedIds  = new Set(chain.map(c2 => c2.artifactId));
    expect(chainedIds).toEqual(expectedIds); // nothing else, and no duplicates (sizes match the chain)
    expect(chainedIds.size).toBe(chain.length);
  }, 30000);

  test('ADC-05 verifyAuditChainDetailed validates a chain hydrated from PostgreSQL via loadChainFromPg', async () => {
    const { loadChainFromPg } = require('../../src/infra/postgres/pg-audit-backend');
    const { verifyAuditChainDetailed } = require('../../src/core/audit/audit-log');

    const prefix = uniquePrefix('verify');
    for (let i = 0; i < 5; i++) {
      await distributedOrdering.appendEntry({
        artifactId: `${prefix}-${i}`,
        inputHash:  crypto.createHash('sha256').update(`${prefix}-${i}`).digest('hex'),
        decision:   'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
        signature:  'test-signature',
        requestHash: crypto.createHash('sha256').update(`${prefix}-${i}:req`).digest('hex'),
        policyHash:  crypto.createHash('sha256').update('test-policy').digest('hex'),
        verificationResult: true,
      });
    }

    const hydrated = await loadChainFromPg();
    expect(hydrated.length).toBeGreaterThan(0);

    const detail = verifyAuditChainDetailed(hydrated);
    expect(detail.valid).toBe(true);
    expect(detail.reason).toBeNull();
    expect(detail.tamperingDetected).toBe(false);
  }, 30000);

  // ADC-05's entries carry none of the schemaVersion 5/6 hash-protected
  // fields (provider/model, stage/reason/semantic/tokenUsage/responseId), so it
  // could not see that appendEntry()'s INSERT never persisted them — every real
  // /ai/chat BLOCK or EXECUTE row then failed re-verification on the next boot
  // ("chain_break: canonical hash mismatch", reproduced live against the Compose
  // reference topology). This entry mirrors the exact shape aiChat.js's
  // _writeAuditBlock() wrote in that reproduction, and is read back through BOTH
  // hydration paths the boot check and the verifier use.
  test('ADC-09 a schemaVersion-6 entry carrying provider/model/stage/reason/semantic/tokenUsage/responseId round-trips through PostgreSQL and re-verifies via loadChainFromPg and fetchChainBatch', async () => {
    const { loadChainFromPg, fetchChainBatch } = require('../../src/infra/postgres/pg-audit-backend');
    const { verifyAuditChainDetailed } = require('../../src/core/audit/audit-log');

    const prefix = uniquePrefix('v6fields');
    const committed = await distributedOrdering.appendEntry({
      artifactId:  `${prefix}-block`,
      inputHash:   crypto.createHash('sha256').update(`${prefix}:in`).digest('hex'),
      decision:    'BLOCK',
      signature:   'test-signature',
      requestHash: crypto.createHash('sha256').update(`${prefix}:req`).digest('hex'),
      policyHash:  crypto.createHash('sha256').update('test-policy').digest('hex'),
      verificationResult: true,
      tenantId:    'h123-tenant',
      publicKeyId: 'h123-tenant:key_v1',
      callerContext: { callerId: 'caller-1', callerName: 'h123-e2e-caller', environment: 'production', credentialType: 'api-key' },
      provider:    'local',
      model:       'llama3.2:1b',
      stage:       'PROVIDER_EXECUTION',
      reason:      'PROVIDER_ERROR',
      semantic:    { decision: 'ALLOW', score: 0.1 },
      tokenUsage:  { inputTokens: 3, outputTokens: 5, totalTokens: 8 },
      responseId:  `${prefix}-resp`,
    });
    expect(committed.schemaVersion).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)

    for (const hydrated of [await loadChainFromPg(), await fetchChainBatch(0, 100000)]) {
      const row = hydrated.find(e => e.artifactId === `${prefix}-block`);
      expect(row).toBeDefined();
      expect(row.provider).toBe('local');
      expect(row.model).toBe('llama3.2:1b');
      expect(row.stage).toBe('PROVIDER_EXECUTION');
      expect(row.reason).toBe('PROVIDER_ERROR');
      expect(row.responseId).toBe(`${prefix}-resp`);

      const detail = verifyAuditChainDetailed(hydrated);
      expect(detail.reason).toBeNull();
      expect(detail.valid).toBe(true);
      expect(detail.tamperingDetected).toBe(false);
    }
  }, 30000);

  test('ADC-06 (REL-06) ordering-authority metrics are non-vacuous: static gauges hold the measured reference constants, the append counter distinguishes real success from real failure, and the duration histogram records genuine, non-identical timings', async () => {
    // Static reference gauges — set once at metrics.js module load from the
    // named ITEM-23/ITEM-24 constants, not computed here. Confirms the
    // values an operator sees in /metrics actually match what this suite's
    // own README section
    // claim, rather than trusting the doc text alone.
    expect(metrics.orderingCeilingAppendsPerSec._values.get('') ).toBe(330);
    expect(metrics.orderingBaselineRps._values.get('')).toBe(70);

    const prefix = uniquePrefix('rel06');
    const successKey = 'mode="distributed",outcome="success"';
    const failureKey = 'mode="distributed",outcome="failure"';
    const successBefore = metrics.orderingAppendTotal._values.get(successKey) || 0;
    const failureBefore = metrics.orderingAppendTotal._values.get(failureKey) || 0;
    const histBefore = metrics.auditAppendDurationSeconds._data.get('mode="distributed",outcome="success"');
    const countBefore = histBefore ? histBefore.count : 0;

    const fields = {
      artifactId: `${prefix}-dup`,
      inputHash:  crypto.createHash('sha256').update(`${prefix}-dup`).digest('hex'),
      decision:   'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:  'test-signature',
      requestHash: crypto.createHash('sha256').update(`${prefix}-dup:req`).digest('hex'),
      policyHash:  crypto.createHash('sha256').update('test-policy').digest('hex'),
      verificationResult: true,
    };

    // Through auditLog.append() — the real dispatch point every production
    // request actually uses (aiChat.js/streamEnforcer.js), and the one
    // REL-06's instrumentation wraps. distributedOrdering.appendEntry()
    // called directly (as ADC-01..05 above deliberately do, to test the raw
    // row-lock primitive in isolation) never reaches this instrumentation.
    const entry1 = await auditLog.append(fields);
    expect(entry1.artifactId).toBe(fields.artifactId);

    // Second append with the SAME artifactId: PG's unique constraint on
    // artifact_id rejects it — a genuine failure outcome, not a simulated
    // one. Proves orderingAppendTotal's outcome label moves with reality in
    // BOTH directions (success and failure), not just always incrementing
    // the same counter regardless of what actually happened.
    await expect(auditLog.append(fields)).rejects.toThrow('already_executed');

    const successAfter = metrics.orderingAppendTotal._values.get(successKey) || 0;
    const failureAfter = metrics.orderingAppendTotal._values.get(failureKey) || 0;
    expect(successAfter - successBefore).toBe(1);
    expect(failureAfter - failureBefore).toBe(1);

    // The duration histogram recorded a real observation for the successful
    // call — sum/count > 0 proves it's a genuine timing, not a hardcoded or
    // always-zero value (the exact vacuous-metric failure mode).
    const histAfter = metrics.auditAppendDurationSeconds._data.get('mode="distributed",outcome="success"');
    expect(histAfter.count).toBe(countBefore + 1);
    expect(histAfter.sum).toBeGreaterThan(histBefore ? histBefore.sum : 0);
    const lastObservationSeconds = histAfter.sum - (histBefore ? histBefore.sum : 0);
    expect(lastObservationSeconds).toBeGreaterThan(0);
    // Sanity bound, not a precision assertion: a single row-lock transaction
    // against a local PostgreSQL instance should land well under 1 second
    // even under this suite's own concurrent load — catches a metric that's
    // silently observing something absurd (e.g. accumulated wall-clock
    // instead of per-call latency) without over-fitting to exact timing.
    expect(lastObservationSeconds).toBeLessThan(1);
  }, 30000);

  test('ADC-08 (REL-06) the in-flight gauge tracks real per-process state through the real audit-log.js dispatch — genuinely non-vacuous, and correctly bounded to 1 because append()\'s own _writeChain FIFO self-serializes even in distributed mode', async () => {
    // Discovered while writing this test, not assumed: audit-log.js's
    // append() (the real dispatch every production call site uses) chains
    // every call through a single module-level `_writeChain` promise FIFO
    // BEFORE _appendOne() ever runs — unconditionally, in both single-node
    // and distributed mode (see audit-log.js line ~724-733). So within one
    // process, orderingInflightAppends{mode="distributed"} can only ever be
    // 0 or 1 via this path: genuine multi-way contention on the PG row lock
    // is a cross-REPLICA phenomenon (proven separately by ADC-01's direct,
    // unserialized distributedOrdering.appendEntry() calls and ADC-02's
    // true multi-process workers), not something one process's own append()
    // traffic can produce. Documented plainly in
    // rather than left as
    // a surprise — an operator scraping one replica's /metrics should not
    // expect to see this gauge exceed 1 and should not read that as the
    // metric being broken.
    const prefix = uniquePrefix('rel06burst');
    const N = 20;
    const submissions = Array.from({ length: N }, (_, i) => ({
      artifactId: `${prefix}-${i}`,
      inputHash:  crypto.createHash('sha256').update(`${prefix}-${i}`).digest('hex'),
      decision:   'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:  'test-signature',
      requestHash: crypto.createHash('sha256').update(`${prefix}-${i}:req`).digest('hex'),
      policyHash:  crypto.createHash('sha256').update('test-policy').digest('hex'),
      verificationResult: true,
    }));

    const inflightKey = 'mode="distributed"';
    const baseline = metrics.orderingInflightAppends._values.get(inflightKey) || 0;
    let observedNonZero = false;
    let maxObserved = baseline;
    // Polling, not a fixed sleep: proves the gauge genuinely moves off its
    // baseline while the batch is in flight
    // without asserting a specific peak this call path cannot produce.
    const pollHandle = setInterval(() => {
      const v = metrics.orderingInflightAppends._values.get(inflightKey) || 0;
      if (v > baseline) observedNonZero = true;
      if (v > maxObserved) maxObserved = v;
    }, 1);

    await Promise.all(submissions.map(f => auditLog.append(f)));
    clearInterval(pollHandle);

    expect(observedNonZero).toBe(true); // moved off baseline — not stuck at a fixed value
    expect(maxObserved).toBe(baseline + 1); // never exceeds 1 in-flight, exactly as _writeChain guarantees
    // The finally-block dec() in audit-log.js's _appendOne() cannot leak
    // even across N sequentially-pipelined append() calls — back to exactly
    // the pre-burst value once every one has settled.
    expect(metrics.orderingInflightAppends._values.get(inflightKey) || 0).toBe(baseline);
  }, 30000);

  test('ADC-07 (REL-06) instrumentation overhead: 100k raw inc/dec/observe calls complete in well under the ~1.2-1.9ms single row-lock transaction cost ITEM-23 measured', () => {
    // Pure in-memory Map operations (Counter/Gauge/Histogram — see
    // src/observability/metrics.js's own "zero I/O on increment" design
    // invariant) — this does not need real PostgreSQL, just confirms the
    // per-call cost the ordering path now pays is negligible relative to the
    // ~1.2-1.9ms critical section ITEM-23 measured, so instrumentation
    // cannot itself be what pushes the system toward the ceiling it exists
    // to make observable.
    const N = 100_000;
    const label = { mode: 'distributed' };
    const start = process.hrtime.bigint();
    for (let i = 0; i < N; i++) {
      metrics.orderingInflightAppends.inc(label);
      metrics.orderingAppendTotal.inc({ mode: 'distributed', outcome: 'success' });
      metrics.auditAppendDurationSeconds.observe({ mode: 'distributed', outcome: 'success' }, 0.0015);
      metrics.orderingInflightAppends.dec(label);
    }
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
    const perIterationUs = (elapsedMs * 1000) / N;
    // Measured locally at ~7-8us per iteration (4 ops: inc, 2x the
    // counter/histogram pair, dec — so ~2us per individual metric call).
    // Bound set at 50us/iteration: a >6x margin over the observed value to
    // absorb CI/shared-machine variance without flaking, while still being
    // a real regression trip-wire — and even at the full 50us bound, that's
    // still >24x cheaper than the 1200us row-lock transaction floor ITEM-23
    // measured, so instrumentation cannot itself become the bottleneck.
    expect(perIterationUs).toBeLessThan(50);
  });

  afterAll(async () => {
    if (evidenceWrites) { await evidenceWrites.settle(); evidenceWrites.restore(); }
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    if (_originalOrderingModeEnv === undefined) {
      delete process.env.QODIQA_AUDIT_ORDERING_MODE;
    } else {
      process.env.QODIQA_AUDIT_ORDERING_MODE = _originalOrderingModeEnv;
    }

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(
          `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
          [TEST_DB_NAME],
        );
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // Best-effort cleanup only — a leftover uniquely-named disposable
        // test DB is a minor annoyance, never a reason to fail the suite.
        // eslint-disable-next-line no-console
        console.warn(`[audit-chain-distributed.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);
});
