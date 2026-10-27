'use strict';

/**
 * #129 — non-blocking chunked chain-walk verification.
 *
 * Proves three things about _walkChainChunked (exercised via the exported
 * verifyAuditChainDetailedChunked/validateChainIntegrityChunked) against a
 * large synthetic in-memory chain:
 *
 *  1. Identical results to the synchronous walker — same valid/reason/
 *     entriesVerified/head/tail/offendingIndex/offendingArtifactId for both
 *     a clean chain and a tampered one (no relaxed verification, no skipped
 *     links, deterministic failure reporting).
 *  2. It actually yields — the number of event-loop yields matches the
 *     configured cadence, not zero.
 *  3. It measurably reduces event-loop lag versus the synchronous walk on
 * the same large chain (the actual complaint).
 *
 * Entries are built directly via entryBuilder.buildEntry() (the same
 * primitive audit-log.js's own append() path uses for hashing/chaining) so
 * this never touches disk/fsync — fast enough to build tens of thousands of
 * entries in a unit test while still exercising real hashing.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const os = require('os');
const path = require('path');
const fs = require('fs');

function _freshAuditLog() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-chunkedwalk-'));
  process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
  jest.resetModules();
  return {
    auditLog:    require('../audit-log'),
    entryBuilder: require('../entryBuilder'),
  };
}

function _buildSyntheticChain(entryBuilder, n) {
  const entries = [];
  let prevHash = 'GENESIS';
  for (let i = 0; i < n; i++) {
    const normalized = entryBuilder.normalizeFields({
      artifactId: `artifact-${i}`,
      inputHash:  `input-${i}`,
      decision:   i % 7 === 0 ? 'BLOCK' : 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:  `sig-${i}`,
      requestHash: `req-${i}`,
      policyHash:  `pol-${i}`,
      verificationResult: true,
    });
    const entry = entryBuilder.buildEntry(normalized, prevHash);
    entries.push(entry);
    prevHash = entry.hash;
  }
  return entries;
}

describe('#129 — chunked audit-chain walk', () => {
  afterEach(() => {
    delete process.env.QODIQA_AUDIT_LOG;
    delete process.env.QODIQA_AUDIT_CHAIN_WALK_YIELD_EVERY;
    jest.restoreAllMocks();
  });

  test('a valid large chain: chunked walk matches the synchronous walk exactly', async () => {
    const { auditLog, entryBuilder } = _freshAuditLog();
    const entries = _buildSyntheticChain(entryBuilder, 5000);

    const syncResult    = auditLog.verifyAuditChainDetailed(entries);
    const chunkedResult = await auditLog.verifyAuditChainDetailedChunked(entries);

    expect(chunkedResult).toEqual(syncResult);
    expect(chunkedResult.valid).toBe(true);
    expect(chunkedResult.entriesVerified).toBe(5000);
  });

  test('a tampered entry mid-chain: chunked walk reports the identical failure as the synchronous walk', async () => {
    const { auditLog, entryBuilder } = _freshAuditLog();
    const entries = _buildSyntheticChain(entryBuilder, 3000);

    // Tamper entry 1500's decision without recomputing its hash — a classic
    // AUDIT_CHAIN_TAMPERED case (hash no longer matches canonical fields).
    const tampered = entries.slice();
    tampered[1500] = { ...tampered[1500], decision: 'BLOCK' };

    const syncResult    = auditLog.verifyAuditChainDetailed(tampered);
    const chunkedResult = await auditLog.verifyAuditChainDetailedChunked(tampered);

    expect(chunkedResult).toEqual(syncResult);
    expect(chunkedResult.valid).toBe(false);
    expect(chunkedResult.reason).toBe('AUDIT_CHAIN_TAMPERED');
    expect(chunkedResult.offendingIndex).toBe(1500);
    expect(chunkedResult.tamperingDetected).toBe(true);
    // No skipped links: everything strictly before the tampered entry was
    // still verified, nothing beyond it was silently accepted.
    expect(chunkedResult.entriesVerified).toBe(1500);
  });

  test('yields to the event loop at the configured cadence, not zero times', async () => {
    const { auditLog, entryBuilder } = _freshAuditLog();
    const entries = _buildSyntheticChain(entryBuilder, 2000);

    const originalSetImmediate = global.setImmediate;
    let yieldCount = 0;
    jest.spyOn(global, 'setImmediate').mockImplementation((fn, ...args) => {
      yieldCount++;
      return originalSetImmediate(fn, ...args);
    });

    await auditLog.verifyAuditChainDetailedChunked(entries, undefined, { yieldEvery: 100 });

    // 2000 entries / 100 per chunk => 19 yield points (i=100,200,...,1900).
    expect(yieldCount).toBe(19);
  });

  test('a concurrent callback actually interleaves DURING the chunked walk (the claim), never during the synchronous one', async () => {
    // perf_hooks.monitorEventLoopDelay()'s histogram is too coarse/sampled
    // to reliably assert on on a chain small enough for a fast unit test —
    // the deterministic proof of "did the event loop actually get free time
    // mid-walk" is whether independently-scheduled work observably ran
    // while the walk was still in flight, not an aggregate lag statistic.
    //
    // 20,000 entries plus 100 setImmediate round-trips comfortably finishes
    // in ~1-2s standalone, but can run considerably slower under full-suite
    // parallel worker contention — a generous explicit timeout avoids a
    // false failure from scheduler contention rather than an actual bug.
    const { auditLog, entryBuilder } = _freshAuditLog();
    const entries = _buildSyntheticChain(entryBuilder, 20000);

    // A concurrent "heartbeat" driven by the same primitive the walker
    // yields with (setImmediate) — if the walk never releases the event
    // loop, this can never tick while the walk's promise is still pending,
    // by construction of the single-threaded JS execution model.
    function startHeartbeat() {
      let ticks = 0;
      let stopped = false;
      function tick() {
        if (stopped) return;
        ticks++;
        setImmediate(tick);
      }
      setImmediate(tick);
      return { stop: () => { stopped = true; }, count: () => ticks };
    }

    // Synchronous walk: by definition of JS's execution model, nothing else
    // (including the heartbeat) can run while this call is on the stack.
    const syncHeartbeat = startHeartbeat();
    auditLog.verifyAuditChainDetailed(entries);
    const syncTicksDuringWalk = syncHeartbeat.count();
    syncHeartbeat.stop();
    expect(syncTicksDuringWalk).toBe(0);

    // Chunked walk: the heartbeat must observably advance WHILE the walk's
    // promise is still pending — proof the event loop was genuinely free
    // between chunks, not just that setImmediate was called.
    const chunkedHeartbeat = startHeartbeat();
    await auditLog.verifyAuditChainDetailedChunked(entries, undefined, { yieldEvery: 200 });
    const chunkedTicksDuringWalk = chunkedHeartbeat.count();
    chunkedHeartbeat.stop();
    expect(chunkedTicksDuringWalk).toBeGreaterThan(0);
  }, 30000);
});
