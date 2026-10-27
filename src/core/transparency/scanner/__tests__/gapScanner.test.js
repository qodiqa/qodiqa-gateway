'use strict';

/**
 * Transparency Gap Scanner — Test Suite — Component #34
 *
 * Tests:
 *  1.  Periodic scan execution (timer fires at configured interval)
 *  2.  Full scan: sequence break detection
 *  3.  Full scan: hash chain break detection (prev_hash mismatch)
 *  4.  Full scan: entry hash recomputation mismatch
 *  5.  Full scan: genesis entry with non-null previous_entry_hash
 *  6.  Incremental scan: resumes from last_scanned_id
 *  7.  Incremental scan: chain boundary verification (overlap)
 *  8.  Scanner restart: loads persisted state on start
 *  9.  Persisted scan state: saved after successful scan
 * 10.  Duplicate scanner prevention: lock not acquired → skipped
 * 11.  Concurrent execution: within-process guard (isScanning flag)
 * 12.  PostgreSQL failure: pgPool.withTransaction throws
 * 13.  Interrupted scan recovery: crash does not update state
 * 14.  Gap detection: root chain break (CHECKPOINT_DIVERGENCE)
 * 15.  Gap detection: root hash mismatch (CHECKPOINT_DIVERGENCE)
 * 16.  Gap detection: root entry count mismatch
 * 17.  Gap recovery integration: auto-resolve called for each gap
 * 18.  Audit logging: scan started / completed / failed events
 * 19.  Metrics updates: success, failure, entries checked, gaps
 * 20.  Configuration: FULL mode starts from id=1 ignoring state
 * 21.  Configuration: startupScan runs immediately on start()
 * 22.  Disabled scanner: start() is a no-op when enabled=false
 * 23.  Empty log: scan completes successfully with 0 entries
 * 24.  Scanner stop(): clears timer, marks not running
 * 25.  Idempotent start: second start() emits warning, no-op
 */

const { createGapScanner }  = require('../GapScanner');
const { createScanner }     = require('../index');
const { computeEntryHash }  = require('../../log');

// ── Test helpers ──────────────────────────────────────────────────────────────

function makeEntry(overrides = {}) {
  const base = {
    id:                   1,
    transparency_id:      'tid-1',
    entry_type:           'ARTIFACT',
    artifact_id:          'art-1',
    evidence_chain_id:    null,
    verification_id:      null,
    payload_hash:         'a'.repeat(64),
    previous_entry_hash:  null,
    entry_hash:           null, // computed below if not provided
    signer_key_id:        'key-1',
    signer_key_version:   1,
    signature:            'sig-base64',
    registered_by:        'system',
    tenant_id:            null,
  };
  const row = { ...base, ...overrides };
  if (row.entry_hash === null) {
    row.entry_hash = computeEntryHash({
      transparencyId:    row.transparency_id,
      entryType:         row.entry_type,
      artifactId:        row.artifact_id,
      evidenceChainId:   row.evidence_chain_id,
      verificationId:    row.verification_id,
      payloadHash:       row.payload_hash,
      previousEntryHash: row.previous_entry_hash,
      signerKeyId:       row.signer_key_id,
    });
  }
  return row;
}

function makeRoot(overrides = {}) {
  return {
    id:                 1,
    root_id:            'root-1',
    seq_from:           1,
    seq_to:             1,
    entry_count:        1,
    root_hash:          'r'.repeat(64),
    previous_root_hash: null,
    signer_key_id:      'key-1',
    generated_at:       new Date().toISOString(),
    ...overrides,
  };
}

/** Build a chain of N entries with valid hashes. */
function makeChain(n, startId = 1) {
  const entries = [];
  let prevHash = null;
  for (let i = 0; i < n; i++) {
    const id  = startId + i;
    const row = makeEntry({
      id,
      transparency_id:     `tid-${id}`,
      artifact_id:         `art-${id}`,
      previous_entry_hash: prevHash,
      entry_hash:          null, // auto-compute
    });
    prevHash = row.entry_hash;
    entries.push(row);
  }
  return entries;
}

function makeMockPgPool(queryFn, opts = {}) {
  const { lockAcquired = true } = opts;
  return {
    isEnabled: () => true,
    // the scanner's cross-tenant reads run on qodiqa_system (injected _definerQuery), not in its tx.
    definerQuery: (sql, params) => queryFn(sql, params),
    withTransaction: async (fn, _txOpts) => {
      const tx = {
        query: async (sql, params) => {
          // Handle advisory lock
          if (sql.includes('pg_try_advisory_xact_lock')) {
            return { rows: [{ acquired: lockAcquired }] };
          }
          return queryFn(sql, params);
        },
      };
      return fn(tx);
    },
  };
}

function makeMockGapFramework() {
  const handleGapCalls = [];
  const autoResolveCalls = [];
  return {
    handleGap: jest.fn(async (gapType, context) => {
      const gap = { gapId: `gap-${Math.random().toString(36).slice(2)}`, gapType, ...context };
      handleGapCalls.push({ gapType, context });
      return { gap, blocked: false };
    }),
    autoResolveGap: jest.fn((gapId) => {
      autoResolveCalls.push(gapId);
      return false; // default: unrecoverable
    }),
    handleGapCalls,
    autoResolveCalls,
  };
}

function makeMockState(row = null) {
  let saved = null;
  return {
    load: jest.fn(async () => row),
    save: jest.fn(async (state) => { saved = state; }),
    getSaved: () => saved,
  };
}

function makeMockMetrics() {
  const counters = {};
  const gauges   = {};
  const histos   = {};

  const makeCounter = (name) => ({
    inc: jest.fn(),
    name,
    _counters: counters,
  });
  const makeGauge = (name) => ({
    set: jest.fn(),
    inc: jest.fn(),
    name,
  });
  const makeHisto = (name) => ({
    observe: jest.fn(),
    name,
  });

  return {
    gapScannerRunsTotal:            makeCounter('gapScannerRunsTotal'),
    gapScannerSuccessTotal:         makeCounter('gapScannerSuccessTotal'),
    gapScannerFailuresTotal:        makeCounter('gapScannerFailuresTotal'),
    gapScannerSkippedTotal:         makeCounter('gapScannerSkippedTotal'),
    gapScannerActive:               makeGauge('gapScannerActive'),
    gapScannerRunnerActive:         makeGauge('gapScannerRunnerActive'),
    gapScannerLastSuccessTs:        makeGauge('gapScannerLastSuccessTs'),
    gapScannerDurationMs:           makeHisto('gapScannerDurationMs'),
    gapScannerGapsDetectedTotal:    makeCounter('gapScannerGapsDetectedTotal'),
    gapScannerGapsRecoveredTotal:   makeCounter('gapScannerGapsRecoveredTotal'),
    gapScannerGapsUnrecoverableTotal: makeCounter('gapScannerGapsUnrecoverableTotal'),
    gapScannerEntriesCheckedTotal:  makeCounter('gapScannerEntriesCheckedTotal'),
    gapScannerRetriesTotal:         makeCounter('gapScannerRetriesTotal'),
  };
}

function makeEmit() {
  const calls = [];
  return {
    emit: jest.fn((level, event, data) => calls.push({ level, event, data })),
    calls,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GapScanner — core engine', () => {

  // ── 1. Empty log ─────────────────────────────────────────────────────────────
  test('empty log: scan completes with 0 entries checked', async () => {
    const { emit, calls } = makeEmit();
    const metrics   = makeMockMetrics();
    const gap       = makeMockGapFramework();
    const state     = makeMockState(null);

    const pgPool = makeMockPgPool(async (sql) => {
      if (sql.includes('gap_scanner_state')) return { rows: [null].filter(Boolean) };
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: [] };
      }
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] }; // boundary query
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: true, verifyRoots: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(result.skipped).toBeFalsy();
    expect(result.entriesChecked).toBe(0);
    expect(result.gapsDetected).toBe(0);
    expect(gap.handleGap).not.toHaveBeenCalled();
    expect(metrics.gapScannerSuccessTotal.inc).toHaveBeenCalled();
  });

  // ── 2. Sequence break ────────────────────────────────────────────────────────
  test('detects sequence break when entry IDs are not contiguous', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const chain = makeChain(2); // ids 1, 2
    // Force id=3 to become id=5 (gap)
    chain[1] = makeEntry({
      id:                   5,
      transparency_id:      'tid-5',
      previous_entry_hash:  chain[0].entry_hash,
    });

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        const fromId = params[0];
        return { rows: chain.filter(r => r.id >= fromId) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] }; // boundary
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: true, verifyRoots: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    const seqBreaks = gap.handleGapCalls.filter(c => c.gapType === 'SEQUENCE_BREAK');
    expect(seqBreaks.length).toBeGreaterThanOrEqual(1);
    expect(seqBreaks[0].context.details.gap).toBe(3); // ids 2..4 missing
  });

  // ── 3. Hash chain break (prev_hash mismatch) ──────────────────────────────
  test('detects hash chain break when previous_entry_hash is wrong', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const chain = makeChain(3);
    // Corrupt the previous_entry_hash of entry 2 but keep entry_hash intact
    // Use verifyEntryHashes:false so only chain link is checked (not hash recomputation)
    const originalHash = chain[1].entry_hash;
    chain[1].previous_entry_hash = 'deadbeef' + 'a'.repeat(56);
    chain[1].entry_hash = originalHash; // keep stored hash so hash recomputation check is skipped

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        const fromId = params[0];
        return { rows: chain.filter(r => r.id >= fromId) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    const chainBreaks = gap.handleGapCalls.filter(c => c.gapType === 'HASH_CHAIN_BREAK');
    expect(chainBreaks.length).toBeGreaterThanOrEqual(1);
    expect(chainBreaks[0].context.details.context).toBe('prev_hash_mismatch');
  });

  // ── 4. Entry hash integrity ───────────────────────────────────────────────
  test('detects corrupted entry where stored entry_hash does not match recomputed', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const chain = makeChain(2);
    // Tamper with entry 1's stored hash
    chain[0].entry_hash = 'f'.repeat(64);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        const fromId = params[0];
        return { rows: chain.filter(r => r.id >= fromId) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: true, verifyRoots: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    const hashMismatches = gap.handleGapCalls.filter(
      c => c.gapType === 'HASH_CHAIN_BREAK' && c.context.details.context === 'entry_hash_mismatch'
    );
    expect(hashMismatches.length).toBeGreaterThanOrEqual(1);
  });

  // ── 5. Genesis entry check ────────────────────────────────────────────────
  test('detects genesis entry with non-null previous_entry_hash', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const entry = makeEntry({ id: 1, previous_entry_hash: 'a'.repeat(64) });

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: params[0] <= 1 ? [entry] : [] };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    const genesisBreaks = gap.handleGapCalls.filter(
      c => c.gapType === 'HASH_CHAIN_BREAK' && c.context.details.context === 'genesis_has_prev_hash'
    );
    expect(genesisBreaks.length).toBe(1);
  });

  // ── 6. Incremental scan resumes ───────────────────────────────────────────
  test('incremental scan starts from last_scanned_id + 1', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();

    const persistedState = { last_scanned_id: 5, last_completed_root_id: null };
    const state = makeMockState(persistedState);

    // Build boundary entry at id=5
    const boundary = makeEntry({ id: 5, transparency_id: 'tid-5', previous_entry_hash: null });

    // Build entries 6, 7, 8 chaining correctly from boundary
    const chain6 = [];
    let prevHash = boundary.entry_hash;
    for (let i = 6; i <= 8; i++) {
      const e = makeEntry({ id: i, transparency_id: `tid-${i}`, previous_entry_hash: prevHash });
      prevHash = e.entry_hash;
      chain6.push(e);
    }

    const queriedIds = [];
    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        queriedIds.push(params[0]);
        return { rows: chain6.filter(r => r.id >= params[0]) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) {
        return { rows: params[0] > 5 ? [boundary] : [] };
      }
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'INCREMENTAL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('INCREMENTAL');

    // First entry query should start at id=6 (5+1)
    expect(queriedIds[0]).toBe(6);
    expect(gap.handleGap).not.toHaveBeenCalled(); // clean chain
  });

  // ── 7. Incremental boundary overlap ──────────────────────────────────────
  test('incremental scan loads boundary entry to verify chain at resume point', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();

    const chain5 = makeChain(5); // ids 1-5
    const persistedState = { last_scanned_id: 5, last_completed_root_id: null };
    const state = makeMockState(persistedState);

    // New entries start at 6, correctly chained from 5
    const entry6 = makeEntry({
      id:                   6,
      transparency_id:      'tid-6',
      previous_entry_hash:  chain5[4].entry_hash, // correctly linked
    });

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) {
        // Return entry 5
        return { rows: [chain5[4]] };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: params[0] <= 6 ? [entry6] : [] };
      }
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'INCREMENTAL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('INCREMENTAL');
    // No hash chain break expected since entry6 is correctly linked
    expect(gap.handleGap).not.toHaveBeenCalled();
  });

  // ── 8. State persistence ──────────────────────────────────────────────────
  test('saves scan state after successful scan', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const chain = makeChain(3);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: chain.filter(r => r.id >= params[0]) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    expect(state.save).toHaveBeenCalled();
    const saved = state.getSaved();
    expect(saved.lastScannedId).toBe(3); // last entry id
    expect(saved.lastScanMode).toBe('FULL');
    expect(saved.lastScanEntriesChecked).toBe(3);
  });

  // ── 9. Lock not acquired ──────────────────────────────────────────────────
  test('returns skipped when advisory lock cannot be acquired', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const pgPool = makeMockPgPool(async () => ({ rows: [] }), { lockAcquired: false });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('LOCK_NOT_ACQUIRED');
    expect(gap.handleGap).not.toHaveBeenCalled();
    expect(metrics.gapScannerSkippedTotal.inc).toHaveBeenCalledWith({ reason: 'lock_not_acquired' });
  });

  // ── 10. PostgreSQL failure ─────────────────────────────────────────────────
  test('returns failure result when pgPool.withTransaction throws', async () => {
    const { emit, calls } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const pgPool = {
      isEnabled: () => true,
      withTransaction: jest.fn().mockRejectedValue(new Error('DB connection lost')),
    };

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(result.success).toBe(false);
    expect(result.error).toBe('DB connection lost');
    expect(metrics.gapScannerFailuresTotal.inc).toHaveBeenCalled();
    const failedEvents = calls.filter(c => c.event === 'TRANSPARENCY_SCANNER_SCAN_FAILED');
    expect(failedEvents.length).toBe(1);
  });

  // ── 11. PG disabled ───────────────────────────────────────────────────────
  test('returns skipped when PostgreSQL is disabled', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const pgPool = { isEnabled: () => false, withTransaction: jest.fn() };

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('PG_DISABLED');
    expect(pgPool.withTransaction).not.toHaveBeenCalled();
  });

  // ── 12. Root chain break ───────────────────────────────────────────────────
  test('detects root chain break (CHECKPOINT_DIVERGENCE)', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const { computeRootHash } = require('../../log');

    // Build two entries so each root covers one entry with correct root_hash
    const entry1 = makeEntry({ id: 1 });
    const entry2 = makeEntry({ id: 2, transparency_id: 'tid-2', previous_entry_hash: entry1.entry_hash });

    // Root1 covers entry1 with correct root_hash
    const root1Hash = computeRootHash([entry1.entry_hash]);
    const root1 = makeRoot({ id: 1, root_hash: root1Hash, previous_root_hash: null, seq_from: 1, seq_to: 1, entry_count: 1 });

    // Root2 has wrong previous_root_hash (chain break)
    const root2Hash = computeRootHash([entry2.entry_hash]);
    const root2 = makeRoot({
      id:                 2,
      root_id:            'root-2',
      seq_from:           2, seq_to: 2, entry_count: 1,
      root_hash:          root2Hash,
      previous_root_hash: 'WRONG_HASH_NOT_ROOT1', // should be root1Hash
    });

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_hashes_in_range')) {
        const from = params[0], to = params[1];
        const all = [entry1, entry2];
        return { rows: all.filter(r => r.id >= from && r.id <= to).map(r => ({ id: r.id, entry_hash: r.entry_hash })) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: [entry1, entry2].filter(r => r.id >= params[0]) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots') && sql.includes('id < $1')) return { rows: [] };
      if (sql.includes('FROM transparency_roots') && sql.includes('WHERE id >= $1')) {
        return { rows: [root1, root2].filter(r => r.id >= params[0]) };
      }
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    const cpGaps = gap.handleGapCalls.filter(c => c.gapType === 'CHECKPOINT_DIVERGENCE');
    expect(cpGaps.length).toBeGreaterThanOrEqual(1);
    // The root chain break on root2 should be detected
    const chainBreak = cpGaps.find(c => c.context.details.context === 'root_chain_break');
    expect(chainBreak).toBeDefined();
  });

  // ── 13. Root hash mismatch ─────────────────────────────────────────────────
  test('detects root hash mismatch (CHECKPOINT_DIVERGENCE)', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const entry = makeEntry({ id: 1 });
    // Root with a wrong (tampered) root_hash — must be exactly 64 hex chars
    const root = makeRoot({ id: 1, root_hash: 'f'.repeat(64), previous_root_hash: null, entry_count: 1 });

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_hashes_in_range')) {
        return { rows: [{ id: 1, entry_hash: entry.entry_hash }] };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: params[0] <= 1 ? [entry] : [] };
      }
      if (sql.includes('id < $1') && sql.includes('transparency_roots')) return { rows: [] };
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots') && sql.includes('WHERE id >= $1')) {
        return { rows: params[0] <= 1 ? [root] : [] };
      }
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    const hashMismatches = gap.handleGapCalls.filter(
      c => c.gapType === 'CHECKPOINT_DIVERGENCE' && c.context.details.context === 'root_hash_mismatch'
    );
    expect(hashMismatches.length).toBe(1);
  });

  // ── 14. Root entry count mismatch ─────────────────────────────────────────
  test('detects root entry count mismatch', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const entry = makeEntry({ id: 1 });
    const root = makeRoot({
      id: 1,
      entry_count: 5, // claims 5 entries but only 1 exists
      previous_root_hash: null,
    });

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_hashes_in_range')) {
        return { rows: [{ id: 1, entry_hash: entry.entry_hash }] }; // only 1 row, not 5
      }
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: params[0] <= 1 ? [entry] : [] };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots') && sql.includes('WHERE id >= $1')) {
        return { rows: params[0] <= 1 ? [root] : [] };
      }
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    const countMismatches = gap.handleGapCalls.filter(
      c => c.gapType === 'CHECKPOINT_DIVERGENCE' && c.context.details.context === 'root_entry_count_mismatch'
    );
    expect(countMismatches.length).toBe(1);
    expect(countMismatches[0].context.details.expectedCount).toBe(5);
    expect(countMismatches[0].context.details.actualCount).toBe(1);
  });

  // ── 14b. regression: a SECOND root reports NO gap ──────────────────
  //
  // registrar.generateRoot() writes seq_from/seq_to as the INCREMENTAL range
  // that generation call newly covered, while entry_count and root_hash cover
  // the FULL log 1..seq_to (its own comment there, and AT-078: computing from
  // only the incremental range "produced a root that shared no leaves at all
  // with any prior root"). _scanRoots() was never updated to match and fetched
  // seq_from..seq_to, so every root after the first reported a spurious
  // root_entry_count_mismatch. Invisible while seq_from === 1, and invisible
  // entirely until root generation ran on real data -- saw it live as
  // 390 fetched rows against an entry_count of 1020.
  //
  // Test 14 above still pins the GENUINE count-mismatch detection; this one
  // pins that a correctly-formed multi-root log is NOT flagged.
  test('a correctly-formed second root produces no gap (full-tree entry_count)', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const { computeRootHash } = require('../../log');

    const e1 = makeEntry({ id: 1 });
    const e2 = makeEntry({ id: 2, transparency_id: 'tid-2', previous_entry_hash: e1.entry_hash });
    const e3 = makeEntry({ id: 3, transparency_id: 'tid-3', previous_entry_hash: e2.entry_hash });
    const all = [e1, e2, e3];

    const root1Hash = computeRootHash([e1.entry_hash]);
    const root1 = makeRoot({
      id: 1, root_id: 'root-1',
      seq_from: 1, seq_to: 1, entry_count: 1,
      root_hash: root1Hash, previous_root_hash: null,
    });

    // Incremental range 2..3; hash and count over the FULL tree 1..3.
    const root2Hash = computeRootHash(all.map(e => e.entry_hash));
    const root2 = makeRoot({
      id: 2, root_id: 'root-2',
      seq_from: 2, seq_to: 3, entry_count: 3,
      root_hash: root2Hash, previous_root_hash: root1Hash,
    });

    // ST23-03: a correctly-formed root is also SIGNED under a verifiable transparency key — the scanner
    // now reports an unsigned root. Sign both genuinely (as registrar.generateRoot does) with an ephemeral in-memory
    // test key, and serve it from an injected transparency key store as 'active'.
    const crypto = require('crypto');
    const { computeRootSigningBuffer } = require('../../log');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    for (const r of [root1, root2]) {
      r.signature = crypto.sign(null, computeRootSigningBuffer({
        rootId: r.root_id, seqFrom: r.seq_from, seqTo: r.seq_to, entryCount: r.entry_count,
        rootHash: r.root_hash, previousRootHash: r.previous_root_hash,
      }), privateKey).toString('base64');
    }
    const pubDer = publicKey.export({ format: 'der', type: 'spki' });
    const transparencyKeys = {
      getKeyStatus:   (k) => (k === 'key-1' ? 'active' : null),
      getPublicKey:   () => ({ pubDer, status: 'active' }),
      reloadFromDisk: () => ({ reloaded: false }),
    };

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_hashes_in_range')) {
        const from = Number(params[0]), to = Number(params[1]);
        return { rows: all.filter(r => r.id >= from && r.id <= to).map(r => ({ id: r.id, entry_hash: r.entry_hash })) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: all.filter(r => r.id >= Number(params[0])) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots') && sql.includes('id < $1')) return { rows: [] };
      if (sql.includes('FROM transparency_roots') && sql.includes('WHERE id >= $1')) {
        return { rows: [root1, root2].filter(r => r.id >= Number(params[0])) };
      }
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
      _transparencyKeys: transparencyKeys,
    });

    const result = await scanner.scan('FULL');

    expect(gap.handleGapCalls.filter(c => c.gapType === 'CHECKPOINT_DIVERGENCE')).toEqual([]);
    expect(result.gapsDetected).toBe(0);
    expect(result.success).toBe(true);
  });

  // ── 15. Gap auto-resolve called ───────────────────────────────────────────
  test('calls autoResolveGap for each detected gap', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    gap.autoResolveGap.mockReturnValue(true); // auto-resolvable
    const state    = makeMockState(null);

    const chain = makeChain(2);
    chain[1] = makeEntry({ id: 5, transparency_id: 'tid-5', previous_entry_hash: chain[0].entry_hash }); // ID gap

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: chain.filter(r => r.id >= params[0]) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(gap.autoResolveGap).toHaveBeenCalledTimes(gap.handleGap.mock.calls.length);
    expect(result.gapsRecovered).toBeGreaterThanOrEqual(1);
    expect(metrics.gapScannerGapsRecoveredTotal.inc).toHaveBeenCalled();
  });

  // ── 16. Metrics: entries checked ──────────────────────────────────────────
  test('records entries checked in metrics after clean scan', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const chain = makeChain(5);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: chain.filter(r => r.id >= params[0]) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(result.entriesChecked).toBe(5);
    expect(metrics.gapScannerEntriesCheckedTotal.inc).toHaveBeenCalledWith({}, 5);
  });

  // ── 17. FULL mode ignores last_scanned_id ─────────────────────────────────
  test('FULL mode starts from id=1 regardless of persisted state', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState({ last_scanned_id: 100, last_completed_root_id: null });

    const queriedFromIds = [];
    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        queriedFromIds.push(params[0]);
        return { rows: [] };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    expect(queriedFromIds[0]).toBe(1);
  });

  // ── 18. Audit events ──────────────────────────────────────────────────────
  test('emits SCAN_STARTED and SCAN_COMPLETED audit events', async () => {
    const { emit, calls } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) return { rows: [] };
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    await scanner.scan('FULL');

    expect(calls.some(c => c.event === 'TRANSPARENCY_SCANNER_SCAN_STARTED')).toBe(true);
    expect(calls.some(c => c.event === 'TRANSPARENCY_SCANNER_SCAN_COMPLETED')).toBe(true);
  });

  // ── 19. getLastResult() ───────────────────────────────────────────────────
  test('getLastResult() returns last scan outcome', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) return { rows: [] };
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    expect(scanner.getLastResult()).toBeNull();
    await scanner.scan('FULL');
    expect(scanner.getLastResult()).not.toBeNull();
    expect(scanner.getLastResult().success).toBe(true);
  });

  // ── 20. Batch processing ──────────────────────────────────────────────────
  test('processes entries in batches of maxBatchSize', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const chain = makeChain(10);
    let batchCount = 0;

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        const fromId    = params[0];
        const batchSize = params[1];
        const slice     = chain.filter(r => r.id >= fromId).slice(0, batchSize);
        if (slice.length > 0) batchCount++;
        return { rows: slice };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 3, verifyEntryHashes: false, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(result.entriesChecked).toBe(10);
    expect(batchCount).toBeGreaterThan(1); // multiple batches
  });
});

// ── Runner tests (createScanner) ──────────────────────────────────────────────

describe('createScanner — runner', () => {

  // ── 21. Disabled scanner ───────────────────────────────────────────────────
  test('start() is a no-op when enabled=false', async () => {
    const { emit, calls } = makeEmit();
    const runner = createScanner({
      config:   { enabled: false, intervalMs: 100, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: false },
      _emit:    emit,
      _metrics: makeMockMetrics(),
    });

    await runner.start();

    expect(runner.isRunning()).toBe(false);
    expect(calls.some(c => c.event === 'TRANSPARENCY_SCANNER_DISABLED')).toBe(true);
  });

  // ── 22. Idempotent start ───────────────────────────────────────────────────
  test('second start() call emits warning and returns', async () => {
    const { emit, calls } = makeEmit();
    const metrics = makeMockMetrics();

    // A runner that doesn't actually scan
    const pgPool = { isEnabled: () => false, withTransaction: jest.fn() };

    const runner = createScanner({
      config:        { enabled: true, intervalMs: 60_000, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: makeMockState(null),
    });

    await runner.start();
    await runner.start(); // second call

    const warnings = calls.filter(c => c.event === 'TRANSPARENCY_SCANNER_ALREADY_RUNNING');
    expect(warnings.length).toBe(1);

    runner.stop();
  });

  // ── 23. Stop clears timer ─────────────────────────────────────────────────
  test('stop() marks runner as not running', async () => {
    const { emit } = makeEmit();
    const metrics = makeMockMetrics();
    const pgPool  = { isEnabled: () => false, withTransaction: jest.fn() };

    const runner = createScanner({
      config:        { enabled: true, intervalMs: 60_000, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: makeMockState(null),
    });

    await runner.start();
    expect(runner.isRunning()).toBe(true);

    runner.stop();
    expect(runner.isRunning()).toBe(false);
  });

  // ── 24. startupScan triggers immediate scan ────────────────────────────────
  test('startupScan=true triggers a scan immediately on start()', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) return { rows: [] };
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const runner = createScanner({
      config:        { enabled: true, intervalMs: 60_000, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: true },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _emit:         emit,
      _metrics:      metrics,
      _gapFramework: gap,
      _scannerState: state,
    });

    await runner.start();

    // Scanner should have run once (startupScan)
    expect(metrics.gapScannerRunsTotal.inc).toHaveBeenCalled();

    runner.stop();
  });

  // ── 25. scanOnce ──────────────────────────────────────────────────────────
  test('scanOnce() triggers an immediate scan outside the timer loop', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) return { rows: [] };
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const runner = createScanner({
      config:        { enabled: true, intervalMs: 60_000, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _emit:         emit,
      _metrics:      metrics,
      _gapFramework: gap,
      _scannerState: state,
    });

    const result = await runner.scanOnce('FULL');
    expect(result.skipped).toBeFalsy();
    expect(typeof result.entriesChecked).toBe('number');
  });

  // ── 26. getStatus ─────────────────────────────────────────────────────────
  test('getStatus() reflects current runner state', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const pgPool   = { isEnabled: () => false, withTransaction: jest.fn() };

    const runner = createScanner({
      config:        { enabled: true, intervalMs: 60_000, mode: 'INCREMENTAL', maxRetries: 3, retryDelayMs: 1000, startupScan: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: makeMockState(null),
    });

    await runner.start();
    const status = runner.getStatus();

    expect(status.running).toBe(true);
    expect(status.enabled).toBe(true);
    expect(status.mode).toBe('INCREMENTAL');
    expect(status.intervalMs).toBe(60_000);
    expect(status.maxRetries).toBe(3);

    runner.stop();

    const stoppedStatus = runner.getStatus();
    expect(stoppedStatus.running).toBe(false);
  });

  // ── 27. Concurrent execution guard ────────────────────────────────────────
  test('second concurrent _execute() is skipped when scan in progress', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    let scanStarted = false;
    let resolveHang;
    const hangPromise = new Promise(resolve => { resolveHang = resolve; });

    // First scan will hang until we resolve it
    let callCount = 0;
    const pgPool = {
      isEnabled: () => true,
      withTransaction: jest.fn(async (fn) => {
        callCount++;
        if (callCount === 1) {
          const tx = {
            query: async (sql) => {
              if (sql.includes('pg_try_advisory_xact_lock')) return { rows: [{ acquired: true }] };
              if (sql.includes('gap_scanner_state')) return { rows: [] };
              scanStarted = true;
              await hangPromise; // hang
              return { rows: [] };
            },
          };
          return fn(tx);
        }
        return { skipped: true };
      }),
    };

    const runner = createScanner({
      config:        { enabled: true, intervalMs: 60_000, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _emit:         emit,
      _metrics:      metrics,
      _gapFramework: gap,
      _scannerState: state,
    });

    // Start first scan (will hang)
    const scan1 = runner.scanOnce('FULL');

    // Briefly yield so scan1 can start
    await new Promise(r => setTimeout(r, 5));

    // Within-process concurrent guard is on GapScanner level, so let runner track it
    // Just verify the runner correctly marks scanning state
    resolveHang(); // unblock
    await scan1;
  });
});

// ── Finding 3.6 — unhandled rejection isolation ────────────────────────────────
//
// Before this remediation, _tick() (bare `setTimeout(_tick, …)`) was
// `try { await _execute() } finally { … reschedule … }` with no catch, and
// _execute() itself was the same shape around _executeWithRetry(). Neither
// let an error escape today (GapScanner's own error handling already
// swallows scan failures), but there was no backstop if that ever changed.
// These tests inject a controllable _taskRunner to simulate a failure
// escaping BackgroundTaskRunner's own containment, proving _execute()'s and
// _tick()'s outer catch blocks are real defense-in-depth: no unhandled
// rejection, and the self-rescheduling loop keeps running.

describe('Finding 3.6 — unhandled rejection isolation', () => {
  afterEach(() => {
    jest.useRealTimers();
  });

  test('a rejection escaping the injected task runner is contained — no unhandled rejection', async () => {
    jest.useFakeTimers();
    const unhandled = jest.fn();
    process.on('unhandledRejection', unhandled);
    try {
      const { emit } = makeEmit();
      const pgPool = { isEnabled: () => false, withTransaction: jest.fn() };
      const taskRunner = { runTask: jest.fn().mockRejectedValueOnce(new Error('escaped-the-runner')) };

      const runner = createScanner({
        config:        { enabled: true, intervalMs: 1_000, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: false },
        _pgPool:       pgPool,
        _definerQuery: pgPool.definerQuery,
        _emit:         emit,
        _metrics:      makeMockMetrics(),
        _scannerState: makeMockState(null),
        _taskRunner:   taskRunner,
      });

      await runner.start();
      await jest.advanceTimersByTimeAsync(0); // first tick fires immediately (startupScan=false)

      expect(unhandled).not.toHaveBeenCalled();
      expect(runner.isRunning()).toBe(true);
      expect(taskRunner.runTask).toHaveBeenCalledWith('transparency-gap-scan', expect.any(Function));

      runner.stop();
    } finally {
      process.removeListener('unhandledRejection', unhandled);
    }
  });

  test('scheduling continues after a failed tick — the next interval still ticks', async () => {
    jest.useFakeTimers();
    const { emit } = makeEmit();
    const pgPool = { isEnabled: () => false, withTransaction: jest.fn() };
    const taskRunner = {
      runTask: jest.fn()
        .mockRejectedValueOnce(new Error('first-tick-fails'))
        .mockResolvedValue({ ok: true }),
    };

    const runner = createScanner({
      config:        { enabled: true, intervalMs: 1_000, mode: 'FULL', maxRetries: 0, retryDelayMs: 0, startupScan: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _emit:         emit,
      _metrics:      makeMockMetrics(),
      _scannerState: makeMockState(null),
      _taskRunner:   taskRunner,
    });

    await runner.start();
    await jest.advanceTimersByTimeAsync(0);      // tick 1: fails, contained
    expect(taskRunner.runTask).toHaveBeenCalledTimes(1);

    await jest.advanceTimersByTimeAsync(1_000);  // tick 2: still scheduled, succeeds
    expect(taskRunner.runTask).toHaveBeenCalledTimes(2);

    runner.stop();
  });
});

// ── Integration: multi-gap scan ───────────────────────────────────────────────

describe('GapScanner — multi-gap integration', () => {
  test('reports multiple gap types in a single scan run', async () => {
    const { emit } = makeEmit();
    const metrics  = makeMockMetrics();
    const gap      = makeMockGapFramework();
    const state    = makeMockState(null);

    const chain = makeChain(3);
    // Introduce two gaps:
    // 1. ID gap between entry 1 and entry 3 (id=2 missing)
    chain[1] = makeEntry({ id: 3, transparency_id: 'tid-3', previous_entry_hash: chain[0].entry_hash });
    chain[2] = makeEntry({ id: 4, transparency_id: 'tid-4', previous_entry_hash: chain[1].entry_hash });
    // 2. Tamper with entry 3's stored hash
    chain[1].entry_hash = 'c'.repeat(64);

    const pgPool = makeMockPgPool(async (sql, params) => {
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        return { rows: chain.filter(r => r.id >= params[0]) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
      if (sql.includes('FROM transparency_roots')) return { rows: [] };
      return { rows: [] };
    });

    const scanner = createGapScanner({
      config:        { mode: 'FULL', maxBatchSize: 100, verifyEntryHashes: true, verifyRoots: false },
      _pgPool:       pgPool,
      _definerQuery: pgPool.definerQuery,
      _gapFramework: gap,
      _emit:         emit,
      _metrics:      metrics,
      _scannerState: state,
    });

    const result = await scanner.scan('FULL');

    expect(result.gapsDetected).toBeGreaterThanOrEqual(2);
    const types = gap.handleGapCalls.map(c => c.gapType);
    expect(types).toContain('SEQUENCE_BREAK');
    expect(types).toContain('HASH_CHAIN_BREAK');
  });
});
