'use strict';

/**
 * Live Enforcement → Transparency Log bridge — remediation tests.
 *
 * enforcementBridge.js is the module aiChat.js and streamEnforcer.js call to
 * register a transparency log leaf for every finalized /ai/chat enforcement
 * decision. These tests exercise it against the REAL registrar.js/logStore.js/
 * log.js/merkle.js stack (only the PostgreSQL pool is mocked, as an
 * in-memory, stateful, order-preserving fake — not per-call canned
 * responses) so the assertions below reflect genuine Merkle behavior, not a
 * mocked illusion of it.
 *
 * ENF-BR-01…03   Leaf payload shape: no secrets, no prompt text, correct entryType
 * ENF-BR-04…06   EXECUTE (ALLOW) and DENY (BLOCK) each create a transparency entry
 * ENF-BR-07      No duplicate entries for repeated distinct calls
 * ENF-BR-08…10   Tree size / root hash update correctly across multiple entries
 * ENF-BR-11      Inclusion proof for an enforcement-decision leaf validates
 * ENF-BR-12      Concurrent requests append correctly (chain stays valid, no corruption)
 * ENF-BR-13      Restart/recovery: root generation after a simulated process
 *                restart is consistent with pre-restart state (persistence-only design)
 */

const { randomUUID } = require('crypto');

// ── Stateful, in-memory fake PostgreSQL pool ──────────────────────────────────
//
// Unlike log.test.js's per-call mockResolvedValueOnce sequencing (appropriate
// for unit-testing registrar.js in isolation), this fake actually stores rows
// across calls so multi-entry, concurrency, and "restart" behavior can be
// observed end-to-end through the real registrar/logStore/log/merkle stack.
// Variable must be prefixed `mock` for Jest's module-factory hoisting rule.
const mockStatefulPool = (function _buildStatefulPool() {
  const entries = [];
  const roots   = [];
  const merkleBlocks = []; // transparency_merkle_checkpoints
  let logHead   = { tail_hash: null, tail_id: 0 };
  let rootsHead = { tail_hash: null, tail_id: 0 };
  let _lock = Promise.resolve();
  // R1 transactional realism: a transaction that throws is rolled back, and named SAVEPOINTs snapshot the
  // stored state so ROLLBACK TO SAVEPOINT restores it exactly — as PostgreSQL does. The group-commit batch path
  // (registrar.js _commitBatch / _fastPathBatch / _perLeafBatch) depends on both.
  const _snap = () => ({ entries: entries.length, roots: roots.length, merkleBlocks: merkleBlocks.length,
    logHead: { ...logHead }, rootsHead: { ...rootsHead } });
  const _restore = (s) => {
    entries.length = s.entries; roots.length = s.roots; merkleBlocks.length = s.merkleBlocks;
    logHead = { ...s.logHead }; rootsHead = { ...s.rootsHead };
  };
  let _savepoints = new Map();
  // Same 15 columns and ON CONFLICT (entry_hash) DO NOTHING as logStore.appendEntry()/appendEntries().
  const _insertEntry = (p) => {
    if (entries.some((e) => e.entry_hash === p[8])) return null; // ON CONFLICT (entry_hash) DO NOTHING
    const row = {
      id: entries.length + 1,
      transparency_id: p[0], entry_type: p[1],
      artifact_id: p[2], evidence_chain_id: p[3], verification_id: p[4],
      payload: p[5], payload_hash: p[6],
      previous_entry_hash: p[7], entry_hash: p[8],
      signer_key_id: p[9], signer_key_version: p[10], signature: p[11],
      registered_by: p[12], tenant_id: p[13], created_at: p[14],
    };
    entries.push(row);
    return row;
  };

  const pool = {
    _enabled: true,
    _entries: entries,
    _roots:   roots,
    isEnabled() { return this._enabled; },

    query: jest.fn(async (sql, params) => {
      // FINDING-PG-TENANT-CONTEXT-WRITE-PATH: registrar.js now sets tenant
      // context (SELECT set_config(...)) immediately before the INSERT when
      // fullRecord.tenantId is non-null — see registrar.js. No-op here: this
      // fake pool doesn't model RLS/session GUCs at all, only row storage.
      if (sql.includes('set_config')) {
        return { rows: [{ set_config: params?.[0] ?? null }] };
      }

      // R1 group commit: SAVEPOINT <name> / RELEASE SAVEPOINT <name> / ROLLBACK TO SAVEPOINT <name>.
      const sp = /^\s*(SAVEPOINT|RELEASE SAVEPOINT|ROLLBACK TO SAVEPOINT)\s+([a-z_][a-z0-9_]*)\s*$/i.exec(sql);
      if (sp) {
        const [, verb, name] = sp;
        const v = verb.toUpperCase();
        if (v === 'SAVEPOINT') { _savepoints.set(name, _snap()); return { rows: [] }; }
        if (!_savepoints.has(name)) throw new Error(`enforcementBridge.test.js mock pool: savepoint "${name}" does not exist`);
        if (v === 'ROLLBACK TO SAVEPOINT') { _restore(_savepoints.get(name)); return { rows: [] }; } // savepoint stays
        _savepoints.delete(name); // RELEASE
        return { rows: [] };
      }

      // FINDING-EVIDENCE-CHAIN-FORK-RACE (migration 042): registrar.js
      // serializes through these dedicated pointer tables now, not a
      // FOR UPDATE lock on the ledgers' own last row — see logStore.js's
      // lockTransparencyLogHead()/lockTransparencyRootsHead(). Checked
      // before the plain 'transparency_log_entries'/'transparency_roots'
      // patterns below since 'transparency_roots_head' contains
      // 'transparency_roots' as a substring.
      if (sql.includes('FROM transparency_log_head') && sql.includes('FOR UPDATE')) {
        return { rows: [{ tail_hash: logHead.tail_hash, tail_id: String(logHead.tail_id) }] };
      }
      if (sql.includes('UPDATE transparency_log_head')) {
        logHead = { tail_hash: params[0], tail_id: params[1] };
        return { rows: [] };
      }
      if (sql.includes('FROM transparency_roots_head') && sql.includes('FOR UPDATE')) {
        return { rows: [{ tail_hash: rootsHead.tail_hash, tail_id: String(rootsHead.tail_id) }] };
      }
      if (sql.includes('UPDATE transparency_roots_head')) {
        rootsHead = { tail_hash: params[0], tail_id: params[1] };
        return { rows: [] };
      }
      if (sql.includes('SELECT seq_to FROM transparency_roots WHERE root_hash')) {
        const root = roots.find(r => r.root_hash === params[0]);
        return { rows: root ? [{ seq_to: root.seq_to }] : [] };
      }

      if (sql.includes('INSERT INTO transparency_log_entries')) {
        // Single-row (appendEntry: RETURNING id, transparency_id, created_at) or multi-row (R1 appendEntries:
        // 15 params per row, RETURNING ... entry_hash). Rows are inserted in VALUES order; conflicting rows are
        // skipped and absent from RETURNING, exactly like ON CONFLICT (entry_hash) DO NOTHING.
        if (!params || params.length === 0 || params.length % 15 !== 0) {
          throw new Error(`enforcementBridge.test.js mock pool: INSERT INTO transparency_log_entries with ${params ? params.length : 0} params (expected a multiple of 15)`);
        }
        const withHash = /RETURNING[^;]*entry_hash/i.test(sql);
        const rows = [];
        for (let o = 0; o < params.length; o += 15) {
          const row = _insertEntry(params.slice(o, o + 15));
          if (row) rows.push(withHash
            ? { id: row.id, transparency_id: row.transparency_id, created_at: row.created_at, entry_hash: row.entry_hash }
            : { id: row.id, transparency_id: row.transparency_id, created_at: row.created_at });
        }
        return { rows };
      }
      // logStore.js's getLatestEntry()/getEntriesInRange() now route
      // through SECURITY DEFINER functions (migration 050) instead of plain
      // SQL against transparency_log_entries directly — match on the
      // function names instead of the old inline predicates.
      if (sql.includes('qodiqa_transparency_log_latest_entry')) {
        return { rows: entries.length ? [entries[entries.length - 1]] : [] };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_range_full')) {
        const [from, to] = params;
        return { rows: entries.filter(e => e.id >= from && e.id <= to) };
      }
      // merkleCheckpoints.js — the id-ordered batch read (migration
      // 049) and the Merkle block checkpoint table (migration 059), modelled as
      // real storage like everything else in this fake.
      // Merkle construction reads only (id, entry_hash) through the
      // app-executable hash readers — same stored entries, projected.
      if (sql.includes('qodiqa_transparency_public_hashes_from_id')) {
        const [from, limit] = params;
        return { rows: entries.filter(e => e.id >= from).slice(0, limit).map(e => ({ id: e.id, entry_hash: e.entry_hash })) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_hashes_in_range')) {
        const [from, to] = params;
        return { rows: entries.filter(e => e.id >= from && e.id <= to).map(e => ({ id: e.id, entry_hash: e.entry_hash })) };
      }
      if (sql.includes('qodiqa_transparency_log_fetch_batch')) {
        const [from, limit] = params;
        return { rows: entries.filter(e => e.id >= from).slice(0, limit) };
      }
      if (sql.includes('FROM transparency_merkle_checkpoints')) {
        return { rows: merkleBlocks.filter(b => b.block_size === params[0]).sort((a, b) => a.block_index - b.block_index) };
      }
      if (sql.includes('INSERT INTO transparency_merkle_checkpoints')) {
        const [block_size, block_index, first_id, last_id, subtree_hash] = params;
        if (!merkleBlocks.some(b => b.block_size === block_size && b.block_index === block_index)) {
          merkleBlocks.push({ block_size, block_index, first_id, last_id, subtree_hash });
        }
        return { rows: [] };
      }
      if (sql.includes('INSERT INTO transparency_roots')) {
        const row = {
          id: roots.length + 1,
          root_id: params[0], seq_from: params[1], seq_to: params[2], entry_count: params[3],
          root_hash: params[4], previous_root_hash: params[5],
          signature: params[6], signer_key_id: params[7],
          generated_by: params[8], generated_at: params[9],
        };
        roots.push(row);
        return { rows: [{ id: row.id, root_id: row.root_id, generated_at: row.generated_at }] };
      }
      if (sql.includes('FROM transparency_roots') && sql.includes('ORDER BY id DESC LIMIT 1')) {
        return { rows: roots.length ? [roots[roots.length - 1]] : [] };
      }
      throw new Error('enforcementBridge.test.js mock pool: unhandled SQL: ' + sql);
    }),

    // Real Postgres serializes concurrent writers here via `SELECT ... FOR
    // UPDATE` on the dedicated transparency_log_head/transparency_roots_head
    // pointer row (migration 042; see logStore.lockTransparencyLogHead()/
    // lockTransparencyRootsHead()). A single promise-chained mutex
    // reproduces that same serialization guarantee for this in-memory fake,
    // without which two concurrent registerEnforcementDecision() calls
    // could both read "no latest entry" and both write
    // previousEntryHash=null — a race the real DB lock prevents. This is
    // what ENF-BR-12 actually verifies.
    withTransaction(fn, _opts) {
      const run = _lock.then(async () => {
        const begin = _snap();
        _savepoints = new Map();
        try {
          return await fn({ query: (sql, params) => pool.query(sql, params) });
        } catch (err) {
          _restore(begin); // ROLLBACK: nothing of a failed transaction stays visible
          throw err;
        } finally {
          _savepoints = new Map();
        }
      });
      _lock = run.catch(() => {});
      return run;
    },

    _reset() {
      entries.length = 0;
      roots.length = 0;
      merkleBlocks.length = 0;
      logHead   = { tail_hash: null, tail_id: 0 };
      rootsHead = { tail_hash: null, tail_id: 0 };
      _savepoints = new Map();
      pool.query.mockClear();
    },
    _logHead() { return { ...logHead }; },
  };
  return pool;
}());

// cross-tenant DEFINER reads now go through rolePools (qodiqa_system / qodiqa_reporting);
// the forwarder sends them to the same mocked pool and records which pool served each call.
jest.mock('../../../infra/postgres/rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../../../infra/postgres/pool')));
jest.mock('../../../infra/postgres/pool', () => mockStatefulPool);

jest.mock('../../../../services/logger', () => ({
  emit:                 jest.fn(),
  allowed:              jest.fn(),
  blocked:              jest.fn(),
  eventBus:             { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

jest.mock('../../transparencyGap', () => ({
  detectSequenceBreak: jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectPartialAppend: jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
}));

const { registerEnforcementDecision } = require('../enforcementBridge');
const registrar = require('../registrar');
const log       = require('../log');

beforeEach(() => {
  mockStatefulPool._reset();
});

function baseArgs(overrides = {}) {
  return {
    requestId:   randomUUID(),
    decision:    'ALLOW',
    reason:      'ALL_CHECKS_PASSED',
    stage:       'PROVIDER_EXECUTION',
    auditEntryHash: 'a'.repeat(64),
    inputHash:   'b'.repeat(64),
    signature:   'c'.repeat(88), // base64-looking placeholder, not a real signature
    policyHash:  'd'.repeat(64),
    verificationResult: true,
    tenantId:    'tenant-1',
    publicKeyId: 'default:key_v1',
    provider:    'openai',
    semantic:    { decision: 'ALLOW', reason: null, score: 0.1, matchedPolicies: [] },
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// ENF-BR-01…03  Leaf payload shape
// ═════════════════════════════════════════════════════════════════════════════

describe('ENF-BR-01…03: leaf payload never leaks secrets or prompt content', () => {
  test('ENF-BR-01: entryType is AUDIT, artifactId is the requestId', async () => {
    const requestId = randomUUID();
    const result = await registerEnforcementDecision(baseArgs({ requestId }));
    expect(result.persisted).toBe(true);
    const row = mockStatefulPool._entries[0];
    expect(row.entry_type).toBe('AUDIT');
    expect(row.artifact_id).toBe(requestId);
  });

  test('ENF-BR-02: payload never contains the raw signature or a "prompt" field', async () => {
    await registerEnforcementDecision(baseArgs({ signature: 'THIS-IS-THE-RAW-SIGNATURE-VALUE' }));
    const row = mockStatefulPool._entries[0];
    const payload = JSON.parse(row.payload);
    expect(JSON.stringify(payload)).not.toContain('THIS-IS-THE-RAW-SIGNATURE-VALUE');
    expect(payload).not.toHaveProperty('prompt');
    expect(payload).not.toHaveProperty('signature');
    expect(payload.signatureRef).toMatch(/^[0-9a-f]{64}$/);
  });

  test('ENF-BR-03: payload carries the required evidence fields', async () => {
    const args = baseArgs();
    await registerEnforcementDecision(args);
    const payload = JSON.parse(mockStatefulPool._entries[0].payload);
    expect(payload.requestId).toBe(args.requestId);
    expect(payload.decision).toBe('ALLOW');
    expect(payload.artifactHash).toBe(args.inputHash);
    expect(payload.policyHash).toBe(args.policyHash);
    expect(payload.auditEntryHash).toBe(args.auditEntryHash);
    expect(payload.publicKeyId).toBe(args.publicKeyId);
    expect(payload.provider).toBe(args.provider);
    expect(payload.tenantId).toBe(args.tenantId);
    expect(typeof payload.recordedAt).toBe('string');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENF-BR-04…06  EXECUTE and DENY both create entries
// ═════════════════════════════════════════════════════════════════════════════

describe('ENF-BR-04…06: EXECUTE and DENY decisions both create transparency entries', () => {
  test('ENF-BR-04: EXECUTE (ALLOW) request creates a transparency entry', async () => {
    const result = await registerEnforcementDecision(baseArgs({ decision: 'ALLOW' }));
    expect(result.persisted).toBe(true);
    expect(mockStatefulPool._entries).toHaveLength(1);
  });

  test('ENF-BR-05: DENY (BLOCK) request creates a transparency entry', async () => {
    const result = await registerEnforcementDecision(baseArgs({
      decision: 'BLOCK', reason: 'POLICY_BLOCKED', stage: 'POLICY_ENFORCEMENT', verificationResult: false,
    }));
    expect(result.persisted).toBe(true);
    const payload = JSON.parse(mockStatefulPool._entries[0].payload);
    expect(payload.decision).toBe('BLOCK');
    expect(payload.reason).toBe('POLICY_BLOCKED');
  });

  test('ENF-BR-06: BLOCK entries with no audit reference still register (auditEntryHash null)', async () => {
    const result = await registerEnforcementDecision(baseArgs({ decision: 'BLOCK', auditEntryHash: null }));
    expect(result.persisted).toBe(true);
    const payload = JSON.parse(mockStatefulPool._entries[0].payload);
    expect(payload.auditEntryHash).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENF-BR-07  No duplicate entries
// ═════════════════════════════════════════════════════════════════════════════

test('ENF-BR-07: two distinct decisions produce two distinct entryHashes, no duplicates', async () => {
  const r1 = await registerEnforcementDecision(baseArgs());
  const r2 = await registerEnforcementDecision(baseArgs());
  expect(r1.entryHash).not.toBe(r2.entryHash);
  expect(mockStatefulPool._entries).toHaveLength(2);
  const hashes = mockStatefulPool._entries.map(e => e.entry_hash);
  expect(new Set(hashes).size).toBe(2);
});

// ═════════════════════════════════════════════════════════════════════════════
// ENF-BR-08…10  Tree size / root hash grow correctly
// ═════════════════════════════════════════════════════════════════════════════

describe('ENF-BR-08…10: Merkle tree size and root update correctly across enforcement decisions', () => {
  test('ENF-BR-08: entryCount and rootHash after 1 entry', async () => {
    await registerEnforcementDecision(baseArgs());
    const root = await registrar.generateRoot({ generatedBy: 'test' });
    expect(root.entryCount).toBe(1);
    expect(root.rootHash).toBe(log.computeRootHash([mockStatefulPool._entries[0].entry_hash]));
  });

  test('ENF-BR-09: entryCount and rootHash after 5 mixed ALLOW/BLOCK entries', async () => {
    for (let i = 0; i < 5; i++) {
      await registerEnforcementDecision(baseArgs({ decision: i % 2 === 0 ? 'ALLOW' : 'BLOCK' }));
    }
    const root = await registrar.generateRoot({ generatedBy: 'test' });
    expect(root.entryCount).toBe(5);
    const expectedHashes = mockStatefulPool._entries.map(e => e.entry_hash);
    expect(root.rootHash).toBe(log.computeRootHash(expectedHashes));
  });

  test('ENF-BR-10: tree size and root strictly change as more entries are registered', async () => {
    await registerEnforcementDecision(baseArgs());
    const rootAfter1 = await registrar.generateRoot({ generatedBy: 'test' });

    await registerEnforcementDecision(baseArgs());
    await registerEnforcementDecision(baseArgs());
    const rootAfter3 = await registrar.generateRoot({ generatedBy: 'test' });

    expect(rootAfter3.entryCount).toBeGreaterThan(rootAfter1.entryCount);
    expect(rootAfter3.entryCount).toBe(3);
    expect(rootAfter3.rootHash).not.toBe(rootAfter1.rootHash);
    expect(rootAfter3.previousRootHash).toBe(rootAfter1.rootHash);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// ENF-BR-11  Inclusion proof validates
// ═════════════════════════════════════════════════════════════════════════════

test('ENF-BR-11: an inclusion proof for an enforcement-decision leaf validates', async () => {
  const targetTransparencyId = (await registerEnforcementDecision(baseArgs())).transparencyId;
  await registerEnforcementDecision(baseArgs());
  await registerEnforcementDecision(baseArgs());

  const root = await registrar.generateRoot({ generatedBy: 'test' });

  const targetRow = mockStatefulPool._entries.find(e => e.transparency_id === targetTransparencyId);
  const allHashes = mockStatefulPool._entries.map(e => e.entry_hash);

  const entryRecord = {
    transparencyId: targetRow.transparency_id, id: targetRow.id, entryType: targetRow.entry_type,
    artifactId: targetRow.artifact_id, evidenceChainId: targetRow.evidence_chain_id,
    verificationId: targetRow.verification_id, payloadHash: targetRow.payload_hash,
    previousEntryHash: targetRow.previous_entry_hash, entryHash: targetRow.entry_hash,
    signerKeyId: targetRow.signer_key_id, signature: targetRow.signature, createdAt: targetRow.created_at,
  };
  const rootRecord = {
    rootId: root.rootId, seqFrom: root.seqFrom, seqTo: root.seqTo, entryCount: root.entryCount,
    rootHash: root.rootHash, previousRootHash: root.previousRootHash,
    signerKeyId: root.keyId, signature: root.signature, generatedAt: new Date().toISOString(),
  };

  const proof = log.generateInclusionProof(entryRecord, allHashes, rootRecord);
  expect(proof.verifiable).toBe(true);

  const verification = log.verifyInclusionProof(proof);
  expect(verification.valid).toBe(true);
});

// ═════════════════════════════════════════════════════════════════════════════
// ENF-BR-12  Concurrent requests append correctly
// ═════════════════════════════════════════════════════════════════════════════

test('ENF-BR-12: concurrent enforcement decisions append correctly (valid, unbroken chain)', async () => {
  const N = 10;
  const gc0 = registrar.groupCommitStats(); // module-level counters: earlier tests in this file also registered
  const results = await Promise.all(
    Array.from({ length: N }, () => registerEnforcementDecision(baseArgs())),
  );

  expect(mockStatefulPool._entries).toHaveLength(N);
  // Every entryHash is unique — no lost updates / overwritten entries.
  expect(new Set(results.map(r => r.entryHash)).size).toBe(N);
  expect(new Set(mockStatefulPool._entries.map(e => e.entry_hash)).size).toBe(N);

  // The persisted chain (ordered by insertion / id) must be a single,
  // unbroken previousEntryHash linkage — i.e. concurrent writers did not
  // race past the FOR-UPDATE-style serialization and produce two entries
  // with the same previousEntryHash (a fork) or a gap.
  const sorted = [...mockStatefulPool._entries].sort((a, b) => a.id - b.id);
  expect(sorted[0].previous_entry_hash).toBeNull();
  for (let i = 1; i < sorted.length; i++) {
    expect(sorted[i].previous_entry_hash).toBe(sorted[i - 1].entry_hash);
  }

  const chainRecords = sorted.map(row => ({
    transparencyId: row.transparency_id, entryType: row.entry_type, artifactId: row.artifact_id,
    evidenceChainId: row.evidence_chain_id, verificationId: row.verification_id,
    payload: JSON.parse(row.payload), payloadHash: row.payload_hash,
    previousEntryHash: row.previous_entry_hash, entryHash: row.entry_hash,
    signerKeyId: row.signer_key_id, signature: row.signature,
  }));
  expect(log.validateChainContinuity(chainRecords).valid).toBe(true);

  // The head pointer names the last persisted leaf (both modes).
  const head = mockStatefulPool._logHead();
  expect(head.tail_hash).toBe(sorted[N - 1].entry_hash);
  expect(Number(head.tail_id)).toBe(sorted[N - 1].id);

  // Mode-specific: with R1 group commit ON (QODIQA_TRANSPARENCY_GROUP_COMMIT=true) the concurrent decisions must
  // actually have been batched — a multi-leaf batch on the multi-row fast path, with no fallback; with it OFF the
  // legacy one-transaction-per-leaf path ran and the batcher was never engaged.
  const sql = mockStatefulPool.query.mock.calls.map((c) => c[0]);
  const gc1 = registrar.groupCommitStats();
  const d = (k) => gc1[k] - gc0[k];
  if (process.env.QODIQA_TRANSPARENCY_GROUP_COMMIT === 'true') {
    expect(gc1.enabled).toBe(true);
    expect(d('entries')).toBe(N);
    expect(d('batches')).toBeLessThan(N);          // fewer transactions than leaves: real batching happened
    expect(gc1.maxBatch).toBeGreaterThan(1);
    expect(d('fastBatches')).toBeGreaterThanOrEqual(1);
    expect(d('fastFallbacks')).toBe(0);
    expect(d('batchFailures')).toBe(0);
    expect(d('leafFailures')).toBe(0);
    expect(sql.some((s) => /SAVEPOINT qodiqa_tgc_batch/.test(s))).toBe(true);
    expect(sql.some((s) => /INSERT INTO transparency_log_entries[\s\S]*VALUES\s*\([^)]*\)\s*,\s*\(/.test(s))).toBe(true);
    // one head update per batch, not per leaf
    expect(sql.filter((s) => s.includes('UPDATE transparency_log_head')).length).toBe(d('batches'));
  } else {
    expect(gc1.enabled).toBe(false);
    expect(gc1.batches).toBe(0);
    expect(sql.some((s) => /SAVEPOINT/.test(s))).toBe(false);
    expect(sql.filter((s) => s.includes('UPDATE transparency_log_head')).length).toBe(N);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ENF-BR-13  Restart/recovery preserves tree integrity
// ═════════════════════════════════════════════════════════════════════════════

test('ENF-BR-13: root generation after a simulated restart is consistent with pre-restart state', async () => {
  // "Pre-restart" process: register 2 decisions, generate a root.
  await registerEnforcementDecision(baseArgs());
  await registerEnforcementDecision(baseArgs());
  const preRestartRoot = await registrar.generateRoot({ generatedBy: 'pre-restart' });
  expect(preRestartRoot.entryCount).toBe(2);

  // Simulate a process restart: clear the module registry so registrar.js,
  // logStore.js, and log.js are re-executed from scratch (zero shared
  // in-process state) — but the mocked "PostgreSQL" pool (mockStatefulPool)
  // is unaffected, exactly as a real database survives a process restart.
  // The top-level jest.mock() factory closure still returns the SAME
  // mockStatefulPool instance on the next require(), which is what actually
  // simulates durable persistence here.
  jest.resetModules();
  const freshRegistrar = require('../registrar');
  const freshLog       = require('../log');
  const { registerEnforcementDecision: freshRegister } = require('../enforcementBridge');

  // A decision registered by the "restarted" process must chain off the
  // pre-restart tail, proving no state was lost.
  await freshRegister(baseArgs());
  const postRestartRoot = await freshRegistrar.generateRoot({ generatedBy: 'post-restart' });

  expect(postRestartRoot.previousRootHash).toBe(preRestartRoot.rootHash);
  expect(postRestartRoot.entryCount).toBe(3);

  const allHashes = mockStatefulPool._entries.map(e => e.entry_hash);
  expect(postRestartRoot.rootHash).toBe(freshLog.computeRootHash(allHashes));
});
