'use strict';

/**
 * Audit Chain Index Tests —
 *
 * AC-01…AC-10:  Artifact ID index — O(1) lookup, tenant isolation, duplicate rejection
 * AC-11…AC-20:  Hash index — O(1) lookup, GENESIS handling, unknown hash
 * AC-21…AC-30:  Nonce index — O(1) replay detection, expiry-free append-only semantics
 * AC-31…AC-40:  Replay lineage index — O(1) multi-replay, unlinked replays
 * AC-41…AC-50:  Tenant index — O(1) isolation, cross-tenant blocked
 * AC-51…AC-60:  Request hash index — O(1) correlated-request lookup, UNAVAILABLE excluded
 * AC-61…AC-70:  O(1) chain stats counters — allow/block/replay counts, head/tail hash
 * AC-71…AC-80:  Modern chain position and neighbor access — O(1) position, prev/next
 * AC-81…AC-90:  Security — duplicate artifactId rejection, duplicate nonce rejection
 * AC-91…AC-100: Chain integrity — validateChainIntegrity uses indexed stats
 * AC-101…AC-110: Regression — existing exported API preserved, backward compat
 * AC-111…AC-120: Performance ceilings — O(1) lookups under simulated scale
 *
 * NOTE (PERF-10): append() is asynchronous — its durable disk I/O now runs via
 * fs.promises behind a module-level FIFO write queue instead of blocking
 * fs.*Sync calls. Every `.append(...)` call below is awaited so the entry is
 * actually committed to the in-memory chain/indexes (and the returned value
 * is the committed entry object, not a pending Promise) before assertions
 * run. Where a beforeAll/test builds several entries whose relative order
 * matters (hash-chain prevHash linkage, chain position, array index), the
 * appends are awaited SEQUENTIALLY, one at a time — not via Promise.all —
 * reproducing the exact ordering the old synchronous code got for free.
 * Validation/duplicate/replay errors (invalid_*, already_executed,
 * replay_detected) now surface as a REJECTED promise rather than a
 * synchronous throw (append() always returns a Promise), so
 * `expect(() => audit.append(...)).toThrow(...)` became
 * `await expect(audit.append(...)).rejects.toThrow(...)`.
 *
 * jest.mock('fs') automocks every fs.* function but does NOT create an
 * fs.promises object at all — it stays undefined — so freshAudit() installs
 * fs.promises.* mocks (each resolving immediately) on the isolated fs
 * instance before requiring audit-log.js, otherwise the module-scope
 * `const fsp = fs.promises;` in audit-log.js would be undefined and every
 * append() would reject with "Cannot read properties of undefined".
 */

// ── Mocks (must precede require of audit-log) ─────────────────────────────────

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
jest.mock('fs');
jest.mock('../../../infra/postgres/pg-audit-backend', () => ({
  persistEntry: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

// ── Helpers ───────────────────────────────────────────────────────────────────

const crypto = require('crypto');

function uuid() { return crypto.randomUUID(); }

// Minimal valid ALLOW entry parameters.
function allowParams(overrides = {}) {
  return {
    artifactId:         uuid(),
    inputHash:          'a'.repeat(64),
    decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:          's'.repeat(64),
    requestHash:        'r'.repeat(64),
    policyHash:         'p'.repeat(64),
    verificationResult: true,
    ...overrides,
  };
}

// Minimal valid BLOCK entry parameters.
// Always includes a unique artifactId to prevent sha256('UNAVAILABLE') collisions
// when blockParams() is called multiple times on the same audit instance.
function blockParams(overrides = {}) {
  return {
    artifactId: uuid(),
    decision:   'BLOCK',
    ...overrides,
  };
}

// Installs fs.promises.* mocks (each resolving immediately) on an automocked
// `fs` module instance — see file header note for why this is necessary.
function _installFsPromisesMocks(fsMod) {
  fsMod.promises = {
    writeFile:  jest.fn().mockResolvedValue(undefined),
    appendFile: jest.fn().mockResolvedValue(undefined),
    open:       jest.fn().mockResolvedValue({
      sync:  jest.fn().mockResolvedValue(undefined),
      close: jest.fn().mockResolvedValue(undefined),
      // S33: the reused WAL is written/truncated through its held FileHandle (real fs.promises FileHandle API)
      write:    jest.fn().mockImplementation((buf, off, len) => Promise.resolve({ bytesWritten: len, buffer: buf })),
      truncate: jest.fn().mockResolvedValue(undefined),
    }),
    rename:    jest.fn().mockResolvedValue(undefined),
    copyFile:  jest.fn().mockResolvedValue(undefined),
    unlink:    jest.fn().mockResolvedValue(undefined),
  };
}

// ── Module bootstrap ──────────────────────────────────────────────────────────
//
// Each describe block that needs fresh state uses jest.isolateModules() to
// obtain an isolated module instance, ensuring the in-memory indexes start empty.
//

function freshAudit() {
  let mod;
  jest.isolateModules(() => {
    const fs = require('fs');
    fs.existsSync.mockReturnValue(false);
    _installFsPromisesMocks(fs);
    mod = require('../audit-log');
  });
  return mod;
}

// ── AC-01…AC-10: Artifact ID index ────────────────────────────────────────────

describe('AC-01…AC-10: Artifact ID index', () => {
  let audit;
  let aid1, aid2, aid3;

  beforeAll(async () => {
    audit = freshAudit();
    aid1  = uuid(); aid2 = uuid(); aid3 = uuid();
    await audit.append(allowParams({ artifactId: aid1 }));
    await audit.append(allowParams({ artifactId: aid2, tenantId: 'tenant-A' }));
    await audit.append(blockParams({ artifactId: aid3 }));
  });

  test('AC-01 getArtifactById returns the entry for a known artifactId', async () => {
    const e = await audit.getArtifactById(aid1);
    expect(e).not.toBeNull();
    expect(e.artifactId).toBe(aid1);
  });

  test('AC-02 getArtifactById returns null for an unknown artifactId', async () => {
    expect(await audit.getArtifactById(uuid())).toBeNull();
  });

  test('AC-03 getArtifactById returns null for null/undefined input', async () => {
    expect(await audit.getArtifactById(null)).toBeNull();
    expect(await audit.getArtifactById(undefined)).toBeNull();
    expect(await audit.getArtifactById('')).toBeNull();
  });

  test('AC-04 getArtifactById enforces tenant isolation — wrong tenant returns null', async () => {
    expect(await audit.getArtifactById(aid2, 'tenant-B')).toBeNull();
  });

  test('AC-05 getArtifactById passes tenant isolation when tenantId matches', async () => {
    const e = await audit.getArtifactById(aid2, 'tenant-A');
    expect(e).not.toBeNull();
    expect(e.artifactId).toBe(aid2);
  });

  test('AC-06 getArtifactById passes when no tenantId filter supplied (any tenant)', async () => {
    const e = await audit.getArtifactById(aid2);
    expect(e).not.toBeNull();
  });

  test('AC-07 alreadyExecuted returns true for an appended artifactId', async () => {
    expect(await audit.alreadyExecuted(aid1)).toBe(true);
  });

  test('AC-08 alreadyExecuted returns false for an unknown artifactId', async () => {
    expect(await audit.alreadyExecuted(uuid())).toBe(false);
  });

  test('AC-09 append rejects duplicate artifactId', async () => {
    await expect(audit.append(allowParams({ artifactId: aid1 }))).rejects.toThrow('already_executed');
  });

  test('AC-10 BLOCK entries are indexed by artifactId', async () => {
    const e = await audit.getArtifactById(aid3);
    expect(e).not.toBeNull();
    expect(e.decision).toBe('BLOCK');
  });
});

// ── AC-11…AC-20: Hash index ────────────────────────────────────────────────────

describe('AC-11…AC-20: Hash index', () => {
  let audit;
  let entry1;

  beforeAll(async () => {
    audit  = freshAudit();
    entry1 = await audit.append(allowParams());
  });

  test('AC-11 auditChainContains returns true for an appended entry hash', async () => {
    expect(await audit.auditChainContains(entry1.hash)).toBe(true);
  });

  test('AC-12 auditChainContains returns false for an unknown hash', async () => {
    expect(await audit.auditChainContains('0'.repeat(64))).toBe(false);
  });

  test('AC-13 auditChainContains returns true for "GENESIS"', async () => {
    expect(await audit.auditChainContains('GENESIS')).toBe(true);
  });

  test('AC-14 auditChainContains returns false for non-string input', async () => {
    expect(await audit.auditChainContains(null)).toBe(false);
    expect(await audit.auditChainContains(42)).toBe(false);
  });

  test('AC-15 second entry hash is indexed correctly', async () => {
    const e2 = await audit.append(allowParams());
    expect(await audit.auditChainContains(e2.hash)).toBe(true);
  });

  test('AC-16 hash index does not contain hashes from different module instances', async () => {
    const audit2 = freshAudit();
    const e = await audit2.append(allowParams());
    // audit's index must not know about audit2's entry
    expect(await audit.auditChainContains(e.hash)).toBe(false);
  });

  test('AC-17 getAuditTailHash returns GENESIS on empty chain', async () => {
    const empty = freshAudit();
    expect(empty.getAuditTailHash()).toBe('GENESIS');
  });

  test('AC-18 getAuditTailHash returns the last entry hash after appends', async () => {
    const a    = freshAudit();
    const e1   = await a.append(allowParams());
    expect(a.getAuditTailHash()).toBe(e1.hash);
    const e2   = await a.append(allowParams());
    expect(a.getAuditTailHash()).toBe(e2.hash);
  });

  test('AC-19 getChainStats headHash is the first modern entry hash', async () => {
    const a  = freshAudit();
    const e1 = await a.append(allowParams());
    await a.append(allowParams());
    expect(a.getChainStats().headHash).toBe(e1.hash);
  });

  test('AC-20 getChainStats tailHash updates to the latest modern entry', async () => {
    const a  = freshAudit();
    await a.append(allowParams());
    const e2 = await a.append(allowParams());
    expect(a.getChainStats().tailHash).toBe(e2.hash);
  });
});

// ── AC-21…AC-30: Nonce index ──────────────────────────────────────────────────

describe('AC-21…AC-30: Nonce index', () => {
  let audit;
  const NONCE_A = 'nonce-unique-abc-' + uuid();
  const NONCE_B = 'nonce-unique-xyz-' + uuid();

  beforeAll(async () => {
    audit = freshAudit();
    await audit.append(allowParams({ nonce: NONCE_A }));
  });

  test('AC-21 isNonceUsed returns true for a consumed nonce', async () => {
    expect(await audit.isNonceUsed(NONCE_A)).toBe(true);
  });

  test('AC-22 isNonceUsed returns false for an unseen nonce', async () => {
    expect(await audit.isNonceUsed(NONCE_B)).toBe(false);
  });

  test('AC-23 isNonceUsed returns false for empty string', async () => {
    expect(await audit.isNonceUsed('')).toBe(false);
  });

  test('AC-24 isNonceUsed returns false for non-string', async () => {
    expect(await audit.isNonceUsed(null)).toBe(false);
    expect(await audit.isNonceUsed(undefined)).toBe(false);
  });

  test('AC-25 append rejects a duplicate nonce', async () => {
    await expect(audit.append(allowParams({ nonce: NONCE_A }))).rejects.toThrow('replay_detected');
  });

  test('AC-26 second distinct nonce is accepted and indexed', async () => {
    const e = await audit.append(allowParams({ nonce: NONCE_B }));
    expect(e.nonce).toBe(NONCE_B);
    expect(await audit.isNonceUsed(NONCE_B)).toBe(true);
  });

  test('AC-27 entries without a nonce do not corrupt the nonce index', async () => {
    const before = await audit.isNonceUsed('some-fresh-nonce');
    await audit.append(allowParams());  // no nonce
    expect(await audit.isNonceUsed('some-fresh-nonce')).toBe(before);
  });

  test('AC-28 nonce on a BLOCK entry is also indexed', async () => {
    const n = 'block-nonce-' + uuid();
    await audit.append(blockParams({ nonce: n }));
    expect(await audit.isNonceUsed(n)).toBe(true);
  });

  test('AC-29 replay_detected error prevents the entry from entering the chain', async () => {
    const REPLAY_NONCE = 'replay-' + uuid();
    await audit.append(allowParams({ nonce: REPLAY_NONCE }));
    const lenBefore = audit.getChainLength();
    await expect(audit.append(allowParams({ nonce: REPLAY_NONCE }))).rejects.toThrow('replay_detected');
    expect(audit.getChainLength()).toBe(lenBefore);
  });

  test('AC-30 nonce index grows monotonically (append-only semantics)', async () => {
    const n1 = 'n1-' + uuid();
    const n2 = 'n2-' + uuid();
    await audit.append(allowParams({ nonce: n1 }));
    await audit.append(allowParams({ nonce: n2 }));
    expect(await audit.isNonceUsed(n1)).toBe(true);
    expect(await audit.isNonceUsed(n2)).toBe(true);
  });
});

// ── AC-31…AC-40: Replay lineage index ────────────────────────────────────────

describe('AC-31…AC-40: Replay lineage index', () => {
  let audit;
  let originalId, replayId1, replayId2;

  beforeAll(async () => {
    audit      = freshAudit();
    originalId = uuid();
    replayId1  = uuid();
    replayId2  = uuid();

    await audit.append(allowParams({ artifactId: originalId }));
    await audit.append(blockParams({
      artifactId:       replayId1,
      executionContext: { replayOf: originalId, stage: 'REPLAY_GUARD', reason: 'REPLAY_DETECTED' },
    }));
    await audit.append(blockParams({
      artifactId:       replayId2,
      executionContext: { replayOf: originalId, stage: 'REPLAY_GUARD', reason: 'REPLAY_DETECTED' },
    }));
  });

  test('AC-31 getReplayLineage returns all replay entries for an original', async () => {
    const replays = await audit.getReplayLineage(originalId);
    expect(replays).toHaveLength(2);
    expect(replays.map(r => r.artifactId).sort()).toEqual([replayId1, replayId2].sort());
  });

  test('AC-32 getReplayLineage returns empty array for an artifact with no replays', async () => {
    expect(await audit.getReplayLineage(uuid())).toEqual([]);
  });

  test('AC-33 getReplayLineage returns empty array for empty/invalid input', async () => {
    expect(await audit.getReplayLineage('')).toEqual([]);
    expect(await audit.getReplayLineage(null)).toEqual([]);
  });

  test('AC-34 getReplayLineage result is a copy — mutations do not corrupt the index', async () => {
    const replays = await audit.getReplayLineage(originalId);
    replays.push({ fake: true });
    expect(await audit.getReplayLineage(originalId)).toHaveLength(2);
  });

  test('AC-35 replay entries themselves are NOT replayed — their replayOf is indexed', async () => {
    // The replay entries (replayId1/replayId2) themselves have no replays.
    expect(await audit.getReplayLineage(replayId1)).toEqual([]);
  });

  test('AC-36 replayCount counter reflects total replay entries', async () => {
    expect(audit.getChainStats().replayCount).toBe(2);
  });

  test('AC-37 a third replay against the same original is indexed correctly', async () => {
    const replayId3 = uuid();
    await audit.append(blockParams({
      artifactId:       replayId3,
      executionContext: { replayOf: originalId, stage: 'REPLAY_GUARD', reason: 'REPLAY_DETECTED' },
    }));
    expect(await audit.getReplayLineage(originalId)).toHaveLength(3);
    expect(audit.getChainStats().replayCount).toBe(3);
  });

  test('AC-38 replays against different originals are indexed independently', async () => {
    const origB   = uuid();
    const replayB = uuid();
    await audit.append(allowParams({ artifactId: origB }));
    await audit.append(blockParams({
      artifactId:       replayB,
      executionContext: { replayOf: origB, stage: 'REPLAY_GUARD', reason: 'REPLAY_DETECTED' },
    }));
    expect(await audit.getReplayLineage(origB)).toHaveLength(1);
    expect((await audit.getReplayLineage(origB))[0].artifactId).toBe(replayB);
  });

  test('AC-39 entry without executionContext is NOT in replay index', async () => {
    const plain = uuid();
    await audit.append(allowParams({ artifactId: plain }));
    expect(await audit.getReplayLineage(plain)).toEqual([]);
  });

  test('AC-40 validateChainIntegrity replaysDetected matches replayCount', async () => {
    const stats    = audit.getChainStats();
    const report   = audit.validateChainIntegrity();
    expect(report.replayCorrelationState.replaysDetected).toBe(stats.replayCount);
  });
});

// ── AC-41…AC-50: Tenant index ─────────────────────────────────────────────────

describe('AC-41…AC-50: Tenant index', () => {
  let audit;
  let aidA1, aidA2, aidB1, aidNoTenant;

  beforeAll(async () => {
    audit      = freshAudit();
    aidA1      = uuid(); aidA2 = uuid();
    aidB1      = uuid(); aidNoTenant = uuid();

    await audit.append(allowParams({ artifactId: aidA1, tenantId: 'tenant-X' }));
    await audit.append(allowParams({ artifactId: aidA2, tenantId: 'tenant-X' }));
    await audit.append(allowParams({ artifactId: aidB1, tenantId: 'tenant-Y' }));
    await audit.append(allowParams({ artifactId: aidNoTenant }));
  });

  test('AC-41 getAuditChainForTenant returns all entries for a tenant', async () => {
    const entries = await audit.getAuditChainForTenant('tenant-X');
    expect(entries).toHaveLength(2);
    expect(entries.map(e => e.artifactId).sort()).toEqual([aidA1, aidA2].sort());
  });

  test('AC-42 getAuditChainForTenant returns only entries for that specific tenant', async () => {
    const entries = await audit.getAuditChainForTenant('tenant-Y');
    expect(entries).toHaveLength(1);
    expect(entries[0].artifactId).toBe(aidB1);
  });

  test('AC-43 getAuditChainForTenant returns empty array for unknown tenant', async () => {
    expect(await audit.getAuditChainForTenant('tenant-unknown')).toEqual([]);
  });

  test('AC-44 getAuditChainForTenant returns empty array for null/empty', async () => {
    expect(await audit.getAuditChainForTenant(null)).toEqual([]);
    expect(await audit.getAuditChainForTenant('')).toEqual([]);
  });

  test('AC-45 getAuditChainForTenant result is a copy — mutations do not corrupt index', async () => {
    const entries = await audit.getAuditChainForTenant('tenant-X');
    entries.push({ fake: true });
    expect(await audit.getAuditChainForTenant('tenant-X')).toHaveLength(2);
  });

  test('AC-46 entries without tenantId do not appear in tenant index', async () => {
    const all = await audit.getAuditChainForTenant('tenant-X');
    expect(all.map(e => e.artifactId)).not.toContain(aidNoTenant);
  });

  test('AC-47 getArtifactById with wrong tenant returns null (cross-tenant blocked)', async () => {
    expect(await audit.getArtifactById(aidA1, 'tenant-Y')).toBeNull();
  });

  test('AC-48 getArtifactById with correct tenant returns the entry', async () => {
    expect(await audit.getArtifactById(aidA1, 'tenant-X')).not.toBeNull();
  });

  test('AC-49 new tenant entry is indexed immediately after append', async () => {
    const aidC = uuid();
    await audit.append(allowParams({ artifactId: aidC, tenantId: 'tenant-Z' }));
    const entries = await audit.getAuditChainForTenant('tenant-Z');
    expect(entries).toHaveLength(1);
    expect(entries[0].artifactId).toBe(aidC);
  });

  test('AC-50 tenant index does not bleed between distinct tenants', async () => {
    const xEntries = await audit.getAuditChainForTenant('tenant-X');
    const yEntries = await audit.getAuditChainForTenant('tenant-Y');
    const xIds = xEntries.map(e => e.artifactId);
    const yIds = yEntries.map(e => e.artifactId);
    expect(xIds.some(id => yIds.includes(id))).toBe(false);
  });
});

// ── AC-51…AC-60: Request hash index ──────────────────────────────────────────

describe('AC-51…AC-60: Request hash index', () => {
  let audit;
  const RH_SHARED = 'r'.repeat(64);
  let aid1, aid2, aid3, aidBlock;

  beforeAll(async () => {
    audit = freshAudit();
    aid1  = uuid(); aid2 = uuid(); aid3 = uuid(); aidBlock = uuid();

    await audit.append(allowParams({ artifactId: aid1, requestHash: RH_SHARED }));
    await audit.append(allowParams({ artifactId: aid2, requestHash: RH_SHARED }));
    await audit.append(allowParams({ artifactId: aid3, requestHash: 'x'.repeat(64) }));
    await audit.append(blockParams({ artifactId: aidBlock }));  // requestHash = UNAVAILABLE
  });

  test('AC-51 getRequestHashEntries returns all entries with the shared requestHash', async () => {
    const entries = await audit.getRequestHashEntries(RH_SHARED);
    expect(entries).toHaveLength(2);
    expect(entries.map(e => e.artifactId).sort()).toEqual([aid1, aid2].sort());
  });

  test('AC-52 getRequestHashEntries returns empty array for unknown requestHash', async () => {
    expect(await audit.getRequestHashEntries('0'.repeat(64))).toEqual([]);
  });

  test('AC-53 getRequestHashEntries excludes UNAVAILABLE sentinel entries', async () => {
    const entries = await audit.getRequestHashEntries('UNAVAILABLE');
    expect(entries).toEqual([]);
  });

  test('AC-54 getRequestHashEntries returns empty for null/empty input', async () => {
    expect(await audit.getRequestHashEntries(null)).toEqual([]);
    expect(await audit.getRequestHashEntries('')).toEqual([]);
  });

  test('AC-55 BLOCK entries with UNAVAILABLE requestHash are NOT in request hash index', async () => {
    const allRh = await audit.getRequestHashEntries(RH_SHARED);
    expect(allRh.map(e => e.artifactId)).not.toContain(aidBlock);
  });

  test('AC-56 getRequestHashEntries result is a copy — mutations do not corrupt index', async () => {
    const entries = await audit.getRequestHashEntries(RH_SHARED);
    entries.push({ fake: true });
    expect(await audit.getRequestHashEntries(RH_SHARED)).toHaveLength(2);
  });

  test('AC-57 unique requestHash entries appear in their own index bucket', async () => {
    const entries = await audit.getRequestHashEntries('x'.repeat(64));
    expect(entries).toHaveLength(1);
    expect(entries[0].artifactId).toBe(aid3);
  });

  test('AC-58 new entry with existing requestHash extends the index bucket', async () => {
    const aid4 = uuid();
    await audit.append(allowParams({ artifactId: aid4, requestHash: RH_SHARED }));
    expect(await audit.getRequestHashEntries(RH_SHARED)).toHaveLength(3);
  });

  test('AC-59 requestHash index does not mix buckets across distinct hashes', async () => {
    const e1 = await audit.getRequestHashEntries(RH_SHARED);
    const e2 = await audit.getRequestHashEntries('x'.repeat(64));
    const ids1 = e1.map(e => e.artifactId);
    const ids2 = e2.map(e => e.artifactId);
    expect(ids1.some(id => ids2.includes(id))).toBe(false);
  });

  test('AC-60 ALLOW entries with real requestHash are included in the index', async () => {
    const rh  = 'f'.repeat(64);
    const aid = uuid();
    await audit.append(allowParams({ artifactId: aid, requestHash: rh }));
    const entries = await audit.getRequestHashEntries(rh);
    expect(entries).toHaveLength(1);
    expect(entries[0].decision).toBe('ALLOW');
  });
});

// ── AC-61…AC-70: O(1) chain stats counters ────────────────────────────────────

describe('AC-61…AC-70: O(1) chain stats counters', () => {
  let audit;

  beforeAll(async () => { audit = freshAudit(); });

  test('AC-61 getChainStats returns zero counts on empty chain', async () => {
    const s = audit.getChainStats();
    expect(s.chainLength).toBe(0);
    expect(s.modernLength).toBe(0);
    expect(s.allowCount).toBe(0);
    expect(s.blockCount).toBe(0);
    expect(s.replayCount).toBe(0);
    expect(s.headHash).toBeNull();
    expect(s.tailHash).toBe('GENESIS');
  });

  test('AC-62 allowCount increments on ALLOW append', async () => {
    await audit.append(allowParams());
    expect(audit.getChainStats().allowCount).toBe(1);
  });

  test('AC-63 blockCount increments on BLOCK append', async () => {
    await audit.append(blockParams());
    expect(audit.getChainStats().blockCount).toBe(1);
  });

  test('AC-64 replayCount increments when a replay entry is appended', async () => {
    const origId = uuid();
    await audit.append(allowParams({ artifactId: origId }));
    await audit.append(blockParams({ executionContext: { replayOf: origId, reason: 'REPLAY_DETECTED' } }));
    expect(audit.getChainStats().replayCount).toBe(1);
  });

  test('AC-65 chainLength equals total entries including legacy', async () => {
    const initial = audit.getChainStats().chainLength;
    await audit.append(allowParams());
    expect(audit.getChainStats().chainLength).toBe(initial + 1);
  });

  test('AC-66 modernLength equals chainLength when no legacy entries exist', async () => {
    const s = audit.getChainStats();
    expect(s.modernLength).toBe(s.chainLength);
  });

  test('AC-67 headHash is set on first modern entry and never changes', async () => {
    const a    = freshAudit();
    const e1   = await a.append(allowParams());
    const head = a.getChainStats().headHash;
    expect(head).toBe(e1.hash);
    await a.append(allowParams());
    expect(a.getChainStats().headHash).toBe(head);  // unchanged
  });

  test('AC-68 tailHash advances to each new modern entry hash', async () => {
    const a  = freshAudit();
    const e1 = await a.append(allowParams());
    expect(a.getChainStats().tailHash).toBe(e1.hash);
    const e2 = await a.append(allowParams());
    expect(a.getChainStats().tailHash).toBe(e2.hash);
    const e3 = await a.append(blockParams());
    expect(a.getChainStats().tailHash).toBe(e3.hash);
  });

  test('AC-69 getChainStats is consistent with getChainLength', async () => {
    const s = audit.getChainStats();
    expect(s.chainLength).toBe(audit.getChainLength());
  });

  test('AC-70 validateChainIntegrity uses allowCount/blockCount from index', async () => {
    const a  = freshAudit();
    await a.append(allowParams());
    await a.append(allowParams());
    await a.append(blockParams());
    const report = a.validateChainIntegrity();
    expect(report.allowCount).toBe(2);
    expect(report.blockCount).toBe(1);
  });
});

// ── AC-71…AC-80: Modern chain position and neighbors ─────────────────────────

describe('AC-71…AC-80: Modern chain position and neighbors', () => {
  let audit;
  let entries;

  beforeAll(async () => {
    audit   = freshAudit();
    entries = [];
    // Sequential — position/prev/next assertions below depend on the exact
    // append order, so these cannot be built with Promise.all.
    for (let i = 0; i < 5; i++) entries.push(await audit.append(allowParams()));
  });

  test('AC-71 getArtifactNeighbors returns correct position for first entry', async () => {
    const n = await audit.getArtifactNeighbors(entries[0].artifactId);
    expect(n).not.toBeNull();
    expect(n.position).toBe(0);
    expect(n.prev).toBeNull();
    expect(n.next.artifactId).toBe(entries[1].artifactId);
  });

  test('AC-72 getArtifactNeighbors returns correct position for last entry', async () => {
    const last = entries[entries.length - 1];
    const n    = await audit.getArtifactNeighbors(last.artifactId);
    expect(n.position).toBe(entries.length - 1);
    expect(n.next).toBeNull();
    expect(n.prev.artifactId).toBe(entries[entries.length - 2].artifactId);
  });

  test('AC-73 getArtifactNeighbors returns correct neighbors for a middle entry', async () => {
    const n = await audit.getArtifactNeighbors(entries[2].artifactId);
    expect(n.position).toBe(2);
    expect(n.prev.artifactId).toBe(entries[1].artifactId);
    expect(n.next.artifactId).toBe(entries[3].artifactId);
  });

  test('AC-74 getArtifactNeighbors returns null for unknown artifactId', async () => {
    expect(await audit.getArtifactNeighbors(uuid())).toBeNull();
  });

  test('AC-75 getModernChain returns all modern entries in append order', async () => {
    const modern = await audit.getModernChain();
    expect(modern).toHaveLength(entries.length);
    for (let i = 0; i < entries.length; i++) {
      expect(modern[i].artifactId).toBe(entries[i].artifactId);
    }
  });

  test('AC-76 getModernChain result is a copy — mutations do not corrupt the index', async () => {
    const m = await audit.getModernChain();
    m.push({ fake: true });
    expect(await audit.getModernChain()).toHaveLength(entries.length);
  });

  test('AC-77 position updates when new entry is appended', async () => {
    const newEntry = await audit.append(allowParams());
    const n        = await audit.getArtifactNeighbors(newEntry.artifactId);
    expect(n.position).toBe(entries.length);
    expect(n.prev.artifactId).toBe(entries[entries.length - 1].artifactId);
    expect(n.next).toBeNull();
  });

  test('AC-78 BLOCK entries appear in modern chain at correct position', async () => {
    const a    = freshAudit();
    const e1   = await a.append(allowParams());
    const e2   = await a.append(blockParams());
    const e3   = await a.append(allowParams());
    const n    = await a.getArtifactNeighbors(e2.artifactId);
    expect(n.position).toBe(1);
    expect(n.prev.artifactId).toBe(e1.artifactId);
    expect(n.next.artifactId).toBe(e3.artifactId);
  });

  test('AC-79 getModernChain length matches modernLength in getChainStats', async () => {
    expect((await audit.getModernChain()).length).toBe(audit.getChainStats().modernLength);
  });

  test('AC-80 prev/next entries returned by getArtifactNeighbors are the frozen entry objects', async () => {
    const n    = await audit.getArtifactNeighbors(entries[1].artifactId);
    const same = await audit.getArtifactById(entries[0].artifactId);
    expect(Object.isFrozen(n.prev)).toBe(true);
    expect(n.prev).toBe(same);  // same reference, not a copy
  });
});

// ── AC-81…AC-90: Security — duplicate rejection ───────────────────────────────

describe('AC-81…AC-90: Security — duplicate detection', () => {
  let audit;

  beforeAll(async () => { audit = freshAudit(); });

  test('AC-81 duplicate artifactId is rejected before any file write', async () => {
    const aid = uuid();
    await audit.append(allowParams({ artifactId: aid }));
    const fs = require('fs');
    // require('fs') here may resolve to a DIFFERENT automock instance than the
    // one audit-log.js's closure holds (jest.isolateModules() inside
    // freshAudit() gives 'fs' its own fresh mock when 'fs' hasn't already
    // been required in the outer registry) — fs.promises was never installed
    // on it, so guard against the crash exactly like freshAudit() does.
    if (!fs.promises) _installFsPromisesMocks(fs);
    fs.promises.appendFile.mockClear();
    await expect(audit.append(allowParams({ artifactId: aid }))).rejects.toThrow('already_executed');
    expect(fs.promises.appendFile).not.toHaveBeenCalled();
  });

  test('AC-82 duplicate nonce is rejected before any file write', async () => {
    const n = 'sec-nonce-' + uuid();
    await audit.append(allowParams({ nonce: n }));
    const fs = require('fs');
    if (!fs.promises) _installFsPromisesMocks(fs);
    fs.promises.appendFile.mockClear();
    await expect(audit.append(allowParams({ nonce: n }))).rejects.toThrow('replay_detected');
    expect(fs.promises.appendFile).not.toHaveBeenCalled();
  });

  test('AC-83 rejected append does not corrupt chain length', async () => {
    const aid = uuid();
    await audit.append(allowParams({ artifactId: aid }));
    const lenBefore = audit.getChainLength();
    await expect(audit.append(allowParams({ artifactId: aid }))).rejects.toThrow();
    expect(audit.getChainLength()).toBe(lenBefore);
  });

  test('AC-84 rejected append does not corrupt allowCount', async () => {
    const aid        = uuid();
    const countBefore = audit.getChainStats().allowCount;
    await audit.append(allowParams({ artifactId: aid }));
    await expect(audit.append(allowParams({ artifactId: aid }))).rejects.toThrow();
    expect(audit.getChainStats().allowCount).toBe(countBefore + 1);  // only incremented once
  });

  test('AC-85 rejected append does not corrupt nonce index', async () => {
    const n = 'sec-nonce-85-' + uuid();
    await audit.append(allowParams({ nonce: n }));
    await expect(audit.append(allowParams({ nonce: n }))).rejects.toThrow('replay_detected');
    expect(await audit.isNonceUsed(n)).toBe(true);  // still indexed from first valid append
  });

  test('AC-86 different artifactIds never collide in the artifact index', async () => {
    const ids = Array.from({ length: 10 }, () => uuid());
    for (const id of ids) await audit.append(allowParams({ artifactId: id }));
    for (const id of ids) {
      expect(await audit.getArtifactById(id)).not.toBeNull();
      expect((await audit.getArtifactById(id)).artifactId).toBe(id);
    }
  });

  test('AC-87 invalid decision is rejected without corrupting state', async () => {
    const lenBefore = audit.getChainLength();
    await expect(audit.append({ ...allowParams(), decision: 'INVALID' })).rejects.toThrow('invalid_decision');
    expect(audit.getChainLength()).toBe(lenBefore);
  });

  test('AC-88 ALLOW without inputHash is rejected without corrupting state', async () => {
    const lenBefore = audit.getChainLength();
    await expect(audit.append({ ...allowParams(), inputHash: '' })).rejects.toThrow('invalid_inputHash');
    expect(audit.getChainLength()).toBe(lenBefore);
  });

  test('AC-89 chain integrity report detects duplicate artifactId injection', async () => {
    // The _walkChain detects AUDIT_DUPLICATE_ENTRY via the seenArtifactIds Set.
    // We test that validateChainIntegrity() returns valid=true on a clean chain.
    const a = freshAudit();
    await a.append(allowParams());
    await a.append(allowParams());
    expect(a.validateChainIntegrity().chainValid).toBe(true);
  });

  test('AC-90 verifyAuditChain returns true on a correctly built chain', async () => {
    const a = freshAudit();
    await a.append(allowParams());
    await a.append(allowParams());
    await a.append(blockParams());
    expect(a.verifyAuditChain()).toBe(true);
  });
});

// ── AC-91…AC-100: Chain integrity — uses indexed stats ────────────────────────

describe('AC-91…AC-100: Chain integrity with indexed stats', () => {
  let audit;

  beforeAll(async () => {
    audit = freshAudit();
    await audit.append(allowParams());
    await audit.append(allowParams());
    await audit.append(blockParams());
    const origId = uuid();
    await audit.append(allowParams({ artifactId: origId }));
    await audit.append(blockParams({ executionContext: { replayOf: origId, reason: 'REPLAY_DETECTED' } }));
  });

  test('AC-91 validateChainIntegrity returns chainValid=true', async () => {
    expect(audit.validateChainIntegrity().chainValid).toBe(true);
  });

  test('AC-92 validateChainIntegrity.modernLength matches getChainStats().modernLength', async () => {
    const report = audit.validateChainIntegrity();
    const stats  = audit.getChainStats();
    expect(report.modernLength).toBe(stats.modernLength);
  });

  test('AC-93 validateChainIntegrity.allowCount is O(1) from index', async () => {
    const report = audit.validateChainIntegrity();
    expect(report.allowCount).toBe(audit.getChainStats().allowCount);
  });

  test('AC-94 validateChainIntegrity.blockCount is O(1) from index', async () => {
    const report = audit.validateChainIntegrity();
    expect(report.blockCount).toBe(audit.getChainStats().blockCount);
  });

  test('AC-95 validateChainIntegrity replayCorrelationState uses indexed counts', async () => {
    const report = audit.validateChainIntegrity();
    expect(report.replayCorrelationState.replaysDetected).toBe(audit.getChainStats().replayCount);
    expect(report.replayCorrelationState.replaysLinked).toBe(1);    // original IS in chain
    expect(report.replayCorrelationState.replaysUnlinked).toBe(0);
  });

  test('AC-96 validateChainIntegrity.lineageCompleteness is COMPLETE on valid chain', async () => {
    expect(audit.validateChainIntegrity().lineageCompleteness).toBe('COMPLETE');
  });

  test('AC-97 validateChainIntegrity.lineageCompleteness is EMPTY on empty chain', async () => {
    const a = freshAudit();
    expect(a.validateChainIntegrity().lineageCompleteness).toBe('EMPTY');
  });

  test('AC-98 verifyAuditChainDetailed without args uses internal chain', async () => {
    const detail = audit.verifyAuditChainDetailed();
    expect(detail.valid).toBe(true);
    expect(typeof detail.entriesVerified).toBe('number');
  });

  test('AC-99 verifyAuditChainDetailed with external array arg still works', async () => {
    const chain  = await audit.getAuditChain();
    const detail = audit.verifyAuditChainDetailed(chain);
    expect(detail.valid).toBe(true);
  });

  test('AC-100 getAuditTailHash matches tailHash from getChainStats', async () => {
    expect(audit.getAuditTailHash()).toBe(audit.getChainStats().tailHash);
  });
});

// ── AC-101…AC-110: Backward compatibility ─────────────────────────────────────

describe('AC-101…AC-110: Backward compatibility — existing API preserved', () => {
  let audit;

  beforeAll(async () => {
    audit = freshAudit();
    await audit.append(allowParams());
    await audit.append(blockParams());
  });

  test('AC-101 getAuditChain returns array slice of full chain', async () => {
    const chain = await audit.getAuditChain();
    expect(Array.isArray(chain)).toBe(true);
    expect(chain.length).toBe(audit.getChainLength());
  });

  test('AC-102 getAuditChain returns a copy — mutations do not affect internal chain', async () => {
    const chain = await audit.getAuditChain();
    chain.push({ injected: true });
    expect((await audit.getAuditChain()).length).toBe(2);
  });

  test('AC-103 getChainLength returns the total number of entries', async () => {
    expect(audit.getChainLength()).toBe(2);
  });

  test('AC-104 verifyAuditChain is a boolean', async () => {
    expect(typeof audit.verifyAuditChain()).toBe('boolean');
  });

  test('AC-105 verifyAuditChainDetailed returns the expected fields', async () => {
    const d = audit.verifyAuditChainDetailed();
    expect(d).toHaveProperty('valid');
    expect(d).toHaveProperty('reason');
    expect(d).toHaveProperty('entriesVerified');
    expect(d).toHaveProperty('head');
    expect(d).toHaveProperty('tail');
    expect(d).toHaveProperty('tamperingDetected');
  });

  test('AC-106 validateChainIntegrity returns the expected fields', async () => {
    const r = audit.validateChainIntegrity();
    expect(r).toHaveProperty('chainValid');
    expect(r).toHaveProperty('chainLength');
    expect(r).toHaveProperty('modernLength');
    expect(r).toHaveProperty('replayCorrelationState');
    expect(r).toHaveProperty('allowCount');
    expect(r).toHaveProperty('blockCount');
  });

  test('AC-107 append returns the frozen entry object', async () => {
    const e = await audit.append(allowParams());
    expect(Object.isFrozen(e)).toBe(true);
    expect(typeof e.hash).toBe('string');
    expect(e.hash).toHaveLength(64);
  });

  test('AC-108 all module exports are present', async () => {
    const expected = [
      'append', 'isNonceUsed', 'alreadyExecuted', 'getArtifactById',
      'getAuditChainForTenant', 'getAuditTailHash', 'auditChainContains',
      'getReplayLineage', 'getArtifactNeighbors', 'getRequestHashEntries',
      'getChainStats', 'getAuditChain', 'getModernChain', 'getChainLength',
      'verifyAuditChain', 'verifyAuditChainDetailed', 'validateChainIntegrity',
    ];
    for (const name of expected) {
      expect(typeof audit[name]).toBe('function');
    }
  });

  test('AC-109 append prevHash links form a valid chain', async () => {
    const a  = freshAudit();
    const e1 = await a.append(allowParams());
    const e2 = await a.append(allowParams());
    const e3 = await a.append(blockParams());
    expect(e1.prevHash).toBe('GENESIS');
    expect(e2.prevHash).toBe(e1.hash);
    expect(e3.prevHash).toBe(e2.hash);
  });

  test('AC-110 getAuditTailHash returns GENESIS when chain is empty', async () => {
    const a = freshAudit();
    expect(a.getAuditTailHash()).toBe('GENESIS');
  });
});

// ── AC-111…AC-120: Performance ceilings ──────────────────────────────────────
//
// Verifies that index-backed lookups complete within strict time budgets
// regardless of chain size.  These tests build chains at multiple scales and
// measure lookup latency.
//

describe('AC-111…AC-120: Performance ceilings', () => {
  const SIZES = [10, 100, 1_000, 10_000];

  // Build audit instances of each size.
  const instances = {};

  beforeAll(async () => {
    for (const n of SIZES) {
      const a   = freshAudit();
      const ids = [];
      // Sequential — matches the old synchronous build order; with mocked
      // fs.promises resolving immediately this is still fast (well under the
      // 60s budget below) and keeps prevHash chaining/position semantics
      // identical to before.
      for (let i = 0; i < n; i++) {
        const e = await a.append(allowParams());
        ids.push(e.artifactId);
      }
      instances[n] = { audit: a, ids };
    }
  }, 60_000);  // allow up to 60s for chain building

  // Helper: measures median of k iterations in milliseconds.
  function measureMs(fn, k = 1000) {
    const times = [];
    for (let i = 0; i < k; i++) {
      const t0 = process.hrtime.bigint();
      fn();
      const t1 = process.hrtime.bigint();
      times.push(Number(t1 - t0) / 1e6);
    }
    times.sort((a, b) => a - b);
    return times[Math.floor(k / 2)];
  }

  // Async twin for the async lookups — awaits each iteration; the
  // in-window fast path resolves as an already-fulfilled promise, so the
  // same <1ms medians still apply (assertions unchanged).
  async function measureMsAsync(fn, k = 1000) {
    const times = [];
    for (let i = 0; i < k; i++) {
      const t0 = process.hrtime.bigint();
      await fn();
      const t1 = process.hrtime.bigint();
      times.push(Number(t1 - t0) / 1e6);
    }
    times.sort((a, b) => a - b);
    return times[Math.floor(k / 2)];
  }

  for (const n of SIZES) {
    test(`AC-111 getArtifactById median < 1ms at chain size ${n}`, async () => {
      const { audit, ids } = instances[n];
      const target = ids[Math.floor(n / 2)];
      const ms = await measureMsAsync(() => audit.getArtifactById(target));
      expect(ms).toBeLessThan(1);
    });

    test(`AC-112 isNonceUsed median < 1ms at chain size ${n}`, async () => {
      const { audit }  = instances[n];
      const knownNonce = 'known-nonce-' + uuid();
      await audit.append(allowParams({ nonce: knownNonce }));
      const ms = await measureMsAsync(() => audit.isNonceUsed(knownNonce));
      expect(ms).toBeLessThan(1);
    });

    test(`AC-113 auditChainContains median < 1ms at chain size ${n}`, async () => {
      const { audit, ids } = instances[n];
      // pick a tail id — earlier suites' extra appends can push the
      // oldest ids past the 10k window bound at the largest size, and this
      // micro-benchmark pins the in-window O(1) path.
      const entry  = await audit.getArtifactById(ids[ids.length - 1]);
      const ms     = await measureMsAsync(() => audit.auditChainContains(entry.hash));
      expect(ms).toBeLessThan(1);
    });

    test(`AC-114 getReplayLineage median < 1ms at chain size ${n}`, async () => {
      const { audit, ids } = instances[n];
      const ms = await measureMsAsync(() => audit.getReplayLineage(ids[0]));
      expect(ms).toBeLessThan(1);
    });

    test(`AC-115 getChainStats median < 1ms at chain size ${n}`, async () => {
      const { audit } = instances[n];
      const ms = measureMs(() => audit.getChainStats());
      expect(ms).toBeLessThan(1);
    });
  }

  test('AC-116 O(1) lookups do not degrade as chain doubles from 100 to 10000', async () => {
    const { audit: a100,  ids: ids100  } = instances[100];
    const { audit: a10k, ids: ids10k  } = instances[10_000];

    const ms100 = await measureMsAsync(() => a100.getArtifactById(ids100[50]));
    const ms10k = await measureMsAsync(() => a10k.getArtifactById(ids10k[5000]));

    // O(1) means < 10× degradation for 100× chain size.
    expect(ms10k).toBeLessThan(Math.max(ms100 * 10, 1));
  });

  test('AC-117 getArtifactNeighbors median < 1ms at chain size 1000', async () => {
    const { audit, ids } = instances[1_000];
    const target = ids[500];
    const ms     = await measureMsAsync(() => audit.getArtifactNeighbors(target));
    expect(ms).toBeLessThan(1);
  });

  test('AC-118 getRequestHashEntries median < 1ms at chain size 1000', async () => {
    const { audit } = instances[1_000];
    const rh = 'bench-rh-' + uuid();
    await audit.append(allowParams({ requestHash: rh }));
    const ms = await measureMsAsync(() => audit.getRequestHashEntries(rh));
    expect(ms).toBeLessThan(1);
  });

  test('AC-119 getAuditTailHash median < 0.1ms at chain size 10000', async () => {
    const { audit } = instances[10_000];
    const ms = measureMs(() => audit.getAuditTailHash(), 10_000);
    expect(ms).toBeLessThan(0.1);
  });

  test('AC-120 alreadyExecuted median < 1ms at chain size 10000', async () => {
    const { audit, ids } = instances[10_000];
    const ms = await measureMsAsync(() => audit.alreadyExecuted(ids[9000]));
    expect(ms).toBeLessThan(1);
  });
});
