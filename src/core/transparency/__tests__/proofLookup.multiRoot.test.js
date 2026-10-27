'use strict';

/**
 * regression — inclusion proofs must verify for entries covered by a
 * SECOND OR LATER Merkle root, not just the first.
 *
 * THE DEFECT THIS PINS
 * --------------------
 * `registrar.generateRoot()` computes a root's `root_hash` and `entry_count`
 * over the FULL log, entries 1..seq_to — its own comment says so explicitly,
 * and records that computing from only the incremental range "produced a root
 * that shared no leaves at all with any prior root ... every root after the
 * first was cryptographically unrelated to the ones before it" (corrected
 * there under AT-078). `seq_from`/`seq_to` survive only as a record of which
 * range that particular generation call newly covered; they are NOT the tree.
 *
 * `proofLookup.getInclusionProofForEntry()` was never updated to match. It
 * rebuilt the tree from `seq_from..seq_to`, so the root it recomputed could
 * not equal the stored one — every inclusion proof for an entry covered by a
 * second or later root failed MERKLE_PATH and ROOT_HASH_MATCH.
 *
 * WHY IT WAS INVISIBLE
 * --------------------
 * For the FIRST root, `seq_from === 1`, so `1..seq_to` and `seq_from..seq_to`
 * are the same range and everything verifies. A second root is required to
 * expose it — and root generation had never run on real data at all until
 *. The
 * control case below is exactly that first-root scenario, and it passes both
 * with and without the fix; only the multi-root case discriminates.
 *
 * The identical stale assumption in `GapScanner._scanRoots()` is pinned by
 * `src/core/transparency/scanner/__tests__/gapScanner.test.js`.
 */

jest.mock('../logStore');

const crypto   = require('crypto');
const logStore = require('../logStore');
const log      = require('../log');
const proofLookup = require('../proofLookup');

// A realistic two-root log: 12 entries, root 1 covering 1..7, root 2 newly
// covering 8..12 but — per the registrar — hashed over the full 1..12.
const TOTAL = 12;
const ROOT1_SEQ_TO = 7;

const ENTRIES = Array.from({ length: TOTAL }, (_, i) => ({
  id: i + 1,
  transparency_id: `tid-${i + 1}`,
  entry_type: 'SYSTEM',
  artifact_id: null,
  evidence_chain_id: null,
  verification_id: null,
  payload_hash: crypto.createHash('sha256').update(`p${i}`).digest('hex'),
  previous_entry_hash: i === 0 ? null : crypto.createHash('sha256').update(`e${i - 1}`).digest('hex'),
  entry_hash: crypto.createHash('sha256').update(`e${i}`).digest('hex'),
  signer_key_id: 'k1',
  signature: 'SIG',
  created_at: '2026-09-14T12:00:00.000Z',
}));

const ALL_HASHES = ENTRIES.map((e) => e.entry_hash);

const ROOT_1 = {
  id: 1,
  root_id: crypto.randomUUID(),
  seq_from: 1,
  seq_to: ROOT1_SEQ_TO,
  entry_count: ROOT1_SEQ_TO,
  root_hash: log.computeRootHash(ALL_HASHES.slice(0, ROOT1_SEQ_TO)),
  previous_root_hash: null,
  signature: 'SIG',
  signer_key_id: 'k1',
  generated_at: '2026-09-14T12:00:00.000Z',
};

// seq_from/seq_to record the INCREMENTAL range (8..12), while entry_count and
// root_hash cover the FULL tree (1..12) — exactly what registrar.generateRoot()
// writes, and exactly the shape observed live (seqFrom 631,
// seqTo 1020, entryCount 1020).
const ROOT_2 = {
  id: 2,
  root_id: crypto.randomUUID(),
  seq_from: ROOT1_SEQ_TO + 1,
  seq_to: TOTAL,
  entry_count: TOTAL,
  root_hash: log.computeRootHash(ALL_HASHES),
  previous_root_hash: ROOT_1.root_hash,
  signature: 'SIG',
  signer_key_id: 'k1',
  generated_at: '2026-09-14T12:00:01.000Z',
};

beforeEach(() => {
  jest.clearAllMocks();

  logStore.getRootCoveringEntry.mockImplementation(async (entryId) =>
    Number(entryId) <= ROOT1_SEQ_TO ? ROOT_1 : ROOT_2);

  // Faithful to the real implementation: an inclusive id range.
  logStore.getHashesInRange /* the tail read is hash-only */.mockImplementation(async (from, to) =>
    ENTRIES.filter((e) => e.id >= Number(from) && e.id <= Number(to)));

  // proofs now go through merkleCheckpoints.js. Faithful in-memory
  // versions of its three logStore reads/writes; with 12 entries and the
  // default block size (1024) no block is complete, so the whole tree is the
  // "final incomplete block" and the 1..seq_to assertions below are unchanged.
  // Block-backed proofs are covered in merkleCheckpoints.test.js.
  const blocks = [];
  logStore.fetchEntriesFromId.mockImplementation(async (from, limit) =>
    ENTRIES.filter((e) => e.id >= Number(from)).slice(0, Number(limit)));
  logStore.getMerkleBlocks.mockImplementation(async () => blocks.slice());
  logStore.insertMerkleBlock.mockImplementation(async (b) => { blocks.push(b); });
});

describe('inclusion proofs across multiple Merkle roots', () => {
  test('an entry covered by the SECOND root produces a proof that verifies', async () => {
    const target = ENTRIES[9]; // id 10, inside root 2's incremental range
    const { proof, proofVerification, message } =
      await proofLookup.getInclusionProofForEntry(target);

    expect(message).toBeNull();
    expect(proof).not.toBeNull();
    expect(proofVerification.valid).toBe(true);
    expect(proofVerification.checks.map((c) => `${c.check}:${c.result}`)).toEqual([
      'LEAF_INDEX_RANGE:PASS',
      'TREE_SIZE_MATCH:PASS',   // the proof's tree is the one the signed root covers
      'MERKLE_PATH:PASS',
      'ROOT_HASH_MATCH:PASS',
    ]);
  });

  test('the tree is rebuilt from 1..seq_to, not seq_from..seq_to', async () => {
    await proofLookup.getInclusionProofForEntry(ENTRIES[9]);

    // The single call that matters: it must span the whole log, because that
    // is what the stored root_hash was computed over.
    // (merkleCheckpoints.js passes a third, options argument — compare the range.)
    const ranges = logStore.getHashesInRange.mock.calls.map((c) => [c[0], c[1]]);
    expect(ranges).toContainEqual([1, TOTAL]);
    expect(ranges).not.toContainEqual([ROOT_1.seq_to + 1, TOTAL]);
  });

  test('every entry in the log verifies, across both roots', async () => {
    const outcomes = [];
    for (const entry of ENTRIES) {
      const { proofVerification } = await proofLookup.getInclusionProofForEntry(entry);
      outcomes.push({ id: entry.id, valid: proofVerification?.valid ?? null });
    }
    expect(outcomes.filter((o) => o.valid !== true)).toEqual([]);
  });

  test('CONTROL: the first root still verifies (this case passes with or without the fix)', async () => {
    const { proofVerification } = await proofLookup.getInclusionProofForEntry(ENTRIES[2]); // id 3
    expect(proofVerification.valid).toBe(true);
  });

  test('an entry with no covering root reports that, rather than a bogus proof', async () => {
    logStore.getRootCoveringEntry.mockResolvedValueOnce(null);
    const { proof, message } = await proofLookup.getInclusionProofForEntry(ENTRIES[0]);
    expect(proof).toBeNull();
    expect(message).toMatch(/No root has been generated covering this entry yet/);
  });
});
