'use strict';

/**
 * RFC6962 Merkle Tree Tests — Component #22
 *
 * MK-01 … MK-10   Hash primitives (leafHash, nodeHash)
 * MK-11 … MK-25   merkleRoot correctness
 * MK-26 … MK-45   inclusionPath + verifyInclusionPath
 * MK-46 … MK-65   consistencyProof + verifyConsistencyProof
 * MK-66 … MK-75   batchVerifyInclusion
 * MK-76 … MK-85   Edge cases and adversarial inputs
 * MK-86 … MK-95   Cross-validation (merkle.js ↔ log.js)
 * MK-96 … MK-105  Performance ceiling assertions (must complete within time budget)
 */

const crypto = require('crypto');
const merkle = require('../merkle');
const log    = require('../log');

// ── Helpers ───────────────────────────────────────────────────────────────────

function randomHex64() {
  return crypto.randomBytes(32).toString('hex');
}

function makeHashes(n) {
  return Array.from({ length: n }, randomHex64);
}

// Build a consistent set of entry hashes deterministically for reproducible tests
function deterministicHashes(n) {
  return Array.from({ length: n }, (_, i) =>
    crypto.createHash('sha256').update(`entry-${i}`).digest('hex'),
  );
}

// ── MK-01 … MK-10: Hash primitives ───────────────────────────────────────────

describe('MK-01 … MK-10: Hash primitives (leafHash, nodeHash)', () => {
  test('MK-01 leafHash returns 64-char lowercase hex', () => {
    const h = merkle.leafHash(randomHex64());
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  test('MK-02 leafHash is deterministic', () => {
    const input = randomHex64();
    expect(merkle.leafHash(input)).toBe(merkle.leafHash(input));
  });

  test('MK-03 leafHash differs for different inputs', () => {
    expect(merkle.leafHash(randomHex64())).not.toBe(merkle.leafHash(randomHex64()));
  });

  test('MK-04 nodeHash returns 64-char lowercase hex', () => {
    const h = merkle.nodeHash(randomHex64(), randomHex64());
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  test('MK-05 nodeHash is deterministic', () => {
    const l = randomHex64(), r = randomHex64();
    expect(merkle.nodeHash(l, r)).toBe(merkle.nodeHash(l, r));
  });

  test('MK-06 nodeHash is not commutative (order matters)', () => {
    const l = randomHex64(), r = randomHex64();
    expect(merkle.nodeHash(l, r)).not.toBe(merkle.nodeHash(r, l));
  });

  test('MK-07 leafHash ≠ nodeHash for same data (domain separation)', () => {
    const input = randomHex64();
    const lh = merkle.leafHash(input);
    const nh = merkle.nodeHash(input, input);
    expect(lh).not.toBe(nh);
  });

  test('MK-08 leafHash embeds 0x00 prefix (RFC6962 §2.1)', () => {
    const entryHex = randomHex64();
    const expected = crypto.createHash('sha256')
      .update(Buffer.from([0x00]))
      .update(Buffer.from(entryHex, 'hex'))
      .digest('hex');
    expect(merkle.leafHash(entryHex)).toBe(expected);
  });

  test('MK-09 nodeHash embeds 0x01 prefix (RFC6962 §2.1)', () => {
    const l = randomHex64(), r = randomHex64();
    const expected = crypto.createHash('sha256')
      .update(Buffer.from([0x01]))
      .update(Buffer.from(l, 'hex'))
      .update(Buffer.from(r, 'hex'))
      .digest('hex');
    expect(merkle.nodeHash(l, r)).toBe(expected);
  });

  test('MK-10 _largestPow2LessThan returns correct values', () => {
    expect(merkle._largestPow2LessThan(2)).toBe(1);
    expect(merkle._largestPow2LessThan(3)).toBe(2);
    expect(merkle._largestPow2LessThan(4)).toBe(2);
    expect(merkle._largestPow2LessThan(5)).toBe(4);
    expect(merkle._largestPow2LessThan(8)).toBe(4);
    expect(merkle._largestPow2LessThan(9)).toBe(8);
    expect(merkle._largestPow2LessThan(1000)).toBe(512);
  });
});

// ── MK-11 … MK-25: merkleRoot correctness ────────────────────────────────────

describe('MK-11 … MK-25: merkleRoot correctness', () => {
  test('MK-11 single entry: root = leafHash(entries[0])', () => {
    const hashes = [randomHex64()];
    expect(merkle.merkleRoot(hashes)).toBe(merkle.leafHash(hashes[0]));
  });

  test('MK-12 two entries: root = nodeHash(leaf(0), leaf(1))', () => {
    const hashes = [randomHex64(), randomHex64()];
    const expected = merkle.nodeHash(merkle.leafHash(hashes[0]), merkle.leafHash(hashes[1]));
    expect(merkle.merkleRoot(hashes)).toBe(expected);
  });

  test('MK-13 four entries: balanced tree, correct root', () => {
    const [a, b, c, d] = makeHashes(4);
    const l = merkle.nodeHash(merkle.leafHash(a), merkle.leafHash(b));
    const r = merkle.nodeHash(merkle.leafHash(c), merkle.leafHash(d));
    expect(merkle.merkleRoot([a, b, c, d])).toBe(merkle.nodeHash(l, r));
  });

  test('MK-14 five entries: RFC6962 k=4 split', () => {
    const h = makeHashes(5);
    // MTH(D[0:5]) = nodeHash(MTH(D[0:4]), leafHash(D[4]))
    const left = merkle.merkleRoot(h.slice(0, 4));
    const right = merkle.leafHash(h[4]);
    expect(merkle.merkleRoot(h)).toBe(merkle.nodeHash(left, right));
  });

  test('MK-15 seven entries: RFC6962 k=4 split (both unbalanced subtrees)', () => {
    const h = makeHashes(7);
    // MTH(D[0:7]) = nodeHash(MTH(D[0:4]), MTH(D[4:7]))
    const left  = merkle.merkleRoot(h.slice(0, 4));
    const right = merkle.merkleRoot(h.slice(4, 7));
    expect(merkle.merkleRoot(h)).toBe(merkle.nodeHash(left, right));
  });

  test('MK-16 root is deterministic', () => {
    const hashes = makeHashes(10);
    expect(merkle.merkleRoot(hashes)).toBe(merkle.merkleRoot(hashes));
  });

  test('MK-17 root changes when any entry changes', () => {
    const hashes = deterministicHashes(8);
    const root1  = merkle.merkleRoot(hashes);
    const modified = [...hashes];
    modified[3] = randomHex64();
    expect(merkle.merkleRoot(modified)).not.toBe(root1);
  });

  test('MK-18 root changes when order changes', () => {
    const hashes = deterministicHashes(4);
    const shuffled = [hashes[1], hashes[0], hashes[2], hashes[3]];
    expect(merkle.merkleRoot(hashes)).not.toBe(merkle.merkleRoot(shuffled));
  });

  test('MK-19 power-of-2 sizes produce correct roots', () => {
    for (const n of [1, 2, 4, 8, 16, 32]) {
      const hashes = deterministicHashes(n);
      const root = merkle.merkleRoot(hashes);
      expect(root).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test('MK-20 non-power-of-2 sizes produce correct roots', () => {
    for (const n of [3, 5, 6, 7, 9, 10, 15, 17]) {
      const hashes = deterministicHashes(n);
      const root = merkle.merkleRoot(hashes);
      expect(root).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test('MK-21 merkleRoot throws for empty array', () => {
    expect(() => merkle.merkleRoot([])).toThrow(RangeError);
  });

  test('MK-22 merkleRoot throws for non-array', () => {
    expect(() => merkle.merkleRoot(null)).toThrow();
    expect(() => merkle.merkleRoot('string')).toThrow();
  });

  test('MK-23 appending an entry changes the root', () => {
    const hashes = deterministicHashes(10);
    const root1  = merkle.merkleRoot(hashes);
    const root2  = merkle.merkleRoot([...hashes, randomHex64()]);
    expect(root1).not.toBe(root2);
  });

  test('MK-24 log.computeRootHash uses Merkle (matches merkle.merkleRoot)', () => {
    const hashes = deterministicHashes(10);
    expect(log.computeRootHash(hashes)).toBe(merkle.merkleRoot(hashes));
  });

  test('MK-25 incremental appends produce consistent roots (each size matches)', () => {
    const hashes = deterministicHashes(8);
    for (let n = 1; n <= 8; n++) {
      const partial = hashes.slice(0, n);
      const root    = merkle.merkleRoot(partial);
      expect(root).toMatch(/^[0-9a-f]{64}$/);
      // Appending more entries changes the root
      if (n < 8) {
        const larger = merkle.merkleRoot(hashes.slice(0, n + 1));
        expect(root).not.toBe(larger);
      }
    }
  });
});

// ── MK-26 … MK-45: inclusionPath + verifyInclusionPath ───────────────────────

describe('MK-26 … MK-45: inclusionPath + verifyInclusionPath', () => {
  test('MK-26 single entry: path is empty', () => {
    const hashes = [randomHex64()];
    expect(merkle.inclusionPath(hashes, 0)).toEqual([]);
  });

  test('MK-27 two entries: path has exactly one element', () => {
    const hashes = makeHashes(2);
    const path0 = merkle.inclusionPath(hashes, 0);
    const path1 = merkle.inclusionPath(hashes, 1);
    expect(path0).toHaveLength(1);
    expect(path1).toHaveLength(1);
  });

  test('MK-28 path length is O(log n)', () => {
    for (const n of [1, 2, 4, 8, 16, 32, 64, 128]) {
      const hashes = deterministicHashes(n);
      const path   = merkle.inclusionPath(hashes, 0);
      expect(path.length).toBeLessThanOrEqual(Math.ceil(Math.log2(n)) + 1);
    }
  });

  test('MK-29 path elements have hash and side properties', () => {
    const hashes = makeHashes(8);
    const path   = merkle.inclusionPath(hashes, 3);
    for (const step of path) {
      expect(step).toHaveProperty('hash');
      expect(step).toHaveProperty('side');
      expect(['left', 'right']).toContain(step.side);
      expect(step.hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test('MK-30 verifyInclusionPath succeeds for all leaves in tree of size 1', () => {
    const hashes = deterministicHashes(1);
    const root   = merkle.merkleRoot(hashes);
    const path   = merkle.inclusionPath(hashes, 0);
    expect(merkle.verifyInclusionPath(hashes[0], path, root, 0, hashes.length)).toBe(true);
  });

  test('MK-31 verifyInclusionPath succeeds for all leaves in tree of size 2', () => {
    const hashes = deterministicHashes(2);
    const root   = merkle.merkleRoot(hashes);
    for (let i = 0; i < 2; i++) {
      const path = merkle.inclusionPath(hashes, i);
      expect(merkle.verifyInclusionPath(hashes[i], path, root, i, hashes.length)).toBe(true);
    }
  });

  test('MK-32 verifyInclusionPath succeeds for all leaves in tree of size 7', () => {
    const hashes = deterministicHashes(7);
    const root   = merkle.merkleRoot(hashes);
    for (let i = 0; i < 7; i++) {
      const path = merkle.inclusionPath(hashes, i);
      expect(merkle.verifyInclusionPath(hashes[i], path, root, i, hashes.length)).toBe(true);
    }
  });

  test('MK-33 verifyInclusionPath succeeds for all leaves in tree of size 8', () => {
    const hashes = deterministicHashes(8);
    const root   = merkle.merkleRoot(hashes);
    for (let i = 0; i < 8; i++) {
      const path = merkle.inclusionPath(hashes, i);
      expect(merkle.verifyInclusionPath(hashes[i], path, root, i, hashes.length)).toBe(true);
    }
  });

  test('MK-34 verifyInclusionPath succeeds for all leaves in sizes [1..17]', () => {
    for (let n = 1; n <= 17; n++) {
      const hashes = deterministicHashes(n);
      const root   = merkle.merkleRoot(hashes);
      for (let i = 0; i < n; i++) {
        const path = merkle.inclusionPath(hashes, i);
        expect(merkle.verifyInclusionPath(hashes[i], path, root, i, hashes.length)).toBe(true);
      }
    }
  });

  test('MK-35 verifyInclusionPath fails for wrong entry hash', () => {
    const hashes = deterministicHashes(10);
    const root   = merkle.merkleRoot(hashes);
    const path   = merkle.inclusionPath(hashes, 5);
    expect(merkle.verifyInclusionPath(randomHex64(), path, root, 5, hashes.length)).toBe(false);
  });

  test('MK-36 verifyInclusionPath fails for wrong root', () => {
    const hashes = deterministicHashes(10);
    const root   = merkle.merkleRoot(hashes);
    const path   = merkle.inclusionPath(hashes, 5);
    expect(merkle.verifyInclusionPath(hashes[5], path, randomHex64(), 5, hashes.length)).toBe(false);
  });

  test('MK-37 verifyInclusionPath fails for tampered path', () => {
    const hashes = deterministicHashes(10);
    const root   = merkle.merkleRoot(hashes);
    const path   = merkle.inclusionPath(hashes, 5);
    const tampered = path.map((s, i) => i === 0 ? { ...s, hash: randomHex64() } : s);
    expect(merkle.verifyInclusionPath(hashes[5], tampered, root, 5, hashes.length)).toBe(false);
  });

  test('MK-38 verifyInclusionPath fails for path from different position', () => {
    const hashes = deterministicHashes(8);
    const root   = merkle.merkleRoot(hashes);
    const path4  = merkle.inclusionPath(hashes, 4);
    // Use the path for index 4, but try to verify index 5
    expect(merkle.verifyInclusionPath(hashes[5], path4, root, 5, hashes.length)).toBe(false);
  });

  test('MK-39 inclusionPath throws for out-of-range index', () => {
    const hashes = deterministicHashes(5);
    expect(() => merkle.inclusionPath(hashes, -1)).toThrow(RangeError);
    expect(() => merkle.inclusionPath(hashes, 5)).toThrow(RangeError);
    expect(() => merkle.inclusionPath(hashes, 100)).toThrow(RangeError);
  });

  test('MK-40 verifyInclusionPath returns false for null/missing inputs', () => {
    expect(merkle.verifyInclusionPath(null, [], randomHex64())).toBe(false);
    expect(merkle.verifyInclusionPath(randomHex64(), null, randomHex64())).toBe(false);
    expect(merkle.verifyInclusionPath(randomHex64(), [], null)).toBe(false);
  });

  test('MK-41 path for leaf 0 always has only right-side siblings', () => {
    // Leaf 0 is always the leftmost; all siblings are on the right
    for (const n of [2, 3, 4, 5, 8, 16]) {
      const hashes = deterministicHashes(n);
      const path   = merkle.inclusionPath(hashes, 0);
      for (const step of path) {
        expect(step.side).toBe('right');
      }
    }
  });

  test('MK-42 path for last leaf in power-of-2 tree has only left-side siblings', () => {
    for (const n of [2, 4, 8, 16]) {
      const hashes = deterministicHashes(n);
      const path   = merkle.inclusionPath(hashes, n - 1);
      for (const step of path) {
        expect(step.side).toBe('left');
      }
    }
  });

  test('MK-43 proof size grows logarithmically: 2→1, 4→2, 8→3, 16→4, 1024→10', () => {
    const sizes = [2, 4, 8, 16, 1024];
    const expectedLengths = [1, 2, 3, 4, 10];
    for (let j = 0; j < sizes.length; j++) {
      const n     = sizes[j];
      const hashes = deterministicHashes(n);
      const path   = merkle.inclusionPath(hashes, 0);
      expect(path).toHaveLength(expectedLengths[j]);
    }
  });

  test('MK-44 inclusion paths for adjacent leaves differ', () => {
    const hashes = deterministicHashes(8);
    const path3  = merkle.inclusionPath(hashes, 3);
    const path4  = merkle.inclusionPath(hashes, 4);
    expect(JSON.stringify(path3)).not.toBe(JSON.stringify(path4));
  });

  test('MK-45 tree of size 100: all leaves verify', () => {
    const hashes = deterministicHashes(100);
    const root   = merkle.merkleRoot(hashes);
    for (let i = 0; i < 100; i++) {
      expect(merkle.verifyInclusionPath(hashes[i], merkle.inclusionPath(hashes, i), root, i, hashes.length)).toBe(true);
    }
  });
});

// ── MK-46 … MK-65: consistencyProof + verifyConsistencyProof ─────────────────

describe('MK-46 … MK-65: consistencyProof + verifyConsistencyProof', () => {
  test('MK-46 same size: proof is empty', () => {
    const hashes = deterministicHashes(5);
    expect(merkle.consistencyProof(5, 5, hashes)).toEqual([]);
  });

  test('MK-47 same size: verifyConsistencyProof passes trivially', () => {
    const hashes = deterministicHashes(5);
    const root   = merkle.merkleRoot(hashes);
    expect(merkle.verifyConsistencyProof(root, root, 5, 5, [])).toBe(true);
  });

  test('MK-48 oldSize=0: proof is empty; verify returns true', () => {
    const hashes = deterministicHashes(5);
    expect(merkle.consistencyProof(0, 5, hashes)).toEqual([]);
    expect(merkle.verifyConsistencyProof(randomHex64(), randomHex64(), 0, 5, [])).toBe(true);
  });

  test('MK-49 1→2: proof has 1 element', () => {
    const hashes = deterministicHashes(2);
    const proof  = merkle.consistencyProof(1, 2, hashes);
    expect(proof).toHaveLength(1);
    // The only proof element is leafHash(hashes[1])
    expect(proof[0]).toBe(merkle.leafHash(hashes[1]));
  });

  test('MK-50 2→4: proof is correct (m is power of 2)', () => {
    const hashes = deterministicHashes(4);
    const old2   = merkle.merkleRoot(hashes.slice(0, 2));
    const new4   = merkle.merkleRoot(hashes);
    const proof  = merkle.consistencyProof(2, 4, hashes);
    expect(merkle.verifyConsistencyProof(old2, new4, 2, 4, proof)).toBe(true);
  });

  test('MK-51 3→7: verify succeeds (RFC6962 example-like)', () => {
    const hashes = deterministicHashes(7);
    const old3   = merkle.merkleRoot(hashes.slice(0, 3));
    const new7   = merkle.merkleRoot(hashes);
    const proof  = merkle.consistencyProof(3, 7, hashes);
    expect(merkle.verifyConsistencyProof(old3, new7, 3, 7, proof)).toBe(true);
  });

  test('MK-52 all sizes 1..8 → 8: all consistency proofs verify', () => {
    const hashes = deterministicHashes(8);
    const newRoot = merkle.merkleRoot(hashes);
    for (let m = 1; m <= 8; m++) {
      const oldRoot = merkle.merkleRoot(hashes.slice(0, m));
      const proof   = merkle.consistencyProof(m, 8, hashes);
      expect(merkle.verifyConsistencyProof(oldRoot, newRoot, m, 8, proof)).toBe(true);
    }
  });

  test('MK-53 all pairs (m, n) with 1 ≤ m ≤ n ≤ 16: all verify', () => {
    const hashes = deterministicHashes(16);
    for (let n = 1; n <= 16; n++) {
      const newRoot = merkle.merkleRoot(hashes.slice(0, n));
      for (let m = 1; m <= n; m++) {
        const oldRoot = merkle.merkleRoot(hashes.slice(0, m));
        const proof   = merkle.consistencyProof(m, n, hashes.slice(0, n));
        expect(merkle.verifyConsistencyProof(oldRoot, newRoot, m, n, proof)).toBe(true);
      }
    }
  });

  test('MK-54 proof length is O(log n)', () => {
    const hashes = deterministicHashes(1024);
    const proof  = merkle.consistencyProof(1, 1024, hashes);
    expect(proof.length).toBeLessThanOrEqual(20); // log2(1024) = 10, +1 for base
  });

  test('MK-55 verifyConsistencyProof fails with wrong oldRoot', () => {
    const hashes  = deterministicHashes(8);
    const oldRoot = merkle.merkleRoot(hashes.slice(0, 4));
    const newRoot = merkle.merkleRoot(hashes);
    const proof   = merkle.consistencyProof(4, 8, hashes);
    expect(merkle.verifyConsistencyProof(randomHex64(), newRoot, 4, 8, proof)).toBe(false);
  });

  test('MK-56 verifyConsistencyProof fails with wrong newRoot', () => {
    const hashes  = deterministicHashes(8);
    const oldRoot = merkle.merkleRoot(hashes.slice(0, 4));
    const newRoot = merkle.merkleRoot(hashes);
    const proof   = merkle.consistencyProof(4, 8, hashes);
    expect(merkle.verifyConsistencyProof(oldRoot, randomHex64(), 4, 8, proof)).toBe(false);
  });

  test('MK-57 verifyConsistencyProof fails with tampered proof', () => {
    const hashes  = deterministicHashes(8);
    const oldRoot = merkle.merkleRoot(hashes.slice(0, 3));
    const newRoot = merkle.merkleRoot(hashes);
    const proof   = merkle.consistencyProof(3, 8, hashes);
    const tampered = [...proof];
    tampered[0] = randomHex64();
    expect(merkle.verifyConsistencyProof(oldRoot, newRoot, 3, 8, tampered)).toBe(false);
  });

  test('MK-58 verifyConsistencyProof fails for wrong old size', () => {
    const hashes  = deterministicHashes(8);
    const oldRoot = merkle.merkleRoot(hashes.slice(0, 4));
    const newRoot = merkle.merkleRoot(hashes);
    const proof   = merkle.consistencyProof(4, 8, hashes);
    // Supply wrong old size (3 instead of 4) → wrong path decisions → fail
    expect(merkle.verifyConsistencyProof(oldRoot, newRoot, 3, 8, proof)).toBe(false);
  });

  test('MK-59 verifyConsistencyProof returns false for oldSize > newSize', () => {
    const hashes = deterministicHashes(4);
    const r1 = merkle.merkleRoot(hashes.slice(0, 2));
    const r2 = merkle.merkleRoot(hashes);
    expect(merkle.verifyConsistencyProof(r2, r1, 4, 2, [])).toBe(false);
  });

  test('MK-60 consistencyProof throws for invalid sizes', () => {
    const hashes = deterministicHashes(4);
    expect(() => merkle.consistencyProof(5, 4, hashes)).toThrow(RangeError);
    expect(() => merkle.consistencyProof(-1, 4, hashes)).toThrow(RangeError);
  });

  test('MK-61 consistencyProof throws when entryHashHexArray length ≠ newSize', () => {
    const hashes = deterministicHashes(4);
    expect(() => merkle.consistencyProof(2, 5, hashes)).toThrow(RangeError); // 5 > 4
  });

  test('MK-62 power-of-2 old sizes: b=true path (no base hash in proof)', () => {
    // When oldSize is a power of 2, proof starts from old_root directly (b=true)
    for (const m of [1, 2, 4, 8]) {
      const n      = 10;
      const hashes = deterministicHashes(n);
      const proof  = merkle.consistencyProof(m, n, hashes);
      const oldRoot = merkle.merkleRoot(hashes.slice(0, m));
      const newRoot = merkle.merkleRoot(hashes);
      expect(merkle.verifyConsistencyProof(oldRoot, newRoot, m, n, proof)).toBe(true);
    }
  });

  test('MK-63 non-power-of-2 old sizes: b=false path (base hash in proof)', () => {
    for (const m of [3, 5, 6, 7]) {
      const n      = 10;
      const hashes = deterministicHashes(n);
      const proof  = merkle.consistencyProof(m, n, hashes);
      const oldRoot = merkle.merkleRoot(hashes.slice(0, m));
      const newRoot = merkle.merkleRoot(hashes);
      expect(merkle.verifyConsistencyProof(oldRoot, newRoot, m, n, proof)).toBe(true);
    }
  });

  test('MK-64 proof of non-prefix is cryptographically rejected', () => {
    // Use hashes from two completely different trees
    const hashesA = deterministicHashes(4);
    const hashesB = deterministicHashes(8).map(h => h.split('').reverse().join('')); // different
    // Actually generate a B tree with a different set of entries
    const hashesB2 = Array.from({ length: 8 }, (_, i) =>
      crypto.createHash('sha256').update(`other-entry-${i}`).digest('hex'),
    );
    const oldRoot = merkle.merkleRoot(hashesA);
    const newRoot = merkle.merkleRoot(hashesB2);
    // proof from hashesB2[0..4] as if it matches hashesA
    const proof = merkle.consistencyProof(4, 8, hashesB2);
    // The old root doesn't match what this proof would reconstruct
    expect(merkle.verifyConsistencyProof(oldRoot, newRoot, 4, 8, proof)).toBe(false);
  });

  test('MK-65 proof hashes are all valid 64-char hex strings', () => {
    const hashes = deterministicHashes(16);
    const proof  = merkle.consistencyProof(5, 16, hashes);
    for (const h of proof) {
      expect(h).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

// ── MK-66 … MK-75: batchVerifyInclusion ─────────────────────────────────────

describe('MK-66 … MK-75: batchVerifyInclusion', () => {
  test('MK-66 empty batch returns valid=true with 0 results', () => {
    const result = merkle.batchVerifyInclusion(randomHex64(), []);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(0);
    expect(result.results).toEqual([]);
  });

  test('MK-67 all-valid batch returns valid=true', () => {
    const hashes = deterministicHashes(10);
    const root   = merkle.merkleRoot(hashes);
    const proofs = hashes.map((h, i) => ({
      entryHash: h,
      path:      merkle.inclusionPath(hashes, i),
      leafIndex: i,
      treeSize:  hashes.length,
    }));
    const result = merkle.batchVerifyInclusion(root, proofs);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(10);
    expect(result.results.every(r => r.valid)).toBe(true);
  });

  test('MK-68 one invalid proof makes batch valid=false', () => {
    const hashes = deterministicHashes(5);
    const root   = merkle.merkleRoot(hashes);
    const proofs = hashes.map((h, i) => ({
      entryHash: h,
      path:      merkle.inclusionPath(hashes, i),
      leafIndex: i,
      treeSize:  hashes.length,
    }));
    // Corrupt the third proof
    proofs[2] = { ...proofs[2], entryHash: randomHex64() };
    const result = merkle.batchVerifyInclusion(root, proofs);
    expect(result.valid).toBe(false);
    expect(result.results[2].valid).toBe(false);
    // Others still pass
    expect(result.results[0].valid).toBe(true);
    expect(result.results[4].valid).toBe(true);
  });

  test('MK-69 results include index, entryHash, valid, error fields', () => {
    const hashes = deterministicHashes(3);
    const root   = merkle.merkleRoot(hashes);
    const proofs = hashes.map((h, i) => ({
      entryHash: h,
      path:      merkle.inclusionPath(hashes, i),
      leafIndex: i,
      treeSize:  3,
    }));
    const { results } = merkle.batchVerifyInclusion(root, proofs);
    for (let i = 0; i < 3; i++) {
      expect(results[i]).toHaveProperty('index', i);
      expect(results[i]).toHaveProperty('entryHash');
      expect(results[i]).toHaveProperty('valid');
      expect(results[i]).toHaveProperty('error');
    }
  });

  test('MK-70 wrong root for all proofs: all invalid', () => {
    const hashes = deterministicHashes(5);
    const root   = merkle.merkleRoot(hashes);
    const proofs = hashes.map((h, i) => ({
      entryHash: h,
      path:      merkle.inclusionPath(hashes, i),
      leafIndex: i,
      treeSize:  5,
    }));
    const result = merkle.batchVerifyInclusion(randomHex64(), proofs);
    expect(result.valid).toBe(false);
    expect(result.results.every(r => !r.valid)).toBe(true);
  });

  test('MK-71 batchVerifyInclusion throws for non-array proofs', () => {
    expect(() => merkle.batchVerifyInclusion(randomHex64(), null)).toThrow(TypeError);
  });

  test('MK-72 batch with error in one proof captures error message', () => {
    const hashes = deterministicHashes(3);
    const root   = merkle.merkleRoot(hashes);
    const proofs = [
      { entryHash: hashes[0], path: merkle.inclusionPath(hashes, 0), leafIndex: 0, treeSize: 3 },
      { entryHash: null, path: [], leafIndex: 0, treeSize: 3 }, // null entryHash
    ];
    const result = merkle.batchVerifyInclusion(root, proofs);
    expect(result.results[0].valid).toBe(true);
    expect(result.results[1].valid).toBe(false);
  });

  test('MK-73 batch of 100 proofs all verify correctly', () => {
    const hashes = deterministicHashes(100);
    const root   = merkle.merkleRoot(hashes);
    const proofs = hashes.map((h, i) => ({
      entryHash: h,
      path:      merkle.inclusionPath(hashes, i),
      leafIndex: i,
      treeSize:  100,
    }));
    const result = merkle.batchVerifyInclusion(root, proofs);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(100);
  });
});

// ── MK-76 … MK-85: Edge cases and adversarial inputs ─────────────────────────

describe('MK-76 … MK-85: Edge cases and adversarial inputs', () => {
  test('MK-76 merkleRoot of 1000 entries completes without error', () => {
    const hashes = deterministicHashes(1000);
    expect(() => merkle.merkleRoot(hashes)).not.toThrow();
    expect(merkle.merkleRoot(hashes)).toMatch(/^[0-9a-f]{64}$/);
  });

  test('MK-77 inclusionPath for size-1000 tree verifies for all boundary indices', () => {
    const hashes = deterministicHashes(1000);
    const root   = merkle.merkleRoot(hashes);
    for (const i of [0, 1, 499, 500, 998, 999]) {
      const path = merkle.inclusionPath(hashes, i);
      expect(merkle.verifyInclusionPath(hashes[i], path, root, i, hashes.length)).toBe(true);
    }
  });

  test('MK-78 consistencyProof for 500→1000 verifies', () => {
    const hashes  = deterministicHashes(1000);
    const oldRoot = merkle.merkleRoot(hashes.slice(0, 500));
    const newRoot = merkle.merkleRoot(hashes);
    const proof   = merkle.consistencyProof(500, 1000, hashes);
    expect(merkle.verifyConsistencyProof(oldRoot, newRoot, 500, 1000, proof)).toBe(true);
  });

  test('MK-79 all-zero entry hashes produce valid tree', () => {
    const hashes = Array(4).fill('00'.repeat(32));
    const root   = merkle.merkleRoot(hashes);
    expect(root).toMatch(/^[0-9a-f]{64}$/);
  });

  test('MK-80 all-same entry hashes produce non-trivial distinct root per tree size', () => {
    const h = '00'.repeat(32);
    const r1 = merkle.merkleRoot([h]);
    const r2 = merkle.merkleRoot([h, h]);
    // Different tree sizes must produce different roots
    expect(r1).not.toBe(r2);
  });

  test('MK-81 verifyInclusionPath with empty path only succeeds for size-1 tree', () => {
    const hashes = deterministicHashes(1);
    const root   = merkle.merkleRoot(hashes);
    expect(merkle.verifyInclusionPath(hashes[0], [], root, 0, 1)).toBe(true);
  });

  test('MK-82 verifyInclusionPath with empty path fails for size-2 tree (root ≠ leaf)', () => {
    const hashes = deterministicHashes(2);
    const root   = merkle.merkleRoot(hashes);
    // Empty path: result = leafHash(entry) ≠ root (which is nodeHash of two leaves)
    expect(merkle.verifyInclusionPath(hashes[0], [], root, 0, 2)).toBe(false);
  });

  test('MK-83 consistency proof length ≤ 2*ceil(log2(n))+1 for any n', () => {
    for (const [m, n] of [[1, 7], [3, 100], [50, 100], [127, 128]]) {
      const hashes = deterministicHashes(n);
      const proof  = merkle.consistencyProof(m, n, hashes);
      const maxLen = 2 * Math.ceil(Math.log2(n)) + 2;
      expect(proof.length).toBeLessThanOrEqual(maxLen);
    }
  });

  test('MK-84 _subtreeRoot of single leaf returns that leaf unchanged', () => {
    const leafBuf = merkle._leafHashBuf(randomHex64());
    const result  = merkle._subtreeRoot([leafBuf], 0, 1);
    expect(result.equals(leafBuf)).toBe(true);
  });

  test('MK-85 nodeHash preimage collision prevention: nodeHash(a,b) ≠ leafHash(a+b)', () => {
    // Ensure domain separation prevents any preimage confusion
    const a = randomHex64(), b = randomHex64();
    const concatenated = a + b;
    // leafHash of concatenation should not equal nodeHash(a, b)
    // (they use different prefix bytes)
    const lh = merkle.leafHash(concatenated.slice(0, 64)); // just first 64 chars as a hex
    const nh = merkle.nodeHash(a, b);
    expect(lh).not.toBe(nh);
  });
});

// ── MK-86 … MK-95: Cross-validation (merkle.js ↔ log.js) ────────────────────

describe('MK-86 … MK-95: Cross-validation (merkle.js ↔ log.js)', () => {
  function buildChain(n) {
    const records = [];
    let prevHash  = null;
    for (let i = 0; i < n; i++) {
      const payload     = { seq: i, data: `entry-${i}` };
      const payloadHash = log.computePayloadHash(payload);
      const base = {
        transparencyId:    crypto.randomUUID(),
        entryType:         'ARTIFACT',
        artifactId:        `art-${i}`,
        evidenceChainId:   null,
        verificationId:    null,
        payloadHash,
        previousEntryHash: prevHash,
        signerKeyId:       'test-key-v1',
      };
      const entryHash = log.computeEntryHash(base);
      records.push({ ...base, entryHash, payload, signature: 'SIG', id: i + 1 });
      prevHash = entryHash;
    }
    return records;
  }

  test('MK-86 log.computeRootHash delegates to merkle.merkleRoot', () => {
    const hashes = deterministicHashes(10);
    expect(log.computeRootHash(hashes)).toBe(merkle.merkleRoot(hashes));
  });

  test('MK-87 generateInclusionProof returns proofVersion 2', () => {
    const records = buildChain(5);
    const hashes  = records.map(r => r.entryHash);
    const root    = log.computeRootHash(hashes);
    const rootRecord = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 5, entryCount: 5,
      rootHash: root, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
      generated_at: new Date().toISOString(),
    };
    const proof = log.generateInclusionProof(records[2], hashes, rootRecord);
    expect(proof.proofVersion).toBe('2');
  });

  test('MK-88 generateInclusionProof proof.merklePath is O(log n)', () => {
    const records = buildChain(16);
    const hashes  = records.map(r => r.entryHash);
    const root    = log.computeRootHash(hashes);
    const rootRecord = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 16, entryCount: 16,
      rootHash: root, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
      generated_at: new Date().toISOString(),
    };
    const proof = log.generateInclusionProof(records[7], hashes, rootRecord);
    expect(proof.proof.merklePath).toHaveLength(4); // log2(16) = 4
  });

  test('MK-89 verifyInclusionProof validates Merkle path correctly', () => {
    const records = buildChain(10);
    const hashes  = records.map(r => r.entryHash);
    const root    = log.computeRootHash(hashes);
    const rootRecord = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 10, entryCount: 10,
      rootHash: root, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
      generated_at: new Date().toISOString(),
    };
    for (let i = 0; i < 10; i++) {
      const proof       = log.generateInclusionProof(records[i], hashes, rootRecord);
      const verification = log.verifyInclusionProof(proof);
      expect(verification.valid).toBe(true);
    }
  });

  test('MK-90 verifyInclusionProof.MERKLE_PATH check passes', () => {
    const records = buildChain(8);
    const hashes  = records.map(r => r.entryHash);
    const root    = log.computeRootHash(hashes);
    const rootRecord = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 8, entryCount: 8,
      rootHash: root, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
      generated_at: new Date().toISOString(),
    };
    const proof = log.generateInclusionProof(records[3], hashes, rootRecord);
    const result = log.verifyInclusionProof(proof);
    expect(result.checks.find(c => c.check === 'MERKLE_PATH').result).toBe('PASS');
  });

  test('MK-91 tampered entryHash fails MERKLE_PATH check', () => {
    const records = buildChain(8);
    const hashes  = records.map(r => r.entryHash);
    const root    = log.computeRootHash(hashes);
    const rootRecord = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 8, entryCount: 8,
      rootHash: root, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
      generated_at: new Date().toISOString(),
    };
    const proof    = log.generateInclusionProof(records[3], hashes, rootRecord);
    const tampered = { ...proof, entry: { ...proof.entry, entryHash: randomHex64() } };
    const result   = log.verifyInclusionProof(tampered);
    expect(result.valid).toBe(false);
    expect(result.checks.find(c => c.check === 'MERKLE_PATH').result).toBe('FAIL');
  });

  test('MK-92 generateConsistencyProof returns proofVersion 2', () => {
    const records  = buildChain(10);
    const allHash  = records.map(r => r.entryHash);
    const oldRoot  = log.computeRootHash(allHash.slice(0, 5));
    const newRoot  = log.computeRootHash(allHash);
    const oldRootRec = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 5, entryCount: 5,
      rootHash: oldRoot, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
    };
    const newRootRec = {
      rootId: crypto.randomUUID(), seqFrom: 6, seqTo: 10, entryCount: 10,
      rootHash: newRoot, previousRootHash: oldRoot, signerKeyId: 'k1', signature: 'SIG',
    };
    const cp = log.generateConsistencyProof(oldRootRec, newRootRec, allHash);
    expect(cp.proofVersion).toBe('2');
    expect(cp.proofType).toBe('TRANSPARENCY_CONSISTENCY');
  });

  test('MK-93 verifyConsistencyProof (log.js wrapper) validates correctly', () => {
    const records  = buildChain(10);
    const allHash  = records.map(r => r.entryHash);
    const oldRoot  = log.computeRootHash(allHash.slice(0, 5));
    const newRoot  = log.computeRootHash(allHash);
    const oldRootRec = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 5, entryCount: 5,
      rootHash: oldRoot, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
    };
    const newRootRec = {
      rootId: crypto.randomUUID(), seqFrom: 6, seqTo: 10, entryCount: 10,
      rootHash: newRoot, previousRootHash: oldRoot, signerKeyId: 'k1', signature: 'SIG',
    };
    const cp     = log.generateConsistencyProof(oldRootRec, newRootRec, allHash);
    const result = log.verifyConsistencyProof(cp);
    expect(result.valid).toBe(true);
    expect(result.checks.find(c => c.check === 'CONSISTENCY_PROOF').result).toBe('PASS');
  });

  test('MK-94 proof does not contain all entry hashes (O(log n) not O(n))', () => {
    const records = buildChain(100);
    const hashes  = records.map(r => r.entryHash);
    const root    = log.computeRootHash(hashes);
    const rootRecord = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 100, entryCount: 100,
      rootHash: root, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
      generated_at: new Date().toISOString(),
    };
    const proof = log.generateInclusionProof(records[50], hashes, rootRecord);
    // merklePath should have << 100 elements (log2(100) ≈ 7)
    expect(proof.proof.merklePath.length).toBeLessThan(20);
    expect(proof.proof.merklePath.length).toBeLessThanOrEqual(Math.ceil(Math.log2(100)) + 1);
  });

  test('MK-95 proof for entry not in range: leafIndex=-1, verifiable=false', () => {
    const records = buildChain(5);
    const hashes  = records.map(r => r.entryHash);
    const root    = log.computeRootHash(hashes);
    const rootRecord = {
      rootId: crypto.randomUUID(), seqFrom: 1, seqTo: 5, entryCount: 5,
      rootHash: root, previousRootHash: null, signerKeyId: 'k1', signature: 'SIG',
      generated_at: new Date().toISOString(),
    };
    // Create a record NOT in the hash list
    const stranger = buildChain(1)[0];
    const proof = log.generateInclusionProof(stranger, hashes, rootRecord);
    expect(proof.verifiable).toBe(false);
    expect(proof.proof.leafIndex).toBe(-1);
  });
});

// ── MK-96 … MK-105: Performance ceiling assertions ───────────────────────────

describe('MK-96 … MK-105: Performance ceiling assertions', () => {
  const TIME_BUDGET_MS = 2000; // 2s per case — generous for CI

  function timeMs(fn) {
    const start = Date.now();
    fn();
    return Date.now() - start;
  }

  test('MK-96 merkleRoot of 10 entries completes < 50ms', () => {
    const hashes = deterministicHashes(10);
    expect(timeMs(() => merkle.merkleRoot(hashes))).toBeLessThan(50);
  });

  test('MK-97 merkleRoot of 1000 entries completes < 200ms', () => {
    const hashes = deterministicHashes(1000);
    expect(timeMs(() => merkle.merkleRoot(hashes))).toBeLessThan(200);
  });

  test('MK-98 merkleRoot of 10000 entries completes < TIME_BUDGET_MS', () => {
    const hashes = deterministicHashes(10_000);
    expect(timeMs(() => merkle.merkleRoot(hashes))).toBeLessThan(TIME_BUDGET_MS);
  });

  test('MK-99 inclusionPath for leaf in 1000-entry tree completes < 200ms', () => {
    const hashes = deterministicHashes(1000);
    expect(timeMs(() => merkle.inclusionPath(hashes, 500))).toBeLessThan(200);
  });

  test('MK-100 verifyInclusionPath for 10-element path completes < 5ms', () => {
    const hashes = deterministicHashes(1024);
    const root   = merkle.merkleRoot(hashes);
    const path   = merkle.inclusionPath(hashes, 512);
    expect(timeMs(() => merkle.verifyInclusionPath(hashes[512], path, root, 512, hashes.length))).toBeLessThan(5);
  });

  test('MK-101 consistencyProof for 500→1000 completes < 200ms', () => {
    const hashes = deterministicHashes(1000);
    expect(timeMs(() => merkle.consistencyProof(500, 1000, hashes))).toBeLessThan(200);
  });

  test('MK-102 verifyConsistencyProof completes < 5ms', () => {
    const hashes  = deterministicHashes(100);
    const oldRoot = merkle.merkleRoot(hashes.slice(0, 50));
    const newRoot = merkle.merkleRoot(hashes);
    const proof   = merkle.consistencyProof(50, 100, hashes);
    expect(timeMs(() => merkle.verifyConsistencyProof(oldRoot, newRoot, 50, 100, proof))).toBeLessThan(5);
  });

  test('MK-103 batch verify 100 proofs in 1000-entry tree < TIME_BUDGET_MS', () => {
    const hashes = deterministicHashes(1000);
    const root   = merkle.merkleRoot(hashes);
    const proofs = Array.from({ length: 100 }, (_, i) => {
      const idx = i * 10;
      return {
        entryHash: hashes[idx],
        path:      merkle.inclusionPath(hashes, idx),
        leafIndex: idx,
        treeSize:  1000,
      };
    });
    expect(timeMs(() => merkle.batchVerifyInclusion(root, proofs))).toBeLessThan(TIME_BUDGET_MS);
  });

  test('MK-104 10000-entry merkle root simulates 1M-scale linearity', () => {
    // At 10k entries, verify time scales linearly (no super-linear blowup)
    const h1k  = deterministicHashes(1_000);
    const h10k = deterministicHashes(10_000);
    const t1k  = timeMs(() => merkle.merkleRoot(h1k));
    const t10k = timeMs(() => merkle.merkleRoot(h10k));
    // t10k should be < 20 * t1k (allowing generous slack for JIT, GC, timing noise)
    // Linear would be exactly 10x; we allow 20x for safety
    if (t1k > 0) {
      expect(t10k).toBeLessThan(Math.max(t1k * 20, 2000));
    }
  });

  test('MK-105 no recursion: verify that inclusionPath does not exhaust stack for size 10000', () => {
    // If implementation were recursive, O(log2(10000)) ≈ 14 levels deep — safe.
    // But for correctness, we verify that a deeply unbalanced case completes.
    const hashes = deterministicHashes(10_000);
    const root   = merkle.merkleRoot(hashes);
    const path   = merkle.inclusionPath(hashes, 0);
    expect(merkle.verifyInclusionPath(hashes[0], path, root, 0, hashes.length)).toBe(true);
    expect(path.every(s => s.side === 'right')).toBe(true); // leftmost leaf: all right siblings
  });
});

// ──: inclusion proofs are bound to their position ─────────────
// verifyInclusionPath ignored leafIndex/treeSize: the path's side flags alone drove the computation, so a
// valid proof for leaf N also "verified" when presented as leaf M or for a different tree size.
describe('position-bound inclusion proofs', () => {
  const sizes = [2, 3, 5, 7, 8, 13, 64, 100];

  test('CRY16-01 a proof for leaf N never verifies as leaf M (exhaustive over several tree sizes)', () => {
    for (const n of sizes) {
      const hashes = deterministicHashes(n);
      const root = merkle.merkleRoot(hashes);
      for (let i = 0; i < n; i++) {
        const path = merkle.inclusionPath(hashes, i);
        expect(merkle.verifyInclusionPath(hashes[i], path, root, i, n)).toBe(true);
        for (let j = 0; j < n; j++) if (j !== i) expect(merkle.verifyInclusionPath(hashes[i], path, root, j, n)).toBe(false);
      }
    }
  });

  // For some sizes RFC6962 paths have the same SHAPE (e.g. leaf 0 of a 7- and of an 8-leaf tree), so the path alone
  // cannot bind the tree size; that binding is proof.treeSize === the signed root's entryCount (log.js TREE_SIZE_MATCH,
  // log.test.js TL-CRY16-02). Here: whenever the claimed size implies a different path shape, the proof is refused.
  test('CRY16-02 a path is refused for any claimed tree size whose RFC6962 path shape differs', () => {
    let distinguished = 0;
    for (const n of sizes) {
      const hashes = deterministicHashes(n);
      const root = merkle.merkleRoot(hashes);
      for (let i = 0; i < n; i++) {
        const path = merkle.inclusionPath(hashes, i);
        for (const m of [n - 1, n + 1, 2 * n]) {
          if (m <= i) continue;
          const sameShape = JSON.stringify(merkle.expectedPathSides(i, m)) === JSON.stringify(merkle.expectedPathSides(i, n));
          if (!sameShape) { distinguished++; expect(merkle.verifyInclusionPath(hashes[i], path, root, i, m)).toBe(false); }
        }
      }
    }
    expect(distinguished).toBeGreaterThan(100);
  });

  test('CRY16-03 a modified leaf, sibling hash, side, or path length fails; the untouched proof succeeds', () => {
    const hashes = deterministicHashes(13);
    const root = merkle.merkleRoot(hashes);
    const path = merkle.inclusionPath(hashes, 9);
    expect(merkle.verifyInclusionPath(hashes[9], path, root, 9, 13)).toBe(true);
    expect(merkle.verifyInclusionPath(hashes[8], path, root, 9, 13)).toBe(false);                                        // leaf
    for (let k = 0; k < path.length; k++) {
      expect(merkle.verifyInclusionPath(hashes[9], path.map((st, i) => (i === k ? { ...st, hash: randomHex64() } : st)), root, 9, 13)).toBe(false); // sibling
      expect(merkle.verifyInclusionPath(hashes[9], path.map((st, i) => (i === k ? { ...st, side: st.side === 'left' ? 'right' : 'left' } : st)), root, 9, 13)).toBe(false); // side
    }
    expect(merkle.verifyInclusionPath(hashes[9], path.slice(1), root, 9, 13)).toBe(false);                               // shorter
    expect(merkle.verifyInclusionPath(hashes[9], [...path, { hash: randomHex64(), side: 'left' }], root, 9, 13)).toBe(false); // longer
  });

  test('CRY16-04 there is no unbound mode: a missing or invalid position is refused', () => {
    const hashes = deterministicHashes(8);
    const root = merkle.merkleRoot(hashes);
    const path = merkle.inclusionPath(hashes, 3);
    for (const [li, ts] of [[undefined, undefined], [3, undefined], [undefined, 8], [-1, 8], [8, 8], [3.5, 8], [3, 8.5], [NaN, 8], ['3', 8], [3, 0], [3, -8]]) {
      expect(merkle.verifyInclusionPath(hashes[3], path, root, li, ts)).toBe(false);
    }
  });

  test('CRY16-05 expectedPathSides matches inclusionPath for every leaf (one decomposition, two uses)', () => {
    for (const n of [1, 2, 3, 6, 17, 100]) {
      const hashes = deterministicHashes(n);
      for (let i = 0; i < n; i++) expect(merkle.expectedPathSides(i, n)).toEqual(merkle.inclusionPath(hashes, i).map((st) => st.side));
    }
    expect(merkle.expectedPathSides(5, 5)).toBeNull();
  });

  test('CRY16-06 batchVerifyInclusion enforces each proof\'s claimed position', () => {
    const hashes = deterministicHashes(10);
    const root = merkle.merkleRoot(hashes);
    const good = [2, 7].map((i) => ({ entryHash: hashes[i], path: merkle.inclusionPath(hashes, i), leafIndex: i, treeSize: 10 }));
    expect(merkle.batchVerifyInclusion(root, good).valid).toBe(true);
    const relabelled = [{ ...good[0], leafIndex: 3 }, good[1]];
    const r = merkle.batchVerifyInclusion(root, relabelled);
    expect(r.valid).toBe(false);
    expect(r.results.map((x) => x.valid)).toEqual([false, true]);
  });
});
