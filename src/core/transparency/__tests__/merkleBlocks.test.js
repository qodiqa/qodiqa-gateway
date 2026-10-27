'use strict';

// roots/paths from block checkpoints must be byte-identical to the
// full-tree RFC 6962 implementation (merkle.js), while reading leaves ONLY from
// the target leaf's block and the final incomplete block.

const crypto = require('crypto');
const merkle = require('../merkle');
const { createBlockMerkle, perfectFromNodes } = require('../merkleBlocks');

function hashes(n, seed) {
  return Array.from({ length: n }, (_, i) => crypto.createHash('sha256').update(`${seed}:${i}`).digest('hex'));
}

function blockSrc(entryHashes, blockSize, allowed) {
  const numBlocks = Math.floor(entryHashes.length / blockSize);
  const blockHashes = [];
  for (let b = 0; b < numBlocks; b++) blockHashes.push(merkle.merkleRoot(entryHashes.slice(b * blockSize, (b + 1) * blockSize)));
  const reads = new Set();
  return {
    reads,
    bm: createBlockMerkle({
      blockSize, blockHashes,
      leafHashAt: (pos) => {
        if (allowed && !allowed(pos)) throw new Error(`leaf ${pos} read outside the allowed blocks`);
        reads.add(pos);
        return merkle.leafHash(entryHashes[pos]);
      },
    }),
    numBlocks,
  };
}

describe('perfectFromNodes', () => {
  test('equals merkleRoot of the underlying leaves for a power-of-two range', () => {
    const h = hashes(16, 'p');
    const blocks = [0, 1, 2, 3].map((b) => merkle.merkleRoot(h.slice(b * 4, b * 4 + 4)));
    expect(perfectFromNodes(blocks)).toBe(merkle.merkleRoot(h));
  });
  test('rejects a non power-of-two count', () => expect(() => perfectFromNodes(['a', 'b', 'c'])).toThrow(RangeError));
});

describe('root from blocks === full-tree merkleRoot', () => {
  const sizes = [1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 64, 65, 100, 127, 128, 129, 255, 257, 1000, 1023, 1024, 1025];
  for (const blockSize of [2, 4, 16, 64]) {
    test.each(sizes)(`blockSize ${blockSize}, n=%i`, (n) => {
      const h = hashes(n, `r${blockSize}`);
      const numBlocks = Math.floor(n / blockSize);
      const tailStart = numBlocks * blockSize;
      const { bm } = blockSrc(h, blockSize, (pos) => pos >= tailStart); // only the incomplete tail may be read
      expect(bm.root(n)).toBe(merkle.merkleRoot(h));
    });
  }
});

describe('inclusion path from blocks === full-tree inclusionPath, reading only 2 blocks of leaves', () => {
  const rnd = (() => { let s = 12345; return () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s; }; })();
  const cases = [];
  for (let i = 0; i < 60; i++) {
    const blockSize = [2, 4, 16, 64][i % 4];
    const n = 1 + (rnd() % 1500);
    cases.push([blockSize, n, rnd() % n]);
  }
  test.each(cases)('blockSize %i, n=%i, leaf %i', (blockSize, n, leaf) => {
    const h = hashes(n, `p${blockSize}:${n}`);
    const numBlocks = Math.floor(n / blockSize);
    const tailStart = numBlocks * blockSize;
    const targetBlock = Math.floor(leaf / blockSize);
    const allowed = (pos) => pos >= tailStart || Math.floor(pos / blockSize) === targetBlock;
    const { bm, reads } = blockSrc(h, blockSize, allowed);
    const path = bm.inclusionPath(leaf, n);
    expect(path).toEqual(merkle.inclusionPath(h, leaf));
    expect(merkle.verifyInclusionPath(h[leaf], path, merkle.merkleRoot(h), leaf, n)).toBe(true);
    expect(reads.size).toBeLessThanOrEqual(2 * blockSize);
  });

  test('a leaf index out of range is refused', () => {
    const { bm } = blockSrc(hashes(10, 'x'), 4);
    expect(() => bm.inclusionPath(10, 10)).toThrow(RangeError);
  });

  test('a missing block hash is detected, never silently recomputed', () => {
    const h = hashes(32, 'm');
    const bm = createBlockMerkle({ blockSize: 8, blockHashes: [], leafHashAt: (p) => merkle.leafHash(h[p]) });
    expect(() => bm.root(32)).toThrow(/not all stored/);
  });
});
