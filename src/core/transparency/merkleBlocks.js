'use strict';

/**
 * RFC 6962 Merkle root / inclusion path from stored BLOCK checkpoints.
 *
 * every inclusion proof and every root rebuilt the tree from leaf 1
 * (merkle.inclusionPath / merkleRoot over the whole log). RFC 6962's MTH splits
 * a range of n leaves at the largest power of two k < n, so every complete,
 * aligned range of 2^j leaves is a fixed subtree whose hash never changes as
 * the log grows. With the hash of each complete aligned block of `blockSize`
 * leaves stored (transparency_merkle_checkpoints, migration 059), any root or
 * path needs only:
 *   - the stored block hashes, combined as a perfect binary tree for aligned
 *     power-of-two ranges >= blockSize; and
 *   - individual leaves only inside the target leaf's block and inside the
 *     final, incomplete block.
 * O(n / blockSize + blockSize) instead of O(n). Output is byte-identical to
 * merkle.merkleRoot / merkle.inclusionPath (property-tested against them).
 *
 * Pure: the caller supplies the block hashes and a leafHashAt(position)
 * accessor; leafHashAt throws for a position that was not loaded, so a gap in
 * the loading logic can never silently produce a wrong hash.
 */

const merkle = require('./merkle');

function _isPow2(n) { return n > 0 && (n & (n - 1)) === 0; }
function _largestPow2LessThan(n) { let k = 1; while (k * 2 < n) k *= 2; return k; }

/** Perfect binary tree over already-computed node hashes (length must be a power of two). */
function perfectFromNodes(nodes) {
  if (!_isPow2(nodes.length)) throw new RangeError(`perfectFromNodes: ${nodes.length} is not a power of two`);
  let level = nodes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(merkle.nodeHash(level[i], level[i + 1]));
    level = next;
  }
  return level[0];
}

/**
 * @param {object} src
 * @param {number}   src.blockSize      power of two >= 2
 * @param {string[]} src.blockHashes    hex subtree hash of complete block i (0..numBlocks-1)
 * @param {(pos: number) => string} src.leafHashAt  RFC 6962 LEAF hash (merkle.leafHash) at a position
 */
function createBlockMerkle({ blockSize, blockHashes, leafHashAt }) {
  if (!_isPow2(blockSize) || blockSize < 2) throw new RangeError('blockSize must be a power of two >= 2');
  const numBlocks = blockHashes.length;

  function subtreeHash(lo, count) {
    if (count === 1) return leafHashAt(lo);
    if (_isPow2(count) && count >= blockSize && lo % blockSize === 0) {
      const first = lo / blockSize; const n = count / blockSize;
      if (first + n > numBlocks) throw new RangeError(`subtreeHash: blocks ${first}..${first + n - 1} not all stored (${numBlocks})`);
      return n === 1 ? blockHashes[first] : perfectFromNodes(blockHashes.slice(first, first + n));
    }
    const k = _largestPow2LessThan(count);
    return merkle.nodeHash(subtreeHash(lo, k), subtreeHash(lo + k, count - k));
  }

  function root(treeSize) {
    if (!(treeSize >= 1)) throw new RangeError('root: treeSize must be >= 1');
    return subtreeHash(0, treeSize);
  }

  // Same walk as merkle.inclusionPath(), with subtreeHash() in place of a full leaf array.
  function inclusionPath(leafIndex, treeSize) {
    if (leafIndex < 0 || leafIndex >= treeSize) throw new RangeError(`inclusionPath: leafIndex ${leafIndex} out of range [0, ${treeSize - 1}]`);
    if (treeSize === 1) return [];
    const path = [];
    let lo = 0; let size = treeSize; let idx = leafIndex;
    while (size > 1) {
      const k = _largestPow2LessThan(size);
      if (idx < k) {
        path.push({ hash: subtreeHash(lo + k, size - k), side: 'right' });
        size = k;
      } else {
        path.push({ hash: subtreeHash(lo, k), side: 'left' });
        lo += k; idx -= k; size -= k;
      }
    }
    path.reverse();
    return path;
  }

  return { subtreeHash, root, inclusionPath };
}

module.exports = { createBlockMerkle, perfectFromNodes };
