/**
 * RFC6962-compatible Merkle tree — verification-only SDK-side port of
 * `src/core/transparency/merkle.js`. Tree/proof *generation* is a server-only
 * concern; the SDK only ever needs to verify an inclusion path it was given.
 *
 * Leaf hash:  H(0x00 || bytes(entryHashHex))
 * Node hash:  H(0x01 || left || right)
 *
 * @module
 */

import crypto from 'node:crypto';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export interface MerklePathStep {
  hash: string;
  side: 'left' | 'right';
}

function leafHashBuf(entryHashHex: string): Buffer {
  return crypto.createHash('sha256').update(LEAF_PREFIX).update(Buffer.from(entryHashHex, 'hex')).digest();
}

function nodeHashBuf(left: Buffer, right: Buffer): Buffer {
  return crypto.createHash('sha256').update(NODE_PREFIX).update(left).update(right).digest();
}

/**
 * the RFC6962 side sequence (deepest first) of leaf `leafIndex` in a
 * `treeSize`-leaf tree — for a given tree size the index determines the path
 * length and every side. `null` for an invalid (index, size) pair.
 */
export function expectedPathSides(leafIndex: number, treeSize: number): Array<'left' | 'right'> | null {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize) || leafIndex < 0 || leafIndex >= treeSize) return null;
  const sides: Array<'left' | 'right'> = [];
  let size = treeSize;
  let idx = leafIndex;
  while (size > 1) {
    let k = 1;
    while (k * 2 < size) k *= 2; // largest power of two < size
    if (idx < k) { sides.push('right'); size = k; } else { sides.push('left'); idx -= k; size -= k; }
  }
  return sides.reverse();
}

/**
 * Verify an RFC6962 Merkle audit (inclusion) proof: rebuild the Merkle root
 * from the leaf's entry hash and the sibling path, then compare with
 * `rootHex`. Never throws — returns `false` for any malformed input.
 *
 * pass `leafIndex` and `treeSize` to bind the proof to its claimed
 * position — the path must then be exactly the RFC6962 path of that leaf
 * (same length, same side at every step), so a proof for leaf N cannot be
 * presented as leaf M. Without them only path → root is checked (the
 * pre-CRY-16 behaviour, kept for compatibility); `verifyTransparencyProof`
 * always binds, and also requires `treeSize` to equal the signed root's
 * `entryCount`.
 */
export function verifyInclusionPath(entryHashHex: string, path: MerklePathStep[], rootHex: string, leafIndex?: number, treeSize?: number): boolean {
  try {
    if (!entryHashHex || !Array.isArray(path) || !rootHex) return false;
    if (leafIndex !== undefined || treeSize !== undefined) {
      const sides = expectedPathSides(leafIndex as number, treeSize as number);
      if (!sides || path.length !== sides.length) return false;
      for (let i = 0; i < sides.length; i++) if (!path[i] || path[i]!.side !== sides[i]) return false;
    }

    let current = leafHashBuf(entryHashHex);
    for (const step of path) {
      if (!step || (step.side !== 'left' && step.side !== 'right') || typeof step.hash !== 'string') {
        return false;
      }
      const sibling = Buffer.from(step.hash, 'hex');
      current = step.side === 'right' ? nodeHashBuf(current, sibling) : nodeHashBuf(sibling, current);
    }

    return current.toString('hex') === rootHex;
  } catch {
    return false;
  }
}
