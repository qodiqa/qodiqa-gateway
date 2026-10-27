'use strict';

/**
 * RFC6962-compatible Merkle Tree — Component #22
 *
 * Implements the Certificate Transparency Merkle tree specification:
 *   RFC6962 §2.1  Hash function — domain-separated SHA-256
 *   RFC6962 §2.1.1 Merkle Audit Proof (inclusion proof)
 *   RFC6962 §2.1.2 Merkle Consistency Proof
 *
 * Leaf hash:   H(0x00 || leaf_data)
 * Node hash:   H(0x01 || left || right)
 *
 * All tree traversal is iterative — no recursion, no stack overflow risk.
 * The stack-based iterative algorithm is mathematically equivalent to RFC6962's
 * recursive definition (verified against §2.1 examples).
 *
 * Performance characteristics:
 *   - merkleRoot:         O(n) time, O(log n) space (stack)
 *   - inclusionPath:      O(n) time, O(log n) proof size
 *   - verifyInclusionPath: O(log n) time
 *   - consistencyProof:   O(n) time, O(log n) proof size
 *   - verifyConsistency:  O(log n) time
 */

const { createHash } = require('crypto');

// ── RFC6962 domain prefixes ───────────────────────────────────────────────────
// Prevent second-preimage attacks by domain-separating leaf and node hashes.

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

// ── Internal primitives ───────────────────────────────────────────────────────

/**
 * Compute SHA-256 of (0x00 || bytes(entryHashHex)).
 * Returns a 32-byte Buffer.
 *
 * @param {string} entryHashHex — 64-char hex entry hash
 * @returns {Buffer}
 */
function _leafHashBuf(entryHashHex) {
  return createHash('sha256')
    .update(LEAF_PREFIX)
    .update(Buffer.from(entryHashHex, 'hex'))
    .digest();
}

/**
 * Compute SHA-256 of (0x01 || left || right).
 * Returns a 32-byte Buffer.
 *
 * @param {Buffer} leftBuf
 * @param {Buffer} rightBuf
 * @returns {Buffer}
 */
function _nodeHashBuf(leftBuf, rightBuf) {
  return createHash('sha256')
    .update(NODE_PREFIX)
    .update(leftBuf)
    .update(rightBuf)
    .digest();
}

/**
 * Largest power of 2 strictly less than n.
 * RFC6962 uses this split point for all internal nodes.
 *
 * @param {number} n — must be >= 2
 * @returns {number}
 */
function _largestPow2LessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Compute the Merkle root hash of leaves[offset..offset+count-1].
 * Leaves must already be Merkle leaf hashes (32-byte Buffers).
 *
 * Uses iterative stack-based algorithm equivalent to RFC6962 §2.1 recursive definition.
 * Proof: each iteration merges pairs of equal-height subtrees, producing the same
 * power-of-2 split structure as MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n])).
 *
 * Space: O(log n) stack entries.
 *
 * @param {Buffer[]} leaves
 * @param {number}   offset
 * @param {number}   count
 * @returns {Buffer}
 */
function _subtreeRoot(leaves, offset, count) {
  if (count === 1) return leaves[offset];

  const stack = []; // [{buf: Buffer, height: number}]

  for (let i = 0; i < count; i++) {
    let h      = leaves[offset + i];
    let height = 0;

    while (stack.length > 0 && stack[stack.length - 1].height === height) {
      h = _nodeHashBuf(stack.pop().buf, h);
      height++;
    }
    stack.push({ buf: h, height });
  }

  // Finalize: merge remaining stack entries from right-to-left (shallowest sibling first)
  let result = stack[stack.length - 1].buf;
  for (let i = stack.length - 2; i >= 0; i--) {
    result = _nodeHashBuf(stack[i].buf, result);
  }
  return result;
}

// ── Public hash functions ─────────────────────────────────────────────────────

/**
 * RFC6962 leaf hash: SHA-256(0x00 || bytes(entryHashHex)).
 *
 * @param {string} entryHashHex — 64-char hex
 * @returns {string} 64-char hex
 */
function leafHash(entryHashHex) {
  return _leafHashBuf(entryHashHex).toString('hex');
}

/**
 * RFC6962 node hash: SHA-256(0x01 || bytes(leftHex) || bytes(rightHex)).
 *
 * @param {string} leftHex  — 64-char hex
 * @param {string} rightHex — 64-char hex
 * @returns {string} 64-char hex
 */
function nodeHash(leftHex, rightHex) {
  return _nodeHashBuf(
    Buffer.from(leftHex,  'hex'),
    Buffer.from(rightHex, 'hex'),
  ).toString('hex');
}

// ── Root computation ──────────────────────────────────────────────────────────

/**
 * Compute the Merkle root of an ordered list of entry hashes.
 *
 * For a single entry, returns leafHash(entries[0]).
 * For n > 1, computes the RFC6962 Merkle tree root iteratively.
 *
 * Throws for empty input — callers must ensure at least one entry.
 *
 * @param {string[]} entryHashHexArray — ordered entry_hash values
 * @returns {string} 64-char hex Merkle root
 */
function merkleRoot(entryHashHexArray) {
  if (!Array.isArray(entryHashHexArray) || entryHashHexArray.length === 0) {
    throw new RangeError('merkleRoot: entryHashHexArray must be a non-empty array');
  }
  const leaves = entryHashHexArray.map(_leafHashBuf);
  return _subtreeRoot(leaves, 0, leaves.length).toString('hex');
}

// ── Inclusion proof ───────────────────────────────────────────────────────────

/**
 * Generate an RFC6962 Merkle audit proof (inclusion proof) for a leaf.
 *
 * Returns the O(log n) path of sibling hashes from leaf to root.
 * Each step has a hash and a side ('left'|'right') indicating which side
 * the sibling is on — the verifier uses this to reconstruct the root.
 *
 * @param {string[]} entryHashHexArray — all entry hashes in the tree
 * @param {number}   leafIndex         — 0-based index of the target leaf
 * @returns {Array<{hash: string, side: 'left'|'right'}>}
 */
function inclusionPath(entryHashHexArray, leafIndex) {
  const n = entryHashHexArray.length;

  if (leafIndex < 0 || leafIndex >= n) {
    throw new RangeError(`inclusionPath: leafIndex ${leafIndex} out of range [0, ${n - 1}]`);
  }
  if (n === 1) return []; // single entry; root is the leaf hash, no path needed

  const leaves = entryHashHexArray.map(_leafHashBuf);
  const path   = [];

  let lo   = 0;
  let size = n;
  let idx  = leafIndex;

  while (size > 1) {
    const k = _largestPow2LessThan(size);

    if (idx < k) {
      // Target is in left subtree; sibling is the right subtree root
      path.push({
        hash: _subtreeRoot(leaves, lo + k, size - k).toString('hex'),
        side: 'right',
      });
      size = k;
    } else {
      // Target is in right subtree; sibling is the left subtree root
      path.push({
        hash: _subtreeRoot(leaves, lo, k).toString('hex'),
        side: 'left',
      });
      lo  += k;
      idx -= k;
      size -= k;
    }
  }

  // RFC6962 §2.1.1 PATH() is defined recursively so deeper siblings come first.
  // Our iterative loop collects them root-to-leaf (shallowest first).
  // Reverse so verifyInclusionPath can process deepest-first (matching PATH()).
  path.reverse();
  return path;
}

/**
 *the side of every sibling on the RFC6962 audit path of leaf
 * `leafIndex` in a tree of `treeSize` leaves, deepest first — the same decomposition inclusionPath() walks. For a given
 * tree size the index determines the path length and every side uniquely, so comparing a supplied path's sides with
 * this sequence binds the proof to its claimed position. Returns null for an invalid (index, size) pair.
 *
 * @param {number} leafIndex
 * @param {number} treeSize
 * @returns {Array<'left'|'right'>|null}
 */
function expectedPathSides(leafIndex, treeSize) {
  if (!Number.isSafeInteger(leafIndex) || !Number.isSafeInteger(treeSize) || leafIndex < 0 || leafIndex >= treeSize) return null;
  const sides = [];
  let size = treeSize;
  let idx  = leafIndex;
  while (size > 1) {
    const k = _largestPow2LessThan(size);
    if (idx < k) { sides.push('right'); size = k; } else { sides.push('left'); idx -= k; size -= k; }
  }
  return sides.reverse();
}

/**
 * Verify an RFC6962 Merkle audit proof, BOUND TO ITS POSITION.
 *
 * Rebuilds the Merkle root from the leaf and path, then compares with rootHex — and first requires the path
 * to be exactly the one RFC6962 defines for leaf `leafIndex` of a `treeSize`-leaf tree: same length, same side at
 * every step. leafIndex/treeSize were ignored ("kept for API symmetry"), so a valid proof for leaf N also
 * "verified" when relabelled as leaf M, or for another tree size; the side flags alone drove the computation.
 * The caller must also bind treeSize to the signed root (entryCount) — see log.js verifyInclusionProof.
 * O(log n) time — only processes path elements, no tree traversal.
 *
 * @param {string} entryHashHex — the entry's entry_hash (pre-Merkle leaf)
 * @param {Array<{hash: string, side: string}>} path — from inclusionPath()
 * @param {string} rootHex     — expected Merkle root
 * @param {number} leafIndex   — the claimed 0-based position (required)
 * @param {number} treeSize    — the claimed tree size (required)
 * @returns {boolean}
 */
function verifyInclusionPath(entryHashHex, path, rootHex, leafIndex, treeSize) {
  if (!entryHashHex || !Array.isArray(path) || !rootHex) return false;

  const sides = expectedPathSides(leafIndex, treeSize);
  if (!sides || path.length !== sides.length) return false;
  for (let i = 0; i < sides.length; i++) {
    if (!path[i] || path[i].side !== sides[i]) return false;
  }

  let current = _leafHashBuf(entryHashHex);

  for (const { hash, side } of path) {
    const sibBuf = Buffer.from(hash, 'hex');
    current = side === 'right'
      ? _nodeHashBuf(current, sibBuf)
      : _nodeHashBuf(sibBuf, current);
  }

  return current.toString('hex') === rootHex;
}

// ── Consistency proof ─────────────────────────────────────────────────────────

/**
 * Generate an RFC6962 Merkle consistency proof.
 *
 * Proves that tree(oldSize) is a prefix of tree(newSize) using
 * PROOF(m, D[n]) = SUBPROOF(m, D[n], true) from RFC6962 §2.1.2.
 *
 * The algorithm is iterative: traverse the tree path, collecting sibling hashes,
 * then order them per RFC6962 (base-case hash first if b=false, then siblings
 * from deepest to shallowest).
 *
 * Returns an empty array when oldSize === newSize (trivially consistent).
 *
 * @param {number}   oldSize             — number of entries in the older tree
 * @param {number}   newSize             — number of entries in the newer tree
 * @param {string[]} entryHashHexArray   — all newSize entry hashes (includes the old entries)
 * @returns {string[]} proof — ordered list of 64-char hex hashes
 */
function consistencyProof(oldSize, newSize, entryHashHexArray) {
  if (typeof oldSize !== 'number' || typeof newSize !== 'number') {
    throw new TypeError('consistencyProof: sizes must be numbers');
  }
  if (oldSize < 0 || newSize < 0 || oldSize > newSize) {
    throw new RangeError('consistencyProof: invalid sizes');
  }
  if (newSize !== entryHashHexArray.length) {
    throw new RangeError('consistencyProof: entryHashHexArray length must equal newSize');
  }
  if (oldSize === 0 || oldSize === newSize) return [];

  const leaves  = entryHashHexArray.map(_leafHashBuf);
  const suffixes = []; // collected shallow-to-deep during traversal

  let lo   = 0;
  let size = newSize;
  let m    = oldSize;
  let b    = true;

  // Iterative SUBPROOF traversal
  while (m !== size) {
    const k = _largestPow2LessThan(size);

    if (m <= k) {
      // SUBPROOF(m, D[lo:lo+k], b) ++ [MTH(D[lo+k:lo+size])]
      suffixes.push(_subtreeRoot(leaves, lo + k, size - k));
      size = k;
    } else {
      // SUBPROOF(m-k, D[lo+k:lo+size], false) ++ [MTH(D[lo:lo+k])]
      suffixes.push(_subtreeRoot(leaves, lo, k));
      lo   += k;
      m    -= k;
      size -= k;
      b     = false;
    }
  }

  // RFC6962 proof = [base_if_b_false] ++ suffixes[deepest..shallowest]
  const proof = [];
  if (!b) {
    // Base case adds MTH(D[lo:lo+m]) as the first element
    proof.push(_subtreeRoot(leaves, lo, m).toString('hex'));
  }
  // Append collected siblings in reverse order (deepest first)
  for (let i = suffixes.length - 1; i >= 0; i--) {
    proof.push(suffixes[i].toString('hex'));
  }

  return proof;
}

/**
 * Verify an RFC6962 Merkle consistency proof.
 *
 * Reconstructs both old_root and new_root from the proof hashes and verifies
 * they match the provided values.  O(log n) time.
 *
 * @param {string}   oldRoot  — Merkle root of the older tree
 * @param {string}   newRoot  — Merkle root of the newer tree
 * @param {number}   oldSize  — number of entries in the older tree
 * @param {number}   newSize  — number of entries in the newer tree
 * @param {string[]} proof    — from consistencyProof()
 * @returns {boolean}
 */
function verifyConsistencyProof(oldRoot, newRoot, oldSize, newSize, proof) {
  if (oldSize === 0) return true;
  if (oldSize === newSize) return oldRoot === newRoot && proof.length === 0;
  if (oldSize > newSize) return false;
  if (!Array.isArray(proof)) return false;

  // Replay the generation path to determine decision sequence
  const decisions = []; // [{wentRight: boolean}] — shallow to deep
  let m    = oldSize;
  let size = newSize;
  let b    = true;

  while (m !== size) {
    const k = _largestPow2LessThan(size);
    if (m <= k) {
      decisions.push({ wentRight: false });
      size = k;
    } else {
      decisions.push({ wentRight: true });
      m    -= k;
      size -= k;
      b     = false;
    }
  }

  const expectedLen = decisions.length + (b ? 0 : 1);
  if (proof.length !== expectedLen) return false;

  let proofIdx = 0;

  // Initialize fn/sn: both start at the base case value
  let fn, sn;
  if (!b) {
    const baseBuf = Buffer.from(proof[proofIdx++], 'hex');
    fn = baseBuf;
    sn = baseBuf;
  } else {
    // b=true: old_root covers all m leaves in the left subtree at the terminal level
    fn = Buffer.from(oldRoot, 'hex');
    sn = Buffer.from(oldRoot, 'hex');
  }

  // Unwind decisions from deepest to shallowest (reverse order)
  // proof hashes are ordered deepest-first (matching reversed suffixes)
  for (let i = decisions.length - 1; i >= 0; i--) {
    const sibBuf = Buffer.from(proof[proofIdx++], 'hex');

    if (decisions[i].wentRight) {
      // At this level, old leaves were in the right subtree → sibling is left
      // Both old_root and new_root incorporate the left sibling
      sn = _nodeHashBuf(sibBuf, sn);
      fn = _nodeHashBuf(sibBuf, fn);
    } else {
      // At this level, old leaves were in the left subtree → sibling is right
      // Only new_root incorporates the right sibling; old_root is purely left
      sn = _nodeHashBuf(sn, sibBuf);
      // fn unchanged
    }
  }

  return fn.toString('hex') === oldRoot && sn.toString('hex') === newRoot;
}

// ── Batch verification ────────────────────────────────────────────────────────

/**
 * Verify multiple inclusion proofs against a single Merkle root.
 *
 * Each proof must have: { entryHash, path, leafIndex, treeSize }
 * (leafIndex and treeSize are verified — each path must be the one for its claimed position).
 *
 * @param {string}   rootHex — Merkle root all proofs are verified against
 * @param {Array<{entryHash: string, path: Array, leafIndex: number, treeSize: number}>} proofs
 * @returns {{ valid: boolean, verifiedCount: number, results: Array }}
 */
function batchVerifyInclusion(rootHex, proofs) {
  if (!Array.isArray(proofs)) throw new TypeError('batchVerifyInclusion: proofs must be an array');

  const results = proofs.map((p, i) => {
    try {
      const valid = verifyInclusionPath(p.entryHash, p.path, rootHex, p.leafIndex, p.treeSize);
      return { index: i, entryHash: p.entryHash, leafIndex: p.leafIndex, valid, error: null };
    } catch (err) {
      return { index: i, entryHash: p.entryHash, leafIndex: p.leafIndex, valid: false, error: err.message };
    }
  });

  return {
    valid:         results.every(r => r.valid),
    verifiedCount: results.length,
    results,
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  // Hash primitives
  leafHash,
  nodeHash,
  // Root computation
  merkleRoot,
  // Inclusion proofs (O(log n))
  inclusionPath,
  verifyInclusionPath,
  expectedPathSides,
  // Consistency proofs (RFC6962 §2.1.2)
  consistencyProof,
  verifyConsistencyProof,
  // Batch operations
  batchVerifyInclusion,
  // Internal helpers exported for tests
  _leafHashBuf,
  _nodeHashBuf,
  _largestPow2LessThan,
  _subtreeRoot,
};
