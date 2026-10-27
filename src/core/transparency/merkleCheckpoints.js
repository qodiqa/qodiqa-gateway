'use strict';

/**
 * Transparency Merkle block checkpoints.
 *
 * Maintains transparency_merkle_checkpoints (migration 059) — the RFC 6962
 * subtree hash of every complete, aligned block of BLOCK_SIZE leaves in id
 * order — and builds the tree context a root or an inclusion proof needs:
 * stored block hashes + the leaves of the final incomplete block (+ the target
 * leaf's block for a proof). See merkleBlocks.js for the math; results are
 * byte-identical to the full-tree computation.
 *
 * ids may have gaps (a rolled-back insert burns an id); the tree is over
 * POSITIONS in id order, so each block records its first_id/last_id and
 * positions are derived from blocks, never from ids.
 *
 * Blocks are derived data: deterministic from the (append-only) log, idempotent
 * to insert (ON CONFLICT DO NOTHING), and tamper-evident without a signature —
 * a wrong block hash produces a root/path that does not match the SIGNED root.
 */

const logStore = require('./logStore');
const merkle = require('./merkle');
const { createBlockMerkle } = require('./merkleBlocks');

const BLOCK_SIZE = (() => {
  const v = parseInt(process.env.QODIQA_TRANSPARENCY_MERKLE_BLOCK_SIZE || '1024', 10);
  return Number.isInteger(v) && v >= 2 && (v & (v - 1)) === 0 ? v : 1024;
})();

/**
 * Make sure every complete block whose last entry id is <= uptoId is stored.
 * @returns {Promise<Array<{blockIndex, firstId, lastId, subtreeHash}>>} blocks with lastId <= uptoId
 */
async function ensureBlocks({ tx, uptoId, blockSize = BLOCK_SIZE } = {}) {
  const blocks = await logStore.getMerkleBlocks(blockSize, { tx });
  blocks.forEach((b, i) => {
    if (b.blockIndex !== i) throw new Error(`MERKLE_CHECKPOINT_GAP: block ${i} missing (found index ${b.blockIndex})`);
  });
  let lastId = blocks.length ? blocks[blocks.length - 1].lastId : 0;
  for (;;) {
    const batch = await logStore.fetchEntriesFromId(lastId + 1, blockSize, { tx });
    if (batch.length < blockSize || Number(batch[blockSize - 1].id) > uptoId) break;
    const block = {
      blockIndex: blocks.length,
      firstId: Number(batch[0].id),
      lastId: Number(batch[blockSize - 1].id),
      subtreeHash: merkle.merkleRoot(batch.map((e) => e.entry_hash)),
    };
    await logStore.insertMerkleBlock({ blockSize, ...block }, { tx });
    blocks.push(block);
    lastId = block.lastId;
  }
  return blocks.filter((b) => b.lastId <= uptoId);
}

/**
 * Tree context for the log up to (and including) entry id `seqTo`.
 * @param {object} o
 * @param {number} o.seqTo
 * @param {number} [o.targetId]  entry id whose leaf index is wanted (proofs)
 * @returns {Promise<{treeSize, leafIndex, root: () => string, inclusionPath: (i) => object[], leavesRead: number}>}
 */
async function treeFor({ tx, seqTo, targetId = null, blockSize = BLOCK_SIZE } = {}) {
  const blocks = await ensureBlocks({ tx, uptoId: seqTo, blockSize });
  const tailFrom = blocks.length ? blocks[blocks.length - 1].lastId + 1 : 1;
  const tail = tailFrom <= seqTo ? await logStore.getHashesInRange(tailFrom, seqTo, { tx }) /* hash-only, app-executable */ : [];
  if (tail.length >= blockSize) throw new Error(`MERKLE_CHECKPOINT_TAIL_TOO_LONG: ${tail.length} >= ${blockSize}`);
  const base = blocks.length * blockSize;
  const leaves = new Map();
  tail.forEach((e, i) => leaves.set(base + i, merkle.leafHash(e.entry_hash)));

  let leafIndex = null;
  if (targetId !== null) {
    const inTail = tail.findIndex((e) => Number(e.id) === Number(targetId));
    if (inTail >= 0) {
      leafIndex = base + inTail;
    } else {
      const block = blocks.find((b) => b.firstId <= targetId && targetId <= b.lastId);
      if (block) {
        const entries = await logStore.fetchEntriesFromId(block.firstId, blockSize, { tx });
        const offset = entries.findIndex((e) => Number(e.id) === Number(targetId));
        if (offset >= 0) {
          entries.forEach((e, i) => leaves.set(block.blockIndex * blockSize + i, merkle.leafHash(e.entry_hash)));
          leafIndex = block.blockIndex * blockSize + offset;
        }
      }
    }
  }

  const bm = createBlockMerkle({
    blockSize,
    blockHashes: blocks.map((b) => b.subtreeHash),
    leafHashAt: (pos) => {
      const h = leaves.get(pos);
      if (h === undefined) throw new Error(`MERKLE_CHECKPOINT_LEAF_NOT_LOADED: position ${pos}`);
      return h;
    },
  });
  const treeSize = base + tail.length;
  return {
    treeSize,
    leafIndex,
    leavesRead: leaves.size,
    blocksUsed: blocks.length,
    root: () => bm.root(treeSize),
    inclusionPath: (i) => bm.inclusionPath(i, treeSize),
  };
}

module.exports = { ensureBlocks, treeFor, BLOCK_SIZE };
