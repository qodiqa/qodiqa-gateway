'use strict';

// merkleCheckpoints.js against an in-memory log WITH id gaps,
// compared to the legacy full-tree computation (every entry from id 1).

jest.mock('../logStore');

const crypto = require('crypto');
const logStore = require('../logStore');
const merkle = require('../merkle');
const log = require('../log');
const { ensureBlocks, treeFor } = require('../merkleCheckpoints');

let ENTRIES; let BLOCKS; let READS;
function makeLog(n, gapEvery = 7) {
  const out = []; let id = 0;
  for (let i = 0; i < n; i++) {
    id += (i > 0 && i % gapEvery === 0) ? 3 : 1; // burned ids (rolled-back inserts)
    out.push({ id, entry_hash: crypto.createHash('sha256').update(`e${i}`).digest('hex') });
  }
  return out;
}

beforeEach(() => {
  jest.clearAllMocks();
  ENTRIES = makeLog(300); BLOCKS = []; READS = 0;
  logStore.getHashesInRange /* the tail read is hash-only */.mockImplementation(async (from, to) => {
    const r = ENTRIES.filter((e) => e.id >= from && e.id <= to); READS += r.length; return r;
  });
  logStore.fetchEntriesFromId.mockImplementation(async (from, limit) => {
    const r = ENTRIES.filter((e) => e.id >= from).slice(0, limit); READS += r.length; return r;
  });
  logStore.getMerkleBlocks.mockImplementation(async (size) => BLOCKS.filter((b) => b.blockSize === size).map(({ blockSize, ...b }) => b));
  logStore.insertMerkleBlock.mockImplementation(async (b) => { BLOCKS.push(b); });
});

const legacyTree = (seqTo) => ENTRIES.filter((e) => e.id <= seqTo).map((e) => e.entry_hash);

describe('ensureBlocks', () => {
  test('stores exactly the complete blocks, with first/last ids across gaps', async () => {
    const lastId = ENTRIES[ENTRIES.length - 1].id;
    const blocks = await ensureBlocks({ uptoId: lastId, blockSize: 16 });
    expect(blocks).toHaveLength(Math.floor(300 / 16));
    blocks.forEach((b, i) => {
      const slice = ENTRIES.slice(i * 16, (i + 1) * 16);
      expect(b).toEqual({ blockIndex: i, firstId: slice[0].id, lastId: slice[15].id, subtreeHash: merkle.merkleRoot(slice.map((e) => e.entry_hash)) });
    });
    expect(logStore.insertMerkleBlock).toHaveBeenCalledTimes(blocks.length);
  });

  test('is incremental: a second call stores nothing new and returns the same blocks', async () => {
    const lastId = ENTRIES[ENTRIES.length - 1].id;
    await ensureBlocks({ uptoId: lastId, blockSize: 16 });
    logStore.insertMerkleBlock.mockClear();
    const again = await ensureBlocks({ uptoId: lastId, blockSize: 16 });
    expect(logStore.insertMerkleBlock).not.toHaveBeenCalled();
    expect(again).toHaveLength(Math.floor(300 / 16));
  });

  test('never stores a block that ends past uptoId (an older root never uses newer blocks)', async () => {
    const blocks = await ensureBlocks({ uptoId: ENTRIES[40].id, blockSize: 16 });
    expect(blocks.every((b) => b.lastId <= ENTRIES[40].id)).toBe(true);
    expect(blocks).toHaveLength(2); // positions 0..31 complete, 32..40 not
  });

  test('a gap in stored block indices is refused (MERKLE_CHECKPOINT_GAP)', async () => {
    BLOCKS.push({ blockSize: 16, blockIndex: 1, firstId: 1, lastId: 2, subtreeHash: 'x'.repeat(64) });
    await expect(ensureBlocks({ uptoId: 999, blockSize: 16 })).rejects.toThrow(/MERKLE_CHECKPOINT_GAP/);
  });
});

describe('treeFor === legacy full-tree root and proof', () => {
  const seqTos = () => [1, 5, 16, 17, 100, ENTRIES[150].id, ENTRIES[299].id];

  test.each([4, 16, 64])('root, blockSize %i, several seqTo', async (blockSize) => {
    for (const seqTo of seqTos()) {
      const t = await treeFor({ seqTo, blockSize });
      const legacy = legacyTree(seqTo);
      expect(t.treeSize).toBe(legacy.length);
      expect(t.root()).toBe(log.computeRootHash(legacy));
    }
  });

  test.each([4, 16, 64])('every proof in a 300-entry log, blockSize %i', async (blockSize) => {
    const seqTo = ENTRIES[299].id;
    const legacy = legacyTree(seqTo);
    const root = merkle.merkleRoot(legacy);
    for (let i = 0; i < ENTRIES.length; i += 7) {
      const t = await treeFor({ seqTo, targetId: ENTRIES[i].id, blockSize });
      expect(t.leafIndex).toBe(i);
      expect(t.inclusionPath(t.leafIndex)).toEqual(merkle.inclusionPath(legacy, i));
      expect(merkle.verifyInclusionPath(ENTRIES[i].entry_hash, t.inclusionPath(t.leafIndex), root, t.leafIndex, legacy.length)).toBe(true);
    }
  });

  test('an id that is not in the tree yields leafIndex null (not a wrong proof)', async () => {
    const t = await treeFor({ seqTo: ENTRIES[299].id, targetId: ENTRIES[299].id + 1000, blockSize: 16 });
    expect(t.leafIndex).toBeNull();
  });

  test('a proof after blocks exist reads at most two blocks of leaves (not the whole log)', async () => {
    const seqTo = ENTRIES[299].id;
    await ensureBlocks({ uptoId: seqTo, blockSize: 16 }); // blocks already stored (normal state)
    READS = 0;
    const t = await treeFor({ seqTo, targetId: ENTRIES[37].id, blockSize: 16 });
    expect(t.leavesRead).toBeLessThanOrEqual(2 * 16);
    expect(READS).toBeLessThanOrEqual(3 * 16); // tail + target block (+ the ensureBlocks probe)
    expect(READS).toBeLessThan(ENTRIES.length);
  });
});
