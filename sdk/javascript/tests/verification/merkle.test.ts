import crypto from 'node:crypto';
import { verifyInclusionPath, type MerklePathStep } from '../../src/verification/merkle.js';

// Independent (test-local) reference implementation of RFC6962 root/path
// computation, deliberately NOT importing the server's own merkle.js — the
// point is to cross-check the SDK's verification-only port against a
// from-scratch reimplementation, not against itself.
function leafHash(entryHashHex: string): Buffer {
  return crypto.createHash('sha256').update(Buffer.from([0x00])).update(Buffer.from(entryHashHex, 'hex')).digest();
}
function nodeHash(l: Buffer, r: Buffer): Buffer {
  return crypto.createHash('sha256').update(Buffer.from([0x01])).update(l).update(r).digest();
}
function largestPow2LessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function subtreeRoot(leaves: Buffer[], offset: number, count: number): Buffer {
  if (count === 1) return leaves[offset] as Buffer;
  const k = largestPow2LessThan(count);
  return nodeHash(subtreeRoot(leaves, offset, k), subtreeRoot(leaves, offset + k, count - k));
}
function root(hashes: string[]): string {
  const leaves = hashes.map(leafHash);
  return subtreeRoot(leaves, 0, leaves.length).toString('hex');
}
function path(hashes: string[], leafIndex: number): MerklePathStep[] {
  const n = hashes.length;
  if (n === 1) return [];
  const leaves = hashes.map(leafHash);
  const out: MerklePathStep[] = [];
  let lo = 0;
  let size = n;
  let idx = leafIndex;
  while (size > 1) {
    const k = largestPow2LessThan(size);
    if (idx < k) {
      out.push({ hash: subtreeRoot(leaves, lo + k, size - k).toString('hex'), side: 'right' });
      size = k;
    } else {
      out.push({ hash: subtreeRoot(leaves, lo, k).toString('hex'), side: 'left' });
      lo += k;
      idx -= k;
      size -= k;
    }
  }
  return out.reverse();
}
function randomEntryHash(): string {
  return crypto.randomBytes(32).toString('hex');
}

describe('verifyInclusionPath', () => {
  test.each([1, 2, 3, 5, 8, 13])('verifies every leaf of a %i-leaf tree', (n) => {
    const hashes = Array.from({ length: n }, randomEntryHash);
    const r = root(hashes);
    for (let i = 0; i < n; i++) {
      const p = path(hashes, i);
      expect(verifyInclusionPath(hashes[i] as string, p, r)).toBe(true);
    }
  });

  test('rejects a wrong root', () => {
    const hashes = Array.from({ length: 5 }, randomEntryHash);
    const p = path(hashes, 2);
    expect(verifyInclusionPath(hashes[2] as string, p, 'f'.repeat(64))).toBe(false);
  });

  test('rejects a path with a tampered sibling hash', () => {
    const hashes = Array.from({ length: 5 }, randomEntryHash);
    const r = root(hashes);
    const p = path(hashes, 2);
    const tampered = p.map((step, i) => (i === 0 ? { ...step, hash: 'a'.repeat(64) } : step));
    expect(verifyInclusionPath(hashes[2] as string, tampered, r)).toBe(false);
  });

  test('rejects a path with a flipped side', () => {
    const hashes = Array.from({ length: 5 }, randomEntryHash);
    const r = root(hashes);
    const p = path(hashes, 2);
    if (p.length === 0) return;
    const tampered = p.map((step, i) => (i === 0 ? { ...step, side: (step.side === 'left' ? 'right' : 'left') as 'left' | 'right' } : step));
    expect(verifyInclusionPath(hashes[2] as string, tampered, r)).toBe(false);
  });

  test('rejects a truncated path', () => {
    const hashes = Array.from({ length: 8 }, randomEntryHash);
    const r = root(hashes);
    const p = path(hashes, 3);
    expect(verifyInclusionPath(hashes[3] as string, p.slice(1), r)).toBe(false);
  });

  test('rejects a reordered path', () => {
    const hashes = Array.from({ length: 8 }, randomEntryHash);
    const r = root(hashes);
    const p = path(hashes, 3);
    if (p.length < 2) return;
    const reordered = [p[1] as MerklePathStep, p[0] as MerklePathStep, ...p.slice(2)];
    expect(verifyInclusionPath(hashes[3] as string, reordered, r)).toBe(false);
  });

  test('never throws on malformed input', () => {
    expect(verifyInclusionPath('', [], '')).toBe(false);
    expect(verifyInclusionPath('nothex', [{ hash: 'x', side: 'left' }], 'root')).toBe(false);
    expect(verifyInclusionPath(randomEntryHash(), [{ hash: 'x', side: 'sideways' as 'left' }], 'a'.repeat(64))).toBe(false);
  });
});

// with leafIndex/treeSize the proof is bound to its claimed position.
describe('verifyInclusionPath — position-bound', () => {
  test('a proof verifies only at its own position', () => {
    for (const n of [2, 3, 5, 8, 13]) {
      const hashes = Array.from({ length: n }, randomEntryHash);
      const r = root(hashes);
      for (let i = 0; i < n; i++) {
        const p = path(hashes, i);
        expect(verifyInclusionPath(hashes[i] as string, p, r, i, n)).toBe(true);
        for (let j = 0; j < n; j++) if (j !== i) expect(verifyInclusionPath(hashes[i] as string, p, r, j, n)).toBe(false);
      }
    }
  });

  test('invalid positions are refused in bound mode', () => {
    const hashes = Array.from({ length: 8 }, randomEntryHash);
    const r = root(hashes);
    const p = path(hashes, 3);
    for (const [li, ts] of [[-1, 8], [8, 8], [3.5, 8], [NaN, 8], [3, 0]] as Array<[number, number]>) {
      expect(verifyInclusionPath(hashes[3] as string, p, r, li, ts)).toBe(false);
    }
  });
});
