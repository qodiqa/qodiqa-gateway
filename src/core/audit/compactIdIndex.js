'use strict';

/**
 * — exact artifact-ID set for the streamed full-chain scan, at a fixed cost per entry.
 *
 * The disk full scan (audit-log.js _diskScanLine) must remember every artifact ID of the chain: duplicate detection is
 * global, and replay linkage asks whether an original ID exists anywhere. Two Sets of JS strings did that at ~590 bytes
 * of retained heap per entry (317 MB at 409,736 entries; restore probe 572 MB RSS). This index stores, per ID, an
 * 8-byte fingerprint and the byte offset of the entry that holds it — 16 bytes per slot, load factor kept in (0.375, 0.75],
 * so 21–43 bytes per entry (plus a transient ×1.5 while growing). Linear probing at ≤ 0.75 load stays a few probes.
 *
 * EXACTNESS (never probabilistic): the fingerprint only selects candidates. Every fingerprint match is confirmed by
 * `resolveIdAt(offset)` — re-reading the earlier entry from the log and comparing the artifact IDs as strings. A match
 * with a different ID is a collision and is NOT a duplicate (probing continues); an equal ID always is one. A failed
 * confirmation read throws: the caller's scan fails closed. The fingerprint is the first 8 bytes of SHA-256(id), so
 * crafted collisions cannot be produced cheaply (each one would only cost an extra confirmation read anyway).
 */

const crypto = require('crypto');

const MIN_CAPACITY = 1 << 16;

function _sha256Fingerprint(id) {
  const d = crypto.createHash('sha256').update(id, 'utf8').digest();
  return [d.readUInt32BE(0), d.readUInt32BE(4)];
}
let _fingerprint = _sha256Fingerprint;

class CompactIdIndex {
  /** @param {(offset: number) => string} resolveIdAt  the artifact ID of the entry at that byte offset (throws on failure) */
  constructor(resolveIdAt) {
    if (typeof resolveIdAt !== 'function') throw new TypeError('CompactIdIndex needs a resolveIdAt(offset) function');
    this._resolveIdAt = resolveIdAt;
    this.size = 0;
    this.confirmReads = 0;
    this._alloc(MIN_CAPACITY);
  }

  _alloc(capacity) {
    this.capacity = capacity;
    this._mask = capacity - 1;
    this._hi = new Uint32Array(capacity);
    this._lo = new Uint32Array(capacity);
    this._ref = new Float64Array(capacity);   // byte offset + 1; 0 = empty slot
  }

  /** Slot holding `id`, or the empty slot where it would go (exact, confirmed). */
  _find(id, hi, lo) {
    let i = lo & this._mask;
    for (;;) {
      const ref = this._ref[i];
      if (ref === 0) return { slot: i, found: false };
      if (this._hi[i] === hi && this._lo[i] === lo) {
        this.confirmReads++;
        if (this._resolveIdAt(ref - 1) === id) return { slot: i, found: true };
      }
      i = (i + 1) & this._mask;
    }
  }

  /** true if `id` was added before (exact). Otherwise records it at `offset` and returns false. */
  add(id, offset) {
    const [hi, lo] = _fingerprint(id);
    const r = this._find(id, hi, lo);
    if (r.found) return true;
    this._hi[r.slot] = hi; this._lo[r.slot] = lo; this._ref[r.slot] = offset + 1;
    this.size++;
    if (this.size * 4 > this.capacity * 3) this._grow();   // max load factor 0.75
    return false;
  }

  /** true if `id` was added (exact). */
  has(id) {
    const [hi, lo] = _fingerprint(id);
    return this._find(id, hi, lo).found;
  }

  _grow() {
    const { _hi: hi, _lo: lo, _ref: ref, capacity } = this;
    this._alloc(capacity * 2);
    for (let j = 0; j < capacity; j++) {
      if (ref[j] === 0) continue;
      let i = lo[j] & this._mask;            // every stored ID is distinct: re-place by fingerprint, no confirmation needed
      while (this._ref[i] !== 0) i = (i + 1) & this._mask;
      this._hi[i] = hi[j]; this._lo[i] = lo[j]; this._ref[i] = ref[j];
    }
  }
}

/** Test hook: force fingerprint collisions to prove exactness (A-2). Pass null to restore SHA-256. */
function _setFingerprintForTests(fn) { _fingerprint = typeof fn === 'function' ? fn : _sha256Fingerprint; }

module.exports = { CompactIdIndex, _setFingerprintForTests };
