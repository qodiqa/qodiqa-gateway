'use strict';

const crypto = require('crypto');
const fs     = require('fs');

// files are hashed in fixed-size chunks. readFileSync capped every component at 2 GiB
// (ERR_FS_FILE_TOO_LARGE) — the real pilot audit.log passed that after ~2 h at 20 req/s and no backup was written.
const CHUNK_BYTES = 8 * 1024 * 1024;

/**
 * Feed `[start, start+length)` of a file (default: the whole file) to `onChunk(buf)` in CHUNK_BYTES pieces.
 * Synchronous, bounded memory. Returns the number of bytes read.
 */
function forEachChunkSync(filePath, onChunk, { start = 0, length = null, chunkBytes = CHUNK_BYTES } = {}) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const end = length === null ? Infinity : start + length;
    const buf = Buffer.allocUnsafe(chunkBytes);
    let pos = start;
    while (pos < end) {
      const want = Math.min(buf.length, end - pos);
      const n = fs.readSync(fd, buf, 0, want, pos);
      if (n <= 0) break;
      onChunk(buf.subarray(0, n));
      pos += n;
    }
    return pos - start;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * SHA-256 hex digest of a file's contents.
 * @param {string} filePath
 * @returns {string} 64-char lowercase hex
 */
function sha256File(filePath) {
  const h = crypto.createHash('sha256');
  forEachChunkSync(filePath, (b) => h.update(b));
  return h.digest('hex');
}

module.exports = { sha256File, forEachChunkSync, CHUNK_BYTES };
