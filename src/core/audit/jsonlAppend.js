'use strict';

/**
 * PH16-D2 — durable append of ONE JSON record to a JSON-lines file, shared by the checkpoint
 * sidecar (checkpointWriter.js) and the customer-held anchor export (anchoring/anchors.js).
 *
 * The previous appends discarded writeSync()'s byte count and never looked at the file's tail. One short write (disk
 * filling up: write(2) returns the bytes that fit, no error) or one crash mid-append left a torn last line; the NEXT
 * append was then merged into it (that record silently lost), and two records later the strict readers refused the
 * file — and the boot checks exit the process.
 *
 * Now:
 *   1. the whole record is written (looping on the returned byte count; a write that cannot complete throws — the
 *      record is reported as NOT written, never as written);
 *   2. before appending, a torn tail (non-empty file whose last byte is not '\n') is handled per `onTornTail`:
 *        'repair'  the bytes after the last '\n' are first COPIED to `<file>.torn-<timestamp>` (nothing is destroyed
 *                  without a copy — the audit-log quarantine rule), then the file is truncated to the last '\n';
 *        'refuse'  nothing is written; throws code `<errorPrefix>_TORN` so the caller reports a failed append and the
 *                  operator decides (used for the customer-held anchor export: rewriting customer storage is an owner
 *                  decision, QODIQA_ANCHOR_EXPORT_TORN_TAIL=repair opts in);
 *   3. fsync before returning.
 */

const fs = require('fs');

function _tornTail(fd, size) {
  if (size === 0) return null;
  const last = Buffer.alloc(1);
  fs.readSync(fd, last, 0, 1, size - 1);
  if (last[0] === 0x0a) return null;
  // find the last '\n' (scan backwards in chunks)
  const chunk = 64 * 1024; let pos = size; let cut = 0;
  while (pos > 0) {
    const len = Math.min(chunk, pos); pos -= len;
    const buf = Buffer.alloc(len); fs.readSync(fd, buf, 0, len, pos);
    const i = buf.lastIndexOf(0x0a);
    if (i >= 0) { cut = pos + i + 1; break; }
  }
  const torn = Buffer.alloc(size - cut); fs.readSync(fd, torn, 0, torn.length, cut);
  return { cut, torn };
}

/**
 * @param {string} file
 * @param {object} record
 * @param {{ onTornTail?: 'repair'|'refuse', errorPrefix?: string, mode?: number, emit?: Function }} [o]
 * @returns {{ repairedTornTail: null | { quarantinedTo: string, bytes: number } }}
 */
function appendJsonlRecord(file, record, { onTornTail = 'repair', errorPrefix = 'JSONL_APPEND', mode = 0o640, emit = null } = {}) {
  const data = Buffer.from(JSON.stringify(record) + '\n', 'utf8');
  const fd = fs.openSync(file, fs.existsSync(file) ? 'r+' : 'w+', mode);
  let repaired = null;
  try {
    const size = fs.fstatSync(fd).size;
    const torn = _tornTail(fd, size);
    let offset = size;
    if (torn) {
      if (onTornTail !== 'repair') {
        const e = new Error(`${errorPrefix}_TORN: ${file} ends in a torn (incomplete) line of ${torn.torn.length} bytes; refusing to append onto it`);
        e.code = `${errorPrefix}_TORN`; throw e;
      }
      const q = `${file}.torn-${new Date().toISOString().replace(/[:.]/g, '-')}`;
      fs.writeFileSync(q, torn.torn, { mode: 0o600 });
      fs.ftruncateSync(fd, torn.cut);
      fs.fsyncSync(fd);
      offset = torn.cut;
      repaired = { quarantinedTo: q, bytes: torn.torn.length };
      if (emit) { try { emit('WARN', `${errorPrefix}_TORN_TAIL_REPAIRED`, { file, quarantinedTo: q, bytes: torn.torn.length }); } catch { /* logging is best-effort */ } }
    }
    let written = 0;
    while (written < data.length) {
      const n = fs.writeSync(fd, data, written, data.length - written, offset + written);
      if (!(n > 0)) { const e = new Error(`${errorPrefix}_SHORT_WRITE: wrote ${written} of ${data.length} bytes to ${file}`); e.code = `${errorPrefix}_SHORT_WRITE`; throw e; }
      written += n;
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  return { repairedTornTail: repaired };
}

module.exports = { appendJsonlRecord };
