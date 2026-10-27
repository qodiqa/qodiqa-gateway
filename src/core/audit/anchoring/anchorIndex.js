'use strict';

/**
 *the persisted byte-offset index of the anchored audit entries.
 *
 * `<audit.log>.anchor-index.json` = { version, logHead, entries: [[position, byteOffset, hash], ...] } for the anchored
 * positions, written after a PASSING boot anchor check. It is a DERIVED, CROSS-CHECKED artifact and is never trusted for
 * a verdict: every boot re-derives the offsets from the log itself (forward raw newline count, audit-log
 * getModernHashesAtByOffset) and compares; the index only tells the operator whether the log's line layout changed
 * between boots (AUDIT_ANCHOR_INDEX_INCONSISTENT) and is then rebuilt from the log. Acceptance criteria G-1..G-6:
 *
 */

const fs = require('fs');
const path = require('path');

const VERSION = 1;

function indexPath(logPath) { return `${logPath}.anchor-index.json`; }

/** @returns {{ status: 'OK'|'MISSING'|'MALFORMED'|'VERSION', index?: { logHead: string|null, entries: Map<number, {off:number, hash:string}> }, error?: string }} */
function readIndex(logPath) {
  const p = indexPath(logPath);
  let raw;
  try { raw = fs.readFileSync(p, 'utf8'); } catch (e) { return e && e.code === 'ENOENT' ? { status: 'MISSING' } : { status: 'MALFORMED', error: e.message }; }
  let doc;
  try { doc = JSON.parse(raw); } catch (e) { return { status: 'MALFORMED', error: 'not JSON' }; }
  if (!doc || typeof doc !== 'object') return { status: 'MALFORMED', error: 'not an object' };
  if (doc.version !== VERSION) return { status: 'VERSION', error: `version ${doc.version}` };
  if (!Array.isArray(doc.entries)) return { status: 'MALFORMED', error: 'entries missing' };
  const entries = new Map();
  for (const e of doc.entries) {
    if (!Array.isArray(e) || !Number.isInteger(e[0]) || e[0] < 0 || !Number.isInteger(e[1]) || e[1] < 0 || typeof e[2] !== 'string' || entries.has(e[0])) {
      return { status: 'MALFORMED', error: 'bad entry' };
    }
    entries.set(e[0], { off: e[1], hash: e[2] });
  }
  return { status: 'OK', index: { logHead: typeof doc.logHead === 'string' ? doc.logHead : null, entries } };
}

/**
 * Persisted vs re-derived. `derived` = { logHead, offsets: Map(pos → off), hashes: Map(pos → hash) }.
 * @returns {{ consistent: boolean, reason: string|null, compared: number, mismatches: number, firstMismatch: object|null }}
 */
function compareIndex(persisted, derived) {
  if (persisted.logHead && derived.logHead && persisted.logHead !== derived.logHead) {
    return { consistent: false, reason: 'LOG_IDENTITY', compared: 0, mismatches: 0, firstMismatch: null };
  }
  let compared = 0; let mismatches = 0; let firstMismatch = null;
  for (const [pos, rec] of persisted.entries) {
    if (!derived.offsets.has(pos)) continue;
    compared++;
    const off = derived.offsets.get(pos); const hash = derived.hashes.get(pos);
    if (off !== rec.off || hash !== rec.hash) {
      mismatches++;
      if (!firstMismatch) firstMismatch = { position: pos, indexedOffset: rec.off, derivedOffset: off, hashMatches: hash === rec.hash };
    }
  }
  return { consistent: mismatches === 0, reason: mismatches ? 'OFFSET_OR_HASH_MISMATCH' : null, compared, mismatches, firstMismatch };
}

/** Atomic write (temp file + rename). Throws on failure; the caller reports it and never fails the boot on it. */
function writeIndex(logPath, { logHead, offsets, hashes }) {
  const p = indexPath(logPath);
  const entries = [...offsets.keys()].filter((pos) => hashes.has(pos)).sort((a, b) => a - b).map((pos) => [pos, offsets.get(pos), hashes.get(pos)]);
  const tmp = path.join(path.dirname(p), `.${path.basename(p)}.${process.pid}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify({ version: VERSION, logHead: logHead || null, entries }), { mode: 0o640 });
  fs.renameSync(tmp, p);
  return entries.length;
}

module.exports = { indexPath, readIndex, compareIndex, writeIndex, VERSION };
