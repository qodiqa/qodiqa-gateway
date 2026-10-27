// ORACLE — byte copy of src/core/audit/audit-log.js at commit 01d8e240 (BEFORE the change), with only
// its relative require() paths and default LOG_PATH re-rooted to this fixture directory. Used by
// src/core/audit/__tests__/compactIdIndex.test.js to prove byte-identical integrity reports. Never edit.
'use strict';

const fs   = require('fs');
const fsp  = fs.promises;
const path = require('path');

// Field set / entry-shaping logic lives in entryBuilder.js, shared with
// distributedOrdering.js (QODIQA_AUDIT_ORDERING_MODE=distributed) so both
// ordering modes validate and hash entries identically — see that module's
// header comment for why this was extracted rather than duplicated.
const entryBuilder = require('../../../entryBuilder');
const {
  CORE_HASH_FIELDS_V1,
  CORE_HASH_FIELDS_V2,
  CORE_HASH_FIELDS_V3,
  CORE_HASH_FIELDS_V4,
  CORE_HASH_FIELDS_V5,
  CORE_HASH_FIELDS_V6,
  CORE_HASH_FIELDS_V7,
  CURRENT_SCHEMA_VERSION,
  VALID_DECISIONS,
  verifyCanonicalHash: _verifyCanonicalHash,
  expectedHashFor: _expectedHashFor,
  v7IntegrityDetail: _v7IntegrityDetail,
  entryTypeOf: _entryTypeOf,
} = entryBuilder;
// audit schema v7: cross-entry lifecycle rules for every chain walk (SCHEMA-V7-DESIGN.md §8, R-2/R-17, C-26).
const { createLifecycleTracker: _createLifecycleTracker } = require('../../../v7Lifecycle');

const pgAuditBackend = require('../../../../../infra/postgres/pg-audit-backend');
const subjectPseudonym = require('../../../../dsr/subjectPseudonym');   // v7 R-12: identity pseudonyms (no cache, R-15)
const { reduceUsage, mergePgDailyRows } = require('../../../../usage/usageAggregation');
const { getVerificationKey } = require('../../../../../../services/artifact/keyManager');
// #2 (finding #109): checksum anchor isolation — see checksumAnchor.js
// header for why the startup gate below still uses the file-only functions.
const checksumAnchor = require('../../../checksumAnchor');
const _ST = require('../../../../../observability/stageTimer'); // closure diagnostic (bench only)

// Dependency-inversion wiring: pg-audit-backend.js (Infrastructure) must not
// import services/artifact/keyManager.js (Services) directly, so it exposes
// setKeyInfoResolver() as an injection point instead of requiring keyManager
// itself. audit-log.js is the sole caller of persistEntry() and already
// legitimately depends on both modules, so it performs this one-time wiring
// at load time, before any entry is appended. Guarded for the many existing
// unit tests that jest.mock('.../pg-audit-backend') with a partial
// { persistEntry: jest.fn() } shape unrelated to evidence-chain wiring —
// those never call persistEntry() in a way that needs the resolver.
if (typeof pgAuditBackend.setKeyInfoResolver === 'function') {
  pgAuditBackend.setKeyInfoResolver(getVerificationKey);
}

// QODIQA_AUDIT_ORDERING_MODE=distributed promotes PostgreSQL to the ordering
// authority (SCAL-11 remediation) so multiple replicas can append safely —
// see docs/protocol/AUDIT-SCHEMA-V8.md "Decision Update". Default
// ('single-node' — any other value, including unset) is byte-for-byte the
// original single-process behavior.
const ORDERING_MODE = process.env.QODIQA_AUDIT_ORDERING_MODE === 'distributed'
  ? 'distributed'
  : 'single-node';

const LOG_PATH          = process.env.QODIQA_AUDIT_LOG
  || path.join(__dirname, '..', '..', '..', '..', '..', '..', 'audit.log');
const WAL_PATH          = LOG_PATH + '.wal';
// #2: QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH lets an operator point the
// file anchor at a different directory/mount than LOG_PATH's own — defaults
// to the historical co-located `<LOG_PATH>.sum` path (100% backward
// compatible when unset). See checksumAnchor.js for the PG-backed isolated
// anchor, dual-written alongside this file anchor when PG is enabled.
const CHECKSUM_PATH     = checksumAnchor.resolveFileAnchorPath(LOG_PATH);

// ── step 6: where the file chain starts ──────────────────────────────────────────────────────────────
// After an archived prefix is removed (the operator command, M4), audit.log holds only entries C+1…N and
// <audit.log>.base.json holds the signed checkpoint C (src/core/audit/checkpoint/checkpoint.js) that vouches for the
// removed prefix: every walker then starts at C.headHash with the lifetime ordinal C.chainLength instead of GENESIS/0.
// Lifetime counters stay lifetime (the checksum anchor's no-decrease rule holds). Three states are valid:
//   'none' no base record, the file starts at GENESIS — unchanged earlier behaviour;
//   'rebased'    base record present and the file's first entry chains from its headHash (or the file is empty);
//   'full-file'  base record present but the file still holds the whole history (a prune stopped after writing the
//                base record, before replacing the log): the file starts at GENESIS and its entry #chainLength must
//                hash to headHash.
// Everything else FAILS CLOSED: a base record that is unreadable or whose signature does not verify with a
// published, non-revoked checkpoint key; a log that does not start at GENESIS without a base record; a log whose first
// entry does not chain from the base record. Only the signed checkpoint inside the base record is trusted; its other
// fields (prefixStats: allow/block/replay counts of the removed prefix) feed statistics only.
const BASE_PATH         = LOG_PATH + '.base.json';

function _firstLineSync() {
  if (!fs.existsSync(LOG_PATH)) return null;
  let first = null;
  _streamLinesSync(LOG_PATH, (line) => { first = line; return false; });
  if (first === null) return null;
  try { return JSON.parse(first); } catch { return { __unparseable: true }; }
}

/** Resolve the chain's start from disk (fresh read; the base record's signature verified). Never throws. */
function _resolveStart() {
  let base = null;
  if (fs.existsSync(BASE_PATH)) {
    let rec;
    try { rec = JSON.parse(fs.readFileSync(BASE_PATH, 'utf8')); } catch (e) { return { error: `AUDIT_BASE_UNREADABLE: ${e.message}` }; }
    const v = require('../../../checkpoint/checkpoint').verifyCheckpoint(rec && rec.checkpoint);
    if (!v.ok) return { error: `AUDIT_BASE_SIGNATURE_INVALID: ${v.reason}` };
    base = rec;
  }
  const first = _firstLineSync();
  if (first && first.__unparseable) return { error: 'AUDIT_BASE_UNVERIFIABLE: the first log line is not valid JSON' };
  const firstIsLegacy = !!first && (!('inputHash' in first) || first.inputHash == null);
  if (!base) {
    if (first && !firstIsLegacy && first.prevHash !== 'GENESIS') {
      return { error: `AUDIT_BASE_MISSING: the log's first entry chains from ${first.prevHash}, not GENESIS, and no signed base record (${path.basename(BASE_PATH)}) exists` };
    }
    return { state: 'none', start: 'GENESIS', offset: 0, base: null };
  }
  const cp = base.checkpoint.payload;
  if (!first || (!firstIsLegacy && first.prevHash === cp.headHash)) {
    return { state: 'rebased', start: cp.headHash, offset: cp.chainLength, base, startCheckpoint: base.checkpoint, prefixStats: base.prefixStats || null };
  }
  if (firstIsLegacy || first.prevHash === 'GENESIS') {
    return { state: 'full-file', start: 'GENESIS', offset: 0, base, startCheckpoint: null, prefixStats: null, mustHaveAt: { modernIndex: cp.chainLength - 1, hash: cp.headHash } };
  }
  // A SECOND prune interrupted after writing its base record: the log still starts at the PREVIOUS base's head, which
  // the new base record carries (signed) as priorBase — the file is still whole from there, and its entry at the new
  // checkpoint must hash to the new headHash.
  const prior = base.priorBase && base.priorBase.checkpoint;
  if (prior && !firstIsLegacy && prior.payload && first.prevHash === prior.payload.headHash) {
    const pv = require('../../../checkpoint/checkpoint').verifyCheckpoint(prior);
    if (!pv.ok) return { error: `AUDIT_BASE_SIGNATURE_INVALID: prior base: ${pv.reason}` };
    const pp = prior.payload;
    if (!(pp.chainLength < cp.chainLength)) return { error: 'AUDIT_BASE_MISMATCH: the prior base record is not before the base record' };
    return { state: 'full-file', start: pp.headHash, offset: pp.chainLength, base, startCheckpoint: prior, prefixStats: base.priorBase.prefixStats || null,
      mustHaveAt: { modernIndex: cp.chainLength - pp.chainLength - 1, hash: cp.headHash } };
  }
  return { error: `AUDIT_BASE_MISMATCH: the log's first entry chains from ${first.prevHash}, the signed base record ends at ${cp.headHash}` };
}

// The start resolved at boot (a prune is an offline operation; readers use this cached value, while the verifier's
// full disk rescans re-resolve fresh so a base record tampered after boot is still caught).
let _start = { state: 'none', start: 'GENESIS', offset: 0, base: null };

/** The chain's start as other modules need it (mirror check, verifier gate, ChainVerifier). */
function getChainStart() {
  // checkpoint = the signed checkpoint the start IS (its headHash = startHash, its pgSeq = where PG's kept rows begin);
  // null when the chain starts at GENESIS (no base, or a first prune interrupted before replacing the log).
  return { state: _start.state, startHash: _start.start, startCount: _start.offset, checkpoint: _start.startCheckpoint || null };
}

// ── group commit — ─────────────────
// Single-node appends that queue while a flush is in progress are written TOGETHER: one WAL write + fsync, one log
// append + fsync, one checksum write, one WAL unlink per batch. A caller's promise resolves only after its own entry
// is fsynced in audit.log (the owner's rule: no response before its own entry is durably on disk). No timer: an
// append that arrives while nothing is flushing is flushed at once. QODIQA_AUDIT_GROUP_COMMIT=false restores the
// per-entry path unchanged (rollback switch, reported in the boot report).
// (VERIFIER-DESIGN.md): QODIQA_AUDIT_FOLLOWER=true (set ONLY by the verifier worker thread) loads this module as a
// READ-ONLY follower of the log the main thread writes: no WAL recovery, no write of any file, append() refused, and
// every read stops at the last COMPLETE line (_readLimit) — a line the main thread is still writing is never read.
// refreshFromDisk() follows newly committed lines.
const FOLLOWER          = process.env.QODIQA_AUDIT_FOLLOWER === 'true';
let _readLimit          = Infinity;
const GROUP_COMMIT      = !FOLLOWER && ORDERING_MODE !== 'distributed' && process.env.QODIQA_AUDIT_GROUP_COMMIT !== 'false';
// closure S33: with group commit,
// ONE WAL file is reused for every batch instead of being created and deleted per batch — the per-batch create/delete
// was measured to trigger the periodic ~5.6 s fsync stalls (design ablation AB3 vs AB1/AB6/AB7). The handle is held
// open while the writer runs; each batch is written at offset 0 and fsynced (byte-identical WAL content, same fsync,
// same order); after the batch the file is truncated to 0 — the "invalidated" state recovery already recognises —
// instead of unlinked (neither is fsynced). drainPendingWrites() (graceful shutdown) closes the handle and removes the
// EMPTY file. approved on-disk contract: WAL absent or empty while running; absent after recovery and after a clean
// stop. QODIQA_AUDIT_WAL_REUSE=false restores create/unlink per batch exactly.
const WAL_REUSE         = GROUP_COMMIT && process.env.QODIQA_AUDIT_WAL_REUSE !== 'false';
const MAX_BATCH_ENTRIES = 256;
const MAX_BATCH_BYTES   = 1024 * 1024;
// Bytes this module removes from its own files (a torn tail at boot, a failed batch's log tail) are copied here
// first — never discarded silently.
const QUARANTINE_DIR    = LOG_PATH + '.quarantine';
const _recoveryReport   = { walFound: false, walEntries: 0, walReplayed: 0, walAlreadyCommitted: 0, walEmptyInvalidated: false,
  walTornDiscarded: false, tornTailRepaired: null };
const _groupStats       = { batches: 0, entries: 0, maxBatch: 0, aborted: 0, abortedEntries: 0 };

// ── Bounded in-memory window
//
// chain[] is no longer the full history: it is a TAIL WINDOW of the most
// recent entries (default QODIQA_AUDIT_WINDOW_SIZE=10000). The durable store
// (audit.log in single-node mode, PostgreSQL in distributed mode) is the
// authority for anything older; the async lookup functions below fall back
// to it on a window miss. Lifetime counters (_totalCount/_modernCount/
// _allowCount/_blockCount/_replayCount/_headHash/_tailHash) remain EXACT for
// the whole history — they are maintained by the streamed boot and every
// append, never recomputed from the window.
//
// Escape hatch (one release only — removal documented in the ADR):
// QODIQA_AUDIT_WINDOW_SIZE=unbounded restores the previous keep-everything
// behaviour and logs a WARN at boot. Default is bounded; that is the fix.
const _rawWindowSize = process.env.QODIQA_AUDIT_WINDOW_SIZE;
const WINDOW_UNBOUNDED = _rawWindowSize === 'unbounded';
const WINDOW_SIZE = WINDOW_UNBOUNDED
  ? Infinity
  : (Number.isInteger(parseInt(_rawWindowSize, 10)) && parseInt(_rawWindowSize, 10) > 0
    ? parseInt(_rawWindowSize, 10)
    : 10000);

function _emitSafe(level, event, extra) {
  try { require('../../../../../../services/logger').emit(level, event, extra); } catch { /* logging must never affect the audit path */ }
}

// ── In-memory chain window (append-only tail; durable store is the authority) ──
const chain = [];
let _chainStartOrdinal = 0;  // absolute 0-based ordinal (over ALL entries ever) of chain[0]
let _totalCount = 0;         // lifetime count of ALL entries (legacy + modern) — the old chain.length

// ── In-memory indexes ─────────────────────────────────────────────────────────
//
// All Map/Set values hold references to the same frozen entry objects that live
// in chain[].  No data is duplicated — only references.  Every index is built
// atomically at startup and updated atomically on every append().
//
// Lookup complexity:
//   _byArtifactId      Map  artifactId  → entry           O(1) get/set/has
//   _byHash            Map  hash        → entry           O(1) get/set/has
//   _nonceSet          Set  nonce                         O(1) has/add
//   _replayIndex       Map  originalId  → entry[]         O(1) get/set
//   _tenantIndex       Map  tenantId    → entry[]         O(1) get/set
//   _requestHashIdx    Map  requestHash → entry[]         O(1) get/set
//   _modernChain       []   ordered modern entries        O(1) tail, O(1) position
//   _modernPosByArtifactId Map artifactId → int position  O(1) get/set
//
const _byArtifactId          = new Map();
const _byHash                = new Map();
const _nonceSet              = new Set();
const _replayIndex           = new Map();
const _tenantIndex           = new Map();
const _requestHashIdx        = new Map();
const _modernChain           = [];  // modern entries inside the window
const _modernPosByArtifactId = new Map(); // artifactId → ABSOLUTE modern position
let _modernWindowStartPos = 0;      // absolute modern position of _modernChain[0]
let _windowStartPrevHash  = 'GENESIS'; // hash of the modern entry just before the window ('GENESIS' at history start)

// O(1) lifetime counters — maintained on boot stream + every append; exact
// for the whole history regardless of the window. Readable in O(1).
let _modernCount = 0;         // lifetime modern-entry count — the old _modernChain.length
let _allowCount  = 0;
let _blockCount  = 0;
let _replayCount = 0;
let _tailHash    = 'GENESIS'; // hash of the most recent modern entry
let _headHash    = null;      // hash of the first modern entry (null = empty)

// ── Checksum helpers ──────────────────────────────────────────────────────────

// Startup (this function) runs synchronously at module require-time — see
// loadFromDisk()'s IIFE below — BEFORE pgPool.initialize() has run, so this
// stays file-anchor-only by construction; it delegates to checksumAnchor.js
// but never touches the PG-backed anchor. Unchanged behavior/shape from
// #2.
function _loadChecksum() {
  return checksumAnchor.loadChecksum(CHECKSUM_PATH);
}

// the v2 block persists the exact lifetime counters plus the byte
// offset they were valid at, enabling the O(delta + window) streamed boot
// fast path. Additive — earlier readers ignore it; a missing v2 block
// simply routes boot through the full streamed validation pass.
function _anchorV2() {
  return {
    totalCount:  _totalCount,
    modernCount: _modernCount,
    allowCount:  _allowCount,
    blockCount:  _blockCount,
    replayCount: _replayCount,
    headHash:    _headHash,
    byteLength:  _fileByteLength,
  };
}

function _saveChecksum(count, tailHash) {
  if (FOLLOWER) return; // the follower never writes
  checksumAnchor.saveChecksum(CHECKSUM_PATH, count, tailHash, _anchorV2());
}

// Async counterpart of _saveChecksum(), used on the hot append path so the
// request path never blocks the event loop. Startup (_saveChecksum, sync)
// keeps using the sync version since it runs once before the server accepts
// connections.
//
// #2: additionally dual-writes the identical {count, tailHash} into
// the isolated PG anchor (audit_checksum_anchor, migration 036) when PG is
// enabled — fire-and-forget, exactly like pg-audit-backend.js's persistEntry()
// dual-write of the entry itself, so a PG hiccup never adds latency to or
// fails the audit append. The file write below remains the one awaited,
// crash-safety-ordering-relevant write (see the "BEFORE clearing WAL"
// comment at this function's call site).
async function _saveChecksumAsync(count, tailHash, v2 = _anchorV2()) {
  if (FOLLOWER) return; // the follower never writes
  await checksumAnchor.saveChecksumFileAsync(CHECKSUM_PATH, count, tailHash, v2);
  checksumAnchor.saveChecksumPg(count, tailHash).catch(() => {});
}

// #2: independent verification that the isolated PG anchor agrees
// with the in-memory chain's current tail — deliberately makes NO fs.* calls
// at all, so it can still detect divergence even if the audit-log directory
// itself has been corrupted, truncated, or is temporarily unavailable (the
// actual isolation guarantee this finding requires; the file-based checksum
// validated at startup, above, cannot offer this by construction, since it
// and audit.log share the same filesystem/failure domain).
//
// No-op-shaped result (applicable: false) when PG isn't enabled or has no
// anchor row yet (fresh install, or PG enabled after existing chain history)
// — this is an additive, opt-in isolation signal, not a replacement for the
// file-based startup gate.
function _recordAnchorMismatch() {
  try { require('../../../../../observability/metrics').auditChecksumAnchorMismatchTotal.inc({}); }
  catch { /* metrics must never affect verification */ }
}

async function verifyChecksumAnchorIsolation() {
  const pgAnchor = await checksumAnchor.loadChecksumPg();
  if (!pgAnchor) {
    return { applicable: false, reason: 'PG_ANCHOR_UNAVAILABLE', valid: null };
  }

  const memoryCount    = _totalCount;
  const memoryTailHash = _tailHash === 'GENESIS' ? null : _tailHash;

  if (pgAnchor.count > memoryCount) {
    _recordAnchorMismatch();
    return {
      applicable: true, valid: false, reason: 'PG_ANCHOR_AHEAD_OF_MEMORY',
      pgAnchor, memoryCount, memoryTailHash,
    };
  }

  if (pgAnchor.count === memoryCount && pgAnchor.tailHash && pgAnchor.tailHash !== memoryTailHash) {
    _recordAnchorMismatch();
    return {
      applicable: true, valid: false, reason: 'PG_ANCHOR_HASH_MISMATCH',
      pgAnchor, memoryCount, memoryTailHash,
    };
  }

  return { applicable: true, valid: true, reason: null, pgAnchor, memoryCount, memoryTailHash };
}

// ── fsync helper ──────────────────────────────────────────────────────────────

function _fsync(filePath) {
  const fd = fs.openSync(filePath, 'r+');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

// Async counterpart of _fsync(), used on the hot append path. Opening/syncing/
// closing the fd all go through the libuv threadpool instead of blocking the
// event loop for the duration of the disk flush.
async function _fsyncAsync(filePath) {
  const fh = await fsp.open(filePath, 'r+');
  try { await fh.sync(); } finally { await fh.close(); }
}

// ── Streamed line reader ───────────────────────────────────────────────
//
// Fixed-buffer synchronous NDJSON reader — the bounded-memory replacement for
// the previous readFileSync-whole-file pattern on the boot path. onLine
// receives (lineString, byteOffsetOfLineStart, ordinal) and may return false
// to stop early. Returns { bytesRead, lines }.
const BOOT_CHUNK_BYTES = (() => {
  const v = parseInt(process.env.QODIQA_AUDIT_BOOT_CHUNK_BYTES, 10);
  return Number.isInteger(v) && v >= 4096 ? v : 1048576;
})();

function _streamLinesSync(filePath, onLine, fromByte = 0) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(BOOT_CHUNK_BYTES);
    let carry = '';
    let carryStart = fromByte;
    let pos = fromByte;
    let ordinal = 0;
    for (;;) {
      const want = Math.min(buf.length, _readLimit - pos);
      if (want <= 0) break;
      const n = fs.readSync(fd, buf, 0, want, pos);
      if (n <= 0) break;
      const text = carry + buf.toString('utf8', 0, n);
      const parts = text.split('\n');
      carry = parts.pop(); // last piece may be partial (or '' on exact boundary)
      let lineStart = carryStart;
      for (const part of parts) {
        const line = part.trim();
        if (line.length > 0) {
          if (onLine(line, lineStart, ordinal) === false) return { bytesRead: pos - fromByte, lines: ordinal + 1 };
          ordinal++;
        }
        lineStart += Buffer.byteLength(part, 'utf8') + 1;
      }
      carryStart = lineStart;
      pos += n;
    }
    const tail = carry.trim();
    if (tail.length > 0) { onLine(tail, carryStart, ordinal); ordinal++; }
    return { bytesRead: pos - fromByte, lines: ordinal };
  } finally {
    fs.closeSync(fd);
  }
}

// Find the byte offset at which the last `count` newline-terminated lines
// begin — backward chunked scan, bounded memory.
function _offsetOfLastLines(filePath, count) {
  const size = Math.min(fs.statSync(filePath).size, _readLimit);
  if (size === 0 || count === Infinity) return 0;
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(Math.min(BOOT_CHUNK_BYTES, size));
    let newlines = 0;
    let pos = size;
    while (pos > 0) {
      const readLen = Math.min(buf.length, pos);
      pos -= readLen;
      fs.readSync(fd, buf, 0, readLen, pos);
      for (let i = readLen - 1; i >= 0; i--) {
        if (buf[i] === 0x0a) {
          // ignore the file-terminating newline itself
          if (pos + i === size - 1) continue;
          newlines++;
          if (newlines >= count) return pos + i + 1;
        }
      }
    }
    return 0;
  } finally {
    fs.closeSync(fd);
  }
}

// ── Lifetime counters ──────────────────────
function _countEntry(entry) {
  _totalCount++;
  if (entry.legacy) return;
  _modernCount++;
  if (_headHash === null) _headHash = entry.hash;
  _tailHash = entry.hash;
  // v7: decision statistics count DECISION entries only — INTENT / STREAM_OPENED lifecycle entries carry
  // decision "ALLOW" (R-8) and must never inflate them. Structural counters above (_totalCount, _modernCount, head/tail)
  // stay entry counts: the checksum anchor's truncation check and the S2 row counter count every entry.
  if (_entryTypeOf(entry) !== 'DECISION') return;
  if (entry.decision === 'ALLOW')      _allowCount++;
  else if (entry.decision === 'BLOCK') _blockCount++;
  const replayOf = entry.executionContext?.replayOf;
  if (typeof replayOf === 'string' && replayOf) _replayCount++;
}

// ── Window index population / eviction ────────────────────────────────────────
//
// _indexEntry indexes one entry INTO THE WINDOW (counters live in
// _countEntry above — callers invoke both for a new entry, or only
// _indexEntry when re-filling the window from already-counted history).
// Must be called AFTER the entry is frozen and pushed to chain[].
//
function _indexEntry(entry) {
  if (entry.legacy) return;

  _byArtifactId.set(entry.artifactId, entry);
  _byHash.set(entry.hash, entry);

  const pos = _modernWindowStartPos + _modernChain.length;
  _modernChain.push(entry);
  _modernPosByArtifactId.set(entry.artifactId, pos);

  if (entry.nonce) _nonceSet.add(entry.nonce);

  if (entry.tenantId) {
    let list = _tenantIndex.get(entry.tenantId);
    if (!list) { list = []; _tenantIndex.set(entry.tenantId, list); }
    list.push(entry);
  }

  if (entry.requestHash && entry.requestHash !== 'UNAVAILABLE') {
    let list = _requestHashIdx.get(entry.requestHash);
    if (!list) { list = []; _requestHashIdx.set(entry.requestHash, list); }
    list.push(entry);
  }

  const replayOf = entry.executionContext?.replayOf;
  if (typeof replayOf === 'string' && replayOf) {
    let list = _replayIndex.get(replayOf);
    if (!list) { list = []; _replayIndex.set(replayOf, list); }
    list.push(entry);
  }
}

function _removeFromList(map, key, entry) {
  const list = map.get(key);
  if (!list) return;
  const i = list.indexOf(entry);
  if (i !== -1) list.splice(i, 1);
  if (list.length === 0) map.delete(key);
}

function _unindexEntry(entry) {
  if (entry.legacy) return;
  if (_byArtifactId.get(entry.artifactId) === entry) _byArtifactId.delete(entry.artifactId);
  if (_byHash.get(entry.hash) === entry) _byHash.delete(entry.hash);
  if (entry.nonce) _nonceSet.delete(entry.nonce);
  _modernPosByArtifactId.delete(entry.artifactId);
  if (entry.tenantId) _removeFromList(_tenantIndex, entry.tenantId, entry);
  if (entry.requestHash && entry.requestHash !== 'UNAVAILABLE') _removeFromList(_requestHashIdx, entry.requestHash, entry);
  const replayOf = entry.executionContext?.replayOf;
  if (typeof replayOf === 'string' && replayOf) _removeFromList(_replayIndex, replayOf, entry);
}

// Push a frozen entry into the window and evict past the bound. Counters are
// NOT touched here (see _countEntry).
function _pushWindow(entry) {
  chain.push(entry);
  _indexEntry(entry);
  while (chain.length > WINDOW_SIZE) {
    const evicted = chain.shift();
    _chainStartOrdinal++;
    if (!evicted.legacy) {
      if (_modernChain[0] === evicted) {
        _modernChain.shift();
        _modernWindowStartPos++;
      }
      _windowStartPrevHash = evicted.hash;
      _unindexEntry(evicted);
    }
  }
}

// ── Hash computation ──────────────────────────────────────────────────────────
//
// The canonical chain hash (QODIQA-PROTOCOL-SPEC.md §11.3): a domain-separated
// SHA-256 over the canonical JSON serialization of the 9 core hash fields.
// This is the one and only hash algorithm used for any entry produced by the
// current append() path. There is no alternate/legacy hash implementation —
// an entry lacking a `canonical` field is a structural integrity violation,
// not a supported legacy format, and is rejected below.
//
// (_verifyCanonicalHash itself now lives in entryBuilder.js — see the
// destructure at the top of this file.)

// ── Entry validation ──────────────────────────────────────────────────────────
//
// Validates one entry during startup.  expectedPrevHash is threaded through the
// outer loop so this function never performs a backwards scan (was O(n) per
// entry before; now O(1) per entry → O(n) total startup cost).
//
// `legacy` is a DERIVED, in-memory
// classification — a pre-hash-chain line is one with no inputHash. No writer ever
// persists a `legacy` key (entries come only from entryBuilder.buildEntry), so a
// stored `legacy` key on a line is forged: the fast-path boot tail window,
// the full-disk scan and _walkChain all trusted it and skipped every check for that
// line, so an inserted line carrying it verified as a valid chain. The derived flag is
// set non-enumerable (_markLegacy) so it can never be serialized back out, and a
// genuine pre-hash line can only sit in the prefix before the first hash-chained
// entry (nothing ever wrote one after the upgrade).
function _hasStoredLegacyKey(entry) {
  return !!entry && Object.prototype.propertyIsEnumerable.call(entry, 'legacy');
}
function _isLegacyShaped(entry) {
  return !('inputHash' in entry) || entry.inputHash == null;
}
function _markLegacy(entry) {
  Object.defineProperty(entry, 'legacy', { value: true, enumerable: false });
}

function _validateChainEntry(entry, expectedPrevHash) {
  if (typeof entry.timestamp  !== 'string') throw new Error('invalid_field: timestamp');
  if (typeof entry.artifactId !== 'string') throw new Error('invalid_field: artifactId');

  if (_hasStoredLegacyKey(entry)) {
    throw new Error('chain_break: stored legacy flag (the legacy classification is derived, never persisted)');
  }
  if (_isLegacyShaped(entry)) {
    if (expectedPrevHash !== 'GENESIS') {
      throw new Error('chain_break: legacy-shaped line after the first hash-chained entry');
    }
    _markLegacy(entry);
    return;
  }

  if (typeof entry.inputHash  !== 'string') throw new Error('invalid_field: inputHash');
  if (!VALID_DECISIONS.has(entry.decision)) throw new Error('invalid_field: decision');
  if (typeof entry.signature  !== 'string') throw new Error('invalid_field: signature');
  if (typeof entry.prevHash   !== 'string') throw new Error('invalid_field: prevHash');
  if (typeof entry.hash       !== 'string') throw new Error('invalid_field: hash');

  if (entry.prevHash !== expectedPrevHash) {
    throw new Error('chain_break: prevHash mismatch — expected ' + expectedPrevHash);
  }

  if (typeof entry.canonical !== 'string') throw new Error('invalid_field: canonical');
  if (!_verifyCanonicalHash(entry)) {
    const shape = _v7IntegrityDetail(entry);
    throw new Error('chain_break: canonical hash mismatch' + (shape ? ' (' + shape + ')' : ''));
  }
}

// v7: apply the lifecycle tracker to a boot/refresh loop entry; a failure is an integrity violation.
function _lifecycleStepOrThrow(tracker, entry, where) {
  if (entry.legacy) return;
  const r = tracker.step(entry);
  if (r) throw new Error(`AUDIT_INTEGRITY_VIOLATION: ${r.detail} at ${where} (artifactId ${entry.artifactId})`);
}
function _emitLifecycleWarnings(tracker, where) {
  const warnings = tracker.finish();
  if (warnings.length) _emitSafe('WARN', 'AUDIT_V7_LIFECYCLE_WARNINGS', { where, lifecycleComplete: tracker.lifecycleComplete, warnings: warnings.map((w) => ({ code: w.code, count: w.count })) });
  return warnings;
}

// ── Startup: load chain from disk ─────────────────────────────────────────────
//
// Runs synchronously at module load.  After this IIFE completes every index is
// populated, all O(1) lookup functions are ready, and the checksum is validated.
//
// In distributed mode this is a deliberate no-op: the file is not the
// ordering authority (PostgreSQL's audit_chain_head is — see
// distributedOrdering.js), and file-based hydration can't run here anyway
// since pgPool hasn't been initialized yet at module-require time (see
// server.js's startup sequence). Distributed-mode startup instead calls the
// async hydrateFromPgIfDistributed() below, explicitly, after
// pgPool.initialize() succeeds.
//
// Tracked precisely so every append can persist the v2 anchor's byteLength
// without a per-append stat() call. Initialized by loadFromDisk().
let _fileByteLength = 0;

function _parseLineOrThrow(line, ordinal) {
  try { return JSON.parse(line); }
  catch { throw new Error('audit_log: malformed JSON at line ' + (ordinal + 1)); }
}

// Fill the window from the parsed tail of already-counted history. Entries
// arrive oldest→newest; counters are untouched (already lifetime-counted).
function _refillWindow(tailEntries) {
  let modernInTail = 0;
  let firstModern = null;
  for (const e of tailEntries) {
    if (!e.legacy) { modernInTail++; if (!firstModern) firstModern = e; }
  }
  _chainStartOrdinal = _totalCount - tailEntries.length;
  _modernWindowStartPos = _modernCount - modernInTail;
  _windowStartPrevHash = firstModern ? firstModern.prevHash : 'GENESIS';
  for (const e of tailEntries) {
    chain.push(e);
    _indexEntry(e);
  }
}

// ── WAL recovery for group-commit batches (GROUP-COMMIT-DESIGN.md §4-§6) ──────────────────────────────────────
// The WAL holds one JSON entry per line, in chain order (an earlier single-entry WAL is a batch of one).
//   empty WAL           → a failed batch invalidated it before its callers got the error (crash point B'): nothing
//                         to replay, ever.
//   no final newline    → torn WAL: the crash hit while the WAL itself was being written, so the log append for that
//                         batch never started and no caller of it was answered (point A): discarded (copied to
//                         quarantine first).
//   otherwise           → every line must parse, carry a valid hash, and link to the previous line; else boot fails
//                         closed. The log's tail tells how many of the WAL's entries are already committed; the rest
//                         are appended. A torn LAST LOG LINE is repaired only if its bytes are exactly a prefix of
//                         the first missing WAL entry's line (point C) — copied to quarantine, truncated, recorded
//                         (event + boot report); anything else fails closed.
function _quarantineSync(tag, buf) {
  fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  const p = path.join(QUARANTINE_DIR, `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}-${tag}.bin`);
  fs.writeFileSync(p, buf);
  _fsync(p);
  return p;
}
// follower: the byte offset just after the log's last newline — the end of its last COMPLETE line.
function _stableLength() {
  if (!fs.existsSync(LOG_PATH)) return 0;
  const size = fs.statSync(LOG_PATH).size;
  if (size === 0) return 0;
  const fd = fs.openSync(LOG_PATH, 'r');
  try {
    const buf = Buffer.alloc(64 * 1024);
    let end = size;
    while (end > 0) {
      const start = Math.max(0, end - buf.length);
      const n = fs.readSync(fd, buf, 0, end - start, start);
      for (let i = n - 1; i >= 0; i--) if (buf[i] === 0x0a) return start + i + 1;
      end = start;
    }
    return 0;
  } finally { fs.closeSync(fd); }
}

function _integrity(msg) { return new Error(`AUDIT_INTEGRITY_VIOLATION: ${msg}`); }

// M3: after a prune the chain's start is the signed base record's headHash, not GENESIS (see _resolveStart).
function _adoptBaseCounters(S) {
  if (!S || !(S.offset > 0)) return;
  const ps = S.prefixStats || {};
  _totalCount = S.offset;
  _modernCount = S.offset;
  _allowCount = Number.isInteger(ps.allowCount) ? ps.allowCount : 0;     // prefixStats: statistics only (unsigned)
  _blockCount = Number.isInteger(ps.blockCount) ? ps.blockCount : 0;
  _replayCount = Number.isInteger(ps.replayCount) ? ps.replayCount : 0;
  _headHash = typeof ps.headHash === 'string' ? ps.headHash : null;
  _tailHash = S.start;
  _windowStartPrevHash = S.start;
  _modernWindowStartPos = S.offset;
  _chainStartOrdinal = S.offset;
}

function _recoverWalSync(startHash = 'GENESIS') {
  if (FOLLOWER || ORDERING_MODE === 'distributed' || !fs.existsSync(WAL_PATH)) return;
  _recoveryReport.walFound = true;
  const raw = fs.readFileSync(WAL_PATH);
  const text = raw.toString('utf8');
  if (text.length === 0) {
    _recoveryReport.walEmptyInvalidated = true;
    try { fs.unlinkSync(WAL_PATH); } catch {}
    return;
  }
  // No final newline: complete-and-verifiable (a write that stopped just before its newline — replaying it is as safe
  // as discarding it, since the log append starts only after the WAL fsync, so no caller of that batch was answered;
  // replay keeps the earlier behaviour, CU-02) or torn (the last line does not parse / verify).
  // A last line that PARSES as a complete object but fails its hash check cannot come from a torn write (a crash cuts
  // bytes, it does not rewrite a complete object): it is tampering, and falls through to the verification below,
  // which fails boot closed. Only an unparseable last line is a torn write.
  let lastComplete = false;
  if (!text.endsWith('\n')) {
    const lastLine = text.slice(text.lastIndexOf('\n') + 1);
    try { JSON.parse(lastLine); lastComplete = true; } catch { lastComplete = false; }
  }
  if (!text.endsWith('\n') && !lastComplete) {
    const q = _quarantineSync('torn-wal', raw);
    _recoveryReport.walTornDiscarded = true;
    _emitSafe('WARN', 'AUDIT_WAL_TORN_DISCARDED', { bytes: raw.length, quarantine: q,
      message: 'The WAL was being written when the process stopped: its batch was never appended nor acknowledged.' });
    try { fs.unlinkSync(WAL_PATH); } catch {}
    return;
  }
  const walLines = (text.endsWith('\n') ? text.slice(0, -1) : text).split('\n');
  const wal = walLines.map((l, i) => {
    let e; try { e = JSON.parse(l); } catch { throw _integrity(`WAL line ${i + 1} of ${walLines.length} is not valid JSON`); }
    if (!entryBuilder.verifyCanonicalHash(e)) throw _integrity(`canonical hash mismatch in WAL entry ${i + 1} of ${walLines.length}`);
    if (i > 0 && e.prevHash !== JSON.parse(walLines[i - 1]).hash) throw _integrity(`WAL entry ${i + 1} does not link to entry ${i}`);
    return e;
  });
  _recoveryReport.walEntries = wal.length;

  // The log's tail: enough bytes for the whole batch plus the line before it.
  const size = fs.existsSync(LOG_PATH) ? fs.statSync(LOG_PATH).size : 0;
  const want = Math.min(size, Buffer.byteLength(text, 'utf8') + 256 * 1024);
  const tailBuf = Buffer.alloc(want);
  if (want > 0) { const fd = fs.openSync(LOG_PATH, 'r'); try { fs.readSync(fd, tailBuf, 0, want, size - want); } finally { fs.closeSync(fd); } }
  const tail = tailBuf.toString('utf8');
  const lastNl = tail.lastIndexOf('\n');
  const fragment = tail.slice(lastNl + 1);                 // bytes after the last newline ('' when clean)
  let complete = lastNl >= 0 ? tail.slice(0, lastNl).split('\n') : [];
  if (want < size) complete = complete.slice(1);          // the first line may be cut by the read window
  const hashes = complete.map((l) => { try { return JSON.parse(l).hash ?? null; } catch { throw _integrity('a complete line near the log tail is not valid JSON'); } });

  let k = 0;
  for (let c = Math.min(wal.length, hashes.length); c >= 1; c--) {
    const seg = hashes.slice(hashes.length - c);
    if (seg.every((h, j) => h === wal[j].hash)) { k = c; break; }
  }
  const before = hashes.length - k - 1 >= 0 ? hashes[hashes.length - k - 1] : null;
  const linkOk = size === 0 || before === null || before === wal[0].prevHash || (hashes.length - k === 0 && wal[0].prevHash === startHash);
  if (!linkOk) throw _integrity(`the WAL batch does not continue the log (log entry before it: ${before}, WAL expects ${wal[0].prevHash})`);
  _recoveryReport.walAlreadyCommitted = k;

  if (fragment.length > 0) {
    const expected = k < wal.length ? JSON.stringify(wal[k]) + '\n' : null;
    if (expected === null || !expected.startsWith(fragment)) {
      throw _integrity('the log ends with an incomplete line that is not a prefix of the next WAL entry');
    }
    const fragBytes = Buffer.byteLength(fragment, 'utf8');
    const q = _quarantineSync('torn-log-tail', Buffer.from(fragment, 'utf8'));
    fs.truncateSync(LOG_PATH, size - fragBytes);
    _fsync(LOG_PATH);
    _recoveryReport.tornTailRepaired = { bytes: fragBytes, quarantine: q, walEntryHash: wal[k].hash };
    _emitSafe('WARN', 'AUDIT_LOG_TORN_TAIL_REPAIRED', { bytes: fragBytes, quarantine: q, walEntryHash: wal[k].hash,
      message: 'The last log line was cut by a crash; it matched the start of an unacknowledged WAL entry and was re-written whole.' });
  }
  if (k < wal.length) {
    fs.appendFileSync(LOG_PATH, wal.slice(k).map((e) => JSON.stringify(e) + '\n').join(''), 'utf8');
    _fsync(LOG_PATH);
    _recoveryReport.walReplayed = wal.length - k;
    _emitSafe('INFO', 'AUDIT_WAL_REPLAYED', { entries: wal.length - k, alreadyCommitted: k });
  }
  try { fs.unlinkSync(WAL_PATH); } catch {}
}

(function loadFromDisk() {
  if (ORDERING_MODE === 'distributed') return;

  if (WINDOW_UNBOUNDED) {
    _emitSafe('WARN', 'AUDIT_WINDOW_UNBOUNDED', {
      message: 'QODIQA_AUDIT_WINDOW_SIZE=unbounded retains the full audit chain in process memory. '
        + 'This escape hatch exists for one release only — migrate to the bounded default '
        + 'or PG-authoritative mode.',
    });
  }

  // ── 0. M3: where the chain starts (fail closed on a bad or missing base record) ──
  const S0 = _resolveStart();
  if (S0.error) throw new Error(`AUDIT_INTEGRITY_VIOLATION: ${S0.error}`);

  // ── 1. WAL recovery ────────────────────
  _recoverWalSync(S0.start);

  // Re-resolved: recovery may have appended the log's first lines.
  const S = _resolveStart();
  if (S.error) throw new Error(`AUDIT_INTEGRITY_VIOLATION: ${S.error}`);
  _start = S;
  if (S.state !== 'none') {
    _emitSafe('INFO', 'AUDIT_CHAIN_BASE', { state: S.state, startCount: S.offset, startHash: S.start,
      checkpointId: S.base.checkpoint.payload.checkpointId, keyId: S.base.checkpoint.payload.keyId });
  }

  // ── 2. Load state ───────────────────────────────────────────────────────────
  if (!fs.existsSync(LOG_PATH)) { _adoptBaseCounters(S); return; }
  _fileByteLength = fs.statSync(LOG_PATH).size;
  if (_fileByteLength === 0) { _adoptBaseCounters(S); return; }

  const cs = _loadChecksum();
  // follower: read only up to the last complete line present NOW (the checksum, read first, never runs ahead of
  // the log: it is written after the log's fsync).
  if (FOLLOWER) { _readLimit = _stableLength(); _fileByteLength = _readLimit; if (_fileByteLength === 0) return; }

  // ── 2a. FAST PATH: a v2 anchor carries the exact
  // lifetime counters and the byte offset they were valid at. Boot cost is
  // O(delta + window), not O(history): adopt the counters, replay only the
  // suffix the anchor has not yet seen (validated exactly as the full pass
  // would), then refill the tail window. Full-history hash-linkage
  // verification remains the background verifier's job (verifier/ FULL
  // scans re-read the file fresh) — identical to its pre-existing role of
  // catching post-startup file tampering.
  // M3: never in the 'full-file' state (a prune stopped midway) — the full pass below checks the base record's
  // headHash against the file; a prune also drops the v2 block, so the first boot after one always takes the full pass.
  if (S.state !== 'full-file' && cs && cs.v2 && Number.isInteger(cs.v2.byteLength) && cs.v2.byteLength >= 0) {
    if (_fileByteLength < cs.v2.byteLength) {
      throw new Error(
        `AUDIT_INTEGRITY_VIOLATION: checksum expects ${cs.count} entries (${cs.v2.byteLength} bytes) but the log is shorter — log may have been truncated`
      );
    }
    // Anchor self-consistency: the legacy count and the v2 counter block are
    // written atomically by the same _saveChecksum call, so a divergence can
    // only mean tampering/rollback of one of them (e.g. REC-17's count
    // inflated above the real entry total). Fail closed exactly as the
    // earlier loader did for a count/file mismatch.
    if (Number.isInteger(cs.v2.totalCount) && cs.count !== cs.v2.totalCount) {
      throw new Error(
        `AUDIT_INTEGRITY_VIOLATION: checksum count ${cs.count} disagrees with its own v2 counter block (${cs.v2.totalCount}) — anchor may have been tampered`
      );
    }
    _totalCount  = cs.count;
    _modernCount = cs.v2.modernCount;
    _allowCount  = cs.v2.allowCount;
    _blockCount  = cs.v2.blockCount;
    _replayCount = cs.v2.replayCount;
    _headHash    = cs.v2.headHash;
    _tailHash    = cs.tailHash ?? 'GENESIS';

    // Delta replay: entries appended after the anchor was written (crash
    // between append and anchor write, or WAL replay above).
    if (_fileByteLength > cs.v2.byteLength) {
      let lastModernHash = _tailHash === null ? 'GENESIS' : _tailHash;
      // v7 (C-26): the delta replay starts at the anchor, after GENESIS — a bounded walk.
      const tracker = _createLifecycleTracker({ lifecycleComplete: false });
      _streamLinesSync(LOG_PATH, (line, off, ord) => {
        const parsed = _parseLineOrThrow(line, cs.count + ord);
        _validateChainEntry(parsed, lastModernHash);
        _lifecycleStepOrThrow(tracker, parsed, 'boot delta replay');
        const frozen = Object.freeze(parsed);
        _countEntry(frozen);
        if (!frozen.legacy) lastModernHash = frozen.hash;
      }, cs.v2.byteLength);
      _emitLifecycleWarnings(tracker, 'boot delta replay');
    }

    // Tail-window refill from the file's last ≤W lines.
    const tailEntries = [];
    let prevModernHash = null;
    const windowLen = Math.min(WINDOW_SIZE, _totalCount);
    // pre-hash lines are a GENESIS prefix, decided from the window's own lines — never from
    // the (unsigned) anchor's counters: one is allowed only before the window's first chained
    // entry, and that entry must then be the history's first (prevHash GENESIS).
    let legacyBeforeFirstModern = false;
    _streamLinesSync(LOG_PATH, (line, off, ord) => {
      const parsed = _parseLineOrThrow(line, ord);
      // Window-internal linkage: each modern entry must chain off the
      // previous modern entry seen inside the window. (The first window
      // entry's predecessor is outside the window — its linkage is covered
      // by the anchor identity check below plus the verifier's full scans.)
      if (_hasStoredLegacyKey(parsed)) {
        throw new Error('AUDIT_INTEGRITY_VIOLATION: stored legacy flag in tail window at ordinal ' + ord);
      }
      if (_isLegacyShaped(parsed)) {
        if (prevModernHash !== null) {
          throw new Error('AUDIT_INTEGRITY_VIOLATION: legacy-shaped line after the first hash-chained entry in tail window at ordinal ' + ord);
        }
        legacyBeforeFirstModern = true;
        _markLegacy(parsed);
      } else if (prevModernHash === null && legacyBeforeFirstModern && parsed.prevHash !== 'GENESIS') {
        throw new Error('AUDIT_INTEGRITY_VIOLATION: legacy-shaped line after the first hash-chained entry in tail window before ordinal ' + ord);
      } else if (prevModernHash !== null && parsed.prevHash !== prevModernHash) {
        throw new Error('AUDIT_INTEGRITY_VIOLATION: chain_break in tail window at ordinal ' + ord);
      }
      if (!parsed.legacy) {
        if (typeof parsed.canonical !== 'string' || !_verifyCanonicalHash(parsed)) {
          throw new Error('AUDIT_INTEGRITY_VIOLATION: canonical hash mismatch in tail window at ordinal ' + ord);
        }
        prevModernHash = parsed.hash;
      }
      tailEntries.push(Object.freeze(parsed));
    }, _offsetOfLastLines(LOG_PATH, windowLen));

    // a window of only pre-hash lines while chained history exists can only be lines appended after it.
    if (prevModernHash === null && legacyBeforeFirstModern && _tailHash !== 'GENESIS') {
      throw new Error('AUDIT_INTEGRITY_VIOLATION: legacy-shaped lines after the first hash-chained entry in tail window');
    }
    // Identity anchor: the window's newest modern hash must equal the
    // lifetime tail hash the counters claim.
    if (prevModernHash !== null && _tailHash !== 'GENESIS' && prevModernHash !== _tailHash) {
      throw new Error('AUDIT_INTEGRITY_VIOLATION: tail window hash does not match checksum tailHash — log may have been tampered');
    }
    _refillWindow(tailEntries);

    if (_fileByteLength > cs.v2.byteLength) {
      _saveChecksum(_totalCount, _tailHash === 'GENESIS' ? null : _tailHash);
    }
    return;
  }

  // ── 2b. FULL STREAMED PASS (first boot after upgrade / no v2 anchor) ─────────
  // Behaviourally identical validation to the historical loader — every
  // entry parsed, chained, canonical-hash-verified — but through the fixed-
  // buffer reader with a rolling ≤W window instead of a whole-file string
  // and a whole-history array (O(W) memory instead of O(history)).
  // M3: start at the resolved base (GENESIS / 0 unless the file was rebased), counters from the base.
  let lastModernHash = S.start;
  if (S.offset > 0) _adoptBaseCounters(S);
  let anchorHashAtCsCount = null;
  let anchorLegacyAtCsCount = false;
  let fileModernIdx = 0;
  const windowBuf = [];
  // v7 (C-26): lifecycle-complete only when the file chain starts at GENESIS (a pruned chain starts at a signed base).
  const bootTracker = _createLifecycleTracker({ lifecycleComplete: S.start === 'GENESIS' });
  _streamLinesSync(LOG_PATH, (line, off, ord) => {
    const parsed = _parseLineOrThrow(line, S.offset + ord);
    _validateChainEntry(parsed, lastModernHash);
    _lifecycleStepOrThrow(bootTracker, parsed, `ordinal ${S.offset + ord}`);
    const frozen = Object.freeze(parsed);
    _countEntry(frozen);
    if (!frozen.legacy) {
      lastModernHash = frozen.hash;
      if (S.mustHaveAt && fileModernIdx === S.mustHaveAt.modernIndex && frozen.hash !== S.mustHaveAt.hash) {
        throw new Error(`AUDIT_INTEGRITY_VIOLATION: AUDIT_BASE_MISMATCH: entry ${fileModernIdx + 1} is ${frozen.hash}, the signed base record says ${S.mustHaveAt.hash}`);
      }
      fileModernIdx++;
    }
    if (cs && S.offset + ord === cs.count - 1) {
      anchorHashAtCsCount = frozen.hash;
      anchorLegacyAtCsCount = frozen.legacy === true;
    }
    windowBuf.push(frozen);
    if (windowBuf.length > WINDOW_SIZE) windowBuf.shift();
  });
  if (S.mustHaveAt && fileModernIdx <= S.mustHaveAt.modernIndex) {
    throw new Error(`AUDIT_INTEGRITY_VIOLATION: AUDIT_BASE_MISMATCH: the log holds ${fileModernIdx} entries, the signed base record vouches for ${S.mustHaveAt.modernIndex + 1}`);
  }
  _emitLifecycleWarnings(bootTracker, 'boot full pass');

  // ── 3. Anti-deletion checksum validation (unchanged semantics) ──────────────
  if (cs) {
    if (_totalCount < cs.count) {
      throw new Error(
        `AUDIT_INTEGRITY_VIOLATION: checksum expects ${cs.count} entries but only ${_totalCount} found — log may have been truncated`
      );
    }
    if (cs.tailHash && cs.count > 0) {
      if (anchorHashAtCsCount !== null && !anchorLegacyAtCsCount && anchorHashAtCsCount !== cs.tailHash) {
        throw new Error(
          `AUDIT_INTEGRITY_VIOLATION: hash at index ${cs.count - 1} does not match checksum — log may have been tampered`
        );
      }
    }
  }
  _refillWindow(windowBuf);
  // Persist/upgrade the anchor (adds the v2 lifetime-counter block).
  _saveChecksum(_totalCount, _tailHash === 'GENESIS' ? null : _tailHash);
})();

// ── Independent full-chain re-verification, read fresh from disk ─────────────
//
// loadFromDisk() above runs exactly once, at require-time, and throws on any
// violation — appropriate for a startup gate, but it never runs again, so the
// in-memory chain[]/_modernChain/_tailHash can silently drift from the actual
// on-disk file if something external touches audit.log while the process
// keeps running (a hand-edited file, a backup restored over the live file,
// disk-level corruption). This function re-reads and re-validates the file
// from scratch, independently of and without mutating any in-memory chain
// state, and returns a result object instead of throwing — used by the live
// audit chain verifier's FULL scan (src/core/audit/verifier/) to catch
// exactly that class of tampering. It deliberately does NOT repeat WAL
// replay (a one-time startup recovery action, not a repeated verification
// step) and it never writes anything.
//
// ── Streamed full-file scan ────────────────────────────────────────────
//
// Shared by verifyFullChainFromDisk / verifyFullChainFromDiskChunked /
// validateChainIntegrityFromDurableStoreChunked: one bounded-memory pass
// over audit.log performing the IDENTICAL per-entry checks _walkChain does
// (the step body below is a literal copy of _walkChain's loop body — the
// same anti-drift strategy _walkChainChunked documents) while incrementally
// accumulating the aggregate stats _computeStatsFromEntries would otherwise
// need the whole array for. Memory is O(read chunk + artifact-id sets), not
// O(file): the previous fs.readFileSync-whole-file pattern hard-failed with
// ERR_STRING_TOO_LONG once audit.log crossed V8's ~512 MB string limit
// (~330k entries at observed entry sizes) — measured during's
// 1M-entry proof, where the earlier loader could not open the chain at all.
function _newDiskScanState(startPrevHash = 'GENESIS') {
  return {
    // v7: lifecycle-complete only when the scan starts at GENESIS (C-26); a pruned chain starts at a signed base.
    tracker: _createLifecycleTracker({ lifecycleComplete: startPrevHash === 'GENESIS' }),
    // walk state (mirrors _walkChain locals)
    lastModernHash: startPrevHash,
    head: null,
    tail: null,
    entriesVerified: 0,
    seenArtifactIds: new Set(),
    failure: null,          // first walk failure result (walk stops; scan continues)
    index: 0,
    // aggregate stats (mirrors _computeStatsFromEntries)
    allowCount: 0, blockCount: 0, replayCount: 0, modernLength: 0,
    firstTimestamp: null, lastTimestamp: null,
    allArtifactIds: new Set(), replayCountByOrig: new Map(),
    // checksum-anchor capture
    csAnchorIndex: -1, csAnchorHash: null, csAnchorLegacy: false,
    count: 0,
  };
}

function _diskScanLine(st, line, ord) {
  let entry;
  try { entry = JSON.parse(line); }
  catch { throw new Error('malformed_json_at_line_' + (ord + 1)); }
  const i = st.index++;
  st.count++;

  // stats accumulation — over every entry, independent of the walk verdict
  if (entry && !entry.legacy) {
    st.modernLength++;
    if (typeof entry.artifactId === 'string') st.allArtifactIds.add(entry.artifactId);
    if (st.firstTimestamp === null) st.firstTimestamp = entry.timestamp ?? null;
    st.lastTimestamp = entry.timestamp ?? null;
    const isDecision = _entryTypeOf(entry) === 'DECISION';   // v7: decision statistics count DECISION entries only
    if (isDecision && entry.decision === 'ALLOW')      st.allowCount++;
    else if (isDecision && entry.decision === 'BLOCK') st.blockCount++;
    const replayOf = isDecision ? entry.executionContext?.replayOf : null;
    if (typeof replayOf === 'string' && replayOf) {
      st.replayCount++;
      st.replayCountByOrig.set(replayOf, (st.replayCountByOrig.get(replayOf) || 0) + 1);
    }
  }
  if (i === st.csAnchorIndex) {
    st.csAnchorHash   = entry?.hash ?? null;
    st.csAnchorLegacy = !!entry?.legacy;
  }

  if (st.failure) return; // walk already concluded; keep counting/stats only

  // ── per-entry walk checks: literal copy of _walkChain's loop body ──────────
  const fail = (obj) => { st.failure = { valid: false, entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, offendingIndex: i, ...obj }; };
  if (!entry || typeof entry !== 'object') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: null }); return; }
  if (typeof entry.timestamp  !== 'string') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: entry.artifactId ?? null }); return; }
  if (typeof entry.artifactId !== 'string') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: null }); return; }
  // a line read from disk carries a `legacy` key only if forged (see _hasStoredLegacyKey).
  if (_hasStoredLegacyKey(entry)) { fail({ reason: 'AUDIT_CHAIN_TAMPERED', detail: 'STORED_LEGACY_FLAG', tamperingDetected: true, offendingArtifactId: entry.artifactId }); return; }
  if (st.seenArtifactIds.has(entry.artifactId)) { fail({ reason: 'AUDIT_DUPLICATE_ENTRY', tamperingDetected: true, offendingArtifactId: entry.artifactId }); return; }
  st.seenArtifactIds.add(entry.artifactId);
  if (typeof entry.prevHash  !== 'string') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: entry.artifactId }); return; }
  if (typeof entry.hash      !== 'string') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: entry.artifactId }); return; }
  if (typeof entry.inputHash !== 'string') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: entry.artifactId }); return; }
  if (typeof entry.decision  !== 'string') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: entry.artifactId }); return; }
  if (typeof entry.signature !== 'string' || !entry.signature) { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: entry.artifactId }); return; }
  if (entry.prevHash !== st.lastModernHash) {
    fail({ reason: 'AUDIT_CHAIN_BROKEN', tamperingDetected: false, offendingArtifactId: entry.artifactId, expectedPrevHash: st.lastModernHash, actualPrevHash: entry.prevHash });
    return;
  }
  if (typeof entry.canonical !== 'string') { fail({ reason: 'AUDIT_ENTRY_MISSING', tamperingDetected: false, offendingArtifactId: entry.artifactId }); return; }
  if (!_verifyCanonicalHash(entry)) {
    const shape = _v7IntegrityDetail(entry);
    fail({ reason: 'AUDIT_CHAIN_TAMPERED', ...(shape ? { detail: shape } : {}), tamperingDetected: true, offendingArtifactId: entry.artifactId, expectedHash: _expectedHashFor(entry), actualHash: entry.hash });
    return;
  }
  const lifecycle = st.tracker.step(entry);   // v7 (R-2 / R-17 / C-26)
  if (lifecycle) { fail({ reason: 'AUDIT_CHAIN_TAMPERED', detail: lifecycle.detail, tamperingDetected: true, offendingArtifactId: entry.artifactId }); return; }
  if (st.head === null) st.head = entry.hash;
  st.tail = entry.hash;
  st.lastModernHash = entry.hash;
  st.entriesVerified++;
  // M3 'full-file' state: the file still holds the archived prefix; its entry #chainLength must be the base's head.
  if (st.mustHaveAt && st.fileModernIdx === st.mustHaveAt.modernIndex && entry.hash !== st.mustHaveAt.hash) {
    fail({ reason: 'AUDIT_CHAIN_TAMPERED', detail: `AUDIT_BASE_MISMATCH: entry ${st.fileModernIdx + 1} is not the signed base record's head`,
      tamperingDetected: true, offendingArtifactId: entry.artifactId });
  }
  st.fileModernIdx = (st.fileModernIdx || 0) + 1;
}

function _diskScanFinish(st) {
  // M3: lifetime figures — the archived prefix (vouched for by the signed base record) plus this file.
  const off = st.offset || 0;
  if (!st.failure && st.mustHaveAt && (st.fileModernIdx || 0) <= st.mustHaveAt.modernIndex) {
    st.failure = { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'AUDIT_BASE_MISMATCH: the log is shorter than the signed base record',
      tamperingDetected: true, entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, offendingIndex: st.index, offendingArtifactId: null };
  }
  if (st.failure && off) st.failure = { ...st.failure, entriesVerified: st.failure.entriesVerified + off };
  st.count += off;
  st.modernLength += off;
  if (off && st.tail === null) st.tail = st.lastModernHash;   // empty rebased file: the chain ends at the base's head
  const walkResult = st.failure
    ? st.failure
    : { valid: true, reason: null, entriesVerified: st.entriesVerified + off, head: st.head, tail: st.tail, tamperingDetected: false };
  let replaysLinked = 0;
  for (const [originalId, count] of st.replayCountByOrig) {
    if (st.allArtifactIds.has(originalId)) replaysLinked += count;
  }
  const stats = {
    allowCount: st.allowCount, blockCount: st.blockCount,
    replaysDetected: st.replayCount, replaysLinked,
    modernLength: st.modernLength,
    firstTimestamp: st.firstTimestamp, lastTimestamp: st.lastTimestamp,
  };
  // v7 (C-26): lifecycle scope + non-fatal warnings travel with the verdict.
  const warnings = st.tracker.finish();
  return { walkResult, stats, count: st.count, csAnchorHash: st.csAnchorHash, csAnchorLegacy: st.csAnchorLegacy, lifecycleComplete: st.tracker.lifecycleComplete, warnings };
}

// M3: every rescan re-resolves where the chain starts FROM DISK (the base record re-read and its signature
// re-verified — a base record tampered after boot is caught here). Counts are then lifetime: offset + file lines.
function _newBasedScanState(cs) {
  const S = _resolveStart();
  const st = _newDiskScanState(S.error ? 'GENESIS' : S.start);
  st.offset = S.error ? 0 : S.offset;
  st.mustHaveAt = S.error ? null : (S.mustHaveAt || null);
  st.fileModernIdx = 0;
  st.csAnchorIndex = cs && cs.count > 0 ? cs.count - 1 - st.offset : -1;   // < 0: the anchor lies in the archived prefix
  // No base record on disk: the walk from GENESIS reports the first entry's own defect with its earlier reason code
  // (the contract pins those: AUDIT_CHAIN_BROKEN / AUDIT_ENTRY_MISSING at index 0) — still a failure, never a pass.
  if (S.error && !fs.existsSync(BASE_PATH)) return st;
  if (S.error) {
    st.failure = { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: S.error, tamperingDetected: true,
      entriesVerified: 0, head: null, tail: null, offendingIndex: 0, offendingArtifactId: null };
  }
  return st;
}

// One synchronous streamed pass over the whole log (fixed read buffer).
function _scanDiskStreamedSync(cs) {
  const st = _newBasedScanState(cs);
  _streamLinesSync(LOG_PATH, (line, off, ord) => { _diskScanLine(st, line, ord); });
  return _diskScanFinish(st);
}

// Chunked, event-loop-yielding twin — same fixed-buffer read pattern as
// _streamLinesSync, but awaits setImmediate every `yieldEvery` entries so a
// large chain's full scan cannot monopolize the event loop (#129 /
// preserved from the array-based _walkChainChunked design).
async function _scanDiskStreamedChunked(cs, { yieldEvery = CHAIN_WALK_YIELD_EVERY } = {}) {
  const st = _newBasedScanState(cs);
  const fd = fs.openSync(LOG_PATH, 'r');
  try {
    const buf = Buffer.alloc(BOOT_CHUNK_BYTES);
    let carry = '';
    let pos = 0;
    let ordinal = 0;
    let sinceYield = 0;
    for (;;) {
      const want = Math.min(buf.length, _readLimit - pos);
      if (want <= 0) break;
      const n = fs.readSync(fd, buf, 0, want, pos);
      if (n <= 0) break;
      const text = carry + buf.toString('utf8', 0, n);
      const parts = text.split('\n');
      carry = parts.pop();
      for (const part of parts) {
        const line = part.trim();
        if (line.length > 0) {
          _diskScanLine(st, line, ordinal);
          ordinal++;
          if (++sinceYield >= yieldEvery) {
            sinceYield = 0;
            await require('../../../verifierPacer').pace();
          }
        }
      }
      pos += n;
    }
    const tail = carry.trim();
    if (tail.length > 0) _diskScanLine(st, tail, ordinal);
  } finally {
    fs.closeSync(fd);
  }
  return _diskScanFinish(st);
}

// Shared checksum-anchor/divergence post-processing for the two full-scan
// entry points below — byte-for-byte the same checks the array-based code
// performed, fed from the scan's captured anchor entry instead of an index
// into a materialized array.
function _fullScanVerdict(scan, cs, memory = null) {
  // in the verifier worker, memory is the MAIN thread's {totalCount, tailHash} (RPC), so the divergence this
  // reports is still "the file vs what the serving process believes" — never the follower compared with itself.
  const memTotal = memory ? memory.totalCount : _totalCount;
  const memTail  = memory ? memory.tailHash : _tailHash;
  let checksumOk = true;
  if (cs) {
    if (scan.count < cs.count) {
      checksumOk = false;
    } else if (cs.tailHash && cs.count > 0) {
      if (scan.csAnchorHash !== null && !scan.csAnchorLegacy && scan.csAnchorHash !== cs.tailHash) checksumOk = false;
    }
  }
  const diskTail = scan.walkResult.tail ?? 'GENESIS';
  const memoryVsDiskDivergence = scan.count !== memTotal || diskTail !== memTail;
  return {
    applicable:             true,
    diskEntriesCount:       scan.count,
    walkResult:             scan.walkResult,
    // v7 (C-26): lifecycle scope + non-fatal warnings (INTENT_BEFORE_START, ORPHAN_INTENT).
    lifecycleComplete:      scan.lifecycleComplete === true,
    warnings:               Array.isArray(scan.warnings) ? scan.warnings : [],
    checksumOk,
    memoryVsDiskDivergence,
    parseError:             null,
  };
}

// No-op in distributed mode, where the file is not the ordering authority.
function verifyFullChainFromDisk() {
  if (ORDERING_MODE === 'distributed') {
    return { applicable: false, reason: 'DISTRIBUTED_MODE_NO_FILE' };
  }

  if (!fs.existsSync(LOG_PATH)) {
    const emptyWalk = { valid: true, reason: null, entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
    return {
      applicable:              true,
      diskEntriesCount:        0,
      walkResult:              emptyWalk,
      checksumOk:              true,
      memoryVsDiskDivergence:  _totalCount > 0,
      parseError:              null,
    };
  }

  const cs = _loadChecksum();
  let scan;
  try {
    scan = _scanDiskStreamedSync(cs);
  } catch (err) {
    return {
      applicable:             true,
      diskEntriesCount:       0,
      walkResult:             null,
      checksumOk:             false,
      memoryVsDiskDivergence: true,
      parseError:             err.message,
    };
  }
  return _fullScanVerdict(scan, cs);
}

// Non-blocking twin of verifyFullChainFromDisk — identical file read and
// checksum/divergence logic, but the hash-chain walk itself (the part that
// scales with chain size and can run for a non-trivial duration on a large
// on-disk chain) uses the chunked, yielding walker. This is what
// ChainVerifier's scheduled FULL scan (default every 24h, src/core/audit/
// verifier/ChainVerifier.js) uses instead of verifyFullChainFromDisk, so a
// large chain's periodic full re-verification can no longer stall
// concurrent request handling for its entire duration.
async function verifyFullChainFromDiskChunked(opts) {
  if (ORDERING_MODE === 'distributed') {
    return { applicable: false, reason: 'DISTRIBUTED_MODE_NO_FILE' };
  }

  if (!fs.existsSync(LOG_PATH)) {
    const emptyWalk = { valid: true, reason: null, entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
    return {
      applicable:              true,
      diskEntriesCount:        0,
      walkResult:              emptyWalk,
      checksumOk:              true,
      memoryVsDiskDivergence:  _totalCount > 0,
      parseError:              null,
    };
  }

  const cs = _loadChecksum();
  // follower: scan exactly the byte prefix the MAIN thread had committed when it took its memory snapshot
  // (memory.byteLength), so the divergence verdict compares one consistent point in time; else the stable length.
  if (FOLLOWER) _readLimit = opts && opts.memory && Number.isInteger(opts.memory.byteLength) ? Math.min(opts.memory.byteLength, _stableLength()) : _stableLength();
  let scan;
  try {
    scan = await _scanDiskStreamedChunked(cs, opts);
  } catch (err) {
    return {
      applicable:             true,
      diskEntriesCount:       0,
      walkResult:             null,
      checksumOk:             false,
      memoryVsDiskDivergence: true,
      parseError:             err.message,
    };
  }
  return _fullScanVerdict(scan, cs, opts && opts.memory); // the verifier worker passes the MAIN thread's memory
}

// ── Startup: hydrate chain from PostgreSQL (distributed mode only) ────────────
//
// Called explicitly by server.js after pgPool.initialize() succeeds (and
// after the startup precondition probe in multiInstanceGuard.js). No-op in
// single-node mode. Reuses the exact same validation/indexing path as the
// file loader above (_validateChainEntry, _indexEntry) — PostgreSQL rows are
// shaped identically (see pg-audit-backend.js loadChainFromPg()), and
// ordering by `seq ASC` now reflects true commit order because every append
// serializes through the audit_chain_head row lock (distributedOrdering.js).
//
// This is a point-in-time snapshot of the global chain as of startup; it is
// NOT kept live-synced with other replicas' subsequent writes (this
// replica's own later appends do update it — see _appendOne). Reads through
// the O(1) lookup functions below reflect that: fine for convenience/debug
// queries, but the hard security guarantees (dedup, replay, ordering) are
// enforced by PostgreSQL's UNIQUE constraints on every write, not by this
// local cache — see distributedOrdering.js's header comment.
async function hydrateFromPgIfDistributed() {
  if (ORDERING_MODE !== 'distributed') return;

  // full-chain hydration replaced by lifetime counters (streamed in
  // one validated pass) + a tail window — O(W) steady memory. The rows are
  // still fetched batch-wise and EVERY entry is chain-validated exactly as
  // the full hydrate did; only retention is windowed.
  let lastModernHash = 'GENESIS';
  let fromSeq = 0;
  const windowBuf = [];
  const hydrateTracker = _createLifecycleTracker({ lifecycleComplete: true });   // v7: hydrates from GENESIS
  for (;;) {
    const rows = await pgAuditBackend.fetchChainBatch(fromSeq, 5000);
    if (rows.length === 0) break;
    for (const parsed of rows) {
      _validateChainEntry(parsed, lastModernHash);
      _lifecycleStepOrThrow(hydrateTracker, parsed, 'distributed hydrate');
      const frozen = Object.freeze(parsed);
      _countEntry(frozen);
      if (!frozen.legacy) lastModernHash = frozen.hash;
      windowBuf.push(frozen);
      if (windowBuf.length > WINDOW_SIZE) windowBuf.shift();
    }
    fromSeq = rows[rows.length - 1].seq;
    if (rows.length < 5000) break;
  }
  _emitLifecycleWarnings(hydrateTracker, 'distributed hydrate');
  _refillWindow(windowBuf);
}

// ── Startup: hydrate _tailHash from PostgreSQL (single-node mode) ───────────
//
// FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION: single-node mode's file is
// the authoritative source and this must NEVER override it — chain[],
// every index, and _tailHash all stay exactly as loadFromDisk()'s IIFE
// built them whenever the file already has real history. This only ever
// touches _tailHash, and only when the file yielded none at all (still
// 'GENESIS' after loadFromDisk() ran) — that is precisely the case where a
// fresh process was about to unconditionally re-claim 'GENESIS' against a
// shared, persistent audit_chain table that may already hold a committed
// chain from a prior process lifetime, colliding with
// idx_audit_chain_prev_hash_unique (migration 026) and — because the
// failure is absorbed, by design, same as every dual-write failure here —
// silently orphaning every entry appended for the rest of this process's
// life. See FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION-REPORT.md.
//
// Runs at most once per process (memoized via _pgHydrationPromise), lazily
// on the first append() — not eagerly at module-require time, since
// pgPool.initialize() is not guaranteed to have run yet when this module is
// first required (same constraint hydrateFromPgIfDistributed() above
// already documents).
//
// A failure here (PG unreachable, query error) falls back to exactly
// today's pre-fix behavior (_tailHash stays 'GENESIS') — but, unlike the
// silent fallback that hid this defect, always with an explicit ERROR log
// and a dedicated counter, never silently.
let _pgHydrationPromise = null;
async function _hydrateTailFromPg() {
  if (ORDERING_MODE === 'distributed') return; // handled by hydrateFromPgIfDistributed()
  if (_tailHash !== 'GENESIS') return;          // file already has real history — never override it

  try {
    const tail = await pgAuditBackend.getChainTail();
    if (tail && tail.hash) {
      _tailHash = tail.hash;
      require('../../../../../../services/logger').emit('INFO', 'AUDIT_PG_TAIL_HYDRATED', {
        hash: tail.hash,
        seq:  tail.seq,
      });
    }
    // tail === null means either PG is disabled or audit_chain is
    // genuinely empty (fresh install) — both correctly leave _tailHash at
    // 'GENESIS', no error, nothing to log.
  } catch (err) {
    // Observability must never affect the append path itself (same
    // principle as _recordAnchorMismatch() above) — guarded for the many
    // existing unit tests that jest.mock('.../pg-audit-backend') and
    // jest.mock('.../metrics') with partial shapes unrelated to this
    // hydration path.
    try { require('../../../../../observability/metrics').auditPgHydrationFailedTotal.inc({}); } catch { /* metrics must never affect append */ }
    try {
      require('../../../../../../services/logger').emit('ERROR', 'AUDIT_PG_HYDRATION_FAILED', {
        error: err.message,
        code:  err.code ?? null,
      });
    } catch { /* logging must never affect append */ }
    // Fall through — _tailHash stays 'GENESIS', identical to the original
    // behavior, but now surfaced instead of silent.
  }
}
function _ensurePgHydrated() {
  if (!_pgHydrationPromise) _pgHydrationPromise = _hydrateTailFromPg();
  return _pgHydrationPromise;
}

// ── O(1) Lookup functions ─────────────────────────────────────────────────────

// O(1) — uses _nonceSet.
// every history-reading lookup below is now ASYNC — O(1) from the
// window when the answer is in the tail, falling back to the durable store
// (indexed SQL in distributed mode; a bounded-memory streamed file scan in
// single-node mode) for anything older. The exported names and result
// semantics are unchanged (Option A of the ADR); only the Promise wrapper is
// new. The hot append path never calls these.

// Streamed predicate scan over the durable file — bounded memory, admin-
// plane cost model (O(file) per miss, documented in the ADR).
function _scanFile(visit) {
  if (!fs.existsSync(LOG_PATH)) return;
  let modernPos = _start.offset;   // M3: lifetime positions — the file starts after the archived prefix
  _streamLinesSync(LOG_PATH, (line, off, ord) => {
    let parsed;
    try { parsed = JSON.parse(line); } catch { return; }
    if (_isLegacyShaped(parsed) && !_hasStoredLegacyKey(parsed)) _markLegacy(parsed);
    const isModern = !parsed.legacy;
    const ret = visit(Object.freeze(parsed), { ordinal: ord, modernPos: isModern ? modernPos : null, byteOffset: off });
    if (isModern) modernPos++;
    return ret;
  });
}

const _distributed = () => ORDERING_MODE === 'distributed';

async function isNonceUsed(nonce) {
  if (typeof nonce !== 'string' || nonce.length === 0) return false;
  if (_nonceSet.has(nonce)) return true;
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) return false;
  if (_distributed()) {
    // Distributed dedup is enforced durably by PG UNIQUE constraints at
    // append time; this read-only check scans the mirror.
    const rows = await pgAuditBackend.loadChainFromPg();
    return rows.some((r) => r.nonce === nonce);
  }
  let found = false;
  _scanFile((e) => { if (e.nonce === nonce) { found = true; return false; } });
  return found;
}

async function alreadyExecuted(artifactId) {
  if (typeof artifactId !== 'string' || !artifactId) return false;
  if (_byArtifactId.has(artifactId)) return true;
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) return false;
  return (await getArtifactById(artifactId)) !== null;
}

// Window O(1); durable fallback on miss. Tenant isolation enforced inline.
async function getArtifactById(artifactId, tenantId) {
  if (typeof artifactId !== 'string' || !artifactId) return null;
  let entry = _byArtifactId.get(artifactId) ?? null;
  if (!entry && !WINDOW_UNBOUNDED && _totalCount > chain.length) {
    if (_distributed()) {
      entry = await pgAuditBackend.queryByArtifactId(artifactId);
    } else {
      _scanFile((e) => { if (!e.legacy && e.artifactId === artifactId) { entry = e; return false; } });
    }
  }
  if (!entry) return null;
  if (tenantId && entry.tenantId && entry.tenantId !== tenantId) return null;
  return entry;
}

async function getAuditChainForTenant(tenantId) {
  if (!tenantId) return [];
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) {
    return (_tenantIndex.get(tenantId) ?? []).slice();
  }
  if (_distributed()) {
    return pgAuditBackend.queryByTenant(tenantId);
  }
  const out = [];
  _scanFile((e) => { if (!e.legacy && e.tenantId === tenantId) out.push(e); });
  return out;
}

/**
 * Action 2 — dispatch point for the usage-metering service
 * (src/core/usage/usageMeteringService.js). Mirrors getAuditChainForTenant()'s
 * own single-node/distributed branch immediately above: the in-memory/file
 * path reuses that same tenant-scoped read and reduces it with the
 * canonical pure reducer; the distributed path defers entirely to
 * pg-audit-backend.js's SQL twin (aggregateUsageByTenantPg) rather than
 * pulling every raw entry, then folds its per-day rows with the same
 * numeric policy via mergePgDailyRows(). Both paths state the identical
 * metering semantics — see usageAggregation.js's header for the full rules
 * and test/integration/usageMeteringPg.integration.test.js for the cross-check proof.
 *
 * @param {string} tenantId
 * @param {{fromMs: number, toMs: number}} range — half-open [fromMs, toMs)
 * @returns {Promise<{totals: object, series: Array<object>}>}
 */
async function aggregateTenantUsage(tenantId, { fromMs, toMs }) {
  if (!tenantId) return reduceUsage([], { fromMs, toMs });
  if (_distributed()) {
    const rows = await pgAuditBackend.aggregateUsageByTenantPg(tenantId, {
      fromIso: new Date(fromMs).toISOString(),
      toIso:   new Date(toMs).toISOString(),
    });
    return mergePgDailyRows(rows);
  }
  const entries = await getAuditChainForTenant(tenantId);
  return reduceUsage(entries, { fromMs, toMs });
}

// O(1) — returns _tailHash maintained on every append. (Sync: lifetime counter.)
function getAuditTailHash() {
  return _tailHash;
}

async function auditChainContains(hash) {
  if (typeof hash !== 'string') return false;
  if (hash === 'GENESIS') return true;
  if (_start.base && hash === _start.start) return true;   // M3: the signed base record's head (archived prefix)
  if (_byHash.has(hash)) return true;
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) return false;
  if (_distributed()) {
    const rows = await pgAuditBackend.loadChainFromPg();
    return rows.some((r) => r.hash === hash);
  }
  let found = false;
  _scanFile((e) => { if (!e.legacy && e.hash === hash) { found = true; return false; } });
  return found;
}

// (NF-9): an optional tenantId applies the same filter getArtifactById()
// applies — a route that scoped the artifact itself to a tenant still
// returned every tenant's replay lineage for it.
async function getReplayLineage(artifactId, tenantId = null) {
  if (typeof artifactId !== 'string' || !artifactId) return [];
  const keep = (e) => !tenantId || !e.tenantId || e.tenantId === tenantId;
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) {
    return (_replayIndex.get(artifactId) ?? []).filter(keep);
  }
  if (_distributed()) {
    return (await pgAuditBackend.queryReplayLineage(artifactId)).filter(keep);
  }
  const out = [];
  _scanFile((e) => {
    const replayOf = e.executionContext?.replayOf;
    if (!e.legacy && replayOf === artifactId && keep(e)) out.push(e);
  });
  return out;
}

// Position and neighbour entries; window O(1), durable scan on miss.
// Returns null if the artifact is not in the modern chain.
async function getArtifactNeighbors(artifactId) {
  const winPos = _modernPosByArtifactId.get(artifactId);
  if (winPos !== undefined) {
    const i = winPos - _modernWindowStartPos;
    const needPrevOutside = i === 0 && _modernWindowStartPos > 0;
    if (!needPrevOutside) {
      return {
        position: winPos,
        prev:     i > 0                        ? _modernChain[i - 1] : null,
        next:     i < _modernChain.length - 1  ? _modernChain[i + 1] : null,
      };
    }
  }
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) return winPos === undefined ? null : {
    position: winPos,
    prev: null,
    next: _modernChain.length > 1 ? _modernChain[1] : null,
  };
  if (_distributed()) {
    const row = await pgAuditBackend.queryByArtifactId(artifactId);
    if (!row || !Number.isInteger(row.seq)) return null;
    const prev = row.seq > 1 ? (await pgAuditBackend.fetchChainBatch(row.seq - 2, 1))[0] ?? null : null;
    const next = (await pgAuditBackend.fetchChainBatch(row.seq, 1))[0] ?? null;
    return { position: row.seq - 1, prev, next };
  }
  let result = null;
  let prevEntry = null;
  let matched = null;
  _scanFile((e, meta) => {
    if (e.legacy) return;
    if (matched) { result = { position: matched.pos, prev: matched.prev, next: e }; return false; }
    if (e.artifactId === artifactId) { matched = { pos: meta.modernPos, prev: prevEntry }; }
    prevEntry = e;
  });
  if (!result && matched) result = { position: matched.pos, prev: matched.prev, next: null };
  return result;
}

async function getRequestHashEntries(requestHash) {
  if (!requestHash || requestHash === 'UNAVAILABLE') return [];
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) {
    return (_requestHashIdx.get(requestHash) ?? []).slice();
  }
  if (_distributed()) {
    const rows = await pgAuditBackend.loadChainFromPg();
    return rows.filter((r) => r.requestHash === requestHash);
  }
  const out = [];
  _scanFile((e) => { if (!e.legacy && e.requestHash === requestHash && e.requestHash !== 'UNAVAILABLE') out.push(e); });
  return out;
}

// O(1) — all counters are maintained on every append.
function getChainStats() {
  return {
    chainLength:  _totalCount,
    modernLength: _modernCount,
    allowCount:   _allowCount,
    blockCount:   _blockCount,
    replayCount:  _replayCount,
    headHash:     _headHash,
    tailHash:     _tailHash,
  };
}

// ── Paginated history access (the getModernChain/getAuditChain
// replacement) — stable-ordered by entry sequence and resumable via an
// opaque cursor, so a caller can walk a million-entry history without any
// side holding it all at once. File mode cursors carry the exact byte
// offset to resume from (O(page) per page); distributed mode cursors carry
// the last PG seq.
// S3: durable=true always reads audit.log from disk (never the in-memory tail window), so every returned
// nextCursor carries the byte offset {m, o}; the divergence verifier persists such cursors and resumes in O(page).
async function getModernChainPage({ cursor = null, limit = 1000, durable = false } = {}) {
  const lim = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 10000) : 1000;

  if (_distributed()) {
    const fromSeq = cursor && Number.isInteger(cursor.seq) ? cursor.seq : 0;
    const rows = await pgAuditBackend.fetchChainBatch(fromSeq, lim);
    const last = rows[rows.length - 1];
    return {
      entries: rows,
      startPos: fromSeq,
      nextCursor: rows.length === lim && last ? { seq: last.seq } : null,
    };
  }

  const fromModernPos = cursor && Number.isInteger(cursor.m) ? cursor.m : 0;

  // Window fast path: everything requested is inside the tail window.
  if (!durable && fromModernPos >= _modernWindowStartPos) {
    const i = fromModernPos - _modernWindowStartPos;
    const entries = _modernChain.slice(i, i + lim);
    const nextPos = fromModernPos + entries.length;
    return {
      entries,
      startPos: fromModernPos,
      nextCursor: nextPos < _modernCount ? { m: nextPos } : null,
    };
  }

  // Durable path: resume from the cursor's byte offset (or the file start).
  const fromByte = cursor && Number.isInteger(cursor.o) ? cursor.o : 0;
  // M3: the file starts at the base; a request inside the archived prefix begins at the base (startPos says so).
  const effectiveFrom = Math.max(fromModernPos, _start.offset);
  let skipModern = cursor && Number.isInteger(cursor.o) ? 0 : effectiveFrom - _start.offset;
  const entries = [];
  let nextByte = fromByte;
  let seenModern = 0;
  if (fs.existsSync(LOG_PATH)) {
    _streamLinesSync(LOG_PATH, (line, off) => {
      let parsed;
      try { parsed = JSON.parse(line); } catch { return; }
      if (!('inputHash' in parsed) || parsed.inputHash == null) { return; }
      if (skipModern > 0) { skipModern--; seenModern++; return; }
      if (entries.length >= lim) { nextByte = off; return false; }
      entries.push(Object.freeze(parsed));
      seenModern++;
      nextByte = off + Buffer.byteLength(line, 'utf8') + 1;
    }, fromByte);
  }
  const pageStart = cursor && Number.isInteger(cursor.o) ? fromModernPos : effectiveFrom;   // M3
  const nextPos = pageStart + entries.length;
  return {
    entries,
    startPos: pageStart,
    nextCursor: nextPos < _modernCount ? { m: nextPos, o: nextByte } : null,
  };
}

// Point lookup by absolute modern position (used by the verifier startup
// gate for its single watermark-anchor read). Window O(1); durable otherwise.
async function getModernEntryAt(pos) {
  if (!Number.isInteger(pos) || pos < 0 || pos >= _modernCount) return null;
  if (pos < _start.offset) return null;   // M3: archived — no longer in audit.log (see the archive segment)
  if (pos >= _modernWindowStartPos) return _modernChain[pos - _modernWindowStartPos] ?? null;
  if (_distributed()) {
    const rows = await pgAuditBackend.fetchChainBatch(pos, 1);
    return rows[0] ?? null;
  }
  let found = null;
  _scanFile((e, meta) => {
    if (meta.modernPos === pos) { found = e; return false; }
  });
  return found;
}

// the hashes at MANY absolute modern positions, resolved exactly as getModernEntryAt() resolves
// one (window first; distributed: per-position PG read; single node: file position), but with ONE file pass that stops
// once every requested position is found — instead of one full scan from the start of the file per position. The boot
// anchor check needs one position per anchor: after a 1-h soak (403 anchors, 430k entries) per-position scans meant
// ~87M line parses and an indefinitely stalled boot. Returns Map(position → hash); unresolvable positions are absent.
async function getModernHashesAt(positions) {
  const out = new Map();
  const want = new Set((positions || []).filter((p) => Number.isInteger(p) && p >= 0 && p < _modernCount && p >= _start.offset));
  for (const p of [...want]) {
    if (p >= _modernWindowStartPos) {
      const e = _modernChain[p - _modernWindowStartPos];
      if (e) out.set(p, e.hash);
      want.delete(p);
    }
  }
  if (want.size === 0) return out;
  if (_distributed()) {
    for (const p of want) {
      const rows = await pgAuditBackend.fetchChainBatch(p, 1);
      if (rows[0]) out.set(p, rows[0].hash);
    }
    return out;
  }
  const last = Math.max(...want);
  _scanFile((e, meta) => {
    if (meta.modernPos === null) return undefined;
    if (want.has(meta.modernPos)) { out.set(meta.modernPos, e.hash); want.delete(meta.modernPos); }
    return (want.size === 0 || meta.modernPos >= last) ? false : undefined;
  });
  return out;
}

// v7 lifecycles (INTENT / STREAM_OPENED) in the in-memory tail window with no later DECISION
// for their requestId. A DECISION always follows its INTENT, so for every INTENT inside the window the answer is exact.
// Used at boot (before the server listens) by lifecycleReconciler.reconcileAtBoot().
function getOpenLifecyclesInWindow() {
  const open = new Map();
  for (const e of _modernChain) {
    if (!e || e.schemaVersion !== 7 || typeof e.requestId !== 'string' || !e.requestId) continue;
    if (e.entryType === 'INTENT' || e.entryType === 'STREAM_OPENED') {
      const o = open.get(e.requestId) || { requestId: e.requestId, intent: null, streamOpened: null };
      if (e.entryType === 'INTENT') o.intent = e; else o.streamOpened = e;
      open.set(e.requestId, o);
    } else {
      open.delete(e.requestId);
    }
  }
  return [...open.values()];
}

// byte offsets of MANY modern positions from ONE forward raw newline count (no JSON parse of the
// history), then one read + parse per position. Same positional semantics as locateModernCursor() below (counted from
// the start of the file); the results are CANDIDATES — the caller compares each hash with what it expects and falls back
// to the parse-based getModernHashesAt() when anything differs (a blank line or any other irregularity shifts the count).
// Returns { offsets: Map(pos → byteOffset), hashes: Map(pos → hash) }; unresolvable positions are absent.
function getModernHashesAtByOffset(positions) {
  const offsets = new Map(); const hashes = new Map();
  if (_distributed() || !fs.existsSync(LOG_PATH)) return { offsets, hashes };
  const legacyLines = _start.offset > 0 ? 0 : Math.max(0, _totalCount - _modernCount);
  // newline count before the wanted line → position(s)
  const wantByNl = new Map();
  for (const p of positions || []) {
    if (!Number.isInteger(p) || p < _start.offset || p >= _modernCount) continue;
    const nl = legacyLines + (p - _start.offset);
    if (!wantByNl.has(nl)) wantByNl.set(nl, []);
    wantByNl.get(nl).push(p);
  }
  if (wantByNl.size === 0) return { offsets, hashes };
  const maxNl = Math.max(...wantByNl.keys());
  if (wantByNl.has(0)) for (const p of wantByNl.get(0)) offsets.set(p, 0);
  const fd = fs.openSync(LOG_PATH, 'r');
  try {
    const buf = Buffer.alloc(BOOT_CHUNK_BYTES);
    let base = 0; let seen = 0;
    while (seen < maxNl) {
      const want = Math.min(buf.length, _readLimit - base);
      if (want <= 0) break;
      const n = fs.readSync(fd, buf, 0, want, base);
      if (n <= 0) break;
      let i = -1;
      while ((i = buf.indexOf(0x0a, i + 1)) !== -1 && i < n) {
        seen++;
        const ps = wantByNl.get(seen);
        if (ps) for (const p of ps) offsets.set(p, base + i + 1);
        if (seen >= maxNl) break;
      }
      base += n;
    }
    for (const [p, off] of offsets) {
      const line = _readLineAtSync(fd, off);
      if (line === null) { offsets.delete(p); continue; }
      try { const e = JSON.parse(line); if (e && typeof e.hash === 'string') hashes.set(p, e.hash); } catch { /* unparsable: no hash → caller falls back */ }
    }
  } finally {
    fs.closeSync(fd);
  }
  return { offsets, hashes };
}

// One complete line starting at byte `off` (without its newline), or null at/after the readable end.
function _readLineAtSync(fd, off) {
  const chunks = []; let pos = off; const buf = Buffer.alloc(65536);
  for (;;) {
    const want = Math.min(buf.length, _readLimit - pos);
    if (want <= 0) break;
    const n = fs.readSync(fd, buf, 0, want, pos);
    if (n <= 0) break;
    const nl = buf.indexOf(0x0a);
    if (nl !== -1 && nl < n) { chunks.push(Buffer.from(buf.subarray(0, nl))); return Buffer.concat(chunks).toString('utf8'); }
    chunks.push(Buffer.from(buf.subarray(0, n))); pos += n;
  }
  return chunks.length ? Buffer.concat(chunks).toString('utf8') : null;
}

// a cursor { m: pos, o: byteOffset } for modern position `pos`, found by counting raw newlines from
// the START of the file — no JSON parse of the prefix (the O(file) parse pass the startup mirror check paid twice to
// reach its checkpoint). Counting from the start keeps the positional property of the parse-based locate (the number of
// lines before the position equals the position). It is only a CANDIDATE: a blank line, a pre-hash line in a rebased
// file or any other irregularity shifts it, so callers must read the entry there and confirm its identity (hash) before
// trusting it, and fall back to the parse-based locate otherwise. Returns null when it cannot apply (distributed mode,
// position outside the file, file missing).
function locateModernCursor(pos) {
  if (_distributed() || !Number.isInteger(pos) || pos < _start.offset || pos >= _modernCount) return null;
  if (!fs.existsSync(LOG_PATH)) return null;
  // Pre-hash (legacy) lines can only precede the first chained entry (enforced at load); a rebased file has none.
  const legacyLines = _start.offset > 0 ? 0 : Math.max(0, _totalCount - _modernCount);
  let need = legacyLines + (pos - _start.offset);   // newlines to pass before the wanted line starts
  if (need === 0) return { m: pos, o: 0 };
  const fd = fs.openSync(LOG_PATH, 'r');
  try {
    const buf = Buffer.alloc(BOOT_CHUNK_BYTES);
    let base = 0;
    for (;;) {
      const want = Math.min(buf.length, _readLimit - base);
      if (want <= 0) return null;
      const n = fs.readSync(fd, buf, 0, want, base);
      if (n <= 0) return null;
      let i = -1;
      while ((i = buf.indexOf(0x0a, i + 1)) !== -1 && i < n) {
        if (--need === 0) return { m: pos, o: base + i + 1 };
      }
      base += n;
    }
  } finally {
    fs.closeSync(fd);
  }
}

// Diagnostic snapshot of the in-memory window — lets tests and
// operators verify the memory bound directly: windowLength never exceeds
// windowSize regardless of lifetime totalCount.
function getWindowStats() {
  return {
    windowSize:           WINDOW_SIZE,
    unbounded:            WINDOW_UNBOUNDED,
    windowLength:         chain.length,
    modernWindowLength:   _modernChain.length,
    chainStartOrdinal:    _chainStartOrdinal,
    modernWindowStartPos: _modernWindowStartPos,
    totalCount:           _totalCount,
  };
}

// Full modern-chain copy — ASYNC (collected via the paginated
// walk when history exceeds the window). Exact results; callers that must
// stay memory-bounded on huge chains should use getModernChainPage directly.
async function getModernChain() {
  if (WINDOW_UNBOUNDED || (_modernWindowStartPos === 0 && !_distributed())) return _modernChain.slice();
  const out = [];
  let cursor = null;
  do {
    const page = await getModernChainPage({ cursor, limit: 5000 });
    out.push(...page.entries);
    cursor = page.nextCursor;
  } while (cursor);
  return out;
}

// getModernChain()'s exact walk — same shortcut, same pages, same end condition, so the same
// entries in the same order — delivered page by page to `onPage(entries)` (which may be async and yield), so a
// caller that keeps only a digest of each entry never holds the whole parsed chain. Returns the entry count.
async function forEachModernChainPage(onPage, { limit = 5000 } = {}) {
  if (WINDOW_UNBOUNDED || (_modernWindowStartPos === 0 && !_distributed())) {
    const all = _modernChain.slice();
    for (let i = 0; i < all.length; i += limit) await onPage(all.slice(i, i + limit));
    return all.length;
  }
  let n = 0;
  let cursor = null;
  do {
    const page = await getModernChainPage({ cursor, limit });
    n += page.entries.length;
    await onPage(page.entries);
    cursor = page.nextCursor;
  } while (cursor);
  return n;
}

// Modern entries from startIndex onward — ASYNC. Window-served
// whenever the slice begins inside the window (the incremental verifier's
// steady state); durable page-walk when the caller's watermark has fallen
// behind the window.
async function getModernChainSlice(startIndex) {
  const from = Number.isInteger(startIndex) && startIndex >= 0 ? startIndex : 0;
  if (WINDOW_UNBOUNDED || from >= _modernWindowStartPos) {
    return _modernChain.slice(Math.max(0, from - _modernWindowStartPos));
  }
  const out = [];
  let cursor = { m: from };
  do {
    const page = await getModernChainPage({ cursor, limit: 5000 });
    out.push(...page.entries);
    cursor = page.nextCursor;
  } while (cursor);
  return out;
}

// ── Append ────────────────────────────────────────────────────────────────────
//
// append() is asynchronous (returns a Promise) so its durable disk I/O never
// blocks Node's single event loop the way the old fully-synchronous
// implementation did. Every call is serialized through _writeChain — a
// module-level FIFO promise chain — so that:
//
//   - ordering is exact: task N+1's body never starts until task N's entire
//     async function (including every await) has settled, reproducing the
//     ordering guarantee the old sync implementation got "for free" from
//     blocking the whole process;
//   - a failed write never advances _tailHash or the dedup/replay indexes
//     (chain.push/_indexEntry only run after a successful durable write,
//     exactly as before) — the next queued entry correctly chains off the
//     last entry actually committed, matching the old throw-and-move-on
//     behavior;
//   - the only thing that serializes is the audit write itself — unrelated
//     concurrent request work (CPU-bound policy evaluation, LLM provider
//     calls, JSON parsing, etc.) is free to run on the event loop while any
//     one entry's fsync is in flight on the libuv threadpool.
//
// See drainPendingWrites() for graceful-shutdown draining of this queue.

let _writeChain = Promise.resolve();

// audit schema v7: the two identities inside hashed
// objects — consentProvenance.subject and callerContext.callerId — are replaced by their subject pseudonym
// (src/core/dsr/subjectPseudonym.js, ap1:HMAC(K_subject, tenant ‖ 0x00 ‖ actorId)) BEFORE the entry is built, so no raw
// identifier ever reaches a hashed v7 field. No new cache (R-15): one key lookup per identity per append. Fail-closed
// (R-14): when PostgreSQL is not enabled the append is refused with a non-retryable `subject_pseudonym_unavailable`
// error — never a silent raw-identity or v6 fallback. A transient PostgreSQL error keeps its own message and is retried
// by appendMandatory() like any other transient persistence failure. Values that already are pseudonyms pass unchanged.
function _identityToPseudonymize(fields) {
  const cp = fields && fields.consentProvenance;
  const cc = fields && fields.callerContext;
  const cpSubject = cp && typeof cp === 'object' && typeof cp.subject === 'string' && cp.subject && !subjectPseudonym.isPseudonym(cp.subject);
  const ccCaller  = cc && typeof cc === 'object' && typeof cc.callerId === 'string' && cc.callerId && !subjectPseudonym.isPseudonym(cc.callerId);
  return (cpSubject || ccCaller) ? { cpSubject, ccCaller } : null;
}

async function _pseudonymizeIdentities(fields, need) {
  const tenantId = fields.tenantId ?? null;
  const out = { ...fields };
  try {
    if (need.cpSubject) out.consentProvenance = { ...fields.consentProvenance, subject: await subjectPseudonym.pseudonymFor(tenantId, fields.consentProvenance.subject) };
    if (need.ccCaller)  out.callerContext     = { ...fields.callerContext, callerId: await subjectPseudonym.pseudonymFor(tenantId, fields.callerContext.callerId) };
  } catch (err) {
    if (err && err.code === 'SUBJECT_PSEUDONYM_UNAVAILABLE') {
      const e = new Error(`subject_pseudonym_unavailable: v7 audit entries require the subject pseudonym (${err.message})`);
      e.code = 'SUBJECT_PSEUDONYM_UNAVAILABLE';
      e.cause = err;
      throw e;
    }
    throw err;
  }
  return out;
}

function append(fields) {
  if (FOLLOWER) return Promise.reject(new Error('invalid_follower_read_only: the verifier worker follows the audit log and never writes it'));
  // / F6-N2: refuse U+0000 / lone surrogates BEFORE anything is persisted — including the subject-pseudonym key
  // the step below would create (entryBuilder.normalizeFields applies the same rule again on every path).
  const unrepresentable = entryBuilder.unrepresentableTextPath(fields);
  if (unrepresentable) return Promise.reject(entryBuilder.unrepresentableTextError(unrepresentable));
  const need = _identityToPseudonymize(fields);
  if (_ST.ON) return _appendStageTimed(fields, need);
  if (need) return _pseudonymizeIdentities(fields, need).then(_enqueueAppend);
  return _enqueueAppend(fields);
}

// closure diagnostic (bench only, QODIQA_BENCH_STAGE_TIMING=true): the same two steps as append() above, timed as
// S33p (pseudonym lookup) and S33f (enqueue -> own entry durable) in the caller's request record.
async function _appendStageTimed(fields, need) {
  let f = fields;
  if (need) {
    const t = _ST.start();
    try { f = await _pseudonymizeIdentities(fields, need); } finally { _ST.end('S33p', t); }
  }
  const t2 = _ST.start();
  try { return await _enqueueAppend(f); } finally { _ST.end('S33f', t2); }
}

function _enqueueAppend(fields) {
  if (GROUP_COMMIT) {
    return new Promise((resolve, reject) => {
      _pending.push({ fields, resolve, reject, enqueuedNs: process.hrtime.bigint() });
      _kickFlusher();
    });
  }
  const task = _writeChain.then(() => _appendOne(fields));
  // Keep the chain alive regardless of this task's outcome — a rejection here
  // must not stop subsequent queued appends from running. The real
  // resolution/rejection is still observed by the caller via `task`.
  _writeChain = task.catch(() => {});
  return task;
}

// Resolves once every append enqueued so far has settled (committed or
// failed). Used by graceful shutdown to confirm no audit write is still
// in flight before the process exits.
function drainPendingWrites() {
  if (GROUP_COMMIT) return (async () => { while (_flushLoop) await _flushLoop; await _walRelease_(); })();
  return _writeChain;
}

// ── group commit: the flusher ─────────────────────────────────────────────
let _pending = [];
let _flushLoop = null;

// ── S33: the reused WAL file (WAL_REUSE only) ──────────────────────────────
// _walFh: the held handle ('w+': created empty on first use after boot recovery, which always leaves no WAL behind).
// _walDirty: the file may hold bytes from a committed batch whose post-commit truncate failed — truncated (and the
// failure surfaced through the batch) before the next write, so a write at offset 0 never lands on stale bytes.
// _walRelease: an in-progress release (drain), awaited before the next open so close/unlink never race a reopen.
let _walFh = null;
let _walDirty = false;
let _walRelease = null;

async function _walOpen() {
  if (_walRelease) await _walRelease;
  if (!_walFh) { _walFh = await fsp.open(WAL_PATH, 'w+'); _walDirty = false; }
  return _walFh;
}

// Step 1 of a batch: the whole batch durable in the WAL before the log is touched.
async function _walWriteDurable(data) {
  if (!WAL_REUSE) {
    await fsp.writeFile(WAL_PATH, data, 'utf8');
    await _fsyncAsync(WAL_PATH);
    return;
  }
  const fh = await _walOpen();
  if (_walDirty) { await fh.truncate(0); _walDirty = false; }
  const buf = Buffer.from(data, 'utf8');
  let off = 0;
  while (off < buf.length) {
    const { bytesWritten } = await fh.write(buf, off, buf.length - off, off);
    off += bytesWritten;
  }
  await fh.sync();
}

// Step 5 of a batch (after the log fsync and the checksum): the WAL is no longer needed. Not fsynced — exactly like
// the unlink it replaces (a directory entry cannot be fsynced on Windows; documented residual): a WAL that
// reappears after power loss holds only this committed batch, which recovery counts as already committed (k = all).
async function _walInvalidateCommitted() {
  if (!WAL_REUSE) { try { await fsp.unlink(WAL_PATH); } catch {} return; }
  if (!_walFh) return;
  try { await _walFh.truncate(0); } catch { _walDirty = true; }
}

// Graceful drain: close the handle and remove the WAL only if it is EMPTY (a non-empty one is left for recovery).
async function _walRelease_() {
  if (!WAL_REUSE || !_walFh || _flushLoop || _pending.length) return;
  const fh = _walFh;
  _walFh = null;
  _walRelease = (async () => {
    try { await fh.close(); } catch { /* the unlink below decides */ }
    try { if ((await fsp.stat(WAL_PATH)).size === 0) await fsp.unlink(WAL_PATH); } catch { /* absent, or kept for recovery */ }
  })();
  try { await _walRelease; } finally { _walRelease = null; }
}

function _kickFlusher() {
  if (_flushLoop) return;
  _flushLoop = (async () => {
    try {
      while (_pending.length) await _flushBatch(_pending.splice(0, MAX_BATCH_ENTRIES));
    } finally { _flushLoop = null; }
  })();
}

// Default: a batch whose failure could not be made safe (the WAL could not be invalidated, or the log could not be
// restored) must not be reported to its callers as failed — boot recovery may still commit it. The process stops,
// fail-closed, without answering them (their outcome is then decided by recovery, exactly like a crash at point B).
let _onUnrecoverable = (invalidationErr, batchErr) => {
  _emitSafe('FATAL', 'AUDIT_BATCH_ABORT_FAILED', { error: batchErr && batchErr.message, invalidationError: invalidationErr && invalidationErr.message,
    message: 'A failed audit batch could not be invalidated; stopping so that no caller is told "failed" for an entry recovery may commit.' });
  setImmediate(() => process.exit(70));
};

async function _flushBatch(batch) {
  const metrics = require('../../../../../observability/metrics');
  try { await _ensurePgHydrated(); } catch (err) { for (const b of batch) b.reject(err); return; }

  // Validate + build in queue order, each entry chained on the previous one. A rejected entry never reaches the WAL;
  // a duplicate inside the batch is rejected exactly as it would be one flush later.
  const accepted = [];
  const seenNonce = new Set();
  const seenId = new Set();
  let tail = _tailHash;
  let bytes = 0;
  for (let i = 0; i < batch.length; i++) {
    const item = batch[i];
    try {
      _assertPolicyIdRepresentable(item.fields);
      _assertMirrorRepresentable(item.fields); // PH16-D3
      const normalized = entryBuilder.normalizeFields(item.fields);
      if (normalized.nonce && (_nonceSet.has(normalized.nonce) || seenNonce.has(normalized.nonce))) throw new Error('replay_detected: nonce already used');
      if (_byArtifactId.has(normalized.resolvedId) || seenId.has(normalized.resolvedId)) throw new Error('already_executed: artifactId already in audit log');
      const entry = entryBuilder.buildEntry(normalized, tail);
      const line = JSON.stringify(entry) + '\n';
      const len = Buffer.byteLength(line, 'utf8');
      if (accepted.length > 0 && bytes + len > MAX_BATCH_BYTES) { _pending.unshift(...batch.slice(i)); break; }
      if (normalized.nonce) seenNonce.add(normalized.nonce);
      seenId.add(normalized.resolvedId);
      accepted.push({ item, entry, line });
      bytes += len;
      tail = entry.hash;
    } catch (err) {
      metrics.auditAppendDurationSeconds.observe({ mode: 'single-node', outcome: 'failure' }, Number(process.hrtime.bigint() - item.enqueuedNs) / 1e9);
      metrics.orderingAppendTotal.inc({ mode: 'single-node', outcome: 'failure' });
      item.reject(err);
    }
  }
  if (!accepted.length) return;

  const data = accepted.map((a) => a.line).join('');
  const preLength = _fileByteLength;
  // 1. WAL — the whole batch, durable before the log is touched.
  const walT0 = process.hrtime.bigint();
  try {
    await _walWriteDurable(data);
  } catch (err) { await _abortBatch(accepted, err, preLength, false); return; }
  finally { metrics.auditWalFsyncDurationSeconds.observe({}, Number(process.hrtime.bigint() - walT0) / 1e9); }

  // 2-4. Log append + fsync, then the checksum for the state AFTER the last entry.
  let n = 0; let allow = 0; let block = 0; let replay = 0;
  for (const a of accepted) {
    n++;
    if (a.entry.decision === 'ALLOW') allow++; else if (a.entry.decision === 'BLOCK') block++;
    const r = a.entry.executionContext?.replayOf; if (typeof r === 'string' && r) replay++;
  }
  const last = accepted[accepted.length - 1].entry;
  try {
    await fsp.appendFile(LOG_PATH, data, 'utf8');
    const fsT0 = process.hrtime.bigint();
    try { await _fsyncAsync(LOG_PATH); } finally { metrics.auditFsyncDurationSeconds.observe({}, Number(process.hrtime.bigint() - fsT0) / 1e9); }
    const csT0 = process.hrtime.bigint();
    try {
    await checksumAnchor.saveChecksumFileAsync(CHECKSUM_PATH, _totalCount + n, last.hash, {
      totalCount: _totalCount + n, modernCount: _modernCount + n, allowCount: _allowCount + allow, blockCount: _blockCount + block,
      replayCount: _replayCount + replay, headHash: _headHash ?? accepted[0].entry.hash, byteLength: preLength + bytes,
    });
    } finally { metrics.auditChecksumPersistDurationSeconds.observe({}, Number(process.hrtime.bigint() - csT0) / 1e9); }
  } catch (err) { await _abortBatch(accepted, err, preLength, true); return; }

  // 5. Durable: WAL no longer needed. 6. Commit in memory, in order. Then PG mirror (post-commit, in chain order).
  _fileByteLength = preLength + bytes;
  await _walInvalidateCommitted();
  checksumAnchor.saveChecksumPg(_totalCount + n, last.hash).catch(() => {});
  for (const a of accepted) { _countEntry(a.entry); _pushWindow(a.entry); }
  for (const a of accepted) _enqueueMirrorWrite(a.entry);
  _groupStats.batches++; _groupStats.entries += n; _groupStats.maxBatch = Math.max(_groupStats.maxBatch, n);
  const now = process.hrtime.bigint();
  for (const a of accepted) {
    metrics.auditAppendDurationSeconds.observe({ mode: 'single-node', outcome: 'success' }, Number(now - a.item.enqueuedNs) / 1e9);
    metrics.orderingAppendTotal.inc({ mode: 'single-node', outcome: 'success' });
    a.item.resolve(a.entry);
  }
}

// Crash point B': a batch that fails AFTER its WAL was written. Before ANY caller is
// told, the batch is made impossible to commit later: the log is restored to its pre-batch length (any bytes of the
// batch that reached it copied to quarantine first), the pre-batch checksum is re-written, and the WAL is emptied
// and fsynced (an empty WAL is "invalidated" to recovery). Only then are the callers rejected — so a failed entry
// can never appear committed after a restart, and its retry can never appear twice.
async function _abortBatch(accepted, err, preLength, logTouched) {
  let truncated = 0;
  try {
    if (logTouched) {
      const size = fs.existsSync(LOG_PATH) ? (await fsp.stat(LOG_PATH)).size : 0;
      if (size > preLength) {
        const fh = await fsp.open(LOG_PATH, 'r');
        const buf = Buffer.alloc(size - preLength);
        try { await fh.read(buf, 0, buf.length, preLength); } finally { await fh.close(); }
        fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
        const q = path.join(QUARANTINE_DIR, `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}-failed-batch-log-tail.bin`);
        await fsp.writeFile(q, buf);
        await _fsyncAsync(q);
        await fsp.truncate(LOG_PATH, preLength);
        await _fsyncAsync(LOG_PATH);
        truncated = buf.length;
      }
      await checksumAnchor.saveChecksumFileAsync(CHECKSUM_PATH, _totalCount, _tailHash, _anchorV2());
    }
    // Invalidate the WAL: empty it and fsync (durable, and an empty WAL is "invalidated" to recovery). If that is not
    // possible — e.g. the disk is full, where even rewriting fails — remove it instead (removal needs no space). The
    // removal's directory entry cannot be fsynced on Windows; the residual window is documented in the report.
    // S33: with WAL reuse the same invalidation goes through the held handle; the removal fallback closes the
    // handle first (Windows cannot re-create a name whose open handle is delete-pending) — reopened on the next batch.
    try {
      if (WAL_REUSE && _walFh) { await _walFh.truncate(0); await _walFh.sync(); _walDirty = false; }
      else { await fsp.truncate(WAL_PATH, 0); await _fsyncAsync(WAL_PATH); }
    } catch {
      if (WAL_REUSE && _walFh) { const fh = _walFh; _walFh = null; try { await fh.close(); } catch { /* removal below */ } }
      try { await fsp.unlink(WAL_PATH); } catch (e) { if (!e || e.code !== 'ENOENT') throw e; }
    }
  } catch (invalidationErr) {
    _onUnrecoverable(invalidationErr, err);
    return;
  }
  _groupStats.aborted++; _groupStats.abortedEntries += accepted.length;
  _emitSafe('ERROR', 'AUDIT_BATCH_ABORTED', { entries: accepted.length, error: err.message, logBytesRemoved: truncated });
  const metrics = require('../../../../../observability/metrics');
  const nowNs = process.hrtime.bigint();
  for (const a of accepted) {
    metrics.auditAppendDurationSeconds.observe({ mode: 'single-node', outcome: 'failure' }, Number(nowNs - a.item.enqueuedNs) / 1e9);
    metrics.orderingAppendTotal.inc({ mode: 'single-node', outcome: 'failure' });
    a.item.reject(err);
  }
}

/**
 * follower only: read the lines the main thread has COMMITTED since the last read (up to the last complete line),
 * validated exactly as boot validates a suffix (linkage + canonical hash), into this follower's counters and window.
 * If the log is now SHORTER than what was read (a failed batch's bytes removed by the main thread — crash point B'),
 * throws AUDIT_FOLLOWER_LOG_SHRANK: the worker restarts and reloads rather than follow a history that was undone.
 * @returns {number} entries added
 */
function refreshFromDisk() {
  if (!FOLLOWER) return 0;
  const limit = _stableLength();
  if (limit < _fileByteLength) throw new Error(`AUDIT_FOLLOWER_LOG_SHRANK: log is ${limit} bytes, the follower had read ${_fileByteLength}`);
  if (limit === _fileByteLength) return 0;
  const from = _fileByteLength;
  _readLimit = limit;
  let lastModernHash = _tailHash === null ? 'GENESIS' : _tailHash;
  let added = 0;
  const followerTracker = _createLifecycleTracker({ lifecycleComplete: false });   // v7: incremental = bounded
  _streamLinesSync(LOG_PATH, (line) => {
    const parsed = _parseLineOrThrow(line, _totalCount);
    _validateChainEntry(parsed, lastModernHash);
    _lifecycleStepOrThrow(followerTracker, parsed, 'follower refresh');
    const frozen = Object.freeze(parsed);
    _countEntry(frozen);
    _pushWindow(frozen);
    if (!frozen.legacy) lastModernHash = frozen.hash;
    added++;
  }, from);
  _fileByteLength = limit;
  return added;
}
function isFollower() { return FOLLOWER; }

/**
 * the serving process's committed state at ONE point in time — counters and _fileByteLength change in the same
 * synchronous block (group commit), so this is consistent. The verifier worker scans exactly this byte prefix.
 */
function memorySnapshot() { return { totalCount: _totalCount, tailHash: _tailHash, modernCount: _modernCount, byteLength: _fileByteLength }; }

/** what the boot report shows about the audit store (group commit on/off, and any boot recovery action). */
function getStorageReport() {
  return { groupCommit: GROUP_COMMIT, rollbackSwitch: 'QODIQA_AUDIT_GROUP_COMMIT=false', maxBatchEntries: MAX_BATCH_ENTRIES,
    maxBatchBytes: MAX_BATCH_BYTES, walReuse: WAL_REUSE, walReuseRollbackSwitch: 'QODIQA_AUDIT_WAL_REUSE=false',
    recovery: { ..._recoveryReport } };
}
function groupCommitStats() { return { ..._groupStats, pending: _pending.length, flushing: !!_flushLoop }; }
function _setUnrecoverableHandlerForTests(fn) { _onUnrecoverable = fn; }

// an audit decision must never commit if its
// policyDecision.policyId cannot subsequently be represented by the evidence
// ledger — evidence_chain_records.policy_id is VARCHAR(256) (migration 010),
// while the audit layer stores policyDecision as unbounded JSONB, and a longer
// id failed the post-commit evidence write with a non-retryable 22001, leaving
// the committed audit row permanently without evidence. PostgreSQL counts
// characters (code points), so the bound does too. The value is never
// truncated or transformed; the append is rejected, before any write, with the
// same deterministic `invalid_*` class entryBuilder uses (not retried by
// appendMandatory). Every policy store bounds ids to 64 characters, so no
// product path reaches this — it is defense in depth for the audit boundary.
const EVIDENCE_POLICY_ID_MAX_CHARS = 256;

// PH16-D3: the PostgreSQL mirror's bounded columns (audit_chain: artifact_id/tenant_id
// VARCHAR(128), nonce/public_key_id VARCHAR(256), input/request/policy_hash VARCHAR(64), decision VARCHAR(8)). An entry
// the authoritative file chain accepted but the mirror cannot store was dropped from the mirror non-retryably, and every
// later entry then waited forever for that missing parent — a permanent mirror stall. Such an entry is now refused
// before anything is persisted (same contract as the policyId bound below). Lengths are measured on the mirror
// PROJECTION, i.e. on what PostgreSQL would actually have to store.
const MIRROR_FIELD_BOUNDS = Object.freeze({ artifactId: 128, tenantId: 128, nonce: 256, publicKeyId: 256, inputHash: 64, requestHash: 64, policyHash: 64, decision: 8 });
function _assertMirrorRepresentable(fields) {
  if (!fields) return;
  const { encodeString } = require('../../../../../infra/postgres/mirrorProjection');
  for (const [f, max] of Object.entries(MIRROR_FIELD_BOUNDS)) {
    const v = fields[f];
    if (typeof v === 'string' && encodeString(v).length > max) {
      throw new Error(`invalid_${f}: exceeds the audit mirror column limit of ${max} characters`);
    }
  }
}

function _assertPolicyIdRepresentable(fields) {
  const policyId = fields && fields.policyDecision && fields.policyDecision.policyId;
  if (typeof policyId === 'string' && [...policyId].length > EVIDENCE_POLICY_ID_MAX_CHARS) {
    throw new Error(`invalid_policyDecision: policyId exceeds the evidence ledger limit of ${EVIDENCE_POLICY_ID_MAX_CHARS} characters`);
  }
}


// ── serialized single-node PG mirror writer ───────────────────────
// One writer, FIFO, in chain order: each mirror INSERT starts only after the
// previous one has settled. persistEntry() never throws (a retryable failure is
// durably queued by the Persistence Recovery Queue, which falls back to its
// file journal when PG itself is down), so one failed write never stalls the
// writer. drainMirrorWriter() resolves once everything enqueued so far has
// settled (graceful shutdown, tests).
let _mirrorDepth = 0;
// The depth gauge is updated fail-safe: this runs AFTER the entry is durably in
// audit.log, so a metrics fault must never turn a committed append into a
// reported failure.
function _setMirrorDepthGauge() {
  try { require('../../../../../observability/metrics').auditMirrorWriterDepth.set({}, _mirrorDepth); } catch { /* metrics must never affect the audit write */ }
}
// 2026-10-06 — bounded mirror backlog. Every pending mirror write holds its entry in this promise chain, so a
// PostgreSQL that is slow-but-up (not down: then the recovery queue/journal takes over) made the backlog — and the heap —
// grow without limit (measured: 58,756 entries behind and ~15 MB/30 s of post-GC heap growth on a slow test database).
// Above QODIQA_AUDIT_MIRROR_MAX_DEPTH pending writes, back-pressure ENGAGES: admission (src/api/admission.js) refuses
// new /sign and /ai/chat requests with 503 SERVER_OVERLOADED (cause audit_backlog — nothing written, no provider call,
// nonce unconsumed) and GET /ready reports not-ready, until the backlog drains to half the limit (hysteresis). The
// authoritative file chain is unaffected; this only bounds the in-memory mirror queue. Single-node mirror writer only.
const _mirrorLatch = require('../../../mirrorBackpressure').createLatch();
function _updateMirrorBackpressure() {
  const t = _mirrorLatch.update(_mirrorDepth);
  if (!t) return;
  _emitSafe(t === 'engaged' ? 'WARN' : 'INFO', t === 'engaged' ? 'AUDIT_MIRROR_BACKPRESSURE_ENGAGED' : 'AUDIT_MIRROR_BACKPRESSURE_RELEASED',
    { depth: _mirrorDepth, maxDepth: _mirrorLatch.maxDepth, resumeDepth: _mirrorLatch.resumeDepth });
}
// phase 9: the writer drains the queue in BATCHES of up to QODIQA_AUDIT_MIRROR_BATCH entries
// (default 64; 1 = the previous strictly per-entry behaviour). One drain loop, FIFO, so chain order is preserved; a batch
// is one guard query + one mirror transaction + one evidence transaction per same-tenant run
// (pg-audit-backend.persistEntries), with an automatic per-entry fallback on any failure. Batches form naturally under
// load (entries accumulate while a batch is in flight); at low load a batch is a single entry, so latency is unchanged.
// Measured on the disposable container: ~125 mirrored entries/s per-entry vs the batched figure in
//
const MIRROR_BATCH = (() => { const v = Number(process.env.QODIQA_AUDIT_MIRROR_BATCH); return Number.isInteger(v) && v >= 1 && v <= 1000 ? v : 64; })();
const _mirrorQueue = [];
let _mirrorRunning = null;
async function _runMirrorWriter() {
  try {
    await null; // start on a later microtask so a burst of synchronous appends lands in one batch
    while (_mirrorQueue.length) {
      const batch = _mirrorQueue.splice(0, MIRROR_BATCH);
      try {
        if (batch.length > 1 && typeof pgAuditBackend.persistEntries === 'function') await pgAuditBackend.persistEntries(batch);
        else for (const e of batch) await pgAuditBackend.persistEntry(e);
      } catch (err) {
        // persistEntry/persistEntries never throw by contract; a defect must not stop the writer — but it must never be
        // silent either (PH16-O1): the batch's entries are in the authoritative file chain, and the mirror-count
        // reconciler / gap tooling will flag the missing mirror rows; this event names them.
        _emitSafe('ERROR', 'AUDIT_MIRROR_WRITER_BATCH_FAILED', { entries: batch.length, firstHash: batch[0] && batch[0].hash,
          lastHash: batch[batch.length - 1] && batch[batch.length - 1].hash, error: err && err.message });
      }
      _mirrorDepth -= batch.length;
      _mirrorSettledTotal += batch.length;
      _settleMirrorWaiters();
      _setMirrorDepthGauge();
      _updateMirrorBackpressure();
    }
  } finally {
    _mirrorRunning = null;
  }
}
// GA-CKPT-RATE: BOUNDED drain for the checkpoint writer. drainMirrorWriter() resolves only once the queue is
// EMPTY, including entries enqueued while it waits — under sustained load that never happens, so a checkpoint run that
// awaited it stalled (single-flight), every later tick was skipped, and the uncovered tail outgrew the boot check's
// 2 x QODIQA_AUDIT_CHECKPOINT_EVERY bound. drainMirrorWriterThrough() waits only for the entries enqueued up to the call.
let _mirrorEnqueuedTotal = 0;
let _mirrorSettledTotal = 0;
const _mirrorThroughWaiters = [];
function _settleMirrorWaiters() {
  for (let i = _mirrorThroughWaiters.length - 1; i >= 0; i--) {
    if (_mirrorThroughWaiters[i].target <= _mirrorSettledTotal) { _mirrorThroughWaiters[i].resolve(); _mirrorThroughWaiters.splice(i, 1); }
  }
}
/** Resolves once every mirror write enqueued BEFORE this call has settled (later ones are not waited for). */
function drainMirrorWriterThrough() {
  const target = _mirrorEnqueuedTotal;
  if (_mirrorSettledTotal >= target) return Promise.resolve();
  return new Promise((resolve) => { _mirrorThroughWaiters.push({ target, resolve }); });
}
/** Lifetime counters of the single-node mirror writer: entries enqueued and settled (handed to PG or its recovery path). */
function mirrorWriterCounters() { return { enqueued: _mirrorEnqueuedTotal, settled: _mirrorSettledTotal }; }
function _enqueueMirrorWrite(entry) {
  _mirrorQueue.push(entry);
  _mirrorEnqueuedTotal++;
  _mirrorDepth++;
  _setMirrorDepthGauge();
  _updateMirrorBackpressure();
  if (!_mirrorRunning) _mirrorRunning = _runMirrorWriter();
}
/** Resolves once every entry enqueued so far (and any enqueued while draining) has been handed to the mirror. */
function drainMirrorWriter() { return _mirrorRunning || Promise.resolve(); }
function mirrorWriterDepth() { return _mirrorDepth; }
/** True while the mirror backlog is above its bound (until it drains to half). Read by admission and GET /ready. */
function mirrorBackpressureEngaged() { return _mirrorLatch.engaged(); }
function mirrorBackpressureConfig() { return { maxDepth: _mirrorLatch.maxDepth, resumeDepth: _mirrorLatch.resumeDepth }; }

async function _appendOne(fields) {
  // REL-06: measurement only, wrapping both branches below — the ordering
  // logic itself (distributedOrdering.js, and the single-node body below) is
  // untouched.
  const metrics = require('../../../../../observability/metrics');
  const _orderingMode = ORDERING_MODE === 'distributed' ? 'distributed' : 'single-node';
  metrics.orderingInflightAppends.inc({ mode: _orderingMode });
  try {
    // before either ordering branch writes anything (distributed
    // transaction, or single-node WAL / log / PG mirror).
    _assertPolicyIdRepresentable(fields);
    _assertMirrorRepresentable(fields); // PH16-D3

    // ── Distributed mode: PostgreSQL is the ordering authority ──────────────────
    // distributedOrdering.js does its own field validation (entryBuilder,
    // shared with the single-node path below) and its own dedup/replay
    // enforcement (PG UNIQUE constraints — see that module's header comment for
    // why the in-memory _nonceSet/_byArtifactId below aren't authoritative
    // here). The local chain[]/index update after a successful append is a
    // best-effort read-path cache for this replica only; see
    // hydrateFromPgIfDistributed()'s comment for what it does and doesn't
    // guarantee.
    if (ORDERING_MODE === 'distributed') {
      const _distAppendStartNs = process.hrtime.bigint();
      let _distOutcome = 'failure';
      try {
        const entry = await require('../../../distributedOrdering').appendEntry(fields);
        _countEntry(entry);
        _pushWindow(entry);
        // the evidence-chain record, written
        // AFTER the audit transaction above has committed and NOT awaited —
        // the same post-commit, best-effort contract as single-node's
        // persistEntry() below (retryable failure → EVIDENCE_CHAIN_SAVE queue;
        // the committed audit entry is never failed or rolled back by it).
        // typeof guard: same reason as setKeyInfoResolver's at module load
        // (test doubles of pg-audit-backend that predate this export).
        if (typeof pgAuditBackend.recordEvidenceForEntry === 'function') {
          pgAuditBackend.recordEvidenceForEntry(entry).catch(() => {});
        }
        _distOutcome = 'success';
        return entry;
      } finally {
        metrics.auditAppendDurationSeconds.observe(
          { mode: 'distributed', outcome: _distOutcome },
          Number(process.hrtime.bigint() - _distAppendStartNs) / 1e9
        );
        metrics.orderingAppendTotal.inc({ mode: 'distributed', outcome: _distOutcome });
      }
    }

    // ── Single-node mode (unchanged behavior) ────────────────────────────────────
    // #3: additive latency histograms alongside the existing
    // auditAppendRetriesTotal/auditAppendFailedTotal counters (metrics.js).
    // Timed on both success and failure — a slow failing append is exactly the
    // signal operators need, not just a successful one.
    const _appendStartNs = process.hrtime.bigint();
    let _outcome = 'failure';
    try {
      // FINDING-AUDIT-CHAIN-TENANT-GENESIS-COLLISION: must resolve before
      // _tailHash is read below — see _ensurePgHydrated()'s header comment.
      await _ensurePgHydrated();

      const normalized = entryBuilder.normalizeFields(fields);

      // O(1) nonce replay detection via _nonceSet.
      if (normalized.nonce && _nonceSet.has(normalized.nonce)) {
        throw new Error('replay_detected: nonce already used');
      }

      // O(1) duplicate detection via _byArtifactId.
      if (_byArtifactId.has(normalized.resolvedId)) {
        throw new Error('already_executed: artifactId already in audit log');
      }

      // O(1) prev-hash access via _tailHash.
      const entry = entryBuilder.buildEntry(normalized, _tailHash);

      // 1. Write-ahead log. Finding C: a WAL entry is only a valid
      // recovery record if it is guaranteed durable BEFORE the main-log append
      // it protects is attempted — otherwise a crash between this write and
      // step 2 can lose the WAL file itself (fs.writeFile's underlying write()
      // syscall returns once the OS buffer accepts the bytes, not once they
      // are on stable storage), and loadFromDisk()'s WAL-recovery branch would
      // have nothing to replay even though step 2 may have partially landed.
      // fsync-ing the WAL here — not just LOG_PATH in step 3 below — closes
      // that gap and is the textbook write-ahead-logging ordering guarantee:
      // the log record precedes, and outlives, the data write it describes.
      const _walFsyncStartNs = process.hrtime.bigint();
      try {
        await fsp.writeFile(WAL_PATH, JSON.stringify(entry) + '\n', 'utf8');
        await _fsyncAsync(WAL_PATH);
      } finally {
        metrics.auditWalFsyncDurationSeconds.observe({}, Number(process.hrtime.bigint() - _walFsyncStartNs) / 1e9);
      }

      // 2. Append-only write.
      const _line = JSON.stringify(entry) + '\n';
      await fsp.appendFile(LOG_PATH, _line, 'utf8');
      _fileByteLength += Buffer.byteLength(_line, 'utf8');

      // 3. fsync.
      const _fsyncStartNs = process.hrtime.bigint();
      try {
        await _fsyncAsync(LOG_PATH);
      } finally {
        metrics.auditFsyncDurationSeconds.observe({}, Number(process.hrtime.bigint() - _fsyncStartNs) / 1e9);
      }

      // 4. Update checksum BEFORE clearing WAL (crash-safe ordering).
      const _checksumStartNs = process.hrtime.bigint();
      try {
        // v2 reflects the state INCLUDING this entry — the write happens
        // before the in-memory commit (step 6), preserving the historical
        // crash-safe ordering, so the counters are projected forward here.
        const _replayOf = entry.executionContext?.replayOf;
        await _saveChecksumAsync(_totalCount + 1, entry.hash, {
          totalCount:  _totalCount + 1,
          modernCount: _modernCount + 1,
          allowCount:  _allowCount + (entry.decision === 'ALLOW' ? 1 : 0),
          blockCount:  _blockCount + (entry.decision === 'BLOCK' ? 1 : 0),
          replayCount: _replayCount + (typeof _replayOf === 'string' && _replayOf ? 1 : 0),
          headHash:    _headHash ?? entry.hash,
          byteLength:  _fileByteLength, // already includes this entry's line (step 2)
        });
      } finally {
        metrics.auditChecksumPersistDurationSeconds.observe({}, Number(process.hrtime.bigint() - _checksumStartNs) / 1e9);
      }

      // 5. WAL committed.
      try { await fsp.unlink(WAL_PATH); } catch {}

      // 6. Commit: lifetime counters + window (with eviction past the bound).
      _countEntry(entry);
      _pushWindow(entry);

      // Dual-write to PostgreSQL. Not best-effort-and-forgotten: a retryable
      // failure is durably queued via the Persistence Recovery Queue so it is
      // retried and, if still failing, surfaced in the DLQ rather than lost.
      // The file-based chain above remains the sole MANDATORY store in
      // single-node mode; this dual-write and the evidence chain record it
      // triggers are the recoverable-but-non-blocking secondary store (
      // distributed mode above is where PG itself is mandatory).
      //
      // through ONE serialized writer, in chain order.
      // this was fired per entry without awaiting, so concurrent INSERTs drew
      // seq = nextval() out of chain order (auditor: 7 breaks / 500 appends).
      // The response still never waits on PG; the writer runs behind it. The
      // INSERT itself is also parent-guarded (pg-audit-backend.js
      // insertMirrorRow), so replays can never land out of order either.
      _enqueueMirrorWrite(entry);

      _outcome = 'success';
      return entry;
    } finally {
      metrics.auditAppendDurationSeconds.observe(
        { mode: 'single-node', outcome: _outcome },
        Number(process.hrtime.bigint() - _appendStartNs) / 1e9
      );
      metrics.orderingAppendTotal.inc({ mode: 'single-node', outcome: _outcome });
    }
  } finally {
    metrics.orderingInflightAppends.dec({ mode: _orderingMode });
  }
}

// ── Mandatory append with bounded retry ───────────────────────────────────────
//
// append() above throws synchronously and immediately on any failure — no
// retry, by design, so that validation/duplicate/replay errors (invalid_*,
// already_executed, replay_detected) fail fast with zero added latency.
//
// appendMandatory() wraps it for call sites where the audit entry is the
// platform's REQUIRED evidence record for a decision that is about to be
// reported to the caller (e.g. the ALLOW/EXECUTE path in aiChat.js). It
// retries a small, bounded number of times ONLY for failures that look like
// transient filesystem/system conditions (disk momentarily busy, EMFILE,
// ENOSPC, EIO, etc.) — never for validation/duplicate/replay errors, which
// are deterministic and retrying them would just waste the retry budget.
//
// If every attempt fails, throws an AUDIT_PERSISTENCE_FAILED error (with the
// last underlying error preserved as `.cause`) instead of returning quietly.
// Callers on the request-blocking path MUST let this propagate — a request
// must never be reported as successful when its mandatory audit evidence
// could not be durably recorded. Callers on a path where the response has
// already been sent (streaming) or where the outcome is already a block
// (BLOCK decisions) cannot "undo" that fact, but MUST still treat this as a
// CRITICAL, not routine, failure — see aiChat.js and streamEnforcer.js.

const _NON_RETRYABLE_AUDIT_PREFIXES = ['invalid_', 'already_executed', 'replay_detected', 'subject_pseudonym_unavailable'];

function _isNonRetryableAuditError(err) {
  const msg = (err && err.message) || '';
  return _NON_RETRYABLE_AUDIT_PREFIXES.some(p => msg.startsWith(p));
}

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const AUDIT_APPEND_MAX_RETRIES   = parseInt(process.env.QODIQA_AUDIT_APPEND_MAX_RETRIES, 10) || 2;
const AUDIT_APPEND_RETRY_DELAY_MS = parseInt(process.env.QODIQA_AUDIT_APPEND_RETRY_DELAY_MS, 10) || 50;

/**
 * @param {object} fields         Same shape as append().
 * @param {object} [opts]
 * @param {number} [opts.maxRetries]   Default: QODIQA_AUDIT_APPEND_MAX_RETRIES env or 2.
 * @param {number} [opts.retryDelayMs] Default: QODIQA_AUDIT_APPEND_RETRY_DELAY_MS env or 50.
 * @param {string} [opts.stage]        Label for metrics/logging: 'ALLOW' | 'BLOCK' | 'STREAM'.
 * @returns {Promise<object>} the committed entry (same shape append() returns).
 * @throws {Error} the original error immediately for non-retryable (validation/
 *                 duplicate/replay) failures; an AUDIT_PERSISTENCE_FAILED error
 *                 (code: 'AUDIT_PERSISTENCE_FAILED', cause: <original error>)
 *                 after all retries are exhausted for retryable failures.
 */
async function appendMandatory(fields, opts = {}) {
  const maxRetries   = Number.isFinite(opts.maxRetries)   ? opts.maxRetries   : AUDIT_APPEND_MAX_RETRIES;
  const retryDelayMs = Number.isFinite(opts.retryDelayMs) ? opts.retryDelayMs : AUDIT_APPEND_RETRY_DELAY_MS;
  const stage        = opts.stage || 'UNKNOWN';
  const metrics      = require('../../../../../observability/metrics');

  let lastErr = null;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await append(fields);
    } catch (err) {
      lastErr = err;
      if (_isNonRetryableAuditError(err)) throw err;
      if (attempt < maxRetries) {
        metrics.auditAppendRetriesTotal.inc({ stage });
        await _sleep(retryDelayMs);
      }
    }
  }

  metrics.auditAppendFailedTotal.inc({ stage });

  // #9: ENOSPC is bucketed generically into auditAppendFailedTotal
  // above like every other retryable failure — emit a distinct, specific
  // event too, so alerting can tell "disk full" (actionable, one clear
  // remediation) apart from generic persistence failure.
  if (lastErr && lastErr.code === 'ENOSPC') {
    try { metrics.auditDiskFullTotal.inc({ stage }); } catch { /* metrics are best-effort */ }
    try {
      require('../../../../../../services/logger').emit('CRITICAL', 'AUDIT_DISK_FULL', {
        stage, attempts: maxRetries + 1,
      });
    } catch { /* logging must never mask the original failure */ }
  }

  const failure = new Error(`AUDIT_PERSISTENCE_FAILED: ${lastErr.message}`);
  failure.code  = 'AUDIT_PERSISTENCE_FAILED';
  failure.cause = lastErr;
  failure.attempts = maxRetries + 1;
  throw failure;
}

// ── Chain walk (integrity verification) ──────────────────────────────────────
//
// Full O(n) walk — inherently required for complete hash-chain verification.
// Secondary per-entry operations are all O(1) (Map lookups replace array scans).
//
// `startPrevHash` (default 'GENESIS') lets a caller walk a SLICE of the chain
// (e.g. only entries appended since a previously-verified watermark) by
// passing the hash the slice's first entry is expected to chain off of,
// instead of always assuming the slice starts at genesis — this is what
// makes O(delta) incremental verification possible (see
// src/core/audit/verifier/). Existing callers that omit the parameter are
// byte-for-byte unaffected.
//
// Every failure branch additionally reports offendingIndex/offendingArtifactId
// (position within the given `entries` array, not necessarily the full
// chain) and, where meaningful, expected-vs-actual hash/prevHash — additive
// fields consumed by the live verifier's forensic diagnostics. Existing
// callers that destructure only {valid, reason, entriesVerified, head, tail,
// tamperingDetected} are unaffected by the extra keys.
// the per-entry body of _walkChain, unchanged and shared by _walkChain (whole array) and
// createChainWalker (incremental, across pages) so both apply IDENTICAL checks in IDENTICAL order with the same
// cross-entry state (seenArtifactIds duplicate detection, the v7 lifecycle tracker, the prevHash linkage).
// Returns null when the entry passes (or is a legacy prefix entry), else the failure object _walkChain returns.
function _walkStep(st, entry, i) {

      if (!entry || typeof entry !== 'object') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: null };
      }
      if (typeof entry.timestamp  !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId ?? null };
      }
      if (typeof entry.artifactId !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: null };
      }

      // a stored `legacy` key is forged (see _hasStoredLegacyKey); the derived
      // flag is only valid in the pre-hash prefix, before any hash-chained entry.
      if (_hasStoredLegacyKey(entry)) {
        return { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'STORED_LEGACY_FLAG', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (entry.legacy) {
        if (st.lastModernHash !== 'GENESIS') {
          return { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'LEGACY_AFTER_MODERN', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
        }
        return null;
      }

      if (st.seenArtifactIds.has(entry.artifactId)) {
        return { valid: false, reason: 'AUDIT_DUPLICATE_ENTRY', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      st.seenArtifactIds.add(entry.artifactId);

      if (typeof entry.prevHash  !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.hash      !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.inputHash !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.decision  !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.signature !== 'string' || !entry.signature) {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }

      if (entry.prevHash !== st.lastModernHash) {
        return {
          valid: false, reason: 'AUDIT_CHAIN_BROKEN', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false,
          offendingIndex: i, offendingArtifactId: entry.artifactId,
          expectedPrevHash: st.lastModernHash, actualPrevHash: entry.prevHash,
        };
      }

      if (typeof entry.canonical !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (!_verifyCanonicalHash(entry)) {
        const shape = _v7IntegrityDetail(entry);
        return {
          valid: false, reason: 'AUDIT_CHAIN_TAMPERED', ...(shape ? { detail: shape } : {}), entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: true,
          offendingIndex: i, offendingArtifactId: entry.artifactId,
          expectedHash: _expectedHashFor(entry), actualHash: entry.hash,
        };
      }
      const lifecycle = st.tracker.step(entry);   // v7 (R-2 / R-17 / C-26)
      if (lifecycle) {
        return { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: lifecycle.detail, entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }

      if (st.head === null) st.head = entry.hash;
      st.tail = entry.hash;
      st.lastModernHash = entry.hash;
      st.entriesVerified++;
      return null;
}

function _createWalkState(startPrevHash) {
  return { lastModernHash: startPrevHash, head: null, tail: null, entriesVerified: 0, seenArtifactIds: new Set(),
    // v7 (C-26): lifecycle-complete only for a walk that starts at GENESIS.
    tracker: _createLifecycleTracker({ lifecycleComplete: startPrevHash === 'GENESIS' }) };
}

function _walkChain(entries, startPrevHash = 'GENESIS') {
  try {
    if (!Array.isArray(entries)) {
      return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
    }
    const st = _createWalkState(startPrevHash);
    for (let i = 0; i < entries.length; i++) {
      const failure = _walkStep(st, entries[i], i);
      if (failure) return failure;
    }
    // v7 (C-26): `lifecycleComplete` says whether MISSING_INTENT could be decided; `warnings` are non-fatal.
    return { valid: true, reason: null, entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, lifecycleComplete: st.tracker.lifecycleComplete, warnings: st.tracker.finish() };
  } catch {
    return { valid: false, reason: 'AUDIT_CHAIN_BROKEN', entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
  }
}

// an incremental _walkChain — push(entry) one at a time (e.g. page by page), same verdicts as _walkChain on
// the concatenated sequence, memory O(page) plus the duplicate-detection set (~one artifactId per verified entry).
// push() returns the failure object (and every later push returns it again) or null; result() is _walkChain's result.
function createChainWalker(startPrevHash = 'GENESIS') {
  const st = _createWalkState(startPrevHash);
  let index = 0; let failure = null;
  return {
    push(entry) {
      if (failure) return failure;
      try { failure = _walkStep(st, entry, index++); } catch { failure = { valid: false, reason: 'AUDIT_CHAIN_BROKEN', entriesVerified: 0, head: null, tail: null, tamperingDetected: false }; }
      return failure;
    },
    result() {
      if (failure) return failure;
      return { valid: true, reason: null, entriesVerified: st.entriesVerified, head: st.head, tail: st.tail, tamperingDetected: false, lifecycleComplete: st.tracker.lifecycleComplete, warnings: st.tracker.finish() };
    },
  };
}

// ── Chunked (non-blocking) chain walk — #129 ────────────────────
//
// _walkChain above is a plain synchronous loop: for a large chain it runs
// start-to-finish in one tick, monopolizing the event loop for the entire
// walk. This async twin
// performs the IDENTICAL per-entry checks in the IDENTICAL order (kept as a
// literal copy of _walkChain's loop body, not a re-implementation, so there
// is zero risk of the two drifting apart) but yields to the event loop every
// `yieldEvery` entries via setImmediate, letting concurrent request handling
// interleave between chunks.
//
// `entries.length` is snapshotted once as `targetLength` before the first
// await point. _walkChain's tight loop is implicitly atomic (nothing can
// mutate `entries` mid-call in single-threaded JS), so it always sees a
// stable length; once this walk yields, that's no longer guaranteed if
// `entries` is the live, still-growing `chain` array. Snapshotting
// reproduces exactly what a synchronous walk invoked at the same instant
// would have seen — anything appended after the walk starts is simply
// picked up by the next verification pass, not silently skipped forever.
const CHAIN_WALK_YIELD_EVERY = (() => {
  const v = parseInt(process.env.QODIQA_AUDIT_CHAIN_WALK_YIELD_EVERY, 10);
  return Number.isFinite(v) && v > 0 ? v : 200;
})();

async function _walkChainChunked(entries, startPrevHash = 'GENESIS', { yieldEvery = CHAIN_WALK_YIELD_EVERY } = {}) {
  try {
    if (!Array.isArray(entries)) {
      return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
    }

    const targetLength = entries.length;
    let lastModernHash  = startPrevHash;
    let head            = null;
    let tail             = null;
    let entriesVerified = 0;
    const seenArtifactIds = new Set();
    // v7 (C-26): lifecycle-complete only for a walk that starts at GENESIS.
    const tracker = _createLifecycleTracker({ lifecycleComplete: startPrevHash === 'GENESIS' });

    for (let i = 0; i < targetLength; i++) {
      if (yieldEvery > 0 && i > 0 && i % yieldEvery === 0) {
        await require('../../../verifierPacer').pace();
      }

      const entry = entries[i];

      if (!entry || typeof entry !== 'object') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: null };
      }
      if (typeof entry.timestamp  !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId ?? null };
      }
      if (typeof entry.artifactId !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: null };
      }

      // a stored `legacy` key is forged (see _hasStoredLegacyKey); the derived
      // flag is only valid in the pre-hash prefix, before any hash-chained entry.
      if (_hasStoredLegacyKey(entry)) {
        return { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'STORED_LEGACY_FLAG', entriesVerified, head, tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (entry.legacy) {
        if (lastModernHash !== 'GENESIS') {
          return { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: 'LEGACY_AFTER_MODERN', entriesVerified, head, tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
        }
        continue;
      }

      if (seenArtifactIds.has(entry.artifactId)) {
        return { valid: false, reason: 'AUDIT_DUPLICATE_ENTRY', entriesVerified, head, tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      seenArtifactIds.add(entry.artifactId);

      if (typeof entry.prevHash  !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.hash      !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.inputHash !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.decision  !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (typeof entry.signature !== 'string' || !entry.signature) {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }

      if (entry.prevHash !== lastModernHash) {
        return {
          valid: false, reason: 'AUDIT_CHAIN_BROKEN', entriesVerified, head, tail, tamperingDetected: false,
          offendingIndex: i, offendingArtifactId: entry.artifactId,
          expectedPrevHash: lastModernHash, actualPrevHash: entry.prevHash,
        };
      }

      if (typeof entry.canonical !== 'string') {
        return { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified, head, tail, tamperingDetected: false, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }
      if (!_verifyCanonicalHash(entry)) {
        const shape = _v7IntegrityDetail(entry);
        return {
          valid: false, reason: 'AUDIT_CHAIN_TAMPERED', ...(shape ? { detail: shape } : {}), entriesVerified, head, tail, tamperingDetected: true,
          offendingIndex: i, offendingArtifactId: entry.artifactId,
          expectedHash: _expectedHashFor(entry), actualHash: entry.hash,
        };
      }
      const lifecycle = tracker.step(entry);   // v7 (R-2 / R-17 / C-26)
      if (lifecycle) {
        return { valid: false, reason: 'AUDIT_CHAIN_TAMPERED', detail: lifecycle.detail, entriesVerified, head, tail, tamperingDetected: true, offendingIndex: i, offendingArtifactId: entry.artifactId };
      }

      if (head === null) head = entry.hash;
      tail = entry.hash;
      lastModernHash = entry.hash;
      entriesVerified++;
    }

    // v7 (C-26): `lifecycleComplete` says whether MISSING_INTENT could be decided; `warnings` are non-fatal.
    return { valid: true, reason: null, entriesVerified, head, tail, tamperingDetected: false, lifecycleComplete: tracker.lifecycleComplete, warnings: tracker.finish() };
  } catch {
    return { valid: false, reason: 'AUDIT_CHAIN_BROKEN', entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
  }
}

// Returns { valid, reason, entriesVerified, head, tail, tamperingDetected }.
function verifyAuditChainDetailed(entries, startPrevHash) {
  // M3: with no arguments this walks the in-memory WINDOW, whose first entry chains from _windowStartPrevHash — after
  // a prune (or once history exceeds the window) that is not GENESIS.
  if (entries === undefined && startPrevHash === undefined) return _walkChain(chain, _windowStartPrevHash);
  return _walkChain(entries !== undefined ? entries : chain, startPrevHash);
}

// Non-blocking twin of verifyAuditChainDetailed — same result shape, yields
// to the event loop periodically instead of walking the whole chain in one
// synchronous stretch. Prefer this on any path that runs concurrently with
// live request handling (HTTP routes, background verifiers); the plain sync
// version remains for callers that need a synchronous result (tests, CLI
// scripts) and is otherwise unaffected by this addition.
async function verifyAuditChainDetailedChunked(entries, startPrevHash, opts) {
  if (entries === undefined && startPrevHash === undefined) return _walkChainChunked(chain, _windowStartPrevHash, opts);   // M3 (see above)
  return _walkChainChunked(entries !== undefined ? entries : chain, startPrevHash, opts);
}

// Backwards-compatible boolean wrapper.
function verifyAuditChain(entries) {
  return _walkChain(entries !== undefined ? entries : chain).valid;
}

// Full chain copy (legacy + modern) — ASYNC, collected from the
// durable store when history exceeds the window. Memory-bounded callers
// should use getChainPage instead.
async function getAuditChain() {
  if (WINDOW_UNBOUNDED || _totalCount <= chain.length) return chain.slice();
  if (_distributed()) return pgAuditBackend.loadChainFromPg();
  const out = [];
  _scanFile((e) => { out.push(e); });
  return out;
}

// Paginated full-chain access (legacy + modern), stable file order, byte-
// offset-resumable cursor.
async function getChainPage({ cursor = null, limit = 1000 } = {}) {
  const lim = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 10000) : 1000;
  if (_distributed()) return getModernChainPage({ cursor, limit: lim }); // PG holds modern entries only
  const fromByte = cursor && Number.isInteger(cursor.o) ? cursor.o : 0;
  const fromOrdinal = cursor && Number.isInteger(cursor.n) ? cursor.n : _start.offset;   // M3: the file starts after the archived prefix
  const entries = [];
  let nextByte = fromByte;
  if (fs.existsSync(LOG_PATH)) {
    _streamLinesSync(LOG_PATH, (line, off) => {
      if (entries.length >= lim) { nextByte = off; return false; }
      let parsed;
      try { parsed = JSON.parse(line); } catch { return; }
      if (_isLegacyShaped(parsed) && !_hasStoredLegacyKey(parsed)) _markLegacy(parsed);
      entries.push(Object.freeze(parsed));
      nextByte = off + Buffer.byteLength(line, 'utf8') + 1;
    }, fromByte);
  }
  const nextOrdinal = fromOrdinal + entries.length;
  return {
    entries,
    startOrdinal: fromOrdinal,
    nextCursor: nextOrdinal < _totalCount ? { n: nextOrdinal, o: nextByte } : null,
  };
}

// bounded-memory, snapshot-consistent walk over the WHOLE history, for consumers that must see
// every entry (the dashboard's boot aggregation). getAuditChain() materialises the full history in one array — above
// ~200k entries that exhausted the default heap at boot. Here at most one page is held, the event loop is yielded
// between pages, and only entries that existed when the walk started are visited (single node: the lifetime count;
// distributed: the PG tail seq) — entries appended during the walk reach consumers through their live path, never
// twice. Same entries, same order as getAuditChain(). Resolves to the number of entries visited.
// `afterPage`, when given, is awaited after each page is visited (before the next page is read) —
// a streaming consumer (the unfiltered evidence export) flushes and waits for backpressure there.
async function forEachChainEntry(visit, { pageSize = 1000, afterPage = null } = {}) {
  const lim = Number.isInteger(pageSize) && pageSize > 0 ? Math.min(pageSize, 10000) : 1000;
  const yieldTick = () => new Promise((resolve) => setImmediate(resolve));
  let visited = 0;
  let cursor = null;
  if (_distributed()) {
    const tail = await pgAuditBackend.getChainTail();
    const endSeq = tail && tail.seq != null ? Number(tail.seq) : 0;
    for (;;) {
      const page = await getModernChainPage({ cursor, limit: lim });
      for (const e of page.entries) {
        if (Number(e.seq) > endSeq) { if (afterPage) await afterPage(); return visited; }
        visit(e); visited++;
      }
      if (afterPage) await afterPage();
      if (!page.nextCursor) return visited;
      cursor = page.nextCursor;
      await yieldTick();
    }
  }
  const end = _totalCount;
  for (;;) {
    const page = await getChainPage({ cursor, limit: lim });
    for (let i = 0; i < page.entries.length; i++) {
      if (page.startOrdinal + i >= end) { if (afterPage) await afterPage(); return visited; }
      visit(page.entries[i]); visited++;
    }
    if (afterPage) await afterPage();
    if (!page.nextCursor) return visited;
    cursor = page.nextCursor;
    await yieldTick();
  }
}

function getChainLength() {
  return _totalCount;
}

// ── Full chain integrity report ────────────────────────────────────────────────
//
// The _walkChain call is inherently O(n).  All secondary statistics now use
// O(1) index lookups instead of multiple O(n) array filters.
//
function _buildIntegrityReport(detail) {
  const integrityFailures = [];
  const corruptedEntries  = [];

  if (!detail.valid) {
    integrityFailures.push({
      reason:          detail.reason,
      entriesVerified: detail.entriesVerified,
      atIndex:         detail.entriesVerified,
    });
    if (detail.tamperingDetected) {
      corruptedEntries.push({ reason: detail.reason, atIndex: detail.entriesVerified });
    }
  }

  // Replay correlation — O(distinct replay sources) via _replayIndex.
  let replaysLinked = 0;
  for (const [originalId, replayList] of _replayIndex) {
    if (_byArtifactId.has(originalId)) replaysLinked += replayList.length;
  }

  // O(1) stats from index counters.
  const firstModern = _modernChain[0]                       ?? null;
  const lastModern  = _modernChain[_modernChain.length - 1] ?? null;

  let lineageCompleteness;
  if (_totalCount === 0)   lineageCompleteness = 'EMPTY';
  else if (detail.valid)   lineageCompleteness = 'COMPLETE';
  else                     lineageCompleteness = 'INCOMPLETE';

  return {
    chainValid:           detail.valid,
    // Lifetime figures: counts and head/tail hashes describe the whole
    // history this process has accounted for, not just the in-memory window;
    // detail.valid covers the window walk (full-history linkage is the
    // background verifier's durable-store scan).
    chainLength:          _totalCount,
    modernLength:         _modernCount,
    headHash:             _headHash,
    tailHash:             _tailHash === 'GENESIS' ? null : _tailHash,
    integrityFailures,
    missingEntries:       [],
    corruptedEntries,
    replayCorrelationState: {
      replaysDetected: _replayCount,
      replaysLinked,
      replaysUnlinked: _replayCount - replaysLinked,
    },
    lineageCompleteness,
    allowCount:           _allowCount,
    blockCount:           _blockCount,
    firstTimestamp:       firstModern?.timestamp ?? null,
    lastTimestamp:        lastModern?.timestamp  ?? null,
    validationReason:     detail.reason,
    tamperingDetected:    detail.tamperingDetected,
  };
}

// ── Durable-store integrity report ─────────────────────────
//
// _buildIntegrityReport() above computes every secondary statistic (allow/
// block counts, replay correlation, first/last timestamp) from the O(1)
// in-memory indexes — correct and cheap for a report about what THIS
// process currently holds in memory, but those indexes only reflect this
// process's own startup load plus its own subsequent appends. They cannot
// answer "what does the durable store contain right now": a hand-edited
// audit.log, a restored backup, or (distributed mode) another replica's
// writes are all invisible to them. This computes the identical set of
// statistics directly from an arbitrary freshly-read entries array (a disk
// read or a PG query, not chain[]) in one O(n) pass, so a report built from
// it reflects the persisted store at the moment of the read, not any cached
// state.
function _computeStatsFromEntries(entries) {
  let allowCount = 0;
  let blockCount = 0;
  let replayCount = 0;
  let modernLength = 0;
  let firstTimestamp = null;
  let lastTimestamp  = null;
  const allArtifactIds    = new Set();
  const replayCountByOrig = new Map();

  for (const entry of entries) {
    if (!entry || entry.legacy) continue;
    modernLength++;
    if (typeof entry.artifactId === 'string') allArtifactIds.add(entry.artifactId);
    if (firstTimestamp === null) firstTimestamp = entry.timestamp ?? null;
    lastTimestamp = entry.timestamp ?? null;

    if (entry.decision === 'ALLOW')      allowCount++;
    else if (entry.decision === 'BLOCK') blockCount++;

    const replayOf = entry.executionContext?.replayOf;
    if (typeof replayOf === 'string' && replayOf) {
      replayCount++;
      replayCountByOrig.set(replayOf, (replayCountByOrig.get(replayOf) || 0) + 1);
    }
  }

  let replaysLinked = 0;
  for (const [originalId, count] of replayCountByOrig) {
    if (allArtifactIds.has(originalId)) replaysLinked += count;
  }

  return { allowCount, blockCount, replaysDetected: replayCount, replaysLinked, modernLength, firstTimestamp, lastTimestamp };
}

// Same report shape and post-processing as _buildIntegrityReport(), built
// from an arbitrary entries array + its own walk result instead of from
// chain[]'s in-memory indexes.
function _buildIntegrityReportFromEntries(entries, detail) {
  return _buildIntegrityReportFromStats(entries.length, _computeStatsFromEntries(entries), detail);
}

// Same report, built from a pre-accumulated stats block (the streamed disk
// scan) instead of a materialized entries array.
function _buildIntegrityReportFromStats(entryCount, stats, detail) {
  const integrityFailures = [];
  const corruptedEntries  = [];

  if (!detail.valid) {
    integrityFailures.push({
      reason:          detail.reason,
      entriesVerified: detail.entriesVerified,
      atIndex:         detail.entriesVerified,
    });
    if (detail.tamperingDetected) {
      corruptedEntries.push({ reason: detail.reason, atIndex: detail.entriesVerified });
    }
  }

  let lineageCompleteness;
  if (entryCount === 0)  lineageCompleteness = 'EMPTY';
  else if (detail.valid) lineageCompleteness = 'COMPLETE';
  else                   lineageCompleteness = 'INCOMPLETE';

  return {
    chainValid:           detail.valid,
    chainLength:          entryCount,
    modernLength:         stats.modernLength,
    headHash:             detail.head,
    tailHash:             detail.tail,
    integrityFailures,
    missingEntries:       [],
    corruptedEntries,
    replayCorrelationState: {
      replaysDetected: stats.replaysDetected,
      replaysLinked:   stats.replaysLinked,
      replaysUnlinked: stats.replaysDetected - stats.replaysLinked,
    },
    lineageCompleteness,
    allowCount:           stats.allowCount,
    blockCount:           stats.blockCount,
    firstTimestamp:       stats.firstTimestamp,
    lastTimestamp:        stats.lastTimestamp,
    validationReason:     detail.reason,
    tamperingDetected:    detail.tamperingDetected,
  };
}

// GET /audit/chain/integrity (src/api/routes/audit.js) uses this instead of
// validateChainIntegrityChunked() so its response reflects the durable
// store's CURRENT contents — re-read fresh on every call — rather than this
// process's in-memory cache. File mode re-reads audit.log directly (same
// chunked, non-blocking, yielding walk verifyFullChainFromDiskChunked()
// already uses for the background verifier's own FULL scans — no new I/O
// pattern introduced). Distributed mode re-queries PostgreSQL fresh via
// loadChainFromPg() instead of trusting this replica's local hydrate-once
// cache (see hydrateFromPgIfDistributed()'s header comment on why that
// cache is a convenience read, not a security-relevant source of truth).
async function validateChainIntegrityFromDurableStoreChunked(opts) {
  if (ORDERING_MODE === 'distributed') {
    const rows   = await pgAuditBackend.loadChainFromPg();
    const detail = await _walkChainChunked(rows, undefined, opts);
    return _buildIntegrityReportFromEntries(rows, detail);
  }

  if (!fs.existsSync(LOG_PATH)) {
    const emptyDetail = { valid: true, reason: null, entriesVerified: 0, head: null, tail: null, tamperingDetected: false };
    return _buildIntegrityReportFromEntries([], emptyDetail);
  }

  let scan;
  try {
    scan = await _scanDiskStreamedChunked(null, opts);
  } catch (err) {
    const parseErrorDetail = { valid: false, reason: 'AUDIT_ENTRY_MISSING', entriesVerified: 0, head: null, tail: null, tamperingDetected: true };
    const report = _buildIntegrityReportFromEntries([], parseErrorDetail);
    return { ...report, parseError: err.message };
  }
  return _buildIntegrityReportFromStats(scan.count, scan.stats, scan.walkResult);
}

function validateChainIntegrity() {
  return _buildIntegrityReport(_walkChain(chain, _windowStartPrevHash));
}

// Non-blocking twin of validateChainIntegrity — identical report shape and
// identical post-processing (_buildIntegrityReport is shared verbatim by
// both), built from the chunked walk instead of the monopolizing one so a
// large chain can no longer stall concurrent request handling (#129
// /). Reports the IN-MEMORY chain's state — see
// validateChainIntegrityFromDurableStoreChunked() above for the disk/PG-fresh
// twin GET /audit/chain/integrity now uses instead. This
// function remains available/exported for any caller that specifically
// wants this process's current in-memory view rather than a fresh durable
// read.
async function validateChainIntegrityChunked(opts) {
  const detail = await _walkChainChunked(chain, _windowStartPrevHash, opts);
  return _buildIntegrityReport(detail);
}

module.exports = {
  LOG_PATH, // step 6: the checkpoint sidecar and the signed base record live next to it
  BASE_PATH,      // M3
  getChainStart,  // M3
  drainMirrorWriter,
  drainMirrorWriterThrough, // GA-CKPT-RATE: bounded drain for the checkpoint writer
  mirrorWriterCounters,
  mirrorWriterDepth,
  mirrorBackpressureEngaged, // bounded mirror backlog (admission + /ready)
  mirrorBackpressureConfig,
  // ── Chain mutation ────────────────────────────────────────────────────────
  append,
  appendMandatory,
  drainPendingWrites,
  getStorageReport,
  refreshFromDisk,
  isFollower,
  memorySnapshot,
  groupCommitStats,
  _setUnrecoverableHandlerForTests,

  // ── Distributed-mode startup (no-op in single-node mode) ───────────────────
  hydrateFromPgIfDistributed,
  ORDERING_MODE,

  // ── O(1) indexed lookups ──────────────────────────────────────────────────
  isNonceUsed,
  alreadyExecuted,
  getArtifactById,
  getAuditChainForTenant,
  aggregateTenantUsage,
  getAuditTailHash,
  auditChainContains,
  getReplayLineage,
  getArtifactNeighbors,
  getRequestHashEntries,
  getChainStats,

  // ── Chain access ──────────────────────────────────────────────────────────
  getAuditChain,
  getModernChain,
  getModernChainSlice,
  getChainLength,

  // ── Paginated history access ───────────────────────────────────────
  getChainPage,
  createChainWalker,
  getModernHashesAt,
  locateModernCursor,
  getModernHashesAtByOffset,   //
  getOpenLifecyclesInWindow,   //
  forEachChainEntry,
  getModernChainPage,
  forEachModernChainPage,
  getModernEntryAt,
  WINDOW_SIZE,
  getWindowStats,

  // ── Verification ──────────────────────────────────────────────────────────
  verifyAuditChain,
  verifyAuditChainDetailed,
  validateChainIntegrity,
  verifyFullChainFromDisk,

  // ── Non-blocking verification ─────────────────────────
  verifyAuditChainDetailedChunked,
  validateChainIntegrityChunked,
  verifyFullChainFromDiskChunked,

  // ── Durable-store (disk/PG-fresh) verification ─────────
  validateChainIntegrityFromDurableStoreChunked,

  // ── Checksum anchor isolation ───────────────────────────────────
  verifyChecksumAnchorIsolation,

  // ── Hash schema (exposed for tests / tooling) ─────────────────────────────
  CORE_HASH_FIELDS_V1,
  CORE_HASH_FIELDS_V2,
  CORE_HASH_FIELDS_V3,
  CORE_HASH_FIELDS_V4,
  CORE_HASH_FIELDS_V5,
  CORE_HASH_FIELDS_V6,
  CORE_HASH_FIELDS_V7,
  CURRENT_SCHEMA_VERSION,
};
