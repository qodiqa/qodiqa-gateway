'use strict';

/**
 * Transparency-journal health and the in-memory bridge.
 *
 * Every enforcement decision owes the transparency log one leaf. When the synchronous registration fails, enforcementBridge.js hands the leaf
 * to the durable recovery queue (PostgreSQL) and, if PostgreSQL refuses the enqueue, to the crash-safe file journal on the persistent volume
 * (QODIQA_PRQ_JOURNAL_DIR). This module tracks the one case that remains: NEITHER could take the leaf.
 *
 *   - the failure starts an unavailability window (`unavailableSince`); a success of any kind (a synchronous registration, a queue or journal
 *     write) ends it;
 *   - leaves of BLOCK decisions and of streams (whose response cannot be withdrawn) are kept in a bounded in-memory buffer and retried every
 *     second, in their original order, until a durable store accepts them (`bufferRetry`); they are the explicit residual: a process that dies
 *     inside the window loses them, and the loss is counted and escalated;
 *   - while the window is open longer than the bound (QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS, default 60 s, 1 s .. 1 h) new EXECUTE
 *     decisions are refused before the provider is called (503 TRANSPARENCY_JOURNAL_UNAVAILABLE) and /ready reports the instance not ready —
 *     BLOCK decisions keep being answered (a refusal cannot be less safe than the refusal it replaces), so the missing evidence cannot grow
 *     without bound;
 *   - every leaf that goes through the queue, the journal or this buffer carries `payload.recovery = { late: true, replica, seq, queuedAt }`
 *     (set by the bridge BEFORE the payload hash is computed, so it is signed with the leaf): an independent verifier sees that the leaf
 *     entered after an interruption. ORIGINAL ORDER = the original `recordedAt` (set when the decision was built); `seq` (monotonic per process,
 *     never reused; a new process is a new `replica` id) only breaks ties and exposes gaps: it is assigned when the leaf first failed, so two
 *     decisions in flight together can carry seq in the opposite order of their recordedAt, and a leaf that was never queued consumes none.
 */

const crypto = require('crypto');
const { emit } = require('../../../services/logger');

const DEFAULT_MAX_MS = 60_000;
const MIN_MAX_MS = 1_000;
const MAX_MAX_MS = 3_600_000;
const BUFFER_CAP = 10_000;
const RETRY_MS = 1_000;

const REPLICA = (process.env.HOSTNAME || 'replica') + ':' + crypto.randomBytes(3).toString('hex');
let _seq = 0;
let _unavailableSince = null;
let _lastFailure = null;
let _refusedLogged = false;
const _buffer = [];            // [{ registration, tries, since }]  in original order
let _timer = null;
let _flusher = null;           // (registration) => Promise<boolean> durable?
let _prober = null;            // () => Promise<boolean>  can a leaf be stored again? (queue reachable or journal writable)
let _closedByProbeAt = null;   // N1: a window closed by the PROBE (which cannot prove a real write works) that re-opens within the bound is the SAME window
let _prevSince = null;
let _flushPromise = null;
let _flushing = false;         // re-entrancy guard: two overlapping flushes would each take the same head item

function maxUnavailableMs() {
  const v = Number(process.env.QODIQA_TRANSPARENCY_JOURNAL_MAX_UNAVAILABLE_MS);
  return Number.isInteger(v) && v >= MIN_MAX_MS && v <= MAX_MAX_MS ? v : DEFAULT_MAX_MS;
}

function _metrics() { try { return require('../../observability/metrics'); } catch { return null; } }
function _syncGauges() {
  const m = _metrics();
  if (!m) return;
  try {
    if (m.transparencyJournalUnavailable) m.transparencyJournalUnavailable.set(_unavailableSince === null ? 0 : 1);
    if (m.transparencyJournalBuffered) m.transparencyJournalBuffered.set(_buffer.length);
  } catch { /* metrics are fail-safe */ }
}

/** Next position in this replica's order of late leaves. */
function nextSeq() { _seq += 1; return { replica: REPLICA, seq: _seq }; }

/** The marker a leaf carries when it did not go through the synchronous registration. */
function recoveryMarker() {
  const { replica, seq } = nextSeq();
  return { late: true, replica, seq, queuedAt: new Date().toISOString() };
}

function noteOk(source = 'write') {
  if (_unavailableSince === null) { if (source === 'write') { _prevSince = null; _closedByProbeAt = null; } return; }
  if (_buffer.length > 0) return;          // leaves are still waiting: the store has not proven itself yet (flushBuffer ends the window)
  const ms = Date.now() - _unavailableSince;
  if (source === 'probe') { _prevSince = _unavailableSince; _closedByProbeAt = Date.now(); } else { _prevSince = null; _closedByProbeAt = null; }
  _unavailableSince = null; _refusedLogged = false;
  emit('WARN', 'TRANSPARENCY_JOURNAL_RECOVERED', { unavailableMs: ms, buffered: _buffer.length });
  _syncGauges();
}

function noteFailure(err) {
  _lastFailure = err ? String(err.message || err) : null;
  if (_unavailableSince === null && _prevSince !== null && _closedByProbeAt !== null && Date.now() - _closedByProbeAt <= maxUnavailableMs()) {
    // N1: the probe (SELECT 1 / a journal file) closed the window but real writes are still failing: it is the same outage, with its original start,
    // so the bound is reached even when the store half-works. Only a successful REAL write (a registration, a queue/journal write, a flush) ends it for good.
    _unavailableSince = _prevSince;
  } else if (_unavailableSince === null) {
    _unavailableSince = Date.now();
    emit('CRITICAL', 'TRANSPARENCY_JOURNAL_UNAVAILABLE', { maxUnavailableMs: maxUnavailableMs(), error: _lastFailure,
      message: 'Neither the recovery queue nor the file journal could take a transparency leaf. Leaves are buffered in memory; new EXECUTE decisions are refused if this lasts longer than the bound.' });
  }
  _ensureTimer();                          // D2: the window must be able to close without traffic (probe below)
  _syncGauges();
}

/** Has the window been open longer than the bound? (Then new EXECUTE decisions are refused and /ready is false.) */
function isRefusing(now = Date.now()) {
  return _unavailableSince !== null && now - _unavailableSince > maxUnavailableMs();
}

/** Throws a coded error when EXECUTE decisions are being refused. Call before the provider is dispatched. */
function assertAvailable() {
  if (!isRefusing()) return;
  const m = _metrics(); if (m && m.transparencyJournalRefusedTotal) m.transparencyJournalRefusedTotal.inc();
  if (!_refusedLogged) { _refusedLogged = true; emit('CRITICAL', 'TRANSPARENCY_JOURNAL_REFUSING_EXECUTE', { unavailableMs: Date.now() - _unavailableSince, maxUnavailableMs: maxUnavailableMs() }); }
  const e = new Error('TRANSPARENCY_JOURNAL_UNAVAILABLE: the transparency evidence store has been unavailable for longer than the bound; new executions are refused until it recovers');
  e.code = 'TRANSPARENCY_JOURNAL_UNAVAILABLE';
  throw e;
}

/** Keep a leaf that no durable store would take (BLOCK / stream); retried in order. Returns false when the buffer is full (loss). */
function buffer(registration) {
  if (_buffer.length >= BUFFER_CAP) {
    const m = _metrics(); if (m && m.transparencyUnrecordedTotal) m.transparencyUnrecordedTotal.inc({ reason: 'buffer_full' });
    emit('CRITICAL', 'TRANSPARENCY_LEAF_LOST', { transparencyId: registration.transparencyId, reason: 'buffer_full', cap: BUFFER_CAP });
    return false;
  }
  _buffer.push({ registration, tries: 0, since: Date.now() });
  _ensureTimer(); _syncGauges();
  return true;
}

async function flushBuffer() {
  if (_flushing) return { flushed: 0, remaining: _buffer.length, skipped: true };
  _flushing = true;
  const run = _flushOnce();
  _flushPromise = run;
  try { return await run; } finally { _flushing = false; if (_flushPromise === run) _flushPromise = null; }
}

async function _flushOnce() {
  {
    let flushed = 0;
    if (_flusher) {
      while (_buffer.length > 0) {
        const item = _buffer[0];
        item.tries += 1;
        let ok = false;
        try { ok = await _flusher(item.registration); } catch { ok = false; }
        if (!ok) break;                       // keep the original order: nothing behind a leaf that still cannot be stored goes first
        _buffer.shift(); flushed += 1;
      }
    }
    // D2: with the buffer empty and the window open, ask the store whether it can take a leaf again; a success closes the window
    if (flushed > 0 && _buffer.length === 0) noteOk();                 // the store just accepted our leaves: it is back
    else if (_buffer.length === 0 && _unavailableSince !== null && _prober) {
      let ok = false;
      try { ok = await _prober(); } catch { ok = false; }
      if (ok) noteOk('probe');
    }
    _syncGauges();
    if (_buffer.length === 0 && _unavailableSince === null) _stopTimer();
    return { flushed, remaining: _buffer.length };
  }
}

/** D7: at shutdown try once more; whatever is still buffered is lost with the process - say so (CRITICAL + counter), never silently. */
async function flushOnShutdown({ timeoutMs = 5000 } = {}) {
  // N3: wait for a flush that is already writing (it may be storing the very leaf we would otherwise report lost); N2: never beyond timeoutMs
  const work = (async () => {
    try { if (_flushPromise) await _flushPromise.catch(() => {}); await flushBuffer(); } catch { /* reported below */ }
  })();
  let t; const timeout = new Promise((res) => { t = setTimeout(res, timeoutMs); if (t.unref) t.unref(); });
  await Promise.race([work, timeout]); clearTimeout(t);
  const lost = _buffer.length;
  if (lost > 0) {
    const m = _metrics(); if (m && m.transparencyUnrecordedTotal) m.transparencyUnrecordedTotal.inc({ reason: 'shutdown' }, lost);
    emit('CRITICAL', 'TRANSPARENCY_LEAF_LOST', { reason: 'shutdown', count: lost, transparencyIds: _buffer.slice(0, 20).map((i) => i.registration.transparencyId),
      message: 'The process is exiting with transparency leaves that no durable store took; those decisions have an audit entry but no transparency leaf.' });
  }
  _stopTimer();
  return { lost };
}

function _ensureTimer() {
  if (_timer) return;
  _timer = setInterval(() => { flushBuffer().catch(() => {}); }, RETRY_MS);
  if (_timer.unref) _timer.unref();
}
function _stopTimer() { if (_timer) { clearInterval(_timer); _timer = null; } }

/** The bridge hands over the function that writes one registration to the queue / journal (true = durable). */
function setFlusher(fn) { _flusher = fn; }
/** ... and a probe that says whether a leaf could be stored now (the queue is reachable or the journal is writable). */
function setProber(fn) { _prober = fn; }

function snapshot() {
  return { unavailable: _unavailableSince !== null, unavailableSince: _unavailableSince, refusing: isRefusing(), buffered: _buffer.length,
    maxUnavailableMs: maxUnavailableMs(), lastFailure: _lastFailure, replica: REPLICA };
}

/** Test hook. */
function _reset() { _unavailableSince = null; _lastFailure = null; _refusedLogged = false; _buffer.length = 0; _seq = 0; _flushing = false; _flushPromise = null; _prevSince = null; _closedByProbeAt = null; _stopTimer(); }

module.exports = { recoveryMarker, nextSeq, noteOk, noteFailure, isRefusing, assertAvailable, buffer, flushBuffer, flushOnShutdown, setFlusher, setProber, snapshot, maxUnavailableMs, DEFAULT_MAX_MS, BUFFER_CAP, REPLICA, _reset };
