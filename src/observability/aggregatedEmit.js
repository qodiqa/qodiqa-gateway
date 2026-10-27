'use strict';

/**
 * (step 5) — log-flood control for repeated error events.
 *
 * Under PostgreSQL exhaustion the baseline logged 40k-167k PG_CIRCUIT_OPEN lines (21-67 MB of log per overload
 * phase) — one line per fast-failed query. aggregatedEmit() keeps the FIRST occurrence
 * of each (eventType, key) per WINDOW_MS in full, counts the rest, and emits ONE LOG_EVENTS_AGGREGATED summary per
 * key at the end of the window with the exact suppressed count. The operational signal survives (first event +
 * counts); only the repetition is removed. Metrics are unaffected — callers still increment their counters per
 * occurrence.
 *
 * Used for PG_CIRCUIT_OPEN (key = query label), PG_POOL_ACQUIRE_FAILED (key = error code) and PG_QUERY_ERROR
 * (key = label + code). Per-operation forensic events that carry an operation id (RECOVERY_ENQUEUE_FAILED, journal
 * events) are deliberately NOT aggregated.
 *
 *firstN — the first N occurrences of a key per window are kept in full
 * (default 1, the behaviour above, unchanged). failureEmit() applies it to the per-request failure events
 * measured during a PostgreSQL outage (FAILURE_EVENT_TYPES, ~7-8 lines per request): the first
 * QODIQA_LOG_FAILURE_FIRST_N (default 10) of each type per window in full, the rest counted in the window's
 * LOG_EVENTS_AGGREGATED summary — for stdout and the central audit store alike, since both are fed by the same
 * emit. The per-operation durable records are unaffected (recovery queue / file journal); alert rules fire on the
 * first occurrence, which is always kept; metrics still count every occurrence. QODIQA_LOG_FAILURE_FIRST_N=0 turns
 * the aggregation off for these types (rollback switch).
 */

const WINDOW_MS = 10_000;
const MAX_KEYS = 1_000; // bounded state: beyond this, events pass through un-aggregated (never silently dropped)

const _windows = new Map(); // `${eventType}|${key}` -> { level, eventType, key, suppressed, timer }

function aggregatedEmit(emit, level, eventType, payload, key, { firstN = 1 } = {}) {
  const k = `${eventType}|${key == null ? '' : key}`;
  const w = _windows.get(k);
  if (w) {
    if (w.emitted < w.firstN) { w.emitted++; emit(level, eventType, payload); return true; }
    w.suppressed++; return false;
  }
  if (_windows.size >= MAX_KEYS) { emit(level, eventType, payload); return true; }
  const entry = { level, eventType, key: key == null ? null : String(key), suppressed: 0, emitted: 1,
    firstN: Number.isInteger(firstN) && firstN >= 1 ? firstN : 1, timer: null };
  entry.timer = setTimeout(() => {
    _windows.delete(k);
    if (entry.suppressed > 0) {
      emit(entry.level, 'LOG_EVENTS_AGGREGATED', { eventType: entry.eventType, key: entry.key, suppressed: entry.suppressed, windowMs: WINDOW_MS });
    }
  }, WINDOW_MS);
  if (entry.timer.unref) entry.timer.unref();
  _windows.set(k, entry);
  emit(level, eventType, payload);
  return true;
}

// O9: the per-request failure events of a PostgreSQL outage.
const FAILURE_EVENT_TYPES = Object.freeze(['PG_AUDIT_PERSIST_FAILED', 'RECOVERY_ENQUEUE_FAILED', 'JOURNAL_ENTRY_WRITTEN',
  'EVIDENCE_CHAIN_PERSIST_FAILED', 'CONSENT_AUDIT_LOG_FAILED', 'TRANSPARENCY_ENTRY_PENDING', 'AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED']);
const DEFAULT_FAILURE_FIRST_N = 10;

function failureFirstN() {
  const v = process.env.QODIQA_LOG_FAILURE_FIRST_N;
  if (v === undefined || v === '') return DEFAULT_FAILURE_FIRST_N;
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 ? n : DEFAULT_FAILURE_FIRST_N;
}

/** First N of each failure type per window in full, the rest counted (key = the event type). */
function failureEmit(emit, level, eventType, payload) {
  const n = failureFirstN();
  if (n === 0) { emit(level, eventType, payload); return true; }
  return aggregatedEmit(emit, level, eventType, payload, null, { firstN: n });
}

function _resetForTests() { for (const w of _windows.values()) clearTimeout(w.timer); _windows.clear(); }

module.exports = { aggregatedEmit, failureEmit, failureFirstN, FAILURE_EVENT_TYPES, DEFAULT_FAILURE_FIRST_N, WINDOW_MS, MAX_KEYS, _resetForTests };
