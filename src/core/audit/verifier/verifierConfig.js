'use strict';

/**
 * Live Audit Chain Verifier — Configuration (CHAIN-2)
 *
 * All configuration is read from environment variables at load time. The
 * returned config object is frozen — no runtime mutation. Mirrors the shape
 * of src/core/transparency/scanner/scannerConfig.js.
 *
 * ── Finding D: historical tamper detection latency ────────────────
 * INCREMENTAL only ever walks the delta since its own watermark (the tail),
 * so a direct on-disk/in-table edit to an OLDER entry is invisible to it by
 * construction — only a FULL scan re-reads the entire durable store fresh
 * and can catch that class of tampering. That makes fullIntervalMs the
 * actual worst-case historical-tamper detection-latency bound, not
 * incrementalIntervalMs. The default was lowered from 24h to 4h here: a
 * benchmark of verifyFullChainFromDiskChunked() (chunked/non-blocking,
 * #129) against real on-disk chains showed ~150ms at 5,000 entries,
 * ~550ms at 20,000, and ~2.5s at 100,000 (~140MB) — roughly linear, and
 * because the walk yields to the event loop periodically, none of that time
 * blocks concurrent request handling regardless of interval. Running it 6x
 * more often is a proportionally larger but still small total IO/CPU cost
 * for a 6x tighter worst-case detection window, with no code changes and no
 * new subsystem. This is deliberately NOT a "rolling"/partial-read scan:
 * audit.log is flat, append-only NDJSON with no line-offset index, so
 * there is no way to cheaply verify only entries 50,000-50,500 of a
 * 1,000,000-line file without a byte-offset index this codebase does not
 * have — any partial-read scheme would still have to linearly scan up to
 * its target position, which is not meaningfully cheaper than the existing
 * FULL scan for the common case of eventually covering the whole file.
 * Distributed/PG-authoritative mode's FULL scan shares this same interval
 * but is comparatively cheap regardless (indexed, paginated `seq` batches —
 * see ChainVerifier.js's _verifyPgAuthoritative()), so operators running
 * very large single-node file chains who need a materially tighter bound
 * than a few hours should consider distributed mode rather than shrinking
 * this interval further, per the existing SCAL-11 guidance in
 * docs/protocol/AUDIT-SCHEMA-V8.md. Fully operator-overridable via
 * QODIQA_AUDIT_VERIFIER_FULL_INTERVAL below in either direction.
 *
 * Environment variables:
 *   QODIQA_AUDIT_VERIFIER_ENABLED                  — 'true'/'false' (default: true —
 *     unlike the transparency Gap Scanner, this defaults ON: CHAIN-2 exists
 *     because the primary enforcement record had NO detector at all, and
 *     file-mode operation needs no PostgreSQL precondition the way the Gap
 *     Scanner does.)
 *   QODIQA_AUDIT_VERIFIER_INCREMENTAL_INTERVAL     — tail-only check tick: named
 *     ('30s'|'60s'|'5m'|'15m'|'1h'|'24h') or milliseconds (default: 60s)
 *   QODIQA_AUDIT_VERIFIER_FULL_INTERVAL            — infrequent full disk/table
 *     rescan; the actual worst-case historical-tamper detection-latency bound
 * (default: 4h — Finding D note above; was 24h)
 *   QODIQA_AUDIT_VERIFIER_PG_DIVERGENCE_INTERVAL   — dual-write file-vs-PG
 *     periodic check, independent of the two timers above (default: 15m)
 *   QODIQA_AUDIT_VERIFIER_BATCH_SIZE               — PG pagination batch size
 *     (default: 1000)
 *   QODIQA_AUDIT_VERIFIER_MAX_RETRIES              — scan retry count on
 *     transient (engine, not violation) failure (default: 3)
 *   QODIQA_AUDIT_VERIFIER_RETRY_DELAY_MS           — delay between retries
 *     (default: 5000)
 *   QODIQA_AUDIT_VERIFIER_STARTUP_SCAN             — 'true' to run one
 *     incremental tick immediately when the runner starts (default: false)
 *   QODIQA_AUDIT_VERIFIER_RECOVERY_MODE            — 'true' downgrades the
 *     startup watermark-continuity gate from FATAL to WARN+proceed (default:
 *     false) — mirrors QODIQA_AUDIT_MIRROR_RECOVERY_MODE's naming/behavior.
 *   QODIQA_AUDIT_VERIFIER_FULL_ON_WATERMARK_MISMATCH — in recovery mode, run
 *     an immediate FULL scan after a watermark mismatch for complete
 *     forensics rather than waiting for the next scheduled one (default: true)
 *   QODIQA_AUDIT_VERIFIER_MANUAL_TIMEOUT_MS        — timeout for the admin
 *     POST /audit/chain/verifier/verify endpoint (default: 30000)
 */

const NAMED_INTERVALS = new Map([
  ['30s', 30_000],
  ['60s', 60_000],
  ['1m',  60_000],
  ['5m',  300_000],
  ['15m', 900_000],
  ['1h',  3_600_000],
  ['24h', 86_400_000],
]);

function _envInt(key, fallback) {
  const raw = process.env[key];
  if (raw == null) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function _envBool(key, fallback) {
  const raw = process.env[key];
  if (raw == null) return fallback;
  return raw === 'true';
}

function _resolveInterval(raw, fallbackMs) {
  if (raw == null) return fallbackMs;
  if (NAMED_INTERVALS.has(raw)) return NAMED_INTERVALS.get(raw);
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallbackMs;
}

function load() {
  return Object.freeze({
    enabled:                 _envBool('QODIQA_AUDIT_VERIFIER_ENABLED', true),
    incrementalIntervalMs:   _resolveInterval(process.env.QODIQA_AUDIT_VERIFIER_INCREMENTAL_INTERVAL, 60_000),
    // Finding D: lowered from 86_400_000 (24h) to 14_400_000 (4h) —
    // see this file's header comment for the benchmark and reasoning.
    fullIntervalMs:          _resolveInterval(process.env.QODIQA_AUDIT_VERIFIER_FULL_INTERVAL, 14_400_000),
    pgDivergenceIntervalMs:  _resolveInterval(process.env.QODIQA_AUDIT_VERIFIER_PG_DIVERGENCE_INTERVAL, 900_000),
    batchSize:               _envInt('QODIQA_AUDIT_VERIFIER_BATCH_SIZE', 1000),
    maxRetries:              _envInt('QODIQA_AUDIT_VERIFIER_MAX_RETRIES', 3),
    retryDelayMs:            _envInt('QODIQA_AUDIT_VERIFIER_RETRY_DELAY_MS', 5_000),
    startupScan:             _envBool('QODIQA_AUDIT_VERIFIER_STARTUP_SCAN', false),
    recoveryMode:            _envBool('QODIQA_AUDIT_VERIFIER_RECOVERY_MODE', false),
    fullOnWatermarkMismatch: _envBool('QODIQA_AUDIT_VERIFIER_FULL_ON_WATERMARK_MISMATCH', true),
    manualTimeoutMs:         _envInt('QODIQA_AUDIT_VERIFIER_MANUAL_TIMEOUT_MS', 30_000),
    // S3: 'layered' (default) = 60 s incremental + 15-min anchors/sweep; 'full' = the previous full comparison
    // every pgDivergenceIntervalMs (rollback switch). Anything else is treated as 'layered'.
    divergenceMode:          process.env.QODIQA_AUDIT_DIVERGENCE_MODE === 'full' ? 'full' : 'layered',
  });
}

module.exports = { load, NAMED_INTERVALS };
