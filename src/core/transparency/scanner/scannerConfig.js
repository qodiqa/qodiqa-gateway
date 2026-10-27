'use strict';

/**
 * Transparency Gap Scanner — Configuration — Component #34
 *
 * All configuration is read from environment variables at load time.
 * The returned config object is frozen — no runtime mutation.
 *
 * Environment variables:
 *   TRANSPARENCY_SCANNER_ENABLED          — 'true' to enable (default: false)
 *   TRANSPARENCY_SCANNER_INTERVAL         — scan interval: '1m'|'5m'|'10m'|'1hr'|<ms>
 *                                           (default: '5m' = 300 000 ms)
 *   TRANSPARENCY_SCANNER_MODE             — 'INCREMENTAL'|'FULL' (default: 'INCREMENTAL')
 *   TRANSPARENCY_SCANNER_BATCH_SIZE       — entries per DB query (default: 1000)
 *   TRANSPARENCY_SCANNER_MAX_RETRIES      — max retry attempts on failure (default: 3)
 *   TRANSPARENCY_SCANNER_RETRY_DELAY_MS   — delay between retries in ms (default: 5000)
 *   TRANSPARENCY_SCANNER_STARTUP_SCAN     — 'true' to run a scan immediately on start
 *   TRANSPARENCY_SCANNER_VERIFY_HASHES    — 'true' to recompute entry hashes (default: true)
 *   TRANSPARENCY_SCANNER_VERIFY_ROOTS     — 'true' to verify root chain (default: true)
 */

const NAMED_INTERVALS = new Map([
  ['1m',  60_000],
  ['5m',  300_000],
  ['10m', 600_000],
  ['1hr', 3_600_000],
]);

const VALID_MODES = new Set(['FULL', 'INCREMENTAL']);

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

function _resolveInterval(raw) {
  if (NAMED_INTERVALS.has(raw)) return NAMED_INTERVALS.get(raw);
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 300_000;
}

function load() {
  const intervalRaw = process.env.TRANSPARENCY_SCANNER_INTERVAL || '5m';
  const modeRaw     = (process.env.TRANSPARENCY_SCANNER_MODE || 'INCREMENTAL').toUpperCase();

  return Object.freeze({
    enabled:           _envBool('TRANSPARENCY_SCANNER_ENABLED', false),
    intervalMs:        _resolveInterval(intervalRaw),
    mode:              VALID_MODES.has(modeRaw) ? modeRaw : 'INCREMENTAL',
    maxBatchSize:      _envInt('TRANSPARENCY_SCANNER_BATCH_SIZE', 1000),
    maxRetries:        _envInt('TRANSPARENCY_SCANNER_MAX_RETRIES', 3),
    retryDelayMs:      _envInt('TRANSPARENCY_SCANNER_RETRY_DELAY_MS', 5_000),
    startupScan:       _envBool('TRANSPARENCY_SCANNER_STARTUP_SCAN', false),
    verifyEntryHashes: _envBool('TRANSPARENCY_SCANNER_VERIFY_HASHES', true),
    verifyRoots:       _envBool('TRANSPARENCY_SCANNER_VERIFY_ROOTS', true),
  });
}

module.exports = { load, NAMED_INTERVALS, VALID_MODES };
