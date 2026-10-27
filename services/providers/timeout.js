'use strict';

/**
 * one strict parser for every provider's *_TIMEOUT_MS.
 *
 * The adapters each did `parseInt(process.env.X_TIMEOUT_MS || '30000', 10)` on their own, so LOCAL_TIMEOUT_MS=abc became NaN
 * (every request failed within ~1 ms with no error code) and '1e3' became 1 ms, although config.js had a lenient validator the
 * adapters never consulted. A valid value is a plain positive integer of milliseconds; anything else falls back to the default
 * and is reported once (PROVIDER_TIMEOUT_ENV_INVALID) instead of silently producing a ~1 ms or NaN timeout.
 */

const { emit } = require('../logger');

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 2_147_483_647;
const _warned = new Set();

function resolveTimeoutMs(envName, fallback = DEFAULT_TIMEOUT_MS, env = process.env) {
  const raw = env[envName];
  if (raw === undefined || raw === null || String(raw).trim() === '') return fallback;
  const s = String(raw).trim();
  // (verification): Node's setTimeout overflows above 2^31-1 ms and fires after ~1 ms, so such values are invalid too.
  if (/^[1-9]\d{0,9}$/.test(s) && Number(s) <= MAX_TIMEOUT_MS) return Number(s);
  if (!_warned.has(envName)) {
    _warned.add(envName);
    emit('WARN', 'PROVIDER_TIMEOUT_ENV_INVALID', { variable: envName, fallbackMs: fallback, message: `${envName} must be a positive integer number of milliseconds; using the default` });
  }
  return fallback;
}

module.exports = { resolveTimeoutMs, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS };
