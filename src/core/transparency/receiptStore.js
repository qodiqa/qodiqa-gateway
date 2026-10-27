'use strict';

/**
 * Short-lived store for issued receipts: serves `GET /v1/transparency/receipt/{requestId}`.
 *
 * A receipt is also returned in the response that produced it, and it is a convenience proof (that the gateway recorded a
 * decision); the durable, tamper-evident record is the audit entry and the transparency leaf it points at. So receipts are
 * kept only for a bounded retrieval window — QODIQA_RECEIPT_TTL_SECONDS, default 3600, `0` stores nothing (the endpoint then
 * answers 404), maximum 7 days — in Redis when REDIS_URL is set (shared by every instance), otherwise in process memory
 * (bounded, oldest first). Storage is best-effort: a store failure never fails the request that issued the receipt.
 *
 * This is deliberately not a PostgreSQL table: at sustained load a durable receipt per request grows without bound and a
 * new table would need retention, DR and role-policy work that the owner has not decided; the response copy and
 * the transparency inclusion proof remain the durable evidence.
 */

const { emit } = require('../../../services/logger');

const MAX_TTL_SECONDS = 7 * 24 * 3600;
const MEMORY_CAP = 50000;
const KEY_PREFIX = 'receipt:v1:';

function ttlSeconds() {
  const raw = process.env.QODIQA_RECEIPT_TTL_SECONDS;
  if (raw === undefined || raw === '') return 3600;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) return 3600;
  return Math.min(n, MAX_TTL_SECONDS);
}

const _memory = new Map();            // requestId → { json, expiresAt }
let _client = null;
let _lastWarnAt = 0;

function _warn(code, err) {
  const now = Date.now();
  if (now - _lastWarnAt < 60000) return;
  _lastWarnAt = now;
  emit('WARN', code, { error: err && err.message ? err.message : String(err) });
}

function _redis() {
  if (!process.env.REDIS_URL) return null;
  if (_client) return _client;
  try {
    const { createManagedRedisClient } = require('../../infra/redis/managedClient');
    const { createInfiniteReconnectStrategy } = require('../../infra/redis/reconnectStrategy');
    _client = createManagedRedisClient({
      purpose: 'receipts',
      reconnectStrategy: createInfiniteReconnectStrategy({ source: 'RECEIPT_STORE', oldMaxReconnects: 5, onRetry: () => {} }),
      connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10),
    });
    _client.on('error', (err) => _warn('RECEIPT_STORE_REDIS_ERROR', err));
    _client.connect().catch((err) => _warn('RECEIPT_STORE_REDIS_CONNECT_FAILED', err));
  } catch (err) {
    _warn('RECEIPT_STORE_REDIS_INIT_FAILED', err);
    _client = null;
  }
  return _client;
}

function _memPut(requestId, json, ttl) {
  if (_memory.size >= MEMORY_CAP) _memory.delete(_memory.keys().next().value);
  _memory.set(requestId, { json, expiresAt: Date.now() + ttl * 1000 });
}

/** Keep a receipt for the retrieval window. Never throws; resolves true when something was stored. */
async function putReceipt(receipt) {
  const ttl = ttlSeconds();
  if (ttl === 0 || !receipt || typeof receipt.requestId !== 'string') return false;
  const json = JSON.stringify(receipt);
  _memPut(receipt.requestId, json, ttl);                   // always: the issuing instance can serve it even if Redis is down
  const c = _redis();
  if (c && c.isReady) {
    try { await c.set(KEY_PREFIX + receipt.requestId, json, { EX: ttl, NX: true }); } catch (err) { _warn('RECEIPT_STORE_REDIS_ERROR', err); }
  }
  return true;
}

/** The stored receipt of a request, or null (unknown, expired, or the store is unavailable). Never throws. */
async function getReceipt(requestId) {
  if (typeof requestId !== 'string' || !requestId) return null;
  const c = _redis();
  if (c && c.isReady) {
    try {
      const raw = await c.get(KEY_PREFIX + requestId);
      if (raw) return JSON.parse(raw);
    } catch (err) { _warn('RECEIPT_STORE_REDIS_ERROR', err); }
  }
  const m = _memory.get(requestId);
  if (!m) return null;
  if (m.expiresAt <= Date.now()) { _memory.delete(requestId); return null; }
  try { return JSON.parse(m.json); } catch { return null; }
}

function _resetForTests() { _memory.clear(); _client = null; _lastWarnAt = 0; }

module.exports = { putReceipt, getReceipt, ttlSeconds, MAX_TTL_SECONDS, MEMORY_CAP, _resetForTests };
