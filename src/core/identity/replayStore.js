'use strict';

/**
 * One-time claims: `claim(key, ttlMs)` resolves true the FIRST time a key is claimed and false while it is still remembered - the replay guard for SAML assertion ids.
 *
 * Redis (`SET key 1 NX PX ttl`, shared by every replica) when REDIS_URL is set, process memory otherwise (development, single-node tests). A store that cannot answer REJECTS: the caller
 * must refuse the login ("cannot tell whether it was used" is not "unused"). Same managed-client pattern as src/core/artifactRevocation.
 */

const { emit } = require('../../../services/logger');

const PREFIX = 'idreplay:v1:';
const STORE_TIMEOUT_MS = 2000;
const MEMORY_CAP = 100000;

function withTimeout(p, ms) {
  let t;
  const timeout = new Promise((_, reject) => { t = setTimeout(() => reject(new Error('replay store timed out')), ms); });
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

function createMemoryStore(now = () => Date.now()) {
  const m = new Map();
  return {
    kind: 'memory',
    async claim(key, ttlMs) {
      const t = now();
      const e = m.get(key);
      if (e && e > t) return false;
      if (m.size >= MEMORY_CAP) { for (const [k, exp] of m) if (exp <= t) m.delete(k); if (m.size >= MEMORY_CAP) m.delete(m.keys().next().value); }
      m.set(key, t + ttlMs);
      return true;
    },
  };
}

function createRedisStore(client, { connecting = null } = {}) {
  return {
    kind: 'redis',
    async claim(key, ttlMs) {
      if (!client.isReady && connecting) { try { await connecting; } catch { /* reported below */ } }
      if (!client.isReady) throw new Error('Redis not connected');
      return (await client.set(PREFIX + key, '1', { PX: Math.max(1000, Math.floor(ttlMs)), NX: true })) === 'OK';
    },
  };
}

let _default = null;
function defaultStore() {
  if (_default) return _default;
  if (!process.env.REDIS_URL) { _default = createMemoryStore(); return _default; }
  const { createManagedRedisClient } = require('../../infra/redis/managedClient');
  const { createInfiniteReconnectStrategy } = require('../../infra/redis/reconnectStrategy');
  const client = createManagedRedisClient({
    purpose: 'identityReplay',
    reconnectStrategy: createInfiniteReconnectStrategy({ source: 'IDENTITY_REPLAY', oldMaxReconnects: 5, onRetry: () => {} }),
    connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10),
  });
  client.on('error', (err) => emit('WARN', 'IDENTITY_REPLAY_REDIS_ERROR', { error: err.message }));
  const connecting = client.connect().catch((err) => { emit('ERROR', 'IDENTITY_REPLAY_REDIS_CONNECT_FAILED', { error: err.message }); });
  _default = createRedisStore(client, { connecting });
  return _default;
}

/** The store used by the SAML service: claim(key, ttlMs) -> Promise<boolean>, bounded by a timeout. */
const shared = { claim: (key, ttlMs) => withTimeout(Promise.resolve().then(() => defaultStore().claim(key, ttlMs)), STORE_TIMEOUT_MS) };

function _reset() { _default = null; }
module.exports = { shared, createMemoryStore, createRedisStore, _reset };
