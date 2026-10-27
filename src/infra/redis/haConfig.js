'use strict';

/**
 * Redis High-Availability configuration —.
 *
 * Resolves the deployment mode and topology QODIQA should connect with, from
 * environment variables alone. Every existing single-instance deployment
 * continues to work with ZERO configuration changes: REDIS_MODE defaults to
 * 'single', which reproduces the exact `createClient(buildClientOptions(...))`
 * construction every store already used (see managedClient.js).
 *
 * Env vars:
 *   REDIS_MODE                          'single' (default) | 'sentinel' | 'cluster'
 *
 *   --- sentinel mode ---
 *   REDIS_SENTINEL_HOSTS                 comma-separated host:port list of sentinel
 *                                         nodes, e.g. "sentinel1:26379,sentinel2:26379,sentinel3:26379"
 *   REDIS_SENTINEL_MASTER_NAME           the monitored master group name (required
 *                                         in sentinel mode), e.g. "mymaster"
 *   REDIS_SENTINEL_SCAN_INTERVAL_MS      how often to poll sentinel for topology
 *                                         changes (default: 10000)
 *   REDIS_SENTINEL_USE_REPLICAS          'true' to distribute read-only commands
 *                                         across replicas (default: false — every
 *                                         command goes to the master, matching
 *                                         single-instance semantics exactly)
 *
 *   --- cluster mode ---
 *   REDIS_CLUSTER_HOSTS                  comma-separated host:port list of cluster
 *                                         seed nodes
 *
 *   --- shared retry/circuit-breaker policy (used for HA-mode node-level sockets) ---
 *   REDIS_MAX_RECONNECT_ATTEMPTS         default 5
 *   REDIS_RECONNECT_BASE_DELAY_MS        default 100
 *   REDIS_RECONNECT_MAX_DELAY_MS         default 2000
 *   REDIS_RECONNECT_JITTER_RATIO         0..1, default 0.2 (±20% jitter)
 *   REDIS_CIRCUIT_BREAKER_COOLDOWN_MS    default 30000 — after exhausting retries
 *                                         against one node, wait this long before
 *                                         allowing a fresh retry cycle against it
 *
 * All numeric env vars are validated: non-numeric or out-of-range values fall
 * back to the documented default rather than producing NaN/undefined behavior
 * deep inside the redis client.
 */

function _int(env, name, fallback, { min = 0 } = {}) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < min) return fallback;
  return n;
}

function _ratio(env, name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 1) return fallback;
  return n;
}

function _parseHostList(raw) {
  if (!raw) return [];
  return raw.split(',').map(s => s.trim()).filter(Boolean).map(entry => {
    const [host, portStr] = entry.split(':');
    const port = parseInt(portStr, 10);
    return { host, port: Number.isFinite(port) ? port : 6379 };
  });
}

/**
 * Resolve the full HA configuration from process.env.
 *
 * @returns {{
 *   mode: 'single'|'sentinel'|'cluster',
 *   sentinel: { masterName: string|null, rootNodes: Array<{host,port}>, scanIntervalMs: number, useReplicas: boolean },
 *   cluster: { rootNodes: Array<{host,port}> },
 *   retry: { maxAttempts: number, baseDelayMs: number, maxDelayMs: number, jitterRatio: number, circuitBreakerCooldownMs: number },
 *   valid: boolean,
 *   validationErrors: string[],
 * }}
 */
function resolveHaConfig(env = process.env) {
  const rawMode = (env.REDIS_MODE || 'single').toLowerCase();
  const mode = ['single', 'sentinel', 'cluster'].includes(rawMode) ? /** @type {'single'|'sentinel'|'cluster'} */ (rawMode) : 'single';

  const validationErrors = [];
  if (!['single', 'sentinel', 'cluster'].includes(rawMode)) {
    validationErrors.push(`REDIS_MODE="${env.REDIS_MODE}" is not one of single|sentinel|cluster — falling back to single`);
  }

  const sentinelRootNodes = _parseHostList(env.REDIS_SENTINEL_HOSTS);
  const masterName = env.REDIS_SENTINEL_MASTER_NAME || null;
  if (mode === 'sentinel') {
    if (sentinelRootNodes.length === 0) {
      validationErrors.push('REDIS_MODE=sentinel requires REDIS_SENTINEL_HOSTS (comma-separated host:port list)');
    }
    if (!masterName) {
      validationErrors.push('REDIS_MODE=sentinel requires REDIS_SENTINEL_MASTER_NAME');
    }
  }

  const clusterRootNodes = _parseHostList(env.REDIS_CLUSTER_HOSTS);
  if (mode === 'cluster' && clusterRootNodes.length === 0) {
    validationErrors.push('REDIS_MODE=cluster requires REDIS_CLUSTER_HOSTS (comma-separated host:port list)');
  }

  return {
    mode,
    sentinel: {
      masterName,
      rootNodes: sentinelRootNodes,
      scanIntervalMs: _int(env, 'REDIS_SENTINEL_SCAN_INTERVAL_MS', 10_000, { min: 500 }),
      useReplicas: env.REDIS_SENTINEL_USE_REPLICAS === 'true',
    },
    cluster: {
      rootNodes: clusterRootNodes,
    },
    retry: {
      maxAttempts:              _int(env, 'REDIS_MAX_RECONNECT_ATTEMPTS', 5, { min: 1 }),
      baseDelayMs:              _int(env, 'REDIS_RECONNECT_BASE_DELAY_MS', 100, { min: 1 }),
      maxDelayMs:               _int(env, 'REDIS_RECONNECT_MAX_DELAY_MS', 2_000, { min: 1 }),
      jitterRatio:              _ratio(env, 'REDIS_RECONNECT_JITTER_RATIO', 0.2),
      circuitBreakerCooldownMs: _int(env, 'REDIS_CIRCUIT_BREAKER_COOLDOWN_MS', 30_000, { min: 0 }),
    },
    valid: validationErrors.length === 0,
    validationErrors,
  };
}

module.exports = { resolveHaConfig };
