'use strict';

/**
 * Redis persistence diagnostics for replay protection integrity.
 *
 * Replay protection depends on nonce keys surviving Redis restarts.  If Redis
 * loses nonce state (AOF off, crash before flush), previously used nonces
 * become replayable until their original TTL elapses — a deterministic
 * security regression.
 *
 * This module queries the live Redis config and emits structured diagnostics
 * so operators can detect unsafe persistence modes before they affect
 * production replay guarantees.
 *
 * Safe persistence modes:
 *   appendonly yes + appendfsync everysec   — ≤1s risk window on crash
 *   appendonly yes + appendfsync always     — no risk window (highest durability)
 *
 * Unsafe persistence modes:
 *   appendonly no                            — all nonce state lost on restart
 *   appendonly yes + appendfsync no          — OS decides flush; up to ~30s lost
 *   CONFIG GET disabled / unknown            — cannot verify; treat as unsafe
 */

const SAFE_APPENDFSYNC_MODES = new Set(['everysec', 'always']);

/**
 * @typedef {object} PersistenceDiagnostics
 * @property {boolean}      safe            true only if AOF + safe appendfsync confirmed
 * @property {boolean|null} aofEnabled      null if CONFIG GET failed
 * @property {string|null}  appendfsync     'everysec'|'always'|'no'|'unknown'|null
 * @property {number|null}  lastSave        epoch-ms of last RDB save, or null
 * @property {string|null}  aofCurrentSize  AOF file size string from INFO, or null
 * @property {string[]}     warnings        operator-readable risk descriptions
 * @property {string}       [error]         set if the check itself threw
 */

/**
 * Query a connected Redis client for persistence configuration and return
 * structured diagnostics.
 *
 * Never throws — all errors are captured in the returned object so callers
 * can always inspect and log the result without a try/catch.
 *
 * @param  {import('redis').RedisClientType} client  connected Redis client
 * @returns {Promise<PersistenceDiagnostics>}
 */
async function checkRedisPersistence(client) {
  try {
    const [aofCfg, fsyncCfg, persistInfo] = await Promise.all([
      client.configGet('appendonly'),
      client.configGet('appendfsync'),
      client.info('persistence'),
    ]);

    const aofEnabled  = (aofCfg?.appendonly   ?? 'no') === 'yes';
    const appendfsync =  fsyncCfg?.appendfsync ?? 'unknown';

    // Parse INFO persistence section (key:value lines separated by \r\n)
    const info = {};
    for (const line of (persistInfo ?? '').split(/\r?\n/)) {
      const sep = line.indexOf(':');
      if (sep > 0) info[line.slice(0, sep).trim()] = line.slice(sep + 1).trim();
    }

    // rdb_last_save_time is Unix seconds; convert to epoch-ms for consistency
    const lastSave       = info['rdb_last_save_time']
      ? parseInt(info['rdb_last_save_time'], 10) * 1_000
      : null;
    const aofCurrentSize = info['aof_current_size'] ?? null;

    const warnings = [];

    if (!aofEnabled) {
      warnings.push(
        'AOF_DISABLED: Redis AOF persistence is off. Nonce keys are stored only in memory. ' +
        'A Redis restart or crash will discard all registered nonces. ' +
        'Previously used nonces become replayable until their original TTL elapses, ' +
        'creating a deterministic replay attack window. ' +
        'Fix: set appendonly yes and appendfsync everysec in redis.conf.',
      );
    }

    if (aofEnabled && appendfsync === 'no') {
      warnings.push(
        'APPENDFSYNC_NO: AOF is enabled but appendfsync is set to no. ' +
        'Redis delegates all flush scheduling to the OS. Up to ~30 seconds of nonce ' +
        'writes can be lost on a crash, making those nonces replayable. ' +
        'Fix: set appendfsync everysec (≤1s risk window) or appendfsync always (no window).',
      );
    }

    if (appendfsync === 'unknown') {
      warnings.push(
        'APPENDFSYNC_UNKNOWN: Could not read appendfsync mode from Redis CONFIG GET. ' +
        'Persistence guarantees cannot be verified. ' +
        'Ensure the Redis ACL grants CONFIG GET permission to this client.',
      );
    }

    const safe = aofEnabled && SAFE_APPENDFSYNC_MODES.has(appendfsync);

    return { safe, aofEnabled, appendfsync, lastSave, aofCurrentSize, warnings };

  } catch (err) {
    return {
      safe:           false,
      aofEnabled:     null,
      appendfsync:    null,
      lastSave:       null,
      aofCurrentSize: null,
      warnings: [
        `PERSISTENCE_CHECK_FAILED: Redis persistence config query failed — ${err.message}. ` +
        'Persistence guarantees cannot be verified. ' +
        'Ensure Redis is accessible and the client has CONFIG GET permission.',
      ],
      error: err.message,
    };
  }
}

module.exports = { checkRedisPersistence };
