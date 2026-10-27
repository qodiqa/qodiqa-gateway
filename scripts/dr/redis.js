'use strict';

/**
 * QODIQA Disaster Recovery — Redis / Nonce Store component (DIAGNOSTIC ONLY).
 *
 * IMPORTANT — read before wiring this into any real restore path:
 *
 * The nonce store (src/validation/nonceStore.js) is INTENTIONALLY ephemeral.
 * Its correctness property is "every requestId is accepted at most once
 * within its TTL window" — it is not a source of truth for anything, and
 * replaying its contents into a restored deployment is not meaningful:
 *   - Keys that expired between snapshot and restore would incorrectly
 *     "un-expire" if written back with their original (now-elapsed) TTL
 *     clamped to some arbitrary value — there is no safe way to preserve
 *     "time already spent" across a snapshot/restore gap.
 *   - An EMPTY nonce store after restore is SAFE by design: QODIQA fails
 *     closed (blocks) on nonce store unavailability, and a fresh empty
 *     store simply means "no request has used a nonce yet in this store's
 *     lifetime" — never a security regression, at most a theoretical
 *     re-use window bounded by whatever TTL the original artifacts still
 *     had outstanding at snapshot time.
 *
 * Real Redis durability is Redis's own job (AOF/RDB persistence + replication
 * — see docs/deployment/redis-persistence.md and src/infra/redis/persistenceCheck.js,
 * which QODIQA already checks operationally). This module exists ONLY to
 * give operators/DR-drills visibility into "how many nonces existed at
 * backup time" as a diagnostic — restorePostgres-style replay is
 * deliberately NOT implemented here.
 */

const fs   = require('fs');
const path = require('path');

const KEY_PREFIX = 'qodiqa:req:v2:';

/**
 * Snapshot key count + TTL distribution (NOT the keys themselves — key
 * contents carry no information beyond "exists", and enumerating exact
 * requestId values into a backup file would needlessly widen the blast
 * radius of a leaked backup for zero DR benefit).
 *
 * @param {string} targetDir
 * @param {{ url?: string }} [opts]
 * @returns {Promise<{ snapshotAt: string, keyCount: number, sampleTtlsMs: number[], archiveFile: string, note: string }>}
 */
async function snapshotRedis(targetDir, opts = {}) {
  const { createClient } = require('redis');
  const client = createClient({ url: opts.url || process.env.REDIS_URL });
  await client.connect();

  const NOTE = 'DIAGNOSTIC ONLY — nonce store is intentionally not restored; see redis.js header comment.';

  try {
    // node-redis v5 (the pinned major) passes/returns the SCAN cursor as a
    // string — a numeric 0 throws "arguments[1] must be of type string | Buffer".
    let cursor = '0';
    let keyCount = 0;
    const sampleTtlsMs = [];

    do {
      const res = await client.scan(cursor, { MATCH: `${KEY_PREFIX}*`, COUNT: 500 });
      cursor = String(res.cursor);
      for (const key of res.keys) {
        keyCount++;
        if (sampleTtlsMs.length < 20) {
          const pttl = await client.pTTL(key);
          if (pttl >= 0) sampleTtlsMs.push(pttl);
        }
      }
    } while (cursor !== '0');

    const snapshot = {
      snapshotAt: new Date().toISOString(),
      keyCount,
      sampleTtlsMs,
      note: NOTE,
    };

    const archiveFile = 'redis_nonces.json';
    fs.writeFileSync(path.join(targetDir, archiveFile), JSON.stringify(snapshot, null, 2), 'utf8');

    return { ...snapshot, archiveFile };
  } finally {
    await client.disconnect();
  }
}

module.exports = { snapshotRedis, KEY_PREFIX };
