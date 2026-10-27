'use strict';

/**
 * phase 8 — reference model of the KEYSTORE-SIDE half of the fenced rotation protocol.
 *
 * services/artifact/keyStore.js is outside this work item's scope, so the multi-process fencing test
 * (test/distributed/rotationLockFencing.integration.test.js) drives this stand-in instead of keys.json. It models
 * exactly the change recorded for keyStore.js:
 * 1. re-read the file immediately before the commit;
 *   2. refuse (KEYSTORE_STALE_FENCE) unless the caller's fence is strictly greater than the last fence recorded for
 *      that client in the file;
 *   3. record the new fence in the SAME write as the mutation;
 * 4. write a uniquely named temp file and rename it over the target.
 *
 * Residual (stated, not hidden): steps 1–4 are not one atomic operation on a plain file. A holder paused between
 * step 2 and step 4 still renames late. The fence closes the window between the LOCK and the commit (the
 * defect); closing the check→rename gap needs a resource with a conditional write (a PostgreSQL row
 * `UPDATE … WHERE last_fence < $fence`) — an owner/design item, see the record.
 */

const fs = require('fs');
const crypto = require('crypto');

function initStore(file) {
  fs.writeFileSync(file, JSON.stringify({ version: 0, fences: {}, history: [] }));
}

function readStore(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * @param {string} file
 * @param {string} clientId
 * @param {number|undefined} fence  the fencing token from rotationLock.acquire(); undefined models the pre-fix,
 *                                  unfenced commit (accepted unconditionally) and is used ONLY by the evidence
 *                                  experiment that documents the defect.
 * @param {string} by               who commits (recorded in the history)
 * @param {{ enforceFence?: boolean }} [opts]
 */
function fencedCommit(file, clientId, fence, by, { enforceFence = true } = {}) {
  const cur = readStore(file);
  const last = cur.fences[clientId] || 0;
  if (enforceFence && !(Number.isSafeInteger(fence) && fence > last)) {
    const e = new Error(`KEYSTORE_STALE_FENCE: fence ${fence} is not greater than the last accepted fence ${last} for ${clientId}`);
    e.code = 'KEYSTORE_STALE_FENCE';
    throw e;
  }
  const version = cur.version + 1;
  const next = {
    version,
    fences: { ...cur.fences, ...(fence !== undefined ? { [clientId]: Math.max(last, fence) } : {}) },
    history: [...cur.history, { by, clientId, fence: fence === undefined ? null : fence, version }],
  };
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(next));
  fs.renameSync(tmp, file);
  return { version };
}

module.exports = { initStore, readStore, fencedCommit };
