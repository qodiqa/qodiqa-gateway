'use strict';

/**
 * Policy Store restore probe — runs as a CHILD PROCESS (see validate.js) so
 * QODIQA_POLICY_STORE can point at a restored file in isolation.
 * Exercises the real production module (src/core/policy/store.js).
 *
 * INJ-3/#283: previously required the dead policy/policyStore.js (zero
 * production callers, superseded by this module) and read the unrelated
 * QODIQA_POLICY_STORE_PATH env var that module used — a DR-tooling
 * env-var/module mismatch that only mattered once a deployment customized
 * the policy store path, at which point this probe was silently validating
 * against a file the live store never actually reads.
 */

// THROUGHPUT-12: services/logger.js batches INFO/WARN/ERROR stdout writes and
// flushes them asynchronously — this probe's own result line below is parsed
// positionally by validate.js's _lastJsonLine(), so any not-yet-flushed
// structured log line must be drained BEFORE that print (flush() does its
// actual work synchronously — see that file's header comment).
const _flushLogger = () => require('../../../services/logger').flush();

let policyStore;
try {
  policyStore = require('../../../src/core/policy/store.js');
} catch (err) {
  _flushLogger();
  console.log(JSON.stringify({ valid: false, reason: `MODULE_LOAD_FAILED: ${err.message}` }));
  process.exit(1);
}

try {
  const { total } = policyStore.listPolicies({ status: 'ACTIVE', pageSize: Number.MAX_SAFE_INTEGER });
  _flushLogger();
  console.log(JSON.stringify({ valid: true, policyCount: total }));
  process.exit(0);
} catch (err) {
  _flushLogger();
  console.log(JSON.stringify({ valid: false, reason: `${err.code || 'ERROR'}: ${err.message}` }));
  process.exit(1);
}
