'use strict';

/**
 * QODIQA Disaster Recovery — Post-Restore Integrity Validation.
 *
 * Proves the restored state is not merely byte-identical to the backup but
 * actually FUNCTIONAL: each probe requires the REAL production module
 * (audit-log.js, policyStore.js, keyStore.js) in an isolated child process
 * with env vars pointed at the restored files, and exercises it exactly as
 * a live server startup would.  This is the "restored systems are fully
 * operational" / "no cryptographic values may change" proof — not a
 * reimplementation of chain/key verification logic.
 *
 * Child processes are used (rather than requiring these modules in-process)
 * because each one loads its file via a module-level singleton keyed to an
 * env var read once at require time — running the probes out-of-process is
 * both simpler and MORE faithful to what a real restored deployment does
 * (it also starts a fresh process).
 *
 * The PostgreSQL probe is the one
 * exception: it has no such singleton to isolate and needs an async `pg`
 * connection, so it runs in-process as a plain awaited function instead of
 * a child process.
 */

const path        = require('path');
const { execFileSync } = require('child_process');

const PROBES_DIR = path.join(__dirname, 'probes');

// Probed modules (keyStore.js in particular) emit their own structured JSON
// log lines to stdout via services/logger.js during a normal load/validate
// call — that is legitimate existing behaviour, not something a DR probe
// should have to suppress. The probe's OWN result is always the last line
// it prints, so parsing must target that line specifically rather than the
// full stdout blob (which is NDJSON-like, not a single JSON document).
function _lastJsonLine(text) {
  const lines = String(text).split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) throw new Error('no output to parse');
  return JSON.parse(lines[lines.length - 1]);
}

function _runProbe(probeFile, env) {
  try {
    const stdout = execFileSync(process.execPath, [path.join(PROBES_DIR, probeFile)], {
      env: { ...process.env, ...env },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { ...(stdout.trim() ? _lastJsonLine(stdout) : {}), exitCode: 0 };
  } catch (err) {
    // execFileSync throws on non-zero exit; stdout is still available on err.stdout.
    let parsed = { valid: false, reason: 'PROBE_CRASHED' };
    if (err.stdout) {
      try { parsed = _lastJsonLine(err.stdout); } catch { /* keep default */ }
    }
    return { ...parsed, exitCode: typeof err.status === 'number' ? err.status : 1 };
  }
}

/**
 * Runs the audit-chain integrity probe against whichever source is
 * authoritative for the deployment mode a given backup was taken under
 *.
 *
 * Single-node / file-authoritative mode: the REAL production
 * validateChainIntegrity() path (audit-log.js's
 * validateChainIntegrityFromDurableStoreChunked(), out-of-process) against a
 * restored audit.log file — unchanged behavior from.
 *
 * Distributed mode: the SAME production function (it already internally
 * dispatches to PostgreSQL when ORDERING_MODE === 'distributed' — see
 * src/core/audit/audit-log.js), invoked via auditChainPgProbe.js, against
 * the just-restored audit_chain table (the actual hash-chain table
 * loadChainFromPg()/qodiqa_audit_chain_full_read() read — NOT the
 * differently-named platform_audit_events table, a separate, unrelated
 * table this remediation initially and incorrectly targeted before being
 * corrected against audit-log.js's real dispatch). Requires a real PG
 * connection string; fails closed (does not silently fall back to "valid")
 * if one is not available.
 *
 * Extracted as its own export so
 * restore.js can require the audit-chain integrity check as a mandatory
 * gate on restore success — "restore -> integrity verification -> success",
 * never "restore -> success" — without duplicating the probe-invocation
 * logic that already lives here and is exercised by validateRestoredState()
 * below.
 *
 * @param {string|object} opts — EITHER a plain string (legacy/backward-compatible
 *   shorthand for `{ mode: 'single-node', auditLogPath: opts }`), OR an
 *   options object:
 *   @param {'single-node'|'distributed'} [opts.mode='single-node']
 *   @param {string} [opts.auditLogPath]      — single-node mode only
 *   @param {string} [opts.connectionString]  — distributed mode only, the
 *     RESTORE target's PG connection (never the original backup source)
 *   @param {number} [opts.expectedRowCount]  — distributed mode only, the
 *     backup manifest's own recorded audit_chain row count, used
 *     to detect a "vacuous pass" (the probe silently checking 0 rows
 *     because the PG connection never actually engaged) — see
 *     auditChainPgProbe.js's own header comment for why this matters.
 * @returns {object} probe result, always including `valid: boolean`.
 */
function verifyAuditChainIntegrity(opts) {
  if (typeof opts === 'string' || opts == null) {
    return opts
      ? _runProbe('auditChainProbe.js', { QODIQA_AUDIT_LOG: opts })
      : { valid: false, reason: 'AUDIT_LOG_NOT_RESTORED' };
  }

  const { mode = 'single-node', auditLogPath, connectionString, expectedRowCount, checkpointKeysPath } = opts;

  if (mode === 'distributed') {
    if (!connectionString) {
      return { valid: false, reason: 'PG_CONNECTION_STRING_NOT_AVAILABLE' };
    }
    const env = { QODIQA_PG_ENABLED: 'true', QODIQA_PG_URL: connectionString };
    if (expectedRowCount != null) env.QODIQA_DR_EXPECTED_AUDIT_ROW_COUNT = String(expectedRowCount);
    return _runProbe('auditChainPgProbe.js', env);
  }

  // M3: the restored checkpoint key store verifies a restored signed base record (fail closed without it).
  return auditLogPath
    ? _runProbe('auditChainProbe.js', { QODIQA_AUDIT_LOG: auditLogPath, ...(checkpointKeysPath ? { QODIQA_CHECKPOINT_KEYS_PATH: checkpointKeysPath } : {}) })
    : { valid: false, reason: 'AUDIT_LOG_NOT_RESTORED' };
}

/**
 * @param {object[]} restored — the `restored` array returned by runRestore(): [{ name, destPath }]
 * @param {object} [postgres] — { manifest, connectionString } — present only when the
 * backup included a Postgres component. `manifest` is
 *   the `postgres` field of the backup's manifest.json (what was dumped);
 *   `connectionString` is the restore target to validate against.
 * @param {object} [opts]
 * @param {'single-node'|'distributed'} [opts.auditOrderingMode='single-node'] —
 *   the backup manifest's own recorded `auditOrderingMode` — which source is
 *   authoritative for THIS backup's audit evidence. Passed through by the
 *   caller (cycle.js) from `manifest.auditOrderingMode`; never re-derived
 *   here from ambient environment, since restore may run on a different
 *   host/process than the one that took the backup.
 * @returns {Promise<{ overallValid: boolean, auditChain: object, policyStore: object, keyStore: object, postgres: object }>}
 */
async function validateRestoredState(restored, postgres, opts = {}) {
  const { auditOrderingMode = 'single-node', controlPlaneBackend = 'memory' } = opts;
  const byName = Object.fromEntries(restored.map(r => [r.name, r.destPath]));

  let auditChain;
  if (auditOrderingMode === 'distributed') {
    // Distributed-mode audit evidence lives in PostgreSQL, not in the
    // (correctly absent) local audit.log file — fail closed rather than
    // silently treat a backup that never captured the table as evidence of
    // anything. This is the fix for's finding: restore.js no
    // longer requires a file that a genuinely fresh distributed deployment
    // never produces, but distributed mode still demands PROOF of audit
    // continuity — just from its own authoritative source.
    if (!postgres || !postgres.manifest) {
      auditChain = { valid: false, reason: 'DISTRIBUTED_MODE_BACKUP_MISSING_POSTGRES_COMPONENT' };
    } else {
      const auditTable = Array.isArray(postgres.manifest.tables)
        ? postgres.manifest.tables.find(t => t.table === 'audit_chain')
        : null;
      if (!auditTable || auditTable.present !== true) {
        auditChain = { valid: false, reason: 'DISTRIBUTED_MODE_BACKUP_MISSING_AUDIT_TABLE' };
      } else {
        auditChain = verifyAuditChainIntegrity({
          mode: 'distributed',
          connectionString: postgres.connectionString,
          expectedRowCount: auditTable.rowCount,
        });
      }
    }
  } else {
    auditChain = byName.auditLog
      ? verifyAuditChainIntegrity({ mode: 'single-node', auditLogPath: byName.auditLog, checkpointKeysPath: byName.checkpointKeys })
      : verifyAuditChainIntegrity(byName.auditLog);
  }

  // INJ-3/#283: QODIQA_POLICY_STORE (not the _PATH-suffixed variant) is what
  // the live policy store (src/core/policy/store.js) actually reads.
  // with a PostgreSQL control plane (always, in production) the policies are rows of control_plane_records —
  // restored and row-count-checked with the database below — and the policy file is a legacy seed that does not exist.
  // That proof requires the database component; without it the policies were not restored at all.
  let policyStore;
  if (controlPlaneBackend === 'pg') {
    policyStore = postgres && postgres.manifest
      ? { valid: true, controlPlane: 'pg', reason: 'POLICIES_RESTORED_WITH_POSTGRES (control_plane_records, row count checked by the postgres probe)' }
      : { valid: false, controlPlane: 'pg', reason: 'POLICIES_IN_POSTGRES_BUT_NO_POSTGRES_COMPONENT' };
  } else {
    policyStore = byName.policyStore
      ? _runProbe('policyStoreProbe.js', { QODIQA_POLICY_STORE: byName.policyStore })
      : { valid: false, reason: 'POLICY_STORE_NOT_RESTORED' };
  }

  const keyStore = byName.keyStore
    ? _runProbe('keyStoreProbe.js', {
        QODIQA_KEYS_PATH: byName.keyStore,
        QODIQA_KEYS_ARCHIVE_PATH: byName.keyArchive || undefined,
      })
    : { valid: false, reason: 'KEY_STORE_NOT_RESTORED' };

  // Postgres validation only runs when the backup actually had a postgres
  // component — a file-only DR cycle (no QODIQA_PG_URL configured) is still
  // a complete proof for QODIQA's file-authoritative stores and must not be
  // penalized for a component it was never asked to back up.
  const postgresResult = postgres && postgres.manifest
    ? await require('./probes/postgresProbe').validatePostgresRestore(postgres.manifest, { connectionString: postgres.connectionString, auditOrderingMode }) //
    : { valid: true, skipped: true, reason: 'NO_POSTGRES_COMPONENT_IN_BACKUP' };

  // Fail closed on ambiguity: every probe MUST explicitly report valid:true.
  // A missing/undefined `valid` field (a probe contract violation) must NEVER
  // be treated as passing — that would make this validator itself fail open.
  const overallValid = auditChain.valid === true
    && policyStore.valid === true
    && keyStore.valid === true
    && postgresResult.valid === true;

  return { overallValid, auditChain, policyStore, keyStore, postgres: postgresResult };
}

module.exports = { validateRestoredState, verifyAuditChainIntegrity };

if (require.main === module) {
  const targetRoot = process.argv[2];
  if (!targetRoot) {
    console.error('Usage: node validate.js <targetRoot>');
    process.exit(2);
  }
  const { FILE_COMPONENTS } = require('./components');
  const restored = FILE_COMPONENTS
    .map(c => ({ name: c.name, destPath: path.join(targetRoot, c.restorePath) }));
  // CLI mode validates only the file-based components restored under
  // targetRoot — it has no access to the original backup's manifest.json
  // (and therefore no postgres component to check). Use dr:cycle for a
  // Postgres-inclusive validation pass.
  validateRestoredState(restored).then(result => {
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.overallValid ? 0 : 1;
  }).catch(err => {
    console.error(JSON.stringify({ overallValid: false, error: err.message }, null, 2));
    process.exitCode = 1;
  });
}
