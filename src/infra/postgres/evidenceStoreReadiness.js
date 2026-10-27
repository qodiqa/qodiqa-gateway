'use strict';

/**
 * Evidence-store boot readiness probe —.
 *
 * In the production profile (NODE_ENV=production — the same key REPLAY-2's
 * STRICT_REPLAY forcing already uses) evidence durability is mandatory:
 * server/startup.js refuses to start when PostgreSQL is not enabled, and —
 * this module's job — when PostgreSQL IS enabled but the consent/evidence
 * stores are not actually usable at boot. Without this second half, a
 * production deployment with a reachable-but-unmigrated (or
 * wrongly-permissioned) database would boot, serve, and silently degrade to
 * sign-only transparency + fail-closed consent denials — the exact silent
 * degradation exists to eliminate.
 *
 * The probe issues one cheap read per store, as the application role, against
 * the table each store actually depends on:
 *
 *   consentStore    → consent_records          (migration 007, ConsentStore.js)
 *   transparencyLog → transparency_log_entries         (registrar.js / logStore.js)
 *   evidenceChain   → evidence_chain_records   (migration 042, chainStore.js)
 *
 * `SELECT 1 FROM <table> LIMIT 1` proves, in one round-trip per store: the
 * connection works, the table exists (migrations ran), and the role can read
 * it (grants/RLS are not broken for the app role). It never writes.
 *
 * This module never exits the process itself — it reports; the startup gate
 * in server/startup.js (mirroring the STRICT_REPLAY gate) decides. Callers
 * outside the production gate may also use it diagnostically.
 */

const pgPool   = require('./pool');
const { emit } = require('../../../services/logger');

// Store name → the table its readiness is defined by. Table names are
// hardcoded identifiers from this repo's own migrations (never interpolated
// from input).
const STORE_TABLES = Object.freeze({
  consentStore:    'consent_records',
  transparencyLog: 'transparency_log_entries',
  evidenceChain:   'evidence_chain_records',
});

/**
 * Probe every consent/evidence store once.
 *
 * @returns {Promise<{
 *   ok: boolean,
 *   cause: null | 'PG_DISABLED' | 'STORE_NOT_READY',
 *   stores: Record<string, boolean>,
 *   failures: Array<{ store: string, table: string, error: string }>,
 * }>}
 */
async function probeEvidenceStores() {
  if (!pgPool.isEnabled()) {
    return { ok: false, cause: 'PG_DISABLED', stores: {}, failures: [] };
  }

  const stores   = {};
  const failures = [];

  for (const [store, table] of Object.entries(STORE_TABLES)) {
    try {
      await pgPool.query(`SELECT 1 FROM ${table} LIMIT 1`, [], `evidence_readiness_${store}`);
      stores[store] = true;
    } catch (err) {
      stores[store] = false;
      failures.push({ store, table, error: err.message });
    }
  }

  const ok = failures.length === 0;
  if (!ok) {
    try {
      emit('ERROR', 'EVIDENCE_STORE_READINESS_FAILED', {
        stores,
        failures,
        message: 'One or more consent/evidence stores failed the boot readiness probe.',
      });
    } catch { /* logging must never affect the probe verdict */ }
  }
  return { ok, cause: ok ? null : 'STORE_NOT_READY', stores, failures };
}

module.exports = { probeEvidenceStores, STORE_TABLES };
