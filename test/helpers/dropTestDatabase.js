'use strict';

/**
 * drop a test suite's OWN disposable database reliably.
 *
 * Observed leak: a suite's fire-and-forget PostgreSQL work (e.g. the
 * distributed-mode evidence write) can still be in flight after the suite's pgPool.shutdown(); it
 * lazily re-creates a role pool (rolePools._ensure) and attaches a backend of ANOTHER role
 * (qodiqa_system). qodiqa_test cannot terminate a foreign-role backend without pg_signal_backend
 * (CLAUDE.md residual — an owner privilege decision), so DROP ... WITH (FORCE) is refused
 * ("permission denied to terminate process") and the database leaks.
 *
 * Each attempt first re-runs the suite's own shutdown (closing any pool re-created since, including
 * its role pools), then drops WITH (FORCE); a refused attempt waits and retries. It never touches
 * any database but the one named, and reports — never hides — the backends still attached if it
 * finally gives up.
 *
 * @param {import('pg').Pool} maintenancePool  a pool on the maintenance database (the suite's own)
 * @param {string} name                        the suite's generated database name
 * @param {{ shutdown?: () => Promise<void>, attempts?: number }} [opts]
 * @returns {Promise<{ dropped: boolean, attempts: number, error?: string, attached?: object[] }>}
 */
async function dropTestDatabase(maintenancePool, name, { shutdown = async () => {}, attempts = 6 } = {}) {
  if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error(`dropTestDatabase: refusing unexpected database name ${JSON.stringify(name)}`);
  let lastError = null;
  for (let i = 1; i <= attempts; i++) {
    await shutdown().catch(() => {});
    try {
      await maintenancePool.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
      return { dropped: true, attempts: i };
    } catch (err) {
      lastError = err;
      await new Promise((r) => setTimeout(r, 200 * i));
    }
  }
  const attached = await maintenancePool.query('SELECT usename, application_name, state FROM pg_stat_activity WHERE datname = $1', [name])
    .then((r) => r.rows).catch(() => []);
  return { dropped: false, attempts, error: lastError && lastError.message, attached };
}

module.exports = { dropTestDatabase };
