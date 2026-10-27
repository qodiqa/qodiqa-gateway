'use strict';

/**
 * QODIQA Tenant Context — Component #31
 *
 * Single canonical module for PostgreSQL tenant context operations.
 * All tenant-scoped database operations must use this module to set context.
 *
 * MECHANISM:
 *   set_config('qodiqa.tenant_id', tenantId, true)
 *   The third param (true) = transaction-local.
 *   Context automatically resets when the transaction commits or rolls back.
 *   This guarantees no context leaks across pooled connections.
 *
 * USAGE:
 *   Always call inside a transaction via pool.withTenantTransaction().
 *   Never call setLocal() outside a transaction — session-level settings
 *   persist across connection pool reuse, causing cross-tenant leakage.
 *
 * FAIL CLOSED:
 *   validate() throws TypeError on any invalid tenantId.
 *   RLS policies treat NULL context as "no tenant" → 0 tenant-specific rows.
 *   Empty string context is equivalent to NULL (cleared by qodiqa_current_tenant()).
 *
 * POOL SAFETY:
 *   The transaction-local flag means context always resets at transaction end.
 *   It is impossible for Tenant A's context to persist to Tenant B's next request
 *   on the same pooled connection.
 */

// Matches the QODIQA tenant ID format: 1–64 chars, alphanumeric + _ + -
// Mirrors the pattern in src/core/tenancy/tenantRegistry.js
const TENANT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * Validate a tenant ID string.
 * Throws TypeError for any value that would be unsafe to set as a session variable.
 *
 * @param {*} tenantId
 * @throws {TypeError}
 */
function validate(tenantId) {
  if (tenantId === null || tenantId === undefined || typeof tenantId !== 'string') {
    throw new TypeError(
      `TenantContext: tenantId must be a non-empty string, got ${JSON.stringify(tenantId)}`,
    );
  }
  if (tenantId === '') {
    throw new TypeError('TenantContext: tenantId must not be empty');
  }
  if (!TENANT_ID_RE.test(tenantId)) {
    throw new TypeError(
      `TenantContext: invalid tenantId format "${tenantId}" — ` +
      'must match [A-Za-z0-9_-]{1,64}',
    );
  }
}

/**
 * Set the tenant context for the current transaction (transaction-local).
 *
 * MUST be called inside a transaction.
 * The context resets automatically when the transaction ends.
 * This is the only safe mechanism for pooled connections.
 *
 * @param {{ query: Function }} client  — pg client or tx object with .query()
 * @param {string} tenantId            — validated tenant identifier
 * @returns {Promise<void>}
 * @throws {TypeError}  if tenantId is invalid
 */
async function setLocal(client, tenantId) {
  validate(tenantId);
  // set_config(name, value, is_local):
  //   is_local = true → resets when current transaction ends (commit or rollback)
  //   is_local = false → persists for the entire session (DANGEROUS for pooling)
  await client.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [tenantId]);
}

/**
 * Clear the tenant context for the current transaction (transaction-local).
 * Sets to empty string, which qodiqa_current_tenant() converts to NULL.
 *
 * @param {{ query: Function }} client
 * @returns {Promise<void>}
 */
async function clearLocal(client) {
  await client.query("SELECT set_config('qodiqa.tenant_id', '', true)", []);
}

module.exports = { validate, setLocal, clearLocal };
