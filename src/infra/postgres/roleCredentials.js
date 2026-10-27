'use strict';

/**
 * — migration-created LOGIN
 * roles and their PUBLISHED placeholder passwords.
 *
 * Migrations 002/038/060/065/067 create LOGIN roles with literal placeholder
 * passwords (`REPLACE_WITH_VAULT_SECRET_*`). They are in the repository, so
 * they are public. Already-applied migrations are never edited, so a fresh
 * install always passes through this state. Boot validation used to check
 * only the passwords the gateway itself is configured with, which left
 * `qodiqa_read` (cross-tenant SELECT) and `qodiqa_backup` (BYPASSRLS) usable
 * with their published passwords indefinitely.
 *
 * This module PROVES, rather than assumes, that no migration-created role
 * accepts its published placeholder. For every role it opens a connection
 * as that role with the placeholder password and classifies the result:
 *
 *   ACCEPTED      the placeholder logs in            → VIOLATION
 *   NOT_PERMITTED placeholder correct but NOLOGIN    → safe (cannot log in)
 *   REJECTED      password authentication failed     → safe (rotated, or role
 *                 (28P01; PostgreSQL deliberately       absent — PG does not
 *                 reports this for a missing role too)   distinguish the two)
 *   HBA_REJECTED  pg_hba has no entry for this host   → UNPROVEN from here
 *   INCONCLUSIVE  any other error (network, TLS…)    → UNPROVEN
 *
 * It never changes a role. Rotation and hardening are operator actions
 * (scripts/db/role-credentials.js, docs/operations/database-role-management.md).
 *
 * The role list below is pinned against the migrations themselves by
 *:
 * a new CREATE ROLE … PASSWORD '<literal>' anywhere in the migration chain
 * fails that test until it is added here.
 */

const { Client } = require('pg');
const { resolvePgSslOptions } = require('./pgSsl');

const MIGRATION_LOGIN_ROLES = Object.freeze([
  { role: 'qodiqa_app',       placeholder: 'REPLACE_WITH_VAULT_SECRET_APP',       migration: '002', purpose: 'request-serving application pool (pool.js)', envPassword: 'QODIQA_PG_PASSWORD' },
  { role: 'qodiqa_read',      placeholder: 'REPLACE_WITH_VAULT_SECRET_READ',      migration: '002', purpose: 'legacy read-only role (dashboards); no runtime consumer', envPassword: null },
  { role: 'qodiqa_mig',       placeholder: 'REPLACE_WITH_VAULT_SECRET_MIG',       migration: '002', purpose: 'schema migrations (owner of most tables, BYPASSRLS)', envPassword: 'QODIQA_PG_MIG_PASSWORD' },
  { role: 'qodiqa_retention', placeholder: 'REPLACE_WITH_VAULT_SECRET_RETENTION', migration: '038', purpose: 'audit retention/pruning (retentionPool.js)', envPassword: 'QODIQA_PG_RETENTION_PASSWORD' },
  { role: 'qodiqa_system',    placeholder: 'REPLACE_WITH_VAULT_SECRET_SYSTEM',    migration: '060', purpose: 'platform integrity / background cross-tenant reader (rolePools.js)', envPassword: 'QODIQA_PG_SYSTEM_PASSWORD' },
  { role: 'qodiqa_reporting', placeholder: 'REPLACE_WITH_VAULT_SECRET_REPORTING', migration: '060', purpose: 'RBAC-gated operator consoles (rolePools.js)', envPassword: 'QODIQA_PG_REPORTING_PASSWORD' },
  { role: 'qodiqa_control',   placeholder: 'REPLACE_WITH_VAULT_SECRET_CONTROL',   migration: '065', purpose: 'control-plane store (rolePools.js)', envPassword: 'QODIQA_PG_CONTROL_PASSWORD' },
  { role: 'qodiqa_backup',    placeholder: 'REPLACE_WITH_VAULT_SECRET_BACKUP',    migration: '067', purpose: 'backup jobs only (pg_dump / DR dump; BYPASSRLS)', envPassword: 'QODIQA_PG_BACKUP_PASSWORD' },
]);

const SAFE = new Set(['NOT_PERMITTED', 'REJECTED']);

function classifyError(err) {
  const code = err && err.code;
  const msg = String((err && err.message) || '');
  if (code === '28P01') return 'REJECTED';
  if (code === '28000' && /not permitted to log in/i.test(msg)) return 'NOT_PERMITTED';
  if (code === '28000' && /pg_hba\.conf/i.test(msg)) return 'HBA_REJECTED';
  // pg_hba "reject" lines and missing roles under trust/ident surface as 28000 too.
  if (code === '28000' && /does not exist/i.test(msg)) return 'REJECTED';
  return 'INCONCLUSIVE';
}

/** Connection target shared with pool.js / rolePools.js (same host/port/db/TLS), credentials swapped. */
function targetFromEnv(env = process.env) {
  const ssl = resolvePgSslOptions(env) || false;
  if (env.QODIQA_PG_URL) {
    const u = new URL(env.QODIQA_PG_URL);
    return { host: u.hostname, port: parseInt(u.port || '5432', 10), database: decodeURIComponent(u.pathname.slice(1)) || 'qodiqa', ssl };
  }
  return {
    host: env.QODIQA_PG_HOST || 'localhost',
    port: parseInt(env.QODIQA_PG_PORT || '5432', 10),
    database: env.QODIQA_PG_DATABASE || 'qodiqa',
    ssl,
  };
}

/**
 * Probe one role. Never logs or returns the password. `ClientImpl` is injectable for tests.
 * @returns {Promise<{role, migration, result, code: string|null}>}
 */
async function probeRole(spec, target, { timeoutMs = 3000, ClientImpl = Client } = {}) {
  const client = new ClientImpl({
    host: target.host, port: target.port, database: target.database, ssl: target.ssl,
    user: spec.role, password: spec.placeholder,
    connectionTimeoutMillis: timeoutMs, application_name: 'qodiqa-role-credential-probe',
  });
  // A late socket error after the probe has settled must never become an uncaught 'error'.
  if (typeof client.on === 'function') client.on('error', () => {});
  try {
    await client.connect();
    try { await client.end(); } catch { /* already closed */ }
    return { role: spec.role, migration: spec.migration, result: 'ACCEPTED', code: null };
  } catch (err) {
    try { await client.end(); } catch { /* never connected */ }
    return { role: spec.role, migration: spec.migration, result: classifyError(err), code: (err && err.code) || null };
  }
}

/**
 * Probe every migration-created LOGIN role.
 * @returns {Promise<{ok: boolean, proven: boolean, violations: object[], unproven: object[], results: object[]}>}
 *   ok      — no role ACCEPTED its placeholder
 *   proven  — ok AND every role was classified SAFE (nothing HBA_REJECTED / INCONCLUSIVE)
 */
async function probeMigrationRoles({ env = process.env, roles = MIGRATION_LOGIN_ROLES, target, timeoutMs, ClientImpl } = {}) {
  const t = target || targetFromEnv(env);
  const results = [];
  for (const spec of roles) results.push(await probeRole(spec, t, { timeoutMs, ClientImpl }));
  const violations = results.filter((r) => r.result === 'ACCEPTED');
  const unproven = results.filter((r) => r.result !== 'ACCEPTED' && !SAFE.has(r.result));
  return { ok: violations.length === 0, proven: violations.length === 0 && unproven.length === 0, violations, unproven, results };
}

/** True when a configured password is one of the published migration placeholders. */
function isMigrationPlaceholder(value) {
  return typeof value === 'string' && /^REPLACE_WITH_VAULT_SECRET_[A-Z_]+$/.test(value.trim());
}

module.exports = { MIGRATION_LOGIN_ROLES, probeRole, probeMigrationRoles, classifyError, targetFromEnv, isMigrationPlaceholder };
