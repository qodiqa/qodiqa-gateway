'use strict';

/**
 * Development-only consent provisioning.
 *
 * Extends the same philosophy already used by scripts/lib/keyStoreProvisioning.js
 * and scripts/lib/devEnvironment.js for signing keys, transparency keys, and
 * Redis: idempotently ensure a piece of infrastructure exists for a fresh
 * `npm run dev` invocation, using the exact same code paths production uses,
 * never a parallel/weaker implementation.
 *
 * What this module does NOT do:
 *   - It never disables, stubs, or bypasses REQUIRE_CONSENT, ConsentVerifier,
 *     or any other enforcement code. Consent is still evaluated for real on
 *     every request; this module only pre-seeds a granted record so that
 *     evaluation can return ALLOW instead of CONSENT_NOT_FOUND.
 *   - It never inserts rows directly. Every write goes through
 *     src/core/consent (the same registry.grant() production callers use)
 *     and src/infra/postgres/migrate.js (the same migration runner
 *     `node src/infra/postgres/migrate.js` uses in every environment).
 *   - It never runs unless the developer has explicitly opted in via
 *     QODIQA_PG_ENABLED=true — with that flag unset (the default), behavior
 *     is byte-for-byte identical to before this module existed.
 *   - It never touches a database other than QODIQA_PG_DATABASE for this
 *     run, and never grants consent for any actor_id other than the real
 *     signing IDENTITY's own id (not the tenant's artifact-signing key's
 * id — a distinct value from a distinct store; see the fix
 *     comment at this module's grant() call site for why the two were once
 *     conflated) created moments earlier in this same invocation of
 *     prepareIsolatedEnvironment().
 *
 * Failure mode: best-effort. Unlike Redis (a hard, fail-fast prerequisite
 * for server.js to start at all), PostgreSQL-backed consent is optional —
 * a misconfigured local Postgres must not prevent `npm run dev` from
 * starting. Any failure here is logged as a warning and the caller
 * continues; the running server will simply BLOCK consent-gated requests
 * with CONSENT_STORE_UNAVAILABLE or CONSENT_NOT_FOUND, exactly as it does
 * today when this feature is not opted into.
 */

const crypto = require('crypto');
const { Pool } = require('pg');
const { assertBootstrapDatabaseIsolated } = require('./bootstrapIsolationGuard');

// Mirrors services/providers/router.js's REGISTRY keys exactly, and the same
// env-var set scripts/lib/devEnvironment.js already checks for
// hasAnyProviderConfigured() — duplicated here (read-only) rather than
// imported, since devEnvironment.js only exposes a boolean "any configured",
// not which specific providers.
const PROVIDER_ENV_MAP = Object.freeze({
  openai:    'OPENAI_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  gemini:    'GEMINI_API_KEY',
  mistral:   'MISTRAL_API_KEY',
  llama:     'LLAMA_BASE_URL',
  local:     'LOCAL_BASE_URL',
});

// A conservative, safe-identifier check for the database name we may issue
// a CREATE DATABASE for. CREATE DATABASE cannot be parameterized like a
// normal query, so the name is validated against this pattern before any
// string interpolation is used to build that statement.
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

function configuredProviders() {
  return Object.entries(PROVIDER_ENV_MAP)
    .filter(([, envVar]) => !!process.env[envVar])
    .map(([provider]) => provider);
}

/**
 * Ensure the target database (QODIQA_PG_DATABASE, default 'qodiqa') exists,
 * connecting to a maintenance database (default 'postgres') to check/create
 * it. No-op if it already exists.
 *
 * B4 (Option C, item-23 discipline — see ITEM-23-REMEDIATION-REPORT.md §2):
 * uses QODIQA_PG_TEST_USER/QODIQA_PG_TEST_PASSWORD (the qodiqa_test role,
 * provisioned with CREATEDB per FINDING-F2-PREVENTION-LAYERS-REMEDIATION-
 * REPORT.md §1) via this function's own explicitly-configured Pool — never
 * process.env.QODIQA_PG_USER/PASSWORD, the ambient qodiqa_app identity every
 * other connection (including the spawned server.js child, which inherits
 * process.env) uses. Deliberately NO fallback to QODIQA_PG_USER/PASSWORD:
 * qodiqa_app is not expected to hold CREATEDB, so falling back to it would
 * either fail anyway or, worse, succeed unexpectedly on a database where it
 * does — an unpredictable privilege surface this function must not rely on.
 * Missing QODIQA_PG_TEST_USER is itself the failure case; the caller decides
 * how to respond (see provisionDevConsent's FATAL-vs-warn split below).
 *
 * @returns {Promise<{ created: boolean }>} whether this call actually
 *   created the database (true) or found it already present (false) — OPS-01
 *   (D2): callers use this to distinguish "created but then failed to
 *   migrate" (fail loudly) from "pre-existing, unrelated migration failure"
 *   (unchanged best-effort warning).
 */
async function ensureDatabaseExists({ log, warn }) {
  const dbName = process.env.QODIQA_PG_DATABASE || 'qodiqa';
  if (!SAFE_IDENTIFIER.test(dbName)) {
    throw new Error(`QODIQA_PG_DATABASE="${dbName}" is not a safe SQL identifier — refusing to auto-create it. Create it manually.`);
  }

  if (!process.env.QODIQA_PG_TEST_USER) {
    throw new Error(
      'QODIQA_PG_TEST_USER is not set. Creating/verifying a development database requires the ' +
      'qodiqa_test role (CREATEDB) via QODIQA_PG_TEST_USER/QODIQA_PG_TEST_PASSWORD in .env — see ' +
      'FINDING-F2-PREVENTION-LAYERS-REMEDIATION-REPORT.md §1.',
    );
  }

  const maintenancePool = new Pool({
    host:     process.env.QODIQA_PG_HOST || 'localhost',
    port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
    user:     process.env.QODIQA_PG_TEST_USER,
    password: process.env.QODIQA_PG_TEST_PASSWORD,
    ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
    connectionTimeoutMillis: 5000,
  });

  try {
    const existing = await maintenancePool.query('SELECT 1 FROM pg_database WHERE datname = $1', [dbName]);
    if (existing.rows.length) {
      log(`Development database "${dbName}" already exists.`);
      return { created: false };
    }
    log(`Development database "${dbName}" does not exist — creating it...`);
    // Safe: dbName was validated against SAFE_IDENTIFIER above.
    await maintenancePool.query(`CREATE DATABASE "${dbName}"`);
    log(`Created development database "${dbName}".`);
    return { created: true };
  } finally {
    await maintenancePool.end().catch(() => {});
  }
}

/**
 * Idempotently provision a development PostgreSQL database, schema, and a
 * consent grant for the freshly generated dev signing key — but only if the
 * developer has opted in via QODIQA_PG_ENABLED=true.
 *
 * @param {object} opts
 * @param {string} opts.clientId          — the dev client/tenant id (matches devEnvironment.js's clientId)
 * @param {(msg: string) => void} [opts.log]
 * @param {(msg: string) => void} [opts.warn]
 * @returns {Promise<{ attempted: boolean, granted?: string[] }>}
 */
async function provisionDevConsent({ clientId, log = () => {}, warn = () => {} }) {
  if (process.env.QODIQA_PG_ENABLED !== 'true') {
    log(
      'QODIQA_PG_ENABLED is not "true" — skipping development consent provisioning. ' +
      'Consent-gated executions will BLOCK with CONSENT_STORE_UNAVAILABLE, exactly as they ' +
      'would in any environment with this flag unset. Set QODIQA_PG_ENABLED=true plus the ' +
      'QODIQA_PG_* connection variables (see src/infra/postgres/pool.js) to exercise the full ' +
      'pipeline, including consent, in development.',
    );
    return { attempted: false };
  }

  log('QODIQA_PG_ENABLED=true — provisioning the development PostgreSQL schema and consent grant...');

  // B4 isolation-gap fix (2026-08-02 program-doc entry, audit_chain seq 157
  // incident): bootstrap-dev.js redirects the audit-log FILE to a fresh
  // per-boot temp dir, but QODIQA_PG_* was left fully ambient — a PG-enabled
  // dev boot with no explicit QODIQA_PG_DATABASE wrote real, permanent rows
  // (this consent grant, and independently the audit_chain PG mirror via
  // pg-audit-backend.js in the spawned server.js) into the shared "qodiqa"
  // database, with no file-side counterpart — contradicting this script's
  // own "every invocation is fully independent" guarantee.
  //
  // Fix: when the developer has not explicitly pointed QODIQA_PG_DATABASE at
  // a database of their own choosing, generate a fresh, uniquely-named
  // disposable database for this boot only. Setting it on process.env here
  // (before the caller spawns server.js as a child inheriting this same
  // env) isolates BOTH this process's own pool AND the spawned server's
  // independent one — never the shared "qodiqa" database. An explicit
  // QODIQA_PG_DATABASE is always left untouched (a deliberate operator
  // choice, e.g. to reuse seeded local data).
  let generatedDevDbName = null;
  if (!process.env.QODIQA_PG_DATABASE) {
    generatedDevDbName = `qodiqa_dev_${crypto.randomBytes(4).toString('hex')}`;
    process.env.QODIQA_PG_DATABASE = generatedDevDbName;
    log(
      `No QODIQA_PG_DATABASE set — using a fresh, isolated per-boot database "${generatedDevDbName}" ` +
      '(never the shared "qodiqa" database). See docs/operations/troubleshooting.md "Development PostgreSQL ' +
      'databases accumulate" for cleanup guidance.',
    );
  }

  // the last point before ANY write — ensureDatabaseExists() below can
  // CREATE DATABASE, runMigrations() after it writes schema, and the consent
  // grants at the end write rows. The B4 fix above generates a disposable
  // database only when QODIQA_PG_DATABASE is falsy; it cannot tell an operator
  // who deliberately set it from dotenv silently backfilling it out of .env,
  // and was exactly the latter. This guard refuses either way unless the
  // override is passed inline for this one invocation.
  assertBootstrapDatabaseIsolated({ generatedDbName: generatedDevDbName, warn });

  // OPS-01 (D2, fail-loudly option): tracked separately from
  // generatedDevDbName so a freshly-created EXPLICIT QODIQA_PG_DATABASE can
  // also be recognized below — ensureDatabaseExists() reports whether it
  // just created the database (vs. found it already there); "just created"
  // is exactly the case the default migration pool is known to lack schema
  // privilege on for PostgreSQL 15+ (see FINDINGS-GROUP-B-REMEDIATION-
  // REPORT.md §B4 Control A, which first demonstrated this against the
  // explicit-database path).
  let explicitDbWasCreated = false;

  try {
    const { created } = await ensureDatabaseExists({ log, warn });
    if (!generatedDevDbName) {
      explicitDbWasCreated = created;
    }
  } catch (err) {
    if (generatedDevDbName) {
      // Isolation was implicitly requested (no explicit QODIQA_PG_DATABASE)
      // and could not be honored. Revert the env var as hygiene — nothing
      // downstream (including the spawned server.js child) should point at
      // a database that was never created — but do NOT silently fall back
      // to the shared "qodiqa" database and continue. That silent fallback
      // is exactly the isolation gap this fix exists to close (the
      // audit_chain seq 157 incident): a "convenience" that can write real,
      // permanent rows into shared state on every future boot is the
      // finding recurring, not a degradation worth accepting quietly. The
      // caller (bootstrap-dev.js) treats qodiqaIsolationFatal as fatal,
      // distinct from every other best-effort failure in this function.
      delete process.env.QODIQA_PG_DATABASE;
      const fatal = new Error(
        `Could not create isolated development database "${generatedDevDbName}": ${err.message}. ` +
        'Two remedies: (1) grant/verify CREATEDB on the qodiqa_test role and set QODIQA_PG_TEST_USER/' +
        'QODIQA_PG_TEST_PASSWORD in .env (see FINDING-F2-PREVENTION-LAYERS-REMEDIATION-REPORT.md §1), ' +
        'then re-run `npm run dev`; or (2) set QODIQA_PG_DATABASE explicitly in .env — a conscious ' +
        'opt-out of per-boot isolation, reusing one persistent database across boots.',
      );
      fatal.qodiqaIsolationFatal = true;
      throw fatal;
    }
    throw err;
  }

  // Reuse the exact same, already-idempotent, checksummed migration runner
  // every environment uses (node src/infra/postgres/migrate.js) — never a
  // separate/ad-hoc schema definition.
  //
  // B4 (Option C, item-23 discipline — see ITEM-23-REMEDIATION-REPORT.md §2):
  // runMigrations()'s own default pool authenticates as QODIQA_PG_MIG_USER
  // (default 'qodiqa_mig') — neither role has CREATE on a freshly
  // CREATE DATABASE'd database's public schema (PostgreSQL 15+ revokes
  // PUBLIC's default CREATE there; only the creating role — qodiqa_test —
  // and the database owner have it). Passing an explicit, qodiqa_test-
  // credentialed Pool into runMigrations({ pool }) (which accepts an
  // external pool exactly for this purpose, migrate.js:78-90) runs
  // migrations with a role that actually has privilege on the schema it
  // just created — mirroring distributedOrderingLoadTest.js's identical
  // "second, separate explicit Pool, same qodiqa_test credentials" pattern.
  // Only used for the isolated-database path (generatedDevDbName) — an
  // explicit QODIQA_PG_DATABASE (e.g. the pre-existing 'qodiqa') already has
  // its schema owned by whichever role originally created it, so the
  // pre-existing default-pool behavior is left untouched there.
  const { runMigrations } = require('../../src/infra/postgres/migrate');
  let migrationPool = null;
  if (generatedDevDbName) {
    if (!process.env.QODIQA_PG_TEST_USER) {
      // Guarded again here defensively — ensureDatabaseExists() above
      // already requires this to have gotten this far, but a future change
      // to that function must not silently reintroduce this gap.
      const fatal = new Error(
        'QODIQA_PG_TEST_USER is not set — cannot migrate the isolated development database ' +
        `"${generatedDevDbName}". See FINDING-F2-PREVENTION-LAYERS-REMEDIATION-REPORT.md §1.`,
      );
      fatal.qodiqaIsolationFatal = true;
      throw fatal;
    }
    migrationPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: generatedDevDbName,
      user:     process.env.QODIQA_PG_TEST_USER,
      password: process.env.QODIQA_PG_TEST_PASSWORD,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
  }

  let migrationResult;
  try {
    migrationResult = await runMigrations(migrationPool ? { pool: migrationPool } : {});
  } catch (err) {
    if (generatedDevDbName) {
      // Migration failure on the isolated-database path is fatal for the
      // same reason database-creation failure is (see above): a database
      // that exists but has no schema is just as unusable as one that
      // doesn't exist, and the spawned server would otherwise crash on its
      // own audit-mirror consistency check with a confusing, disconnected
      // error instead of an honest one naming the actual cause here.
      delete process.env.QODIQA_PG_DATABASE;
      const fatal = new Error(
        `Created isolated development database "${generatedDevDbName}" but failed to migrate it: ` +
        `${err.message}. This is a migration failure, not a database-creation failure — the database ` +
        'itself was created successfully. Two remedies: (1) verify the qodiqa_test role and its ' +
        'QODIQA_PG_TEST_USER/PASSWORD credentials have sufficient privilege (CREATEDB implies schema ' +
        'ownership of databases it creates — see FINDING-F2-PREVENTION-LAYERS-REMEDIATION-REPORT.md §1); ' +
        'or (2) set QODIQA_PG_DATABASE explicitly in .env to opt out of per-boot isolation.',
      );
      fatal.qodiqaIsolationFatal = true;
      throw fatal;
    }
    // OPS-01 (D2): the explicit-QODIQA_PG_DATABASE path has no auto-generated
    // name to revert (it's the operator's own persistent choice — never
    // deleted here), but the same "created but unmigrated" hazard applies
    // whenever this run is the one that actually created it. Fail loudly
    // instead of the prior silent warn-and-continue (FINDINGS-GROUP-B-
    // REMEDIATION-REPORT.md §B4 Control A first demonstrated this gap).
    if (explicitDbWasCreated) {
      const dbName = process.env.QODIQA_PG_DATABASE;
      const fatal = new Error(
        `Database "${dbName}" did not exist and was just created by this run, but failed to migrate ` +
        `it: ${err.message}. This is a migration failure, not a database-creation failure — the ` +
        'database itself was created successfully and now exists but has no schema. Two remedies: ' +
        '(1) run "node src/infra/postgres/migrate.js" manually against it with QODIQA_PG_MIG_USER set ' +
        'to a superuser or the qodiqa_test bootstrap role (see ' +
        'docs/operations/database-role-management.md), then re-run `npm run dev`; or (2) drop this ' +
        'database and leave QODIQA_PG_DATABASE unset in .env to use the automatically isolated, ' +
        'auto-migrated per-boot database instead.',
      );
      fatal.qodiqaIsolationFatal = true;
      throw fatal;
    }
    throw err;
  } finally {
    if (migrationPool) await migrationPool.end().catch(() => {});
  }
  log(`Development schema up to date (${migrationResult.applied.length} migration(s) applied this run, ${migrationResult.skipped} already current).`);

  // Initialize the shared pool singleton in THIS process (bootstrap-dev.js)
  // so src/core/consent below can use it. server.js initializes its own,
  // completely independent pool instance in its own child process at its
  // own startup — nothing here is shared with or reused by the server.
  const pool = require('../../src/infra/postgres/pool');
  pool.initialize();
  if (!pool.isEnabled()) {
    warn('PostgreSQL pool did not report enabled after provisioning — skipping consent grant. Consent-gated executions will BLOCK.');
    return { attempted: true, granted: [] };
  }

  // consent must be granted against the signing IDENTITY's own id
  // (the value services/policy/evaluators/requireConsent.js's
  // caller-binding actually looks up at verification time — read from
  // artifact.payload.callerContext.callerId / context.callerId, which
  // src/api/routes/sign.js populates from the signing identity's `id`,
  // unconditionally, on every /sign call), NOT the tenant's artifact-signing
  // KEY id (`keyManager.getSigningKey(clientId).keyId`) this used to grant
  // against. Those are two different identifiers from two different stores
  // that happen to share a similar-looking format — the old code granted
  // for the wrong one, so every real signed request's consent lookup
  // silently missed the auto-granted record (found live: docs/guides/quickstart.md's
  // own "Path A — npm run dev" section, remediation). Looked up via
  // listSigningIdentities() rather than threading a new return value through
  // devEnvironment.js/bootstrap-dev.js — prepareIsolatedEnvironment() already
  // created exactly this one identity, in this same isolated store, moments
  // earlier in this same invocation (see this module's own header comment).
  const { listSigningIdentities } = require('../../src/core/signing/signingIdentityStore');
  const devIdentity = listSigningIdentities().find(i => i.tenantId === clientId && i.createdBy === 'DEV_BOOTSTRAP');
  if (!devIdentity) {
    warn(`No dev-bootstrap signing identity found for tenant "${clientId}" — skipping consent grant. Consent-gated executions will BLOCK.`);
    return { attempted: true, granted: [] };
  }

  // The real production consent API — the same grant() every ops-authenticated
  // POST /consent call goes through. No raw INSERT anywhere in this file.
  const consent = require('../../src/core/consent');

  const providers = configuredProviders();
  if (!providers.length) {
    log('No AI provider is configured this run — no consent record to grant yet.');
    return { attempted: true, granted: [] };
  }

  const granted = [];
  for (const provider of providers) {
    try {
      // grant() is itself idempotent (ON CONFLICT (actor_id, action, tenant_id)
      // DO UPDATE, guarded so a REVOKED/EXPIRED record is never silently
      // reactivated) — safe to call on every `npm run dev` invocation.
      await consent.grant({
        actor_id:        devIdentity.id,
        action:          provider,
        tenant_id:       clientId,
        granted_by:      'qodiqa-dev-bootstrap',
        granted_via:     'DEV_BOOTSTRAP',
        grant_reference: 'Automatically provisioned by scripts/bootstrap-dev.js for local development only.',
        request_id:      null,
      });
      granted.push(provider);
      log(`Granted development consent: actor_id=${devIdentity.id} action=${provider} tenant_id=${clientId}`);
    } catch (err) {
      // Most commonly: a previously REVOKED/EXPIRED record for this exact
      // triple, which store.create() deliberately refuses to reactivate.
      // That is correct behavior, not a bootstrap failure — warn and move on.
      warn(`Could not grant development consent for action="${provider}": ${err.message}`);
    }
  }

  return { attempted: true, granted };
}

module.exports = { provisionDevConsent, configuredProviders, PROVIDER_ENV_MAP };
