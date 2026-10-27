'use strict';

/**
 * Bootstrap PostgreSQL isolation guard —.
 *
 * This is FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md §8's prevention layer 2
 * ("require an explicit opt-in env var before falling through to the ambient
 * .env value") extended to the one entry point it was never applied to.
 * Layer 2 shipped for the TEST entry points — test/support/jest.setup.js and
 * scripts/performance/lib/setupEnv.js both force QODIQA_PG_ENABLED off for a
 * local non-CI run unless the developer opts in (see test/pgIsolationGuard.
 * test.js). `npm run dev` was left out, and that gap has now produced two
 * further incidents of the same class:
 *
 * - an unisolated POLICY_FILE leaked test config into the real
 *           repo's policies.json during a live witness.
 * - Session 2: a boot launched with PowerShell's
 *           `$env:QODIQA_PG_DATABASE = ""`. Windows drops an empty
 *           environment variable from the child process entirely, so dotenv
 *           backfilled QODIQA_PG_DATABASE=qodiqa from .env and bootstrap ran
 *           against the SHARED database, re-granting two pre-existing
 *           dev-local:key_v1 consent rows before anything stopped it.
 *
 * ── Why a coherence check rather than a name denylist ────────────────────────
 * bootstrap-dev.js isolates the FILE half of the world unconditionally on
 * every invocation — keys, audit log, transparency keys, signing store all get
 * a fresh per-run temp path (scripts/lib/devEnvironment.js). A bootstrap run
 * against a database it did not itself generate is therefore not merely
 * "unisolated", it is internally INCOHERENT: isolated file side, shared DB
 * side. That mismatch is the exact signature of both incidents above, and it
 * is what server.js's own AUDIT_MIRROR_CONSISTENCY_VIOLATION detects — but
 * that check runs at server startup, three steps AFTER provisionDevConsent()
 * has already written to the database. This guard runs before the first write.
 *
 * ── Why the override may never live in .env ─────────────────────────────────
 * QODIQA_PG_ALLOW_SHARED=true in .env would be supplied by dotenv to every
 * future bootstrap — including isolated witness sessions that never asked for
 * it — which is precisely the backfill mechanism that caused in the first
 * place. An override that can be silently inherited is not an override, it is
 * a disabled guard. assertOverrideNotFromDotenv() below therefore refuses on
 * the mere PRESENCE of the key in the .env file, whatever its value, and
 * regardless of whether it actually took effect this run.
 */

const SHARED_DB_DEFAULT = 'qodiqa';
const OVERRIDE_VAR      = 'QODIQA_PG_ALLOW_SHARED';

function _fatal(message) {
  const err = new Error(message);
  // Reuses bootstrap-dev.js's existing fatal channel (see devConsent.js's
  // qodiqaIsolationFatal) so this exits(1) with a clean message instead of
  // falling through to the best-effort warn-and-continue path that every
  // other provisionDevConsent() failure takes.
  err.qodiqaIsolationFatal = true;
  return err;
}

/**
 * Refuse if the shared-database override was supplied through the .env file.
 *
 * @param {object|undefined} dotenvParsed — the `parsed` object returned by
 *   require('dotenv').config(). Keys present here were read FROM THE FILE,
 *   independently of whether dotenv actually applied them (dotenv never
 *   overrides an already-set process.env value, so a key can appear here
 *   without having taken effect — both cases are refused, because the file is
 *   what future sessions will inherit).
 * @throws {Error} with qodiqaIsolationFatal set
 */
function assertOverrideNotFromDotenv(dotenvParsed) {
  if (!dotenvParsed || !Object.prototype.hasOwnProperty.call(dotenvParsed, OVERRIDE_VAR)) return;

  throw _fatal(
    `${OVERRIDE_VAR} is present in .env — refusing to start.\n` +
    `  This override exists so a developer can deliberately point ONE bootstrap run at a shared\n` +
    '  database. Placing it in .env makes dotenv supply it to EVERY future run, including isolated\n' +
    '  witness sessions that never asked for it — the same silent-backfill mechanism that caused\n' +
    '  the earlier shared-database incident (see this file\'s header). An override that can be inherited is a disabled guard.\n' +
    `  Remove ${OVERRIDE_VAR} from .env. To allow a shared-database run, pass it inline for that\n` +
    `  invocation only, e.g.  ${OVERRIDE_VAR}=true npm run dev`,
  );
}

/**
 * Refuse to provision against a database this bootstrap run did not generate.
 *
 * Called from provisionDevConsent() BEFORE ensureDatabaseExists() — i.e.
 * before the first write of any kind (CREATE DATABASE, migrations, or the dev
 * consent grants themselves).
 *
 * @param {object} opts
 * @param {string|null} opts.generatedDbName — the per-boot disposable database
 *   name this run generated, or null when QODIQA_PG_DATABASE was already set
 *   (explicitly by the operator, or ambiently by dotenv — indistinguishable
 *   here, which is the whole point: both are "not generated by this run").
 * @param {(msg: string) => void} [opts.warn]
 * @throws {Error} with qodiqaIsolationFatal set
 */
function assertBootstrapDatabaseIsolated({ generatedDbName, warn = () => {} }) {
  if (generatedDbName) return; // this run generated its own disposable database — coherent

  const dbName = process.env.QODIQA_PG_DATABASE || SHARED_DB_DEFAULT;

  if (process.env[OVERRIDE_VAR] === 'true') {
    warn(
      `${OVERRIDE_VAR}=true — proceeding against the non-isolated database "${dbName}". ` +
      'This bootstrap has already redirected the keys, audit log, transparency keys and signing ' +
      'store to fresh per-run temp paths, so the file and database halves of this run are ' +
      'deliberately incoherent: PG-only rows written now will have no file-side counterpart, and ' +
      "server.js's own audit-mirror consistency check may refuse to start against them later.",
    );
    return;
  }

  throw _fatal(
    `Refusing to bootstrap against the non-isolated database "${dbName}".\n` +
    '  bootstrap-dev.js isolates the keys, audit log, transparency keys and signing store to fresh\n' +
    '  per-run temp paths unconditionally, so running against a database it did not itself generate\n' +
    '  is internally incoherent — isolated file side, shared database side. That mismatch is what\n' +
    "  produced the earlier shared-database incident, and it is what server.js's AUDIT_MIRROR_CONSISTENCY_VIOLATION catches\n" +
    '  three steps later, after this provisioning step has already written rows.\n' +
    '  Two ways forward:\n' +
    '    (1) Unset QODIQA_PG_DATABASE (remove it from .env) so every boot gets a fresh, isolated\n' +
    '        per-boot database — the intended default, and what this guard assumes.\n' +
    `    (2) If you genuinely mean to use "${dbName}", pass the override inline for this one\n` +
    `        invocation:  ${OVERRIDE_VAR}=true npm run dev\n` +
    `        Never put ${OVERRIDE_VAR} in .env — see this guard's own dotenv check.`,
  );
}

module.exports = {
  assertOverrideNotFromDotenv,
  assertBootstrapDatabaseIsolated,
  SHARED_DB_DEFAULT,
  OVERRIDE_VAR,
};
