'use strict';

/**
 * QODIQA development bootstrap.
 *
 * Prepares a fully isolated, ephemeral development environment and then
 * launches the REAL production server (server.js) inside it — unmodified,
 * running the complete production enforcement pipeline (cryptographic
 * verification, consent evaluation, policy evaluation, audit logging).
 *
 * This script does not implement, mock, stub, or bypass any part of the
 * server. It only prepares environment variables and isolated on-disk
 * storage paths (via scripts/lib/devEnvironment.js, shared with the
 * test/serverStartupSmoke.test.js regression test so both stay in sync),
 * then spawns `node server.js` as a normal child process — exactly the
 * same code path `npm start` uses, with the same fail-closed startup
 * validation intact.
 *
 * Isolation guarantees (see requirements below and docs/guides/installation.md):
 *   - A fresh OS temp directory is created for every invocation. Nothing is
 *     ever written under data/, config/, or the repository root.
 *   - A fresh, cryptographically random Key Encryption Key (KEK) and a
 *     dev-scoped signing identity API key are generated for every invocation
 *     via crypto.randomBytes — never hard-coded, never reused across runs.
 *   - The production key store (data/keys.json) is never read, decrypted,
 *     or written. The development key store lives entirely in the fresh
 *     temp directory and is provisioned via the SAME provisioning helper
 *     used by the Jest test environment (scripts/lib/keyStoreProvisioning.js).
 *   - The production audit log (audit.log) is never read or appended to.
 *   - Every `npm run dev` invocation is fully independent of every other —
 *     no state leaks between consecutive runs.
 *   - PostgreSQL-backed consent is opt-in (see scripts/lib/devConsent.js). If
 *     the developer has set QODIQA_PG_ENABLED=true, this script provisions
 *     the configured database/schema and grants development consent for the
 *     freshly generated dev signing key — through the real, unmodified
 *     src/core/consent API, never raw SQL. With the flag unset (the
 *     default), this step is a complete no-op.
 *
 * What this script does NOT do:
 *   - It does not change server.js's startup validation in any way.
 *   - It does not disable cryptographic verification, consent evaluation,
 *     or policy evaluation — those are unconditional parts of server.js's
 *     request pipeline and are never touched here. Consent provisioning
 *     (above) grants a real record for consent to find; it never bypasses
 *     the REQUIRE_CONSENT check itself, which still runs on every request.
 *   - It does not introduce a mock AI provider. If no real provider API key
 *     is configured, it points the server at the `local` provider type
 *     (a real, production-supported provider for self-hosted OpenAI-
 *     compatible runtimes such as Ollama) — if nothing is actually
 *     listening there, /ai/chat calls correctly fail with
 *     PROVIDER_UNAVAILABLE, exactly as they would in production.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { spawn } = require('child_process');

// Load .env (if present) the same way server.js does, so provider-key
// detection below sees exactly what the real server will see. dotenv never
// overrides an already-set process.env value.
// the `parsed` result is retained, not discarded — it is the only
// reliable record of which keys came from the .env FILE as opposed to the real
// process environment, which is exactly the distinction the isolation guard
// needs (see scripts/lib/bootstrapIsolationGuard.js). dotenv never overrides an
// already-set process.env value, so a key can appear in `parsed` without having
// taken effect this run; the guard refuses on presence either way.
const _dotenvResult = require('dotenv').config();

const { prepareIsolatedEnvironment } = require('./lib/devEnvironment');
const { assertOverrideNotFromDotenv } = require('./lib/bootstrapIsolationGuard');

const REPO_ROOT = path.join(__dirname, '..');

function log(message) {
  process.stdout.write(`[bootstrap-dev] ${message}\n`);
}

function warn(message) {
  process.stdout.write(`[bootstrap-dev] WARNING: ${message}\n`);
}

// ── remove this run's own isolated temp dir on exit ─────────────
// Every run creates %TEMP%/qodiqa-dev-XXXXXX (key stores, audit log, stores);
// none was ever removed — 11,475 had accumulated by 2026-09-28. Removal is
// limited to exactly the directory this process created: it must sit directly
// in os.tmpdir() and be named qodiqa-dev-*, or nothing is removed.
let _ownTempDir = null;
function registerTempCleanup(dir) {
  _ownTempDir = dir;
  process.on('exit', removeOwnTempDir);
}
function removeOwnTempDir() {
  const dir = _ownTempDir;
  _ownTempDir = null;
  if (!dir) return;
  const inTmp = path.resolve(path.dirname(dir)) === path.resolve(os.tmpdir());
  if (!inTmp || !path.basename(dir).startsWith('qodiqa-dev-')) return;
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort on exit */ }
}

async function main() {
  // runs before anything else in this script — before the isolated temp
  // dirs are created and long before the first database write — because a
  // shared-database override sitting in .env would silently apply to every
  // future run, including the isolated witness sessions this guard exists to
  // protect. Throws with qodiqaIsolationFatal, handled by main().catch below.
  assertOverrideNotFromDotenv(_dotenvResult.parsed);

  log('Preparing isolated development environment (never touches production data/ or audit.log)...');

  const devClientId = process.env.QODIQA_DEV_CLIENT_ID || 'dev-local';
  const { paths, redisUrl, redisReachable } = await prepareIsolatedEnvironment({
    clientId:   devClientId,
    tempPrefix: 'qodiqa-dev-',
    log,
    warn,
  });
  registerTempCleanup(paths.root);

  // the dev server reads its policy source from POLICY_FILE
  // and policy management can write it back. Unset, that is the tracked
  // repository-root policies.json — so give the dev server its own copy.
  if (!process.env.POLICY_FILE) {
    const policyCopy = path.join(paths.root, 'policies.json');
    // `qodiqa dev` (scripts/dev/qodiqa-dev.js) names its own policy set; the default stays the repository policies.json
    const policySource = process.env.QODIQA_DEV_POLICY_SOURCE ? path.resolve(process.env.QODIQA_DEV_POLICY_SOURCE) : path.join(REPO_ROOT, 'policies.json');
    fs.copyFileSync(policySource, policyCopy);
    process.env.POLICY_FILE = policyCopy;
    log(`POLICY_FILE: isolated copy of ${path.relative(REPO_ROOT, policySource) || policySource}.`);
  }

  // ── Redis — genuine, unconditional prerequisite ─────────────────────────────
  // Redis is not optional for a full server boot: independent of
  // STRICT_REPLAY_PROTECTION, server.js also requires a live subscription to
  // the consent-revocation pub/sub channel before it will finish starting
  // ("required control-plane dependency" — server.js, "Revocation subscriber"
  // section) and exits fatally if that subscription cannot be established.
  // There is no dev-mode escape hatch for that gate, by design — bypassing it
  // would mean the node could not guarantee instant enforcement of revoked
  // consent, which this bootstrap must never weaken. So rather than let the
  // spawned server hang for ~10-15s and then exit fatally, fail fast here
  // with a clear, actionable message.
  if (!redisReachable) {
    process.stderr.write(
      `[bootstrap-dev] FATAL: Redis is not reachable at ${redisUrl}.\n` +
      '[bootstrap-dev] Redis is required to start the real server — it backs the nonce ' +
      'store, anomaly store, rate-limit store, and the consent-revocation subscriber ' +
      '(a required control-plane dependency with no bypass). Start Redis locally, e.g.:\n' +
      '[bootstrap-dev]   redis-server\n' +
      '[bootstrap-dev]   # or: docker run --rm -p 6379:6379 redis\n' +
      '[bootstrap-dev] then re-run `npm run dev`.\n',
    );
    process.exit(1);
  }
  log(`Redis reachable at ${redisUrl}.`);

  // ── PostgreSQL-backed consent — opt-in, best-effort ──────────────────────────
  // Only runs if the developer has explicitly set QODIQA_PG_ENABLED=true (e.g.
  // in .env). With it unset — the default — this is a complete no-op and
  // behavior is identical to every prior release: consent-gated requests BLOCK
  // with CONSENT_STORE_UNAVAILABLE, same as production would with the flag
  // unset. Unlike Redis above, a failure here never halts `npm run dev` —
  // PostgreSQL/consent are not required for the server to start; only for
  // consent-gated executions to succeed. See scripts/lib/devConsent.js.
  try {
    const { provisionDevConsent } = require('./lib/devConsent');
    await provisionDevConsent({ clientId: devClientId, log, warn });
  } catch (err) {
    // B4: a failure to create the implicitly-requested isolated development
    // database is fatal, not best-effort — see devConsent.js's
    // qodiqaIsolationFatal for why silently continuing here would reopen
    // the audit_chain seq 157 isolation gap this fix exists to close.
    if (err.qodiqaIsolationFatal) {
      process.stderr.write(`[bootstrap-dev] FATAL: ${err.message}\n`);
      process.exit(1);
    }
    warn(`Development consent provisioning failed — continuing without it: ${err.message}`);
    warn('The server will still start; consent-gated executions will BLOCK until this is resolved.');
  }

  log('Launching the real server (server.js) in development mode...');
  log('─────────────────────────────────────────────────────────────');

  const child = spawn(process.execPath, ['server.js'], {
    cwd:   REPO_ROOT,
    env:   process.env,
    stdio: 'inherit',
  });

  const forward = (signal) => {
    if (!child.killed) child.kill(signal);
  };
  process.on('SIGINT',  () => forward('SIGINT'));
  process.on('SIGTERM', () => forward('SIGTERM'));

  child.on('exit', (code, signal) => {
    removeOwnTempDir();
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code ?? 0);
    }
  });

  child.on('error', (err) => {
    process.stderr.write(`[bootstrap-dev] Failed to launch server.js: ${err.message}\n`);
    process.exit(1);
  });
}

main().catch((err) => {
  process.stderr.write(`[bootstrap-dev] FATAL: ${err.message}\n`);
  process.exit(1);
});
