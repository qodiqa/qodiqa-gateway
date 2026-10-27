'use strict';

/**
 * Starts a real, unmodified QODIQA server for an acceptance test, in one of
 * two modes:
 *
 *  - startBootstrapped(): spawns `node scripts/bootstrap-dev.js` — the same
 *    entry point a developer runs (`npm run dev`). Isolation (fresh KEK,
 *    sign token, key store, audit log, transparency key store) is provided
 *    entirely by scripts/lib/devEnvironment.js running inside that fresh
 *    child process — nothing here duplicates that logic. Use this for any
 * test that just needs "a normal, fully-working server" (most
 * signing tests, and the happy-path parts).
 *
 *  - startRaw(): spawns `node server.js` directly with a fully
 *    caller-supplied env (see helpers/environment.js buildRawEnv/
 *    buildWorkingEnv) and does NOT wait for GATEWAY_START by default — for
 *    tests that specifically exercise startup failure sequencing (AT-001)
 *    or a deliberately-broken precondition (AT-009's empty key store).
 *
 * Every spawned server gets its own free port and its own child process —
 * never a suite-wide shared instance — so tests never interfere with each
 * other (requirement #15) and a crash/timeout in one test can't corrupt
 * another's server state.
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const { Client } = require('pg');

const { getFreePort, spawnCapturing, waitForCondition, killProcessTree } = require('./process');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const DEFAULT_TIMEOUT_MS = 25000;

// ── Per-boot dev database cleanup ─────────
//
// scripts/lib/devConsent.js generates a fresh `qodiqa_dev_<hex>` database
// whenever a bootstrap-dev.js boot has QODIQA_PG_ENABLED=true (the .env
// default) and no explicit QODIQA_PG_DATABASE — exactly the common case for
// startBootstrapped() callers here, since only a handful of cases (the ones
// that need the shared PG-backed acceptance database via
// helpers/postgres.js) set QODIQA_PG_DATABASE themselves. Nothing ever
// dropped these: killProcessTree() only ends the child process, not the
// database it created. Across a full acceptance run this leaked one
// database per PG-enabled case, unboundedly, run after run (1,422
// accumulated by 2026-08-26 — see CLAUDE.md's environment section).
//
// bootstrap-dev.js logs the generated name in a plain-text line (never a
// structured JSON event, so waitForStartupOutcome's parser does not surface
// it) — matched here directly out of the captured output instead of adding
// a new boot-time event to product code, keeping this fix entirely inside
// the runner.
const DEV_DB_LOG_RE = /using a fresh, isolated per-boot database "(qodiqa_dev_[0-9a-f]+)"/;

// bootstrap-dev.js removes its own %TEMP%/qodiqa-dev-* dir on a
// graceful exit, but killProcessTree() force-kills the tree (taskkill /T /F on
// Windows), so its exit handlers never run — the same gap as the per-boot
// database above, closed the same way: read the directory from bootstrap-dev's
// own "Isolated storage: <dir>" log line and remove exactly that directory,
// only if it sits directly in os.tmpdir() and is named qodiqa-dev-*.
const DEV_TEMP_LOG_RE = /\[bootstrap-dev\] Isolated storage: (.+)/;
function _removeDevTempDir(dir) {
  if (!dir) return;
  const inTmp = path.resolve(path.dirname(dir)) === path.resolve(os.tmpdir());
  if (!inTmp || !path.basename(dir).startsWith('qodiqa-dev-')) return;
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

/**
 * Resolves qodiqa_test credentials (CREATEDB — the role devConsent.js uses
 * to create these databases, and therefore their owner, able to drop them
 * without superuser): an explicit QODIQA_ACCEPTANCE_PG_TEST_* override first,
 * else the process's own QODIQA_PG_* test identity (pl-env.sh / CI).
 *
 * phase 17: never .env. It used to be the fallback for the host, port
 * AND credentials, and on the development machine .env names the cluster that
 * hosts LIVE (127.0.0.1:5432) — the drop connection went there. With no
 * explicit target there is nothing to drop on (the boot itself could not have
 * created a database: its .env back-fill is blocked, see startBootstrapped).
 */
function _resolveDevDbDropCredentials() {
  const host = process.env.QODIQA_ACCEPTANCE_PG_HOST || process.env.QODIQA_PG_HOST;
  const port = process.env.QODIQA_ACCEPTANCE_PG_PORT || process.env.QODIQA_PG_PORT;
  return {
    host: host || null,
    port: port ? parseInt(port, 10) : null,
    user: process.env.QODIQA_ACCEPTANCE_PG_TEST_USER || process.env.QODIQA_PG_TEST_USER,
    password: process.env.QODIQA_ACCEPTANCE_PG_TEST_PASSWORD || process.env.QODIQA_PG_TEST_PASSWORD,
  };
}

/**
 * Drops one per-boot dev database this helper's own spawn generated.
 * Best-effort and silent-to-the-test-result by design: the acceptance test
 * that used this server already has its verdict by the time stop() runs —
 * a cleanup failure here must never turn a PASS into a FAIL. Logged to
 * stderr so it is still visible in the run's captured output.
 */
async function _dropDevDatabase(dbName) {
  const creds = _resolveDevDbDropCredentials();
  if (!creds.host || !creds.port || !creds.user || !creds.password) {
    process.stderr.write(
      `[acceptance] WARNING: no explicit PostgreSQL target / qodiqa_test credentials to drop per-boot database "${dbName}" — it was left behind.\n`,
    );
    return;
  }
  const client = new Client({ ...creds, database: 'postgres', connectionTimeoutMillis: 5000 });
  try {
    await client.connect();
    // WITH (FORCE) (PostgreSQL 13+) disconnects any session still attached
    // — the just-killed child's pool may not have closed its sockets yet.
    await client.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
  } catch (err) {
    process.stderr.write(`[acceptance] WARNING: failed to drop per-boot database "${dbName}": ${err.message}\n`);
  } finally {
    await client.end().catch(() => {});
  }
}

/**
 * Watches a spawned process's combined stdout/stderr for the structured
 * JSON log events server.js emits (see services/logger.js), resolving as
 * soon as one of three outcomes is observed:
 *   - 'ready': a GATEWAY_START event was logged (readyEvent attached)
 *   - 'fatal': a level:"FATAL" event was logged (fatalEvent attached), or a
 *              non-JSON line containing "FATAL" was seen (fatalText attached
 *              — covers scripts/bootstrap-dev.js's own plain-text
 *              Redis-unreachable message, which is not a JSON log line)
 *   - 'exited': the process exited without matching either of the above
 *
 * @returns {Promise<{ outcome: 'ready'|'fatal'|'exited', readyEvent?, fatalEvent?, fatalText?, seenEvents: Set<string>, exitCode: number|null, output: string }>}
 */
function waitForStartupOutcome(handle, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const seenEvents = new Set();
  let readyEvent = null;
  let fatalEvent = null;
  let fatalText = null;

  handle.onLine((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      if (!fatalText && /FATAL/.test(trimmed)) fatalText = trimmed;
      return;
    }
    if (parsed && typeof parsed === 'object') {
      // services/logger.js's emit() writes {severity, eventType, ...} — not
      // {level, event}. This helper predates that field rename (see the
      // stale {ts,level,event} shape still visible in logs/AT-003-dev-
      // bootstrap.log) and was silently never matching a real GATEWAY_START
      // or FATAL JSON line since, always falling through to the 'exited'
      // outcome once its timeout elapsed regardless of the child's actual
      // state. Fixed as part (needed a working spawned-server
      // readiness signal for its multi-instance rate-limit integration test).
      if (parsed.eventType) seenEvents.add(parsed.eventType);
      if (parsed.eventType === 'GATEWAY_START' && !readyEvent) readyEvent = parsed;
      if (parsed.severity === 'FATAL' && !fatalEvent) fatalEvent = parsed;
    }
  });

  return waitForCondition(
    () => {
      if (readyEvent) return 'ready';
      if (fatalEvent || fatalText) return 'fatal';
      if (handle.child.exitCode !== null || handle.child.signalCode) return 'exited';
      return null;
    },
    { timeoutMs, intervalMs: 150 },
  ).then((outcome) => ({
    outcome: outcome || 'exited',
    readyEvent,
    fatalEvent,
    fatalText,
    seenEvents,
    exitCode: handle.child.exitCode,
    output: handle.getOutput(),
  }));
}

const STARTUP_CRASH_RETRIES = 2;

/**
 * Spawns `node scripts/bootstrap-dev.js` and waits for it to reach
 * GATEWAY_START, returning a handle for making HTTP requests and stopping
 * the server afterward.
 *
 * Retries (bounded, STARTUP_CRASH_RETRIES times) ONLY for infrastructure-
 * level hiccups unrelated to the request under test, never when a real
 * FATAL was logged:
 *   - no diagnostic at all (no FATAL event, no FATAL text) — observed in
 *     practice as an intermittent native crash, exit code 3221226505 /
 *     STATUS_STACK_BUFFER_OVERRUN.
 *   - a FATAL UNCAUGHT_EXCEPTION whose message is an EADDRINUSE port
 *     collision — getFreePort() finding a port and the child actually
 *     binding it are two separate moments; under many rapid successive
 *     spawns (a full suite run) something else can grab the same port in
 *     between. This still logs as a JSON FATAL event, so it needs its own
 *     check rather than falling under the "no diagnostic" case above.
 * This is the framework's one "infrastructure operation" retry per
 * requirement #19 — every other logged FATAL is a real result and is
 * never retried.
 *
 * @param {object} [opts]
 * @param {object} [opts.env] additional/override env vars for the child
 *   (e.g. REDIS_URL pointing at a disposable instance, QODIQA_DEV_CLIENT_ID)
 * @param {number} [opts.timeoutMs]
 */
async function startBootstrapped(opts = {}) {
  let lastResult;

  for (let attempt = 0; attempt <= STARTUP_CRASH_RETRIES; attempt += 1) {
    const port = await getFreePort();
    // phase 17: bootstrap-dev.js loads .env itself (it is also the `npm run dev` entry point, so the guard
    // lives here, at the spawn): every PostgreSQL/Redis target .env defines but this env does not is pinned to ''
    // (QODIQA_PG_ENABLED to 'false'), so the child can never back-fill .env's cluster — on the dev machine the one
    // hosting LIVE — and the LIVE-endpoint socket guard is preloaded against the product defaults (CI exempt).
    // eslint-disable-next-line global-require
    const env = require('../helpers/liveEndpointGuard').isolatedChildEnv(process.env, { PORT: String(port), ...(opts.env || {}) });

    // isolation guard (scripts/lib/bootstrapIsolationGuard.js, added
    // 2026-08-12, after this framework's last full run): bootstrap-dev
    // refuses to run against a database it did not itself generate unless
    // QODIQA_PG_ALLOW_SHARED=true arrives via the child's own process env
    // (never .env). A case that sets QODIQA_PG_DATABASE here is deliberately
    // opting into the persistent acceptance database that helpers/postgres.js
    // truncate-isolates around every test — the guard's documented sanctioned
    // case — so supply its per-invocation override for exactly that spawn.
    if (env.QODIQA_PG_DATABASE && env.QODIQA_PG_ALLOW_SHARED === undefined) {
      env.QODIQA_PG_ALLOW_SHARED = 'true';
    }

    // Hermetic provider config (same coupling CLAUDE.md documents for
    // routeHardening/quickstartFlow): bootstrap-dev's dotenv backfills any
    // provider key the child env leaves absent, and a dev .env carrying TWO
    // provider configs (e.g. OPENAI_API_KEY + LOCAL_BASE_URL) breaks every
    // /sign single-provider inference with PROVIDER_REQUIRED. Pre-block each
    // provider var with '' (dotenv never overrides an existing var; QODIQA
    // treats '' as unconfigured) unless the case's own env sets it — cases
    // that need a provider already pass their disposable stub's
    // LOCAL_BASE_URL explicitly, and a case that sets none gets
    // bootstrap-dev's documented single local-provider fallback.
    for (const key of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY',
      'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL']) {
      if (!(opts.env && key in opts.env)) env[key] = '';
    }

    const handle = spawnCapturing(process.execPath, ['scripts/bootstrap-dev.js'], {
      cwd: REPO_ROOT,
      env,
    });

    const result = await waitForStartupOutcome(handle, { timeoutMs: opts.timeoutMs });
    const devDbMatch = result.output.match(DEV_DB_LOG_RE);
    const generatedDevDbName = devDbMatch ? devDbMatch[1] : null;
    const tempMatch = result.output.match(DEV_TEMP_LOG_RE);
    const devTempDir = tempMatch ? tempMatch[1].trim() : null;

    if (result.outcome === 'ready') {
      return {
        baseUrl: `http://127.0.0.1:${port}`,
        port,
        handle,
        startupResult: result,
        async stop() {
          await killProcessTree(handle.child);
          if (generatedDevDbName) await _dropDevDatabase(generatedDevDbName);
          _removeDevTempDir(devTempDir);
        },
      };
    }

    await killProcessTree(handle.child);
    _removeDevTempDir(devTempDir);
    // A failed/retried attempt can still have created its per-boot database
    // before failing later (e.g. a migration error) — drop it now rather
    // than leaking it into the next attempt or the next run.
    if (generatedDevDbName) await _dropDevDatabase(generatedDevDbName);
    lastResult = result;

    const undiagnosedCrash = !result.fatalEvent && !result.fatalText;
    const portRace = result.fatalEvent
      && result.fatalEvent.eventType === 'UNCAUGHT_EXCEPTION'
      && /EADDRINUSE/.test(result.fatalEvent.message || '');
    if (!(undiagnosedCrash || portRace) || attempt === STARTUP_CRASH_RETRIES) break;
  }

  const detail = lastResult.fatalEvent
    ? JSON.stringify(lastResult.fatalEvent)
    : lastResult.fatalText || `process exited with code ${lastResult.exitCode}`;
  const err = new Error(`Server did not reach GATEWAY_START: ${detail}\n\nOutput:\n${lastResult.output}`);
  err.startupResult = lastResult;
  throw err;
}

/**
 * Spawns `node server.js` directly with a fully explicit env (built by
 * helpers/environment.js), for tests that need to control exactly which
 * QODIQA_* variables exist. Does not wait for readiness by itself — call
 * waitForStartupOutcome(handle, opts) with the returned handle.
 *
 * @param {object} env  a complete env object (see environment.js buildRawEnv/buildWorkingEnv)
 * @param {object} [opts]
 * @param {string} [opts.entry]  script to run instead of 'server.js' (relative to REPO_ROOT)
 * @param {string[]} [opts.stdio]  stdio array override — e.g. adding 'ipc' as a
 *   4th element, for tests (AT-099) that need an IPC channel to the child
 */
function startRaw(env, opts = {}) {
  const handle = spawnCapturing(process.execPath, [opts.entry || 'server.js'], {
    cwd: REPO_ROOT,
    env,
    ...(opts.stdio ? { stdio: opts.stdio } : {}),
  });
  return handle;
}

module.exports = {
  REPO_ROOT,
  DEFAULT_TIMEOUT_MS,
  waitForStartupOutcome,
  startBootstrapped,
  startRaw,
};
