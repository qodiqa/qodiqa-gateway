'use strict';

// the MAC keyring no longer creates its key file on a request path (server/startup.js does, at boot). Unit/component tests that sign without booting the server get
// the old create-on-first-use behaviour through this explicit hook (never honoured when NODE_ENV is production).
globalThis.__qodiqaMacKeyringAutoProvision = () => { require('../../src/core/security/macKeyring').init(); };

// ── Deployment mode isolation ────────────────────────────────────────
// QODIQA_DEPLOYMENT_MODE must never leak ambiently into the test suite from a
// developer's shell or CI environment — every test that cares about
// deployment-mode resolution sets it explicitly (see
// src/infra/config/deploymentMode.test.js, src/core/audit/
// __tests__/multiInstanceGuard.test.js). Without this, an ambient
// QODIQA_DEPLOYMENT_MODE=distributed export would silently override tests
// that drive behavior via the legacy QODIQA_PG_ENABLED / QODIQA_AUDIT_
// ORDERING_MODE vars instead (e.g. test/serverStartupSmoke.test.js,
// test/integration/audit-chain-distributed.integration.test.js).
delete process.env.QODIQA_DEPLOYMENT_MODE;

// ── PostgreSQL mirror isolation (FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md §8,
// prevention layer 2) ───────────────────────────────────────────────────────
// Every isolation above redirects the FILE half of the audit mirror (and
// keyStore/transparency-key stores below) to a per-run temp path, but until
// now nothing redirected or gated the PostgreSQL half — a local run of any
// QODIQA_PG_ENABLED-gated suite against this repo's real .env could silently
// and permanently write PG-only rows with no file-side counterpart (see that
// report for the full forensic writeup: a single such local run produced 147
// orphan rows in the real `qodiqa` database). Individual suites now isolate
// themselves onto a disposable database (see
// test/integration/audit-chain-verifier-pg.integration.test.js and its siblings), but
// that redirection happens inside each suite's own beforeAll — AFTER this
// setupFiles hook and after each suite's top-level `QODIQA_PG_ENABLED ===
// 'true'` describe/describe.skip gate has already been evaluated. This is the
// systemic backstop that gate reads: ambient QODIQA_PG_ENABLED=true must
// never reach a local run unless it's either running in CI (an ephemeral,
// disposable-per-job Postgres container — GitHub Actions sets CI=true
// automatically; see .github/workflows/test.yml) or the developer has
// explicitly opted in for this run.
//
// Local integration runs: QODIQA_ALLOW_PG_INTEGRATION_TESTS=true npm run test:integration
// the guard above was a no-op for six days because of load ordering.
// setupFiles runs BEFORE any test file, and nothing in the jest bootstrap
// loads dotenv, so `process.env.QODIQA_PG_ENABLED` was `undefined` here and
// the condition below was always false. Suites that call
// `require('dotenv').config()` THEMSELVES (e.g.
// test/integration/consentActionSemantics.integration.test.js) then pulled
// QODIQA_PG_ENABLED=true out of .env *after* this guard had already declined
// to act, and ran against the real, persistent `qodiqa` database — 306 orphan
// consent rows across 81 write bursts before this was caught, the same
// incident FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md documented at 147 rows.
//
// Fix: read .env's value WITHOUT applying it. dotenv.parse() returns the
// file's contents as a plain object and never touches process.env, so this
// stays a pure inspection — importing .env globally here would change what
// every other suite in the repo sees (provider keys, PG credentials, feature
// flags) and is far too blunt a hammer for a safety guard.
//
// The guard then SETS QODIQA_PG_ENABLED='false' explicitly, which is what
// makes it stick: dotenv never overrides an already-set process.env value, so
// a suite's own later dotenv.config() call cannot resurrect 'true'.
let _ambientPgEnabled = process.env.QODIQA_PG_ENABLED;
if (_ambientPgEnabled === undefined) {
  try {
    const _fs = require('fs');
    const _path = require('path');
    // QODIQA_TEST_DOTENV_PATH: test-only override so test/pgIsolationGuard.test.js can probe the guard against a
    // fixture .env instead of depending on the developer's own.
    const _envPath = process.env.QODIQA_TEST_DOTENV_PATH || _path.resolve(__dirname, '..', '..', '.env');
    if (_fs.existsSync(_envPath)) {
      const _parsed = require('dotenv').parse(_fs.readFileSync(_envPath));
      _ambientPgEnabled = _parsed.QODIQA_PG_ENABLED;
    }
  } catch {
    // No .env, unreadable, or dotenv absent — nothing ambient to guard against.
  }
}

if (
  _ambientPgEnabled === 'true' &&
  process.env.CI !== 'true' &&
  process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS !== 'true'
) {
  // eslint-disable-next-line no-console
  console.warn(
    '[jest.setup] QODIQA_PG_ENABLED=true ambient from .env, but this is a local, non-CI run ' +
    'with no QODIQA_ALLOW_PG_INTEGRATION_TESTS=true opt-in — forcing QODIQA_PG_ENABLED=false ' +
    'for this run so PG-gated suites self-skip instead of risking a write to the real, ' +
    'persistent database (see FINDING-AUDIT-MIRROR-RECURRENCE-REPORT.md). Run ' +
    '`QODIQA_ALLOW_PG_INTEGRATION_TESTS=true npm run test:integration` to opt in.'
  );
  process.env.QODIQA_PG_ENABLED = 'false';
}

// 2026-10-06 — connection-target isolation (same class, a second door). The guard above only neutralises the
// QODIQA_PG_ENABLED flag. A suite that calls require('dotenv').config() itself and builds its OWN connection from
// QODIQA_PG_HOST / _PORT / _URL (test/dr/postgresFullCoverage.integration.test.js did exactly this, ungated) still
// reached whatever cluster .env names — on this machine the cluster hosting LIVE (127.0.0.1:5432). Without the explicit
// opt-in (and outside CI), every PostgreSQL connection-target key that .env defines but the process env does not is
// pre-set to the EMPTY string: dotenv never overrides a key that is already set, so a later dotenv.config() cannot
// backfill a host, and the suite sees "no PostgreSQL configured" and skips. The process env still wins (a gate runner
// that passes an explicit disposable host is unaffected), and opted-in runs keep their behaviour.
//
// — the full fix (test/helpers/liveEndpointGuard.js has the mechanism and the reasons):
//  (a) the blanking now covers the Redis targets too (REDIS_URL/REDIS_HOST/REDIS_PORT) and applies to OPTED-IN local runs
//      as well — an opted-in run must name its target explicitly (b), so .env is never a test target in any local run;
//  (b) a local opted-in run with no explicit PostgreSQL target, or one that names a LIVE port on this machine, is refused
//      here, loudly, before any suite runs (it used to silently fall through to .env's cluster / the localhost:5432
//      product default);
//  (c) the same blanking (and the PG_ENABLED=false decision above) is applied to the Jest worker's REAL environment, not
//      just this file's copy — a child spawned WITHOUT an `env` option inherits the real one, and its own dotenv load
//      would otherwise back-fill .env's cluster;
//  (d) a socket guard refuses any in-process connection to an own-host address on 5432/6379, and is preloaded
//      (NODE_OPTIONS) into every Node child that inherits this environment — the product defaults
//      (localhost:5432, redis://localhost:6379) apply even when a key is blanked, so (a) alone cannot close that door.
// CI (CI=true) is exempt from all of it, exactly as before; QODIQA_TEST_ALLOW_LIVE_PORTS=true is the escape hatch for a
// machine where those ports are disposable (never this one).
const _liveGuard = require('../helpers/liveEndpointGuard');
if (!_liveGuard.isExempt(process.env)) {
  if (process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true') {
    const _problems = _liveGuard.optInProblems(process.env);
    if (_problems.length) {
      throw new Error('[jest.setup] refusing a local PostgreSQL-integration run: ' + _problems.join('; ') + '. Run it through ' +
        'disposable PostgreSQL and Redis instances (see docs/development.md).');
    }
  }
  let _realEnv = null;
  try { _realEnv = require('vm').runInThisContext('process').env; } catch (_) { /* no real-context access */ }
  const _parsedDotenv = _liveGuard.dotenvParsed();
  for (const _env of _realEnv && _realEnv !== process.env ? [process.env, _realEnv] : [process.env]) {
    _liveGuard.neutraliseDotenvTargets(_env, { parsed: _parsedDotenv });
    if (process.env.QODIQA_PG_ENABLED === 'false') _env.QODIQA_PG_ENABLED = 'false'; // the flag decision above, for env-less children too
    _env.NODE_OPTIONS = _liveGuard.withPreload(_env.NODE_OPTIONS);
  }
  _liveGuard.installSocketGuard();
}

// ── FT-2 fifth-gate isolation ─────────────────────────────
// SAME CLASS OF BUG AS THE PG GUARD ABOVE, discovered the same way: an
// ambient production default silently reaching every test file rather than
// only the ones that opted in. `QODIQA_SEM_FT2_ENABLED` now defaults to TRUE
// in config.js — but dozens of
// existing suites mock `../embeddingBackend` to keep classifier tests fast and
// offline (e.g. windowing.test.js, failClosed.test.js, thresholdBoundary.test.js)
// and never touch `ft2Gate` at all. With the flag on, `index.js`'s `init()`
// calls the REAL `ft2Gate.load()` regardless of what embeddingBackend was
// mocked to — loading the actual 90 MB ONNX artifact and a real tokenizer, in
// every worker, for every such suite. Measured cost of not guarding this: the
// full suite went from ~2 minutes to 4,392s (73 minutes) and 24 suites failed
// outright, because boot either failed inside the test's mocked environment or
// never returned in time — `embed()`'s mock was asserted as called 0 times,
// meaning classify() short-circuited to a DENY before reaching it.
//
// Fix, same shape as the PG guard: force the flag OFF for local/non-opted-in
// runs. Individual suites that need FT-2 live (the pinning suite's fault-
// injection and default-value tests, ft2Monitoring.test.js) already set
// `process.env.QODIQA_SEM_FT2_ENABLED` explicitly inside their own test body
// AFTER this file has already run, which — exactly as the PG guard's own
// comment explains for dotenv — is what makes an explicit per-test override
// stick: this hook only sets a value when one isn't already present in the
// *test's own* process.env manipulation, and a later `delete` inside a test
// restores the "unset → default true" state for that one assertion.
if (process.env.QODIQA_SEM_FT2_ENABLED === undefined) {
  process.env.QODIQA_SEM_FT2_ENABLED = 'false';
}

// ── control-plane backend isolation ───────────────────────────────
// Same pattern as the guards above. The control plane (identities, RBAC,
// tenants, orgs, portal users, policy state, key status) uses PostgreSQL only
// when QODIQA_CONTROL_PLANE_BACKEND=pg (always, in production). Tests run the
// explicit in-memory test mode unless the suite itself opts in to pg (the
// PostgreSQL / multi-replica suites do).
if (process.env.QODIQA_CONTROL_PLANE_BACKEND === undefined) {
  process.env.QODIQA_CONTROL_PLANE_BACKEND = 'memory';
}

// ── FT-3 SIXTH-gate isolation ─────────────────────────────
// WRITTEN BEFORE THE GATE IT GUARDS, deliberately. FT-3 ships DISABLED
// (`QODIQA_SEM_FT3_ENABLED` defaults to false in config.js), so unlike the FT-2
// case above this guard is not yet load-bearing — `init()` cannot reach
// `ft3Gate.load()` while the production default is off, and no ambient default
// can leak into a suite today.
//
// It exists anyway, and it exists FIRST, because the FT-2 flip is the whole
// reason: that gate was wired disabled too, and the guard was only written
// AFTER the default was flipped to true — at a measured cost of 73 minutes and
// 24 false suite failures on the very next full run. The guard is cheap, it is
// correct in both flag states, and writing it now means the eventual FT-3
// enable decision cannot reproduce that incident by omission. The identical
// mechanism (dozens of suites mock `../embeddingBackend` without ever mocking
// `ft3Gate`, so a true default would have each of them load the real 90 MB
// artifact per `init()`) applies verbatim the moment the default changes.
//
// Same shape as both guards above: force OFF unless the test set it itself.
// the HTTP rate limiter is now ON by default (it no longer
// depends on REDIS_URL), and RL_ENABLED=false is its only off switch. Suites
// that do not exercise the limiter must not meet a Redis-backed 429 (or the
// degraded fallback) just because no Redis runs under Jest — the same
// isolation pattern as the PG/FT guards in this file. Suites that exercise the
// limiter set RL_ENABLED='true' (or inject _evalFn) themselves.
if (process.env.RL_ENABLED === undefined) {
  process.env.RL_ENABLED = 'false';
}
// /sign's auth-failure lockout is Redis-backed and
// fails CLOSED without Redis, and operator MFA step-up is required by default.
// Same isolation pattern: suites that exercise either set the variable itself.
if (process.env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED === undefined) {
  process.env.QODIQA_SIGN_AUTH_LOCKOUT_ENABLED = 'false';
}
if (process.env.QODIQA_OPS_MFA_REQUIRED === undefined) {
  process.env.QODIQA_OPS_MFA_REQUIRED = 'false';
}

if (process.env.QODIQA_SEM_FT3_ENABLED === undefined) {
  process.env.QODIQA_SEM_FT3_ENABLED = 'false';
}

// The embedding screening layer needs models and reference data that are not distributed with this repository, so tests run with it off
// unless a suite switches it on for itself (the gate suites below do, with a stand-in classifier).
if (process.env.QODIQA_SEM_EMBEDDING_ENABLED === undefined) {
  process.env.QODIQA_SEM_EMBEDDING_ENABLED = 'false';
}

// the audit chain verifier now runs in a worker thread by default (verifier/workerHost.js). A test that reaches
// getDefaultRunner() must not spawn a real worker (own PG pools, own follower audit-log) unless it opts in — the
// same guard pattern as the flags above (CLAUDE.md: a default that loads heavy machinery is guarded in tests first).
if (process.env.QODIQA_AUDIT_VERIFIER_WORKER === undefined) {
  process.env.QODIQA_AUDIT_VERIFIER_WORKER = 'false';
}

// ── Test key encryption key ───────────────────────────────────────────────────
// A fixed 256-bit KEK used exclusively in the test environment.
// This must be set before ensureActiveKey() (below) or any test performs its
// first real keyStore operation (getActiveKey, rotateKey, validateKeyStore,
// etc.) — that first operation is what lazily loads/decrypts an existing
// keys.json (see services/artifact/keyStore.js), not require() itself.
// NEVER use this value outside of the test environment.
if (!process.env.QODIQA_KEY_ENCRYPTION_KEY) {
  process.env.QODIQA_KEY_ENCRYPTION_KEY =
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
}

// ── Test execution-invariant HMAC secret ─────────────────────────────
// A fixed 256-bit secret used exclusively in the test environment to sign/
// verify the execution invariant context (services/executionInvariantToken.js).
// Deliberately a DIFFERENT value from the KEK above — purpose isolation.
// NEVER use this value outside of the test environment.
if (!process.env.QODIQA_EXECUTION_INVARIANT_SECRET) {
  process.env.QODIQA_EXECUTION_INVARIANT_SECRET =
    'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
}

// Per-worker keyStore isolation for the test suite.
//
// DATA_PATH in keyStore.js is evaluated at require() time from QODIQA_KEYS_PATH.
// Setting QODIQA_KEYS_PATH here — before the test file requires any module that
// transitively loads keyStore — redirects the singleton to a fresh temp file
// rather than the production data/keys.json.
//
// Guarantees:
//   - Tests that do NOT call jest.resetModules() get an isolated keyStore with
//     only the 'default' client provisioned.
//   - Tests that DO call jest.resetModules() (e.g. loadFresh()) re-evaluate
//     keyStore from QODIQA_KEYS_PATH. If they set their own QODIQA_KEYS_PATH
//     before resetModules(), they get their own isolated store (unchanged here).
//     If they do not (e.g. verifier.test.js), they reload from the temp file
//     written here and find 'default' already active on disk.
//   - Never touches production data/keys.json.
//   - Never throws — any failure is silently absorbed.

const os   = require('os');
const fs   = require('fs');
const path = require('path');

// Tests must give the same result inside and outside a container: the boot validator treats the presence of /.dockerenv as "running in a container"
// (production journal on the container root filesystem), which would otherwise make the configuration suites depend on where they run.
// Suites that exercise the container branch inject their own file-system double.
if (!fs.existsSync.__qodiqaNoDockerenv) {
  const realExistsSync = fs.existsSync;
  const patched = function existsSync(p) { return p === '/.dockerenv' ? false : realExistsSync.call(this, p); };
  patched.__qodiqaNoDockerenv = true;
  fs.existsSync = patched;
}

try {
  // Only set the path if not already overridden by the calling environment.
  if (!process.env.QODIQA_KEYS_PATH) {
    const ksDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-ks-'));
    process.env.QODIQA_KEYS_PATH = path.join(ksDir, 'keys.json');
  }

  // Redirect audit log writes to a per-run temp file so tests never pollute
  // the production audit.log and the chain starts clean for every test run.
  if (!process.env.QODIQA_AUDIT_LOG) {
    const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-audit-'));
    process.env.QODIQA_AUDIT_LOG = path.join(auditDir, 'audit.log');
  }

  // ensureActiveKey() is a no-op if the store already has an active 'default'
  // key — avoids double-provisioning when QODIQA_KEYS_PATH was already set to
  // a non-empty store by the caller. Shared with scripts/bootstrap-dev.js so
  // the "provision if empty" logic lives in exactly one place.
  const { ensureActiveKey } = require('../../scripts/lib/keyStoreProvisioning');
  ensureActiveKey('default');
} catch (_) {
  // keyStore unavailable or env not ready — tests manage their own provisioning.
}

// step 6: the audit-checkpoint key file is NOT set here — it defaults to checkpoint-keys.json next to
// QODIQA_TRANSPARENCY_KEYS_PATH (checkpointKeyStore.js), so the per-file transparency isolation below isolates it too, and
// a server a test spawns with its own transparency path gets its own checkpoint key file (an inherited explicit path
// would be shared by every spawn of the file, across different KEKs).

// Per-worker transparency key store isolation (Component #30).
// Must be set before transparencyKeyStore is required, since DATA_PATH is
// evaluated at require() time from QODIQA_TRANSPARENCY_KEYS_PATH.
try {
  if (!process.env.QODIQA_TRANSPARENCY_KEYS_PATH) {
    const tsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-ts-'));
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = path.join(tsDir, 'transparency-keys.json');
  }
  const { ensureActiveTransparencyKey } = require('../../scripts/lib/keyStoreProvisioning');
  ensureActiveTransparencyKey();
} catch (_) {
  // transparency key store unavailable — tests manage their own provisioning.
}

// ──: teardown-race guard for ENDING pg pools ────────────
// `await pool.end()` resolves before its sockets close, so a suite's teardown DROP DATABASE … WITH (FORCE) can
// terminate a still-closing backend; the FATAL 57P01 is then re-emitted on the pool and, on a test pool with no
// 'error' listener, thrown as "Unhandled error" into whatever suite is running (reproduced 11/300 against a PG17
// container). Only pools that are ENDING and have no listener of their own get
// an absorbing listener; live pools and every product pool (which has its own listener) are untouched.
try {
  require('../helpers/pgEndingPoolGuard').installEndingPoolGuard(require('pg'));
} catch (_) {
  // pg not installed in this context — nothing to guard.
}
