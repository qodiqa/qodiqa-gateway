'use strict';

/**
 * LOG-1 / regression — PG circuit-breaker self-amplifying logging
 * cascade must not recur.
 *
 * pool.js's query() emits logger.emit('WARN', 'PG_CIRCUIT_OPEN', ...) (and,
 * on any real query failure, emit('ERROR', 'PG_QUERY_ERROR', ...))
 * synchronously, before ever awaiting anything. logger.emit()'s last step
 * is a fire-and-forget call into centralStore.ingest(), which itself calls
 * pgPool.query() — so, unguarded, a query failure ingest() is trying to log
 * about re-triggers the exact same ingest() call on the same native call
 * stack: ingest() -> query() -> emit() -> ingest() -> ..., unbounded until
 * Node's own stack limit throws RangeError. Live-witnessed producing both a
 * sustained event flood (443,618 events/~31s from a single ~12s PG
 * outage) and outright process death via processHardening.js's fail-fast
 * unhandledRejection handler. Fixed via a synchronous
 * re-entrancy guard in centralStore.ingest() (see that file's own LOG-1
 * comment) for the full live
 * before/after numbers this test's own thresholds are derived from.
 *
 * This test reproduces the actual feedback condition against a REAL,
 * genuinely running server.js (child process, same pattern as
 * test/serverStartupSmoke.test.js) and a REAL, disposable PostgreSQL
 * cluster — own initdb, own port, own process — driven into a genuine
 * outage by killing it mid-test (not a mock, not a forced in-process
 * state). This is the chaos-harness pattern: the real,
 * shared postgresql-x64-17 service is never touched (this test never
 * connects to it, targets it, or discovers its data — only its own
 * install directory's binaries are reused, read-only, to build a wholly
 * separate disposable cluster on its own port).
 *
 * Asserts: the resulting PG_CIRCUIT_OPEN volume over a real observation
 * window stays bounded (roughly 1-2 events per real trigger, not
 * thousands), the very first breaker-open WARN still reaches the log
 * stream (operational signal preserved, only the amplification is
 * suppressed), the server process survives without any FATAL/RangeError/
 * uncaught-exception/unhandled-rejection event, and the server stays
 * genuinely responsive (a real /health round-trip) throughout.
 */

const fs   = require('fs');
const net  = require('net');
const os   = require('os');
const path = require('path');
const { spawn, spawnSync, execSync } = require('child_process');


const REPO_ROOT          = path.join(__dirname, '..');
const STARTUP_TIMEOUT_MS = 30_000;
// Real observation window post-outage. Shorter than's original ~31s
// (which this test's own reproduces
// in full) — long enough (with a 500ms readiness-check interval) to collect
// well over a dozen independent real triggers and prove the growth rate is
// linear/bounded, not exponential.
const OBSERVATION_WINDOW_MS = 8_000;

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/**
 * Locates the real PostgreSQL install's bin/ directory by reading the
 * shared postgresql-x64-17 Windows service's own binary path — read-only
 * inspection, never a connection to or mutation of that service. Falls back
 * to null (caller skips) if the service isn't found, so this test degrades
 * the same way serverStartupSmoke.test.js degrades on missing Redis.
 */
function findPgBinDir() {
  try {
    const out = execSync(
      'powershell -NoProfile -Command "(Get-CimInstance Win32_Service -Filter \\"Name=\'postgresql-x64-17\'\\").PathName"',
      { encoding: 'utf8' },
    ).trim();
    const match = out.match(/"([^"]+\\bin\\pg_ctl\.exe)"/i);
    if (!match) return null;
    return path.dirname(match[1]);
  } catch {
    return null;
  }
}

let _redisAvailable = null;
async function isRedisAvailable() {
  if (_redisAvailable === null) {
    _redisAvailable = await require('./helpers/redisTarget').reachable(); // phase 17: explicit REDIS_URL only — the old
    // `|| 'redis://localhost:6379'` fallback probed (and the spawned server then used) the LIVE qodiqa-redis container
  }
  return _redisAvailable;
}

describe('LOG-1 / PG circuit-breaker logging cascade (regression)', () => {
  let pgBinDir;
  let pgDataDir;
  let pgLogFile;
  let pgPort;
  let dbName;
  let appPort;
  let server;
  let envTempRoot;
  let pgStarted = false;

  beforeAll(() => {
    pgBinDir = findPgBinDir();
  });

  afterEach(async () => {
    if (server && !server.killed) {
      await new Promise((resolve) => {
        const forceKill = setTimeout(() => { try { server.kill('SIGKILL'); } catch { /* gone */ } resolve(); }, 3000);
        server.once('exit', () => { clearTimeout(forceKill); resolve(); });
        server.kill('SIGTERM');
      });
    }
    server = null;

    if (pgStarted && pgBinDir && pgDataDir) {
      spawnSync(path.join(pgBinDir, 'pg_ctl.exe'), ['-D', pgDataDir, '-m', 'immediate', 'stop'], { encoding: 'utf8', timeout: 15_000 });
      pgStarted = false;
    }
    if (pgDataDir && fs.existsSync(pgDataDir)) fs.rmSync(pgDataDir, { recursive: true, force: true });
    if (envTempRoot && fs.existsSync(envTempRoot)) fs.rmSync(envTempRoot, { recursive: true, force: true });
    pgDataDir = null;
    envTempRoot = null;
  });

  test('a real forced PG outage produces a bounded event count, preserves the first WARN, and never crashes the server', async () => {
    if (!pgBinDir) {
      // eslint-disable-next-line no-console
      console.warn('[log1CircuitBreakerCascade] postgresql-x64-17 service (or its bin/ directory) not found — skipping. This test only reads that service\'s install path; it never connects to or touches the service itself.');
      return;
    }
    if (!(await isRedisAvailable())) {
      // eslint-disable-next-line no-console
      console.warn('[log1CircuitBreakerCascade] Redis not reachable — skipping, same precondition as serverStartupSmoke.');
      return;
    }

    // ── Stand up a wholly separate, disposable PostgreSQL cluster ──────────
    // Every spawnSync below gets an explicit `timeout` — spawnSync blocks
    // the whole process synchronously, so without one, a hung child (e.g. a
    // misconfigured pg_ctl wait) can never be interrupted by jest's own
    // (async, event-loop-based) testTimeout, and the test hangs forever
    // instead of failing fast. On a timeout, spawnSync kills the child and
    // sets `.signal` rather than `.status` — surfaced via failStep() below
    // with full stdout/stderr so a real failure here is diagnosable, not
    // just "expect(0) received null".
    function failStep(name, res) {
      throw new Error(
        `${name} failed (status=${res.status}, signal=${res.signal}, error=${res.error?.message ?? 'none'})\n` +
        `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`,
      );
    }

    pgDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-log1-pgdata-'));
    fs.rmdirSync(pgDataDir); // initdb requires the target dir not already exist
    pgLogFile = path.join(os.tmpdir(), `qodiqa-log1-pg-${Date.now()}.log`);
    pgPort    = await getFreePort();
    dbName    = 'qodiqa_log1_test';

    const initRes = spawnSync(path.join(pgBinDir, 'initdb.exe'),
      ['--auth=trust', '-U', 'postgres', '-E', 'UTF8', '--locale=C', '-D', pgDataDir],
      { encoding: 'utf8', timeout: 30_000 });
    if (initRes.status !== 0) failStep('initdb', initRes);

    // -p as its own clean array element (spawnSync with an args array never
    // goes through a shell, so no quoting is needed or wanted here — an
    // earlier version of this test passed `-p ${pgPort} -k ""` as ONE
    // element, which embedded literal quote characters into pg_ctl's -o
    // value instead of the shell-stripped value a manual, shell-based
    // rehearsal of the same command got; -k (unix socket dir) is dropped
    // entirely since Windows PostgreSQL builds have no unix-socket support
    // to begin with).
    const startRes = spawnSync(path.join(pgBinDir, 'pg_ctl.exe'),
      ['-D', pgDataDir, '-l', pgLogFile, '-o', `-p ${pgPort}`, '-w', '-t', '30', 'start'],
      { encoding: 'utf8', timeout: 35_000 });
    if (startRes.status !== 0) failStep('pg_ctl start', startRes);
    pgStarted = true;

    const createRes = spawnSync(path.join(pgBinDir, 'createdb.exe'),
      ['-h', '127.0.0.1', '-p', String(pgPort), '-U', 'postgres', dbName],
      { encoding: 'utf8', timeout: 15_000 });
    if (createRes.status !== 0) failStep('createdb', createRes);

    const migrateEnv = {
      ...process.env,
      QODIQA_PG_HOST: '127.0.0.1',
      QODIQA_PG_PORT: String(pgPort),
      QODIQA_PG_DATABASE: dbName,
      QODIQA_PG_MIG_USER: 'postgres',
      QODIQA_PG_SSL: 'false',
    };
    const migrateRes = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, env: migrateEnv, encoding: 'utf8', timeout: 30_000,
    });
    if (migrateRes.status !== 0) failStep('migrate.js', migrateRes);

    // ── Isolated key/audit/RBAC storage (never the real repo's own files) ──
    // jest.resetModules() first: test/support/jest.setup.js already required keyStore.js
    // once for the 'default' client at its own temp path — without a reset,
    // prepareIsolatedEnvironment()'s own ensureActiveKey() call would
    // silently reuse that cached instance instead of re-evaluating DATA_PATH
    // from the env vars this test controls (same reasoning as
    // test/serverStartupSmoke.test.js's own requireDevEnvironmentFresh()).
    const envSnapshot = {};
    for (const k of ['NODE_ENV', 'QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_CLIENT_ID', 'QODIQA_KEYS_PATH',
      'QODIQA_AUDIT_LOG', 'QODIQA_TRANSPARENCY_KEYS_PATH', 'QODIQA_SIGNING_STORE_PATH', 'QODIQA_DEPLOYMENT_MODE']) {
      envSnapshot[k] = process.env[k];
    }
    jest.resetModules();
    const { prepareIsolatedEnvironment } = require('../scripts/lib/devEnvironment');
    const { paths } = await prepareIsolatedEnvironment({ clientId: 'log1-cascade-test', tempPrefix: 'qodiqa-log1-env-' });
    envTempRoot = paths.root;

    appPort = await getFreePort();
    const serverEnv = {
      ...process.env,
      PORT: String(appPort),
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      QODIQA_PG_ENABLED: 'true',
      QODIQA_PG_HOST: '127.0.0.1',
      QODIQA_PG_PORT: String(pgPort),
      QODIQA_PG_DATABASE: dbName,
      QODIQA_PG_USER: 'postgres',
      QODIQA_PG_SSL: 'false',
      // Fast, deterministic breaker/readiness timings so an 8s observation
      // window contains many independent real triggers.
      QODIQA_PG_CB_FAILURE_THRESHOLD: '2',
      QODIQA_PG_CB_RECOVERY_MS: '120000', // stays OPEN for the whole test
      QODIQA_PG_READY_CHECK_INTERVAL_MS: '500',
      QODIQA_PG_READY_TIMEOUT_MS: '400',
    };
    for (const [k, v] of Object.entries(envSnapshot)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }

    const outputChunks = [];
    const events = [];
    let readyEvent = null;
    let fatalEvent = null;

    server = spawn(process.execPath, ['server.js'], {
      cwd: REPO_ROOT, env: serverEnv, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const onData = (buf) => {
      const text = buf.toString();
      outputChunks.push(text);
      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let parsed;
        try { parsed = JSON.parse(trimmed); } catch { continue; }
        events.push(parsed);
        if (parsed.eventType === 'GATEWAY_START') readyEvent = parsed;
        if (parsed.severity === 'FATAL' && !fatalEvent) fatalEvent = parsed;
      }
    };
    server.stdout.on('data', onData);
    server.stderr.on('data', onData);

    const startDeadline = Date.now() + STARTUP_TIMEOUT_MS;
    while (!readyEvent && !fatalEvent && Date.now() < startDeadline) {
      await new Promise((r) => setTimeout(r, 150));
    }
    if (fatalEvent) throw new Error(`server.js reported FATAL during startup: ${JSON.stringify(fatalEvent)}\n${outputChunks.join('')}`);
    if (!readyEvent) throw new Error(`server.js did not reach GATEWAY_START within ${STARTUP_TIMEOUT_MS}ms.\n${outputChunks.join('')}`);

    // ── Force a REAL outage: kill the disposable cluster ────────────────────
    events.length = 0; // only count events from here on
    const outageStart = Date.now();
    const stopRes = spawnSync(path.join(pgBinDir, 'pg_ctl.exe'), ['-D', pgDataDir, '-m', 'immediate', 'stop'], { encoding: 'utf8', timeout: 15_000 });
    if (stopRes.status !== 0) failStep('pg_ctl -m immediate stop (forcing the outage)', stopRes);
    pgStarted = false;

    await new Promise((r) => setTimeout(r, OBSERVATION_WINDOW_MS));

    // ── The server must still be alive and genuinely responsive ────────────
    expect(server.killed).toBe(false);
    expect(server.exitCode).toBeNull();
    const health = await fetch(`http://127.0.0.1:${appPort}/health`, { signal: AbortSignal.timeout(5000) }).catch((e) => e);
    expect(health).not.toBeInstanceOf(Error);
    expect(health.status).toBe(200);
    const healthBody = await health.json();
    expect(healthBody.status).toBe('ok');

    // ── No crash-class event of any kind ────────────────────────────────────
    const crashEvents = events.filter((e) =>
      e.severity === 'FATAL' ||
      e.eventType === 'UNCAUGHT_EXCEPTION' ||
      e.eventType === 'UNHANDLED_REJECTION' ||
      (typeof e.message === 'string' && e.message.includes('Maximum call stack size exceeded')));
    expect(crashEvents).toEqual([]);

    // ── Bounded, not a flood ─────────────────────────────────────────────────
    const circuitOpenEvents = events.filter((e) => e.eventType === 'PG_CIRCUIT_OPEN');
    expect(circuitOpenEvents.length).toBeGreaterThan(0); // the outage genuinely tripped it
    //'s original, unfixed measurement: 443,618 events over ~31s from
    // a single ~12s outage (~14,300/s). A generous, still-decisive bound for
    // this test's shorter window and lighter trigger rate: two orders of
    // magnitude below that sustained rate, scaled to OBSERVATION_WINDOW_MS.
    const maxAcceptable = Math.ceil((OBSERVATION_WINDOW_MS / 1000) * 150);
    expect(circuitOpenEvents.length).toBeLessThan(maxAcceptable);

    // ── Signal preserved: the very first breaker-open WARN is present ──────
    expect(circuitOpenEvents[0].severity).toBe('WARN');
    const firstWarnDelayMs = new Date(circuitOpenEvents[0].timestamp).getTime() - outageStart;
    // Generous upper bound — the breaker only needs QODIQA_PG_CB_FAILURE_THRESHOLD
    // (2) consecutive real connection failures, which should land well within
    // a couple of seconds of the outage starting.
    expect(firstWarnDelayMs).toBeLessThan(5000);
  }, STARTUP_TIMEOUT_MS + OBSERVATION_WINDOW_MS + 60_000);
});
