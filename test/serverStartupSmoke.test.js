'use strict';

/**
 * Permanent regression test — Full Production Startup Smoke Test.
 *
 * Spawns the REAL server.js — as a genuine child OS process via
 * child_process.spawn, never require()'d and never mocked — inside a
 * fully isolated, ephemeral environment prepared the exact same way
 * scripts/bootstrap-dev.js prepares one (shared via
 * scripts/lib/devEnvironment.js), and asserts it reaches the normal
 * production-ready state (the GATEWAY_START log event) and that /health
 * responds successfully.
 *
 * Why this test exists: this is the only place in the entire Jest suite
 * that boots server.js as a whole, unmocked process. Every other test
 * either constructs an individual Express router in isolation (often with
 * `jest.mock('../../core/rateLimit', ...)` or similar module replacements)
 * or injects test-double stores (nonce/anomaly/rate-limit) directly into
 * individual functions. That gap is exactly what let a real integration
 * defect — a route referencing an unregistered rate-limit surface — ship
 * silently through 7206 passing tests: nothing exercised server.js's
 * actual, complete route-registration sequence. This test closes that gap
 * permanently. See test/rateLimitSurfaceConsistency.test.js for the
 * companion static-analysis regression test.
 *
 * No mocking: key manager, policy engine, consent-verification wiring,
 * rate limiter, and startup validation are never stubbed — spawning a real
 * separate OS process makes that structurally impossible, not just a
 * convention this file follows.
 *
 * Redis: this test needs a real, reachable Redis instance (the consent-
 * revocation subscriber has no dev-mode bypass — see docs/guides/installation.md). It
 * probes reachability first and SKIPS (does not fail) if Redis is
 * unavailable, mirroring the existing REAL_PG conditional-skip pattern in
 * src/infra/postgres/__tests__/rls.test.js.
 */

const fs   = require('fs');
const net  = require('net');
const path = require('path');
const { spawn } = require('child_process');


const REPO_ROOT          = path.join(__dirname, '..');
const STARTUP_TIMEOUT_MS = 25_000;

// services/artifact/keyStore.js's DATA_PATH (and transparencyKeyStore.js's
// bootstrap, which still runs synchronously at require() time) are evaluated
// from QODIQA_KEYS_PATH/QODIQA_TRANSPARENCY_KEYS_PATH the first time each
// module is require()'d — and test/support/jest.setup.js has already required keyStore.js
// once, for the 'default' client, at its own temp path. Without
// jest.resetModules() here, prepareIsolatedEnvironment()'s internal
// ensureActiveKey() call would silently operate on that already-cached
// instance (writing to test/support/jest.setup.js's temp path) instead of the fresh path
// this test just set — leaving the file the spawned child actually reads
// empty. jest.resetModules() forces the next require() of keyStore.js
// (triggered inside prepareIsolatedEnvironment, via
// scripts/lib/keyStoreProvisioning.js) to re-evaluate DATA_PATH from the env
// vars this test controls; keyStore's own key-loading bootstrap then runs
// lazily, on ensureActiveKey()'s first real store access rather than at that
// require() call itself, but still against the freshly re-evaluated path.
// Re-require devEnvironment.js itself afterward so its whole dependency
// chain resolves fresh, matching the existing loadFresh() pattern in
//.
function requireDevEnvironmentFresh() {
  jest.resetModules();
  return require('../scripts/lib/devEnvironment');
}

// process.env is a real OS-backed object shared by this whole Jest worker
// process — NOT reset between test files in the same worker. This test
// mutates it (via prepareIsolatedEnvironment) to build the child's
// environment, then must restore exactly what it changed so no other test
// file that happens to share this worker ever observes leaked isolated
// secrets/paths.
const ENV_KEYS_TO_ISOLATE = [
  'NODE_ENV', 'QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_CLIENT_ID',
  'QODIQA_KEYS_PATH', 'QODIQA_AUDIT_LOG', 'QODIQA_TRANSPARENCY_KEYS_PATH',
  'QODIQA_SIGNING_STORE_PATH',
  'LOCAL_BASE_URL', 'STRICT_REPLAY_PROTECTION',
  // this test process's own env should never carry an ambient
  // QODIQA_DEPLOYMENT_MODE into (or out of) the child's environment — see
  // the childEnv comment below.
  'QODIQA_DEPLOYMENT_MODE',
];

function snapshotEnv(keys) {
  const snap = {};
  for (const k of keys) snap[k] = process.env[k];
  return snap;
}

function restoreEnv(snap) {
  for (const [k, v] of Object.entries(snap)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

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

let _redisAvailable = null;
async function isRedisAvailable() {
  if (_redisAvailable === null) {
    _redisAvailable = await require('./helpers/redisTarget').reachable(); // phase 17: explicit REDIS_URL only — the old
    // `|| 'redis://localhost:6379'` fallback probed (and the spawned server then used) the LIVE qodiqa-redis container
  }
  return _redisAvailable;
}

describe('Full production startup smoke test (regression)', () => {
  let child;
  let tempRoot;

  afterEach(async () => {
    if (child && !child.killed) {
      await new Promise((resolve) => {
        const forceKill = setTimeout(() => {
          try { child.kill('SIGKILL'); } catch { /* already gone */ }
          resolve();
        }, 3000);
        child.once('exit', () => { clearTimeout(forceKill); resolve(); });
        child.kill('SIGTERM');
      });
    }
    child = null;

    if (tempRoot && fs.existsSync(tempRoot)) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
    tempRoot = null;
  });

  test('real server.js reaches GATEWAY_START and /health responds, using fully isolated storage', async () => {
    if (!(await isRedisAvailable())) {
      // eslint-disable-next-line no-console
      console.warn(
        '[serverStartupSmoke] Redis not reachable at ' +
        `${process.env.REDIS_URL || '(no explicit REDIS_URL)'} — skipping. ` +
        'Redis is a genuine, unconditional prerequisite for a full server boot ' +
        '(consent-revocation subscriber has no bypass); see docs/guides/installation.md.',
      );
      return;
    }

    const port = await getFreePort();
    const envSnapshot = snapshotEnv(ENV_KEYS_TO_ISOLATE);

    const { prepareIsolatedEnvironment } = requireDevEnvironmentFresh();
    const { paths } = await prepareIsolatedEnvironment({
      clientId:   'dev-smoke-test',
      tempPrefix: 'qodiqa-smoke-',
    });
    tempRoot = paths.root;

    // Build the child's environment from this (now-isolated) process.env,
    // then immediately restore this test process's own env so nothing
    // leaks into later tests in the same Jest worker.
    //
    // QODIQA_PG_ENABLED is forced off here: prepareIsolatedEnvironment()
    // isolates the file-based audit log to a fresh temp path per run, but
    // deliberately does not (and cannot, cheaply) isolate the ambient
    // PostgreSQL instance configured in .env — that connection is real and
    // shared with interactive `npm run dev` sessions.'s startup
    // mirror-consistency check (src/core/audit/mirrorConsistencyCheck.js)
    // correctly refuses to boot when this run's fresh, empty file chain
    // doesn't match whatever unrelated rows already sit in that shared
    // database's audit_chain table — that is the feature working as
    // intended, not a defect in it. This smoke test only asserts on generic
    // startup milestones (GATEWAY_START, /health), never on PG-mirror
    // behavior, so it opts out of the mirror entirely rather than trying to
    // reset a real external database it doesn't own.
    //
    // QODIQA_DEPLOYMENT_MODE is explicitly pinned to 'single-node':
    // that mode still honors QODIQA_PG_ENABLED='false' below exactly as
    // before this variable existed (single-node mode leaves PG enablement to
    // the legacy var — see src/infra/config/deploymentMode.js), so this is
    // not a behavior change, just making explicit what was previously only
    // true because the var didn't exist yet — immune to whatever an
    // operator's ambient shell/CI environment happens to export.
    const childEnv = {
      ...process.env,
      PORT: String(port),
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      QODIQA_PG_ENABLED: 'false',
    };
    restoreEnv(envSnapshot);

    const outputChunks = [];
    let readyEvent  = null;
    let fatalEvent  = null;
    const seenEvents = new Set();

    child = spawn(process.execPath, ['server.js'], {
      cwd:   REPO_ROOT,
      env:   childEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const onData = (buf) => {
      const text = buf.toString();
      outputChunks.push(text);
      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let parsed;
        try { parsed = JSON.parse(trimmed); } catch { continue; }
        if (parsed.eventType) seenEvents.add(parsed.eventType);
        if (parsed.eventType === 'GATEWAY_START') readyEvent = parsed;
        if (parsed.severity === 'FATAL' && !fatalEvent) fatalEvent = parsed;
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);

    const deadline = Date.now() + STARTUP_TIMEOUT_MS;
    while (!readyEvent && !fatalEvent && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 150));
    }

    if (fatalEvent) {
      throw new Error(
        `server.js reported a FATAL event during startup: ${JSON.stringify(fatalEvent)}\n\n` +
        `Full process output:\n${outputChunks.join('')}`,
      );
    }
    if (!readyEvent) {
      throw new Error(
        `server.js did not reach GATEWAY_START within ${STARTUP_TIMEOUT_MS}ms.\n\n` +
        `Full process output:\n${outputChunks.join('')}`,
      );
    }

    // The real production startup pipeline actually ran end to end — not
    // just the final event, but the intermediate milestones that prove the
    // key manager, policy engine, and rate limiter genuinely initialized
    // (none of which are reachable through a mocked module).
    expect(seenEvents.has('KEY_MANAGER_READY')).toBe(true);
    expect(seenEvents.has('POLICIES_LOADED')).toBe(true);
    expect(seenEvents.has('RATE_LIMIT_CONFIG_LOADED')).toBe(true);
    expect(readyEvent.ready).toBe(true);

    // Real HTTP request against the real running process.
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('ok');
  }, STARTUP_TIMEOUT_MS + 10_000);
});
