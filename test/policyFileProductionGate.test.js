'use strict';

/**
 * production policy-file selection startup gate.
 *
 * Two layers, following the established startup-gate pattern
 * (test/evidenceDurabilityStartupGate.test.js = the most recent example of
 * this exact shape: static structural pins + real spawned boots):
 *
 *   STATIC — pins, from server/startup.js's and services/policy/loader.js's
 *     source text, that:
 *       - the production profile is keyed on NODE_ENV=production (the same
 *         key REPLAY-2/F-03 already use — no new knob),
 *       - resolvePolicyFilePath() is the single function deciding this (not
 *         a second, inline check duplicating the same logic),
 *       - the resolution happens before loadPolicies()/app.listen(), wrapped
 *         in a try/catch that emits FATAL POLICY_FILE_REQUIRED and exits.
 *
 *   SPAWNED BOOTS — three real server.js child processes (never require()'d,
 *   never mocked):
 *     - production + no POLICY_FILE   → exits non-zero with FATAL
 *       POLICY_FILE_REQUIRED, never reaches GATEWAY_START or POLICIES_LOADED.
 *       Needs no Redis/PG — this check runs before either is touched.
 *     - production + explicit POLICY_FILE (deploy/env/production.policies.example)
 *       → boots to GATEWAY_START with POLICIES_LOADED present.
 *     - non-production + no POLICY_FILE → boots to GATEWAY_START using the
 *       existing, intentional developer convenience (the repo-root
 *       policies.json demo fixture) — proves dev/test behavior is untouched.
 */

const fs   = require('fs');
const net  = require('net');
const path = require('path');
const { spawn } = require('child_process');

const { validProductionEnv, pickIsolation } = require('./helpers/productionEnv');

const REPO_ROOT       = path.join(__dirname, '..');
const STARTUP_JS      = path.join(REPO_ROOT, 'server', 'startup.js');
const LOADER_JS        = path.join(REPO_ROOT, 'services', 'policy', 'loader.js');
const EXAMPLE_POLICY   = path.join(REPO_ROOT, 'deploy/env/production.policies.example');
const BOOT_TIMEOUT_MS  = 30_000;

// ── STATIC pins ──────────────────────────────────────────────────────────────

describe('gate — static structural pins', () => {
  let startupSource, loaderSource;
  beforeAll(() => {
    startupSource = fs.readFileSync(STARTUP_JS, 'utf8');
    loaderSource  = fs.readFileSync(LOADER_JS, 'utf8');
  });

  test('resolvePolicyFilePath() is keyed on NODE_ENV=production, no new knob', () => {
    expect(loaderSource).toMatch(/process\.env\.NODE_ENV\s*===\s*'production'/);
    expect(loaderSource).toMatch(/err\.code\s*=\s*'POLICY_FILE_REQUIRED'/);
  });

  test('server/startup.js resolves POLICY_FILE via the shared helper, not an inline duplicate', () => {
    expect(startupSource).toMatch(/require\(\s*['"]\.\.\/services\/policy\/loader['"]\s*\)/);
    expect(startupSource).toMatch(/resolvePolicyFilePath\s*\(/);
    // Guard against a second, independently-duplicated fallback expression
    // reappearing (the exact shape this remediation removed).
    expect(startupSource).not.toMatch(/process\.env\.POLICY_FILE\s*\|\|\s*path\.resolve/);
  });

  test('the POLICY_FILE resolution is wrapped in try/catch, emits FATAL, and exits — before loadPolicies()/app.listen()', () => {
    const resolveIdx = startupSource.indexOf('resolvePolicyFilePath(');
    const fatalIdx    = startupSource.indexOf('POLICY_FILE_REQUIRED', resolveIdx);
    const loadCallIdx = startupSource.indexOf('loadPolicies(POLICY_FILE)');
    expect(resolveIdx).toBeGreaterThan(-1);
    expect(fatalIdx).toBeGreaterThan(resolveIdx);
    expect(fatalIdx).toBeLessThan(loadCallIdx);
    // The window between the resolve call and loadPolicies() must contain
    // both the FATAL emit and a process.exit(1).
    const window = startupSource.slice(resolveIdx, loadCallIdx);
    expect(window).toMatch(/emit\(\s*'FATAL'\s*,\s*'POLICY_FILE_REQUIRED'/);
    expect(window).toMatch(/process\.exit\(1\)/);
  });
});

// ── SPAWNED boots ────────────────────────────────────────────────────────────

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
 * Spawns server.js with the given env overlay; resolves when the process
 * exits, or when `resolveOnEvent` (an eventType) is seen.
 */
function bootServer(childEnv, { resolveOnEvent = null, timeoutMs = BOOT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const events = [];
    const chunks = [];
    const child = spawn(process.execPath, ['server.js'], {
      cwd: REPO_ROOT, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let settled = false;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!child.killed) { try { child.kill('SIGKILL'); } catch { /* gone */ } }
      resolve(result);
    };
    const timer = setTimeout(() => {
      settle({ timedOut: true, exitCode: null, events, output: chunks.join('') });
    }, timeoutMs);
    const onData = (buf) => {
      const text = buf.toString();
      chunks.push(text);
      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        let parsed;
        try { parsed = JSON.parse(trimmed); } catch { continue; }
        if (parsed.eventType) events.push(parsed);
        if (resolveOnEvent && parsed.eventType === resolveOnEvent) {
          settle({ timedOut: false, exitCode: null, events, output: chunks.join('') });
        }
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', reject);
    child.on('exit', (code) => settle({ timedOut: false, exitCode: code, events, output: chunks.join('') }));
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

describe('gate — real spawned boots', () => {
  function requireDevEnvironmentFresh() {
    jest.resetModules();
    return require('../scripts/lib/devEnvironment');
  }

  const ENV_KEYS_TO_ISOLATE = [
    'NODE_ENV', 'QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_CLIENT_ID',
    'QODIQA_KEYS_PATH', 'QODIQA_AUDIT_LOG', 'QODIQA_TRANSPARENCY_KEYS_PATH',
    'QODIQA_SIGNING_STORE_PATH', 'POLICY_FILE',
    'LOCAL_BASE_URL', 'STRICT_REPLAY_PROTECTION', 'QODIQA_DEPLOYMENT_MODE',
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

  let tempRoot;
  afterEach(() => {
    if (tempRoot && fs.existsSync(tempRoot)) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
    tempRoot = null;
  });

  async function isolatedChildEnv(overrides, { production = false } = {}) {
    const snap = snapshotEnv(ENV_KEYS_TO_ISOLATE);
    const { prepareIsolatedEnvironment } = requireDevEnvironmentFresh();
    const { paths } = await prepareIsolatedEnvironment({
      clientId: 'dev-f19-gate', tempPrefix: 'qodiqa-f19-',
    });
    tempRoot = paths.root;
    const port = String(await getFreePort());
    // a production child is built by validProductionEnv() (system env only,
    // every other production boot rule satisfied, self-checked) so the rule
    // under test is the only one that can refuse; the isolated keystore and the
    // KEK/client id it was provisioned under are carried over.
    const childEnv = production
      ? validProductionEnv({
        keysPath: process.env.QODIQA_KEYS_PATH,
        overrides: { ...pickIsolation(process.env), PORT: port, ...overrides },
      })
      : {
        ...process.env,
        PORT: port,
        QODIQA_EXECUTION_INVARIANT_SECRET: require('crypto').randomBytes(32).toString('hex'),
        ...overrides,
      };
    restoreEnv(snap);
    return childEnv;
  }

  // the missing-POLICY_FILE refusal now happens in boot validation, before
  // any listener or store is touched; resolvePolicyFilePath()'s own
  // POLICY_FILE_REQUIRED stays as defense in depth (pinned statically above).
  test('production + no POLICY_FILE → refuses at boot validation naming POLICY_FILE only, non-zero exit, no GATEWAY_START', async () => {
    const childEnv = await isolatedChildEnv({
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      POLICY_FILE: undefined, // the exact condition under test (deleted)
    }, { production: true });
    expect('POLICY_FILE' in childEnv).toBe(false);
    const r = await bootServer(childEnv);
    expect(r.timedOut).toBe(false);
    expect(r.exitCode).not.toBe(0);
    const fatal = r.events.find((e) => e.eventType === 'BOOT_VALIDATION_FATAL');
    if (!fatal) {
      throw new Error('no BOOT_VALIDATION_FATAL event; exit=' + r.exitCode + '\nlast output:\n' + r.output.slice(-3000));
    }
    expect(fatal.severity).toBe('FATAL');
    expect(fatal.profile).toBe('prod');
    expect(fatal.violations.map((v) => v.variable)).toEqual(['POLICY_FILE']);
    expect(fatal.violations[0].message).toMatch(/production.policies.example/);
    expect(r.events.some((e) => e.eventType === 'GATEWAY_START')).toBe(false);
    expect(r.events.some((e) => e.eventType === 'POLICIES_LOADED')).toBe(false);
  }, BOOT_TIMEOUT_MS + 10_000);

  test('production + explicit POLICY_FILE (deploy/env/production.policies.example) → boots to GATEWAY_START with POLICIES_LOADED', async () => {
    if (!(await isRedisAvailable())) {
      // eslint-disable-next-line no-console
      console.warn('[policyFileProductionGate] Redis not reachable — skipping (same skip pattern as serverStartupSmoke.test.js).');
      return;
    }
    const childEnv = await isolatedChildEnv({
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      QODIQA_PG_ENABLED: 'false',
      POLICY_FILE: EXAMPLE_POLICY,
    });
    // This test is about POLICY_FILE, not the production profile itself.
    // (D-A): an unset NODE_ENV now refuses to boot, so it is stated explicitly.
    childEnv.NODE_ENV = 'development';
    const r = await bootServer(childEnv, { resolveOnEvent: 'GATEWAY_START' });
    expect(r.timedOut).toBe(false);
    expect(r.events.some((e) => e.eventType === 'GATEWAY_START')).toBe(true);
    expect(r.events.some((e) => e.eventType === 'POLICIES_LOADED')).toBe(true);
    expect(r.events.some((e) => e.eventType === 'POLICY_FILE_REQUIRED')).toBe(false);
  }, BOOT_TIMEOUT_MS + 10_000);

  test('non-production + no POLICY_FILE → boots to GATEWAY_START using the existing repo-root policies.json default (dev/test behavior unchanged)', async () => {
    if (!(await isRedisAvailable())) {
      // eslint-disable-next-line no-console
      console.warn('[policyFileProductionGate] Redis not reachable — skipping (same skip pattern as serverStartupSmoke.test.js).');
      return;
    }
    const childEnv = await isolatedChildEnv({
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      QODIQA_PG_ENABLED: 'false',
    });
    childEnv.NODE_ENV = 'development'; // explicitly non-production
    delete childEnv.POLICY_FILE; // the exact condition under test
    const r = await bootServer(childEnv, { resolveOnEvent: 'GATEWAY_START' });
    expect(r.timedOut).toBe(false);
    expect(r.events.some((e) => e.eventType === 'GATEWAY_START')).toBe(true);
    expect(r.events.some((e) => e.eventType === 'POLICIES_LOADED')).toBe(true);
    expect(r.events.some((e) => e.eventType === 'POLICY_FILE_REQUIRED')).toBe(false);
  }, BOOT_TIMEOUT_MS + 10_000);
});
