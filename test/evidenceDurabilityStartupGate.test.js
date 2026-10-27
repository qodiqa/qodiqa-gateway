'use strict';

/**
 * production evidence-durability startup gate.
 *
 * Two layers, following the established startup-gate pattern
 * (test/auditMirrorStartupGate.test.js = static structural pins;
 * test/serverStartupSmoke.test.js = real spawned boots):
 *
 *   STATIC — pins, from server/startup.js's source text, that:
 *     • the production profile is keyed on NODE_ENV=production (the same key
 *       REPLAY-2's STRICT_REPLAY forcing uses — no new knob),
 *     • the gate calls the real probeEvidenceStores module, awaits it,
 *       textually precedes app.listen(), and exits the process on failure
 *       (both the PG-disabled and store-not-ready branches),
 *   and, from the shipped deploy profiles, that every production profile
 *   defaults to PG enabled (docker-compose.prod.yml and the kubernetes
 *   distributed overlay via QODIQA_DEPLOYMENT_MODE=distributed; the base
 *   configmap stamps NODE_ENV=production; the kubernetes single-node
 * overlay via QODIQA_PG_ENABLED=true at replicas: 1 — option C,
 * design decision 2026-08-26, resolving the deploy-profile conflict
 *   originally reported: single replica + PG mirror, the legal small-
 * production topology).
 *
 * SPAWNED BOOTS — the three behaviours's action 4 names, each a real
 *   server.js child process (never require()'d, never mocked):
 *     • production + no PG          → exits non-zero with EVIDENCE_DURABILITY_VIOLATION (cause PG_DISABLED)
 *     • production + PG not ready   → exits non-zero with EVIDENCE_DURABILITY_VIOLATION (cause STORE_NOT_READY)
 *     • non-production + no PG      → boots to GATEWAY_START with the existing PG_DISABLED WARN
 *   The two refusal boots need no Redis (the gate is the first step of
 *   startServer(), before any Redis probe); the non-production boot follows
 *   serverStartupSmoke.test.js's Redis-reachability skip pattern.
 */

const fs   = require('fs');
const net  = require('net');
const path = require('path');
const { spawn } = require('child_process');

const { validProductionEnv, assertBootValid, pickIsolation } = require('./helpers/productionEnv');

const REPO_ROOT   = path.join(__dirname, '..');
const STARTUP_JS  = path.join(REPO_ROOT, 'server', 'startup.js');
const BOOT_TIMEOUT_MS = 30_000;

// ── STATIC pins ──────────────────────────────────────────────────────────────

describe('gate — static structural pins over server/startup.js', () => {
  let source;
  beforeAll(() => { source = fs.readFileSync(STARTUP_JS, 'utf8'); });

  test('production profile is keyed on NODE_ENV=production, no new knob', () => {
    expect(source).toMatch(
      /const\s+REQUIRE_DURABLE_EVIDENCE\s*=\s*process\.env\.NODE_ENV\s*===\s*'production'\s*;/,
    );
    // Guard against a knob being introduced later under the same name.
    expect(source).not.toMatch(/REQUIRE_DURABLE_EVIDENCE\s*=\s*process\.env\.(?!NODE_ENV)/);
  });

  test('the gate uses the real probe module, awaits it, and precedes app.listen()', () => {
    expect(source).toMatch(/require\(\s*['"]\.\.\/src\/infra\/postgres\/evidenceStoreReadiness['"]\s*\)/);
    const probeCall  = source.match(/await\s+probeEvidenceStores\s*\(\s*\)/);
    const listenCall = source.match(/app\.listen\(/);
    expect(probeCall).not.toBeNull();
    expect(listenCall).not.toBeNull();
    expect(probeCall.index).toBeLessThan(listenCall.index);
  });

  test('both refusal branches emit EVIDENCE_DURABILITY_VIOLATION and exit(1) inside the gate', () => {
    const gateStart = source.indexOf('if (REQUIRE_DURABLE_EVIDENCE) {');
    expect(gateStart).toBeGreaterThan(-1);
    const gateWindow = source.slice(gateStart, gateStart + 3000);
    const fatals = gateWindow.match(/EVIDENCE_DURABILITY_VIOLATION/g) || [];
    expect(fatals.length).toBeGreaterThanOrEqual(2);
    const exits = gateWindow.match(/process\.exit\(1\)/g) || [];
    expect(exits.length).toBeGreaterThanOrEqual(2);
    // The refusal must run before the Redis-dependent STRICT_REPLAY gate.
    const strictGate = source.indexOf('STRICT_REPLAY_PROTECTION_VIOLATION');
    expect(gateStart).toBeLessThan(strictGate);
  });
});

// ── Deploy-profile pins ──────────────────────────────────────────────────────

describe('production deploy profiles default to PG enabled', () => {
  // production refuses the distributed mode (no checkpoints/anchors until), so the
  // single-host compose runs single-node ordering — still with PostgreSQL ENABLED ('s actual requirement: the
  // durable evidence mirror is on by default in every production profile).
  test('docker-compose.prod.yml: NODE_ENV=production, PostgreSQL enabled, single-node (anchored) ordering', () => {
    const compose = fs.readFileSync(path.join(REPO_ROOT, 'deploy', 'docker', 'docker-compose.prod.yml'), 'utf8');
    expect(compose).toMatch(/NODE_ENV:\s+production/);
    expect(compose).toMatch(/QODIQA_DEPLOYMENT_MODE:\s+single-node/);
    expect(compose).toMatch(/QODIQA_PG_ENABLED:\s+"true"/);
    expect(compose).toMatch(/QODIQA_ANCHOR_EXPORT_PATH:/);
  });

  test('kubernetes base configmap stamps NODE_ENV=production', () => {
    const cm = fs.readFileSync(path.join(REPO_ROOT, 'deploy', 'kubernetes', 'base', 'configmap.yaml'), 'utf8');
    expect(cm).toMatch(/NODE_ENV:\s+"production"/);
  });

  test('kubernetes distributed overlay sets QODIQA_DEPLOYMENT_MODE=distributed', () => {
    const cm = fs.readFileSync(
      path.join(REPO_ROOT, 'deploy', 'kubernetes', 'overlays', 'distributed', 'configmap-distributed.yaml'), 'utf8');
    expect(cm).toMatch(/QODIQA_DEPLOYMENT_MODE:\s+"distributed"/);
  });

  // option C: the single-node overlay is the
  // small-production topology — one replica, single-node ordering, PG mirror
  // enabled. Pins the whole legality envelope, not just PG enablement: with
  // the mirror on, >1 replica is the illegal topology assertNoIllegalTopology()
  // refuses, so replicas/QODIQA_REPLICA_COUNT must stay pinned at 1 alongside
  // QODIQA_PG_ENABLED, and QODIQA_K8S_SINGLE_REPLICA must acknowledge the
  // single-replica state or checkSingleInstance() refuses the k8s boot.
  test('kubernetes single-node overlay: PG enabled at exactly one replica', () => {
    const overlayDir = path.join(REPO_ROOT, 'deploy', 'kubernetes', 'overlays', 'single-node');
    const cm  = fs.readFileSync(path.join(overlayDir, 'configmap-single-node.yaml'), 'utf8');
    const sts = fs.readFileSync(path.join(overlayDir, 'statefulset.yaml'), 'utf8');
    expect(cm).toMatch(/QODIQA_PG_ENABLED:\s+"true"/);
    // Single-node ordering must be preserved — distributed mode is the OTHER
    // overlay. Key-form match only: the ConfigMap's comments legitimately
    // MENTION the variable while explaining why it must stay absent.
    expect(cm).not.toMatch(/^\s*QODIQA_DEPLOYMENT_MODE:/m);
    expect(sts).toMatch(/^\s*replicas:\s*1\s*$/m);
    expect(sts).toMatch(/name:\s*QODIQA_REPLICA_COUNT\s*\n\s*value:\s*"1"/);
    expect(sts).toMatch(/name:\s*QODIQA_K8S_SINGLE_REPLICA\s*\n\s*value:\s*"true"/);
    // The mirror credential is actually wired, not just enabled.
    expect(sts).toMatch(/name:\s*QODIQA_PG_PASSWORD/);
    // And the overlay ships the ConfigMap it references.
    const kustomization = fs.readFileSync(path.join(overlayDir, 'kustomization.yaml'), 'utf8');
    expect(kustomization).toMatch(/configmap-single-node\.yaml/);
  });
});

// ── SPAWNED boots ────────────────────────────────────────────────────────────

function requireDevEnvironmentFresh() {
  jest.resetModules();
  return require('../scripts/lib/devEnvironment');
}

const ENV_KEYS_TO_ISOLATE = [
  'NODE_ENV', 'QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_CLIENT_ID',
  'QODIQA_KEYS_PATH', 'QODIQA_AUDIT_LOG', 'QODIQA_TRANSPARENCY_KEYS_PATH',
  'QODIQA_SIGNING_STORE_PATH',
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
  let tempRoot;

  afterEach(() => {
    if (tempRoot && fs.existsSync(tempRoot)) {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    }
    tempRoot = null;
  });

  async function isolatedChildEnv(overrides, { production = false, pg = false } = {}) {
    const snap = snapshotEnv(ENV_KEYS_TO_ISOLATE);
    const { prepareIsolatedEnvironment } = requireDevEnvironmentFresh();
    const { paths } = await prepareIsolatedEnvironment({
      clientId: 'dev-f03-gate', tempPrefix: 'qodiqa-f03-',
    });
    tempRoot = paths.root;
    const port = String(await getFreePort());
    let childEnv;
    if (production) {
      // production boot validation (bootValidator) runs before any listener
      // and refuses on the FIRST fatal rule, so a production child must pass
      // every other rule for the evidence-durability gate to be the refusal
      // under test. validProductionEnv() builds that from system env only (no
      // test/support/jest.setup.js test toggles leak in) and self-checks it; the isolated
      // keystore (in os.tmpdir, outside the repo) and the KEK/client id it was
      // provisioned under are carried over.
      childEnv = validProductionEnv({
        keysPath: process.env.QODIQA_KEYS_PATH,
        pg,
        overrides: { ...pickIsolation(process.env), PORT: port, ...overrides },
      });
      assertBootValid(childEnv);
    } else {
      childEnv = {
        ...process.env,
        PORT: port,
        QODIQA_EXECUTION_INVARIANT_SECRET: require('crypto').randomBytes(32).toString('hex'),
        ...overrides,
      };
    }
    restoreEnv(snap);
    return childEnv;
  }

  test('production + no PG → refuses with EVIDENCE_DURABILITY_VIOLATION (PG_DISABLED), non-zero exit', async () => {
    const childEnv = await isolatedChildEnv({
      QODIQA_DEPLOYMENT_MODE: 'single-node',
    }, { production: true, pg: false });
    const r = await bootServer(childEnv);
    expect(r.timedOut).toBe(false);
    expect(r.exitCode).not.toBe(0);
    const violation = r.events.find((e) => e.eventType === 'EVIDENCE_DURABILITY_VIOLATION');
    if (!violation) {
      throw new Error('no EVIDENCE_DURABILITY_VIOLATION; exit=' + r.exitCode +
        '\nlast output:\n' + r.output.slice(-3000));
    }
    expect(violation.cause).toBe('PG_DISABLED');
    expect(violation.severity).toBe('FATAL');
    // The refusal names the doc an operator needs.
    expect(violation.resolution).toContain('deployment-runbook.md');
    // It refused BEFORE reaching the ready state.
    expect(r.events.some((e) => e.eventType === 'GATEWAY_START')).toBe(false);
  }, BOOT_TIMEOUT_MS + 10_000);

  test('production + PG configured but stores not ready → refuses with STORE_NOT_READY, non-zero exit', async () => {
    const childEnv = await isolatedChildEnv({
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      // A database that does not exist: connection (and therefore every
      // store probe) fails — "configured but not ready".
      QODIQA_PG_DATABASE: 'qodiqa_f03_nonexistent_db',
      // phase 17: with no explicit cluster in the process env this child used to inherit .env's — on the dev
      // machine the cluster hosting LIVE (127.0.0.1:5432), where it authenticated and asked for this database. Name an
      // explicit target instead: a closed loopback port ("configured but not ready" by refusal, nothing reached).
      ...(require('./helpers/liveEndpointGuard').explicitPgTarget(process.env)
        ? {} : { QODIQA_PG_HOST: '127.0.0.1', QODIQA_PG_PORT: String(await getFreePort()), QODIQA_PG_URL: '' }),
    }, { production: true, pg: true });
    const r = await bootServer(childEnv);
    expect(r.timedOut).toBe(false);
    expect(r.exitCode).not.toBe(0);
    const violation = r.events.find((e) => e.eventType === 'EVIDENCE_DURABILITY_VIOLATION');
    if (!violation) {
      throw new Error('no EVIDENCE_DURABILITY_VIOLATION; exit=' + r.exitCode +
        '\nlast output:\n' + r.output.slice(-3000));
    }
    expect(violation.cause).toBe('STORE_NOT_READY');
    expect(r.events.some((e) => e.eventType === 'GATEWAY_START')).toBe(false);
  }, BOOT_TIMEOUT_MS + 10_000);

  test('non-production + no PG → boots to GATEWAY_START with the existing PG_DISABLED WARN', async () => {
    if (!(await isRedisAvailable())) {
      // eslint-disable-next-line no-console
      console.warn('[evidenceDurabilityStartupGate] Redis not reachable — skipping the non-production full-boot case (same skip pattern as serverStartupSmoke.test.js).');
      return;
    }
    const childEnv = await isolatedChildEnv({
      QODIQA_DEPLOYMENT_MODE: 'single-node',
      QODIQA_PG_ENABLED: 'false',
    });
    // Explicitly non-production. (D-A): an UNSET NODE_ENV now refuses to
    // boot, so non-production is stated, not implied by absence.
    childEnv.NODE_ENV = 'development';
    const r = await bootServer(childEnv, { resolveOnEvent: 'GATEWAY_START' });
    expect(r.timedOut).toBe(false);
    expect(r.events.some((e) => e.eventType === 'GATEWAY_START')).toBe(true);
    expect(r.events.some((e) => e.eventType === 'PG_DISABLED' && e.severity === 'WARN')).toBe(true);
    expect(r.events.some((e) => e.eventType === 'EVIDENCE_DURABILITY_VIOLATION')).toBe(false);
    // REL-02: the boot says that this mode cannot audit authenticated decisions.
    const incomplete = r.events.find((e) => e.eventType === 'EVIDENCE_INCOMPLETE_FILE_ONLY_MODE');
    expect(incomplete).toBeDefined();
    expect(incomplete.severity).toBe('WARN');
    expect(incomplete.message).toMatch(/cannot audit authenticated decisions/);
  }, BOOT_TIMEOUT_MS + 10_000);
});
