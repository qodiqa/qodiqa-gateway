'use strict';

/**
 * step 9 — a real multi-replica cluster for the
 * end-to-end tests: N `server.js` processes (development profile, distributed
 * mode — the only mode that permits several replicas on one PostgreSQL), ONE
 * disposable PostgreSQL database (full migration chain), ONE disposable Redis
 * with production persistence (AOF everysec, crash-restartable), one shared
 * keystore directory and MAC keyring — the shape of the distributed overlay
 * (deploy/kubernetes/overlays/distributed).
 *
 * Provisioning goes through the real operator tooling in PostgreSQL mode
 * (scripts/rbac-bootstrap-key.js, scripts/provision-signing-identity.js), so
 * every replica reads the same control plane. Only this helper's own fixtures
 * are created and removed (database, container, temp dirs).
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { Pool } = require('pg');
const { startDisposableRedis, stopDisposableRedis, crashRestartDisposableRedis } = require('./disposableRedis');

const REPO_ROOT = path.join(__dirname, '..', '..');
const BOOT_TIMEOUT_MS = 120_000;

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.on('error', reject);
  srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
});
const hex = (n = 32) => crypto.randomBytes(n).toString('hex');

function maintenancePool(database = 'postgres') {
  return new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), database,
    user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD, ssl: false });
}

function baseEnv(c) {
  const parsed = fs.existsSync(path.join(REPO_ROOT, '.env')) ? require('dotenv').parse(fs.readFileSync(path.join(REPO_ROOT, '.env'))) : {};
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(QODIQA_|OPENAI_|ANTHROPIC_|GEMINI_|MISTRAL_|LLAMA_|LOCAL_|REDIS_|RL_|POLICY_FILE$|NODE_ENV$|STRICT_REPLAY_PROTECTION$|PROVIDER_|PORT$|JEST_WORKER_ID$)/.test(k)));
  for (const name of Object.keys(parsed)) env[name] = ''; // block the child's dotenv backfill
  for (const k of ['QODIQA_PG_HOST', 'QODIQA_PG_PORT', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PG_MIG_USER', 'QODIQA_PG_MIG_PASSWORD',
    'QODIQA_PG_RETENTION_PASSWORD', 'QODIQA_PG_SYSTEM_PASSWORD', 'QODIQA_PG_REPORTING_PASSWORD', 'QODIQA_PG_CONTROL_PASSWORD']) {
    // ER 2026-10-06: an explicitly set process value WINS over .env. The reverse order sent the replicas to the .env cluster
    // (which hosts LIVE on the dev machine) while the parent had created the test database on the cluster the gate run
    // targeted — the replicas authenticated against the wrong cluster and failed with "database … does not exist".
    // with no .env (clean checkout / CI) this is unchanged; locally the test file has already loaded .env into process.env.
    // phase 17: the explicit process value ONLY — never .env's (on the dev machine .env names the cluster
    // hosting LIVE); a run that did not name its cluster explicitly is refused by test/support/jest.setup.js before it gets here.
    const v = process.env[k];
    if (v !== undefined) env[k] = v;
  }
  Object.assign(env, {
    NODE_ENV: 'development',
    QODIQA_ENVIRONMENT: 'development',
    QODIQA_KEY_ENCRYPTION_KEY: c.kek,
    QODIQA_EXECUTION_INVARIANT_SECRET: c.invariant,
    QODIQA_CLIENT_ID: c.clientId,
    QODIQA_KEYS_PATH: path.join(c.dir, 'keys', 'keys.json'),
    QODIQA_KEYS_ARCHIVE_PATH: path.join(c.dir, 'keys', 'key-archive.json'),
    QODIQA_MAC_KEYS_PATH: path.join(c.dir, 'keys', 'mac-keys.json'),
    QODIQA_TRANSPARENCY_KEYS_PATH: path.join(c.dir, 'keys', 'transparency-keys.json'),
    QODIQA_AUDIT_LOG: path.join(c.dir, 'audit.log'),
    QODIQA_DSR_PSEUDONYM_PEPPER: hex(),
    POLICY_FILE: path.join(REPO_ROOT, 'policies.json'),
    QODIQA_POLICY_STORE: path.join(c.dir, 'seed-unused', 'policy-store.json'),
    QODIQA_PG_ENABLED: 'true',
    QODIQA_PG_DATABASE: c.db,
    QODIQA_PG_URL: '',
    QODIQA_CONTROL_PLANE_BACKEND: 'pg',
    QODIQA_DEPLOYMENT_MODE: 'distributed',
    QODIQA_REPLICA_COUNT: String(c.replicas),
    REDIS_URL: `redis://127.0.0.1:${c.redisPort}`,
    RL_ENABLED: 'false',
    QODIQA_OPS_MFA_REQUIRED: 'false',
    QODIQA_ADMIN_ENABLED: 'true',
    LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1',
    // every legacy store path points at an empty temp dir: nothing may be read from repo data/
    QODIQA_RBAC_STORE_PATH: path.join(c.dir, 'seed-unused', 'rbac-users.json'),
    QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH: path.join(c.dir, 'seed-unused', 'rbac-custom-roles.json'),
    QODIQA_SIGNING_STORE_PATH: path.join(c.dir, 'seed-unused', 'signing-identities.json'),
    QODIQA_PORTAL_USER_STORE_PATH: path.join(c.dir, 'seed-unused', 'tenant-portal-users.json'),
    TENANT_STORE_PATH: path.join(c.dir, 'seed-unused', 'tenants.json'),
    ORG_STORE_PATH: path.join(c.dir, 'seed-unused', 'organizations.json'),
    ...c.extraEnv,
  });
  // phase 17: preload the LIVE-endpoint socket guard into every replica/tool child (CI exempt).
  return require('./liveEndpointGuard').isolatedChildEnv(env);
}

function runTool(c, script, args = [], extra = {}) {
  const r = spawnSync(process.execPath, [script, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 90_000, env: { ...baseEnv(c), ...extra } });
  const out = r.stdout || '';
  const i = out.lastIndexOf('\n{');
  let json = null;
  try { json = JSON.parse((i >= 0 ? out.slice(i + 1) : out).trim()); } catch (_) { /* not json */ }
  if (r.status !== 0) throw new Error(`${script} exited ${r.status}: ${(r.stderr || out).slice(-1200)}`);
  return json;
}

function bootServer(c, name) {
  return new Promise((resolve, reject) => {
    const port = c.ports[name];
    const events = []; const chunks = [];
    const child = spawn(process.execPath, ['server.js'], { cwd: REPO_ROOT, env: { ...baseEnv(c), PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'] });
    let settled = false; let partial = '';
    const settle = (err) => { if (settled) return; settled = true; clearTimeout(timer); err ? reject(err) : resolve({ name, port, child, events, output: () => chunks.join('') }); };
    const timer = setTimeout(() => settle(new Error(`${name} did not start within ${BOOT_TIMEOUT_MS} ms\n${chunks.join('').slice(-3000)}`)), BOOT_TIMEOUT_MS);
    const onData = (buf) => {
      const text = partial + buf.toString(); chunks.push(buf.toString());
      const lines = text.split('\n'); partial = lines.pop();
      for (const line of lines) {
        let e; try { e = JSON.parse(line.trim()); } catch { continue; }
        if (!e.eventType) continue;
        events.push(e);
        if (e.eventType === 'GATEWAY_START') settle();
        if (e.severity === 'FATAL') settle(new Error(`${name} FATAL ${e.eventType}: ${JSON.stringify(e).slice(0, 1500)}`));
      }
    };
    child.stdout.on('data', onData); child.stderr.on('data', onData);
    child.on('exit', (code) => settle(new Error(`${name} exited ${code} before GATEWAY_START\n${chunks.join('').slice(-3000)}`)));
  });
}

const killAndWait = (child) => new Promise((resolve) => {
  if (!child || child.exitCode !== null || child.signalCode) return resolve();
  child.once('exit', () => resolve()); child.kill('SIGKILL');
});

/**
 * @param {{ replicas?: number, tag?: string, extraEnv?: object }} opts
 */
async function startCluster({ replicas = 3, tag = 'w6c', extraEnv = {} } = {}) {
  const id = `${tag}_${Date.now()}_${hex(3)}`;
  const c = {
    replicas, extraEnv, id,
    db: `qodiqa_${id}`.toLowerCase(),
    redisName: `qodiqa-w6-cluster-redis-${hex(3)}`,
    dir: fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w6-cluster-')),
    kek: hex(), invariant: hex(), clientId: 'w6cluster',
    ports: {}, servers: {},
  };
  // 2026-10-06: cleanup is defined BEFORE anything is acquired, and any start-up failure runs it and rethrows.
  // Previously c.stop was assigned only at the very end, so a failure part-way (e.g. keystore provisioning) leaked the
  // Redis container, the test database, the temp dir and any booted servers (seen: qodiqa-w6-cluster-redis-015532).
  c.stop = async () => {
    for (const s of Object.values(c.servers)) await killAndWait(s.child);
    if (c.redisStarted) c.redisGone = stopDisposableRedis(c.redisName);
    if (c.dbCreated) {
      const m = maintenancePool();
      try {
        await m.query(`DROP DATABASE IF EXISTS "${c.db}" WITH (FORCE)`);
        c.dbGone = (await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [c.db])).rowCount === 0;
      } finally { await m.end(); }
    }
    fs.rmSync(c.dir, { recursive: true, force: true });
  };
  try {
  fs.mkdirSync(path.join(c.dir, 'keys'), { recursive: true });
  fs.mkdirSync(path.join(c.dir, 'seed-unused'), { recursive: true });
  const maint = maintenancePool();
  try { await maint.query(`CREATE DATABASE "${c.db}"`); } finally { await maint.end(); }
  c.dbCreated = true;
  const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000,
    env: { ...process.env, QODIQA_PG_DATABASE: c.db, QODIQA_PG_URL: '', QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD } });
  if (mig.status !== 0) throw new Error(`migrate failed: ${mig.stderr.slice(-800)}`);
  const redis = await startDisposableRedis(c.redisName, { appendonly: 'yes', restartable: true });
  c.redisPort = redis.port; c.redisStarted = true;

  // shared keystore + MAC keyring + the tenant's first signing key, recorded in the control plane
  const prov = spawnSync(process.execPath, ['-e', `
    (async () => {
      const cp = require('./src/core/controlPlane'); await cp.start({ notifier: false });
      require('./src/core/security/macKeyring').init();
      const ks = require('./services/artifact/keyStore'); require('./scripts/lib/keyStoreProvisioning').ensureActiveKey(process.env.QODIQA_CLIENT_ID);
      await require('./src/core/tenancy/tenantRegistry').registerTenant(process.env.QODIQA_CLIENT_ID);
      await require('./src/core/signing/keyStatusTimeline').reconcileAll();
      console.log(JSON.stringify({ keyId: ks.getActiveKey(process.env.QODIQA_CLIENT_ID).keyId }));
      await cp.stop(); await require('./src/infra/postgres/rolePools').shutdownAll(); process.exit(0);
    })().catch((e) => { console.error(e.stack); process.exit(1); });`], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 90_000, env: baseEnv(c) });
  if (prov.status !== 0) throw new Error(`keystore provisioning failed: ${(prov.stderr || prov.stdout).slice(-1500)}`);
  c.firstKeyId = JSON.parse(prov.stdout.trim().split('\n').filter((l) => l.startsWith('{"keyId"')).pop()).keyId;

  c.operatorKey = runTool(c, 'scripts/rbac-bootstrap-key.js').apiKey;
  c.signing = runTool(c, 'scripts/provision-signing-identity.js', ['--name', 'w6-cluster-signer', '--tenant-id', c.clientId, '--environment', 'development']);

  const names = Array.from({ length: replicas }, (_, i) => String.fromCharCode(65 + i)); // A, B, C
  for (const n of names) c.ports[n] = await freePort();
  for (const n of names) c.servers[n] = await bootServer(c, n);
  c.url = (n) => `http://127.0.0.1:${c.ports[n]}`;
  c.env = () => baseEnv(c);
  c.crashRestartRedis = () => crashRestartDisposableRedis(c.redisName, c.redisPort);
  // H-40: kill one replica and boot it again with the IDENTICAL env (same database, keystore,
  // audit log, MAC keyring, Redis): the same deployment restarted, not a new one.
  c.restart = async (n) => { await killAndWait(c.servers[n].child); c.servers[n] = await bootServer(c, n); return c.servers[n]; };
  // CL-05 diagnosis: called by a test ONLY on its failure path, BEFORE c.stop() removes the
  // database, Redis and keystore directory. Writes, under the evidence directory, everything needed to tell which
  // keyLifecycle branch refused and why: the test's own context (full response, artifact timestamp, key ids), every
  // replica's output and structured events, every replica's in-memory key view (GET /key-admin/inventory), the shared
  // keystore's public key metadata (no key material) and the control-plane signing_key_status rows (data + version).
  // Never throws (a capture problem is recorded in the evidence, so it cannot mask the test failure). Returns the dir.
  c.captureEvidence = async (label, context = {}) => {
    const base = process.env.W6_EVIDENCE_DIR || path.join(REPO_ROOT, 'evidence', 'w6', 'tests', 'runs');
    const dir = path.join(base, `failure-${c.id}-${String(label).replace(/[^A-Za-z0-9_-]/g, '_')}`);
    const errors = [];
    const write = (name, data) => { try { fs.writeFileSync(path.join(dir, name), typeof data === 'string' ? data : JSON.stringify(data, null, 1)); } catch (e) { errors.push(`${name}: ${e.message}`); } };
    try { fs.mkdirSync(dir, { recursive: true }); } catch (e) { return null; }
    write('context.json', { label, capturedAt: new Date().toISOString(), clusterId: c.id, db: c.db, clientId: c.clientId, firstKeyId: c.firstKeyId, ports: c.ports, ...context });
    for (const [n, s] of Object.entries(c.servers)) {
      write(`replica-${n}-output.txt`, s.output());
      write(`replica-${n}-events.json`, s.events);
      try {
        const r = await fetch(`http://127.0.0.1:${c.ports[n]}/key-admin/inventory`, { headers: { Authorization: `Bearer ${c.operatorKey}` } });
        write(`replica-${n}-key-inventory.json`, { httpStatus: r.status, at: new Date().toISOString(), body: await r.json().catch(() => null) });
      } catch (e) { errors.push(`inventory ${n}: ${e.message}`); }
    }
    try {
      const ks = JSON.parse(fs.readFileSync(path.join(c.dir, 'keys', 'keys.json'), 'utf8'));
      const meta = []; (function walk(o) { if (o && typeof o === 'object') { if (typeof o.keyId === 'string' && typeof o.status === 'string') meta.push({ keyId: o.keyId, status: o.status, version: o.version ?? null, createdAt: o.createdAt ?? null, retiredAt: o.retiredAt ?? null, revokedAt: o.revokedAt ?? null }); else for (const v of Object.values(o)) walk(v); } })(ks);
      write('keystore-public-metadata.json', meta);
    } catch (e) { errors.push(`keystore: ${e.message}`); }
    const pool = maintenancePool(c.db);
    try {
      const rows = (await pool.query("SELECT record_id, data, version, deleted, updated_at, updated_by FROM control_plane_records WHERE store = 'signing_key_status' ORDER BY record_id")).rows;
      write('control-plane-signing-key-status.json', rows);
    } catch (e) { errors.push(`control plane: ${e.message}`); } finally { await pool.end().catch(() => {}); }
    write('capture-errors.json', errors);
    c.evidenceDirs = (c.evidenceDirs || []).concat(dir);
    return dir;
  };
  } catch (err) {
    try { await c.stop(); } catch { /* best effort: the original error is what matters */ }
    throw err;
  }
  return c;
}

module.exports = { startCluster, REPO_ROOT };
