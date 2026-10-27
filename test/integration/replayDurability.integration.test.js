'use strict';

/**
 * replay protection across a real
 * Redis restart. Two DISPOSABLE Redis containers (test/helpers/disposableRedis.js,
 * the shared qodiqa-redis is never touched): one with production persistence
 * (AOF, everysec), one without.
 *
 *   RD-01  persistence as production requires it: AOF on, appendfsync everysec (checkRedisPersistence safe)
 *   RD-02  AOF: an artifact used before the restart is still REPLAY_DETECTED after it
 *   RD-03  AOF: an artifact issued before the restart and never used is refused —
 *          REPLAY_STATE_UNPROVABLE (the ≤ 1 s AOF loss window cannot be ruled out)
 *   RD-04  an artifact issued after the restart (+ the 5 s skew) registers normally
 *   RD-05  NO AOF: the used nonce is LOST with the restart, yet the replay is still
 *          refused (the barrier) — nothing issued before the restart can execute
 *   RD-06  NO AOF: checkRedisPersistence reports unsafe — the input the production
 *          boot gate refuses on
 *   RD-07  the validation layer maps the barrier to REPLAY_STATE_UNPROVABLE
 *   RD-08  the boot refusal itself: a real server.js with STRICT_REPLAY_PROTECTION
 *          (forced on in production) exits STRICT_REPLAY_PROTECTION_VIOLATION on the no-AOF Redis
 *
 * The barrier is inside the nonce Lua script (TIME − uptime), so there is no
 * window between the restart and the barrier.
 */

const crypto = require('crypto');
const { startDisposableRedis, stopDisposableRedis, crashRestartDisposableRedis } = require('../helpers/disposableRedis');
const { spawnSync } = require('child_process');

const dockerOk = spawnSync('docker', ['info'], { encoding: 'utf8', timeout: 20_000 }).status === 0;
const describeOrSkip = dockerOk ? describe : describe.skip;
jest.setTimeout(180_000);

const TAG = crypto.randomBytes(3).toString('hex');
const AOF = `qodiqa-w6-redis-aof-${TAG}`;
const NOAOF = `qodiqa-w6-redis-noaof-${TAG}`;
const uuid = () => crypto.randomUUID();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A fresh nonceStore module bound to one Redis. */
function storeFor(port) {
  let mod;
  jest.isolateModules(() => {
    process.env.REDIS_URL = `redis://127.0.0.1:${port}`;
    mod = require('../../src/validation/nonceStore');
  });
  return mod;
}

async function waitReady(store) {
  const deadline = Date.now() + 20_000;
  while (!store.isReady()) { if (Date.now() > deadline) throw new Error('nonce store not ready'); await sleep(50); }
}

// After a crash the client's first command can hit the dead socket before it
// notices (production: that request fails closed, NONCE_STORE_ERROR). The test
// retries ONLY such transport errors, until the client has reconnected.
const TRANSPORT = /Socket closed|ECONNRESET|ECONNREFUSED|not ready|NONCE_STORE|The client is closed/i;
async function register(store, requestId, issuedAtMs) {
  for (let i = 0; ; i++) {
    try {
      return await store.registerAndCheckAnomaly(requestId, Date.now() + 60_000, 'w6tenant', {
        publicKeyId: 'w6tenant:key_v1', nowMs: Date.now(), windowMs: 60_000, perKeyMax: 1000, globalMax: 100_000, issuedAtMs,
      });
    } catch (err) {
      if (i > 100 || !TRANSPORT.test(err.message)) throw err;
      await sleep(100);
    }
  }
}

describeOrSkip('replay durability across a Redis restart (real Redis)', () => {
  let aof; let noaof; let sAof; let sNo; const savedUrl = process.env.REDIS_URL;

  beforeAll(async () => {
    aof = await startDisposableRedis(AOF, { appendonly: 'yes', restartable: true });
    noaof = await startDisposableRedis(NOAOF, { appendonly: 'no', restartable: true });
    sAof = storeFor(aof.port); await sAof.initialize();
    sNo = storeFor(noaof.port); await sNo.initialize();
    // By design, anything issued within the 5 s future-skew tolerance of a Redis
    // START is refused (the barrier cannot tell a skewed pre-crash signer from a
    // post-start one). Fresh containers: wait that out before the first registration.
    await sleep(7000);
  });

  afterAll(async () => {
    for (const s of [sAof, sNo]) if (s) await s.disconnect().catch(() => {});
    if (savedUrl === undefined) delete process.env.REDIS_URL; else process.env.REDIS_URL = savedUrl;
    expect(stopDisposableRedis(AOF)).toBe(true);
    expect(stopDisposableRedis(NOAOF)).toBe(true);
  });

  test('RD-01 the AOF container has production persistence (AOF on, everysec)', async () => {
    const d = await sAof.checkPersistence();
    expect(d).toMatchObject({ safe: true, aofEnabled: true, appendfsync: 'everysec' });
  });

  const usedAof = uuid(); const unusedAof = uuid(); const usedNo = uuid();
  test('RD-02/03/04 AOF: used stays REPLAY_DETECTED; issued-before-restart is REPLAY_STATE_UNPROVABLE; issued-after registers', async () => {
    const issuedBefore = Date.now();
    expect((await register(sAof, usedAof, issuedBefore)).phase).toBe('ALLOWED');
    expect((await register(sAof, usedAof, issuedBefore)).phase).toBe('REPLAY');            // replay before the restart
    await sleep(1500);                                                                      // > 1 s: the AOF everysec fsync has run
    await crashRestartDisposableRedis(AOF, aof.port);
    await waitReady(sAof);
    const replay = await register(sAof, usedAof, issuedBefore);
    expect(replay.phase).toBe('REPLAY');                                                    // RD-02: survived via AOF → REPLAY_DETECTED
    const unprovable = await register(sAof, unusedAof, issuedBefore);
    expect(unprovable.phase).toBe('REPLAY_UNPROVABLE');                                     // RD-03
    await sleep(6000);                                                                      // past the restart + 5 s skew
    expect((await register(sAof, uuid(), Date.now())).phase).toBe('ALLOWED');              // RD-04
  });

  test('RD-05 NO AOF: the nonce is lost with the restart, but the replay is still refused by the barrier', async () => {
    const issuedBefore = Date.now();
    expect((await register(sNo, usedNo, issuedBefore)).phase).toBe('ALLOWED');
    await crashRestartDisposableRedis(NOAOF, noaof.port);
    await waitReady(sNo);
    const replay = await register(sNo, usedNo, issuedBefore);
    expect(replay.phase).toBe('REPLAY_UNPROVABLE');                                         // not REPLAY (nonce gone) — and not ALLOWED
  });

  test('RD-06 NO AOF: persistence is reported unsafe (the production boot gate refuses this)', async () => {
    const d = await sNo.checkPersistence();
    expect(d.safe).toBe(false);
    expect(d.aofEnabled).toBe(false);
  });

  test('RD-08 a real server.js with strict replay protection REFUSES to start on the no-AOF Redis (the gate production forces on)', async () => {
    // server/startup.js: NODE_ENV=production forces STRICT_REPLAY=true; the refusal
    // below is that same gate, exercised in the development profile with the flag set.
    const fs = require('fs'); const os = require('os'); const path = require('path'); const { spawn } = require('child_process');
    const REPO = path.join(__dirname, '..', '..');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w6-rd08-'));
    const envFile = path.join(REPO, '.env'); // a clean checkout / CI has no .env
    const parsed = fs.existsSync(envFile) ? require('dotenv').parse(fs.readFileSync(envFile)) : {};
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(QODIQA_|OPENAI_|ANTHROPIC_|GEMINI_|MISTRAL_|LLAMA_|LOCAL_|REDIS_|RL_|POLICY_FILE$|NODE_ENV$|STRICT_REPLAY_PROTECTION$|PROVIDER_|PORT$|JEST_WORKER_ID$)/.test(k)));
    for (const name of Object.keys(parsed)) env[name] = '';
    Object.assign(env, {
      NODE_ENV: 'development', STRICT_REPLAY_PROTECTION: 'true', PORT: '0',
      QODIQA_KEY_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'), QODIQA_EXECUTION_INVARIANT_SECRET: crypto.randomBytes(32).toString('hex'),
      QODIQA_CLIENT_ID: 'w6rd08', QODIQA_KEYS_PATH: path.join(dir, 'keys.json'), QODIQA_MAC_KEYS_PATH: path.join(dir, 'mac-keys.json'),
      QODIQA_TRANSPARENCY_KEYS_PATH: path.join(dir, 'transparency-keys.json'), QODIQA_AUDIT_LOG: path.join(dir, 'audit.log'),
      POLICY_FILE: path.join(REPO, 'policies.json'), QODIQA_POLICY_STORE: path.join(dir, 'policy-store.json'),
      QODIQA_PG_ENABLED: 'false', QODIQA_CONTROL_PLANE_BACKEND: 'memory', RL_ENABLED: 'false',
      REDIS_URL: `redis://127.0.0.1:${noaof.port}`, LOCAL_BASE_URL: 'http://127.0.0.1:11434/v1',
      QODIQA_DSR_PSEUDONYM_PEPPER: crypto.randomBytes(32).toString('hex'),
      TENANT_STORE_PATH: path.join(dir, 't.json'), ORG_STORE_PATH: path.join(dir, 'o.json'), QODIQA_RBAC_STORE_PATH: path.join(dir, 'r.json'),
      QODIQA_SIGNING_STORE_PATH: path.join(dir, 's.json'), QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH: path.join(dir, 'c.json'), QODIQA_PORTAL_USER_STORE_PATH: path.join(dir, 'p.json'),
    });
    const prov = spawnSync(process.execPath, ['-e', "require('./src/core/security/macKeyring').init(); require('./scripts/lib/keyStoreProvisioning').ensureActiveKey(process.env.QODIQA_CLIENT_ID);"], { cwd: REPO, env, encoding: 'utf8' });
    expect({ status: prov.status, err: prov.status === 0 ? '' : prov.stderr.slice(-400) }).toEqual({ status: 0, err: '' });
    const outcome = await new Promise((resolve) => {
      const child = spawn(process.execPath, ['server.js'], { cwd: REPO, env, stdio: ['ignore', 'pipe', 'pipe'] });
      let buf = ''; const events = [];
      const done = (r) => { clearTimeout(timer); try { child.kill('SIGKILL'); } catch (_) { /* gone */ } resolve({ ...r, events }); };
      const timer = setTimeout(() => done({ result: 'TIMEOUT' }), 120_000);
      const onData = (d) => {
        buf += d.toString(); const lines = buf.split('\n'); buf = lines.pop();
        for (const l of lines) { let e; try { e = JSON.parse(l); } catch { continue; } if (!e.eventType) continue; events.push(e.eventType);
          if (e.eventType === 'STRICT_REPLAY_PROTECTION_VIOLATION') done({ result: 'REFUSED', aofEnabled: e.aofEnabled });
          if (e.eventType === 'GATEWAY_START') done({ result: 'STARTED' }); }
      };
      child.stdout.on('data', onData); child.stderr.on('data', onData);
      child.on('exit', (code) => done({ result: 'EXITED', code }));
    });
    fs.rmSync(dir, { recursive: true, force: true });
    expect({ result: outcome.result, aofEnabled: outcome.aofEnabled }).toEqual({ result: 'REFUSED', aofEnabled: false });
    expect(outcome.events).not.toContain('GATEWAY_START');
  });

  test('RD-07 the validation layer maps the barrier to REPLAY_STATE_UNPROVABLE (never ALLOWED)', async () => {
    const { registerNonceAndCheckAnomaly } = require('../../src/validation/registerNonceAndCheckAnomaly');
    const r = await registerNonceAndCheckAnomaly(uuid(), Date.now() + 30_000, 'w6tenant:key_v1',
      { _store: sNo, tenantId: 'w6tenant', issuedAtMs: Date.now() - 120_000 });
    expect(r.nonceResult).toMatchObject({ ok: false, reason: 'REPLAY_STATE_UNPROVABLE' });
  });
});
