'use strict';

// the two-replica revocation demo as a test.
//
// Step 1 ran this against the per-process JSON-file stores and it FAILED 5/5
// a revocation on A never
// reached B, and a stale replica's write brought a revoked key back.
//
// Since step 3 every replica is a forked process running the PostgreSQL
// control plane (one disposable database, the full migration chain), exactly
// as a production replica does. The assertions are the same, now held to the
// approved guarantee: a revocation anywhere is in force on every
// replica within 5 s, and no stale replica can write it back. Each case records
// the measured propagation time.
//
// Two notifier modes run: 'on'
// and 'off' (pub/sub lost: the periodic pull alone must still meet the bound).

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { fork, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_CONTROL_PASSWORD;
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DRIVER = path.join(__dirname, '..', 'helpers', 'replicaDriver.js');
const BOUND_MS = 5000; //
const DB = `qodiqa_w6rr_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const EVIDENCE = path.join(process.env.W6_EVIDENCE_DIR || path.join(REPO_ROOT, 'evidence', 'w6', 'tests', 'runs') /* C-11: default is git-ignored; the tracked *-latest.json files are historical */, `propagation-${process.env.W6_EVIDENCE_TAG || 'latest'}.json`);
const measured = [];
const live = [];
let maint; let ringDir;

function startReplica(name, { notifier = 'on' } = {}) {
  const env = {
    ...process.env,
    QODIQA_CONTROL_PLANE_BACKEND: 'pg',
    QODIQA_PG_ENABLED: 'true',
    QODIQA_PG_DATABASE: DB,
    QODIQA_MAC_KEYS_PATH: path.join(ringDir, 'mac-keys.json'),
    W6_NOTIFIER: notifier,
  };
  delete env.QODIQA_PG_URL;
  const child = fork(DRIVER, [], { env, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  live.push(child);
  let seq = 0;
  const pending = new Map();
  const ready = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.on('message', (m) => {
      if (m.ready === true) return resolve();
      if (m.ready === false) return reject(new Error(`${name} failed to start: ${m.error}`));
      const p = pending.get(m.seq);
      if (!p) return;
      pending.delete(m.seq);
      if (m.ok) p.resolve(m.value);
      else { const e = new Error(`${name}: ${m.error}`); e.code = m.code; p.reject(e); }
    });
  });
  const call = (op, arg) => new Promise((resolve, reject) => {
    const s = ++seq;
    pending.set(s, { resolve, reject });
    child.send({ seq: s, op, arg });
  });
  return ready.then(() => ({ name, call }));
}

/** Poll `probe` until `ok(value)`; returns elapsed ms, or throws once the bound is exceeded. */
async function within(label, probe, ok, t0 = Date.now()) {
  for (;;) {
    let v; let err = null;
    try { v = await probe(); } catch (e) { err = e; }
    const elapsed = Date.now() - t0;
    if (!err && ok(v)) { measured.push({ label, elapsedMs: elapsed }); return elapsed; }
    if (elapsed > BOUND_MS) throw new Error(`${label}: not in force after ${elapsed} ms (bound ${BOUND_MS} ms); last=${err ? err.message : JSON.stringify(v)}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}

const expectConflict = async (p, label = 'stale write') => {
  const err = await p.then((v) => ({ code: 'SUCCEEDED', value: v }), (e) => e);
  expect({ label, code: err.code }).toEqual({ label, code: 'CONTROL_PLANE_VERSION_CONFLICT' });
};

describeOrSkip('control-plane revocation across replicas (PostgreSQL)', () => {
  beforeAll(async () => {
    maint = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), database: 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    // one MAC keyring shared by every replica (production shares it like the keystore)
    ringDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w6-ring-'));
    const init = spawnSync(process.execPath, ['-e', "require('./src/core/security/macKeyring').init()"], { cwd: REPO_ROOT, encoding: 'utf8', env: { ...process.env, QODIQA_MAC_KEYS_PATH: path.join(ringDir, 'mac-keys.json') } });
    if (init.status !== 0) throw new Error(`mac keyring init failed: ${init.stderr}`);
  });

  afterEach(() => {
    while (live.length) { try { live.pop().kill(); } catch (_) { /* already gone */ } }
  });

  afterAll(async () => {
    fs.mkdirSync(path.dirname(EVIDENCE), { recursive: true });
    fs.writeFileSync(EVIDENCE, JSON.stringify({ boundMs: BOUND_MS, measured }, null, 2));
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  for (const notifier of ['on', 'off']) {
    describe(`notifier ${notifier}`, () => {
      test(`R-01 [${notifier}] signing key revoked on A is rejected on B and C within the bound`, async () => {
        const [A, B, C] = await Promise.all(['A', 'B', 'C'].map((n) => startReplica(n, { notifier })));
        const ident = await A.call('signing.create', { name: `w6-r01-${notifier}`, tenantId: 'w6tenant', environment: 'test', permissions: ['SIGN_ARTIFACT'] });
        const { plaintext } = await A.call('signing.issue', ident.id);
        await within(`R-01/${notifier} B learns the key`, () => B.call('signing.resolve', plaintext), (v) => v !== null);
        await within(`R-01/${notifier} C learns the key`, () => C.call('signing.resolve', plaintext), (v) => v !== null);
        await A.call('signing.revoke', ident.id);
        const t0 = Date.now();
        expect(await A.call('signing.resolve', plaintext)).toBeNull();
        await within(`R-01/${notifier} revocation on B`, () => B.call('signing.resolve', plaintext), (v) => v === null, t0);
        await within(`R-01/${notifier} revocation on C`, () => C.call('signing.resolve', plaintext), (v) => v === null, t0);
      });

      test(`R-02 [${notifier}] a stale write from B cannot resurrect a signing key revoked on A`, async () => {
        const [A, B] = await Promise.all(['A', 'B'].map((n) => startReplica(n, { notifier })));
        const ident = await A.call('signing.create', { name: `w6-r02-${notifier}`, tenantId: 'w6tenant', environment: 'test', permissions: ['SIGN_ARTIFACT'] });
        const { plaintext } = await A.call('signing.issue', ident.id);
        await within(`R-02/${notifier} B learns the key`, () => B.call('signing.resolve', plaintext), (v) => v !== null);
        await B.call('cp.pause');                                   // B stops pulling: its snapshot is now stale
        await A.call('signing.revoke', ident.id);
        await B.call('signing.touch', ident.id);                    // what every /sign on B does — never a versioned write
        // B's stale copy still shows the identity active: a re-issue from that copy would un-revoke it. Refused (409).
        // (One stale write per pause: a refused write makes B pull, after which B is no longer stale.)
        await expectConflict(B.call('signing.issue', ident.id), 'R-02 stale re-issue');
        expect(await B.call('signing.resolve', plaintext)).toBeNull();                     // B pulled on the conflict
        await B.call('signing.create', { name: `w6-r02b-${notifier}`, tenantId: 'w6tenant', environment: 'test', permissions: ['SIGN_ARTIFACT'] }); // unrelated write is fine
        const C = await startReplica('C', { notifier });           // fresh replica reads the authoritative state
        expect(await C.call('signing.resolve', plaintext)).toBeNull();
        expect(await A.call('signing.resolve', plaintext)).toBeNull();
      });

      test(`R-03 [${notifier}] operator key revoked on A is rejected on B, and a stale write from B cannot restore it`, async () => {
        const [A, B, D] = await Promise.all(['A', 'B', 'D'].map((n) => startReplica(n, { notifier })));
        const user = await A.call('rbac.create', { username: `w6-r03-${notifier}`, role: 'operator' });
        const { plaintext } = await A.call('rbac.issue', user.id);
        await within(`R-03/${notifier} B learns the key`, () => B.call('rbac.resolve', plaintext), (v) => v !== null);
        await within(`R-03/${notifier} D learns the key`, () => D.call('rbac.resolve', plaintext), (v) => v !== null);
        await B.call('cp.pause');                                   // B goes stale (still holds the key hash)
        await A.call('rbac.revoke', user.id);
        const t0 = Date.now();
        await within(`R-03/${notifier} revocation on D`, () => D.call('rbac.resolve', plaintext), (v) => v === null, t0);
        await expectConflict(B.call('rbac.update', { id: user.id, patch: { role: 'viewer' } })); // stale copy carries the old hash → 409
        const C = await startReplica('C', { notifier });
        expect(await C.call('rbac.resolve', plaintext)).toBeNull();
      });

      test(`R-04 [${notifier}] RBAC user removed on A is gone on B and stays gone after a stale write`, async () => {
        const [A, B, D] = await Promise.all(['A', 'B', 'D'].map((n) => startReplica(n, { notifier })));
        const user = await A.call('rbac.create', { username: `w6-r04-${notifier}`, role: 'operator' });
        const { plaintext } = await A.call('rbac.issue', user.id);
        await within(`R-04/${notifier} B learns the key`, () => B.call('rbac.resolve', plaintext), (v) => v !== null);
        await within(`R-04/${notifier} D learns the key`, () => D.call('rbac.resolve', plaintext), (v) => v !== null);
        await B.call('cp.pause');
        await A.call('rbac.delete', user.id);
        const t0 = Date.now();
        await within(`R-04/${notifier} removal on D`, () => D.call('rbac.resolve', plaintext), (v) => v === null, t0);
        await expectConflict(B.call('rbac.update', { id: user.id, patch: { role: 'viewer' } })); // stale write on a deleted row → 409
        const C = await startReplica('C', { notifier });
        expect(await C.call('rbac.get', user.id)).toBeNull();
        expect(await C.call('rbac.resolve', plaintext)).toBeNull();
      });

      test(`R-05 [${notifier}] tenant suspended on A is blocked on B within the bound and stays suspended after a stale write`, async () => {
        const [A, B] = await Promise.all(['A', 'B'].map((n) => startReplica(n, { notifier })));
        const tid = `w6r05${notifier}`;
        await A.call('tenant.register', tid);
        await within(`R-05/${notifier} B learns the tenant`, () => B.call('tenant.assert', tid), (v) => v.valid === true);
        await A.call('tenant.suspend', tid);
        const t0 = Date.now();
        await within(`R-05/${notifier} suspension on B`, () => B.call('tenant.assert', tid), (v) => v.reason === 'TENANT_SUSPENDED', t0);
        const S = await startReplica('S', { notifier });
        await S.call('cp.pause');
        await A.call('tenant.update', { id: tid, patch: { quotas: { maxRequestsPerMinute: 10 } } }); // moves the version past S's snapshot
        await expectConflict(S.call('tenant.update', { id: tid, patch: { status: 'active' } }));     // stale un-suspend → 409
        const C = await startReplica('C', { notifier });
        expect((await C.call('tenant.assert', tid)).reason).toBe('TENANT_SUSPENDED');
      });
    });
  }
});
