'use strict';

// the global kill switch across replicas (PostgreSQL control plane, one forked process per replica).
//
// The switch is a signed control-plane record. The approved propagation guarantee is a 5 s bound: an activation
// committed on one replica is in force on every other by t + 5 s, or that replica REFUSES to answer (CONTROL_PLANE_STALE →
// the gate answers 503 KILL_SWITCH_STATE_UNAVAILABLE). Two notifier modes are measured, like test/replicaRevocation:
// 'on' (the signed Redis pub/sub — the normal path) and 'off' (pub/sub lost: the periodic pull alone must still meet the bound).
//
//   KP-01 [on|off]  activation on A is seen by B and C within the bound; release likewise (times are recorded)
//   KP-02           a replica that stops pulling cannot keep claiming "off": past the bound its state() refuses
//   KP-03           a database-level change of the record (active → false) without the MAC is read as ACTIVE on every replica
//   KP-04           a stale replica cannot undo a newer activation (release from a stale snapshot is a 409)
//   KP-05           the database refuses to soft-delete the record or to roll its seq back (migration 097)

const { fork, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_CONTROL_PASSWORD;
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DRIVER = path.join(__dirname, '..', 'helpers', 'replicaDriver.js');
const BOUND_MS = 5000;
const DB = `qodiqa_ksprop_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const measured = [];
const live = [];
let maint; let admin; let ringDir;

function startReplica(name, { notifier = 'on' } = {}) {
  const env = { ...process.env, QODIQA_CONTROL_PLANE_BACKEND: 'pg', QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DB, QODIQA_MAC_KEYS_PATH: path.join(ringDir, 'mac-keys.json'), W6_NOTIFIER: notifier };
  delete env.QODIQA_PG_URL;
  delete env.QODIQA_AUDIT_SCHEMA_V8;
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
      if (m.ok) p.resolve(m.value); else { const e = new Error(`${name}: ${m.error}`); e.code = m.code; p.reject(e); }
    });
  });
  const call = (op, arg) => new Promise((resolve, reject) => { const s = ++seq; pending.set(s, { resolve, reject }); child.send({ seq: s, op, arg }); });
  return ready.then(() => ({ name, call }));
}

/** Poll `probe` until `ok(value)`; returns elapsed ms since t0; throws once the bound is exceeded. */
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

describeOrSkip('kill switch across replicas (PostgreSQL control plane)', () => {
  beforeAll(async () => {
    const base = { host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD };
    maint = new Pool({ ...base, database: 'postgres' });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    admin = new Pool({ ...base, database: DB });
    ringDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-ks-ring-'));
    const init = spawnSync(process.execPath, ['-e', "require('./src/core/security/macKeyring').init()"], { cwd: REPO_ROOT, encoding: 'utf8', env: { ...process.env, QODIQA_MAC_KEYS_PATH: path.join(ringDir, 'mac-keys.json') } });
    if (init.status !== 0) throw new Error(`mac keyring init failed: ${init.stderr}`);
  });

  afterEach(() => {
    while (live.length) { try { live.pop().kill(); } catch (_) { /* already gone */ } }
  });

  afterAll(async () => {
    const out = process.env.KS_EVIDENCE_FILE || path.join(os.tmpdir(), 'qodiqa-kill-switch-propagation.json');
    fs.writeFileSync(out, JSON.stringify({ boundMs: BOUND_MS, measured }, null, 2));
    if (admin) await admin.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  for (const notifier of ['on', 'off']) {
    test(`KP-01 [${notifier}] activation on A is in force on B and C within the bound; release likewise`, async () => {
      const [A, B, C] = await Promise.all(['A', 'B', 'C'].map((n) => startReplica(n, { notifier })));
      for (const r of [A, B, C]) expect(await r.call('ks.state')).toMatchObject({ active: false, tampered: false });
      const t0 = Date.now();
      expect(await A.call('ks.activate', 'propagation test')).toEqual({ changed: true, active: true });
      expect((await A.call('ks.state')).active).toBe(true);
      await within(`KP-01/${notifier} activation on B`, () => B.call('ks.state'), (v) => v.active === true, t0);
      await within(`KP-01/${notifier} activation on C`, () => C.call('ks.state'), (v) => v.active === true, t0);
      const t1 = Date.now();
      expect(await B.call('ks.release')).toEqual({ changed: true, active: false });
      await within(`KP-01/${notifier} release on A`, () => A.call('ks.state'), (v) => v.active === false, t1);
      await within(`KP-01/${notifier} release on C`, () => C.call('ks.state'), (v) => v.active === false, t1);
    });
  }

  test('KP-02 a replica that stops pulling cannot keep claiming "off": past the bound its state() refuses', async () => {
    const [A, B] = await Promise.all(['A', 'B'].map((n) => startReplica(n, { notifier: 'off' })));
    expect((await B.call('ks.state')).active).toBe(false);
    await B.call('cp.pause');                                    // B no longer pulls
    await A.call('ks.activate', 'B must not stay "off" silently');
    await new Promise((r) => setTimeout(r, BOUND_MS + 700));
    const err = await B.call('ks.state').then(() => null, (e) => e);
    expect(err && err.code).toBe('CONTROL_PLANE_STALE');         // the gate turns this into 503 KILL_SWITCH_STATE_UNAVAILABLE
  });

  test('KP-03 a change of the stored record without the MAC is read as ACTIVE on every replica', async () => {
    const [A, B] = await Promise.all(['A', 'B'].map((n) => startReplica(n, { notifier: 'on' })));
    await A.call('ks.activate', 'real activation');
    await within('KP-03 B sees the activation', () => B.call('ks.state'), (v) => v.active === true && v.tampered === false);
    // someone with database write access tries to switch it off: version + 1 (guard trigger) and a higher seq (migration 097), but no valid MAC
    await admin.query("UPDATE control_plane_records SET data = jsonb_set(jsonb_set(data, '{active}', 'false'::jsonb), '{seq}', to_jsonb(((data->>'seq')::bigint) + 1)), version = version + 1 WHERE store = 'kill_switch'");
    const t0 = Date.now();
    await A.call('cp.sync');
    await within('KP-03 tampered record on A', () => A.call('ks.state'), (v) => v.active === true && v.tampered === true, t0);
    await within('KP-03 tampered record on B', () => B.call('ks.state'), (v) => v.active === true && v.tampered === true, t0);
    // a legitimate release re-signs the record and clears the tamper flag everywhere
    expect(await A.call('ks.release')).toEqual({ changed: true, active: false });
    await within('KP-03 clean release on B', () => B.call('ks.state'), (v) => v.active === false && v.tampered === false);
  });

  test('KP-05 the database refuses to tombstone or roll back the kill-switch record (migration 097)', async () => {
    const [A] = await Promise.all(['A'].map((n) => startReplica(n, { notifier: 'off' })));
    await A.call('ks.activate', 'first');
    await A.call('ks.release');
    await A.call('ks.activate', 'second');                       // seq has advanced at least three times
    const before = (await admin.query("SELECT version, data FROM control_plane_records WHERE store = 'kill_switch'")).rows[0];
    // (a) tombstone: a missing record would read as "never activated"
    await expect(admin.query("UPDATE control_plane_records SET deleted = true, version = version + 1 WHERE store = 'kill_switch'")).rejects.toThrow(/cannot be deleted/);
    // (b) rollback: an older sequence number written over a newer one
    await expect(admin.query("UPDATE control_plane_records SET data = jsonb_set(data, '{seq}', '1'::jsonb), version = version + 1 WHERE store = 'kill_switch'")).rejects.toThrow(/seq must strictly increase/);
    // (c) same seq with other content is a rollback too; a non-numeric seq is refused
    await expect(admin.query("UPDATE control_plane_records SET data = jsonb_set(data, '{active}', 'false'::jsonb), version = version + 1 WHERE store = 'kill_switch'")).rejects.toThrow(/seq must strictly increase/);
    await expect(admin.query("UPDATE control_plane_records SET data = jsonb_set(data, '{seq}', '\"x\"'::jsonb), version = version + 1 WHERE store = 'kill_switch'")).rejects.toThrow(/seq must strictly increase/);
    const after = (await admin.query("SELECT version, data FROM control_plane_records WHERE store = 'kill_switch'")).rows[0];
    expect(after).toEqual(before);
    expect(await A.call('ks.state')).toMatchObject({ active: true, tampered: false });
    expect(await A.call('ks.release')).toEqual({ changed: true, active: false });   // leave the switch off for the next test
  });

  test('KP-04 a stale replica cannot undo a newer activation: its release is refused (409)', async () => {
    const [A, B] = await Promise.all(['A', 'B'].map((n) => startReplica(n, { notifier: 'off' })));
    const base = (await A.call('ks.state')).seq;
    await A.call('ks.activate', 'first');
    await within('KP-04 B learns the first activation', () => B.call('ks.state'), (v) => v.active === true);
    await B.call('cp.pause');                                    // B holds "active, seq 1"
    await A.call('ks.release');
    await A.call('ks.activate', 'second');                       // now seq 3 in the database
    const err = await B.call('ks.release').then(() => null, (e) => e);
    expect(err && err.code).toBe('CONTROL_PLANE_VERSION_CONFLICT');
    const C = await startReplica('C', { notifier: 'off' });
    expect(await C.call('ks.state')).toMatchObject({ active: true, tampered: false, seq: base + 3 });
  });
});
