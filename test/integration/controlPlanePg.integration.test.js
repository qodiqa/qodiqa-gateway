'use strict';

/**
 * the PostgreSQL control plane on a real disposable database with
 * the full migration chain (test:component:serial: it runs the chain).
 *
 *   CP-01  privileges: qodiqa_app has no access; qodiqa_control cannot hard-delete
 *   CP-02  trigger rules: version +1 only, no un-delete, key status forward-only
 *   CP-03  a stale write (wrong expected version) is refused with 409
 *   CP-04  concurrent writes on one version: exactly one wins, no lost update
 *   CP-05  the pull never skips a transaction that commits late (xid8 horizon)
 *   CP-06  PostgreSQL outage: fresh snapshot keeps answering; past 5 s → 503, no stale authorization
 *   CP-07  touchLastUsed: coalesced (≤ 1 write per record per minute), never moves version, no file write
 *   CP-08  store level: a revocation from another writer is visible after a pull; a stale revoke-undo is 409
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_CONTROL_PASSWORD;
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_w6cp_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const base = () => ({
  host: process.env.QODIQA_PG_HOST || 'localhost',
  port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  ssl: false, connectionTimeoutMillis: 5000,
});
let maint; let owner; let control; let app;
const saved = {};

describeOrSkip('control plane on real PostgreSQL', () => {
  let cp; let signing;

  beforeAll(async () => {
    maint = new Pool({ ...base(), database: 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const { spawnSync } = require('child_process');
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    owner = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    control = new Pool({ ...base(), database: DB, user: 'qodiqa_control', password: process.env.QODIQA_PG_CONTROL_PASSWORD, max: 4 });
    app = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env.QODIQA_PG_PASSWORD, max: 2 });

    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_URL', 'QODIQA_CONTROL_PLANE_BACKEND']) saved[k] = process.env[k];
    delete process.env.QODIQA_PG_URL;
    process.env.QODIQA_PG_DATABASE = DB;
    process.env.QODIQA_CONTROL_PLANE_BACKEND = 'pg';
    cp = require('../../src/core/controlPlane');
    signing = require('../../src/core/signing/signingIdentityStore');
    await cp._resetForTest();
    await cp.start({ notifier: false });
  });

  afterAll(async () => {
    if (cp) { await cp.stop(); await require('../../src/infra/postgres/rolePools').shutdownAll(); }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    for (const p of [app, control, owner]) if (p) await p.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  test('CP-01 qodiqa_app has no access; qodiqa_control cannot hard-delete', async () => {
    await expect(app.query('SELECT 1 FROM control_plane_records')).rejects.toThrow(/permission denied/);
    await control.query("INSERT INTO control_plane_records (store, record_id, data) VALUES ('tenant', 'cp01', '{}')");
    await expect(control.query("DELETE FROM control_plane_records WHERE record_id = 'cp01'")).rejects.toThrow(/permission denied/);
    const grants = await owner.query("SELECT privilege_type FROM information_schema.role_table_grants WHERE table_name = 'control_plane_records' AND grantee = 'qodiqa_control' ORDER BY 1");
    expect(grants.rows.map((r) => r.privilege_type)).toEqual(['INSERT', 'SELECT', 'UPDATE']);
  });

  test('CP-02 trigger: version advances by exactly 1, no un-delete, signing-key status only moves forward', async () => {
    await control.query("INSERT INTO control_plane_records (store, record_id, data) VALUES ('tenant', 'cp02', '{\"s\":1}')");
    await expect(control.query("UPDATE control_plane_records SET data='{\"s\":2}', version = version + 2 WHERE record_id='cp02'")).rejects.toThrow(/version must advance by exactly 1/);
    await control.query("UPDATE control_plane_records SET data='{\"s\":2}', version = version + 1, deleted = true WHERE record_id='cp02'");
    await expect(control.query("UPDATE control_plane_records SET data='{\"s\":3}', version = version + 1, deleted = false WHERE record_id='cp02'")).rejects.toThrow(/cannot be restored/);
    await control.query("INSERT INTO control_plane_records (store, record_id, data) VALUES ('signing_key_status', 'cp02:key_v1', '{\"status\":\"revoked\"}')");
    await expect(control.query("UPDATE control_plane_records SET data='{\"status\":\"active\"}', version = version + 1 WHERE record_id='cp02:key_v1'")).rejects.toThrow(/may only move forward/);
  });

  test('CP-03 a write naming a stale version is refused with 409 and changes nothing', async () => {
    const { version } = await cp.writeRow('tenant', 'cp03', { data: { status: 'active' }, expectedVersion: null });
    expect(version).toBe(1);
    await cp.writeRow('tenant', 'cp03', { data: { status: 'suspended' }, expectedVersion: 1 });
    const err = await cp.writeRow('tenant', 'cp03', { data: { status: 'active' }, expectedVersion: 1 }).catch((e) => e);
    expect(err.code).toBe('CONTROL_PLANE_VERSION_CONFLICT');
    expect(err.status).toBe(409);
    const row = (await owner.query("SELECT data, version FROM control_plane_records WHERE store='tenant' AND record_id='cp03'")).rows[0];
    expect(row).toEqual({ data: { status: 'suspended' }, version: '2' });
  });

  test('CP-04 concurrent writes on the same version: exactly one wins, no lost update', async () => {
    await cp.writeRow('tenant', 'cp04', { data: { n: 0 }, expectedVersion: null });
    const results = await Promise.allSettled(Array.from({ length: 8 }, (_, i) => cp.writeRow('tenant', 'cp04', { data: { n: i + 1 }, expectedVersion: 1 })));
    const ok = results.filter((r) => r.status === 'fulfilled');
    const conflicts = results.filter((r) => r.status === 'rejected' && r.reason.code === 'CONTROL_PLANE_VERSION_CONFLICT');
    expect(ok).toHaveLength(1);
    expect(conflicts).toHaveLength(7);
    const row = (await owner.query("SELECT data, version FROM control_plane_records WHERE record_id='cp04'")).rows[0];
    expect(row.version).toBe('2');
    const winner = results.findIndex((r) => r.status === 'fulfilled') + 1;
    expect(row.data).toEqual({ n: winner });
  });

  test('CP-05 the pull never skips a transaction that commits after a later one', async () => {
    const slow = await control.connect();
    try {
      await slow.query('BEGIN');
      await slow.query("INSERT INTO control_plane_records (store, record_id, data) VALUES ('tenant', 'cp05-slow', '{\"status\":\"suspended\"}')");
      await control.query("INSERT INTO control_plane_records (store, record_id, data) VALUES ('tenant', 'cp05-fast', '{\"status\":\"active\"}')");
      await cp.syncNow();
      const tenants = require('../../src/core/tenancy/tenantRegistry');
      expect(tenants.getTenant('cp05-fast')).not.toBeNull();
      expect(tenants.getTenant('cp05-slow')).toBeNull();
      await slow.query('COMMIT');
      await cp.syncNow();
      expect(tenants.getTenant('cp05-slow')).toEqual({ status: 'suspended' });
    } finally { slow.release(); }
  });

  test('CP-06 PostgreSQL outage: a fresh snapshot answers; after 5 s the replica refuses (503) instead of trusting stale authorization', async () => {
    const ident = await signing.createSigningIdentity({ name: 'cp06', tenantId: 'cp06tenant', environment: 'test', permissions: ['SIGN_ARTIFACT'] });
    const { plaintext } = await signing.issueSigningKey(ident.id);
    await cp.syncNow();
    const realPool = require('../../src/infra/postgres/rolePools').control;
    cp._setPoolForTest({ query: async () => { const e = new Error('connect ECONNREFUSED (simulated outage)'); e.code = 'ECONNREFUSED'; throw e; } });
    try {
      const t0 = Date.now();
      await expect(cp.syncNow()).rejects.toThrow(/ECONNREFUSED/);
      expect(signing.resolveSigningIdentity(plaintext)).not.toBeNull();          // fresh: still answers
      const wait = Math.max(0, 5000 - cp.status().ageMs + 300); // lastSyncOkAt is a monotonic stamp; ageMs is computed on the same clock
      await new Promise((r) => setTimeout(r, wait));
      let err = null;
      try { signing.resolveSigningIdentity(plaintext); } catch (e) { err = e; }
      expect(err && err.code).toBe('CONTROL_PLANE_STALE');
      expect(err.status).toBe(503);
      expect(Date.now() - t0).toBeLessThan(7000);
    } finally {
      cp._setPoolForTest(null);
      void realPool;
    }
    await cp.syncNow();
    expect(signing.resolveSigningIdentity(plaintext)).not.toBeNull();            // recovers with PostgreSQL
  });

  test('CP-07 touchLastUsed: ≤ 1 write per identity per minute, version unchanged, no file written', async () => {
    const ident = await signing.createSigningIdentity({ name: 'cp07', tenantId: 'cp07tenant', environment: 'test', permissions: ['SIGN_ARTIFACT'] });
    await signing.issueSigningKey(ident.id);
    const before = (await owner.query("SELECT version FROM control_plane_records WHERE record_id=$1", [ident.id])).rows[0].version;
    const writes = jest.spyOn(fs, 'writeFileSync');
    let touchQueries = 0;
    const realPool = require('../../src/infra/postgres/rolePools').control;
    cp._setPoolForTest({ query: (sql, p, l) => { if (/last_used_at = GREATEST/.test(sql)) touchQueries++; return realPool.query(sql, p, l); } });
    try {
      for (let i = 0; i < 200; i++) signing.touchLastUsed(ident.id);
      await new Promise((r) => setTimeout(r, 300));
      expect(touchQueries).toBe(1);
      expect(writes).not.toHaveBeenCalled();
      expect(cp._touchStats().pending).toBe(1);                                   // the rest waits for the minute
    } finally { cp._setPoolForTest(null); writes.mockRestore(); }
    const after = (await owner.query("SELECT version, last_used_at FROM control_plane_records WHERE record_id=$1", [ident.id])).rows[0];
    expect(after.version).toBe(before);
    expect(after.last_used_at).not.toBeNull();
  });

  test('CP-08 store level: another writer\'s revocation arrives by pull; a stale un-revoke from this replica is 409', async () => {
    const ident = await signing.createSigningIdentity({ name: 'cp08', tenantId: 'cp08tenant', environment: 'test', permissions: ['SIGN_ARTIFACT'] });
    const { plaintext } = await signing.issueSigningKey(ident.id);
    expect(signing.resolveSigningIdentity(plaintext)).not.toBeNull();
    // another replica revokes (direct versioned row write, as that replica's store would)
    const row = (await owner.query("SELECT data, version FROM control_plane_records WHERE record_id=$1", [ident.id])).rows[0];
    await control.query('UPDATE control_plane_records SET data=$2::jsonb, version=version+1 WHERE record_id=$1 AND version=$3',
      [ident.id, JSON.stringify({ ...row.data, revoked: true, apiKeyHash: null }), row.version]);
    // this replica has NOT pulled yet: its stale re-issue (which would un-revoke) is refused
    const err = await signing.issueSigningKey(ident.id).catch((e) => e);
    expect(err.code).toBe('CONTROL_PLANE_VERSION_CONFLICT');
    await cp.syncNow();
    expect(signing.resolveSigningIdentity(plaintext)).toBeNull();
    const final = (await owner.query("SELECT data->>'revoked' AS revoked FROM control_plane_records WHERE record_id=$1", [ident.id])).rows[0];
    expect(final.revoked).toBe('true');
  });
});
