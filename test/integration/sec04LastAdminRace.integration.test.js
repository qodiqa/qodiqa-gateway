'use strict';

/**
 * — the last-admin rule under concurrency, on a real disposable PostgreSQL
 * database with the full migration chain (test:component:serial: it runs the chain).
 *
 * The rule used to be checked only against the replica's in-memory snapshot, then written per row with a per-row
 * version check. Two concurrent demotions of the only two admins each saw the OTHER admin as enabled, touched
 * different rows, and both committed: zero admins.
 *
 *   LA-01 the original defect, reproduced at the storage layer: two unguarded writes both commit → zero admins
 *   LA-02 two concurrent demotions of the only two admins (same snapshot): exactly one commits, the other is
 *         LAST_ADMIN, and PostgreSQL still holds exactly one enabled admin
 *   LA-03 concurrent disable + delete of the only two admins: exactly one commits, one enabled admin remains
 *   LA-04 control: with three admins, two concurrent demotions both commit (the guard does not over-refuse)
 *   LA-05 a write that does not reduce the admin set takes no lock and is unaffected
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_CONTROL_PASSWORD;
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_sec04_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const base = () => ({
  host: process.env.QODIQA_PG_HOST || 'localhost',
  port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  ssl: false, connectionTimeoutMillis: 5000,
});
let maint; let owner;
const saved = {};

describeOrSkip('last-admin rule on real PostgreSQL', () => {
  let cp; let store;

  const enabledAdmins = async () => Number((await owner.query(
    `SELECT count(*)::int AS n FROM control_plane_records
      WHERE store = 'rbac_user' AND NOT deleted AND data->>'role' = 'admin' AND data->'enabled' = 'true'::jsonb`)).rows[0].n);

  // Start every case from an rbac_user store with exactly the given admins (older rows are tombstoned directly).
  async function admins(n, tag) {
    await owner.query("UPDATE control_plane_records SET deleted = true, version = version + 1 WHERE store = 'rbac_user' AND NOT deleted");
    await cp.syncNow();
    const out = [];
    for (let i = 0; i < n; i++) out.push(await store.createUser({ username: `${tag}-admin-${i}`, role: 'admin' }));
    await cp.syncNow();
    expect(await enabledAdmins()).toBe(n);
    return out;
  }

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

    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_URL', 'QODIQA_CONTROL_PLANE_BACKEND']) saved[k] = process.env[k];
    delete process.env.QODIQA_PG_URL;
    process.env.QODIQA_PG_DATABASE = DB;
    process.env.QODIQA_CONTROL_PLANE_BACKEND = 'pg';
    cp = require('../../src/core/controlPlane');
    store = require('../../src/core/rbac/store');
    await cp._resetForTest();
    await cp.start({ notifier: false });
  });

  afterAll(async () => {
    if (cp) { await cp.stop(); await require('../../src/infra/postgres/rolePools').shutdownAll(); }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (owner) await owner.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  test('LA-01 the original defect: two unguarded per-row writes both commit and leave zero admins', async () => {
    const [a, b] = await admins(2, 'la01');
    const demote = (u) => cp.writeRow('rbac_user', u.id, { data: { ...store.getUser(u.id), role: 'operator' }, expectedVersion: 1 });
    const r = await Promise.allSettled([demote(a), demote(b)]);
    expect(r.map((x) => x.status)).toEqual(['fulfilled', 'fulfilled']);
    expect(await enabledAdmins()).toBe(0);
  });

  test('LA-02 two concurrent demotions of the only two admins: exactly one commits, one LAST_ADMIN, one admin left', async () => {
    const [a, b] = await admins(2, 'la02');
    const r = await Promise.allSettled([
      store.updateUser(a.id, { role: 'operator', updatedBy: 'la02' }),
      store.updateUser(b.id, { role: 'operator', updatedBy: 'la02' }),
    ]);
    const ok = r.filter((x) => x.status === 'fulfilled');
    const refused = r.filter((x) => x.status === 'rejected');
    expect(ok).toHaveLength(1);
    expect(refused).toHaveLength(1);
    expect(refused[0].reason.code).toBe('LAST_ADMIN');
    expect(await enabledAdmins()).toBe(1);
  });

  test('LA-03 concurrent disable + delete of the only two admins: exactly one commits, one admin left', async () => {
    const [a, b] = await admins(2, 'la03');
    const r = await Promise.allSettled([
      store.updateUser(a.id, { enabled: false, updatedBy: 'la03' }),
      store.deleteUser(b.id, { deletedBy: 'la03' }),
    ]);
    expect(r.filter((x) => x.status === 'fulfilled')).toHaveLength(1);
    const refused = r.filter((x) => x.status === 'rejected');
    expect(refused).toHaveLength(1);
    expect(refused[0].reason.code).toBe('LAST_ADMIN');
    expect(await enabledAdmins()).toBe(1);
  });

  test('LA-04 control: with three admins, two concurrent demotions both commit', async () => {
    const [a, b] = await admins(3, 'la04');
    const r = await Promise.allSettled([
      store.updateUser(a.id, { role: 'operator', updatedBy: 'la04' }),
      store.updateUser(b.id, { role: 'operator', updatedBy: 'la04' }),
    ]);
    expect(r.map((x) => x.status)).toEqual(['fulfilled', 'fulfilled']);
    expect(await enabledAdmins()).toBe(1);
  });

  test('LA-05 a write that does not reduce the admin set is unaffected (rename of the last admin)', async () => {
    const [a] = await admins(1, 'la05');
    const u = await store.updateUser(a.id, { username: 'la05-renamed', updatedBy: 'la05' });
    expect(u.username).toBe('la05-renamed');
    expect(await enabledAdmins()).toBe(1);
    await expect(Promise.resolve().then(() => store.updateUser(a.id, { role: 'operator', updatedBy: 'la05' }))).rejects.toMatchObject({ code: 'LAST_ADMIN' });
  });
});
