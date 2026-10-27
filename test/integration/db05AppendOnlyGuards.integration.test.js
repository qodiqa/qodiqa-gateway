'use strict';

/**
 * DB-05 — append-only guards (migration 076) on a real disposable database with the
 * full migration chain (test:component:serial: it runs the chain).
 *
 *   AO-01 the app role can no longer UPDATE / DELETE / TRUNCATE policy_history or investigation_audit_events (grant)
 *   AO-02 the OWNER (BYPASSRLS, ALL privileges) is refused UPDATE / DELETE / TRUNCATE on all three tables without an
 *         intent — no role exemption
 *   AO-03 a declared, allowed intent permits the operation (prune on audit_chain; erasure on policy_history), scoped
 *         to the transaction (SET LOCAL): the next transaction is refused again
 *   AO-04 an intent allowed for one table does not open another (prune does not open policy_history; erasure does
 *         not open audit_chain); an unknown intent opens nothing
 *   AO-05 a permitted maintenance statement is logged (WARNING notice naming table, operation, role, intent)
 *   AO-06 INSERT is unaffected for the app role (the tables stay appendable)
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_TEST_PASSWORD;
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_db05_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const base = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false, connectionTimeoutMillis: 5000 });
let maint; let owner; let app;

const APPEND_ONLY = /append-only/;

describeOrSkip('DB-05 append-only guards (migration 076)', () => {
  beforeAll(async () => {
    delete process.env.PGOPTIONS; // this suite must see the guards exactly as production does
    maint = new Pool({ ...base(), database: 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const { spawnSync } = require('child_process');
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    owner = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD, max: 2 });
    app = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env.QODIQA_PG_PASSWORD, max: 2 });

    // Fixture rows (owner, declared fixture intent — the guard is on UPDATE/DELETE/TRUNCATE, not INSERT).
    await owner.query("INSERT INTO policies (id, name, type) VALUES ('db05-pol', 'db05', 'BLOCK_IP')");
    await owner.query("INSERT INTO policy_history (policy_id, event, actor) VALUES ('db05-pol', 'POLICY_CREATED', 'db05')");
    await owner.query("INSERT INTO investigations (id, title, investigator) VALUES ('INV-0000000000DB0005', 'db05', 'db05')");
    await owner.query("INSERT INTO investigation_audit_events (investigation_id, event_type) VALUES ('INV-0000000000DB0005', 'OPENED')");
    await owner.query(`INSERT INTO audit_chain (hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time,
                         input_hash, signature, request_hash, policy_hash, verification_result)
                       VALUES ($1, 'GENESIS', '{}', 'db05-a1', 'BLOCK', now(), '0', 'x', 'x', 'x', 'x', false)`, ['a'.repeat(64)]);
  });

  afterAll(async () => {
    for (const p of [app, owner]) if (p) await p.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  const tx = async (pool, intent, sql) => {
    const c = await pool.connect();
    const notices = [];
    c.on('notice', (n) => notices.push(n.message));
    try {
      await c.query('BEGIN');
      if (intent) await c.query(`SET LOCAL qodiqa.audit_maintenance = '${intent}'`);
      const r = await c.query(sql);
      await c.query('COMMIT');
      return { rowCount: r.rowCount, notices };
    } catch (e) {
      await c.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { c.release(); }
  };

  test('AO-00 fixtures present (the guards are tested against real rows)', async () => {
    for (const t of ['policy_history', 'investigation_audit_events', 'audit_chain']) {
      expect(Number((await owner.query(`SELECT count(*)::int AS n FROM ${t}`)).rows[0].n)).toBeGreaterThan(0);
    }
  });

  test('AO-01 app role: no UPDATE / DELETE / TRUNCATE on policy_history and investigation_audit_events', async () => {
    for (const t of ['policy_history', 'investigation_audit_events']) {
      await expect(app.query(`DELETE FROM ${t}`)).rejects.toThrow(/permission denied/);
      await expect(app.query(`UPDATE ${t} SET id = id`)).rejects.toThrow(/permission denied/);
      await expect(app.query(`TRUNCATE ${t}`)).rejects.toThrow(/permission denied/);
    }
  });

  test('AO-02 the owner is refused on all three tables without an intent', async () => {
    for (const t of ['audit_chain', 'policy_history', 'investigation_audit_events']) {
      await expect(owner.query(`UPDATE ${t} SET ${t === 'audit_chain' ? 'decision = decision' : 'id = id'}`)).rejects.toThrow(APPEND_ONLY);
      await expect(owner.query(`DELETE FROM ${t}`)).rejects.toThrow(APPEND_ONLY);
      await expect(owner.query(`TRUNCATE ${t} CASCADE`)).rejects.toThrow(APPEND_ONLY);
    }
  });

  test('AO-03/AO-05 an allowed intent permits the operation for that transaction only, and it is logged', async () => {
    const r = await tx(owner, 'erasure', "UPDATE policy_history SET comment = 'db05' WHERE actor = 'db05'");
    expect(r.rowCount).toBe(1);
    expect(r.notices.join('\n')).toMatch(/DB-05 audit maintenance: UPDATE on policy_history by role \S+ \(intent erasure/);
    await expect(owner.query("UPDATE policy_history SET comment = 'again' WHERE actor = 'db05'")).rejects.toThrow(APPEND_ONLY);
    const p = await tx(owner, 'prune', "DELETE FROM audit_chain WHERE artifact_id = 'db05-nonexistent'");
    expect(p.rowCount).toBe(0);
  });

  test('AO-04 an intent opens only the tables it is allowed for; an unknown intent opens nothing', async () => {
    await expect(tx(owner, 'prune', "UPDATE policy_history SET comment = 'x'")).rejects.toThrow(APPEND_ONLY);
    await expect(tx(owner, 'erasure', "DELETE FROM audit_chain WHERE artifact_id = 'db05-a1'")).rejects.toThrow(APPEND_ONLY);
    await expect(tx(owner, 'cleanup', 'DELETE FROM investigation_audit_events')).rejects.toThrow(APPEND_ONLY);
  });

  // Correction pass 2026-10-05 (migration 077): the intent is self-declared, so it must never be honoured for an
  // application-facing role — even if that role is granted write privileges by mistake.
  test('AO-07 a misgranted application role declaring a valid intent is still refused (077); the owner is not', async () => {
    await owner.query('GRANT UPDATE, DELETE ON policy_history TO qodiqa_app'); // simulated mistaken grant
    try {
      await expect(tx(app, 'erasure', "UPDATE policy_history SET comment = 'app-bypass' WHERE actor = 'db05'")).rejects.toThrow(/append-only: UPDATE refused for application role qodiqa_app/);
      await expect(tx(app, 'fixture', "DELETE FROM policy_history WHERE actor = 'db05'")).rejects.toThrow(/application role qodiqa_app/);
      expect((await owner.query("SELECT count(*)::int AS n FROM policy_history WHERE actor = 'db05'")).rows[0].n).toBe(1);
      // legitimate maintenance unchanged
      expect((await tx(owner, 'erasure', "UPDATE policy_history SET comment = 'owner-ok' WHERE actor = 'db05'")).rowCount).toBe(1);
    } finally {
      await owner.query('REVOKE UPDATE, DELETE ON policy_history FROM qodiqa_app');
    }
  });

  test('AO-08 migration 077 is recorded and the guard function carries the application-role refusal', async () => {
    expect((await owner.query('SELECT name FROM qodiqa_migrations WHERE version = 77')).rows[0].name).toBe('db05_intent_not_for_app_roles');
    const src = (await owner.query("SELECT prosrc FROM pg_proc WHERE proname = 'qodiqa_audit_append_only_guard'")).rows[0].prosrc;
    expect(src).toMatch(/current_user IN \('qodiqa_app', 'qodiqa_read', 'qodiqa_reporting'\)/);
  });

  test('AO-06 the app role can still append', async () => {
    await expect(app.query("INSERT INTO policy_history (policy_id, event, actor) SELECT policy_id, 'POLICY_UPDATED', 'db05-app' FROM policy_history LIMIT 1")).resolves.toBeDefined();
  });
});
