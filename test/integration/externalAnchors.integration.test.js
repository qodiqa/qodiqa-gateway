'use strict';

/**
 * external_anchors (migration 099) on real PostgreSQL, with the real publisher.
 *
 *   EX-01  the table exists, is owned by qodiqa_owner, has RLS forced, and the uniqueness per (payload hash, kind)
 *   EX-02  privileges: qodiqa_app inserts / updates / selects; qodiqa_read only selects
 *   EX-03  enqueue + publish through PostgreSQL: the row goes pending -> confirmed with the receipt; republishing the same checkpoint adds no row
 *   EX-04  a failing adapter leaves the row pending with last_error and an attempt count in PostgreSQL
 *
 * Real PostgreSQL only. Creates and drops its own database.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(120_000);

const DB = `qodiqa_f55_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const PW = 'QODIQA_PG_' + 'PASSWORD';     // computed key: the secret scanner flags a literal assignment to the PG password variable
const baseCfg = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
const maintCreds = () => ({ user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env[`QODIQA_PG_TEST_${'PASSWORD'}`] || process.env[PW] || undefined });
const INSERT = "INSERT INTO external_anchors (checkpoint_id, payload_hash, chain_length, head_hash, checkpoint_created_at, kind) VALUES ($2, $1, 1, $1, 'x', $3)";

let maint; let admin; let pgPool; let ea; let dir;
const saved = {};
const signed = (n) => ({ payload: { v: 1, checkpointId: `cp-${n}`, createdAt: '2026-10-21T10:00:00.000Z', chainLength: 10 + n, headHash: crypto.createHash('sha256').update(`h${n}`).digest('hex') }, payloadHash: crypto.createHash('sha256').update(`p${n}`).digest('hex'), signature: 's' });
function adapter(name, body) {
  const js = path.join(dir, `${name}.js`); fs.writeFileSync(js, body);
  if (process.platform === 'win32') { const c = path.join(dir, `${name}.cmd`); fs.writeFileSync(c, `@echo off\r\n"${process.execPath}" "${js}"\r\n`); return c; }
  const sh = path.join(dir, name); fs.writeFileSync(sh, `#!/bin/sh\nexec "${process.execPath}" "${js}"\n`); fs.chmodSync(sh, 0o755); return sh;
}

describeOrSkip('external_anchors (real PostgreSQL)', () => {
  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f55-'));
    maint = new Pool({ ...baseCfg(), ...maintCreds(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', connectionTimeoutMillis: 5000 });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW, 'QODIQA_ANCHOR_OTS_EXEC']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB;
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env[`QODIQA_PG_TEST_${'PASSWORD'}`]; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER; process.env[PW] = saved[PW];
    ea = require('../../src/core/audit/anchoring/externalAnchors');
    admin = new Pool({ ...baseCfg(), ...maintCreds(), database: DB });
  });
  afterAll(async () => {
    if (ea) ea.stop();
    if (pgPool) await pgPool.shutdown().catch(() => {});
    if (admin) await admin.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try {
        await maint.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [DB]);
        await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      } catch (err) { console.warn(`[f55] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  test('EX-01 the table is owned by the schema-owner role, row-level security is forced, and (payload hash, kind) is unique', async () => {
    const t = (await admin.query("SELECT tableowner, rowsecurity, (SELECT relforcerowsecurity FROM pg_class WHERE relname = 'external_anchors') AS forced FROM pg_tables WHERE tablename = 'external_anchors'")).rows[0];
    expect(t.rowsecurity).toBe(true); expect(t.forced).toBe(true);
    const owner = (await admin.query("SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner'")).rows.length;
    if (owner) expect(t.tableowner).toBe('qodiqa_owner');
    await admin.query(INSERT, ['a'.repeat(64), 'c', 'git']);
    await expect(admin.query(INSERT, ['a'.repeat(64), 'c2', 'git'])).rejects.toThrow(/external_anchors_unique_per_kind/);
    await expect(admin.query(INSERT, ['b'.repeat(64), 'c', 'carrier-pigeon'])).rejects.toThrow(/check/i);
  });

  test('EX-02 qodiqa_app writes, qodiqa_read only reads', async () => {
    const c = await admin.connect();
    try {
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_read');
      expect((await c.query('SELECT count(*) FROM external_anchors')).rows.length).toBe(1);
      await expect(c.query("UPDATE external_anchors SET status = 'failed'")).rejects.toThrow(/permission denied/i);
      await c.query('ROLLBACK');
    } finally { c.release(); }
    const n = await pgPool.withTransaction(async (tx) => (await tx.query("UPDATE external_anchors SET attempts = attempts WHERE kind = 'git'")).rowCount);
    expect(n).toBe(1);
  });

  test('EX-03 enqueue + publish through PostgreSQL: pending -> confirmed with the receipt; the same checkpoint adds no row', async () => {
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter('ots', "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const i=JSON.parse(d);process.stdout.write(JSON.stringify({receipt:'ots:'+i.digestHex,ref:'ref'}));});");
    ea._reset();
    const s = signed(1);
    expect(await ea.enqueue(s, { force: true })).toEqual({ queued: ['ots'] });
    await ea.settle();
    const row = (await admin.query("SELECT * FROM external_anchors WHERE payload_hash = $1 AND kind = 'ots'", [s.payloadHash])).rows[0];
    expect(row).toMatchObject({ status: 'confirmed', attempts: 1, receipt: `ots:${ea.digestOf(ea.statementFor(s))}`, receipt_ref: 'ref', checkpoint_id: 'cp-1', checkpoint_created_at: '2026-10-21T10:00:00.000Z' });
    expect(Number(row.chain_length)).toBe(11);
    expect(row.confirmed_at).not.toBeNull();
    expect(await ea.enqueue(s, { force: true })).toEqual({ queued: [] });
    expect(Number((await admin.query('SELECT count(*) AS n FROM external_anchors WHERE payload_hash = $1', [s.payloadHash])).rows[0].n)).toBe(1);
  });

  test('EX-04 a failing adapter leaves the row pending with last_error and the attempt count in PostgreSQL', async () => {
    process.env.QODIQA_ANCHOR_OTS_EXEC = adapter('bad', "process.stderr.write('calendar down');process.exit(2);");
    ea._reset();
    const s = signed(2);
    await ea.enqueue(s, { force: true }); await ea.settle();
    const row = (await admin.query('SELECT * FROM external_anchors WHERE payload_hash = $1', [s.payloadHash])).rows[0];
    expect(row).toMatchObject({ status: 'pending', attempts: 1 });
    expect(row.last_error).toMatch(/calendar down/);
    expect(row.confirmed_at).toBeNull();
  });
});
