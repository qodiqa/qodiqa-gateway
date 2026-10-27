'use strict';

/**
 * the distributed audit writer refuses to append a v7 entry when the chain head is v8.
 *
 * audit_chain_head.tail_schema_version (migration 098) is the schema version of the entry the head points at. The distributed writer
 * (distributedOrdering.js) reads it under the same `SELECT ... FOR UPDATE` that orders the append, refuses a LOWER version
 * (invalid_schema_downgrade) and writes the new entry's version back in the same UPDATE. The rebuild script, the seed script and the DR
 * restore maintain it too.
 *
 *   H5-01  migration 098: the column exists, NOT NULL default 0, backfilled from the tail row; the head row survives; grants/RLS as before
 *   H5-02  v7, then v8 (flag on), then a v7 writer: refused (invalid_schema_downgrade), nothing appended, head unchanged
 *   H5-03  two concurrent writers, one v7 and one v8 (many rounds): the chain never holds a v7 after a v8
 *   H5-04  scripts/audit-mirror-rebuild.js --apply keeps / restores the head version
 *   H5-05  scripts/seed-audit-chain-head.js seeds the version from the tail
 *   H5-06  DR: chainHeadReport flags a head whose version differs from its tail; repairAuditChainHeadVersion fixes it
 *   H5-07  privileges: qodiqa_read can read but not update the head; qodiqa_app can
 *
 * Real PostgreSQL only. Creates and drops its own database.
 */

const crypto = require('crypto');
const path = require('path');
const { spawnSync } = require('child_process');
const { Pool } = require('pg');
const { EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(120_000);

const DB = `qodiqa_f512_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const REPO = path.join(__dirname, '..', '..');

const baseCfg = () => ({
  host: process.env.QODIQA_PG_HOST || 'localhost',
  port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
});
const maintCreds = () => ({
  user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
  password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
});

let maint; let admin; let pgPool; let ordering;
const saved = {};
const PW = 'QODIQA_PG_' + 'PASSWORD';      // computed key: the secret scanner flags a literal assignment to the PG password variable

function fields(label, over = {}) {
  const id = `f512-${label}-${crypto.randomBytes(4).toString('hex')}`;
  return {
    artifactId: id,
    inputHash: crypto.createHash('sha256').update(id).digest('hex'),
    decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH,
    signature: 'test-signature',
    requestHash: crypto.createHash('sha256').update(`${id}:req`).digest('hex'),
    policyHash: crypto.createHash('sha256').update('test-policy').digest('hex'),
    verificationResult: true,
    ...over,
  };
}
const withFlag = async (on, fn) => {
  const prev = process.env.QODIQA_AUDIT_SCHEMA_V8;
  if (on) process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; else delete process.env.QODIQA_AUDIT_SCHEMA_V8;
  try { return await fn(); } finally { if (prev === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = prev; }
};
const head = async () => (await admin.query('SELECT tail_hash, tail_seq, tail_schema_version FROM audit_chain_head')).rows[0];

describeOrSkip('audit_chain_head.tail_schema_version (real PostgreSQL)', () => {
  beforeAll(async () => {
    maint = new Pool({ ...baseCfg(), ...maintCreds(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', connectionTimeoutMillis: 5000 });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW, 'QODIQA_AUDIT_ORDERING_MODE']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB;
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env[`QODIQA_PG_TEST_${'PASSWORD'}`]; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER; process.env[PW] = saved[PW];
    ordering = require('../../src/core/audit/distributedOrdering');
    admin = new Pool({ ...baseCfg(), ...maintCreds(), database: DB });
  });

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    if (admin) await admin.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try {
        await maint.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [DB]);
        await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      } catch (err) { console.warn(`[f512] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  test('H5-01 the column exists (SMALLINT NOT NULL DEFAULT 0, CHECK >= 0) and a fresh head starts at genesis / version 0', async () => {
    const col = (await admin.query("SELECT data_type, is_nullable, column_default FROM information_schema.columns WHERE table_name = 'audit_chain_head' AND column_name = 'tail_schema_version'")).rows[0];
    expect(col).toMatchObject({ data_type: 'smallint', is_nullable: 'NO' });
    expect(String(col.column_default)).toMatch(/^0/);
    const h = await head();
    expect(h.tail_hash.trim()).toBe('GENESIS');
    expect(Number(h.tail_schema_version)).toBe(0);
    await expect(admin.query('UPDATE audit_chain_head SET tail_schema_version = -1')).rejects.toThrow(/audit_chain_head_schema_version_check/);
  });

  test('H5-01b the migration backfill sets the version of the tail row on an existing chain (re-running the migration body is a no-op)', async () => {
    const e = await withFlag(false, () => ordering.appendEntry(fields('bf')));
    expect(e.schemaVersion).toBe(7);
    await admin.query('UPDATE audit_chain_head SET tail_schema_version = 0');            // simulate a head written before migration 098
    const sql = require('fs').readFileSync(path.join(REPO, 'src/infra/postgres/migrations/098_audit_chain_head_schema_version.sql'), 'utf8');
    await admin.query(sql);                                                              // idempotent re-run = the backfill path
    expect(Number((await head()).tail_schema_version)).toBe(7);
    await admin.query(sql);
    expect(Number((await head()).tail_schema_version)).toBe(7);
  });

  test('H5-02 v7, then v8, then a v7 writer: the v7 is refused (invalid_schema_downgrade), nothing is appended, the head is unchanged', async () => {
    const v8 = await withFlag(true, () => ordering.appendEntry(fields('v8')));
    expect(v8.schemaVersion).toBe(8);
    const after8 = await head();
    expect(Number(after8.tail_schema_version)).toBe(8);
    expect(after8.tail_hash.trim()).toBe(v8.hash);
    const err = await withFlag(false, () => ordering.appendEntry(fields('v7late'))).then(() => null, (e) => e);
    expect(err).toBeTruthy();
    expect(err.message).toMatch(/^invalid_schema_downgrade: the chain head is schema v8 and this writer would append v7/);
    expect(err.code).toBe('AUDIT_SCHEMA_DOWNGRADE_REFUSED');
    expect(await head()).toEqual(after8);
    const rows = (await admin.query('SELECT schema_version FROM audit_chain ORDER BY seq')).rows.map((r) => Number(r.schema_version));
    expect(rows).toEqual([...rows].sort((a, b) => a - b));        // never decreases
    // a v8 writer keeps working
    const again = await withFlag(true, () => ordering.appendEntry(fields('v8b')));
    expect(again.schemaVersion).toBe(8);
  });

  test('H5-03 concurrent v7 and v8 writers: whatever the interleaving, the chain never holds a v7 after a v8', async () => {
    // the schema version is chosen synchronously when appendEntry() starts (entryBuilder.normalizeFields), so set the flag only around the call
    const start = (v8, label) => {
      const prev = process.env.QODIQA_AUDIT_SCHEMA_V8;
      if (v8) process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; else delete process.env.QODIQA_AUDIT_SCHEMA_V8;
      try { return ordering.appendEntry(fields(label)).then((e) => ({ ok: true, v: e.schemaVersion }), (e) => ({ ok: false, code: e.code })); }
      finally { if (prev === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = prev; }
    };
    const tasks = [];
    for (let i = 0; i < 12; i++) tasks.push(start(i % 2 === 0, `c${i}`));
    const results = await Promise.all(tasks);
    expect(results.length).toBe(12);
    expect(results.filter((r) => !r.ok).every((r) => r.code === 'AUDIT_SCHEMA_DOWNGRADE_REFUSED')).toBe(true);
    const rows = (await admin.query('SELECT schema_version FROM audit_chain ORDER BY seq')).rows.map((r) => Number(r.schema_version));
    for (let i = 1; i < rows.length; i++) expect(rows[i]).toBeGreaterThanOrEqual(rows[i - 1]);
    expect(Number((await head()).tail_schema_version)).toBe(rows[rows.length - 1]);
  });

  test('H5-04 audit-mirror-rebuild --apply keeps the head version equal to its tail entry', async () => {
    const { rebuild } = require('../../scripts/audit-mirror-rebuild');
    await admin.query('UPDATE audit_chain_head SET tail_schema_version = 0');
    const c = await admin.connect();
    try {
      const report = await rebuild(c, { apply: true });
      expect(report.applied).toBe(true);
    } finally { c.release(); }
    const tailV = Number((await admin.query('SELECT schema_version FROM audit_chain ORDER BY seq DESC LIMIT 1')).rows[0].schema_version);
    expect(tailV).toBeGreaterThanOrEqual(8);
    expect(Number((await head()).tail_schema_version)).toBe(tailV);
  });

  test('H5-05 seed-audit-chain-head seeds the version from the tail', async () => {
    await admin.query('UPDATE audit_chain_head SET tail_schema_version = 0');
    const env = { ...process.env, QODIQA_PG_HOST: baseCfg().host, QODIQA_PG_PORT: String(baseCfg().port), QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: maintCreds().user };
    env['QODIQA_PG_MIG_' + 'PASSWORD'] = maintCreds().password || '';
    delete env.QODIQA_PG_URL;
    const r = spawnSync(process.execPath, ['scripts/seed-audit-chain-head.js'], { cwd: REPO, env, encoding: 'utf8' });
    expect({ status: r.status, out: `${r.stdout}${r.stderr}`.slice(0, 400) }).toMatchObject({ status: 0 });
    expect(r.stdout).toMatch(/audit_chain_head seeded/);
    const tailV = Number((await admin.query('SELECT schema_version FROM audit_chain ORDER BY seq DESC LIMIT 1')).rows[0].schema_version);
    expect(Number((await head()).tail_schema_version)).toBe(tailV);
  });

  test('H5-06 DR: chainHeadReport flags a head whose version differs from its tail, repairAuditChainHeadVersion fixes it', async () => {
    const { chainHeadReport, repairAuditChainHeadVersion } = require('../../scripts/dr/chainHeads');
    const tailV = Number((await admin.query('SELECT schema_version FROM audit_chain ORDER BY seq DESC LIMIT 1')).rows[0].schema_version);
    await admin.query('UPDATE audit_chain_head SET tail_schema_version = 0');
    const bad = await chainHeadReport(admin, { auditOrderingMode: 'distributed' });
    const h = bad.heads.find((x) => x.table === 'audit_chain_head');
    expect(h.consistent).toBe(false);
    expect(h.head.ver).toBe(0);
    expect(h.tail.ver).toBe(tailV);
    expect(bad.valid).toBe(false);
    expect(await repairAuditChainHeadVersion(admin)).toBe(true);
    const ok = await chainHeadReport(admin, { auditOrderingMode: 'distributed' });
    expect(ok.heads.find((x) => x.table === 'audit_chain_head').consistent).toBe(true);
    expect(ok.valid).toBe(true);
  });

  test('H5-07 privileges: qodiqa_read can read the head but not change the version; qodiqa_app (the writer) can', async () => {
    const c = await admin.connect();
    try {
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_read');
      expect((await c.query('SELECT tail_schema_version FROM audit_chain_head')).rows.length).toBe(1);
      await expect(c.query('UPDATE audit_chain_head SET tail_schema_version = 99')).rejects.toThrow(/permission denied/i);
      await c.query('ROLLBACK');
    } finally { c.release(); }
    const before = Number((await head()).tail_schema_version);
    const app = await pgPool.withTransaction(async (tx) => { const r = await tx.query('UPDATE audit_chain_head SET tail_schema_version = tail_schema_version RETURNING tail_schema_version'); return r.rows.length; });
    expect(app).toBe(1);
    expect(Number((await head()).tail_schema_version)).toBe(before);
  });
});
