'use strict';

/**
 * step 6 — REAL PostgreSQL proof of signed, anchored audit checkpoints (migration 070).
 *
 *   SC-01  end to end: audit entries mirrored to PG → createSignedCheckpoint() persists the signed checkpoint with the
 *          head's real pg seq, appends the sidecar, and registers an AUDIT_CHECKPOINT transparency leaf whose payload
 *          carries the checkpoint's payloadHash; the stored row verifies
 *   SC-02  audit_signed_checkpoints is append-only for the request-serving role: UPDATE / DELETE / TRUNCATE refused
 *   SC-03  the PUBLIC transparency register API cannot create an AUDIT_CHECKPOINT leaf (input schema refuses it); the
 *          DB CHECK accepts it
 *   SC-04  boot verification against the PG-stored checkpoint: verified; with the head row's hash changed in memory
 *          → fail closed
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const DB = `qodiqa_w10sc_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const APP_PASSWORD = process.env.QODIQA_PG_USER === 'qodiqa_app' ? process.env.QODIQA_PG_PASSWORD : 'REPLACE_WITH_VAULT_SECRET_APP';
const APP_PASSWORD_REAL = process.env.QODIQA_PG_PASSWORD;   // this machine's rotated app password (before elevation)

describeOrSkip('signed, anchored audit checkpoints (real PostgreSQL)', () => {
  let maint; let pgPool; let rolePools; let auditLog; let w; let cp; let backend; let appPool;
  const saved = {};

  beforeAll(async () => {
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD']) saved[k] = process.env[k];
    maint = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER, password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    process.env.QODIQA_PG_DATABASE = DB;
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    rolePools = require('../../src/infra/postgres/rolePools');
    pgPool.initialize();
    await pgPool.runMigrations();
    backend = require('../../src/infra/postgres/pg-audit-backend');
    auditLog = require('../../src/core/audit/audit-log');
    w = require('../../src/core/audit/checkpoint/checkpointWriter');
    cp = require('../../src/core/audit/checkpoint/checkpoint');
    appPool = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), database: DB,
      user: 'qodiqa_app', password: saved.QODIQA_PG_USER === 'qodiqa_app' ? APP_PASSWORD_REAL : APP_PASSWORD });
  }, 120_000);

  afterAll(async () => {
    if (appPool) await appPool.end().catch(() => {});
    await pgPool.shutdown().catch(() => {});
    await rolePools.shutdownAll().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try { await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch (e) { console.warn(`[w10sc] could not drop ${DB}: ${e.message}`); }
      await maint.end();
    }
  }, 60_000);

  let signed;
  test('SC-01 end to end: mirrored chain → signed checkpoint in PG + sidecar + AUDIT_CHECKPOINT leaf', async () => {
    for (let i = 0; i < 6; i++) {
      await auditLog.append({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
    }
    await auditLog.drainMirrorWriter();
    const tail = await backend.getChainTail();
    signed = await w.createSignedCheckpoint({ trigger: 'SC-01', emit: () => {} });
    expect(signed.payload.headHash).toBe(String(tail.hash).trim());
    expect(signed.payload.pgSeq).toBe(Number(tail.seq));
    const latest = await backend.getLatestSignedCheckpoint();
    expect(latest.payloadHash).toBe(signed.payloadHash);
    expect(cp.verifyCheckpoint(latest)).toEqual({ ok: true });
    expect(w.readSidecar(auditLog.LOG_PATH).map((x) => x.payloadHash)).toContain(signed.payloadHash);
    const { rows } = await pgPool.query("SELECT entry_type, payload FROM transparency_log_entries WHERE entry_type = 'AUDIT_CHECKPOINT'");
    expect(rows).toHaveLength(1);
    expect(rows[0].payload).toMatchObject({ checkpointId: signed.payload.checkpointId, checkpointPayloadHash: signed.payloadHash,
      chainLength: signed.payload.chainLength, headHash: signed.payload.headHash });
  });

  test('SC-02 append-only for the request-serving role', async () => {
    const id = signed.payload.checkpointId;
    await expect(appPool.query('UPDATE audit_signed_checkpoints SET signature = $1 WHERE checkpoint_id = $2', ['x', id])).rejects.toThrow(/permission denied|append-only/);
    await expect(appPool.query('DELETE FROM audit_signed_checkpoints WHERE checkpoint_id = $1', [id])).rejects.toThrow(/permission denied|append-only/);
    await expect(appPool.query('TRUNCATE audit_signed_checkpoints')).rejects.toThrow(/permission denied|append-only/);
    expect((await appPool.query('SELECT count(*)::int n FROM audit_signed_checkpoints')).rows[0].n).toBe(1);   // app can read
  });

  test('SC-03 the public register API cannot create an AUDIT_CHECKPOINT leaf', () => {
    const { registerEntryBodySchema } = require('../../src/validation/schemas/transparency.schema');
    expect(registerEntryBodySchema.safeParse({ entryType: 'AUDIT_CHECKPOINT', payload: {} }).success).toBe(false);
    expect(registerEntryBodySchema.safeParse({ entryType: 'SYSTEM', payload: {} }).success).toBe(true);
  });

  test('SC-04 boot verification against the PG checkpoint; a chain that no longer matches fails closed', async () => {
    expect(await w.verifyLatestCheckpointAtBoot({ emit: () => {} })).toMatchObject({ checked: true, checkpointId: signed.payload.checkpointId });
    const real = auditLog.getModernEntryAt;
    const fake = { ...auditLog, getModernEntryAt: async (i) => ({ ...(await real(i)), hash: 'd'.repeat(64) }) };
    await expect(w.verifyLatestCheckpointAtBoot({ emit: () => {}, auditLog: fake })).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED' });
  });
});
