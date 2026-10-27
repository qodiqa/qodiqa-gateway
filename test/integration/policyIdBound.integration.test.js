'use strict';

/**
 * an audit decision must never commit if its
 * policyDecision.policyId cannot subsequently be represented by the evidence ledger
 * (evidence_chain_records.policy_id VARCHAR(256)). Real disposable PostgreSQL (one database
 * per ordering mode), real audit-log.append() / appendMandatory(), real evidence writer;
 * pooled role the non-BYPASSRLS qodiqa_app.
 *
 * For each ordering mode (single-node, distributed):
 *   PB-01  256 characters (the column maximum), ALLOW and BLOCK: audit + evidence written, VALID
 *   PB-02  64 characters (the maximum a policy store accepts): unchanged
 *   PB-03  257 and 300 characters, ALLOW and BLOCK: rejected before commit — no audit row, no
 *          evidence row, no sequence id consumed, no recovery item, deterministic invalid_ error
 *   PB-04  appendMandatory: the rejection is not retried and nothing is written
 *   PB-05  the chain is unaffected: the next append chains normally and the audit chain verifies
 *
 * Opt-in like every PG-gated component suite; runs in test:component:serial.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool }  = require('pg');
const crypto    = require('crypto');
const fs        = require('fs');
const os        = require('os');
const path      = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const STAMP = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const ENV_KEYS = ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_AUDIT_ORDERING_MODE', 'QODIQA_DEPLOYMENT_MODE',
  'QODIQA_AUDIT_LOG', 'QODIQA_PRQ_JOURNAL_DIR', 'TENANT_STORE_PATH'];
const EVIDENCE_POLICY_ID_MAX = 256; // migration 010: evidence_chain_records.policy_id VARCHAR(256)

jest.setTimeout(120_000);

function _restoreEnv(name, value) {
  if (value === undefined) delete process.env[name]; else Object.assign(process.env, { [name]: value });
}

describeOrSkip('policyDecision.policyId bound at the audit-log boundary (real disposable Postgres, qodiqa_app)', () => {
  const orig = {};
  let maint;
  const base = () => ({
    host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false, connectionTimeoutMillis: 5000,
  });

  beforeAll(async () => {
    for (const k of ENV_KEYS) orig[k] = process.env[k];
    maint = new Pool({ ...base(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER, password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD });
  });
  afterAll(async () => {
    for (const k of ENV_KEYS) _restoreEnv(k, orig[k]);
    if (maint) await maint.end().catch(() => {});
  });

  for (const MODE of ['single-node', 'distributed']) {
    describe(`ordering mode: ${MODE}`, () => {
      const DB = `qodiqa_h136_test_${MODE === 'distributed' ? 'dist' : 'single'}_${STAMP}`;
      const TMP = fs.mkdtempSync(path.join(os.tmpdir(), `${DB}-`));
      let pgPool, admin, auditLog, chainStore, pgAudit;

      beforeAll(async () => {
        if (!SAFE_IDENTIFIER.test(DB)) throw new Error(`unsafe test DB name ${DB}`);
        await maint.query(`CREATE DATABASE "${DB}"`);
        Object.assign(process.env, {
          QODIQA_PG_DATABASE: DB, QODIQA_AUDIT_LOG: path.join(TMP, 'audit.log'), QODIQA_PRQ_JOURNAL_DIR: path.join(TMP, 'prq'),
          TENANT_STORE_PATH: path.join(TMP, 'tenants.json'),
        });
        delete process.env.QODIQA_DEPLOYMENT_MODE;
        if (MODE === 'distributed') process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed'; else delete process.env.QODIQA_AUDIT_ORDERING_MODE;
        if (process.env.QODIQA_PG_TEST_USER) {
          Object.assign(process.env, { QODIQA_PG_USER: process.env.QODIQA_PG_TEST_USER, QODIQA_PG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD });
        }
        jest.resetModules();
        pgPool = require('../../src/infra/postgres/pool');
        pgPool.initialize(); await pgPool.runMigrations(); await pgPool.shutdown();
        _restoreEnv('QODIQA_PG_USER', orig.QODIQA_PG_USER); _restoreEnv('QODIQA_PG_PASSWORD', orig.QODIQA_PG_PASSWORD);
        pgPool.initialize();
        admin = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD });
        auditLog = require('../../src/core/audit/audit-log');
        chainStore = require('../../src/core/evidence/chainStore');
        pgAudit = require('../../src/infra/postgres/pg-audit-backend');
      }, 120_000);

      afterAll(async () => {
        if (auditLog && auditLog.drainPendingWrites) await auditLog.drainPendingWrites().catch(() => {});
        await new Promise(r => setTimeout(r, 500));
        if (admin) await admin.end().catch(() => {});
        if (pgPool) await pgPool.shutdown().catch(() => {});
        try { await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch (err) {
          // eslint-disable-next-line no-console
          console.warn(`[policyIdBound.integration] failed to drop ${DB}: ${err.message}`);
        }
        try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* test-owned temp */ }
      }, 30_000);

      const sleep = (ms) => new Promise(r => setTimeout(r, ms));
      const fieldsFor = (policyIdLength, decision = 'ALLOW') => {
        const id = crypto.randomUUID();
        return {
          artifactId: id, requestId: id, inputHash: crypto.createHash('sha256').update(id).digest('hex'), decision, outputHash: require('../../src/core/audit/entryBuilder').EMPTY_OUTPUT_HASH, /* v7 (R-5): synthetic, delivers nothing */ signature: 's',
          requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: decision === 'ALLOW', nonce: `n-${id}`,
          tenantId: 't136', publicKeyId: 't136:key_v1', provider: 'local', model: 'm', stage: 'PROVIDER_EXECUTION',
          policyDecision: { policyId: 'p'.repeat(policyIdLength), policyVersion: 1, policyRuleHash: decision === 'BLOCK' ? 'd'.repeat(64) : null,
            engineVersion: 'h136', evaluatedAt: new Date().toISOString(), evaluationPath: [] },
        };
      };
      const state = async () => (await admin.query(`SELECT (SELECT count(*)::int FROM audit_chain) ac, (SELECT count(*)::int FROM evidence_chain_records) ev,
        (SELECT last_value FROM evidence_chain_records_id_seq)::int seq, (SELECT is_called FROM evidence_chain_records_id_seq) called,
        (SELECT count(*)::int FROM persistence_recovery_queue) prq`)).rows[0];
      async function waitEvidence(artifactId) {
        for (let t = 0; t < 8000; t += 25) {
          const r = (await admin.query('SELECT evidence_id, policy_id FROM evidence_chain_records WHERE artifact_id = $1', [artifactId])).rows[0];
          if (r) return r; await sleep(25);
        }
        return null;
      }

      test(`PB-00 ${MODE}: pooled role is non-BYPASSRLS qodiqa_app; ordering mode as configured`, async () => {
        expect(auditLog.ORDERING_MODE).toBe(MODE);
        const who = await pgPool.query('SELECT current_user AS u, r.rolbypassrls AS bypass FROM pg_roles r WHERE r.rolname = current_user');
        expect(who.rows[0]).toEqual({ u: 'qodiqa_app', bypass: false });
      });

      test.each([['ALLOW'], ['BLOCK']])(`PB-01 ${MODE}: %s with a ${EVIDENCE_POLICY_ID_MAX}-character policyId commits audit + evidence (unchanged, VALID)`, async (decision) => {
        const f = fieldsFor(EVIDENCE_POLICY_ID_MAX, decision);
        await auditLog.append(f);
        const ev = await waitEvidence(f.artifactId);
        expect(ev.policy_id).toBe(f.policyDecision.policyId); // stored exactly, not transformed
        expect((await chainStore.verifyEvidence(ev.evidence_id, { verifiedBy: 'h136' })).result).toBe('VALID');
      });

      test(`PB-02 ${MODE}: a 64-character policyId (store maximum) is unchanged`, async () => {
        const f = fieldsFor(64);
        await auditLog.append(f);
        expect((await waitEvidence(f.artifactId)).policy_id).toBe(f.policyDecision.policyId);
      });

      test.each([[257, 'ALLOW'], [257, 'BLOCK'], [300, 'ALLOW'], [300, 'BLOCK']])(
        `PB-03 ${MODE}: a %i-character policyId (%s) is rejected before commit — no audit row, no evidence, no id, no recovery item`,
        async (len, decision) => {
          await sleep(300);
          const before = await state();
          const f = fieldsFor(len, decision);
          await expect(auditLog.append(f)).rejects.toThrow(/^invalid_policyDecision/);
          await sleep(MODE === 'distributed' ? 400 : 1200);
          const after = await state();
          expect(after).toEqual(before);
          expect((await admin.query('SELECT count(*)::int n FROM audit_chain WHERE artifact_id = $1', [f.artifactId])).rows[0].n).toBe(0);
          expect((await admin.query('SELECT count(*)::int n FROM evidence_chain_records WHERE artifact_id = $1', [f.artifactId])).rows[0].n).toBe(0);
        });

      test(`PB-04 ${MODE}: appendMandatory does not retry the rejection and writes nothing`, async () => {
        await sleep(300);
        const before = await state();
        await expect(auditLog.appendMandatory(fieldsFor(300), { stage: 'ALLOW' })).rejects.toThrow(/^invalid_policyDecision/);
        await sleep(MODE === 'distributed' ? 400 : 1200);
        expect(await state()).toEqual(before);
      });

      test(`PB-05 ${MODE}: after the rejections the next append chains normally and the audit chain verifies`, async () => {
        const f = fieldsFor(64);
        await auditLog.append(f);
        expect(await waitEvidence(f.artifactId)).not.toBeNull();
        await sleep(MODE === 'distributed' ? 200 : 1200);
        const pgChain = await pgAudit.loadChainFromPg();
        const d = auditLog.verifyAuditChainDetailed(pgChain);
        expect(d.valid).toBe(true);
        const n = (await admin.query('SELECT count(*)::int n FROM evidence_chain_records')).rows[0].n;
        const r = await chainStore.verifyChainRange({ startId: 1, endId: n, limit: 10_000, verifiedBy: 'h136' });
        expect(r).toEqual(expect.objectContaining({ valid: true, complete: true, checkedCount: n, warnings: [] }));
      });
    });
  }
});
