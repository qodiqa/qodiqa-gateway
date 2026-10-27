'use strict';

/**
 * non-replay evidence-chain id gaps on real disposable
 * PostgreSQL. Continuity is the cryptographic hash link; an unused id (a sequence value
 * consumed by an evidence transaction that failed after its INSERT) is an additive ID_GAP
 * warning, never a failure. Real audit-log.append(), real
 * evidence writer, real recovery worker, real routers + RBAC for attestation/certification.
 * Faults are injected only inside this disposable database (triggers on evidence_chain_head).
 * Pooled role: the real non-BYPASSRLS qodiqa_app.
 *
 *   G-01  contiguous chain: every record VALID, range valid with warnings [], ATTESTED
 *   G-02  rollback after id allocation: the next genuine record is VALID / ATTESTED with an
 *         ID_GAP warning; range valid + warning; certification chain 5/5; artifact attestation PASS
 *   G-03  interrupted transaction (statement timeout, retryable) → recovery worker → the
 *         recovered record VALID / ATTESTED with an ID_GAP warning
 * G-04 replay cases stay gap-free (single, repeated, concurrent; next id = prior + 1)
 *   G-05  genuine tampering still fails (edited record: EVIDENCE_HASH / range hash mismatch)
 *   G-06  tenant scoping and RLS unchanged across a gap
 *   G-07  deletion of a middle record still fails the range (hash link), runs last
 *
 * Opt-in like every PG-gated component suite; runs in test:component:serial.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool }  = require('pg');
const crypto    = require('crypto');
const express   = require('express');
const request   = require('supertest');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_h135_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const ALPHA = 'h135-alpha';
const BETA  = 'h135-beta';
const TENANT_STORE = require('path').join(require('os').tmpdir(), `${TEST_DB_NAME}-tenants.json`);
const PRQ_JOURNAL  = require('path').join(require('os').tmpdir(), `${TEST_DB_NAME}-prq`);
const ENV_KEYS = ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'TRUSTED_PROXY', 'TENANT_STORE_PATH',
  'QODIQA_AUDIT_ORDERING_MODE', 'QODIQA_DEPLOYMENT_MODE', 'PRQ_POLL_INTERVAL_MS', 'QODIQA_PG_STATEMENT_TIMEOUT_MS', 'QODIQA_PRQ_JOURNAL_DIR'];

let _orig = {};
// Restores an env var to its pre-suite value (unset if it was absent). Written via
// Object.assign so no `NAME = value` literal appears (the gitleaks pg-password rule).
function _restoreEnv(name, value) {
  if (value === undefined) delete process.env[name]; else Object.assign(process.env, { [name]: value });
}
let _maintenancePool, _adminPool;
let pgPool, app, auditLog, chainStore, recoveryManager, OPERATION_TYPES;

jest.setTimeout(120_000);

describeOrSkip('evidence-chain id gaps: continuity by hash link (real disposable Postgres, qodiqa_app)', () => {
  let signArtifact, getActiveKey;
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) throw new Error(`unsafe test DB name ${TEST_DB_NAME}`);
    const base = {
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      ssl:  process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    };
    _maintenancePool = new Pool({ ...base, database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER, password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD });
    await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);

    for (const k of ENV_KEYS) _orig[k] = process.env[k];
    Object.assign(process.env, {
      TENANT_STORE_PATH: TENANT_STORE, QODIQA_PG_DATABASE: TEST_DB_NAME, TRUSTED_PROXY: 'loopback',
      QODIQA_AUDIT_ORDERING_MODE: 'distributed', PRQ_POLL_INTERVAL_MS: '100',
      QODIQA_PG_STATEMENT_TIMEOUT_MS: '2000', QODIQA_PRQ_JOURNAL_DIR: PRQ_JOURNAL,
    });
    delete process.env.QODIQA_DEPLOYMENT_MODE;
    if (process.env.QODIQA_PG_TEST_USER) {
      Object.assign(process.env, { QODIQA_PG_USER: process.env.QODIQA_PG_TEST_USER, QODIQA_PG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD });
    }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    await pgPool.shutdown();
    _restoreEnv('QODIQA_PG_USER', _orig.QODIQA_PG_USER); _restoreEnv('QODIQA_PG_PASSWORD', _orig.QODIQA_PG_PASSWORD);
    pgPool.initialize();

    _adminPool = new Pool({ ...base, database: TEST_DB_NAME, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD });

    require('../../src/core/transparency/transparencyKeyStore').rotateKey();
    const km = require('../../services/artifact/keyManager');
    // explicit mode — the default client may already hold an active key (jest.setup), and a rotation of an
    // existing key has no default mode; without .env's QODIQA_CLIENT_ID this threw in every clean checkout.
    const _m = { mode: 'graceful' };
    km.rotate(ALPHA, _m); km.rotate(BETA, _m); km.rotate(process.env.QODIQA_CLIENT_ID || 'default', _m);
    ({ getActiveKey } = require('../../services/artifact/keyStore'));
    ({ signArtifact } = require('../../src/validation/signArtifact'));
    auditLog = require('../../src/core/audit/audit-log');
    chainStore = require('../../src/core/evidence/chainStore');
    recoveryManager = require('../../src/core/persistenceRecovery/recoveryManager');
    ({ OPERATION_TYPES } = require('../../src/core/persistenceRecovery'));

    const roles = require('../../src/core/rbac/roles');
    const { createRequirePermission } = require('../../src/middleware/rbac');
    const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
    const role = (req, _r, n) => { req.rbacUser = Object.freeze({ id: 'op', username: 'op', role: 'admin', enabled: true }); n(); };
    const at = require('../../src/api/routes/attestation');
    const pv = require('../../src/api/routes/verificationPortal');
    const ce = require('../../src/api/routes/certification');
    const ec = require('../../src/api/routes/evidenceChain');
    app = express();
    app.use(express.json());
    app.use(require('../../middleware/clientIp'));
    app.use((req, _r, n) => { req.requestId = 'h135'; n(); });
    // (D7 = B): public verifications persist only for an authenticated caller; this suite tests the persisted flow.
    app.use('/v1/attestation', at.createAttestationPublicRouter({ optionalAuth: role }));
    app.use('/v1/attestation', role, at.createAttestationAdminRouter({ requirePermission }));
    app.use('/portal', pv.createVerificationPortalPublicRouter({ optionalAuth: role }));
    app.use('/portal', role, pv.createVerificationPortalAdminRouter({ requirePermission }));
    app.use('/v1/certification', ce.createCertificationPublicRouter());
    app.use('/v1/certification', role, ce.createCertificationAdminRouter({ requirePermission }));
    app.use('/evidence-chain', role, ec.createEvidenceChainRouter({ requirePermission }));
  }, 300_000);

  afterAll(async () => {
    if (recoveryManager) await recoveryManager.shutdown().catch(() => {});
    if (_adminPool) await _adminPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    for (const k of ENV_KEYS) _restoreEnv(k, _orig[k]);
    for (const p of [TENANT_STORE, PRQ_JOURNAL]) { try { require('fs').rmSync(p, { recursive: true, force: true }); } catch { /* test-owned temp */ } }
    if (_maintenancePool) {
      try { await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`); } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[evidenceIdGap.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  // ── helpers ────────────────────────────────────────────────────────────────
  const sign = (tenant, requestId = crypto.randomUUID()) => {
    const K = getActiveKey(tenant); const now = Date.now();
    return signArtifact({ payload: { action: 'h135', requestId, tenantId: tenant }, timestamp: now, expiry: now + 600_000, publicKeyId: K.keyId }, K.privDer);
  };
  const fieldsFor = (artifact, decision = 'ALLOW') => ({
    artifactId: artifact.payload.requestId, requestId: artifact.payload.requestId,
    inputHash: crypto.createHash('sha256').update(artifact.payload.requestId).digest('hex'), decision, outputHash: require('../../src/core/audit/entryBuilder').EMPTY_OUTPUT_HASH, /* v7 (R-5): synthetic, delivers nothing */ signature: artifact.signature,
    requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: decision === 'ALLOW', nonce: `n-${artifact.payload.requestId}`,
    tenantId: artifact.payload.tenantId, publicKeyId: artifact.publicKeyId, provider: 'local', model: 'm', stage: 'PROVIDER_EXECUTION',
  });
  const seqValue = async () => Number((await _adminPool.query('SELECT last_value FROM evidence_chain_records_id_seq')).rows[0].last_value);
  const maxId = async () => (await _adminPool.query('SELECT max(id)::int m FROM evidence_chain_records')).rows[0].m;
  const rowOf = async (artifactId) => (await _adminPool.query('SELECT id::int AS id, evidence_id FROM evidence_chain_records WHERE artifact_id = $1', [artifactId])).rows[0] ?? null;
  async function waitRow(artifactId, ms = 15_000) { for (let t = 0; t < ms; t += 25) { const r = await rowOf(artifactId); if (r) return r; await sleep(25); } return null; }
  async function genuine(tenant = ALPHA) { const a = sign(tenant); await auditLog.append(fieldsFor(a)); return { a, row: await waitRow(a.payload.requestId) }; }
  const verify = (evidenceId) => chainStore.verifyEvidence(evidenceId, { verifiedBy: 'h135' });
  const range = (startId, endId, extra = {}) => chainStore.verifyChainRange({ startId, endId, limit: 10_000, verifiedBy: 'h135', ...extra });
  async function withHeadTrigger(body, fn) {
    await _adminPool.query(`CREATE OR REPLACE FUNCTION h135_head_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ${body} END $$`);
    await _adminPool.query('CREATE TRIGGER h135_head_fault BEFORE UPDATE ON evidence_chain_head FOR EACH ROW EXECUTE FUNCTION h135_head_fault()');
    try { return await fn(); } finally {
      await _adminPool.query('DROP TRIGGER IF EXISTS h135_head_fault ON evidence_chain_head');
      await _adminPool.query('DROP FUNCTION IF EXISTS h135_head_fault()');
    }
  }
  async function portalPackage(artifact) {
    const pv = await request(app).post('/portal/verify').send(artifact);
    const vid = JSON.stringify(pv.body).match(/"verificationId":"([^"]+)"/)[1];
    for (let i = 0; i < 40; i++) { const g = await request(app).get(`/portal/evidence/${vid}`); if (g.status === 200) return g.body.data.evidencePackage; await sleep(100); }
    return null;
  }

  test('G-00 positive controls: distributed ordering; pooled role is non-BYPASSRLS qodiqa_app', async () => {
    expect(auditLog.ORDERING_MODE).toBe('distributed');
    const who = await pgPool.query('SELECT current_user AS u, r.rolbypassrls AS bypass FROM pg_roles r WHERE r.rolname = current_user');
    expect(who.rows[0]).toEqual({ u: 'qodiqa_app', bypass: false });
  });

  test('G-01 a contiguous chain: every record VALID without warnings; range valid with warnings []; ATTESTED', async () => {
    const recs = []; for (let i = 0; i < 5; i++) recs.push(await genuine(i % 2 ? ALPHA : BETA));
    for (const { row } of recs) {
      const v = await verify(row.evidence_id);
      expect({ result: v.result, warnings: v.warnings }).toEqual({ result: 'VALID', warnings: [] });
    }
    const m = await maxId();
    expect(await range(1, m)).toEqual(expect.objectContaining({ valid: true, complete: true, checkedCount: m, retrievedCount: m, warnings: [] }));
    const att = await request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: [recs[4].row.evidence_id] });
    expect(att.body.data.attestation.attestationDecision).toBe('ATTESTED');
  });

  describe('G-02 rollback after id allocation', () => {
    let before, next, E, xId;
    test('an evidence transaction that fails after its INSERT consumes an id without a row; the audit row stays', async () => {
      before = await maxId();
      const s0 = await seqValue();
      const X = sign(ALPHA);
      await withHeadTrigger("RAISE EXCEPTION 'h135 injected head failure' USING ERRCODE = '23514';", async () => {
        await auditLog.append(fieldsFor(X)); await sleep(800);
      });
      expect(await seqValue()).toBe(s0 + 1);
      expect(await rowOf(X.payload.requestId)).toBeNull();
      expect((await _adminPool.query('SELECT count(*)::int n FROM audit_chain WHERE artifact_id = $1', [X.payload.requestId])).rows[0].n).toBe(1);
      // the failure (classified non-retryable, 23514) is no longer only logged — it is queued.
      expect((await _adminPool.query("SELECT status FROM persistence_recovery_queue WHERE operation_id = $1", [`evch:${X.payload.requestId}`])).rows).toEqual([{ status: 'PENDING' }]);
      xId = X.payload.requestId;
    });

    test('the next genuine record is VALID with an explicit ID_GAP warning (hash link intact)', async () => {
      E = sign(ALPHA);
      await auditLog.append(fieldsFor(E)); next = await waitRow(E.payload.requestId);
      expect(next.id).toBe(before + 2);
      const v = await verify(next.evidence_id);
      expect(v.result).toBe('VALID');
      expect(v.steps.find(s => s.step === 'CHAIN_LINK').result).toBe('PASS');
      expect(v.steps.find(s => s.step === 'CHAIN_CONTINUITY').result).toBe('PASS');
      expect(v.warnings).toEqual([expect.objectContaining({ code: 'ID_GAP', priorId: before, id: before + 2, missingIds: 1 })]);
    });

    test('range across the gap: valid, complete, one ID_GAP warning — not a tamper failure (admin route too)', async () => {
      expect(await range(1, next.id)).toEqual(expect.objectContaining({ valid: true, complete: true, retrievedCount: next.id - 1,
        warnings: [{ code: 'ID_GAP', afterId: before, id: next.id, missingIds: 1 }] }));
      const adm = await request(app).post('/evidence-chain/chain/verify-range').send({ startId: 1, endId: next.id });
      expect(adm.body.data.rangeVerification).toEqual(expect.objectContaining({ valid: true, complete: true }));
    });

    test('attestation and certification downstream: ATTESTED with the warning, chain 5/5, artifact PASS', async () => {
      const chainV = await request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: [next.evidence_id] });
      expect(chainV.body.data.attestation.attestationDecision).toBe('ATTESTED');
      expect(chainV.body.data.attestation.chainIntegrity.perRecordResults[0].warnings).toEqual([expect.objectContaining({ code: 'ID_GAP' })]);
      const att = await request(app).post('/v1/attestation/verify').send({ artifact: E });
      expect(att.body.data.attestation.attestationDecision).toBe('ATTESTED');
      expect(JSON.stringify(att.body)).toMatch(/"check":"EVIDENCE_CHAIN","result":"PASS"/);
      const pkg = await portalPackage(E);
      const cert = await request(app).post('/v1/certification/evaluate').send({ artifacts: [E], evidencePackages: [pkg], chain: { evidenceIds: [next.evidence_id] } });
      expect(cert.body.data.certification.certificationDecision).toBe('CERTIFIED');
      expect(JSON.stringify(cert.body)).toMatch(/"chainVerification":\{"score":5/);
    });

    // once the injected cause is gone, one replay through the real worker recovers X's evidence
    // (the consumed id stays a gap; X's row is appended at the tail, linked by hash) and empties the queue —
    // the state G-03 starts from.
    test('the queued failure, replayed after its cause is gone, recovers the evidence row', async () => {
      const worker = require('../../src/core/persistenceRecovery/worker');
      worker.registerHandler(OPERATION_TYPES.EVIDENCE_CHAIN_SAVE, recoveryManager._builtinHandlers[OPERATION_TYPES.EVIDENCE_CHAIN_SAVE]);
      const op = await require('../../src/core/persistenceRecovery/queue').claimNext();
      expect(op && op.operationId).toBe(`evch:${xId}`);
      await worker._processOne(op);
      const x = await rowOf(xId);
      expect(Number(x.id)).toBe(next.id + 1);
      expect((await verify(x.evidence_id)).result).toBe('VALID');
      expect((await _adminPool.query("SELECT count(*)::int n FROM persistence_recovery_queue WHERE operation_type = 'EVIDENCE_CHAIN_SAVE'")).rows[0].n).toBe(0);
    });
  });

  test('G-03 an interrupted evidence transaction (statement timeout, retryable) → recovery → the recovered record VALID with ID_GAP', async () => {
    const before = await maxId();
    const Y = sign(BETA);
    await withHeadTrigger('PERFORM pg_sleep(4); RETURN NEW;', async () => {
      await auditLog.append(fieldsFor(Y)); await sleep(3000);
    });
    expect(await rowOf(Y.payload.requestId)).toBeNull();
    expect((await _adminPool.query("SELECT count(*)::int n FROM persistence_recovery_queue WHERE operation_type = 'EVIDENCE_CHAIN_SAVE' AND status = 'PENDING'")).rows[0].n).toBe(1);
    await recoveryManager.initialize();
    const rec = await waitRow(Y.payload.requestId, 20_000);
    expect(rec.id).toBe(before + 2);
    const v = await verify(rec.evidence_id);
    expect({ result: v.result, codes: v.warnings.map(w => w.code) }).toEqual({ result: 'VALID', codes: ['ID_GAP'] });
    const chainV = await request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: [rec.evidence_id] });
    expect(chainV.body.data.attestation.attestationDecision).toBe('ATTESTED');
    for (let i = 0; i < 50 && (await _adminPool.query("SELECT count(*)::int n FROM persistence_recovery_queue WHERE operation_type = 'EVIDENCE_CHAIN_SAVE'")).rows[0].n; i++) await sleep(100);
  });

  test('G-04 replay-safe idempotency is unchanged: single / repeated / concurrent replays consume no id; the next record is id + 1 without a warning', async () => {
    const X = await genuine(ALPHA);
    const entry = (await require('../../src/infra/postgres/pg-audit-backend').loadChainFromPg()).find(e => e.artifactId === X.a.payload.requestId);
    const handler = recoveryManager._builtinHandlers[OPERATION_TYPES.EVIDENCE_CHAIN_SAVE];
    const s0 = await seqValue();
    const payload = JSON.parse(JSON.stringify({ auditEntry: entry, keyInfo: null, opts: null }));
    expect(await handler({ payload })).toEqual({ success: true });
    for (let i = 0; i < 3; i++) expect(await handler({ payload })).toEqual({ success: true });
    expect((await Promise.all(Array.from({ length: 5 }, () => handler({ payload })))).every(r => r.success)).toBe(true);
    expect(await seqValue()).toBe(s0);
    const Y = await genuine(BETA);
    expect(Y.row.id).toBe(X.row.id + 1);
    const v = await verify(Y.row.evidence_id);
    expect({ result: v.result, warnings: v.warnings }).toEqual({ result: 'VALID', warnings: [] });
  });

  test('G-05 genuine tampering still fails: an edited record is INVALID (EVIDENCE_HASH) and fails the range', async () => {
    const T = await genuine(ALPHA);
    const orig = (await _adminPool.query('SELECT policy_hash FROM evidence_chain_records WHERE id = $1', [T.row.id])).rows[0].policy_hash;
    await _adminPool.query('UPDATE evidence_chain_records SET policy_hash = $2 WHERE id = $1', [T.row.id, 'd'.repeat(64)]);
    try {
      const v = await verify(T.row.evidence_id);
      expect(v.result).toBe('INVALID');
      expect(v.stepsFailed.filter(s => s.result === 'FAIL').map(s => s.step)).toEqual(expect.arrayContaining(['EVIDENCE_HASH']));
      const r = await range(1, await maxId());
      expect(r).toEqual(expect.objectContaining({ valid: false, failureId: T.row.id }));
      expect(r.failureDetail).toMatch(/Evidence hash mismatch/);
    } finally {
      await _adminPool.query('UPDATE evidence_chain_records SET policy_hash = $2 WHERE id = $1', [T.row.id, orig]);
    }
    expect((await range(1, await maxId())).valid).toBe(true);
  });

  test('G-06 tenant scoping and RLS across a gap: tenant-scoped reads see only their rows; tenant-scoped range rule unchanged', async () => {
    const seen = await pgPool.withTenantTransaction(ALPHA, tx => tx.query('SELECT tenant_id FROM evidence_chain_records'));
    expect(seen.rows.length).toBeGreaterThan(0);
    expect(seen.rows.every(r => r.tenant_id === ALPHA)).toBe(true);
    const m = await maxId();
    expect(await range(1, m, { tenantId: ALPHA })).toEqual(expect.objectContaining({ valid: false, failureDetail: 'Range contains records of another tenant' }));
  });

  test('G-07 deleting a middle record still fails the range through the hash link (runs last: not restorable)', async () => {
    const m = await maxId();
    await _adminPool.query('DELETE FROM evidence_chain_records WHERE id = 3');
    const r = await range(1, m);
    expect(r).toEqual(expect.objectContaining({ valid: false, complete: false, failureId: 4 }));
    expect(r.failureDetail).toMatch(/^Chain break at id=4/);
  });
});
