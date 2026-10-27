'use strict';

/**
 * distributed-mode evidence ledger on real disposable
 * PostgreSQL. QODIQA_AUDIT_ORDERING_MODE=distributed; real audit-log.append() →
 * distributedOrdering (committed audit transaction) → post-commit, NOT awaited,
 * pg-audit-backend.recordEvidenceForEntry() → chainStore writer; real persistence
 * recovery worker for EVIDENCE_CHAIN_SAVE; real routers + RBAC for attestation and
 * certification. Pooled role: the real non-BYPASSRLS qodiqa_app. Nothing verified is mocked.
 *
 *   A1-P1  normal append → audit row + evidence row, bound, VALID
 *   A1-P2  BLOCK → evidence decision BLOCK, DECISION_CONSISTENCY PASS
 *   A1-P3  concurrent, two tenants → every audit row has exactly one evidence row, tenant kept
 *   A1-P4  duplicate / replay rejected; no extra evidence row
 *   A1-P5  retryable evidence failure → audit committed, append not blocked, EVIDENCE_CHAIN_SAVE
 *          PENDING → recovery worker → VALID; evidence order may differ from audit order (pinned)
 *   A1-P6  replaying the same recovery payload repeatedly → exactly one row, head unchanged
 *   A1-P7  non-retryable evidence failure → audit kept, no evidence, nothing queued, degraded APIs
 *   A1-P8  crash window (audit committed, evidence step never ran) → reconstructed from the
 *          persisted audit row by the existing recovery handler → VALID
 *   A1-P9  RLS: tenant-scoped reads see only their tenant's rows (normal and recovered)
 * A1-P10 attestation / certification semantics on distributed records
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
const TEST_DB_NAME = `qodiqa_h134_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const ALPHA = 'h134-alpha';
const BETA  = 'h134-beta';
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
let pgPool, app, auditLog, pgAudit, chainStore, recoveryManager, distributedOrdering, OPERATION_TYPES;

jest.setTimeout(120_000);

describeOrSkip('distributed-mode evidence ledger, option A1 (real disposable Postgres, qodiqa_app)', () => {
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
    pgAudit = require('../../src/infra/postgres/pg-audit-backend');
    chainStore = require('../../src/core/evidence/chainStore');
    distributedOrdering = require('../../src/core/audit/distributedOrdering');
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
    app.use((req, _r, n) => { req.requestId = 'h134'; n(); });
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
        console.warn(`[distributedEvidenceLedger.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  // ── helpers ────────────────────────────────────────────────────────────────
  const sign = (tenant, requestId = crypto.randomUUID()) => {
    const K = getActiveKey(tenant); const now = Date.now();
    return signArtifact({ payload: { action: 'h134', requestId, tenantId: tenant }, timestamp: now, expiry: now + 600_000, publicKeyId: K.keyId }, K.privDer);
  };
  const fieldsFor = (artifact, decision = 'ALLOW', extra = {}) => ({
    artifactId: artifact.payload.requestId, requestId: artifact.payload.requestId,
    inputHash: crypto.createHash('sha256').update(artifact.payload.requestId).digest('hex'), decision, outputHash: require('../../src/core/audit/entryBuilder').EMPTY_OUTPUT_HASH, /* v7 (R-5): synthetic, delivers nothing */ signature: artifact.signature,
    requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: decision === 'ALLOW', nonce: `n-${artifact.payload.requestId}`,
    tenantId: artifact.payload.tenantId, publicKeyId: artifact.publicKeyId, provider: 'local', model: 'm', stage: 'PROVIDER_EXECUTION', ...extra,
  });
  const evidenceOf = async (artifactId) => (await _adminPool.query('SELECT * FROM evidence_chain_records WHERE artifact_id = $1', [artifactId])).rows;
  const auditOf = async (artifactId) => (await _adminPool.query('SELECT seq::int AS seq, hash, tenant_id, decision FROM audit_chain WHERE artifact_id = $1', [artifactId])).rows[0];
  async function waitForEvidence(artifactId, ms = 10_000) {
    for (let t = 0; t < ms; t += 25) { const r = await evidenceOf(artifactId); if (r.length) return r; await sleep(25); }
    return [];
  }
  const queued = async () => (await _adminPool.query("SELECT operation_id, status, payload FROM persistence_recovery_queue WHERE operation_type = 'EVIDENCE_CHAIN_SAVE'")).rows;
  async function expectBoundValid(artifactId, decision) {
    const ev = await evidenceOf(artifactId); const au = await auditOf(artifactId);
    expect(ev).toHaveLength(1);
    expect(ev[0].audit_record_id).toBe(au.hash);
    expect(ev[0].tenant_id).toBe(au.tenant_id);
    expect(ev[0].decision).toBe(decision);
    const v = await chainStore.verifyEvidence(ev[0].evidence_id, { verifiedBy: 'h134' });
    expect({ result: v.result, stepsFailed: v.stepsFailed.filter(s => s.result === 'FAIL') }).toEqual({ result: 'VALID', stepsFailed: [] });
    expect(v.steps.find(s => s.step === 'DECISION_CONSISTENCY').result).toBe('PASS');
    return ev[0];
  }

  test('A1-P0 positive controls: distributed ordering mode; pooled role is non-BYPASSRLS qodiqa_app', async () => {
    expect(auditLog.ORDERING_MODE).toBe('distributed');
    const who = await pgPool.query('SELECT current_user AS u, r.rolbypassrls AS bypass FROM pg_roles r WHERE r.rolname = current_user');
    expect(who.rows[0]).toEqual({ u: 'qodiqa_app', bypass: false });
  });

  test('A1-P1 a normal distributed append writes the audit row and, after commit, one bound VALID evidence row, served by the API', async () => {
    const a = sign(ALPHA);
    const entry = await auditLog.append(fieldsFor(a));
    expect((await auditOf(a.payload.requestId)).hash).toBe(entry.hash);
    expect(await waitForEvidence(a.payload.requestId)).toHaveLength(1);
    await expectBoundValid(a.payload.requestId, 'ALLOW');
    const g = await request(app).get(`/evidence-chain/records/by-artifact/${a.payload.requestId}`);
    expect(g.status).toBe(200);
  });

  test('A1-P2 a BLOCK decision is persisted and bound (DECISION_CONSISTENCY PASS)', async () => {
    const a = sign(BETA);
    await auditLog.append(fieldsFor(a, 'BLOCK'));
    await waitForEvidence(a.payload.requestId);
    await expectBoundValid(a.payload.requestId, 'BLOCK');
  });

  test('A1-P3 concurrent appends over two tenants: one evidence row per audit row, no duplicates, tenants kept, chain continuous', async () => {
    const as = Array.from({ length: 30 }, (_, i) => sign(i % 2 ? ALPHA : BETA));
    const settled = await Promise.allSettled(as.map((a, i) => auditLog.append(fieldsFor(a, i % 4 === 0 ? 'BLOCK' : 'ALLOW'))));
    expect(settled.every(s => s.status === 'fulfilled')).toBe(true);
    for (const a of as) expect(await waitForEvidence(a.payload.requestId)).toHaveLength(1);
    const ids = as.map(a => a.payload.requestId);
    const joined = (await _adminPool.query(`SELECT a.tenant_id AS at, e.tenant_id AS et, a.hash, e.audit_record_id, a.decision AS ad, e.decision AS ed
      FROM audit_chain a JOIN evidence_chain_records e ON e.artifact_id = a.artifact_id WHERE a.artifact_id = ANY($1)`, [ids])).rows;
    expect(joined).toHaveLength(30);
    for (const r of joined) { expect(r.et).toBe(r.at); expect(r.audit_record_id).toBe(r.hash); expect(r.ed).toBe(r.ad); }
    const dup = (await _adminPool.query('SELECT count(*)::int n, count(DISTINCT artifact_id)::int d FROM evidence_chain_records')).rows[0];
    expect(dup.n).toBe(dup.d);
    const range = await chainStore.verifyChainRange({ startId: 1, endId: dup.n, limit: 10_000, verifiedBy: 'h134' });
    expect(range).toEqual(expect.objectContaining({ valid: true, complete: true, checkedCount: dup.n }));
  });

  test('A1-P4 duplicate artifact and nonce replay stay rejected; no additional evidence row', async () => {
    const a = sign(ALPHA);
    await auditLog.append(fieldsFor(a)); await waitForEvidence(a.payload.requestId);
    const before = (await _adminPool.query('SELECT count(*)::int n FROM evidence_chain_records')).rows[0].n;
    await expect(auditLog.append({ ...fieldsFor(a), nonce: `n-dup-${crypto.randomUUID()}` })).rejects.toThrow(/already_executed/);
    await expect(auditLog.append({ ...fieldsFor(sign(ALPHA)), nonce: `n-${a.payload.requestId}` })).rejects.toThrow(/replay_detected/);
    await sleep(300);
    expect((await _adminPool.query('SELECT count(*)::int n FROM evidence_chain_records')).rows[0].n).toBe(before);
  });

  describe('A1-P5 / P6 retryable evidence failure → recovery, ordering, idempotent replay', () => {
    let A, B, payload;
    test('A1-P5 audit commits and append() returns without waiting; EVIDENCE_CHAIN_SAVE PENDING; recovery → VALID; evidence order ≠ audit order', async () => {
      const holder = await _adminPool.connect();
      await holder.query('BEGIN'); await holder.query('SELECT 1 FROM evidence_chain_head FOR UPDATE');
      A = sign(ALPHA);
      const t0 = Date.now();
      await auditLog.append(fieldsFor(A));
      expect(Date.now() - t0).toBeLessThan(1500); // below the 2 s statement timeout the evidence write is waiting on
      expect(await auditOf(A.payload.requestId)).toBeDefined();
      let q = [];
      for (let i = 0; i < 100 && !q.length; i++) { q = await queued(); if (!q.length) await sleep(100); }
      await holder.query('ROLLBACK'); holder.release();
      expect(q).toHaveLength(1);
      expect(q[0].status).toBe('PENDING');
      expect(q[0].payload.auditEntry.hash).toBe((await auditOf(A.payload.requestId)).hash);
      payload = q[0].payload;
      expect(await evidenceOf(A.payload.requestId)).toHaveLength(0);

      // B is appended AFTER A (higher audit seq) and gets its evidence first; A's comes from recovery.
      B = sign(BETA);
      await auditLog.append(fieldsFor(B)); await waitForEvidence(B.payload.requestId);
      await recoveryManager.initialize();
      expect(await waitForEvidence(A.payload.requestId, 20_000)).toHaveLength(1);
      const evA = await expectBoundValid(A.payload.requestId, 'ALLOW');
      const evB = (await evidenceOf(B.payload.requestId))[0];
      expect((await auditOf(A.payload.requestId)).seq).toBeLessThan((await auditOf(B.payload.requestId)).seq);
      expect(Number(evA.id)).toBeGreaterThan(Number(evB.id)); // A1: evidence order follows evidence writes, not audit order
      for (let i = 0; i < 50 && (await queued()).length; i++) await sleep(100);
      expect(await queued()).toHaveLength(0);
      const all = (await _adminPool.query('SELECT count(*)::int n FROM evidence_chain_records')).rows[0].n;
      const range = await chainStore.verifyChainRange({ startId: 1, endId: all, limit: 10_000, verifiedBy: 'h134' });
      expect(range).toEqual(expect.objectContaining({ valid: true, checkedCount: all }));
    });

    test('A1-P6 replaying the same recovery payload repeatedly creates no second row and leaves the head unchanged', async () => {
      const head = (await _adminPool.query('SELECT tail_hash, tail_id FROM evidence_chain_head')).rows[0];
      const handler = recoveryManager._builtinHandlers[OPERATION_TYPES.EVIDENCE_CHAIN_SAVE];
      for (let i = 0; i < 3; i++) expect(await handler({ payload })).toEqual({ success: true });
      expect(await evidenceOf(A.payload.requestId)).toHaveLength(1);
      expect((await _adminPool.query('SELECT tail_hash, tail_id FROM evidence_chain_head')).rows[0]).toEqual(head);
    });
  });

  // was "nothing queued" — the defect records (a committed
  // audit entry left with no evidence row and only a log line). The failure is
  // now queued; the worker's one replay fails non-retryably again (the grant is
  // still revoked), so it goes straight to the DLQ: visible and replayable by an
  // operator, never auto-fabricated. The grant is restored only once the
  // operation is in the DLQ, so no later replay can race the assertion below.
  test('A1-P7 non-retryable evidence failure: audit kept, no evidence, failure recorded in the DLQ; APIs report the degraded state', async () => {
    await _adminPool.query('REVOKE INSERT ON evidence_chain_records FROM qodiqa_app');
    const C = sign(ALPHA);
    const mine = async () => (await queued()).filter((r) => r.operation_id === `evch:${C.payload.requestId}`);
    try {
      await auditLog.append(fieldsFor(C));
      for (let i = 0; i < 100 && !((await mine())[0]?.status === 'DLQ'); i++) await sleep(100);
      expect(await auditOf(C.payload.requestId)).toBeDefined();
      expect(await evidenceOf(C.payload.requestId)).toHaveLength(0);
      expect((await mine()).map((r) => r.status)).toEqual(['DLQ']);
    } finally {
      await _adminPool.query('GRANT INSERT ON evidence_chain_records TO qodiqa_app');
    }
    expect((await request(app).get(`/evidence-chain/records/by-artifact/${C.payload.requestId}`)).status).toBe(404);
    const att = await request(app).post('/v1/attestation/verify').send({ artifact: C });
    expect(att.body.data.attestation.attestationDecision).toBe('ATTESTED_WITH_WARNINGS');
    expect(JSON.stringify(att.body)).toMatch(/"check":"EVIDENCE_CHAIN","result":"WARN"/);
    await sleep(500);
    expect(await evidenceOf(C.payload.requestId)).toHaveLength(0); // never fabricated later
  });

  test('A1-P8 crash window: an audit commit whose evidence step never ran is reconstructed from the persisted audit row → VALID, idempotent', async () => {
    const D = sign(BETA);
    await distributedOrdering.appendEntry(fieldsFor(D)); // the committed transaction alone: the state a crash after commit leaves
    await sleep(500);
    expect(await auditOf(D.payload.requestId)).toBeDefined();
    expect(await evidenceOf(D.payload.requestId)).toHaveLength(0);
    const persisted = (await pgAudit.loadChainFromPg()).find(e => e.artifactId === D.payload.requestId);
    const km = require('../../services/artifact/keyManager');
    const handler = recoveryManager._builtinHandlers[OPERATION_TYPES.EVIDENCE_CHAIN_SAVE];
    const op = { payload: { auditEntry: persisted, keyInfo: await km.getVerificationKey(persisted.publicKeyId), opts: null } };
    expect(await handler(op)).toEqual({ success: true });
    expect(await handler(op)).toEqual({ success: true });
    await expectBoundValid(D.payload.requestId, 'ALLOW');
  });

  test('A1-P9 RLS: under a tenant context only that tenant\'s evidence rows are visible (normal and recovered rows)', async () => {
    const rows = (await _adminPool.query('SELECT artifact_id, tenant_id FROM evidence_chain_records')).rows;
    const alpha = rows.filter(r => r.tenant_id === ALPHA).map(r => r.artifact_id);
    const beta  = rows.filter(r => r.tenant_id === BETA).map(r => r.artifact_id);
    expect(alpha.length).toBeGreaterThan(0); expect(beta.length).toBeGreaterThan(0);
    const seen = await pgPool.withTenantTransaction(ALPHA, tx => tx.query('SELECT artifact_id, tenant_id FROM evidence_chain_records'));
    expect(seen.rows.every(r => r.tenant_id === ALPHA)).toBe(true);
    expect(seen.rows.map(r => r.artifact_id).sort()).toEqual([...alpha].sort());
  });

  describe('A1-R gap-free idempotent replay ()', () => {
    const seqValue = async () => Number((await _adminPool.query('SELECT last_value FROM evidence_chain_records_id_seq')).rows[0].last_value);
    const maxId = async () => (await _adminPool.query('SELECT max(id)::int m FROM evidence_chain_records')).rows[0].m;
    const handler = () => recoveryManager._builtinHandlers[OPERATION_TYPES.EVIDENCE_CHAIN_SAVE];
    async function genuine(tenant = ALPHA) {
      const a = sign(tenant); const entry = await auditLog.append(fieldsFor(a));
      const ev = (await waitForEvidence(a.payload.requestId))[0];
      return { a, entry, id: Number(ev.id) };
    }

    test('A1-R1 a single replay consumes no id; the next genuine record gets id + 1 and is VALID', async () => {
      const X = await genuine();
      const s0 = await seqValue();
      expect(await handler()({ payload: { auditEntry: X.entry, keyInfo: null, opts: null } })).toEqual({ success: true });
      expect(await seqValue()).toBe(s0);
      const Y = await genuine(BETA);
      expect(Y.id).toBe(X.id + 1);
      await expectBoundValid(Y.a.payload.requestId, 'ALLOW');
    });

    test('A1-R2 three replays (queue JSON payload) → one row, no id consumed, next genuine record contiguous', async () => {
      const X = await genuine();
      const s0 = await seqValue();
      const payload = JSON.parse(JSON.stringify({ auditEntry: X.entry, keyInfo: null, opts: null }));
      for (let i = 0; i < 3; i++) expect(await handler()({ payload })).toEqual({ success: true });
      expect(await evidenceOf(X.a.payload.requestId)).toHaveLength(1);
      expect(await seqValue()).toBe(s0);
      const Y = await genuine();
      expect(Y.id).toBe(X.id + 1);
      await expectBoundValid(Y.a.payload.requestId, 'ALLOW');
    });

    test('A1-R3 concurrent duplicate replays → one row, no id consumed, head unchanged', async () => {
      const X = await genuine(BETA);
      const s0 = await seqValue();
      const head = (await _adminPool.query('SELECT tail_hash, tail_id FROM evidence_chain_head')).rows[0];
      const payload = { auditEntry: X.entry, keyInfo: null, opts: null };
      const res = await Promise.all(Array.from({ length: 6 }, () => handler()({ payload })));
      expect(res.every(r => r.success === true)).toBe(true);
      expect(await evidenceOf(X.a.payload.requestId)).toHaveLength(1);
      expect(await seqValue()).toBe(s0);
      expect((await _adminPool.query('SELECT tail_hash, tail_id FROM evidence_chain_head')).rows[0]).toEqual(head);
    });

    test('A1-R4 after every replay above, the whole chain is contiguous and every record verifies VALID', async () => {
      const m = await maxId();
      const count = (await _adminPool.query('SELECT count(*)::int n FROM evidence_chain_records')).rows[0].n;
      expect(count).toBe(m); // ids 1..m, no gap
      const range = await chainStore.verifyChainRange({ startId: 1, endId: m, limit: 10_000, verifiedBy: 'h134' });
      expect(range).toEqual(expect.objectContaining({ valid: true, complete: true, checkedCount: m }));
      const all = (await _adminPool.query('SELECT evidence_id FROM evidence_chain_records ORDER BY id')).rows;
      for (const r of all) {
        const v = await chainStore.verifyEvidence(r.evidence_id, { verifiedBy: 'h134' });
        expect({ id: r.evidence_id, result: v.result, failed: v.failedStep }).toEqual({ id: r.evidence_id, result: 'VALID', failed: null });
      }
    });
  });

  test('A1-P10 attestation / certification on a distributed record: PASS / ATTESTED / 5/5; a changed decision is still rejected', async () => {
    const E = sign(ALPHA);
    await auditLog.append(fieldsFor(E)); const ev = (await waitForEvidence(E.payload.requestId))[0];
    const att = await request(app).post('/v1/attestation/verify').send({ artifact: E });
    expect(att.body.data.attestation.attestationDecision).toBe('ATTESTED');
    expect(JSON.stringify(att.body)).toMatch(/"check":"EVIDENCE_CHAIN","result":"PASS"/);
    const chainV = await request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: [ev.evidence_id] });
    expect({ d: chainV.body.data.attestation.attestationDecision, r: chainV.body.data.attestation.chainIntegrity?.perRecordResults?.map(x => [x.result, x.failedStep, x.failureReason]) }).toEqual({ d: "ATTESTED", r: [["VALID", null, null]] });
    const pv = await request(app).post('/portal/verify').send(E);
    const vid = JSON.stringify(pv.body).match(/"verificationId":"([^"]+)"/)[1];
    let pkg = null;
    for (let i = 0; i < 40; i++) { const g = await request(app).get(`/portal/evidence/${vid}`); if (g.status === 200) { pkg = g.body.data.evidencePackage; break; } await sleep(100); }
    const cert = await request(app).post('/v1/certification/evaluate').send({ artifacts: [E], evidencePackages: [pkg], chain: { evidenceIds: [ev.evidence_id] } });
    expect(cert.body.data.certification.certificationDecision).toBe('CERTIFIED');
    expect(JSON.stringify(cert.body)).toMatch(/"chainVerification":\{"score":5/);
    await _adminPool.query("UPDATE evidence_chain_records SET decision = 'BLOCK' WHERE evidence_id = $1", [ev.evidence_id]);
    try {
      const flipped = await request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: [ev.evidence_id] });
      expect(flipped.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
    } finally {
      await _adminPool.query("UPDATE evidence_chain_records SET decision = 'ALLOW' WHERE evidence_id = $1", [ev.evidence_id]);
    }
  });
});
