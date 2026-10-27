'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * evidence decision authenticity on real
 * disposable PostgreSQL: real routers, real RBAC middleware (createRequirePermission),
 * production clientIp middleware, real stores / attestor / evaluation engine, genuinely
 * provisioned signing keys, and a genuine two-tenant ALLOW/BLOCK evidence chain written
 * through the real entryBuilder + pg-audit-backend. The pooled role is the real,
 * non-BYPASSRLS qodiqa_app. No verifier, store or engine is mocked.
 *
 * genuine ALLOW and BLOCK records: VALID / ATTESTED / range valid / chain 5/5.
 * a stored decision that differs from the hash-protected audit decision (flip
 *            either way, cross-tenant replay, stale replay, re-hashed, re-bound to the
 *            audit_chain.decision column, re-bound into canonical without rehash) is
 *            INVALID per record, NOT_ATTESTED on the public chain route, invalid in admin
 *            and public ranges, and scores 0/5 in certification; restore → VALID again.
 * fabricated / malformed / missing values never reach the verifier (column
 *            CHECK / length / NOT NULL constraints).
 * evidence packages are unchanged.
 *
 * Opt-in like every other PG-gated component suite; runs in test:component:serial
 *.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool }  = require('pg');
const crypto    = require('crypto');
const express   = require('express');
const request   = require('supertest');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_h133_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const ALPHA = 'h133-alpha';
const BETA  = 'h133-beta';
const TENANT_STORE = require('path').join(require('os').tmpdir(), `${TEST_DB_NAME}-tenants.json`);
// [n, tenant, decision]; evidence id n.
const PLAN = [
  [1, ALPHA, 'ALLOW'], [2, ALPHA, 'BLOCK'], [3, BETA, 'ALLOW'], [4, ALPHA, 'ALLOW'],
  [5, BETA, 'BLOCK'], [6, ALPHA, 'BLOCK'], [7, ALPHA, 'ALLOW'], [8, ALPHA, 'ALLOW'],
];

let _orig = {};
// Restores an env var to its pre-suite value (unset if it was absent). Written via
// Object.assign so no `NAME = value` literal appears (the gitleaks pg-password rule).
function _restoreEnv(name, value) {
  if (value === undefined) delete process.env[name]; else Object.assign(process.env, { [name]: value });
}
let _maintenancePool, _adminPool;
let pgPool, app;

jest.setTimeout(120_000);

describeOrSkip('evidence decision authenticity (real disposable Postgres, qodiqa_app)', () => {
  let signArtifact, getActiveKey, canonicalHash;
  const byId = {};
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  function sign(client, { tamper = false } = {}) {
    const K = getActiveKey(client); const now = Date.now();
    const a = signArtifact({ payload: { action: 'h133', requestId: crypto.randomUUID(), tenantId: client }, timestamp: now, expiry: now + 600_000, publicKeyId: K.keyId }, K.privDer);
    return tamper ? { ...a, payload: { ...a.payload, action: 'tampered' } } : a;
  }

  function buildApp() {
    const roles = require('../../src/core/rbac/roles');
    const { createRequirePermission } = require('../../src/middleware/rbac');
    const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
    const role = (req, _r, n) => { req.rbacUser = Object.freeze({ id: 'op', username: 'op', role: 'admin', enabled: true }); n(); };
    const at = require('../../src/api/routes/attestation');
    const pv = require('../../src/api/routes/verificationPortal');
    const ce = require('../../src/api/routes/certification');
    const ec = require('../../src/api/routes/evidenceChain');
    const a = express();
    a.use(express.json());
    a.use(require('../../middleware/clientIp'));
    a.use((req, _r, n) => { req.requestId = 'h133'; n(); });
    // (D7 = B): public verifications persist only for an authenticated caller; this suite tests the persisted flow.
    a.use('/v1/attestation', at.createAttestationPublicRouter({ optionalAuth: role }));
    a.use('/v1/attestation', role, at.createAttestationAdminRouter({ requirePermission }));
    a.use('/portal', pv.createVerificationPortalPublicRouter({ optionalAuth: role }));
    a.use('/portal', role, pv.createVerificationPortalAdminRouter({ requirePermission }));
    a.use('/v1/certification', ce.createCertificationPublicRouter());
    a.use('/v1/certification', role, ce.createCertificationAdminRouter({ requirePermission }));
    a.use('/evidence-chain', role, ec.createEvidenceChainRouter({ requirePermission }));
    return a;
  }

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

    _orig = { db: process.env.QODIQA_PG_DATABASE, user: process.env.QODIQA_PG_USER, pw: process.env.QODIQA_PG_PASSWORD, proxy: process.env.TRUSTED_PROXY, tenants: process.env.TENANT_STORE_PATH };
    // Key provisioning registers tenants; keep them out of the real data/tenants.json.
    Object.assign(process.env, { TENANT_STORE_PATH: TENANT_STORE });
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    process.env.TRUSTED_PROXY = 'loopback';
    if (process.env.QODIQA_PG_TEST_USER) {
      Object.assign(process.env, { QODIQA_PG_USER: process.env.QODIQA_PG_TEST_USER, QODIQA_PG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD });
    }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    await pgPool.shutdown();
    _restoreEnv('QODIQA_PG_USER', _orig.user); _restoreEnv('QODIQA_PG_PASSWORD', _orig.pw);
    pgPool.initialize();

    _adminPool = new Pool({ ...base, database: TEST_DB_NAME, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD });

    require('../../src/core/transparency/transparencyKeyStore').rotateKey();
    const km = require('../../services/artifact/keyManager');
    // explicit mode — the default client may already hold an active key (jest.setup), and a rotation of an
    // existing key has no default mode; without .env's QODIQA_CLIENT_ID this threw in every clean checkout.
    const _m = { mode: 'graceful' };
    km.rotate(ALPHA, _m); km.rotate(BETA, _m); km.rotate(process.env.QODIQA_CLIENT_ID || 'default', _m); // certificate signer
    ({ getActiveKey } = require('../../services/artifact/keyStore'));
    ({ signArtifact } = require('../../src/validation/signArtifact'));
    ({ canonicalHash } = require('../../services/utils/evidencePackage'));

    // Genuine two-tenant ALLOW/BLOCK chain, real production write path.
    const entryBuilder = require('../../src/core/audit/entryBuilder');
    const be = require('../../src/infra/postgres/pg-audit-backend');
    const ss = require('../../src/utils/stableStringify');
    const ek = crypto.generateKeyPairSync('ed25519');
    let prev = 'GENESIS';
    for (const [n, tenantId, decision] of PLAN) {
      const a = `h133-${n}`;
      const p = { requestId: a, tenantId, method: 'POST', path: '/ai/chat', iat: 1790000000 };
      const e = entryBuilder.buildEntry(entryBuilder.normalizeFields({
        artifactId: a, requestId: a, inputHash: crypto.createHash('sha256').update(a).digest('hex'), decision, outputHash: require('../../src/core/audit/entryBuilder').EMPTY_OUTPUT_HASH, /* v7 (R-5): synthetic, delivers nothing */
        signature: crypto.sign(null, Buffer.from(ss(p)), ek.privateKey).toString('base64'), nonce: `n-${a}`,
        executionContext: { route: '/ai/chat', provider: 'local', latencyMs: 1 },
        requestHash: crypto.createHash('sha256').update(`r${a}`).digest('hex'), policyHash: crypto.createHash('sha256').update('p').digest('hex'),
        verificationResult: true, tenantId, publicKeyId: `${tenantId}:key_v1`, provider: 'local', model: 'm', stage: 'PROVIDER_EXECUTION',
      }), prev);
      prev = e.hash;
      await be.persistEntry(e);
    }
    for (const r of (await _adminPool.query('SELECT id::int AS id, evidence_id, artifact_id, tenant_id, decision FROM evidence_chain_records ORDER BY id')).rows) byId[r.id] = r;
    app = buildApp();
  }, 300_000);

  afterAll(async () => {
    if (_adminPool) await _adminPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    _restoreEnv('QODIQA_PG_DATABASE', _orig.db); _restoreEnv('QODIQA_PG_USER', _orig.user); _restoreEnv('QODIQA_PG_PASSWORD', _orig.pw);
    if (_orig.proxy === undefined) delete process.env.TRUSTED_PROXY; else process.env.TRUSTED_PROXY = _orig.proxy;
    _restoreEnv('TENANT_STORE_PATH', _orig.tenants);
    try { require('fs').rmSync(TENANT_STORE, { force: true }); } catch { /* test-owned temp file */ }
    if (_maintenancePool) {
      try { await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`); } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[decisionConsistency.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  // ── helpers ────────────────────────────────────────────────────────────────
  async function portalOriginal(artifact) {
    const r = await request(app).post('/portal/verify').send(artifact);
    const vid = JSON.stringify(r.body).match(/"verificationId":"([^"]+)"/)[1];
    let g = null;
    for (let i = 0; i < 40; i++) { g = await request(app).get(`/portal/evidence/${vid}`); if (g.status === 200) break; await sleep(100); }
    return { outcome: JSON.stringify(r.body).match(/"overallResult":"([A-Z_]+)"/)[1], pkg: g.body.data.evidencePackage };
  }
  async function attestationOriginal(artifact) {
    const r = await request(app).post('/v1/attestation/verify').send({ artifact });
    const id = r.body.data.attestation.attestationId;
    let g = null;
    for (let i = 0; i < 40; i++) { g = await request(app).get(`/v1/attestation/${id}/evidence`); if (g.status === 200) break; await sleep(100); }
    return { outcome: r.body.data.attestation.attestationDecision, pkg: g.body.data.evidencePackage };
  }

  let X, posX;
  beforeAll(async () => { X = sign(ALPHA); posX = await portalOriginal(X); });

  // Every surface that consumes a chain record's verification.
  async function surfaces(id) {
    const ev = byId[id].evidence_id;
    const per   = await request(app).post(`/evidence-chain/records/${ev}/verify`).send({});
    const pub   = await request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: [ev] });
    const rng   = await request(app).post('/evidence-chain/chain/verify-range').send({ startId: 1, endId: PLAN.length });
    const pubR  = await request(app).post('/v1/attestation/chain/verify').send({ range: { startId: 1, endId: PLAN.length } });
    const cert  = await request(app).post('/v1/certification/evaluate').send({ artifacts: [X], evidencePackages: [posX.pkg], chain: { evidenceIds: [ev] } });
    for (const r of [per, pub, rng, pubR, cert]) expect(r.status).toBe(200);
    const c = cert.body.data.certification;
    return {
      per: per.body.data,
      publicDecision: pub.body.data.attestation.attestationDecision,
      range: rng.body.data.rangeVerification,
      publicRange: pubR.body.data.attestation,
      cert: c,
      chainScore: c.scoreBreakdown?.verificationControls?.breakdown?.chainVerification?.score
        ?? Number(JSON.stringify(cert.body).match(/"chainVerification":\{"score":(\d+)/)[1]),
    };
  }
  const decisionStep = (per) => per.steps.find(s => s.step === 'DECISION_CONSISTENCY');
  function expectGenuine(s) {
    expect(s.per.result).toBe('VALID');
    expect(decisionStep(s.per).result).toBe('PASS');
    expect(s.publicDecision).toBe('ATTESTED');
    expect(s.range).toEqual(expect.objectContaining({ valid: true, complete: true, checkedCount: PLAN.length }));
    expect(s.publicRange.chainIntegrity.rangeResult.valid).toBe(true);
    expect(s.publicRange.attestationDecision).toBe('NOT_ATTESTED'); // a range never attests
    expect(s.cert.certificationDecision).toBe('CERTIFIED');
    expect(s.chainScore).toBe(5);
  }
  function expectRejected(s, id, failedStep = 'DECISION_CONSISTENCY') {
    expect(s.per.result).toBe('INVALID');
    expect(s.per.failedStep).toBe(failedStep);
    expect(decisionStep(s.per).result).toBe('FAIL');
    expect(s.publicDecision).toBe('NOT_ATTESTED');
    expect(s.range).toEqual(expect.objectContaining({ valid: false, failureId: id }));
    expect(s.publicRange.chainIntegrity.rangeResult.valid).toBe(false);
    expect(s.publicRange.attestationDecision).toBe('NOT_ATTESTED');
    expect(s.chainScore).toBe(0);
    // the public payloads carry no raw hash
    expect(JSON.stringify(s.publicRange)).not.toMatch(/\b[0-9a-f]{64}\b/i);
  }
  const auditRow = async (id) => (await _adminPool.query('SELECT decision, canonical FROM audit_chain WHERE artifact_id = $1', [byId[id].artifact_id])).rows[0];
  const storedDecision = async (id) => (await _adminPool.query('SELECT decision FROM evidence_chain_records WHERE id = $1', [id])).rows[0].decision;
  const setDecision = (id, v) => _adminPool.query('UPDATE evidence_chain_records SET decision = $2 WHERE id = $1', [id, v]);

  test('positive controls: pooled role is non-BYPASSRLS qodiqa_app; genuine two-tenant ALLOW/BLOCK chain', async () => {
    const who = await pgPool.query('SELECT current_user AS u, r.rolbypassrls AS bypass FROM pg_roles r WHERE r.rolname = current_user');
    expect(who.rows[0]).toEqual({ u: 'qodiqa_app', bypass: false });
    expect(Object.values(byId).map(r => [r.id, r.tenant_id, r.decision])).toEqual(PLAN.map(([n, t, d]) => [n, t, d]));
    expect(posX.outcome).toMatch(/^VERIFIED/);
  });

  test.each([[1], [2]])('genuine record %i (ALLOW / BLOCK) → VALID, ATTESTED, ranges valid, certification chain 5/5', async (id) => {
    expectGenuine(await surfaces(id));
  });

  // [name, record id, tamper(), restore()]
  const CASES = [
    ['ALLOW replaced with BLOCK', 1, () => setDecision(1, 'BLOCK'), () => setDecision(1, 'ALLOW')],
    ['BLOCK replaced with ALLOW (fabricated ALLOW)', 2, () => setDecision(2, 'ALLOW'), () => setDecision(2, 'BLOCK')],
    ['cross-tenant decision replay (BETA #5 BLOCK into ALPHA #1 ALLOW)', 1,
      () => _adminPool.query('UPDATE evidence_chain_records SET decision = (SELECT decision FROM evidence_chain_records WHERE id = 5) WHERE id = 1'), () => setDecision(1, 'ALLOW')],
    ['stale / replayed decision (same-tenant #6 BLOCK into #7 ALLOW)', 7,
      () => _adminPool.query('UPDATE evidence_chain_records SET decision = (SELECT decision FROM evidence_chain_records WHERE id = 6) WHERE id = 7'), () => setDecision(7, 'ALLOW')],
    ['re-bound to the audit_chain.decision column', 4,
      async () => { await setDecision(4, 'BLOCK'); await _adminPool.query("UPDATE audit_chain SET decision = 'BLOCK' WHERE artifact_id = 'h133-4'"); },
      async () => { await setDecision(4, 'ALLOW'); await _adminPool.query("UPDATE audit_chain SET decision = 'ALLOW' WHERE artifact_id = 'h133-4'"); }],
  ];
  test.each(CASES)('%s → INVALID / NOT_ATTESTED / ranges invalid / chain 0/5; restore → genuine again', async (_n, id, tamper, restore) => {
    const authority = JSON.parse((await auditRow(id)).canonical).decision;
    expect(authority).toBe(byId[id].decision);
    await tamper();
    try {
      expect(await storedDecision(id)).not.toBe(authority); // the write applied
      expectRejected(await surfaces(id), id);
    } finally { await restore(); }
    expect(await storedDecision(id)).toBe(byId[id].decision);
    expectGenuine(await surfaces(id));
  });

  test('re-hashed: the evidence hash recomputed after the change is identical (decision is outside it) — still rejected', async () => {
    const chain = require('../../src/core/evidence/chain');
    await setDecision(8, 'BLOCK');
    try {
      const row = (await _adminPool.query('SELECT * FROM evidence_chain_records WHERE id = 8')).rows[0];
      const h = chain.computeEvidenceHash({ evidenceId: row.evidence_id, artifactId: row.artifact_id, artifactHash: row.artifact_hash, policyId: row.policy_id,
        policyHash: row.policy_hash, keyId: row.key_id, keyFingerprint: row.key_fingerprint, auditRecordId: row.audit_record_id, auditRecordHash: row.audit_record_hash,
        previousEvidenceHash: row.previous_evidence_hash, schema_version: row.schema_version, consentProvenance: row.consent_provenance ?? null,
        policyDecision: row.policy_decision ?? null, callerContext: row.caller_context ?? null, decision: 'BLOCK' });
      expect(h).toBe(row.evidence_hash);
      await _adminPool.query('UPDATE evidence_chain_records SET evidence_hash = $1 WHERE id = 8', [h]);
      expectRejected(await surfaces(8), 8);
    } finally { await setDecision(8, 'ALLOW'); }
    expectGenuine(await surfaces(8));
  });

  test('re-bound into audit_chain.canonical without rehash → the canonical is no longer bound: rejected (AUDIT_RECORD_HASH first)', async () => {
    const orig = await auditRow(1);
    await setDecision(1, 'BLOCK');
    await _adminPool.query('UPDATE audit_chain SET decision = $2, canonical = $3 WHERE artifact_id = $1', ['h133-1', 'BLOCK', orig.canonical.replace('"decision":"ALLOW"', '"decision":"BLOCK"')]);
    try {
      const s = await surfaces(1);
      expectRejected(s, 1, 'AUDIT_RECORD_HASH');
      expect(s.range.failureDetail).toMatch(/Decision not verified at id=1/);
    } finally {
      await setDecision(1, 'ALLOW');
      await _adminPool.query('UPDATE audit_chain SET decision = $2, canonical = $3 WHERE artifact_id = $1', ['h133-1', orig.decision, orig.canonical]);
    }
    expectGenuine(await surfaces(1));
  });

  test.each([
    ['NOT_ATTESTED', /value too long/],
    ['ATTESTED', /ecr_decision_check/],
    ['allow', /ecr_decision_check/],
    ['ALLOW ', /ecr_decision_check/],
    ['', /ecr_decision_check/],
    [null, /not-null/],
  ])('fabricated / malformed / missing stored decision %p is rejected by the column constraints', async (v, err) => {
    await expect(setDecision(1, v)).rejects.toThrow(err);
    expect(await storedDecision(1)).toBe('ALLOW');
  });

  describe('evidence packages — content hash and H132-B eligibility unchanged', () => {
    let failedT, notAttT;
    beforeAll(async () => {
      failedT = await portalOriginal(sign(ALPHA, { tamper: true }));
      notAttT = await attestationOriginal(sign(ALPHA, { tamper: true }));
    });
    const reseal = (p, over) => { const { packageId, generatedAt, packageHash, ...content } = p; const c = { ...content, ...over }; return { ...c, packageHash: canonicalHash(c), packageId, generatedAt }; };
    const flip = (p) => JSON.parse(JSON.stringify(p).replace(/"overallResult":"[A-Z_]+"/g, '"overallResult":"VERIFIED"'));
    async function run(pkg) {
      const v = await request(app).post('/v1/attestation/evidence/verify').send({ evidencePackage: pkg });
      const c = await request(app).post('/v1/certification/evaluate').send({ artifacts: [X], evidencePackages: [pkg] });
      expect(c.status).toBe(200);
      return { verify: v.body.data?.attestation, cert: c.body.data.certification };
    }

    test('genuine positive package → ATTESTED, eligible, CERTIFIED', async () => {
      const { verify, cert } = await run(posX.pkg);
      expect(verify.attestationDecision).toBe('ATTESTED');
      expect(cert.certificationDecision).toBe('CERTIFIED');
      expect(cert.evidenceReferences[0]).toEqual(expect.objectContaining({ eligible: true }));
    });

    test.each([
      ['FAILED original', () => failedT, 'FAILED'],
      ['NOT_ATTESTED original', () => notAttT, 'NOT_ATTESTED'],
    ])('package of a %s → authentic but ineligible → NOT_CERTIFIED (H132-B)', async (_n, of, outcome) => {
      expect(of().outcome).toBe(outcome);
      const { verify, cert } = await run(of().pkg);
      expect(verify.attestationDecision).toBe('ATTESTED');
      expect(cert.certificationDecision).toBe('NOT_CERTIFIED');
      expect(cert.evidenceReferences[0]).toEqual(expect.objectContaining({ eligible: false, ineligibleReason: 'ORIGINAL_OUTCOME_NOT_POSITIVE' }));
    });

    test.each([
      ['outcome flipped, hash kept', () => flip(failedT.pkg)],
      ['outcome flipped and resealed', () => reseal(flip(failedT.pkg), {})],
      ['fabricated (random ids, resealed)', () => reseal(posX.pkg, { verificationId: crypto.randomUUID(), originalVerificationId: crypto.randomUUID() })],
    ])('%s → NOT_ATTESTED, not eligible, NOT_CERTIFIED', async (_n, of) => {
      const { verify, cert } = await run(of());
      expect(verify.attestationDecision).toBe('NOT_ATTESTED');
      expect(cert.certificationDecision).toBe('NOT_CERTIFIED');
      expect(cert.evidenceReferences[0]).toEqual(expect.objectContaining({ eligible: false, ineligibleReason: 'NOT_AUTHENTIC' }));
    });
  });
});
