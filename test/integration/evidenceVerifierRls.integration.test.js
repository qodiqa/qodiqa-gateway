'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * (evidence-verifier RLS) — real-PostgreSQL regression.
 *
 * design decisions: STOP 1 = A (chainStore reads the audit row through
 * migration 048's SECURITY DEFINER qodiqa_audit_chain_fetch_by_artifact_id(),
 * accepted only when its tenant matches the evidence record's), STOP 2 = C
 * (evidence schema_version 4: AUDIT_RECORD_HASH over the persisted audit-record
 * representation; legacy path for schema_version < 4).
 *
 * Before the fix, every genuine tenant-scoped evidence record verified INVALID
 * ("Audit entry not found") under the real non-BYPASSRLS qodiqa_app role, and —
 * with visibility restored — still INVALID at AUDIT_RECORD_HASH.
 *
 * Harness pattern: auditChainCircuitOpenRecovery ACOR-04 /
 * crossTenantAdversarial — disposable database, migrations as the test role,
 * production pool.js re-initialized as QODIQA_PG_USER (qodiqa_app) with a
 * positive control (rolbypassrls = false) so nothing can pass vacuously.
 * Genuine data only: entries from the real entryBuilder carrying a real
 * Ed25519 signature, persisted through the real pg-audit-backend.persistEntry()
 * (which writes audit_chain under tenant context and the evidence record
 * through chainStore). The public route is the real createAttestationPublicRouter()
 * with no mocks on the verifier path. Tamper/restore uses the test role on the
 * disposable database only.
 *
 * Cases (owner brief numbering):
 *   RV-01 genuine tenant-scoped v4 evidence -> VALID
 *   RV-02 no tenant context: plain audit_chain read sees 0 rows, verifier still VALID (not "not found")
 *   RV-03 tampered policy_hash -> detected (value mismatch + EVIDENCE_HASH); restore -> VALID
 *   RV-04 tampered hash-protected provider (in the persisted canonical record) -> detected; restore -> VALID
 *   RV-05 cross-tenant substitution (evidence re-tagged to another tenant) -> audit row rejected, no values leak;
 *         RLS itself unchanged (foreign-tenant / no-context reads still 0)
 *   RV-06 missing audit row -> fail closed ("Audit entry not found")
 *   RV-07 legacy (schema_version 3) rows -> legacy semantics: faithful rebuild PASSES when the entry carried no
 *         non-persisted field; a requestId-bearing entry FAILS closed with the legacy reason (no fabrication)
 *   RV-08 new (schema_version 4) row -> persisted-record semantics, recomputable from the database
 * RV-13 client addresses are internal audit data — public result/record/evidence views withhold them,
 *         RBAC views keep them, V1 package hash unchanged, public verification still ATTESTS
 * RV-14 portal report PDF and attestation export PDF render real PostgreSQL rows (BIGINT timestamps as
 *         strings) without a process-fatal write-after-end; certification PDF unchanged; stored rows unaltered
 *   RV-09 public POST /v1/attestation/chain/verify: per-step results for genuine / tampered / cross-tenant /
 *         legacy / v4 evidence, and no 64-hex value in the public response
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool }  = require('pg');
const crypto    = require('crypto');
const express   = require('express');
const request   = require('supertest');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_h127v_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const ALPHA = 'h127-alpha';
const BETA  = 'h127-beta';

let _originalDatabaseEnv, _originalUserEnv, _originalPasswordEnv;
let _maintenancePool, _adminPool;
let pgPool, pgAuditBackend, entryBuilder, chain, chainStore, stableStringify, app;
const IDS = {};

jest.setTimeout(60_000);

describeOrSkip('evidence verifier under the real qodiqa_app role (real disposable Postgres)', () => {
  const signingKey = crypto.generateKeyPairSync('ed25519');

  // A genuine artifact: real Ed25519 signature over the canonical payload.
  function signedArtifact(tenantId, artifactId) {
    const payload = { requestId: artifactId, tenantId, method: 'POST', path: '/ai/chat', iat: 1790000000 };
    const signature = crypto.sign(null, Buffer.from(stableStringify(payload)), signingKey.privateKey).toString('base64');
    return { payload, signature };
  }

  // audit_chain enforces a unique prev_hash, so fixtures form a real chain.
  let _prevHash = 'GENESIS';
  function genuineEntry(tenantId, artifactId, extra = {}) {
    const art = signedArtifact(tenantId, artifactId);
    return entryBuilder.buildEntry(entryBuilder.normalizeFields({
      artifactId,
      inputHash:          crypto.createHash('sha256').update(`input:${artifactId}`).digest('hex'),
      decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:          art.signature,
      nonce:              `nonce-${artifactId}`,
      executionContext:   { route: '/ai/chat', provider: 'local', latencyMs: 42 },
      requestHash:        crypto.createHash('sha256').update(`req:${artifactId}`).digest('hex'),
      policyHash:         crypto.createHash('sha256').update('policy-set-v1').digest('hex'),
      verificationResult: true,
      tenantId,
      publicKeyId:        `${tenantId}:key_v1`,
      provider:           'local',
      model:              'llama3.2:1b',
      stage:              'PROVIDER_EXECUTION',
      ...extra,
    }), _prevHash);
  }
  function chained(entry) { _prevHash = entry.hash; return entry; }

  async function evidenceIdFor(artifactId) {
    const r = await _adminPool.query('SELECT evidence_id FROM evidence_chain_records WHERE artifact_id = $1', [artifactId]);
    expect(r.rows).toHaveLength(1);
    return r.rows[0].evidence_id;
  }
  const stepOf = (v, name) => v.steps.find(s => s.step === name);

  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) throw new Error(`unsafe test DB name ${TEST_DB_NAME}`);
    _maintenancePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    // Safe: generator-controlled, validated identifier.
    await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER     = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    jest.resetModules();
    pgPool          = require('../../src/infra/postgres/pool');
    pgAuditBackend  = require('../../src/infra/postgres/pg-audit-backend');
    entryBuilder    = require('../../src/core/audit/entryBuilder');
    chain           = require('../../src/core/evidence/chain');
    chainStore      = require('../../src/core/evidence/chainStore');
    stableStringify = require('../../src/utils/stableStringify');

    // Migrations as the test role, then the pooled code as the real app role.
    pgPool.initialize();
    await pgPool.runMigrations();
    await pgPool.shutdown();
    process.env.QODIQA_PG_USER     = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    pgPool.initialize();

    _adminPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_TEST_USER,
      password: process.env.QODIQA_PG_TEST_PASSWORD,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });

    const { createAttestationPublicRouter } = require('../../src/api/routes/attestation');
    // (D7 = B): public verifications persist only for an authenticated caller; this suite tests the persisted flow.
    const optOperator = (req, _res, next) => { req.rbacUser = req.rbacUser || Object.freeze({ id: 'op-1', username: 'op', role: 'admin', enabled: true }); next(); };
    app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'h127v-test'; next(); });
    app.use('/v1/attestation', createAttestationPublicRouter({ optionalAuth: optOperator }));
    // (NF-2): POST /chain/verify moved to the admin router (MANAGE_ATTESTATIONS).
    // Mounted as src/app.js does — after the public router, behind an operator
    // (admin) stand-in and the REAL requirePermission. Its evidence reads now
    // run as qodiqa_reporting, end to end on this real database.
    {
      const roles = require('../../src/core/rbac/roles');
      const { createRequirePermission } = require('../../src/middleware/rbac');
      const { createAttestationAdminRouter } = require('../../src/api/routes/attestation');
      app.use('/v1/attestation', optOperator, createAttestationAdminRouter({
        requirePermission: createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission }),
      }));
    }

    // ── Fixtures, in chain order (legacy history first, then current writes) ──
    // Legacy rows are written through the SAME production path, with
    // buildEvidenceRecord producing exactly what the pre-H127 code produced
    // (schema_version 3, auditRecordHash over the full in-memory entry).
    const realBuild = chain.buildEvidenceRecord;
    const legacySpy = jest.spyOn(chain, 'buildEvidenceRecord').mockImplementation((entry, keyInfo, opts) => {
      const rec = { ...realBuild(entry, keyInfo, opts), schemaVersion: 3, auditRecordHash: chain.computeAuditRecordHash(entry) };
      rec.evidenceHash = chain.computeEvidenceHash(rec);
      return rec;
    });
    const legacyNoReq = chained(genuineEntry(ALPHA, 'h127v-legacy-noreq'));
    await pgAuditBackend.persistEntry(legacyNoReq);
    // v7: requestId is a hashed core field now (recoverable from the persisted canonical); traceId is still never
    // persisted, so it is the field that keeps this legacy record unrecomputable (fail-closed, nothing fabricated).
    const legacyReq   = chained(genuineEntry(ALPHA, 'h127v-legacy-req', { requestId: 'h127v-legacy-req', traceId: 'trace-h127v-legacy-req' }));
    await pgAuditBackend.persistEntry(legacyReq);
    legacySpy.mockRestore();

    const alpha = chained(genuineEntry(ALPHA, 'h127v-alpha-1', { requestId: 'h127v-alpha-1', traceId: 'trace-alpha-1' }));
    await pgAuditBackend.persistEntry(alpha);
    const beta  = chained(genuineEntry(BETA, 'h127v-beta-1', { requestId: 'h127v-beta-1' }));
    await pgAuditBackend.persistEntry(beta);
    // Evidence whose audit row genuinely does not exist (never persisted to audit_chain).
    const orphan = genuineEntry(ALPHA, 'h127v-orphan-1');
    await chainStore._recordEvidenceFromAuditEntryOrThrow(orphan, null, null);

    for (const [k, e] of Object.entries({ legacyNoReq, legacyReq, alpha, beta, orphan })) {
      IDS[k] = { artifactId: e.artifactId, evidenceId: await evidenceIdFor(e.artifactId), entry: e };
    }
  }, 60_000);

  afterAll(async () => {
    if (_adminPool) await _adminPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER     = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[evidenceVerifierRls.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  test('RV-00 positive controls: pooled role is non-BYPASSRLS qodiqa_app; artifacts carry a genuine Ed25519 signature; rows are tenant-scoped', async () => {
    const who = await pgPool.query('SELECT current_user AS u, r.rolbypassrls AS bypass FROM pg_roles r WHERE r.rolname = current_user');
    expect(who.rows[0]).toEqual({ u: 'qodiqa_app', bypass: false });
    const art = signedArtifact(ALPHA, 'h127v-alpha-1');
    expect(crypto.verify(null, Buffer.from(stableStringify(art.payload)), signingKey.publicKey, Buffer.from(IDS.alpha.entry.signature, 'base64'))).toBe(true);
    const rows = await _adminPool.query('SELECT artifact_id, tenant_id FROM audit_chain ORDER BY seq');
    expect(rows.rows).toEqual([
      { artifact_id: 'h127v-legacy-noreq', tenant_id: ALPHA },
      { artifact_id: 'h127v-legacy-req',   tenant_id: ALPHA },
      { artifact_id: 'h127v-alpha-1',      tenant_id: ALPHA },
      { artifact_id: 'h127v-beta-1',       tenant_id: BETA },
    ]);
  });

  test('RV-01 genuine tenant-scoped v4 evidence verifies VALID', async () => {
    const v = await chainStore.verifyEvidence(IDS.alpha.evidenceId);
    expect(v.result).toBe('VALID');
    for (const s of ['ARTIFACT_HASH', 'POLICY_HASH', 'AUDIT_RECORD_HASH', 'EVIDENCE_HASH', 'CHAIN_LINK']) {
      expect(stepOf(v, s).result).toBe('PASS');
    }
  });

  test('RV-02 without any tenant context the plain audit_chain read sees 0 rows, yet the verifier finds the row (never "not found")', async () => {
    const plain = await pgPool.query('SELECT 1 FROM audit_chain WHERE artifact_id = $1', [IDS.alpha.artifactId]);
    expect(plain.rows).toHaveLength(0); // RLS in force for the pooled role — the pre-fix failure condition
    const v = await chainStore.verifyEvidence(IDS.alpha.evidenceId);
    expect(v.result).toBe('VALID');
    expect(JSON.stringify(v.steps)).not.toMatch(/not found/i);
  });

  test('RV-03 tampered policy_hash is detected (value mismatch + EVIDENCE_HASH); restore returns to VALID', async () => {
    const orig = (await _adminPool.query('SELECT policy_hash FROM evidence_chain_records WHERE evidence_id = $1', [IDS.alpha.evidenceId])).rows[0].policy_hash;
    await _adminPool.query('UPDATE evidence_chain_records SET policy_hash = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, 'f'.repeat(64)]);
    try {
      const v = await chainStore.verifyEvidence(IDS.alpha.evidenceId);
      expect(v.result).toBe('INVALID');
      expect(stepOf(v, 'POLICY_HASH').result).toBe('FAIL');
      expect(stepOf(v, 'POLICY_HASH').reason).toMatch(/does not match audit entry policyHash/);
      expect(stepOf(v, 'EVIDENCE_HASH').result).toBe('FAIL');
    } finally {
      await _adminPool.query('UPDATE evidence_chain_records SET policy_hash = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, orig]);
    }
    expect((await chainStore.verifyEvidence(IDS.alpha.evidenceId)).result).toBe('VALID');
  });

  test('RV-04 tampered hash-protected provider in the persisted canonical audit record is detected; restore returns to VALID', async () => {
    const orig = (await _adminPool.query('SELECT canonical FROM audit_chain WHERE artifact_id = $1', [IDS.alpha.artifactId])).rows[0].canonical;
    expect(orig).toContain('"provider":"local"');
    await _adminPool.query('UPDATE audit_chain SET canonical = $2 WHERE artifact_id = $1', [IDS.alpha.artifactId, orig.replace('"provider":"local"', '"provider":"openai"')]);
    try {
      const v = await chainStore.verifyEvidence(IDS.alpha.evidenceId);
      expect(v.result).toBe('INVALID');
      expect(stepOf(v, 'AUDIT_RECORD_HASH').result).toBe('FAIL');
      expect(stepOf(v, 'AUDIT_RECORD_HASH').reason).toMatch(/persisted-record contract/);
    } finally {
      await _adminPool.query('UPDATE audit_chain SET canonical = $2 WHERE artifact_id = $1', [IDS.alpha.artifactId, orig]);
    }
    expect((await chainStore.verifyEvidence(IDS.alpha.evidenceId)).result).toBe('VALID');
  });

  test('RV-05 cross-tenant substitution: an evidence record re-tagged to another tenant cannot use that audit row, and RLS is unchanged', async () => {
    // tenant_id is not part of the evidence hash — the attack surface the tenant check closes.
    await _adminPool.query('UPDATE evidence_chain_records SET tenant_id = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, BETA]);
    let v;
    try {
      v = await chainStore.verifyEvidence(IDS.alpha.evidenceId);
    } finally {
      await _adminPool.query('UPDATE evidence_chain_records SET tenant_id = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, ALPHA]);
    }
    expect(v.result).toBe('INVALID');
    for (const s of ['ARTIFACT_HASH', 'POLICY_HASH', 'AUDIT_RECORD_HASH']) {
      expect(stepOf(v, s).result).toBe('FAIL');
      expect(stepOf(v, s).reason).toMatch(/^Audit entry rejected: audit record tenant does not match/);
    }
    // No value from the other tenant's audit row reaches the result.
    const auditRow = (await _adminPool.query('SELECT input_hash, request_hash, hash FROM audit_chain WHERE artifact_id = $1', [IDS.alpha.artifactId])).rows[0];
    const out = JSON.stringify(v);
    expect(out).not.toContain(auditRow.request_hash);
    expect(out).not.toContain(auditRow.hash);

    // RLS negative controls: the fix added no ambient visibility.
    const foreign = await pgPool.withTenantTransaction(BETA, tx => tx.query('SELECT 1 FROM audit_chain WHERE artifact_id = $1', [IDS.alpha.artifactId]));
    expect(foreign.rows).toHaveLength(0);
    const anyVisible = await pgPool.query('SELECT count(*)::int AS c FROM audit_chain');
    expect(anyVisible.rows[0].c).toBe(0);
    // After restore the genuine record verifies again.
    expect((await chainStore.verifyEvidence(IDS.alpha.evidenceId)).result).toBe('VALID');
  });

  test('RV-06 a genuinely missing audit row fails closed', async () => {
    const v = await chainStore.verifyEvidence(IDS.orphan.evidenceId);
    expect(v.result).toBe('INVALID');
    expect(stepOf(v, 'ARTIFACT_HASH').reason).toBe('Audit entry not found in chain — cannot verify artifact hash');
    expect(stepOf(v, 'AUDIT_RECORD_HASH').result).toBe('FAIL');
  });

  test('RV-07 legacy (schema_version 3) rows are verified under legacy semantics, without fabricating non-persisted fields', async () => {
    const rows = (await _adminPool.query('SELECT artifact_id, schema_version FROM evidence_chain_records WHERE artifact_id = ANY($1) ORDER BY id',
      [[IDS.legacyNoReq.artifactId, IDS.legacyReq.artifactId]])).rows;
    expect(rows.map(r => r.schema_version)).toEqual([3, 3]);

    const noReq = await chainStore.verifyEvidence(IDS.legacyNoReq.evidenceId);
    expect(stepOf(noReq, 'AUDIT_RECORD_HASH').result).toBe('PASS');
    expect(noReq.result).toBe('VALID');

    const withReq = await chainStore.verifyEvidence(IDS.legacyReq.evidenceId);
    expect(stepOf(withReq, 'ARTIFACT_HASH').result).toBe('PASS'); // row visible — not an RLS failure
    expect(stepOf(withReq, 'AUDIT_RECORD_HASH').result).toBe('FAIL');
    expect(stepOf(withReq, 'AUDIT_RECORD_HASH').reason).toMatch(/legacy contract.*requestId\/traceId\/organizationId/);
    expect(withReq.result).toBe('INVALID');
  });

  test('RV-08 new (schema_version 4) rows use the persisted-record contract, recomputable from the database alone', async () => {
    const ev = (await _adminPool.query('SELECT schema_version, audit_record_hash FROM evidence_chain_records WHERE evidence_id = $1', [IDS.beta.evidenceId])).rows[0];
    expect(ev.schema_version).toBe(4);
    const row = (await _adminPool.query('SELECT hash, canonical, high_res_time, tenant_id, nonce, execution_context FROM audit_chain WHERE artifact_id = $1', [IDS.beta.artifactId])).rows[0];
    const fromDb = chain.computePersistedAuditRecordHash({
      hash: row.hash, canonical: row.canonical, highResTime: row.high_res_time,
      tenantId: row.tenant_id, nonce: row.nonce, executionContext: row.execution_context,
    });
    expect(fromDb).toBe(ev.audit_record_hash);
    expect(fromDb).not.toBe(chain.computeAuditRecordHash(IDS.beta.entry)); // not the legacy formula
    expect((await chainStore.verifyEvidence(IDS.beta.evidenceId)).result).toBe('VALID');
  });

  describe('RV-09 public POST /v1/attestation/chain/verify (real router, no verifier mocks)', () => {
    const perRecord = (res) => res.body.data.attestation.chainIntegrity.perRecordResults[0];
    const stepMap = (r) => Object.fromEntries(r.steps.map(s => [s.step, s.result]));
    const post = (evidenceId) => request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: [evidenceId] });

    test('genuine v4 evidence -> ATTESTED, per-step PASS', async () => {
      const res = await post(IDS.alpha.evidenceId);
      expect(res.status).toBe(200);
      expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
      expect(stepMap(perRecord(res))).toMatchObject({ ARTIFACT_HASH: 'PASS', POLICY_HASH: 'PASS', AUDIT_RECORD_HASH: 'PASS', EVIDENCE_HASH: 'PASS' });
      expect(JSON.stringify(res.body)).not.toMatch(/\b[0-9a-f]{64}\b/i);
    });

    test('tampered evidence -> NOT_ATTESTED, failing steps named, no hash value in the public body', async () => {
      const orig = (await _adminPool.query('SELECT policy_hash FROM evidence_chain_records WHERE evidence_id = $1', [IDS.alpha.evidenceId])).rows[0].policy_hash;
      await _adminPool.query('UPDATE evidence_chain_records SET policy_hash = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, 'e'.repeat(64)]);
      let res;
      try { res = await post(IDS.alpha.evidenceId); } finally {
        await _adminPool.query('UPDATE evidence_chain_records SET policy_hash = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, orig]);
      }
      expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
      expect(stepMap(perRecord(res))).toMatchObject({ POLICY_HASH: 'FAIL', EVIDENCE_HASH: 'FAIL', AUDIT_RECORD_HASH: 'PASS' });
      expect(JSON.stringify(res.body)).not.toMatch(/\b[0-9a-f]{64}\b/i);
      expect(JSON.stringify(res.body)).not.toContain(orig);
    });

    test('cross-tenant substitution -> NOT_ATTESTED with the rejection reason, no audit value exposed', async () => {
      await _adminPool.query('UPDATE evidence_chain_records SET tenant_id = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, BETA]);
      let res;
      try { res = await post(IDS.alpha.evidenceId); } finally {
        await _adminPool.query('UPDATE evidence_chain_records SET tenant_id = $2 WHERE evidence_id = $1', [IDS.alpha.evidenceId, ALPHA]);
      }
      expect(res.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
      expect(stepMap(perRecord(res))).toMatchObject({ ARTIFACT_HASH: 'FAIL', POLICY_HASH: 'FAIL', AUDIT_RECORD_HASH: 'FAIL' });
      expect(perRecord(res).failureReason).toMatch(/^Audit entry rejected/);
      expect(JSON.stringify(res.body)).not.toMatch(/\b[0-9a-f]{64}\b/i);
    });

    test('legacy evidence -> legacy semantics on the public route (rebuildable row ATTESTED; requestId-bearing row NOT_ATTESTED, fail-closed)', async () => {
      const a = await post(IDS.legacyNoReq.evidenceId);
      expect(a.body.data.attestation.attestationDecision).toBe('ATTESTED');
      expect(stepMap(perRecord(a)).AUDIT_RECORD_HASH).toBe('PASS');
      const b = await post(IDS.legacyReq.evidenceId);
      expect(b.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
      expect(stepMap(perRecord(b))).toMatchObject({ ARTIFACT_HASH: 'PASS', AUDIT_RECORD_HASH: 'FAIL' });
    });

    test('new schema-version evidence of a second tenant -> ATTESTED', async () => {
      const res = await post(IDS.beta.evidenceId);
      expect(res.body.data.attestation.attestationDecision).toBe('ATTESTED');
      expect(stepMap(perRecord(res))).toMatchObject({ AUDIT_RECORD_HASH: 'PASS', EVIDENCE_HASH: 'PASS' });
    });
  });

  // ── decision integrity: ATTESTED iff every requested record is VALID ──
  // (design decision, Option A). every NOT_ATTESTED expectation marked
  // "was ATTESTED" below returned ATTESTED through this same public route.
  describe('RV-10 public chain-attestation decision integrity (real router, qodiqa_app)', () => {
    const UNKNOWN   = '00000000-0000-4000-8000-000000000000';
    const MALFORMED = 'not-a-uuid';
    const post = (body) => request(app).post('/v1/attestation/chain/verify').send(body);
    const decisionOf = (res) => res.body.data.attestation.attestationDecision;
    const resultsOf = (res) => res.body.data.attestation.chainIntegrity.perRecordResults.map(r => r.result);
    let betaValues;

    beforeAll(async () => {
      const r = (await _adminPool.query('SELECT artifact_hash, evidence_hash FROM evidence_chain_records WHERE evidence_id = $1', [IDS.beta.evidenceId])).rows[0];
      const a = (await _adminPool.query('SELECT hash, request_hash FROM audit_chain WHERE artifact_id = $1', [IDS.beta.artifactId])).rows[0];
      betaValues = [r.artifact_hash, r.evidence_hash, a.hash, a.request_hash, IDS.beta.artifactId];
    });

    // Every negative response: no 64-hex value, and no value of a tenant not requested.
    function expectNoLeak(res) {
      const raw = JSON.stringify(res.body);
      expect(raw).not.toMatch(/\b[0-9a-f]{64}\b/i);
      for (const v of betaValues) expect(raw).not.toContain(v);
    }

    test('positive: multiple genuine VALID records -> ATTESTED', async () => {
      const res = await post({ evidenceIds: [IDS.alpha.evidenceId, IDS.legacyNoReq.evidenceId] });
      expect(resultsOf(res)).toEqual(['VALID', 'VALID']);
      expect(decisionOf(res)).toBe('ATTESTED');
    });

    test.each([
      ['unknown evidence id (verifier ERROR) — was ATTESTED', () => [UNKNOWN], ['ERROR']],
      ['missing audit row for the evidence (INVALID)', () => [IDS.orphan.evidenceId], ['INVALID']],
      ['explicit INVALID (legacy, unrecomputable)', () => [IDS.legacyReq.evidenceId], ['INVALID']],
      ['VALID + INVALID', () => [IDS.alpha.evidenceId, IDS.legacyReq.evidenceId], ['VALID', 'INVALID']],
      ['VALID + ERROR (unknown) — was ATTESTED', () => [IDS.alpha.evidenceId, UNKNOWN], ['VALID', 'ERROR']],
      ['VALID + missing audit row', () => [IDS.alpha.evidenceId, IDS.orphan.evidenceId], ['VALID', 'INVALID']],
    ])('negative: %s -> NOT_ATTESTED, no leak', async (_n, ids, expected) => {
      const res = await post({ evidenceIds: ids() });
      expect(res.status).toBe(200);
      expect(resultsOf(res)).toEqual(expected);
      expect(decisionOf(res)).toBe('NOT_ATTESTED');
      expect(res.body.data.attestation.chainIntegrity.valid).toBe(false);
      expectNoLeak(res);
    });

    // H132-D: a malformed (non-UUID) id is now rejected by the public schema
    // before any lookup (400) instead of reaching PostgreSQL (thrown -> ERROR).
    test('negative: malformed id -> 400 at the route, no attestation, no leak', async () => {
      const res = await post({ evidenceIds: [MALFORMED] });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_PARAM');
      expect(JSON.stringify(res.body)).not.toMatch(/syntax for type|invalid input/);
    });

    test('negative: PARTIAL (injected — verifyEvidenceRecord never emits it) and VALID + PARTIAL -> NOT_ATTESTED — was ATTESTED', async () => {
      const real = chainStore.verifyEvidence;
      const PARTIAL_ID = '00000000-0000-4000-8000-0000000000aa'; // H132-D: ids are UUIDs at the route
      const spy = jest.spyOn(chainStore, 'verifyEvidence').mockImplementation((id, o) => (id === PARTIAL_ID
        ? Promise.resolve({ result: 'PARTIAL', failedStep: null, failureReason: null, stepsPassed: [], stepsFailed: [], steps: [], durationMs: 0 })
        : real(id, o)));
      try {
        const a = await post({ evidenceIds: [PARTIAL_ID] });
        expect(resultsOf(a)).toEqual(['PARTIAL']);
        expect(decisionOf(a)).toBe('NOT_ATTESTED');
        const b = await post({ evidenceIds: [IDS.alpha.evidenceId, PARTIAL_ID] });
        expect(resultsOf(b)).toEqual(['VALID', 'PARTIAL']);
        expect(decisionOf(b)).toBe('NOT_ATTESTED');
        expectNoLeak(a); expectNoLeak(b);
      } finally {
        spy.mockRestore();
      }
    });

    test('zero requested records never attest: empty ids rejected; empty range and ids + empty range NOT_ATTESTED — were ATTESTED', async () => {
      const none = await post({ evidenceIds: [] });
      expect(none.status).toBe(400);
      const emptyRange = await post({ range: { startId: 900000, endId: 900010 } });
      expect(emptyRange.body.data.attestation.chainIntegrity.rangeResult.checkedCount).toBe(0);
      expect(decisionOf(emptyRange)).toBe('NOT_ATTESTED');
      const idsPlusEmpty = await post({ evidenceIds: [IDS.alpha.evidenceId], range: { startId: 900000, endId: 900010 } });
      expect(resultsOf(idsPlusEmpty)).toEqual(['VALID']);
      expect(decisionOf(idsPlusEmpty)).toBe('NOT_ATTESTED');
      expectNoLeak(emptyRange); expectNoLeak(idsPlusEmpty);
    });

    test('stored attestation: GET of a new unknown-id attestation returns the stored NOT_ATTESTED', async () => {
      const res = await post({ evidenceIds: [UNKNOWN] });
      const id = res.body.data.attestation.attestationId;
      let stored = null;
      for (let i = 0; i < 20 && !stored; i++) { // recordAttestation is fire-and-forget
        const g = await request(app).get(`/v1/attestation/${id}`);
        if (g.status === 200) stored = g.body.data.attestation;
        else await new Promise(r => setTimeout(r, 100));
      }
      expect(stored).not.toBeNull();
      expect(stored.attestation_decision ?? stored.attestationDecision).toBe('NOT_ATTESTED');
    });
  });

  // ── H129-B — range verification projection (design decision, Option A) ─────
  // getChain() now projects schema_version / consent_provenance / policy_decision /
  // caller_context, so validateChainContinuity() recomputes each record under its
  // own schema's field set. Before H129-B every range containing a schema >= 2
  // record failed at its first record ("Evidence hash mismatch at id=<first>").
  // validateChainContinuity() requires a range to start at the chain's genesis
  // record (previous_evidence_hash IS NULL) — pre-existing design, unchanged —
  // so ranges here start at the first evidence id.
  describe('RV-11 H129-B range verification over real persisted records (qodiqa_app)', () => {
    let ids; // evidence_chain_records ids in chain order
    // range verification now also authenticates every record's
    // decision against its bound audit row, so the orphan fixture (evidence whose audit
    // row never existed, written last) can no longer be part of a VALID range. "Genuine"
    // ranges below therefore end at the last audit-backed record; R1 pins the orphan case.
    let last;
    const byArtifact = {};
    beforeAll(async () => {
      const rows = (await _adminPool.query('SELECT id, artifact_id, schema_version FROM evidence_chain_records ORDER BY id')).rows;
      ids = rows.map(r => Number(r.id));
      for (const r of rows) byArtifact[r.artifact_id] = { id: Number(r.id), schema: r.schema_version };
      expect(byArtifact['h127v-orphan-1'].id).toBe(ids[ids.length - 1]);
      last = ids[ids.length - 2];
    });
    const range = (startId, endId) => chainStore.verifyChainRange({ startId, endId, limit: 1000, verifiedBy: 'rv-11' });
    const postRange = (r) => request(app).post('/v1/attestation/chain/verify').send({ range: r });

    test('R1/R4 a genuine range from genesis (legacy v3 + current v4 records) verifies valid over every record', async () => {
      expect(Object.values(byArtifact).map(x => x.schema).sort()).toEqual([3, 3, 4, 4, 4]);
      const r = await range(ids[0], last);
      expect(r).toEqual(expect.objectContaining({ valid: true, checkedCount: ids.length - 1, failureId: null }));
      // the orphan's decision cannot be authenticated — the range including it is not valid, at that record.
      const withOrphan = await range(ids[0], ids[ids.length - 1]);
      expect(withOrphan).toEqual(expect.objectContaining({ valid: false, complete: true, checkedCount: ids.length, failureId: ids[ids.length - 1] }));
      expect(withOrphan.failureDetail).toMatch(/Decision not verified/);
      const r4 = await range(ids[0], ids[3]);
      expect(r4).toEqual(expect.objectContaining({ valid: true, checkedCount: 4 }));
    });

    test('R2/R5 tampering a hash-protected v4-only field (caller_context) fails at exactly that record; restore -> valid', async () => {
      const t = byArtifact['h127v-beta-1'];
      const orig = (await _adminPool.query('SELECT caller_context FROM evidence_chain_records WHERE id = $1', [t.id])).rows[0].caller_context;
      await _adminPool.query("UPDATE evidence_chain_records SET caller_context = '{\"callerId\":\"forged\"}'::jsonb WHERE id = $1", [t.id]);
      try {
        const r = await range(ids[0], last);
        expect(r.valid).toBe(false);
        expect(r.failureId).toBe(t.id);                     // the earlier (valid) records passed
        expect(r.checkedCount).toBe(ids.indexOf(t.id));
        expect(r.failureDetail).toMatch(/Evidence hash mismatch/);
        const pub = await postRange({ startId: ids[0], endId: last });
        expect(pub.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
        expect(pub.body.data.attestation.chainIntegrity.rangeResult.valid).toBe(false);
      } finally {
        await _adminPool.query('UPDATE evidence_chain_records SET caller_context = $2 WHERE id = $1', [t.id, orig === null ? null : JSON.stringify(orig)]);
      }
      expect((await range(ids[0], last)).valid).toBe(true);
    });

    test('R3 chain continuity is still enforced: a broken previous_evidence_hash link fails at that record', async () => {
      const t = byArtifact['h127v-alpha-1'];
      const orig = (await _adminPool.query('SELECT previous_evidence_hash FROM evidence_chain_records WHERE id = $1', [t.id])).rows[0].previous_evidence_hash;
      await _adminPool.query('UPDATE evidence_chain_records SET previous_evidence_hash = $2 WHERE id = $1', [t.id, 'b'.repeat(64)]);
      try {
        const r = await range(ids[0], last);
        expect(r.valid).toBe(false);
        expect(r.failureId).toBe(t.id);
        expect(r.failureDetail).toMatch(/Chain break/);
      } finally {
        await _adminPool.query('UPDATE evidence_chain_records SET previous_evidence_hash = $2 WHERE id = $1', [t.id, orig]);
      }
      expect((await range(ids[0], last)).valid).toBe(true);
    });

    test('R6 an empty range is not ATTESTED (continuity of nothing is not evidence)', async () => {
      const r = await range(900000, 900010);
      expect(r.checkedCount).toBe(0);
      const pub = await postRange({ startId: 900000, endId: 900010 });
      expect(pub.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
    });

    test('R7 unknown range bounds / unknown evidence ids are not ATTESTED; a valid range alone does not attest', async () => {
      const unknownIds = await request(app).post('/v1/attestation/chain/verify').send({ evidenceIds: ['00000000-0000-4000-8000-00000000abcd'] });
      expect(unknownIds.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
      const validRange = await postRange({ startId: ids[0], endId: last });
      expect(validRange.body.data.attestation.chainIntegrity.rangeResult).toEqual(expect.objectContaining({ valid: true, checkedCount: ids.length - 1 }));
      expect(validRange.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
    });

    test('R8 cross-tenant isolation: the public range result carries no record content; RLS on evidence rows is unchanged', async () => {
      const pub = await postRange({ startId: ids[0], endId: ids[ids.length - 1] });
      const raw = JSON.stringify(pub.body);
      const beta = (await _adminPool.query('SELECT evidence_id, artifact_hash, evidence_hash, caller_context FROM evidence_chain_records WHERE artifact_id = $1', ['h127v-beta-1'])).rows[0];
      for (const v of [beta.evidence_id, beta.artifact_hash, beta.evidence_hash, 'h127v-beta-1', BETA]) expect(raw).not.toContain(v);
      expect(raw).not.toMatch(/\b[0-9a-f]{64}\b/i);
      // plain table read under another tenant's context still cannot see beta's row
      const visible = await pgPool.withTenantTransaction(ALPHA, tx => tx.query('SELECT 1 FROM evidence_chain_records WHERE artifact_id = $1', ['h127v-beta-1']));
      expect(visible.rows).toHaveLength(0);
    });
  });

  // ── H129-A historical records: flagged at retrieval, never rewritten ───────
  // No such record exists in any local database;
  // this disposable fixture is persisted through the REAL attestationStore exactly
  // as the pre-H129-A verifier did (no complianceResult.contentBound).
  describe('RV-12 H129-A historical package attestation — retrieval flag on real PG', () => {
    test('a pre-binding ATTESTED package attestation is flagged on public GET; the stored row is unchanged', async () => {
      const attestationStore = require('../../src/core/attestation/attestationStore');
      const id = crypto.randomUUID();
      await attestationStore.recordAttestation({
        attestationId: id, attestationType: 'EVIDENCE_VERIFICATION', version: '1.0', artifactFingerprint: null,
        attestationDecision: 'ATTESTED',
        verificationResult: { packageType: 'QODIQA::PORTAL_EVIDENCE::V1', verificationId: null, overallResult: null },
        cryptographicResult: { computedHash: 'c'.repeat(64), providedHash: 'c'.repeat(64), match: true, algorithm: 'SHA-256/stableStringify' },
        complianceResult: { originalFound: false, originalResult: null, verificationId: null },
        chainResult: {}, checksPerformed: [], warnings: [], failedCheck: null, failureReason: null,
        transparencyId: null, evidencePackageHash: 'c'.repeat(64), requestedBy: 'external', requestIp: null, durationMs: 1,
      });
      const before = (await _adminPool.query('SELECT row_to_json(a)::text j FROM attestations a WHERE attestation_id = $1', [id])).rows[0].j;
      const res = await request(app).get(`/v1/attestation/${id}`);
      expect(res.status).toBe(200);
      expect(res.body.data.attestation.attestation_decision).toBe('ATTESTED');
      expect(res.body.data.attestation.integrityAdvisory.code).toBe('EVIDENCE_PACKAGE_NOT_BOUND_TO_ORIGINAL');
      const after = (await _adminPool.query('SELECT row_to_json(a)::text j FROM attestations a WHERE attestation_id = $1', [id])).rows[0].j;
      expect(after).toBe(before);
    });

    test('a package attestation written by the bound verifier is not flagged', async () => {
      // well-formed (64-hex) but wrong hash — evidence_package_hash is a 64-char column
      const res = await request(app).post('/v1/attestation/evidence/verify').send({ evidencePackage: { packageType: 'QODIQA::PORTAL_EVIDENCE::V1', verificationId: crypto.randomUUID(), packageHash: 'd'.repeat(64) } });
      const id = res.body.data.attestation.attestationId;
      let stored = null;
      for (let i = 0; i < 20 && !stored; i++) {
        const g = await request(app).get(`/v1/attestation/${id}`);
        if (g.status === 200) stored = g.body.data.attestation; else await new Promise(r => setTimeout(r, 100));
      }
      expect(stored.compliance_result).toHaveProperty('contentBound');
      expect(stored.integrityAdvisory).toBeUndefined();
    });
  });
  // ──: client addresses are INTERNAL
  // AUDIT DATA. Real stores, real clientIp middleware (TRUSTED_PROXY=loopback, a
  // supported preset), real routers composed as in src/app.js (authentication
  // stood in by a role header; REAL rbac.createRequirePermission). Addresses are
  // RFC 5737 documentation addresses only.
  describe('RV-13 address disclosure boundary on real PG (qodiqa_app)', () => {
    const CLIENT = '203.0.113.10';
    const VERIFIER = '203.0.113.20';
    const AUDITOR = { 'x-test-operator-role': 'auditor' };
    const UNRELATED = { Authorization: 'Bearer sk_h130_unrelated_tenant_credential' };
    let app13, portal, portalStore, certificationStore, canonicalHash, _savedTrustedProxy;
    const ids = {};

    async function pollRow(sql, params) {
      for (let i = 0; i < 40; i++) {
        const r = await _adminPool.query(sql, params);
        if (r.rows.length) return r.rows[0];
        await new Promise(res => setTimeout(res, 100));
      }
      return null;
    }

    beforeAll(async () => {
      _savedTrustedProxy = process.env.TRUSTED_PROXY;
      process.env.TRUSTED_PROXY = 'loopback';
      const roles = require('../../src/core/rbac/roles');
      const { createRequirePermission } = require('../../src/middleware/rbac');
      const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
      const gate = (req, res, next) => {
        const role = req.headers['x-test-operator-role'];
        if (!role) return res.status(401).json({ error: { code: 'UNAUTHORIZED' } });
        req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role, enabled: true });
        return next();
      };
      const vp = require('../../src/api/routes/verificationPortal');
      const at = require('../../src/api/routes/attestation');
      const ce = require('../../src/api/routes/certification');
      portal             = require('../../src/core/verification/portal');
      portalStore        = require('../../src/core/verification/portalStore');
      certificationStore = require('../../src/core/certification/certificationStore');
      ({ canonicalHash } = require('../../services/utils/evidencePackage'));

      app13 = express();
      app13.use(express.json());
      app13.use(require('../../middleware/clientIp'));
      app13.use((req, _res, next) => { req.requestId = 'h130-rv13'; next(); });
      // (D7 = B): public verifications persist only for an authenticated caller; this suite tests the persisted flow.
      const optOperator = (req, _res, next) => { req.rbacUser = req.rbacUser || Object.freeze({ id: 'op-1', username: 'op', role: 'admin', enabled: true }); next(); };
      const pPub = vp.createVerificationPortalPublicRouter({ optionalAuth: optOperator });
      const pAdm = vp.createVerificationPortalAdminRouter({ requirePermission });
      for (const base of ['/portal', '/v1/portal']) { app13.use(base, pPub); app13.use(base, gate, pAdm); }
      app13.use('/v1/attestation', at.createAttestationPublicRouter({ optionalAuth: optOperator }));
      app13.use('/v1/attestation', gate, at.createAttestationAdminRouter({ requirePermission }));
      app13.use('/v1/certification', ce.createCertificationPublicRouter());
      app13.use('/v1/certification', gate, ce.createCertificationAdminRouter({ requirePermission }));

      ids.vid = crypto.randomUUID();
      await portalStore.recordVerification({
        verificationId: ids.vid, artifactFingerprint: 'e'.repeat(64), artifactPublicKeyId: `${ALPHA}:key_v1`,
        artifactTimestampMs: 1790000000000, artifactExpiryMs: 1790000600000, artifactId: 'h130-art-1',
        overallResult: 'VERIFIED', checksPerformed: [{ check: 'SIGNATURE', result: 'PASS' }], warnings: [],
        transparencyId: null, submittedBy: 'public', submissionIp: CLIENT, durationMs: 7,
      });
      ids.cid = crypto.randomUUID();
      await certificationStore.recordCertification({
        certificationId: ids.cid, certificationLevel: 'NOT_CERTIFIED', certificationDecision: 'NOT_CERTIFIED', score: 10,
        requestedBy: 'external', requestIp: CLIENT, durationMs: 3,
      });
    });

    afterAll(() => {
      if (_savedTrustedProxy === undefined) delete process.env.TRUSTED_PROXY;
      else process.env.TRUSTED_PROXY = _savedTrustedProxy;
    });

    test('portal: public result (both mounts) withholds the address; the stored row keeps it', async () => {
      for (const base of ['/portal', '/v1/portal']) {
        const res = await request(app13).get(`${base}/result/${ids.vid}`);
        expect(res.status).toBe(200);
        expect(res.body.data.verification).not.toHaveProperty('submission_ip');
        expect(res.body.data.verification.verification_id).toBe(ids.vid);
        expect(res.text).not.toContain(CLIENT);
      }
      const row = (await _adminPool.query('SELECT submission_ip FROM portal_verifications WHERE verification_id = $1', [ids.vid])).rows[0];
      expect(row.submission_ip).toBe(CLIENT);
    });

    test('portal: the evidence package is refused anonymously and to an unrelated credential (both mounts)', async () => {
      for (const base of ['/portal', '/v1/portal']) {
        for (const headers of [{}, UNRELATED]) {
          const res = await request(app13).get(`${base}/evidence/${ids.vid}`).set(headers);
          expect(res.status).toBe(401);
          expect(res.text).not.toContain(CLIENT);
        }
      }
    });

    test('portal: an auditor receives the unchanged V1 package with the address; it verifies ATTESTED publicly without echoing either address', async () => {
      const res = await request(app13).get(`/v1/portal/evidence/${ids.vid}`).set(AUDITOR);
      expect(res.status).toBe(200);
      const pkg = res.body.data.evidencePackage;
      expect(pkg.packageType).toBe('QODIQA::PORTAL_EVIDENCE::V1');
      expect(pkg.submissionIp).toBe(CLIENT);
      const { packageId: _i, generatedAt: _g, packageHash, ...content } = pkg;
      expect(canonicalHash(content)).toBe(packageHash);
      const row = (await _adminPool.query('SELECT * FROM portal_verifications WHERE verification_id = $1', [ids.vid])).rows[0];
      expect(portal.assembleEvidencePackageFromPortalRecord(row).packageHash).toBe(packageHash);

      const v = await request(app13).post('/v1/attestation/evidence/verify').set('X-Forwarded-For', VERIFIER).send({ evidencePackage: pkg });
      expect(v.status).toBe(200);
      expect(v.body.data.attestation.attestationDecision).toBe('ATTESTED');
      expect(v.body.data.attestation.valid).toBe(true);
      expect(v.text).not.toContain(CLIENT);
      expect(v.text).not.toContain(VERIFIER);
      ids.evAtt = v.body.data.attestation.attestationId;
      ids.pkg = pkg;
    });

    test('attestation: the verifier address reached persistence through the clientIp middleware, is internal-only, and never public', async () => {
      const row = await pollRow('SELECT request_ip FROM attestations WHERE attestation_id = $1', [ids.evAtt]);
      expect(row.request_ip).toBe(VERIFIER);
      const pub = await request(app13).get(`/v1/attestation/${ids.evAtt}`);
      expect(pub.status).toBe(200);
      expect(pub.body.data.attestation).not.toHaveProperty('request_ip');
      expect(pub.text).not.toContain(VERIFIER);
      const other = await request(app13).get(`/v1/attestation/${ids.evAtt}`).set(UNRELATED);
      expect(other.body.data).toEqual(pub.body.data);
      const exp = await request(app13).get(`/v1/attestation/${ids.evAtt}/export`).set(AUDITOR);
      expect(exp.status).toBe(200);
      expect(exp.body.data.attestation.request_ip).toBe(VERIFIER);
      const anon = await request(app13).get(`/v1/attestation/${ids.evAtt}/export`);
      expect(anon.status).toBe(401);
    });

    test('cross-tenant and redaction behaviour unchanged: a re-tenanted or address-redacted package is NOT attested', async () => {
      const { packageId, generatedAt, packageHash: _h, ...content } = ids.pkg;
      const reseal = (c) => ({ ...c, packageHash: canonicalHash(c), packageId, generatedAt });
      for (const forged of [reseal({ ...content, artifactPublicKeyId: `${BETA}:key_v1` }), reseal({ ...content, submissionIp: null })]) {
        const r = await request(app13).post('/v1/attestation/evidence/verify').send({ evidencePackage: forged });
        expect(r.status).toBe(200);
        expect(r.body.data.attestation.attestationDecision).toBe('NOT_ATTESTED');
        expect(r.text).not.toContain(CLIENT);
      }
    });

    test('certification: public record and summary withhold the address; report/export (auditor) keep it', async () => {
      const pub = await request(app13).get(`/v1/certification/${ids.cid}`);
      expect(pub.status).toBe(200);
      expect(pub.body.data.certification).not.toHaveProperty('request_ip');
      expect(pub.body.data.certification.certification_id).toBe(ids.cid);
      expect(pub.text).not.toContain(CLIENT);
      const sum = await request(app13).get(`/v1/certification/${ids.cid}/summary`);
      expect(sum.status).toBe(200);
      expect(sum.text).not.toContain(CLIENT);
      const exp = await request(app13).get(`/v1/certification/${ids.cid}/export`).set(AUDITOR);
      expect(exp.body.data.certification.request_ip).toBe(CLIENT);
      const rep = await request(app13).get(`/v1/certification/${ids.cid}/report`).set(AUDITOR);
      expect(rep.body.data.report.requestMetadata.requestIp).toBe(CLIENT);
      const row = (await _adminPool.query('SELECT request_ip FROM certifications WHERE certification_id = $1', [ids.cid])).rows[0];
      expect(row.request_ip).toBe(CLIENT);
    });
  });
  // ── PDF routes are process-safe with the REAL PostgreSQL row shapes ──
  // BIGINT artifact_timestamp_ms / artifact_expiry_ms come back from the pg driver
  // as strings. both routes threw after doc.pipe(res) and pdfkit's
  // write into the ended error response (ERR_STREAM_WRITE_AFTER_END) terminated
  // the process. `lateWrites` records any write attempted on an ended response.
  describe('RV-14 PDF routes with real PostgreSQL rows (qodiqa_app)', () => {
    const http = require('http');
    const TS = 1790000000000;
    let app14, writeSpy, lateWrites = 0;
    const ids = {};
    const binary = (res, cb) => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => cb(null, Buffer.concat(c))); };
    const rowJson = async (table, col, id) => (await _adminPool.query(`SELECT row_to_json(t)::text j FROM ${table} t WHERE ${col} = $1`, [id])).rows[0].j;

    beforeAll(async () => {
      const roles = require('../../src/core/rbac/roles');
      const { createRequirePermission } = require('../../src/middleware/rbac');
      const requirePermission = createRequirePermission({ isPermitted: roles.isPermitted, isValidPermission: roles.isValidPermission });
      const auditor = (req, _res, next) => { req.rbacUser = Object.freeze({ id: 'op', username: 'op', role: 'auditor', enabled: true }); next(); };
      app14 = express();
      app14.use((req, _res, next) => { req.requestId = 'h131-rv14'; next(); });
      app14.get('/health', (_req, res) => res.status(200).json({ ok: true }));
      app14.use('/portal', require('../../src/api/routes/verificationPortal').createVerificationPortalPublicRouter({ optionalAuth: auditor })); // (D7 = B)
      app14.use('/v1/attestation', auditor, require('../../src/api/routes/attestation').createAttestationAdminRouter({ requirePermission }));
      app14.use('/v1/certification', auditor, require('../../src/api/routes/certification').createCertificationAdminRouter({ requirePermission }));

      ids.vid = crypto.randomUUID(); ids.aid = crypto.randomUUID(); ids.cid = crypto.randomUUID();
      await require('../../src/core/verification/portalStore').recordVerification({
        verificationId: ids.vid, artifactFingerprint: 'a'.repeat(64), artifactPublicKeyId: `${ALPHA}:key_v1`, artifactTimestampMs: TS,
        artifactExpiryMs: TS + 600000, artifactId: 'h131-art', overallResult: 'VERIFIED', checksPerformed: [{ check: 'SIGNATURE', result: 'PASS' }],
        warnings: [], transparencyId: null, submittedBy: 'public', durationMs: 5 });
      await require('../../src/core/attestation/attestationStore').recordAttestation({
        attestationId: ids.aid, attestationType: 'ARTIFACT_VERIFICATION', version: '1.0', artifactFingerprint: 'a'.repeat(64),
        artifactPublicKeyId: `${ALPHA}:key_v1`, artifactTimestampMs: TS, artifactExpiryMs: TS + 600000, artifactId: 'h131-art',
        attestationDecision: 'ATTESTED', verificationResult: { overallResult: 'VERIFIED', checks: [] }, cryptographicResult: {},
        complianceResult: {}, chainResult: {}, checksPerformed: [{ check: 'SIGNATURE', result: 'PASS' }], warnings: [],
        transparencyId: null, evidencePackageHash: 'e'.repeat(64), requestedBy: 'external', durationMs: 5 });
      await require('../../src/core/certification/certificationStore').recordCertification({
        certificationId: ids.cid, certificationLevel: 'NOT_CERTIFIED', certificationDecision: 'NOT_CERTIFIED', score: 10, requestedBy: 'external', durationMs: 3 });
      ids.before = { pv: await rowJson('portal_verifications', 'verification_id', ids.vid), at: await rowJson('attestations', 'attestation_id', ids.aid),
        ce: await rowJson('certifications', 'certification_id', ids.cid) };

      const origWrite = http.ServerResponse.prototype.write;
      writeSpy = jest.spyOn(http.ServerResponse.prototype, 'write').mockImplementation(function (...args) {
        if (this.writableEnded) { lateWrites += 1; return false; }
        return origWrite.apply(this, args);
      });
    });
    afterAll(() => { if (writeSpy) writeSpy.mockRestore(); });
    beforeEach(() => { lateWrites = 0; }); // per case, so one route's late writes cannot be attributed to another

    test('the stored BIGINT timestamps really arrive as strings (the shape that crashed)', async () => {
      const row = await require('../../src/core/verification/portalStore').getByVerificationId(ids.vid);
      expect(typeof row.artifact_timestamp_ms).toBe('string');
      expect(row.verified_at).toBeInstanceOf(Date);
    });

    test.each([
      ['public portal report PDF', () => `/portal/report/${ids.vid}?format=pdf`],
      ['admin attestation export PDF', () => `/v1/attestation/${ids.aid}/export?format=pdf`],
      ['admin certification export PDF (unchanged control)', () => `/v1/certification/${ids.cid}/export?format=pdf`],
    ])('%s: valid PDF twice, health after each, no write-after-end', async (_name, url) => {
      for (let i = 0; i < 2; i++) {
        const res = await request(app14).get(url()).buffer(true).parse(binary);
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toBe('application/pdf');
        expect(res.body.slice(0, 5).toString('latin1')).toBe('%PDF-');
        expect(res.body.slice(-8).toString('latin1')).toContain('%%EOF');
        await new Promise(r => setTimeout(r, 150));
        expect((await request(app14).get('/health')).status).toBe(200);
      }
      expect(lateWrites).toBe(0);
    });

    test('rendering PDFs does not alter any stored row', async () => {
      expect(await rowJson('portal_verifications', 'verification_id', ids.vid)).toBe(ids.before.pv);
      expect(await rowJson('attestations', 'attestation_id', ids.aid)).toBe(ids.before.at);
      expect(await rowJson('certifications', 'certification_id', ids.cid)).toBe(ids.before.ce);
    });
  });
});
