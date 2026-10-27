'use strict';

/**
 * —
 * GDPR erasure end to end, on a real disposable PostgreSQL database with the
 * full migration chain (test:component:serial: it runs the chain).
 *
 * Proves, with the real roles (qodiqa_app for the service, qodiqa_system for
 * the owner-run functions, qodiqa_test only for seeding and ground truth):
 *   - four-eyes approval: requester and identity verifier may not approve (D10);
 * - a subject with MORE THAN 200 consent records is fully erased (earlier cap);
 *   - every catalog-derived table is pseudonymized; nothing plaintext remains;
 *   - record_hash is recomputed and consent_audit_log checksums stay valid;
 *   - other subjects and the same subject in another tenant are untouched;
 *   - the subject key is destroyed and an erasure-ledger row written;
 *   - a FAILED run resumes to COMPLETED; a COMPLETED request is never re-approved;
 *   - a restore that resurrects plaintext rows is re-erased from the ledger.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(240_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_w5er_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const T = 'w5er-tenant-a';
const T_OTHER = 'w5er-tenant-b';
const S = `w5er-subject-${crypto.randomBytes(4).toString('hex')}`;
const S_KEEP = `w5er-keep-${crypto.randomBytes(4).toString('hex')}`;
const S_RESUME = `w5er-resume-${crypto.randomBytes(4).toString('hex')}`;
const N = 230; // > the earlier 200-row ceiling

const pgBase = () => ({
  host: process.env.QODIQA_PG_HOST || 'localhost',
  port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  connectionTimeoutMillis: 5000,
});
const ownerConn = () => `postgres://${encodeURIComponent(process.env.QODIQA_PG_TEST_USER || 'qodiqa_test')}:${encodeURIComponent(process.env.QODIQA_PG_TEST_PASSWORD)}@${process.env.QODIQA_PG_HOST || 'localhost'}:${process.env.QODIQA_PG_PORT || '5432'}/${DB}`;

// ConsentStore._recordHash — pinned here on purpose (the tombstone must hash like any other row).
const recordHash = (r) => crypto.createHash('sha256').update(JSON.stringify({
  id: r.id, actor_id: r.actor_id, action: r.action, state: r.state, scope: r.scope ?? null, tenant_id: r.tenant_id ?? null,
  granted_at: r.granted_at, granted_by: r.granted_by, expires_at: r.expires_at ?? null,
})).digest('hex');

let maint; let owner;
let pool; let rolePools; let ConsentStore; let DSR; let subjectPseudonym;
const saved = {};

async function newErasureRequest(actorId, tenantId = T) {
  const r = await DSR.createRequest({ request_type: 'ERASURE', actor_id: actorId, tenant_id: tenantId, requested_by: 'op-requester' });
  await DSR.verifyIdentity({ requestId: r.id, tenantId, method: 'OPERATOR_ATTESTATION', result: 'VERIFIED', verifiedBy: 'op-verifier' });
  await DSR.approve({ requestId: r.id, tenantId, approvedBy: 'op-approver' });
  return r.id;
}

async function seedSubject(actorId, tenantId, n) {
  for (let i = 0; i < n; i++) {
    await ConsentStore.create({ actor_id: actorId, action: `w5er-action-${i}`, tenant_id: tenantId, granted_by: i === 0 ? actorId : 'op-granter', subject_name: `Name ${i}`, grant_reference: `ref-${i}` });
  }
  await owner.query(
    `INSERT INTO revocation_events (event_id, subject_id, tenant_id, revoked_by, revocation_reason, revocation_timestamp, source_system, raw_payload)
     VALUES (gen_random_uuid(), $1, $2, 'op', 'test', NOW(), 'w5er', json_build_object('subjectId', $1::text)::text)`, [actorId, tenantId]);
  await owner.query(
    `INSERT INTO platform_audit_events (occurred_at, event_type, event_category, severity, component, tenant_id, actor_id, payload)
     VALUES (NOW(), 'W5ER_TEST', 'ACCESS_CONTROL', 'INFO', 'w5er', $1, $2, jsonb_build_object('actorId', $3::text, 'note', 'x'))`, [tenantId, actorId, actorId]);
}

async function plaintextCount(actorId, tenantId) {
  const targets = (await owner.query('SELECT * FROM qodiqa_erasure_targets()')).rows;
  let n = Number((await owner.query('SELECT count(*) FROM consent_records WHERE actor_id = $1 AND tenant_id IS NOT DISTINCT FROM $2', [actorId, tenantId])).rows[0].count);
  for (const t of targets) {
    n += Number((await owner.query(`SELECT count(*) FROM "${t.table_name}" WHERE "${t.column_name}" = $1 AND tenant_id IS NOT DISTINCT FROM $2`, [actorId, tenantId])).rows[0].count);
  }
  n += Number((await owner.query("SELECT count(*) FROM platform_audit_events WHERE payload->>'actorId' = $1 AND tenant_id IS NOT DISTINCT FROM $2", [actorId, tenantId])).rows[0].count);
  return n;
}

describeOrSkip('GDPR erasure end to end', () => {
  beforeAll(async () => {
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_URL', 'QODIQA_DSR_PSEUDONYM_PEPPER', 'QODIQA_PG_SYSTEM_PASSWORD']) saved[k] = process.env[k];
    maint = new Pool({ ...pgBase(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const { spawnSync } = require('child_process');
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 90_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    owner = new Pool({ ...pgBase(), database: DB, user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });

    process.env.QODIQA_PG_DATABASE = DB;
    delete process.env.QODIQA_PG_URL;
    process.env.QODIQA_DSR_PSEUDONYM_PEPPER = crypto.randomBytes(32).toString('hex');
    jest.resetModules();
    pool = require('../../src/infra/postgres/pool');
    rolePools = require('../../src/infra/postgres/rolePools');
    ConsentStore = require('../../src/core/consent/ConsentStore');
    DSR = require('../../src/core/dsr/DataSubjectRightsService');
    subjectPseudonym = require('../../src/core/dsr/subjectPseudonym');
    pool.initialize();

    await seedSubject(S, T, N);
    await seedSubject(S_KEEP, T, 3);
    await seedSubject(S, T_OTHER, 2);
    await seedSubject(S_RESUME, T, 5);
  });

  afterAll(async () => {
    try { await rolePools.shutdownAll(); } catch { /* ignore */ }
    try { await pool.shutdown(); } catch { /* ignore */ }
    try { await require('../../src/core/consent/revocation/RevocationPublisher').disconnect(); } catch { /* ignore */ }
    try { await require('../../src/core/consent/ConsentCache').disconnect(); } catch { /* ignore */ }
    if (owner) await owner.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });

  test('resumable: a run that fails part-way is FAILED, then resumes to COMPLETED with the same pseudonym', async () => {
    const id = await newErasureRequest(S_RESUME);
    // The system pool is created lazily on first use — with no password it fails closed
    // AFTER consent_records were already erased, i.e. part-way through the run.
    delete process.env.QODIQA_PG_SYSTEM_PASSWORD;
    await expect(DSR.erase({ requestId: id, tenantId: T, erasedBy: 'op-dpo' })).rejects.toMatchObject({ code: 'PG_ROLE_POOL_NOT_CONFIGURED' });
    process.env.QODIQA_PG_SYSTEM_PASSWORD = saved.QODIQA_PG_SYSTEM_PASSWORD;
    const failed = await DSR.getRequest(id, T);
    expect(failed.status).toBe('FAILED');
    const partial = Number((await owner.query('SELECT count(*) FROM consent_records WHERE actor_id = $1', [S_RESUME])).rows[0].count);
    expect(partial).toBe(0); // consent_records done, other tables not yet

    await expect(DSR.approve({ requestId: id, tenantId: T, approvedBy: 'op-approver' })).rejects.toMatchObject({ code: 'DSR_INVALID_TRANSITION' });
    const done = await DSR.erase({ requestId: id, tenantId: T, erasedBy: 'op-dpo' });
    expect(done.status).toBe('COMPLETED');
    expect(done.result.resumed).toBe(true);
    expect(await plaintextCount(S_RESUME, T)).toBe(0);
  });

  test('four-eyes: the requester and the identity verifier may not approve (403 DSR_SELF_APPROVAL_FORBIDDEN)', async () => {
    const r = await DSR.createRequest({ request_type: 'ERASURE', actor_id: 'w5er-nobody', tenant_id: T, requested_by: 'op-requester' });
    await DSR.verifyIdentity({ requestId: r.id, tenantId: T, method: 'OPERATOR_ATTESTATION', result: 'VERIFIED', verifiedBy: 'op-verifier' });
    await expect(DSR.approve({ requestId: r.id, tenantId: T, approvedBy: 'op-requester' })).rejects.toMatchObject({ code: 'DSR_SELF_APPROVAL_FORBIDDEN', statusCode: 403 });
    await expect(DSR.approve({ requestId: r.id, tenantId: T, approvedBy: 'op-verifier' })).rejects.toMatchObject({ code: 'DSR_SELF_APPROVAL_FORBIDDEN' });
    expect((await DSR.getRequest(r.id, T)).status).toBe('IDENTITY_VERIFIED');
  });

  let requestId; let pseudonym;
  test(`a subject with ${N} consent records (> 200) is erased completely, in every catalog table`, async () => {
    expect(await plaintextCount(S, T)).toBeGreaterThan(N);
    requestId = await newErasureRequest(S);
    const done = await DSR.erase({ requestId, tenantId: T, erasedBy: 'op-dpo' });
    expect(done.status).toBe('COMPLETED');
    pseudonym = done.result.pseudonym;
    expect(pseudonym).toMatch(/^ap1:[0-9a-f]{64}$/);
    expect(done.result.tables['consent_records.actor_id']).toBe(N);
    expect(done.result.tables['consent_audit_log.actor_id']).toBeGreaterThanOrEqual(N);
    expect(done.result.tables['revocation_events.subject_id']).toBe(1);
    const rev = (await owner.query('SELECT raw_payload FROM revocation_events WHERE subject_id = $1', [pseudonym])).rows;
    expect(rev).toHaveLength(1);
    expect(rev[0].raw_payload).not.toContain(S); // the stored original event no longer carries the identifier
    expect(done.result.tables['platform_audit_events.actor_id']).toBe(1);
    expect(await plaintextCount(S, T)).toBe(0);
    expect(done.actor_id).toBe(pseudonym); // dsr_requests pseudonymized (group c)
  });

  test('tombstones: PII scrubbed, state REVOKED, record_hash recomputed, audit checksums still valid', async () => {
    const rows = (await owner.query('SELECT * FROM consent_records WHERE actor_id = $1 AND tenant_id = $2', [pseudonym, T])).rows;
    expect(rows).toHaveLength(N);
    for (const r of rows) {
      expect(r).toMatchObject({ subject_name: null, grant_reference: null, action_display: null, state: 'REVOKED' });
      expect(r.record_hash).toBe(recordHash(r));
    }
    expect(rows.find((r) => r.action === 'w5er-action-0').granted_by).toBe(pseudonym); // self-granted → pseudonymized
    expect(rows.find((r) => r.action === 'w5er-action-1').granted_by).toBe('op-granter'); // operator kept
    const audit = (await owner.query('SELECT * FROM consent_audit_log WHERE consent_id = ANY($1::uuid[])', [rows.map((r) => r.id)])).rows;
    expect(audit.length).toBeGreaterThanOrEqual(2 * N);
    for (const a of audit) {
      expect(a.actor_id).toBe(pseudonym);
      expect(ConsentStore.verifyAuditChecksum(a).valid).toBe(true);
    }
  });

  test('isolation: another subject, and the same subject in another tenant, are untouched', async () => {
    expect(Number((await owner.query('SELECT count(*) FROM consent_records WHERE actor_id = $1 AND tenant_id = $2', [S_KEEP, T])).rows[0].count)).toBe(3);
    expect(Number((await owner.query('SELECT count(*) FROM consent_records WHERE actor_id = $1 AND tenant_id = $2', [S, T_OTHER])).rows[0].count)).toBe(2);
    expect(await plaintextCount(S, T_OTHER)).toBeGreaterThan(2);
  });

  test('the subject key is destroyed and one erasure-ledger row records the run (keyed ref, no identifier)', async () => {
    expect(Number((await owner.query('SELECT count(*) FROM subject_pseudonym_keys WHERE actor_id = $1 AND tenant_id = $2', [S, T])).rows[0].count)).toBe(0);
    const ledger = (await owner.query('SELECT * FROM dsr_erasure_ledger WHERE request_id = $1', [requestId])).rows;
    expect(ledger).toHaveLength(1);
    expect(ledger[0].subject_ref).toBe(subjectPseudonym.subjectRef(T, S));
    expect(JSON.stringify(ledger[0])).not.toContain(S);
    const events = (await owner.query("SELECT detail::text AS d FROM dsr_request_events WHERE request_id = $1 AND event_type = 'DSR_ERASURE_COMPLETED'", [requestId])).rows;
    expect(events).toHaveLength(1);
    expect(events[0].d).not.toContain(S);
  });

  test('a COMPLETED request is never re-approved or re-executed (409 DSR_INVALID_TRANSITION)', async () => {
    await expect(DSR.approve({ requestId, tenantId: T, approvedBy: 'op-approver' })).rejects.toMatchObject({ code: 'DSR_INVALID_TRANSITION', statusCode: 409 });
    await expect(DSR.erase({ requestId, tenantId: T, erasedBy: 'op-dpo' })).rejects.toThrow(/not approved for execution/);
  });

  test('restore replay: plaintext rows resurrected by a backup are re-erased from the ledger (DB and export-file sources)', async () => {
    // Simulate a restored pre-erasure backup: the subject reappears in plaintext.
    await seedSubject(S, T, 1);
    expect(await plaintextCount(S, T)).toBeGreaterThan(0);
    const { replayErasures } = require('../../scripts/dr/erasureReplay');
    const r1 = await replayErasures({ connectionString: ownerConn(), ledgerSource: null });
    expect(r1.subjectsReErased).toBe(1);
    expect(r1.subjectRefs).toEqual([subjectPseudonym.subjectRef(T, S)]);
    expect(await plaintextCount(S, T)).toBe(0);
    expect(await plaintextCount(S_KEEP, T)).toBeGreaterThan(0); // never erased → never replayed

    // External ledger export (erasures made AFTER the backup): exported rows are replayed and re-imported.
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'w5er-ledger-')), 'ledger.jsonl');
    const rows = (await owner.query('SELECT * FROM qodiqa_erasure_ledger_list(0, 1000)')).rows;
    fs.writeFileSync(file, rows.map((x) => JSON.stringify(x)).join('\n') + '\n');
    await seedSubject(S, T, 1);
    const r2 = await replayErasures({ connectionString: ownerConn(), ledgerSource: file });
    expect(r2.subjectsReErased).toBe(1);
    expect(await plaintextCount(S, T)).toBe(0);
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  });

  test('every table holding an actor_id/subject_id column is either an erasure target or a declared exclusion', async () => {
    const all = (await owner.query(`SELECT DISTINCT c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND NOT c.relispartition
      AND a.attnum > 0 AND NOT a.attisdropped AND a.attname IN ('actor_id','subject_id') ORDER BY 1`)).rows.map((r) => r.t);
    const targets = new Set((await owner.query('SELECT table_name FROM qodiqa_erasure_targets()')).rows.map((r) => r.table_name));
    const declared = new Set(['consent_records', 'dsr_requests', 'subject_pseudonym_keys', 'approval_events', 'policy_provenance_versions']);
    expect(all.filter((t) => !targets.has(t) && !declared.has(t))).toEqual([]);
    expect((await owner.query('SELECT * FROM qodiqa_erasure_targets() WHERE NOT has_tenant')).rows).toEqual([]);
  });
});
