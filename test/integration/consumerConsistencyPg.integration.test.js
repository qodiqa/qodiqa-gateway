'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * consumer consistency on a real, disposable PostgreSQL database (test:component:serial:
 * it runs the migration chain). Every path that writes or re-materializes audit entries into or
 * out of PostgreSQL must produce rows/lines the INDEPENDENT verifier (scripts/audit-repro/verify/,
 * no src/ imports) accepts, with the same hashes the production verifier accepts.
 *
 *   CC-01  production mirror writer (persistEntry): a mixed v1/v5/v6, two-tenant chain → the
 *          independent verifier over `SELECT *` rows is VALID and agrees entry-for-entry with
 *          production's loadChainFromPg() hydration (hashed fields, canonical, hash)
 *   CC-02  scripts/export-audit-chain-snapshot.js (the distributed-mode DR snapshot) run as
 *          qodiqa_app → the NDJSON + .sum verify in the independent verifier AND boot + full-verify
 *          in production (the script's own documented "drop-in QODIQA_AUDIT_LOG" contract)
 *   CC-03  scripts/migrate-files-to-pg.js (file → PG) → the migrated rows verify; a malformed
 *          audit line aborts the migration instead of being silently dropped
 *   CC-04  scripts/dr/seed.js's PostgreSQL audit_chain row verifies
 * CC-05 audit schema v7, migration 075: the five v7 columns exist (nullable, NULL on pre-v7 rows) and
 *          idx_audit_chain_request_id is the single, NON-unique request_id index (R-16)
 *   CC-06  a v7 lifecycle (INTENT → STREAM_OPENED → DECISION) written by the production mirror writer: every row
 *          carries its v7 columns, each lifecycle entry has its OWN evidence_chain_records row (R-11), lookups by
 *          suffixed artifact id and by request_id work, and the whole chain verifies in BOTH verifiers from GENESIS
 * CC-07 subject pseudonyms with the real key store (R-12/R-15): ap1: format, deterministic per (tenant, actor),
 *          distinct across tenants, idempotent on pseudonyms; a v7 row carrying them holds no raw identifier
 * CC-08 mirror projection on real PostgreSQL: v7 entries carrying ASCII, accented Latin, Romanian, CJK, emoji,
 *          quotes, backslashes, TAB / LF / CR, U+0000 and lone high / low surrogates in every per-field column (TEXT and
 * nested JSONB keys / values) are mirrored (the probe's refusals and the silent TEXT alteration are gone);
 *          the stored per-field values are pure ASCII with mirror_encoding = 1 while canonical / hash / prev_hash are
 *          byte-identical; EVERY reader — loadChainFromPg, fetchChainBatch, queryByArtifactId, chainStore's evidence
 *          lookup, queryReplayLineage, the export snapshot path's decoder, the independent verifier's entryFromPgRow,
 *          and the S3 compact readers — reconstructs the exact logical values; production and independent verifiers
 *          agree VALID; canonical JSON and hash recomputed from the decoded row are byte-identical; ChainVerifier's
 *          full divergence comparison finds 0 violations, and a tampered projected artifact_id IS detected
 *   CC-09  legacy (mirror_encoding 0) rows are read natively and verify; a native row whose TEXT column PostgreSQL
 *          altered (lone surrogate) fails verification explicitly — nothing rewrites it; a corrupt projected value and an
 *          unknown marker are refused (production MirrorDecodeError, independent MIRROR_DECODE_ERROR) — never guessed
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawnSync } = require('child_process');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_TEST_PASSWORD;
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(240_000);

const REPO = path.join(__dirname, '..', '..');
const DB = `qodiqa_w7cc_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const TEST_USER = process.env.QODIQA_PG_TEST_USER || 'qodiqa_test';
const TEST_PW = process.env.QODIQA_PG_TEST_PASSWORD;
const APP_PW = process.env.QODIQA_PG_PASSWORD;
const APP_USER = process.env.QODIQA_PG_USER || 'qodiqa_app';
const base = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false, connectionTimeoutMillis: 5000 });

const verify = require('../../scripts/audit-repro/verify/qodiqa-audit-verify');
const contract = require('../../scripts/audit-repro/verify/auditContract');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w7-cc-'));
const saved = {};
let maint; let owner; let pgPool; let backend; let entryBuilder;

/** A child-process env pinned to the disposable DB: no .env backfill can redirect it to LIVE. */
function childEnv(extra) {
  const env = { ...process.env, QODIQA_PG_URL: '', DATABASE_URL: '', QODIQA_PG_DATABASE: DB, QODIQA_PG_HOST: process.env.QODIQA_PG_HOST || 'localhost', QODIQA_PG_PORT: process.env.QODIQA_PG_PORT || '5432', ...extra };
  return env;
}
/** A second disposable database with the full migration chain (dropped by the caller). */
async function freshDb(name) {
  await maint.query(`CREATE DATABASE "${name}"`);
  const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], { cwd: REPO, encoding: 'utf8', timeout: 120_000,
    env: childEnv({ QODIQA_PG_DATABASE: name, QODIQA_PG_MIG_USER: TEST_USER, QODIQA_PG_MIG_PASSWORD: TEST_PW }) });
  if (mig.status !== 0) throw new Error(`migrate.js failed: ${(mig.stdout + mig.stderr).slice(-400)}`);
}
async function dropDb(name) {
  await maint.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  if ((await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [name])).rowCount !== 0) throw new Error(`${name} was not dropped`);
}
async function allRows() { return (await owner.query('SELECT * FROM audit_chain ORDER BY seq')).rows; }

describeOrSkip('consumer consistency on real PostgreSQL', () => {
  beforeAll(async () => {
    maint = new Pool({ ...base(), database: 'postgres', user: TEST_USER, password: TEST_PW });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_PG_URL']) saved[k] = process.env[k];
    delete process.env.QODIQA_PG_URL;
    process.env.QODIQA_PG_DATABASE = DB;
    process.env.QODIQA_PG_USER = TEST_USER;       // the migration chain creates roles (CREATEROLE/BYPASSRLS)
    process.env.QODIQA_PG_PASSWORD = TEST_PW;
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    backend = require('../../src/infra/postgres/pg-audit-backend');
    entryBuilder = require('../../src/core/audit/entryBuilder');
    pgPool.initialize();
    await pgPool.runMigrations();
    owner = new Pool({ ...base(), database: DB, user: TEST_USER, password: TEST_PW });
  });

  afterAll(async () => {
    fs.rmSync(tmp, { recursive: true, force: true }); // this suite's own temp dir
    if (pgPool) await pgPool.shutdown().catch(() => {});
    try { await require('../../src/infra/postgres/rolePools').shutdownAll(); } catch { /* not started */ }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (owner) await owner.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  // a mixed-version, two-tenant chain written through the production mirror writer
  const written = [];
  test('CC-01 production mirror writer → independent verifier agrees with production hydration', async () => {
    const { sortedJSON, domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../src/infra/crypto/hashing');
    const seal = (e, fields) => { const core = {}; for (const f of fields) core[f] = e[f]; const canonical = sortedJSON(core); return { ...e, canonical, hash: domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex') }; };
    const v1 = seal({ artifactId: 'cc-v1', decision: 'ALLOW', inputHash: 'a'.repeat(64), policyHash: 'c'.repeat(64), prevHash: 'GENESIS', requestHash: 'b'.repeat(64), signature: 's1', timestamp: '2026-01-01T00:00:00.000Z', verificationResult: true, highResTime: '1' }, entryBuilder.CORE_HASH_FIELDS_V1);
    const v5 = seal({ artifactId: 'cc-v5', decision: 'BLOCK', inputHash: 'a'.repeat(64), policyHash: 'c'.repeat(64), prevHash: v1.hash, requestHash: 'b'.repeat(64), signature: 's5', timestamp: '2026-05-01T00:00:00.000Z', verificationResult: false, highResTime: '2', publicKeyId: 't:key_v1', schemaVersion: 5, consentProvenance: null, policyDecision: { ruleId: 'r' }, callerContext: { callerId: 'c' }, provider: 'local', model: 'm', tenantId: 'tenant-a' }, entryBuilder.CORE_HASH_FIELDS_V5);
    const v6a = entryBuilder.buildEntry(entryBuilder.normalizeFields({
      artifactId: 'cc-v6a', inputHash: 'd'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 's6', requestHash: 'e'.repeat(64), policyHash: 'f'.repeat(64), verificationResult: true,
      tenantId: 'tenant-a', organizationId: 'org-a', publicKeyId: 'tenant-a:key_v2', nonce: 'n-1', requestId: 'r-1', executionContext: { executingProvider: 'local' },
      consentProvenance: { consentId: 'c-1', scope: ['chat'] }, policyDecision: { ruleId: 'r-7', path: ['a', 'b'] }, callerContext: { callerId: 'caller' },
      provider: 'openai', model: 'gpt-x', stage: 'EXECUTE', reason: null, semantic: { scores: { e: 0.125 } }, tokenUsage: { total: 42 }, responseId: 'resp-1',
    }), v5.hash);
    const v6b = entryBuilder.buildEntry(entryBuilder.normalizeFields({ artifactId: 'cc-v6b-é\u{1F600}', decision: 'BLOCK', verificationResult: false, tenantId: 'tenant-b', stage: 'SEMANTIC', reason: 'résumé "q" \\', semantic: { decision: 'BLOCK' } }), v6a.hash);
    for (const e of [v1, v5, v6a, v6b]) { await backend.persistEntry(e); written.push(e); }

    const rows = await allRows();
    const rep = verify.verify({ audit: writeJson('cc01-rows.json', rows), format: 'pg-json' });
    expect({ verdict: rep.verdict, verified: rep.audit.entriesVerified, anomalies: rep.audit.pgAnomalies }).toEqual({ verdict: 'VALID', verified: 4, anomalies: [] });

    const hydrated = await backend.loadChainFromPg();
    const auditLog = require('../../src/core/audit/audit-log');
    expect(auditLog.verifyAuditChainDetailed(hydrated)).toMatchObject({ valid: true, entriesVerified: 4 });
    const byHash = new Map(rows.map((r) => [r.hash, contract.entryFromPgRow(r)]));
    for (const h of hydrated) {
      const i = byHash.get(h.hash);
      const v = contract.declaredVersion(i);
      const pick = (e) => { const o = { canonical: e.canonical, hash: e.hash }; for (const f of contract.HASHED_FIELDS[v]) o[f] = e[f] ?? null; return o; };
      expect(pick(i)).toEqual(pick(h));
      expect(contract.checkEntryHash(h)).toMatchObject({ ok: true });
    }
  });

  test('CC-02 export-audit-chain-snapshot.js (as qodiqa_system, the full-read role) → the WHOLE multi-tenant chain verifies independently and boots in production', async () => {
    // Pre-W7 evidence: run as qodiqa_app the
    // script read audit_chain directly and RLS returned 1 of 4 rows — a partial snapshot that
    // still "verified". qodiqa_app is now refused the full read outright, never partial:
    const refused = spawnSync(process.execPath, ['scripts/export-audit-chain-snapshot.js', path.join(tmp, 'snap-app')], { cwd: REPO, encoding: 'utf8', timeout: 60_000,
      env: childEnv({ QODIQA_PG_SYSTEM_USER: APP_USER, QODIQA_PG_SYSTEM_PASSWORD: APP_PW }) });
    expect({ status: refused.status, msg: /permission denied for function qodiqa_audit_chain_full_read/.test(refused.stdout + refused.stderr) }).toEqual({ status: 1, msg: true });
    const out = path.join(tmp, 'snap');
    const r = spawnSync(process.execPath, ['scripts/export-audit-chain-snapshot.js', out], { cwd: REPO, encoding: 'utf8', timeout: 60_000,
      env: childEnv({ QODIQA_PG_SYSTEM_USER: process.env.QODIQA_PG_SYSTEM_USER || 'qodiqa_system', QODIQA_PG_SYSTEM_PASSWORD: process.env.QODIQA_PG_SYSTEM_PASSWORD }) });
    expect({ status: r.status, err: r.status === 0 ? '' : (r.stdout + r.stderr).slice(-600) }).toEqual({ status: 0, err: '' });
    const file = fs.readdirSync(out).find((f) => f.endsWith('.ndjson'));
    const snap = path.join(out, file);
    const rep = verify.verify({ audit: snap, format: 'ndjson', anchor: snap + '.sum' });
    expect({ verdict: rep.verdict, verified: rep.audit.entriesVerified, total: rep.audit.total, reason: rep.audit.reason, anchor: rep.anchor }).toEqual({ verdict: 'VALID', verified: 4, total: 4, reason: null, anchor: { ok: true, problems: [] } });
    // production: the documented drop-in contract — boot on the snapshot and full-verify it
    const boot = spawnSync(process.execPath, ['-e', "const a=require('./src/core/audit/audit-log');const v=a.verifyFullChainFromDisk();console.log(JSON.stringify({valid:v.walkResult&&v.walkResult.valid,n:v.walkResult&&v.walkResult.entriesVerified,reason:v.walkResult&&v.walkResult.reason,checksumOk:v.checksumOk,parseError:v.parseError}))"],
      { cwd: REPO, encoding: 'utf8', timeout: 60_000, env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, NODE_ENV: 'test', QODIQA_AUDIT_LOG: snap, QODIQA_PG_ENABLED: 'false', QODIQA_KEYS_PATH: path.join(tmp, 'k.json'), QODIQA_TRANSPARENCY_KEYS_PATH: path.join(tmp, 't.json'), QODIQA_MAC_KEYS_PATH: path.join(tmp, 'm.json') } });
    const line = (boot.stdout || '').trim().split('\n').filter((l) => l.startsWith('{"valid"')).pop();
    expect({ status: boot.status, result: line ? JSON.parse(line) : (boot.stderr || '').slice(-400) }).toEqual({ status: 0, result: { valid: true, n: 4, reason: null, checksumOk: true, parseError: null } });
  });

  test('CC-03 migrate-files-to-pg.js (file → PG) writes rows that verify; a malformed audit line aborts', async () => {
    const DB2 = `${DB}_m`;
    await freshDb(DB2);
    try {
      const log = path.join(tmp, 'mig-audit.log');
      fs.writeFileSync(log, written.map((e) => JSON.stringify(e)).join('\n') + '\n');
      const none = path.join(tmp, 'absent.json');
      const env = childEnv({ QODIQA_PG_DATABASE: DB2, QODIQA_PG_MIG_USER: TEST_USER, QODIQA_PG_MIG_PASSWORD: TEST_PW, QODIQA_AUDIT_LOG: log,
        QODIQA_RBAC_STORE_PATH: none, QODIQA_KEYS_PATH: none, POLICY_FILE: none, QODIQA_POLICY_STORE: none, QODIQA_INVESTIGATIONS_PATH: none, INVESTIGATIONS_PATH: none });
      const r = spawnSync(process.execPath, ['scripts/migrate-files-to-pg.js'], { cwd: REPO, encoding: 'utf8', timeout: 60_000, env });
      expect({ status: r.status, err: r.status === 0 ? '' : (r.stdout + r.stderr).slice(-600) }).toEqual({ status: 0, err: '' });
      const o3 = new Pool({ ...base(), database: DB2, user: TEST_USER, password: TEST_PW });
      const rows = (await o3.query('SELECT * FROM audit_chain ORDER BY seq')).rows;
      await o3.end();
      const rep = verify.verify({ audit: writeJson('cc03-rows.json', rows), format: 'pg-json' });
      expect({ verdict: rep.verdict, verified: rep.audit.entriesVerified, reason: rep.audit.reason, failure: rep.audit.failure }).toEqual({ verdict: 'VALID', verified: 4, reason: null, failure: null });

      fs.writeFileSync(log, [JSON.stringify(written[0]), JSON.stringify(written[1]).slice(0, 50), JSON.stringify(written[2])].join('\n') + '\n');
      const bad = spawnSync(process.execPath, ['scripts/migrate-files-to-pg.js'], { cwd: REPO, encoding: 'utf8', timeout: 60_000, env });
      expect(bad.status).not.toBe(0);
      expect(bad.stdout + bad.stderr).toMatch(/malformed audit line 2/);
    } finally {
      await dropDb(DB2);
    }
  });

  test('CC-04 dr/seed.js: its PostgreSQL audit_chain row verifies', async () => {
    const DB3 = `${DB}_s`; // seed.js starts a fresh chain at GENESIS: it needs an empty audit_chain
    await freshDb(DB3);
    try {
    // exactly the CI drill invocation (.github/workflows/backup-restore.yml): a child process with
    // scratch stores — plus QODIQA_PG_URL pinned to this disposable database
    const S = fs.mkdtempSync(path.join(tmp, 'seed-'));
    const r = spawnSync(process.execPath, ['scripts/dr/seed.js'], { cwd: REPO, encoding: 'utf8', timeout: 120_000, env: {
      PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, NODE_ENV: 'test',
      QODIQA_AUDIT_LOG: path.join(S, 'audit.log'), QODIQA_KEYS_PATH: path.join(S, 'data', 'keys.json'), QODIQA_KEYS_ARCHIVE_PATH: path.join(S, 'data', 'key-archive.json'),
      QODIQA_POLICY_STORE: path.join(S, 'data', 'policy-store.json'), POLICY_FILE: path.join(S, 'policies.json'), ORG_STORE_PATH: path.join(S, 'data', 'organizations.json'),
      TENANT_STORE_PATH: path.join(S, 'data', 'tenants.json'), QODIQA_MAC_KEYS_PATH: path.join(S, 'data', 'mac-keys.json'), QODIQA_TRANSPARENCY_KEYS_PATH: path.join(S, 'data', 'tk.json'),
      QODIQA_KEY_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'), QODIQA_PG_ENABLED: 'false',
      QODIQA_PG_URL: `postgres://${encodeURIComponent(TEST_USER)}:${encodeURIComponent(TEST_PW)}@${process.env.QODIQA_PG_HOST || 'localhost'}:${process.env.QODIQA_PG_PORT || '5432'}/${DB3}`,
    } });
    expect({ status: r.status, err: r.status === 0 ? '' : (r.stdout + r.stderr).slice(-600) }).toEqual({ status: 0, err: '' });
    const o4 = new Pool({ ...base(), database: DB3, user: TEST_USER, password: TEST_PW });
    const added = (await o4.query('SELECT * FROM audit_chain ORDER BY seq')).rows;
    await o4.end();
    expect(added.length).toBe(1);
    const e = contract.entryFromPgRow(added[0]);
    expect({ schemaVersion: added[0].schema_version, check: contract.checkEntryHash(e) }).toEqual({ schemaVersion: 7, check: { ok: true, code: null, version: 7 } }); // dr/seed.js now writes v7
    expect(entryBuilder.verifyCanonicalHash(e)).toBe(true);
    } finally {
      await dropDb(DB3);
    }
  });

  test('CC-05 migration 075: v7 columns + the non-unique request_id index', async () => {
    const cols = (await owner.query(`SELECT column_name, is_nullable, data_type FROM information_schema.columns
      WHERE table_name = 'audit_chain' AND column_name = ANY($1) ORDER BY column_name`, [['entry_type', 'output_hash', 'request_id', 'organization_id', 'executing_provider']])).rows;
    expect(cols).toEqual(['entry_type', 'executing_provider', 'organization_id', 'output_hash', 'request_id'].map((c) => ({ column_name: c, is_nullable: 'YES', data_type: 'text' })));
    const idx = (await owner.query(`SELECT i.relname AS name, ix.indisunique AS uniq FROM pg_index ix JOIN pg_class i ON i.oid = ix.indexrelid JOIN pg_class t ON t.oid = ix.indrelid
      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey) WHERE t.relname = 'audit_chain' AND a.attname = 'request_id'`)).rows;
    expect(idx).toEqual([{ name: 'idx_audit_chain_request_id', uniq: false }]);
    const pre = (await owner.query("SELECT entry_type, output_hash, request_id, organization_id, executing_provider FROM audit_chain WHERE artifact_id IN ('cc-v1', 'cc-v5')")).rows;
    expect(pre).toEqual([{ entry_type: null, output_hash: null, request_id: null, organization_id: null, executing_provider: null }, { entry_type: null, output_hash: null, request_id: null, organization_id: null, executing_provider: null }]);
  });

  test('CC-06 a v7 lifecycle through the production mirror writer: columns, own evidence records, lookups, both verifiers', async () => {
    const rid = 'cc-v7-' + crypto.randomBytes(4).toString('hex');
    const common = { inputHash: 'a'.repeat(64), signature: 's7', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 'tenant-a', organizationId: 'org-a', requestId: rid, publicKeyId: 'tenant-a:key_v2', provider: 'openai', model: 'gpt-x' };
    let prev = (await allRows()).slice(-1)[0].hash;
    const specs = [
      { ...common, artifactId: entryBuilder.lifecycleArtifactId(rid, 'INTENT'), entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', outputHash: null, executingProvider: 'openai', executionContext: { stage: 'PROVIDER_DISPATCH', provider: 'openai' } },
      { ...common, artifactId: entryBuilder.lifecycleArtifactId(rid, 'STREAM_OPENED'), entryType: 'STREAM_OPENED', decision: 'ALLOW', stage: 'STREAM_OPENED', outputHash: null, executingProvider: 'openai', responseId: 'stream-' + rid, executionContext: { stage: 'STREAM_OPENED' } },
      { ...common, artifactId: rid, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash: entryBuilder.outputHashOf('streamed é 😀'), executingProvider: 'local', responseId: 'stream-' + rid, executionContext: { stage: 'PROVIDER_EXECUTION', failover: { from: 'openai', to: 'local', cause: 'PROVIDER_UNAVAILABLE' } } },
    ];
    const v7 = [];
    for (const s of specs) { const e = entryBuilder.buildEntry(entryBuilder.normalizeFields(s), prev); await backend.persistEntry(e); v7.push(e); prev = e.hash; }

    const byReq = (await owner.query('SELECT artifact_id, entry_type, output_hash, request_id, organization_id, executing_provider, schema_version FROM audit_chain WHERE request_id = $1 ORDER BY seq', [rid])).rows;
    expect(byReq).toEqual(v7.map((e) => ({ artifact_id: e.artifactId, entry_type: e.entryType, output_hash: e.outputHash, request_id: rid, organization_id: 'org-a', executing_provider: e.executingProvider, schema_version: 7 })));
    const ev = (await owner.query('SELECT artifact_id FROM evidence_chain_records WHERE artifact_id = ANY($1) ORDER BY artifact_id', [v7.map((e) => e.artifactId)])).rows.map((r) => r.artifact_id);
    expect(ev).toEqual(v7.map((e) => e.artifactId).sort());
    const intentBack = await backend.queryByArtifactId(`${rid}:intent`);
    expect(intentBack).toMatchObject({ entryType: 'INTENT', outputHash: null, requestId: rid, executingProvider: 'openai', schemaVersion: 7 });
    expect(entryBuilder.verifyCanonicalHash({ ...intentBack, timestamp: JSON.parse(intentBack.canonical).timestamp })).toBe(true);

    const rows = await allRows();
    const rep = verify.verify({ audit: writeJson('cc06-rows.json', rows), format: 'pg-json' });
    expect({ verdict: rep.verdict, anomalies: rep.audit.pgAnomalies }).toEqual({ verdict: 'VALID', anomalies: [] });
    const indep = contract.walkChain(contract.orderPgRows(rows).ordered.map(contract.entryFromPgRow));
    expect(indep).toMatchObject({ valid: true, lifecycleComplete: true, warnings: [] });
    const hydrated = await backend.loadChainFromPg();
    const prod = require('../../src/core/audit/audit-log').verifyAuditChainDetailed(hydrated);
    expect(prod).toMatchObject({ valid: true, lifecycleComplete: true, warnings: [], entriesVerified: rows.length });
  });

  test('CC-07 pseudonyms with the real key store, and a v7 row that carries them holds no raw identifier', async () => {
    const sp = require('../../src/core/dsr/subjectPseudonym');
    const a1 = await sp.pseudonymFor('tenant-a', 'alice-raw-id');
    expect(a1).toMatch(/^ap1:[0-9a-f]{64}$/);
    expect(await sp.pseudonymFor('tenant-a', 'alice-raw-id')).toBe(a1);          // deterministic (same key)
    expect(await sp.pseudonymFor('tenant-b', 'alice-raw-id')).not.toBe(a1);      // per-tenant
    expect(await sp.pseudonymFor('tenant-a', a1)).toBe(a1);                      // idempotent on pseudonyms
    const keys = (await owner.query("SELECT count(*)::int AS n FROM subject_pseudonym_keys WHERE actor_id = 'alice-raw-id'")).rows[0].n;
    expect(keys).toBe(2);                                                        // one key per (tenant, subject), no cache layer
    const prev = (await allRows()).slice(-1)[0].hash;
    const e = entryBuilder.buildEntry(entryBuilder.normalizeFields({ artifactId: 'cc07-' + crypto.randomBytes(3).toString('hex'), inputHash: 'a'.repeat(64), decision: 'BLOCK', signature: 's', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: false,
      tenantId: 'tenant-a', consentProvenance: { consentId: 'c-9', subject: a1 }, callerContext: { callerId: await sp.pseudonymFor('tenant-a', 'bob-raw-id') } }), prev);
    await backend.persistEntry(e);
    const row = (await owner.query('SELECT * FROM audit_chain WHERE artifact_id = $1', [e.artifactId])).rows[0];
    expect(JSON.stringify(row)).not.toMatch(/alice-raw-id|bob-raw-id/);
    expect(contract.checkEntryHash(contract.entryFromPgRow(row))).toMatchObject({ ok: true, version: 7 });
  });

  // ── ──────────────────────────────────────────────────────────────────────────────────────────────────────────
  const CLS = {
    ascii: 'plain ASCII', accented: 'éàüñç Ångström', romanian: 'Ștefan își ţară', cjk: '漢字かな한국어', emoji: '😀👩‍👩‍👧🇷🇴',
    quotes: 'say "hi"', backslashes: 'C:\\temp \\u00e9 \\', tabs: 'a\tb', newlines: 'l1\nl2', cr: 'r1\r\n', nul: 'a\u0000b',
    high: 'x\ud800y', low: '\udc00z', empty: '',
  };
  const ALL = Object.values(CLS).join('|');
  // nonce / public_key_id are VARCHAR(256): P expands a non-ASCII code unit to 6 ASCII characters, so the long combined
  // value is used there only in a short form (still NUL + both lone surrogates + quotes) — see the report, finding 1
  const lim = (k, s) => (k === 'combined' ? CLS.nul + CLS.high + CLS.low + CLS.quotes : s);
  const f6 = [];   // the logical (original) entries CC-08 wrote
  const PER_TEXT = ['artifactId', 'decision', 'highResTime', 'inputHash', 'signature', 'requestHash', 'policyHash', 'nonce', 'tenantId', 'publicKeyId', 'provider', 'model', 'stage', 'reason', 'responseId', 'entryType', 'outputHash', 'requestId', 'organizationId', 'executingProvider'];
  const PER_JSON = ['executionContext', 'consentProvenance', 'policyDecision', 'callerContext', 'semantic', 'tokenUsage'];
  const logical = (e) => { const o = {}; for (const f of [...PER_TEXT, ...PER_JSON]) o[f] = e[f] ?? null; o.canonical = e.canonical; o.hash = e.hash; o.prevHash = e.prevHash; return o; };

  test('CC-08 every class mirrors, every reader reconstructs the exact logical values, hashes byte-identical, S3 agrees', async () => {
    const mp = require('../../src/infra/postgres/mirrorProjection');
    let prev = (await allRows()).slice(-1)[0].hash;
    const tag = crypto.randomBytes(3).toString('hex');
    const specs = Object.entries({ ...CLS, combined: ALL }).map(([k, s]) => ({
      // artifact ids: Unicode, quotes and backslashes, but no NUL / lone surrogate (evidence_chain_records keeps raw ids)
      // artifact ids carry Unicode, quotes and backslashes but stay within artifact_id VARCHAR(128) AFTER projection
      artifactId: `f6-${tag}-${k}-${['nul', 'high', 'low', 'combined', 'cjk', 'emoji', 'accented', 'romanian'].includes(k) ? 'Ș😀"\\' : s}`,
      inputHash: 'a'.repeat(64), decision: k === 'empty' ? 'BLOCK' : 'ALLOW', signature: 'sig-' + s, requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: k !== 'empty',
      ...(k === 'empty' ? {} : { outputHash: entryBuilder.outputHashOf(s) }), nonce: `n-${tag}-${k}-${lim(k, s)}`, tenantId: 'tenant-f6', organizationId: 'org-' + s, requestId: 'req-' + s,
      publicKeyId: 'tenant-f6:key-' + lim(k, s), provider: 'prov-' + s, model: 'model-' + s, stage: 'STAGE-' + s, reason: k === 'empty' ? 'R-' + s : null, responseId: 'resp-' + s, executingProvider: 'exec-' + s,
      executionContext: { stage: s, nested: { ['key-' + s]: [s, 1, null, true], deep: { replayOf: null, k: s } } },
      consentProvenance: { consentId: 'c-' + s, subject: s, scope: [s, CLS.cjk] }, policyDecision: { policyId: 'p-' + s, path: [s] },
      callerContext: { callerId: 'ap1:' + 'e'.repeat(64), callerName: s }, semantic: { decision: s, score: 0.5, [s + 'k']: s }, tokenUsage: { ['t-' + s]: 7, totalTokens: 7 },
    }));
    // The classes evidence_chain_records can also hold go through the full production path (persistEntry: mirror row +
    // evidence record); the classes only the projected mirror can hold (U+0000, lone surrogates, and the combination)
    // go through the mirror writer itself — evidence_chain_records / the recovery queue store raw values and still
    // refuse them (reported as a separate finding, outside the approved scope).
    const MIRROR_ONLY = new Set(['nul', 'high', 'low', 'combined']);
    // F6-N2: the write path now REFUSES U+0000 / lone surrogates (entryBuilder.normalizeFields),
    // so entries carrying them can no longer be produced by the application. The mirror projection must still carry them
    // (legacy / foreign writers, defence in depth), so those entries are hand-sealed here exactly as buildEntry would seal
    // them: normalize a masked copy, put the real values back, recompute canonical + hash (CORE_HASH_FIELDS_V7).
    const UNREP_G = /\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
    const mask = (v) => (typeof v === 'string' ? v.replace(UNREP_G, '?') : Array.isArray(v) ? v.map(mask)
      : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [mask(k), mask(x)])) : v);
    const { sortedJSON: sj, domainSeparatedHash: dsh, ARTIFACT_DOMAINS: AD } = require('../../src/infra/crypto/hashing');
    const sealV7 = (fields, prevHash) => {
      const e = { ...entryBuilder.buildEntry(entryBuilder.normalizeFields(mask(fields)), prevHash) };
      for (const k of Object.keys(fields)) if (k in e) e[k] = fields[k];
      const core = {}; for (const f of entryBuilder.CORE_HASH_FIELDS_V7) core[f] = e[f];
      e.canonical = sj(core); e.hash = dsh(AD.AUDIT, e.canonical).toString('hex');
      expect(entryBuilder.verifyCanonicalHash(e)).toBe(true);
      return e;
    };
    const build = (fields, prevHash, mirrorOnly) => (mirrorOnly ? sealV7(fields, prevHash) : entryBuilder.buildEntry(entryBuilder.normalizeFields(fields), prevHash));
    const viaPersist = [];
    const keys = Object.keys({ ...CLS, combined: ALL });
    const write = async (e, mirrorOnly) => {
      expect(mp.encodeString(e.artifactId).length).toBeLessThanOrEqual(128);
      if (mirrorOnly) {
        const r = await pgPool.withTransaction((tx) => backend.insertMirrorRow(tx, e), { isolationLevel: 'READ COMMITTED' });
        expect(r).toEqual({ inserted: true, alreadyPresent: false });
      } else {
        await backend.persistEntry(e);
        viaPersist.push(e.artifactId);
      }
      f6.push(JSON.parse(JSON.stringify(e)));
      prev = e.hash;
    };
    for (let i = 0; i < specs.length; i++) {
      // v7 lifecycle (R-8/R-17): the DECISION names an executingProvider, so its INTENT (same Unicode requestId and
      // executingProvider) precedes it — otherwise a GENESIS walk rightly reports MISSING_INTENT
      const sp = specs[i];
      await write(build({ ...sp, artifactId: entryBuilder.lifecycleArtifactId(sp.artifactId, 'INTENT'), entryType: 'INTENT',
        decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', outputHash: null, reason: null, verificationResult: true, nonce: sp.nonce + ':i' }, prev, MIRROR_ONLY.has(keys[i])), MIRROR_ONLY.has(keys[i]));
      const e = build(sp, prev, MIRROR_ONLY.has(keys[i]));
      if (MIRROR_ONLY.has(keys[i])) {
        const r = await pgPool.withTransaction((tx) => backend.insertMirrorRow(tx, e), { isolationLevel: 'READ COMMITTED' });
        expect(r).toEqual({ inserted: true, alreadyPresent: false });
      } else {
        await backend.persistEntry(e);
        viaPersist.push(e.artifactId);
      }
      f6.push(JSON.parse(JSON.stringify(e)));
      prev = e.hash;
    }
    const byHash = new Map(f6.map((e) => [e.hash, e]));

    // stored form: projected per-field ASCII, marker 1, canonical / hash / prev_hash verbatim
    const rows = (await allRows()).filter((r) => byHash.has(r.hash));
    expect(rows).toHaveLength(f6.length);
    for (const r of rows) {
      const e = byHash.get(r.hash);
      expect({ h: r.hash, enc: r.mirror_encoding, canon: r.canonical === e.canonical, prev: r.prev_hash === e.prevHash }).toEqual({ h: r.hash, enc: 1, canon: true, prev: true });
      for (const c of ['artifact_id', 'reason', 'model', 'request_id', 'organization_id']) if (r[c] !== null) expect({ c, ascii: /^[\x20-\x7e]*$/.test(r[c]) }).toEqual({ c, ascii: true });
      expect(JSON.stringify(r.execution_context)).toMatch(/^[\x20-\x7e]*$/);
      expect(r.artifact_id).toBe(mp.encodeString(e.artifactId));
    }

    // production readers: full, batch, by artifact id, chainStore evidence lookup, replay lineage
    const loaded = (await backend.loadChainFromPg()).filter((x) => byHash.has(x.hash));
    const batch = []; for (let seq = 0; ;) { const b = await backend.fetchChainBatch(seq, 500); if (!b.length) break; batch.push(...b.filter((x) => byHash.has(x.hash))); seq = b[b.length - 1].seq; }
    for (const [who, list] of [['loadChainFromPg', loaded], ['fetchChainBatch', batch]]) {
      expect(list).toHaveLength(f6.length);
      for (const x of list) {
        const e = byHash.get(x.hash);
        expect({ who, v: logical(x) }).toEqual({ who, v: logical(e) });
        // HASH INVARIANCE: canonical recomputed from the decoded fields === stored canonical === original
        const core = {}; for (const f of entryBuilder.CORE_HASH_FIELDS_V7) core[f] = x[f];
        expect({ who, canon: require('../../src/infra/crypto/hashing').sortedJSON(core) === e.canonical, hash: entryBuilder.expectedHashFor(x) === e.hash, ok: entryBuilder.verifyCanonicalHash(x) }).toEqual({ who, canon: true, hash: true, ok: true });
      }
    }
    for (const e of f6) {
      const byId = await backend.queryByArtifactId(e.artifactId);
      expect({ id: e.artifactId, v: byId && logical({ ...byId, prevHash: byId.prevHash }) }).toEqual({ id: e.artifactId, v: logical(e) });
    }
    // chainStore.verifyEvidence() reads the audit row through its own PG lookup (decoded at that boundary): every evidence
    // record written for these entries verifies VALID, i.e. the decoded row reproduces the audit hash the record binds.
    const chainStore = require('../../src/core/evidence/chainStore');
    const ev = (await owner.query('SELECT evidence_id, artifact_id FROM evidence_chain_records WHERE artifact_id = ANY($1)', [viaPersist])).rows;
    expect(ev.map((r) => r.artifact_id).sort()).toEqual([...viaPersist].sort());
    for (const r of ev) {
      const v = await chainStore.verifyEvidence(r.evidence_id);
      expect({ id: r.artifact_id, result: v.result, failed: (v.steps || []).filter((s) => s.result === 'FAIL').map((s) => s.step) }).toEqual({ id: r.artifact_id, result: 'VALID', failed: [] });
    }
    const all = await backend.loadChainFromPg();
    const auditLog = require('../../src/core/audit/audit-log');
    expect(auditLog.verifyAuditChainDetailed(all)).toMatchObject({ valid: true, entriesVerified: all.length });

    // independent verifier over the raw SELECT * rows (its own P⁻¹)
    const raw = await allRows();
    const indepEntries = contract.orderPgRows(raw).ordered.map(contract.entryFromPgRow);
    expect(contract.walkChain(indepEntries)).toMatchObject({ valid: true, entriesVerified: raw.length });
    for (const ie of indepEntries.filter((x) => byHash.has(x.hash))) expect(logical(ie)).toEqual(logical(byHash.get(ie.hash)));
    const rep = verify.verify({ audit: writeJson('cc08-rows.json', raw), format: 'pg-json' });
    expect(rep.verdict).toBe('VALID');

    // S3: compact readers decode artifactId; the full divergence comparison sees 0 violations against the logical chain
    const { _compactForDivergence, createChainVerifier } = require('../../src/core/audit/verifier/ChainVerifier');
    const compactPg = await backend.loadChainFromPgCompact(_compactForDivergence);
    const compactPaged = []; await backend.forEachChainPageCompactInSnapshot(_compactForDivergence, { onPage: (p) => { compactPaged.push(...p); } });
    const compactFile = indepEntries.map(_compactForDivergence);
    expect(compactPg).toEqual(compactFile);
    expect(compactPaged.map((c) => c.hash).sort()).toEqual(compactFile.map((c) => c.hash).sort());
    for (const c of compactPg.filter((x) => byHash.has(x.hash))) expect(c.artifactId).toBe(byHash.get(c.hash).artifactId);
    const fakeLog = { ORDERING_MODE: 'single-node', getModernChain: async () => indepEntries };
    const cv = createChainVerifier({ _auditLog: fakeLog, _pgBackend: backend, _emit: () => {} });
    const div = await cv.verifyPgDivergence('MANUAL');
    expect({ success: div.success, violations: div.violations }).toEqual({ success: true, violations: [] });
    // positive control: a projected per-field value (artifact_id) rewritten to another VALID projection.
    //  - S3 semantics are unchanged by it compares hash / prevHash / canonical (artifactId is only a secondary
    //    correlation key \u2014 mirrorConsistencyCheck.js crossValidateRecords), so this alone is not a divergence there;
    //  - the tamper IS caught where per-field values are bound: entry verification of the decoded row (production) and
    //    the independent verifier both fail at that entry, because the decoded fields no longer reproduce canonical.
    const victim = rows[Math.floor(rows.length / 2)];
    await owner.query('UPDATE audit_chain SET artifact_id = $1 WHERE hash = $2', [mp.encodeString('tampered-\u0219'), victim.hash]);
    try {
      const div2 = await createChainVerifier({ _auditLog: fakeLog, _pgBackend: backend, _emit: () => {} }).verifyPgDivergence('MANUAL');
      expect(div2.violations).toEqual([]);
      const tamperedChain = await backend.loadChainFromPg();
      const at = tamperedChain.findIndex((x) => x.hash === victim.hash);
      expect(tamperedChain[at].artifactId).toBe('tampered-\u0219');                               // decoded, not the stored ASCII
      expect(auditLog.verifyAuditChainDetailed(tamperedChain)).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', offendingIndex: at });
      const iw = contract.walkChain(contract.orderPgRows(await allRows()).ordered.map(contract.entryFromPgRow));
      expect(iw).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', failure: { index: at } });
    } finally {
      await owner.query('UPDATE audit_chain SET artifact_id = $1 WHERE hash = $2', [victim.artifact_id, victim.hash]);
    }
  });

  test('CC-09 legacy native rows verify as stored; altered / corrupt / unknown-marker rows fail explicitly', async () => {
    const { sortedJSON, domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../src/infra/crypto/hashing');
    const seal = (e) => { const core = {}; for (const f of entryBuilder.CORE_HASH_FIELDS_V6) core[f] = e[f]; const canonical = sortedJSON(core); return { ...e, canonical, hash: domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex') }; };
    const legacyInsert = (e, enc) => o5.query(`INSERT INTO audit_chain (hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time, input_hash, signature, request_hash, policy_hash,
      verification_result, schema_version, consent_provenance, policy_decision, caller_context, provider, model, stage, reason, semantic, token_usage, response_id${enc === undefined ? '' : ', mirror_encoding'})
      VALUES ($1,$2,$3,$4,$5,$6,'1',$7,$8,$9,$10,$11,6,NULL,NULL,NULL,NULL,NULL,NULL,$12,NULL,NULL,NULL${enc === undefined ? '' : ', $13'})`,
      [e.hash, e.prevHash, e.canonical, e.artifactId, e.decision, new Date(e.timestamp), e.inputHash, e.signature, e.requestHash, e.policyHash, e.verificationResult, e.reason, ...(enc === undefined ? [] : [enc])]);
    const v6 = (prevHash, id, reason) => seal({ artifactId: id, decision: 'BLOCK', inputHash: 'a'.repeat(64), policyHash: 'c'.repeat(64), prevHash, requestHash: 'b'.repeat(64), signature: 's', timestamp: new Date().toISOString(), verificationResult: false,
      publicKeyId: null, schemaVersion: 6, consentProvenance: null, policyDecision: null, callerContext: null, provider: null, model: null, stage: null, reason, semantic: null, tokenUsage: null, responseId: null });
    const sp = path.join(tmp, 'cc09');
    const DB4 = `${DB}_l`;
    await freshDb(DB4);
    const o5 = new Pool({ ...base(), database: DB4, user: TEST_USER, password: TEST_PW });
    const rowsOf = async () => (await o5.query('SELECT * FROM audit_chain ORDER BY seq')).rows;
    const walkIndep = (rs) => contract.walkChain(contract.orderPgRows(rs).ordered.map(contract.entryFromPgRow));
    try {
      const prodWalk = (rs) => {
        const mp = require('../../src/infra/postgres/mirrorProjection');
        const entries = contract.orderPgRows(rs).ordered.map((r) => {
          const camel = { hash: r.hash, prevHash: r.prev_hash, canonical: r.canonical, mirrorEncoding: r.mirror_encoding };
          for (const f of PER_TEXT) camel[f] = r[f.replace(/[A-Z]/g, (m) => '_' + m.toLowerCase())] ?? null;
          for (const f of PER_JSON) camel[f] = r[f.replace(/[A-Z]/g, (m) => '_' + m.toLowerCase())] ?? null;
          const d = mp.decodeMirrorRow(camel, r.hash);
          return { ...d, schemaVersion: r.schema_version, timestamp: JSON.parse(r.canonical).timestamp, verificationResult: r.verification_result };
        });
        return require('../../src/core/audit/audit-log').verifyAuditChainDetailed(entries);
      };
      // 1. native legacy rows (column default 0, never back-filled), one holding text that LOOKS escaped — read as stored
      const a = v6('GENESIS', 'legacy-1', String.raw`literal \u00e9 and \\ stays`);
      const b = v6(a.hash, 'legacy-é-2', 'résumé');
      await legacyInsert(a); await legacyInsert(b, 0);
      let rs = await rowsOf();
      expect(rs.map((r) => r.mirror_encoding)).toEqual([0, 0]);
      expect(walkIndep(rs)).toMatchObject({ valid: true, entriesVerified: 2 });
      expect(prodWalk(rs)).toMatchObject({ valid: true, entriesVerified: 2 });
      // 2. a native row whose lone surrogate PostgreSQL TEXT altered: explicit verification failure, nothing rewritten
      const c = v6(b.hash, 'legacy-3', 'lone \ud800 here');
      await legacyInsert(c, 0);
      rs = await rowsOf();
      expect(rs[2].reason).not.toBe(c.reason);                                  // PG stored it altered (the probe)
      expect(walkIndep(rs)).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', failure: { index: 2 } });
      expect(prodWalk(rs)).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', offendingIndex: 2 });
      await o5.query("DELETE FROM audit_chain WHERE artifact_id = 'legacy-3'");   // this test's own fixture row, disposable DB
      // 3. a projected row with a corrupt escape / an unknown marker: refused by both decoders, never guessed
      const mp = require('../../src/infra/postgres/mirrorProjection');
      const d = v6(b.hash, 'legacy-4', 'ok');
      await legacyInsert({ ...d, artifactId: mp.encodeString(d.artifactId), reason: String.raw`bad \x escape` }, 1);
      rs = await rowsOf();
      expect(walkIndep(rs)).toMatchObject({ valid: false, reason: 'AUDIT_CHAIN_TAMPERED', failure: { index: 2, detail: 'MIRROR_DECODE_ERROR' } });
      expect(() => prodWalk(rs)).toThrow(mp.MirrorDecodeError);
      await o5.query("UPDATE audit_chain SET reason = 'ok', mirror_encoding = 7 WHERE artifact_id = 'legacy-4'");
      rs = await rowsOf();
      expect(walkIndep(rs)).toMatchObject({ valid: false, failure: { index: 2, detail: 'MIRROR_DECODE_ERROR' } });
      expect(() => prodWalk(rs)).toThrow(/unknown mirror_encoding/);
      await o5.query("UPDATE audit_chain SET mirror_encoding = 1 WHERE artifact_id = 'legacy-4'");
      rs = await rowsOf();
      expect(walkIndep(rs)).toMatchObject({ valid: true, entriesVerified: 3 });   // a correct projection verifies
      expect(prodWalk(rs)).toMatchObject({ valid: true, entriesVerified: 3 });
    } finally {
      await o5.end();
      await dropDb(DB4);
      void sp;
    }
  });
});

function writeJson(name, data) { const p = path.join(tmp, name); fs.writeFileSync(p, JSON.stringify(data)); return p; }
