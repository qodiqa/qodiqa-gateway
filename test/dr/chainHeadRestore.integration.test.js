'use strict';

/**
 * — DR JSON restore left the chain-head pointer rows at the
 * target's genesis seed, so the first append after recovery forked the evidence / transparency chains.
 *
 * scripts/dr/postgres.js restored every row with `INSERT … ON CONFLICT DO NOTHING`. A freshly migrated target already
 * holds the singleton rows of audit_chain_head (migration 026) and evidence_chain_head / transparency_log_head /
 * transparency_roots_head (migration 042) at genesis, so the backed-up heads were SKIPPED while the ledgers were
 * restored. The production append paths read the previous hash ONLY from these heads (distributedOrdering.js,
 * chainStore.js, registrar.register()/generateRoot()), so the next entry chained from genesis.
 *
 *   CH-01 restore → every head equals the source head; then appends through the PRODUCTION paths (distributed
 *         audit append + its evidence record, registrar.register, registrar.generateRoot) continue each chain from
 *         the restored tail — no second genesis — and the production chain walk, the evidence range verifier, the
 * independent verifier (qodiqa-audit-verify) and the DR postgres probe all report VALID; dr:verify
 *         reports the backup VALID.
 * CH-02 the same backup with encryption on: no plaintext pg_*.json in the backup, restore + heads intact.
 *
 * Proof the test catches the defect: run with QODIQA_DD_DR_IMPL_DIR pointing at a copy of the pre-fix scripts/dr
 *. Normal runs use scripts/dr.
 *
 * Real PostgreSQL only (QODIQA_PG_ENABLED=true; locally via, i.e. the
 * disposable qodiqa-er-pg). Databases: qodiqa_dd_chainhead_{src,tgt,tgt2}_<run>, dropped in afterAll unless
 * QODIQA_DD_KEEP_DBS=1 (then they are left for the owner and listed on stdout).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder');
const { trackInFlight } = require('../helpers/inFlight');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(240_000);

const DR = process.env.QODIQA_DD_DR_IMPL_DIR ? path.resolve(process.env.QODIQA_DD_DR_IMPL_DIR) : path.join(__dirname, '..', '..', 'scripts', 'dr');
const RUN = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const DB = { src: `qodiqa_dd_chainhead_src_${RUN}`, tgt: `qodiqa_dd_chainhead_tgt_${RUN}`, tgt2: `qodiqa_dd_chainhead_tgt2_${RUN}` };
const KEYS = { // throwaway, test-only, random per run
  QODIQA_BACKUP_ENCRYPTION_KEY: `dd003-test-enc-${crypto.randomBytes(16).toString('hex')}`,
  QODIQA_BACKUP_HMAC_KEY: `dd003-test-mac-${crypto.randomBytes(16).toString('hex')}`,
};
const tmpDir = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));

function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) saved[k] = process.env[k];
  for (const [k, v] of Object.entries(env)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  return Promise.resolve().then(fn).finally(() => {
    for (const k of Object.keys(env)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  });
}

describeOrSkip('DR restore keeps chain heads; appends continue the restored chains (real PostgreSQL)', () => {
  const host = process.env.QODIQA_PG_HOST || 'localhost';
  const port = parseInt(process.env.QODIQA_PG_PORT || '5432', 10);
  const url = (db, user, password) => { const u = new URL(`postgresql://${host}:${port}/${db}`); u.username = user; u.password = password; return u.toString(); };
  const asTest = (db) => url(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
  const asApp = (db) => url(db, process.env.QODIQA_PG_USER || 'qodiqa_app', process.env.QODIQA_PG_PASSWORD || '');
  const asBackup = (db) => url(db, 'qodiqa_backup', process.env.QODIQA_PG_BACKUP_PASSWORD || 'REPLACE_WITH_VAULT_SECRET_BACKUP');
  let maint;
  const created = [];
  let srcHeads; let srcTails; let backupDir; let backupEncDir;

  async function q(db, sql, params) {
    const p = new Pool({ connectionString: asTest(db), max: 1 });
    try { return (await p.query(sql, params)).rows; } finally { await p.end(); }
  }
  const heads = async (db) => ({
    audit: (await q(db, 'SELECT tail_hash, tail_seq FROM audit_chain_head'))[0],
    evidence: (await q(db, 'SELECT tail_hash, tail_id FROM evidence_chain_head'))[0],
    tlog: (await q(db, 'SELECT tail_hash, tail_id FROM transparency_log_head'))[0],
    roots: (await q(db, 'SELECT tail_hash, tail_id FROM transparency_roots_head'))[0],
  });
  const norm = (h) => JSON.parse(JSON.stringify(h, (k, v) => (typeof v === 'string' ? v.trim() : v)));

  /** Run fn with the production modules bound to `db` as the app role, distributed audit ordering. */
  async function asApplication(db, fn) {
    return withEnv({ QODIQA_PG_URL: asApp(db), QODIQA_PG_ENABLED: 'true', QODIQA_AUDIT_ORDERING_MODE: 'distributed' }, async () => {
      jest.resetModules();
      const pool = require('../../src/infra/postgres/pool');
      pool.initialize();
      const evidenceWrites = trackInFlight(require('../../src/infra/postgres/pg-audit-backend'), 'recordEvidenceForEntry');
      try {
        return await fn({
          auditLog: require('../../src/core/audit/audit-log.js'),
          registrar: require('../../src/core/transparency/registrar'),
          chainStore: require('../../src/core/evidence/chainStore'),
          keyStore: require('../../src/core/transparency/transparencyKeyStore'),
        });
      } finally {
        await evidenceWrites.settle();
        evidenceWrites.restore();
        await pool.shutdown();
      }
    });
  }

  async function appendAll(m, n, prefix) {
    for (let i = 0; i < n; i++) {
      await m.auditLog.append({
        artifactId: `${prefix}-${i}-${crypto.randomUUID()}`, inputHash: 'a'.repeat(64), decision: i % 3 ? 'ALLOW' : 'BLOCK',
        outputHash: EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true,
      });
      await m.registrar.register({ entryType: 'SYSTEM', payload: { prefix, i } });
    }
    await m.registrar.generateRoot();
  }

  async function backup(db, extraEnv) {
    const policyStore = path.join(tmpDir('qodiqa-dd003-ps-'), 'policy-store.json');
    fs.writeFileSync(policyStore, JSON.stringify({ version: 1, policies: {} }, null, 2));
    return withEnv({
      QODIQA_AUDIT_ORDERING_MODE: 'distributed', QODIQA_PG_URL: asBackup(db), QODIQA_POLICY_STORE: policyStore,
      QODIQA_AUDIT_LOG: path.join(tmpDir('qodiqa-dd003-nolog-'), 'audit.log'), ...extraEnv,
    }, () => { jest.resetModules(); return require(path.join(DR, 'backup')).runBackup({ outDir: path.join(tmpDir('qodiqa-dd003-bk-'), 'b'), includePostgres: true, postgresFormat: 'json-rows' /* this suite's subject is the JSON-rows layer's head restore */ }); });
  }

  async function restore(dir, db, extraEnv = {}) {
    return withEnv(extraEnv, () => {
      jest.resetModules();
      return require(path.join(DR, 'restore')).runRestore({
        backupDir: dir, targetRoot: path.join(tmpDir('qodiqa-dd003-rs-'), 'r'), pgConnectionString: asTest(db), erasureLedger: asTest(DB.src),
      });
    });
  }

  beforeAll(async () => {
    for (const d of Object.values(DB)) if (!/^[a-z][a-z0-9_]{0,62}$/.test(d)) throw new Error(`unsafe db name ${d}`);
    maint = new Pool({ connectionString: asTest('postgres'), max: 1 });
    for (const d of Object.values(DB)) {
      await maint.query(`CREATE DATABASE "${d}"`); created.push(d);
      const mp = new Pool({ connectionString: asTest(d) });
      try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: mp }); } finally { await mp.end(); }
    }
    // Source history through the production paths: 12 audit entries (+ their evidence records), 12 transparency
    // leaves, then a signed root — and a second batch + root, so every ledger has a multi-row tail.
    await asApplication(DB.src, async (m) => { await appendAll(m, 6, 'src-a'); await appendAll(m, 6, 'src-b'); });
    srcHeads = norm(await heads(DB.src));
    srcTails = {
      audit: (await q(DB.src, 'SELECT hash, seq FROM audit_chain ORDER BY seq DESC LIMIT 1'))[0],
      evidence: (await q(DB.src, 'SELECT evidence_hash, id FROM evidence_chain_records ORDER BY id DESC LIMIT 1'))[0],
      tlog: (await q(DB.src, 'SELECT entry_hash, id FROM transparency_log_entries ORDER BY id DESC LIMIT 1'))[0],
      roots: (await q(DB.src, 'SELECT root_hash, id FROM transparency_roots ORDER BY id DESC LIMIT 1'))[0],
    };
    ({ targetDir: backupDir } = await backup(DB.src, {}));
    ({ targetDir: backupEncDir } = await backup(DB.src, KEYS));
  });

  afterAll(async () => {
    if (!maint) return;
    if (process.env.QODIQA_DD_KEEP_DBS === '1') {
      console.log(` databases left in place for the owner: ${created.join(', ')}`); // eslint-disable-line no-console
    } else {
      for (const d of created) {
        try { await maint.query(`DROP DATABASE IF EXISTS "${d}" WITH (FORCE)`); } catch (e) { console.warn(` drop ${d}: ${e.message}`); } // eslint-disable-line no-console
      }
    }
    await maint.end();
  });

  test('CH-01 restore restores all four heads; production appends continue each chain; every verifier says VALID', async () => {
    // Sanity: the source chains really are past genesis.
    expect(Number(srcHeads.audit.tail_seq)).toBe(12);
    expect(Number(srcHeads.evidence.tail_id)).toBeGreaterThanOrEqual(12);
    expect(Number(srcHeads.tlog.tail_id)).toBe(12);
    expect(Number(srcHeads.roots.tail_id)).toBe(2);
    expect(norm(await heads(DB.tgt))).toEqual({
      audit: { tail_hash: 'GENESIS', tail_seq: '0' }, evidence: { tail_hash: null, tail_id: '0' },
      tlog: { tail_hash: null, tail_id: '0' }, roots: { tail_hash: null, tail_id: '0' },
    });

    const res = await restore(backupDir, DB.tgt);
    expect(res.auditChainCheck.valid).toBe(true);

    // (1) the heads are the source heads — the defect left all four at genesis.
    expect(norm(await heads(DB.tgt))).toEqual(srcHeads);

    // (2) append through the production paths on the restored database.
    await asApplication(DB.tgt, (m) => appendAll(m, 2, 'post-restore'));

    const firstNewAudit = (await q(DB.tgt, 'SELECT prev_hash, seq FROM audit_chain WHERE seq = $1', [Number(srcTails.audit.seq) + 1]))[0];
    expect(firstNewAudit.prev_hash.trim()).toBe(srcTails.audit.hash.trim());
    const firstNewEvidence = (await q(DB.tgt, 'SELECT previous_evidence_hash FROM evidence_chain_records WHERE id > $1 ORDER BY id LIMIT 1', [srcTails.evidence.id]))[0];
    expect(firstNewEvidence.previous_evidence_hash).toBe(srcTails.evidence.evidence_hash);
    const firstNewLeaf = (await q(DB.tgt, 'SELECT previous_entry_hash FROM transparency_log_entries WHERE id > $1 ORDER BY id LIMIT 1', [srcTails.tlog.id]))[0];
    expect(firstNewLeaf.previous_entry_hash).toBe(srcTails.tlog.entry_hash);
    const newRoot = (await q(DB.tgt, 'SELECT previous_root_hash, seq_from FROM transparency_roots WHERE id > $1 ORDER BY id LIMIT 1', [srcTails.roots.id]))[0];
    expect(newRoot.previous_root_hash).toBe(srcTails.roots.root_hash);
    expect(Number(newRoot.seq_from)).toBe(Number(srcTails.tlog.id) + 1);

    // (3) exactly one genesis per ledger.
    expect((await q(DB.tgt, "SELECT count(*)::int n FROM audit_chain WHERE prev_hash = 'GENESIS'"))[0].n).toBe(1);
    expect((await q(DB.tgt, 'SELECT count(*)::int n FROM evidence_chain_records WHERE previous_evidence_hash IS NULL'))[0].n).toBe(1);
    expect((await q(DB.tgt, 'SELECT count(*)::int n FROM transparency_log_entries WHERE previous_entry_hash IS NULL'))[0].n).toBe(1);
    expect((await q(DB.tgt, 'SELECT count(*)::int n FROM transparency_roots WHERE previous_root_hash IS NULL'))[0].n).toBe(1);

    // (4) verifiers.
    jest.resetModules();
    const { verifyAuditChainIntegrity } = require('../../scripts/dr/validate');
    const walk = verifyAuditChainIntegrity({ mode: 'distributed', connectionString: asTest(DB.tgt) });
    expect(walk).toMatchObject({ valid: true, chainValid: true, chainLength: 14, tamperingDetected: false });

    const evid = await asApplication(DB.tgt, async (m) => {
      const n = (await q(DB.tgt, 'SELECT max(id)::int m FROM evidence_chain_records'))[0].m;
      return m.chainStore.verifyChainRange({ startId: 1, endId: n, limit: 1000 });
    });
    expect(evid).toMatchObject({ valid: true });

    const keys = await asApplication(DB.tgt, async (m) => ({ keys: m.keyStore.listKeys().map((k) => ({ keyId: k.keyId, algorithm: 'ed25519', publicKey: k.publicKeyB64, status: k.status })) }));
    const work = tmpDir('qodiqa-dd003-iv-');
    fs.writeFileSync(path.join(work, 'audit.json'), JSON.stringify(await q(DB.tgt, 'SELECT * FROM audit_chain ORDER BY seq')));
    fs.writeFileSync(path.join(work, 'tle.json'), JSON.stringify(await q(DB.tgt, 'SELECT * FROM transparency_log_entries ORDER BY id')));
    fs.writeFileSync(path.join(work, 'roots.json'), JSON.stringify(await q(DB.tgt, 'SELECT * FROM transparency_roots ORDER BY id')));
    fs.writeFileSync(path.join(work, 'keys.json'), JSON.stringify(keys));
    const { verify } = require('../../scripts/audit-repro/verify/qodiqa-audit-verify');
    const ivAudit = verify({ audit: path.join(work, 'audit.json'), format: 'pg-json' });
    expect(ivAudit.audit).toMatchObject({ valid: true });
    expect(ivAudit.audit.pgRows).toBe(14);
    const ivTr = verify({ transparency: path.join(work, 'tle.json'), roots: path.join(work, 'roots.json'), keys: path.join(work, 'keys.json') });
    expect(ivTr.transparency.valid).toBe(true);
    expect(ivTr.transparency.entries).toHaveLength(14);
    expect(ivTr.transparency.roots).toHaveLength(3);

    const probe = await require('../../scripts/dr/probes/postgresProbe').validatePostgresRestore(null, {});
    expect(probe.skipped).toBe(true); // contract unchanged for "no PG component"
    const { chainHeadReport } = require('../../scripts/dr/chainHeads');
    const p = new Pool({ connectionString: asTest(DB.tgt), max: 1 });
    try {
      const rep = await chainHeadReport(p, { auditOrderingMode: 'distributed' });
      expect(rep.valid).toBe(true);
      expect(rep.heads.map((h) => [h.table, h.consistent])).toEqual([
        ['audit_chain_head', true], ['evidence_chain_head', true], ['transparency_log_head', true], ['transparency_roots_head', true]]);
    } finally { await p.end(); }

    const { verifyBackup } = require('../../scripts/dr/verify');
    const v = verifyBackup(backupDir);
    expect(v.errors).toEqual([]);
    expect(v.valid).toBe(true);
  });

  test('CH-02 encrypted DR backup: no plaintext table archive; restore verifies the seal and keeps the heads', async () => {
    const files = fs.readdirSync(backupEncDir);
    expect(files.filter((f) => /^pg_.*\.json$/.test(f))).toEqual([]);
    expect(files.filter((f) => /^pg_.*\.json\.enc$/.test(f)).length).toBeGreaterThan(60);
    expect(files).toContain('manifest.json.seal');
    jest.resetModules();
    const v = await withEnv(KEYS, () => require('../../scripts/dr/verify').verifyBackup(backupEncDir));
    expect(v.errors).toEqual([]);
    await expect(restore(backupEncDir, DB.tgt2, {})).rejects.toMatchObject({ code: 'BACKUP_KEYS_MISSING' });
    const res = await restore(backupEncDir, DB.tgt2, KEYS);
    expect(res.auditChainCheck.valid).toBe(true);
    expect(res.postgres.chainHeads.valid).toBe(true);
    expect(norm(await heads(DB.tgt2))).toEqual(srcHeads);
    // the restore re-established (pg_dump path) or verified (JSON path) SECURITY DEFINER ownership
    expect(res.postgres.definerOwnership).toMatchObject({ owner: 'qodiqa_definer', definers: 47 });
  });
});
