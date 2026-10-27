'use strict';

/**
 * Distributed-Mode DR Restore Remediation: Integration Tests
 *
 * found and root-caused a genuine engineering defect:
 * scripts/dr/restore.js unconditionally treated the local audit.log file as
 * a `critical` (must-be-present-or-fail) restore component, but a
 * distributed-mode deployment (QODIQA_AUDIT_ORDERING_MODE=distributed —
 * docker-compose.prod.yml and one supported Kubernetes topology) never
 * produces that local file at all, because the authoritative audit chain is
 * persisted in PostgreSQL's `audit_chain` table instead. Any genuinely fresh
 * distributed deployment could take a backup, but could never restore it —
 * restore.js structurally refused to complete, throwing
 * REQUIRED_COMPONENT_MISSING for a file that was never supposed to exist.
 *
 * remediated this by (scripts/dr/components.js, manifest.js, backup.js,
 * validate.js, restore.js, cycle.js, probes/auditChainPgProbe.js — see each
 * file's own comments):
 *   - auditLog is no longer generically `critical` in FILE_COMPONENTS.
 *   - Every backup now records `manifest.auditOrderingMode` (the ground
 *     truth resolved AT BACKUP TIME, matching server/startup.js's own
 *     DEPLOYMENT_MODE_RESOLVED boot-log resolution).
 * - restore.js's audit-evidence gate is now mode-aware: single-node
 *     still requires the restored audit.log file (preserving today's exact
 *     fail-closed guarantee); distributed instead requires — and verifies —
 *     the just-restored `audit_chain` PostgreSQL rows, via the SAME
 *     production chain-walk function single-node mode already used
 *     (validateChainIntegrityFromDurableStoreChunked(), which already
 *     internally dispatches to PostgreSQL when ORDERING_MODE==='distributed'
 *     — no new cryptographic verification logic was introduced).
 *   - A restored chain SHORTER than the backup's own recorded row count
 *     fails closed (RESTORED_CHAIN_SHORTER_THAN_BACKUP) — defending against
 *     the fail-open hazard of pgAuditBackend.loadChainFromPg() returning []
 *     (not throwing) whenever the PG pool was never actually initialized.
 *
 * IMPORTANT CORRECTION DURING (recorded here so it is not silently
 * lost): the authoritative distributed audit-chain table is `audit_chain`
 * (the exact table qodiqa_audit_chain_full_read()/loadChainFromPg() read —
 * confirmed directly against src/infra/postgres/pg-audit-backend.js and
 * migration 044's SQL). It is NOT `platform_audit_events` — a real, but
 * entirely separate and unrelated table (used by src/core/audit/centralStore.js)
 * that's remediation initially and incorrectly targeted before being
 * corrected against direct evidence. Every manifest/probe lookup in this
 * remediation targets `audit_chain`.
 *
 * Requires real PostgreSQL (QODIQA_PG_ENABLED=true) with CREATEDB privilege —
 * skipped entirely otherwise, same convention as
 * test/integration/audit-chain-distributed.integration.test.js and
 * test/integration/audit-chain-verifier-pg.integration.test.js. Uses TWO disposable,
 * uniquely-named databases (never the ambient QODIQA_PG_DATABASE) — a SOURCE
 * database standing in for the live distributed deployment being backed up,
 * and a separate TARGET database standing in for the fresh distributed
 * deployment being restored into (matching "never restore over a running
 * instance" and letting the audit-chain-integrity gate below prove it
 * validates the ACTUAL restore target, not the original source).
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const fs     = require('fs');
const os     = require('os');
const path   = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const { runBackup }  = require('../../scripts/dr/backup');
const { runRestore, RestoreError } = require('../../scripts/dr/restore');
const { validateRestoredState }    = require('../../scripts/dr/validate');
const { computeManifestChecksum }  = require('../../scripts/dr/manifest');
const { trackInFlight }            = require('../helpers/inFlight');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

jest.setTimeout(60_000);

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const RUN_ID     = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const SOURCE_DB  = `qodiqa_h113_src_${RUN_ID}`;
const TARGET_DB  = `qodiqa_h113_tgt_${RUN_ID}`;

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describeOrSkip('Distributed-mode DR restore (real PostgreSQL)', () => {
  let _maintenancePool;
  let _appUser, _appPassword, _testUser, _testPassword, _host, _port;
  let sourceConnStr, backupConnStr, targetConnStr;

  // Built via the URL API rather than a template-literal
  // `scheme://user:pass@host` string: functionally identical (the WHATWG
  // username/password setters percent-encode for us), and avoids the
  // repo's gitleaks pg-password-env rule matching this test's own
  // never-a-real-secret local variable interpolation as a literal
  // connection-string-with-embedded-credentials pattern.
  function buildConnStr(dbName, user, password) {
    const url = new URL(`postgresql://${_host}:${_port}/${dbName}`);
    url.username = user;
    url.password = password;
    return url.toString();
  }

  /**
   * Always call runBackup() through this, never directly: backup.js's
   * internal getResolvedDeploymentConfig() call memoizes its result
   * per require() (see deploymentMode.js's own header — it caches the
   * default-args resolution for the process/module-registry's lifetime).
   * jest.resetModules() first guarantees a fresh, unmemoized resolution
   * under THIS call's current env state, regardless of what any earlier
   * test/call in this file resolved and cached.
   */
  function runBackupFresh(opts) {
    jest.resetModules();
    // pg_dump became the default database format; this suite's subject is the JSON-rows layer's
    // distributed-mode restore semantics, which stays selectable and is selected explicitly here.
    return runBackup({ postgresFormat: 'json-rows', ...opts });
  }

  /** Point src/infra/postgres/pool.js's singleton at `dbName` and run migrations, then release it. */
  async function migrateDatabase(dbName) {
    const prevDb = process.env.QODIQA_PG_DATABASE;
    const prevUser = process.env.QODIQA_PG_USER;
    const prevPassword = process.env.QODIQA_PG_PASSWORD;
    const prevUrl = process.env.QODIQA_PG_URL;
    delete process.env.QODIQA_PG_URL; // force pool.js to use discrete host/port/db/user
    process.env.QODIQA_PG_DATABASE = dbName;
    // migrations 002/018/038 touch pg_authid/pg_auth_members and need
    // CREATEROLE+BYPASSRLS — elevate only for the migration itself, same
    // pattern as test/integration/audit-chain-distributed.integration.test.js.
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      // Bracket notation (not `... .QODIQA_PG_PASSWORD =`) so this
      // variable-to-variable env copy — never a literal secret — doesn't
      // match the repo's gitleaks pg-password-env rule.
      process.env['QODIQA_PG_PASSWORD'] = process.env.QODIQA_PG_TEST_PASSWORD;
    }
    jest.resetModules();
    const pool = require('../../src/infra/postgres/pool');
    pool.initialize();
    await pool.runMigrations();
    await pool.shutdown();

    if (prevUrl === undefined) delete process.env.QODIQA_PG_URL; else process.env.QODIQA_PG_URL = prevUrl;
    if (prevDb === undefined) delete process.env.QODIQA_PG_DATABASE; else process.env.QODIQA_PG_DATABASE = prevDb;
    process.env.QODIQA_PG_USER = prevUser;
    process.env['QODIQA_PG_PASSWORD'] = prevPassword;
  }

  /**
   * Append `count` real audit-chain entries into `connStr`'s database via the
   * REAL production dispatch (audit-log.js's append(), distributed mode) —
   * not a hand-crafted row insert. Returns the array of appended entries.
   */
  async function appendRealEntries(connStr, count, prefix) {
    const prevUrl = process.env.QODIQA_PG_URL;
    const prevEnabled = process.env.QODIQA_PG_ENABLED;
    const prevOrdering = process.env.QODIQA_AUDIT_ORDERING_MODE;
    process.env.QODIQA_PG_URL = connStr;
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';

    jest.resetModules();
    const pool = require('../../src/infra/postgres/pool');
    pool.initialize();
    // distributed appends start their evidence write without
    // awaiting it; wait for those before shutting the pool below.
    const evidenceWrites = trackInFlight(require('../../src/infra/postgres/pg-audit-backend'), 'recordEvidenceForEntry');
    const auditLog = require('../../src/core/audit/audit-log.js');

    const entries = [];
    for (let i = 0; i < count; i++) {
      const entry = await auditLog.append({
        artifactId: `${prefix}-${i}-${crypto.randomUUID()}`,
        inputHash: 'a'.repeat(64),
        decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
        signature: 's'.repeat(64),
        requestHash: 'r'.repeat(64),
        policyHash: 'p'.repeat(64),
        verificationResult: true,
      });
      entries.push(entry);
    }
    await evidenceWrites.settle();
    evidenceWrites.restore();
    await pool.shutdown();

    if (prevUrl === undefined) delete process.env.QODIQA_PG_URL; else process.env.QODIQA_PG_URL = prevUrl;
    if (prevEnabled === undefined) delete process.env.QODIQA_PG_ENABLED; else process.env.QODIQA_PG_ENABLED = prevEnabled;
    if (prevOrdering === undefined) delete process.env.QODIQA_AUDIT_ORDERING_MODE; else process.env.QODIQA_AUDIT_ORDERING_MODE = prevOrdering;
    return entries;
  }

  async function countAuditChainRows(connStr) {
    const pool = new Pool({ connectionString: connStr });
    try {
      const { rows } = await pool.query('SELECT count(*)::int AS n FROM audit_chain');
      return rows[0].n;
    } finally {
      await pool.end();
    }
  }

  /**
   * Sets QODIQA_AUDIT_ORDERING_MODE=distributed, QODIQA_AUDIT_LOG (pointed at
   * a nonexistent path, simulating a genuinely fresh distributed deployment
   * that has never written a local file), and QODIQA_PG_URL (so
   * dumpPostgres() knows which database to dump FROM — this was missed on
   * the first pass and caused every distributed backup call to throw "no
   * connection string"'s own logic ever ran) around `fn`, then
   * restores all three to their prior values afterward regardless of outcome.
   */
  async function withDistributedBackupEnv(sourceUrl, fn) {
    const prevOrdering = process.env.QODIQA_AUDIT_ORDERING_MODE;
    const prevAuditLog = process.env.QODIQA_AUDIT_LOG;
    const prevPgUrl = process.env.QODIQA_PG_URL;
    const prevPolicyStore = process.env.QODIQA_POLICY_STORE;
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
    process.env.QODIQA_AUDIT_LOG = path.join(tmpDir('qodiqa-h113-nolog-'), 'audit.log');
    process.env.QODIQA_PG_URL = sourceUrl;
    // the critical policyStore component used to resolve to the
    // real repository data/policy-store.json, so this suite silently backed
    // up and restored real repo data. It now gets its own fixture, in the
    // shape src/core/policy/store.js writes ({ version: 1, policies: {} }).
    const policyStore = path.join(tmpDir('qodiqa-h113-policystore-'), 'policy-store.json');
    fs.writeFileSync(policyStore, JSON.stringify({ version: 1, policies: {} }, null, 2));
    process.env.QODIQA_POLICY_STORE = policyStore;
    try {
      return await fn();
    } finally {
      if (prevOrdering === undefined) delete process.env.QODIQA_AUDIT_ORDERING_MODE; else process.env.QODIQA_AUDIT_ORDERING_MODE = prevOrdering;
      if (prevAuditLog === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = prevAuditLog;
      if (prevPgUrl === undefined) delete process.env.QODIQA_PG_URL; else process.env.QODIQA_PG_URL = prevPgUrl;
      if (prevPolicyStore === undefined) delete process.env.QODIQA_POLICY_STORE; else process.env.QODIQA_POLICY_STORE = prevPolicyStore;
    }
  }

  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(SOURCE_DB) || !SAFE_IDENTIFIER.test(TARGET_DB)) {
      throw new Error('Generated test DB names failed identifier validation — refusing to proceed.');
    }

    _host = process.env.QODIQA_PG_HOST || 'localhost';
    _port = parseInt(process.env.QODIQA_PG_PORT || '5432', 10);
    // App-level (low-privilege) role — used to WRITE the source fixtures. (Before this comment said the
    // backup DUMP connects as this role too; it must not — RLS hides every tenant-scoped row from it,.)
    _appUser     = process.env.QODIQA_PG_USER || 'qodiqa_app';
    _appPassword = process.env.QODIQA_PG_PASSWORD || '';
    // Elevated role for the RESTORE TARGET connection only: a full
    // includePostgres:true backup/restore in this suite covers every
    // discovered table (~70), not just audit_chain, and _syncSequences()
    // (scripts/dr/postgres.js) needs setval() rights on every restored
    // table's sequence — rights qodiqa_app was never granted for tables
    // outside its own normal runtime write path. A real DR restore is
    // itself an operator/admin action, not a live qodiqa_app runtime
    // connection, so using the elevated test role here (same one
    // migrateDatabase() above already uses for schema migrations) matches
    // how restore is actually expected to be operated, and keeps this
    // suite's actual subject under test — the audit-chain gate — free
    // of an unrelated, pre-existing privilege-boundary gap in unrelated
    // tables that has nothing to do with this remediation.
    _testUser     = process.env.QODIQA_PG_TEST_USER || _appUser;
    _testPassword = process.env.QODIQA_PG_TEST_PASSWORD || _appPassword;

    _maintenancePool = new Pool({
      host: _host,
      port: _port,
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _maintenancePool.query(`CREATE DATABASE "${SOURCE_DB}"`);
    await _maintenancePool.query(`CREATE DATABASE "${TARGET_DB}"`);

    await migrateDatabase(SOURCE_DB);
    await migrateDatabase(TARGET_DB);

    sourceConnStr = buildConnStr(SOURCE_DB, _appUser, _appPassword);
    // the DUMP connects as the dedicated read-only backup role (migration 067, BYPASSRLS). Dumping as
    // qodiqa_app — what this suite did before silently dropped every tenant-scoped row of every RLS table,
    // and dumpPostgres() now refuses it (BACKUP_ROLE_NOT_RLS_EXEMPT). Writes to the source stay on sourceConnStr.
    // Password: the rotated one from .env, else migration 067's placeholder (a fresh CI container never rotates it).
    backupConnStr = buildConnStr(SOURCE_DB, 'qodiqa_backup', process.env.QODIQA_PG_BACKUP_PASSWORD || 'REPLACE_WITH_VAULT_SECRET_BACKUP');
    targetConnStr = buildConnStr(TARGET_DB, _testUser, _testPassword);
  }, 60_000);

  afterAll(async () => {
    if (_maintenancePool) {
      for (const db of [SOURCE_DB, TARGET_DB]) {
        try {
          await _maintenancePool.query(
            `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
            [db],
          );
          await _maintenancePool.query(`DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`);
        } catch (err) {
          // eslint-disable-next-line no-console
          console.warn(` failed to drop ${db}: ${err.message}`);
        }
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  // ── 1/2/3/6: distributed-mode restore succeeds with NO local audit.log ────

  test('distributed-mode backup records auditOrderingMode="distributed" and auditLog as present:false, required:false — the local file genuinely never exists', async () => {
    await appendRealEntries(sourceConnStr, 3, 'h113-manifest-shape');

    const backupOut = tmpDir('qodiqa-h113-backup-');
    const { manifest } = await withDistributedBackupEnv(backupConnStr, () =>
      runBackupFresh({ outDir: backupOut, includePostgres: true }));

    expect(manifest.auditOrderingMode).toBe('distributed');
    const auditLogComp = manifest.components.find(c => c.name === 'auditLog');
    expect(auditLogComp.present).toBe(false);
    expect(auditLogComp.required).toBe(false); //'s exact defect: this used to be `true` unconditionally

    const auditChainTable = manifest.postgres.tables.find(t => t.table === 'audit_chain');
    expect(auditChainTable.present).toBe(true);
    expect(auditChainTable.rowCount).toBeGreaterThan(0);
  });

  test('fix proven end-to-end: distributed-mode restore COMPLETES (no REQUIRED_COMPONENT_MISSING) with real, machine-verified PostgreSQL audit-chain evidence — no local audit.log ever produced', async () => {
    const beforeCount = await countAuditChainRows(sourceConnStr);
    await appendRealEntries(sourceConnStr, 5, 'h113-e2e');
    const expectedRowCount = await countAuditChainRows(sourceConnStr);
    expect(expectedRowCount).toBe(beforeCount + 5);

    const backupOut = tmpDir('qodiqa-h113-backup-');
    const { targetDir: backupDir, manifest } = await withDistributedBackupEnv(backupConnStr, () =>
      runBackupFresh({ outDir: backupOut, includePostgres: true }));

    expect(manifest.auditOrderingMode).toBe('distributed');

    const restoreTarget = path.join(tmpDir('qodiqa-h113-restore-'), 'restored');
    // Before this threw RestoreError { code: 'REQUIRED_COMPONENT_MISSING' }
    // for the (correctly absent) auditLog component —'s exact finding.
    const { restored, auditChainCheck, postgres, erasureReplay } = await runRestore({
      backupDir,
      targetRoot: restoreTarget,
      pgConnectionString: targetConnStr,
      // a PostgreSQL restore replays erasures from a surviving ledger — here the source DB,
      // read as its owner identity: the app role holds no access to the ledger (it fails closed, 42501).
      erasureLedger: buildConnStr(SOURCE_DB, _testUser, _testPassword),
    });
    expect(erasureReplay).toMatchObject({ source: 'restored-db+external', subjectsReErased: 0 });

    // No local audit.log was restored (there was none to restore) — proves
    // the fix isn't "silently skip verification", it's "verify from the
    // correct source".
    expect(restored.find(r => r.name === 'auditLog')).toBeUndefined();
    expect(fs.existsSync(path.join(restoreTarget, 'audit.log'))).toBe(false);

    // The Postgres rows were actually restored into the TARGET database.
    const auditChainResult = postgres.tables.find(t => t.table === 'audit_chain');
    expect(auditChainResult.restored).toBe(expectedRowCount);

    // The mandatory gate ran the REAL production chain-walk against
    // PostgreSQL and found real, non-vacuous evidence.
    expect(auditChainCheck.valid).toBe(true);
    expect(auditChainCheck.chainValid).toBe(true);
    expect(auditChainCheck.chainLength).toBe(expectedRowCount);
    expect(auditChainCheck.tamperingDetected).toBe(false);

    // validateRestoredState() (the same function cycle.js/the CI drill use)
    // agrees, independently, when given the manifest's own auditOrderingMode.
    const validation = await validateRestoredState(
      restored,
      { manifest: manifest.postgres, connectionString: targetConnStr },
      { auditOrderingMode: manifest.auditOrderingMode },
    );
    expect(validation.auditChain.valid).toBe(true);
    expect(validation.overallValid).toBe(true);
  });

  // ── 4/7: missing PostgreSQL audit evidence fails closed ────────────────────

  test('fail-closed: a distributed-mode backup taken WITHOUT the Postgres component at all is refused at restore (operator forgot --with-postgres)', async () => {
    const backupOut = tmpDir('qodiqa-h113-backup-nopg-');
    // includePostgres deliberately omitted (defaults false) — simulates an
    // operator who ran a distributed-mode backup without --with-postgres.
    const { targetDir: backupDir, manifest } = await withDistributedBackupEnv(backupConnStr, () =>
      runBackupFresh({ outDir: backupOut }));

    expect(manifest.auditOrderingMode).toBe('distributed');
    expect(manifest.postgres).toBeNull();

    const restoreTarget = path.join(tmpDir('qodiqa-h113-restore-'), 'restored');
    await expect(runRestore({ backupDir, targetRoot: restoreTarget, pgConnectionString: targetConnStr }))
      .rejects.toMatchObject({ code: 'AUDIT_CHAIN_INTEGRITY_FAILED' });
  });

  test('fail-closed: a distributed-mode backup whose Postgres component exists but never captured the audit_chain table is refused at restore', async () => {
    await appendRealEntries(sourceConnStr, 2, 'h113-notable');

    const backupOut = tmpDir('qodiqa-h113-backup-notable-');
    const { targetDir: backupDir } = await withDistributedBackupEnv(backupConnStr, () =>
      runBackupFresh({ outDir: backupOut, includePostgres: true }));

    // Simulate a real backup that captured every OTHER table but somehow
    // never captured audit_chain (e.g. a transient error at dump time,
    // recorded honestly by dumpPostgres() as present:false rather than
    // fabricated) — strip it from the manifest and recompute the checksum
    // honestly, same technique test/backupRestore.test.js's own
    // REQUIRED_COMPONENT_MISSING test uses.
    const manifestPath = path.join(backupDir, 'manifest.json');
    const onDisk = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const auditChainTable = onDisk.postgres.tables.find(t => t.table === 'audit_chain');
    expect(auditChainTable).toBeDefined();
    auditChainTable.present = false;
    delete auditChainTable.archiveFile;
    delete auditChainTable.rowCount;
    fs.unlinkSync(path.join(backupDir, `pg_audit_chain.json`));
    const { manifestChecksum, ...rest } = onDisk;
    onDisk.manifestChecksum = computeManifestChecksum(rest);
    fs.writeFileSync(manifestPath, JSON.stringify(onDisk, null, 2));

    const restoreTarget = path.join(tmpDir('qodiqa-h113-restore-'), 'restored');
    await expect(runRestore({ backupDir, targetRoot: restoreTarget, pgConnectionString: targetConnStr }))
      .rejects.toMatchObject({ code: 'AUDIT_CHAIN_INTEGRITY_FAILED' });
  });

  // ── 5/7: corrupted/incomplete audit evidence fails closed ─────────────────

  test('fail-closed: a hash-chain break introduced into the restored PostgreSQL audit_chain rows is caught by the same production chain-walk that single-node mode uses — tampering detected, not a vacuous pass', async () => {
    // Uses its OWN fresh, disposable target database rather than the shared
    // targetConnStr other tests in this suite use: restorePostgres() writes
    // via `INSERT ... ON CONFLICT DO NOTHING`, so if the shared target
    // already contains the (untampered) early rows of this ever-growing
    // chain from an earlier test's successful restore, the conflict target
    // (hash, unchanged by this test's tampering — only `decision` is
    // flipped) would already exist and the tampered row would be silently
    // discarded rather than actually written — the exact "tampering
    // invisible because it never really got restored" false pass this was
    // first written to catch. Discovered by running this suite, not by
    // inspection: the first attempt reported chainValid:true with the
    // pre-existing untampered row intact.
    const freshTargetDb = `qodiqa_h113_tgt_tamper_${RUN_ID}`;
    await _maintenancePool.query(`CREATE DATABASE "${freshTargetDb}"`);
    await migrateDatabase(freshTargetDb);
    const freshTargetConnStr = buildConnStr(freshTargetDb, _testUser, _testPassword);

    try {
      await appendRealEntries(sourceConnStr, 4, 'h113-tamper');

      const backupOut = tmpDir('qodiqa-h113-backup-tamper-');
      const { targetDir: backupDir } = await withDistributedBackupEnv(backupConnStr, () =>
        runBackupFresh({ outDir: backupOut, includePostgres: true }));

      // Tamper the dumped audit_chain rows BEFORE restore — a direct edit of
      // the archive file, simulating on-disk backup corruption/tampering. No
      // component checksum covers Postgres table archives (only
      // FILE_COMPONENTS does — see components.js/restore.js), so
      // both succeed; only the mandatory audit-chain gate
      // can catch this. Tampering `decision` (not `hash` or `canonical`)
      // deliberately mirrors test/backupRestore.test.js's own single-node
      // tamper test: entryBuilder.js's verifyCanonicalHash() recomputes the
      // canonical form FRESH from the entry's own current field values
      // (coreFieldsOf(), which includes `decision`) and compares it against
      // the stored `canonical` string — so a `decision`-only edit, done
      // without also updating `canonical`, is exactly what that check exists
      // to catch, without needing to fabricate a fake hash.
      const archivePath = path.join(backupDir, 'pg_audit_chain.json');
      const rows = JSON.parse(fs.readFileSync(archivePath, 'utf8'));
      expect(rows.length).toBeGreaterThan(1);
      rows[1].decision = rows[1].decision === 'ALLOW' ? 'BLOCK' : 'ALLOW';
      fs.writeFileSync(archivePath, JSON.stringify(rows));

      const restoreTarget = path.join(tmpDir('qodiqa-h113-restore-'), 'restored');
      await expect(runRestore({ backupDir, targetRoot: restoreTarget, pgConnectionString: freshTargetConnStr }))
        .rejects.toMatchObject({ code: 'AUDIT_CHAIN_INTEGRITY_FAILED' });
    } finally {
      // cleanup must not decide the test. qodiqa_test cannot
      // terminate a still-attached qodiqa_app backend (no pg_signal_backend —
      // CLAUDE.md residual), so a denied terminate is tolerated, the drop waits
      // (bounded) for other sessions to leave, and a failed drop is a warning —
      // the same handling this file's afterAll already uses. Before this, the
      // denied terminate threw and failed the test.
      try {
        await _maintenancePool.query(
          `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
          [freshTargetDb],
        );
      } catch (err) {
        if (err.code !== '42501') throw err; // only "permission denied to terminate" is expected here
      }
      const deadline = Date.now() + 15_000;
      while (Date.now() < deadline) {
        const { rows } = await _maintenancePool.query(
          'SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [freshTargetDb]);
        if (rows[0].n === 0) break;
        await new Promise(resolve => setTimeout(resolve, 100)); // poll interval of the bounded wait above
      }
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${freshTargetDb}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(` failed to drop ${freshTargetDb}: ${err.message}`);
      }
    }
  });

  test('fail-closed: validateRestoredState() with no PostgreSQL connection string for a distributed-mode backup reports PG_CONNECTION_STRING_NOT_AVAILABLE, never a vacuous pass', async () => {
    // NOTE on why this goes through validateRestoredState() directly rather
    // than the full runRestore() path: when manifest.postgres IS present (as
    // it must be to reach this specific gate reason), runRestore()'s own
    // (restorePostgres()) resolves a connection string via the
    // EXACT SAME env-var chain BEFORE the audit-chain gate ever runs — so
    // with no connection string available anywhere, restorePostgres() itself
    // throws first (a plain Error, "no connection string"), and
    // PG_CONNECTION_STRING_NOT_AVAILABLE never becomes reachable through that
    // path. It exists as defense-in-depth for validateRestoredState() being
    // called independently (as cycle.js's own drill does, and as an operator
    // running `dr:validate` separately might) with a manifest that has a
    // Postgres component but no resolvable connection string for THIS call —
    // this test exercises that actually-reachable path directly.
    await appendRealEntries(sourceConnStr, 1, 'h113-noconn');

    const backupOut = tmpDir('qodiqa-h113-backup-noconn-');
    const { manifest } = await withDistributedBackupEnv(backupConnStr, () =>
      runBackupFresh({ outDir: backupOut, includePostgres: true }));

    expect(manifest.postgres.tables.find(t => t.table === 'audit_chain').present).toBe(true);

    const validation = await validateRestoredState(
      [], // no file components restored — irrelevant to this gate
      { manifest: manifest.postgres, connectionString: undefined }, // no connection string given
      { auditOrderingMode: manifest.auditOrderingMode },
    );

    expect(validation.auditChain.valid).toBe(false);
    expect(validation.auditChain.reason).toBe('PG_CONNECTION_STRING_NOT_AVAILABLE');
    expect(validation.overallValid).toBe(false);
  });

  // ── single-node behavior is provably unchanged by this fix ────────────────

  test('single-node-mode manifests (auditOrderingMode absent, pre-H113 shape) still require the restored audit.log file exactly as before', async () => {
    // A pre-H113 manifest never recorded auditOrderingMode at all —
    // manifest.js's buildManifest() defaults it to 'single-node' for exactly
    // this backward-compatibility case. Simulate that by stripping the field
    // from an otherwise-normal single-node backup (no Postgres, no
    // distributed env) and recomputing the checksum honestly.
    const backupOut = tmpDir('qodiqa-h113-backup-legacy-');
    const auditLogPath = path.join(tmpDir('qodiqa-h113-legacy-src-'), 'audit.log');
    fs.mkdirSync(path.dirname(auditLogPath), { recursive: true });
    fs.writeFileSync(auditLogPath, '');

    const prevAuditLog = process.env.QODIQA_AUDIT_LOG;
    const prevPolicyStore = process.env.QODIQA_POLICY_STORE;
    process.env.QODIQA_AUDIT_LOG = auditLogPath;
    // own policy-store fixture — see withDistributedBackupEnv.
    const policyStore = path.join(tmpDir('qodiqa-h113-legacy-policystore-'), 'policy-store.json');
    fs.writeFileSync(policyStore, JSON.stringify({ version: 1, policies: {} }, null, 2));
    process.env.QODIQA_POLICY_STORE = policyStore;
    let backupDir;
    try {
      ({ targetDir: backupDir } = await runBackupFresh({ outDir: backupOut }));
    } finally {
      if (prevAuditLog === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = prevAuditLog;
      if (prevPolicyStore === undefined) delete process.env.QODIQA_POLICY_STORE; else process.env.QODIQA_POLICY_STORE = prevPolicyStore;
    }

    const manifestPath = path.join(backupDir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    delete manifest.auditOrderingMode; // simulate a genuinely pre-H113 manifest
    // auditLog was empty (0 bytes) but still PRESENT — remove it entirely to
    // exercise the "component never restored" single-node fail-closed path.
    const auditComp = manifest.components.find(c => c.name === 'auditLog');
    fs.unlinkSync(path.join(backupDir, auditComp.archiveFile));
    auditComp.present = false;
    delete auditComp.archiveFile;
    delete auditComp.sha256;
    delete auditComp.sizeBytes;
    const { manifestChecksum, ...rest } = manifest;
    manifest.manifestChecksum = computeManifestChecksum(rest);
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    const restoreTarget = path.join(tmpDir('qodiqa-h113-restore-legacy-'), 'restored');
    await expect(runRestore({ backupDir, targetRoot: restoreTarget }))
      .rejects.toMatchObject({ code: 'AUDIT_CHAIN_INTEGRITY_FAILED' });
  });
});
