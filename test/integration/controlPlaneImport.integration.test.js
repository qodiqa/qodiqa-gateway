'use strict';

/**
 * scripts/controlPlane/import.js on a real disposable database.
 *
 *   IM-01  first run: every fixture record inserted, per-store checksum verified (source set == PostgreSQL set)
 *   IM-02  second run: idempotent — 0 inserted, every record already identical, still verified
 *   IM-03  a row changed in PostgreSQL since the import is reported as a conflict (exit 2) and never overwritten
 *   IM-04  the shared database is refused without --live-approved
 * IM-05 after import the running store (pg mode) assigns the expiry an earlier key lacks (versioned write),
 *          and the import never wrote any source file
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true' && !!process.env.QODIQA_PG_CONTROL_PASSWORD;
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_w6im_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const base = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
let maint; let owner; let dir; let fixtureEnv;
const hash64 = () => crypto.randomBytes(32).toString('hex');

function writeFixtures() {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w6-import-'));
  const now = '2026-09-01T00:00:00.000Z';
  const w = (f, doc) => fs.writeFileSync(path.join(dir, f), JSON.stringify(doc, null, 2));
  w('rbac-users.json', { version: 1, users: {
    'u-admin': { id: 'u-admin', username: 'imp-admin', role: 'admin', enabled: true, createdAt: now, createdBy: 'x', updatedAt: now, updatedBy: 'x', apiKeyHash: hash64(), apiKeyIssuedAt: now, apiKeyExpiresAt: '2027-01-01T00:00:00.000Z' },
    'u-legacy': { id: 'u-legacy', username: 'imp-legacy', role: 'operator', enabled: true, createdAt: now, createdBy: 'x', updatedAt: now, updatedBy: 'x', apiKeyHash: hash64(), apiKeyIssuedAt: now },
  } });
  w('rbac-custom-roles.json', { version: 1, roles: { 'custom:imp': { id: 'custom:imp', name: 'imp', description: '', permissions: ['READ_AUDIT'], enabled: true, builtIn: false, createdAt: now, createdBy: 'x', updatedAt: now, updatedBy: 'x' } } });
  w('signing-identities.json', { version: 1, identities: { 'si-1': { id: 'si-1', name: 'imp-si', tenantId: 'imptenant', environment: 'test', allowedProviders: null, permissions: ['SIGN_ARTIFACT'], credentialType: 'api-key', maxTtlMs: null, enabled: true, revoked: false, revokedAt: null, revokedBy: null, revokedReason: null, apiKeyHash: hash64(), apiKeyIssuedAt: now, apiKeyExpiresAt: '2027-01-01T00:00:00.000Z', lastUsedAt: null, createdAt: now, createdBy: 'x', updatedAt: now, updatedBy: 'x' } } });
  w('tenant-portal-users.json', { version: 1, users: { 'pu_1': { id: 'pu_1', idpIssuer: 'https://idp', idpSubject: 's1', tenantId: 'imptenant', email: null, role: 'tenant', enabled: true, createdAt: now, lastLoginAt: now } } });
  w('tenants.json', { version: 1, tenants: [{ tenantId: 'imptenant', tenantName: 'imptenant', organizationId: null, status: 'active', quotas: null, createdAt: now, updatedAt: now }, { tenantId: 'impsusp', tenantName: 'impsusp', organizationId: null, status: 'suspended', quotas: null, createdAt: now, updatedAt: now }] });
  w('organizations.json', { version: 1, organizations: [{ organizationId: '11111111-1111-4111-8111-111111111111', organizationName: 'imp-org', status: 'active', createdAt: now, updatedAt: now, metadata: {}, quotas: { maxRequestsPerMinute: 5000, maxRequestsPerKeyPerMin: 100, maxStreamingSessions: 500, retentionDays: 365 }, tenantIds: ['imptenant'] }] });
  w('keys.json', { version: 3, clients: { imptenant: {
    'imptenant:key_v1': { clientId: 'imptenant', keyId: 'imptenant:key_v1', version: 1, algorithm: 'Ed25519', status: 'deprecated', createdAt: '2026-01-01T00:00:00.000Z', retiredAt: '2026-06-01T00:00:00.000Z' },
    'imptenant:key_v2': { clientId: 'imptenant', keyId: 'imptenant:key_v2', version: 2, algorithm: 'Ed25519', status: 'active', createdAt: '2026-06-01T00:00:00.000Z', retiredAt: null },
  } } });
  w('key-archive.json', { version: 1, entries: [{ keyId: 'imptenant:key_v0', clientId: 'imptenant', version: 0, createdAt: '2025-01-01T00:00:00.000Z', retiredAt: '2025-06-01T00:00:00.000Z', purgedAt: '2026-01-01T00:00:00.000Z' }] });
  fixtureEnv = {
    QODIQA_RBAC_STORE_PATH: path.join(dir, 'rbac-users.json'),
    QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH: path.join(dir, 'rbac-custom-roles.json'),
    QODIQA_SIGNING_STORE_PATH: path.join(dir, 'signing-identities.json'),
    QODIQA_PORTAL_USER_STORE_PATH: path.join(dir, 'tenant-portal-users.json'),
    TENANT_STORE_PATH: path.join(dir, 'tenants.json'),
    ORG_STORE_PATH: path.join(dir, 'organizations.json'),
    QODIQA_POLICY_STORE: path.join(dir, 'policy-store.json'), // absent → derived from POLICY_FILE
    POLICY_FILE: path.join(REPO_ROOT, 'policies.json'),
    QODIQA_KEYS_PATH: path.join(dir, 'keys.json'),
    QODIQA_KEYS_ARCHIVE_PATH: path.join(dir, 'key-archive.json'),
  };
}

function runImport(database = DB) {
  const r = spawnSync(process.execPath, ['scripts/controlPlane/import.js', '--database', database], {
    cwd: REPO_ROOT, encoding: 'utf8', timeout: 60_000, env: { ...process.env, ...fixtureEnv, NODE_ENV: 'test' },
  });
  const json = r.stdout.slice(r.stdout.indexOf('{\n'));
  let report = null; try { report = JSON.parse(json); } catch (_) { /* refused runs print no report */ }
  return { status: r.status, report, stderr: r.stderr };
}

const dirHash = () => Object.fromEntries(fs.readdirSync(dir).sort().map((f) => [f, crypto.createHash('sha256').update(fs.readFileSync(path.join(dir, f))).digest('hex')]));

describeOrSkip('control-plane import', () => {
  let before;
  beforeAll(async () => {
    maint = new Pool({ ...base(), database: 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    owner = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    writeFixtures();
    before = dirHash();
  });

  afterAll(async () => {
    if (owner) await owner.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  let first;
  test('IM-01 first run inserts every record and verifies every store by checksum', () => {
    first = runImport();
    expect(first.status).toBe(0);
    const s = first.report.stores;
    expect(first.report.verified).toBe(true);
    expect(s.rbac_user).toMatchObject({ records: 2, inserted: 2, alreadyIdentical: 0, conflicting: [], verified: true });
    expect(s.rbac_custom_role).toMatchObject({ records: 1, inserted: 1, verified: true });
    expect(s.signing_identity).toMatchObject({ records: 1, inserted: 1, verified: true });
    expect(s.portal_user).toMatchObject({ records: 1, inserted: 1, verified: true });
    expect(s.tenant).toMatchObject({ records: 2, inserted: 2, verified: true });
    expect(s.organization).toMatchObject({ records: 1, inserted: 1, verified: true });
    expect(s.policy.records).toBeGreaterThan(0);
    expect(s.policy).toMatchObject({ verified: true });
    expect(s.signing_key_status).toMatchObject({ records: 3, inserted: 3, verified: true });
    for (const r of Object.values(s)) expect(r.pgSetSha256).toBe(r.sourceSetSha256);
  });

  test('IM-02 second run is idempotent: nothing inserted, everything identical, same checksums', () => {
    const second = runImport();
    expect(second.status).toBe(0);
    for (const [store, r] of Object.entries(second.report.stores)) {
      expect({ store, inserted: r.inserted, identical: r.alreadyIdentical, conflicting: r.conflicting, verified: r.verified })
        .toEqual({ store, inserted: 0, identical: r.records, conflicting: [], verified: true });
      expect(r.pgSetSha256).toBe(first.report.stores[store].pgSetSha256);
    }
  });

  test('IM-03 a row changed in PostgreSQL since the import is reported, never overwritten (exit 2)', async () => {
    await owner.query("UPDATE control_plane_records SET data = jsonb_set(data, '{status}', '\"suspended\"'), version = version + 1 WHERE store='tenant' AND record_id='imptenant'");
    const third = runImport();
    expect(third.status).toBe(2);
    expect(third.report.stores.tenant.conflicting).toEqual(['imptenant']);
    const row = (await owner.query("SELECT data->>'status' AS s, version FROM control_plane_records WHERE store='tenant' AND record_id='imptenant'")).rows[0];
    expect(row).toEqual({ s: 'suspended', version: '2' });
  });

  test('IM-04 the shared database is refused without --live-approved', () => {
    const r = runImport('qodiqa');
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/refusing to import into the shared database "qodiqa"/);
  });

  test('IM-05 an earlier key without expiry gets one on the first pg pull (versioned); no source file was written', () => {
    const r = spawnSync(process.execPath, ['-e', `
      const cp = require('./src/core/controlPlane');
      (async () => { await cp.start({ notifier: false }); const store = require('./src/core/rbac/store');
        await new Promise((r) => setTimeout(r, 500)); const u = store.getUser('u-legacy');
        console.log('RESULT ' + JSON.stringify({ expiry: u.apiKeyExpiresAt || null })); await cp.stop(); await require('./src/infra/postgres/rolePools').shutdownAll(); })()
        .catch((e) => { console.error(e.message); process.exit(1); });`], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 60_000,
      env: { ...process.env, ...fixtureEnv, NODE_ENV: 'test', QODIQA_CONTROL_PLANE_BACKEND: 'pg', QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DB, QODIQA_PG_URL: '' },
    });
    expect({ status: r.status, stderr: r.status === 0 ? '' : r.stderr.slice(-600) }).toEqual({ status: 0, stderr: '' });
    const out = JSON.parse(r.stdout.split('\n').find((l) => l.startsWith('RESULT ')).slice(7));
    expect(out.expiry).toEqual(expect.any(String));
    return owner.query("SELECT version, data->>'apiKeyExpiresAt' AS e FROM control_plane_records WHERE store='rbac_user' AND record_id='u-legacy'")
      .then(({ rows }) => {
        expect(rows[0].version).toBe('2');
        expect(rows[0].e).toBe(out.expiry);
        expect(dirHash()).toEqual(before);
      });
  });
});
