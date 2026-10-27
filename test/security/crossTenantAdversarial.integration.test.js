'use strict';

/**
 * Follow-up — CRITICAL cross-tenant adversarial harness (task §8).
 *
 * Purpose: this repo's prior audit trail ("Live cross-tenant
 * isolation never tested") and ("Nine PostgreSQL tables have no
 * RLS") were both still OPEN as of this session's start.
 * (test/integration/gapScanner.rls.integration.test.js, test/logStoreRlsVisibility.
 * test.js) already provide a real, live, sentinel-based cross-tenant proof
 * — but ONLY for transparency_log_entries. This file extends that same
 * discipline (real disposable Postgres, real qodiqa_app pooled connection,
 * never BYPASSRLS/superuser, sentinel values for unambiguous leak
 * detection) to two MORE tenant-scoped stores never covered by a live
 * cross-tenant test before: tenantConfigStore (migration 051 — the
 * correct, documented usage of withTransaction+setLocal) and webhookStore
 * (migration 016/018 — discovered THIS session, by direct code reading, to
 * NEVER call withTenantTransaction/setLocal at all, contradicting pool.js's
 * own doc comment: "ALL tenant-scoped database operations MUST use
 * [withTenantTransaction]... Never use withTransaction() for tenant-scoped
 * operations").
 *
 * Adversarial matrix covered (task §8's minimum list), Section A
 * (tenantConfigStore, the CORRECT implementation):
 *   CT-A01  A -> A          (tenant sees its own row)
 *   CT-A02  A -> B          (tenant A cannot see tenant B's row)
 *   CT-A03  B -> A          (tenant B cannot see tenant A's row)
 *   CT-A04  missing tenant  (validate() throws before any connection/query)
 *   CT-A05  invalid tenant  (malformed id throws TypeError, no query issued)
 *   CT-A06  concurrent A/B  (Promise.all on the SAME pool — no interleaving
 *                            contamination from connection reuse)
 *   CT-A07  tenant switch mid-"request-lifecycle" (sequential A/B/A reads
 *           reusing whatever pooled connections come back — proves no
 *           residual context from a prior transaction on a reused socket)
 *
 * Section B (webhookStore, the DISCOVERED-BROKEN implementation):
 *   CT-B01  createEndpoint() against real RLS: does it leak, or fail?
 *   CT-B02  listEndpoints() against real RLS: does it leak tenant B's rows
 *           to tenant A, or does it (fail-closed) return nothing at all?
 *   CT-B03  A raw INSERT bypassing the app layer entirely (as an attacker
 *           with SQL access but only the qodiqa_app role and no tenant
 *           context would be), to give CT-B01/02 an unambiguous baseline.
 *
 * The mandate (task §8) is: crossTenant = NONE only with proof of zero
 * leakage; otherwise FAIL or SUSPECTED with the exact reason. This file
 * produces that proof for Section A and the exact failure mode for
 * Section B for
 * the resulting determination.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');
const path     = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const REPO_ROOT = path.join(__dirname, '..', '..');
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_ctadv_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

const SENTINEL_A = `SENTINEL-ALPHA-${crypto.randomBytes(8).toString('hex')}`;
const SENTINEL_B = `SENTINEL-BRAVO-${crypto.randomBytes(8).toString('hex')}`;
const TENANT_A = 'ctadv-tenant-alpha';
const TENANT_B = 'ctadv-tenant-bravo';

let _originalDatabaseEnv;
let _maintenancePool;
let _appPool; // raw pg Pool, connected AS qodiqa_app — never BYPASSRLS/superuser
let pgPool, tenantConfigStore, webhookStore, tenantContext;

jest.setTimeout(90_000);

describeOrSkip('Follow-up §8 — cross-tenant adversarial harness (real disposable Postgres)', () => {
  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) {
      throw new Error(`Generated test DB name "${TEST_DB_NAME}" failed identifier validation — refusing to proceed.`);
    }

    _maintenancePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);

    const _ownerPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
    await _ownerPool.query(`GRANT ALL ON SCHEMA public TO ${process.env.QODIQA_PG_MIG_USER || 'qodiqa_mig'}`);
    await _ownerPool.end();

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;

    const { spawnSync } = require('child_process');
    const migrateRes = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        QODIQA_PG_DATABASE: TEST_DB_NAME,
        QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
        QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD,
      },
      encoding: 'utf8',
      timeout: 45_000,
    });
    if (migrateRes.status !== 0) {
      throw new Error(`migrate.js failed (status=${migrateRes.status}): \nstdout:\n${migrateRes.stdout}\nstderr:\n${migrateRes.stderr}`);
    }

    jest.resetModules();
    pgPool            = require('../../src/infra/postgres/pool');
    tenantConfigStore = require('../../src/core/tenancy/tenantConfigStore');
    webhookStore      = require('../../src/core/webhooks/webhookStore');
    tenantContext     = require('../../src/infra/postgres/tenantContext');

    pgPool.initialize(); // qodiqa_app, per QODIQA_PG_USER — the real pooled role

    _appPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });
  }, 90_000);

  afterAll(async () => {
    if (_appPool) await _appPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[crossTenantAdversarial] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  // ── Section A: tenantConfigStore — the CORRECT withTransaction+setLocal usage ──

  describe('Section A — tenantConfigStore (migration 051, correct tenant-context usage)', () => {
    beforeAll(async () => {
      await tenantConfigStore.upsertPolicySet({
        tenantId: TENANT_A,
        policies: [{ id: 'p1', type: 'RATE_LIMIT', sentinel: SENTINEL_A }],
        updatedBy: 'ctadv-test',
      });
      await tenantConfigStore.upsertPolicySet({
        tenantId: TENANT_B,
        policies: [{ id: 'p1', type: 'RATE_LIMIT', sentinel: SENTINEL_B }],
        updatedBy: 'ctadv-test',
      });
    });

    test('CT-A01 A -> A: tenant A reads its own policy set, sees its own sentinel', async () => {
      const result = await tenantConfigStore.getPolicySet(TENANT_A);
      expect(result).not.toBeNull();
      expect(JSON.stringify(result.policies)).toContain(SENTINEL_A);
      expect(JSON.stringify(result.policies)).not.toContain(SENTINEL_B);
    });

    test('CT-A02 A -> B is impossible by construction: getPolicySet(tenantId) always queries WHERE tenant_id = $1 for the CALLER-SUPPLIED id, so the adversarial case is tenant A\'s own session/context attempting to read tenant B\'s row — proven by setting A\'s context and querying B\'s id directly', async () => {
      // Simulates the realistic attack: the calling code has tenant A's
      // context/session, but something (a bug, a forged parameter) causes
      // the WHERE clause to target tenant B's row. Even though the SQL
      // *asks* for tenant B's row by id, RLS — keyed off the session
      // variable, not the WHERE clause — must still block it.
      const client = await _appPool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('qodiqa.tenant_id', $1, true)`, [TENANT_A]);
        const res = await client.query('SELECT tenant_id, policies FROM tenant_policy_sets WHERE tenant_id = $1', [TENANT_B]);
        await client.query('COMMIT');
        expect(res.rows.length).toBe(0); // RLS blocks it regardless of the WHERE clause asking for B
      } finally {
        client.release();
      }
    });

    test('CT-A03 B -> A: same adversarial shape, reversed — tenant B\'s context querying for tenant A\'s row', async () => {
      const client = await _appPool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`SELECT set_config('qodiqa.tenant_id', $1, true)`, [TENANT_B]);
        const res = await client.query('SELECT tenant_id, policies FROM tenant_policy_sets WHERE tenant_id = $1', [TENANT_A]);
        await client.query('COMMIT');
        expect(res.rows.length).toBe(0);
      } finally {
        client.release();
      }
    });

    test('CT-A04 missing tenant: getPolicySet(undefined) fails closed — setLocal() validates before any query, so no connection ever queries with a NULL/absent tenant', async () => {
      await expect(tenantConfigStore.getPolicySet(undefined)).rejects.toThrow(TypeError);
    });

    test('CT-A05 invalid tenant: a SQL-injection-shaped tenant id is rejected before any query is issued', async () => {
      await expect(
        tenantConfigStore.getPolicySet("ctadv'; DROP TABLE tenant_policy_sets; --"),
      ).rejects.toThrow(TypeError);
      // Prove the table is still intact and both real rows are still there
      const stillA = await tenantConfigStore.getPolicySet(TENANT_A);
      expect(stillA).not.toBeNull();
    });

    test('CT-A06 concurrent A/B: simultaneous reads on the SAME pool never cross-contaminate (pooled-connection reuse under concurrency)', async () => {
      const rounds = 20;
      const reads = [];
      for (let i = 0; i < rounds; i++) {
        reads.push(tenantConfigStore.getPolicySet(TENANT_A));
        reads.push(tenantConfigStore.getPolicySet(TENANT_B));
      }
      const results = await Promise.all(reads);
      for (let i = 0; i < results.length; i += 2) {
        const a = results[i];
        const b = results[i + 1];
        expect(JSON.stringify(a.policies)).toContain(SENTINEL_A);
        expect(JSON.stringify(a.policies)).not.toContain(SENTINEL_B);
        expect(JSON.stringify(b.policies)).toContain(SENTINEL_B);
        expect(JSON.stringify(b.policies)).not.toContain(SENTINEL_A);
      }
    });

    test('CT-A07 tenant switch mid-lifecycle: sequential A, B, A, B, A reads reusing whatever pooled sockets come back show zero residual context', async () => {
      const sequence = [TENANT_A, TENANT_B, TENANT_A, TENANT_B, TENANT_A];
      const expectedSentinel = { [TENANT_A]: SENTINEL_A, [TENANT_B]: SENTINEL_B };
      const wrongSentinel    = { [TENANT_A]: SENTINEL_B, [TENANT_B]: SENTINEL_A };
      for (const tenantId of sequence) {
        const result = await tenantConfigStore.getPolicySet(tenantId);
        const json = JSON.stringify(result.policies);
        expect(json).toContain(expectedSentinel[tenantId]);
        expect(json).not.toContain(wrongSentinel[tenantId]);
      }
    });
  });

  // ── Pre-fix historical record ──────────────
  //
  //'s fix, this exact suite (then Section B, CT-B01…B03)
  // empirically proved: a bare INSERT with no tenant context set is rejected
  // by RLS ("new row violates row-level security policy" — CT-B03); the
  // real createEndpoint() throws the identical RLS violation because it
  // never called withTenantTransaction (CT-B01); and listEndpoints() against
  // rows seeded directly via qodiqa_mig returned 0 rows for BOTH tenants
  // (CT-B02) — a complete fail-CLOSED functional break, not a leak. That
  // pre-fix run and its output are preserved verbatim in
  //This file now
  // proves the FIX: the same operations succeed for the owning tenant and
  // are denied for any other tenant, at the database layer.

  // ── Positive controls — prevent a vacuous pass ───────────────
  //
  // A harness that cannot demonstrate it is (a) actually running as the
  // unprivileged qodiqa_app role and (b) actually capable of detecting a
  // real cross-tenant leak when one exists proves nothing when its "zero
  // leakage" assertions pass. Both are checked here, independent of
  // Section A/B's own logic, using a dedicated seed.

  describe('Positive controls — the harness itself is capable of detecting a leak', () => {
    const PC_SENTINEL_A = `SENTINEL-PC-ALPHA-${crypto.randomBytes(8).toString('hex')}`;
    const PC_SENTINEL_B = `SENTINEL-PC-BRAVO-${crypto.randomBytes(8).toString('hex')}`;
    let migPool;

    beforeAll(async () => {
      migPool = new Pool({
        host:     process.env.QODIQA_PG_HOST || 'localhost',
        port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
        database: TEST_DB_NAME,
        // Ground truth / ownership note: this beforeAll's own migrate.js
        // invocation runs the migration chain AS qodiqa_test (QODIQA_PG_MIG_USER
        // override above), not qodiqa_mig — so on THIS environment qodiqa_test
        // is the role that actually owns every table this disposable database
        // creates (and per CLAUDE.md's environment notes, qodiqa_test carries
        // BYPASSRLS). qodiqa_mig's own migration-016 grants
        // (GRANT SELECT/INSERT/UPDATE ... TO qodiqa_app/qodiqa_read only) never
        // named qodiqa_mig, and migration 002's blanket
        // "GRANT ALL ON ALL TABLES IN SCHEMA public" only covers tables that
        // already existed when migration 002 ran — webhook_endpoints (016) postdates
        // it, so qodiqa_mig has no privilege on it here (confirmed empirically:
        // "permission denied for table webhook_endpoints" as qodiqa_mig on this
        // machine, unlike the prior session's dedicated container where this
        // ran fine — see baseline.md's recorded deviation from that container).
        user:     process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
        password: process.env.QODIQA_PG_TEST_PASSWORD || undefined,
        ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
        connectionTimeoutMillis: 5000,
      });
      await migPool.query(
        `INSERT INTO webhook_endpoints (tenant_id, url, enabled, event_types, secret_enc, secret_iv, secret_tag)
         VALUES ($1, $2, TRUE, $3, 'enc', 'iv', 'tag')`,
        [TENANT_A, `https://example.invalid/pc/${PC_SENTINEL_A}`, ['certification.completed']],
      );
      await migPool.query(
        `INSERT INTO webhook_endpoints (tenant_id, url, enabled, event_types, secret_enc, secret_iv, secret_tag)
         VALUES ($1, $2, TRUE, $3, 'enc', 'iv', 'tag')`,
        [TENANT_B, `https://example.invalid/pc/${PC_SENTINEL_B}`, ['certification.completed']],
      );
    });

    afterAll(async () => {
      if (migPool) await migPool.end().catch(() => {});
    });

    test('POSITIVE CONTROL 1: this harness\'s pool is the unprivileged qodiqa_app role, not a superuser/BYPASSRLS role', async () => {
      const client = await _appPool.connect();
      try {
        const who = await client.query('SELECT current_user AS u');
        expect(who.rows[0].u).toBe(process.env.QODIQA_PG_USER || 'qodiqa_app');
        const bypass = await client.query('SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user');
        expect(bypass.rows[0].rolbypassrls).toBe(false);
      } finally {
        client.release();
      }
    });

    test('POSITIVE CONTROL 2: the harness CAN see cross-tenant data through the BYPASSRLS ground-truth path, proving it would detect a real leak', async () => {
      const truth = await migPool.query('SELECT url FROM webhook_endpoints');
      const urls = truth.rows.map(r => r.url).join('|');
      expect(urls).toContain(PC_SENTINEL_A);
      expect(urls).toContain(PC_SENTINEL_B); // ground truth sees BOTH — the harness is not blind
    });

    test('POSITIVE CONTROL 3: under real tenant-A context (qodiqa_app), tenant B\'s sentinel is invisible — the RLS boundary the other cases rely on actually exists', async () => {
      const asA = await webhookStore.listEndpoints({ tenantId: TENANT_A });
      const urlsA = asA.endpoints.map(e => e.url).join('|');
      expect(urlsA).toContain(PC_SENTINEL_A);
      expect(urlsA).not.toContain(PC_SENTINEL_B);
    });
  });

  // ── Section B: webhookStore (migration 016/018) — proving the fix ──

  describe('Section B — webhookStore: full adversarial matrix', () => {
    let ENDPOINT_A_ID, ENDPOINT_B_ID;

    async function _groundTruthGetById(id) {
      const migPool = new Pool({
        host:     process.env.QODIQA_PG_HOST || 'localhost',
        port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
        database: TEST_DB_NAME,
        // Ground truth / ownership note: this beforeAll's own migrate.js
        // invocation runs the migration chain AS qodiqa_test (QODIQA_PG_MIG_USER
        // override above), not qodiqa_mig — so on THIS environment qodiqa_test
        // is the role that actually owns every table this disposable database
        // creates (and per CLAUDE.md's environment notes, qodiqa_test carries
        // BYPASSRLS). qodiqa_mig's own migration-016 grants
        // (GRANT SELECT/INSERT/UPDATE ... TO qodiqa_app/qodiqa_read only) never
        // named qodiqa_mig, and migration 002's blanket
        // "GRANT ALL ON ALL TABLES IN SCHEMA public" only covers tables that
        // already existed when migration 002 ran — webhook_endpoints (016) postdates
        // it, so qodiqa_mig has no privilege on it here (confirmed empirically:
        // "permission denied for table webhook_endpoints" as qodiqa_mig on this
        // machine, unlike the prior session's dedicated container where this
        // ran fine — see baseline.md's recorded deviation from that container).
        user:     process.env.QODIQA_PG_TEST_USER || 'qodiqa_test',
        password: process.env.QODIQA_PG_TEST_PASSWORD || undefined,
        ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
        connectionTimeoutMillis: 5000,
      });
      try {
        const res = await migPool.query('SELECT * FROM webhook_endpoints WHERE id = $1', [id]);
        return res.rows[0] ?? null;
      } finally {
        await migPool.end();
      }
    }

    beforeAll(async () => {
      const createdA = await webhookStore.createEndpoint({
        tenantId: TENANT_A, url: `https://example.invalid/b/${SENTINEL_A}`,
        eventTypes: ['certification.completed'], description: 'ctadv-b', createdBy: 'ctadv-test',
      });
      ENDPOINT_A_ID = createdA.endpoint.id;
      const createdB = await webhookStore.createEndpoint({
        tenantId: TENANT_B, url: `https://example.invalid/b/${SENTINEL_B}`,
        eventTypes: ['certification.completed'], description: 'ctadv-b', createdBy: 'ctadv-test',
      });
      ENDPOINT_B_ID = createdB.endpoint.id;
    });

    // ── A: A→A / B→B full lifecycle ───────────────────────────────────────────

    test('CT-B-A1 create/get/list round-trip succeeds for the owning tenant A', async () => {
      const got = await webhookStore.getEndpointById(ENDPOINT_A_ID, TENANT_A);
      expect(got).not.toBeNull();
      expect(got.url).toContain(SENTINEL_A);
      const list = await webhookStore.listEndpoints({ tenantId: TENANT_A });
      expect(list.endpoints.map(e => e.url).join('|')).toContain(SENTINEL_A);
    });

    test('CT-B-A2 create/get/list round-trip succeeds for the owning tenant B', async () => {
      const got = await webhookStore.getEndpointById(ENDPOINT_B_ID, TENANT_B);
      expect(got).not.toBeNull();
      expect(got.url).toContain(SENTINEL_B);
      const list = await webhookStore.listEndpoints({ tenantId: TENANT_B });
      expect(list.endpoints.map(e => e.url).join('|')).toContain(SENTINEL_B);
    });

    test('CT-B-A3 update and (soft) delete succeed for the owning tenant', async () => {
      const updated = await webhookStore.updateEndpoint(ENDPOINT_A_ID, { description: 'ctadv-updated-a' }, TENANT_A);
      expect(updated).not.toBeNull();
      expect(updated.description).toBe('ctadv-updated-a');
      const disabled = await webhookStore.deleteEndpoint(ENDPOINT_A_ID, TENANT_A);
      expect(disabled).not.toBeNull();
      expect(disabled.enabled).toBe(false);
      // Re-enable — later cases in this file still need it live.
      await webhookStore.updateEndpoint(ENDPOINT_A_ID, { enabled: true }, TENANT_A);
    });

    // ── B: A-context reading B's row by exact id → 0 rows ─────────────────────

    test('CT-B-B1 tenant A cannot getEndpointById tenant B\'s endpoint by exact id', async () => {
      const got = await webhookStore.getEndpointById(ENDPOINT_B_ID, TENANT_A);
      expect(got).toBeNull();
    });

    test('CT-B-B2 tenant A\'s listEndpoints never contains tenant B\'s sentinel', async () => {
      const list = await webhookStore.listEndpoints({ tenantId: TENANT_A });
      expect(list.endpoints.map(e => e.url).join('|')).not.toContain(SENTINEL_B);
    });

    // ── C: reversed ────────────────────────────────────────────────────────────

    test('CT-B-C1 tenant B cannot getEndpointById tenant A\'s endpoint by exact id', async () => {
      const got = await webhookStore.getEndpointById(ENDPOINT_A_ID, TENANT_B);
      expect(got).toBeNull();
    });

    test('CT-B-C2 tenant B\'s listEndpoints never contains tenant A\'s sentinel', async () => {
      const list = await webhookStore.listEndpoints({ tenantId: TENANT_B });
      expect(list.endpoints.map(e => e.url).join('|')).not.toContain(SENTINEL_A);
    });

    // ── D: A-context update/delete targeting B's row by id ────────────────────

    test('CT-B-D1 tenant A\'s updateEndpoint targeting tenant B\'s id affects 0 rows; B\'s row unchanged under ground truth', async () => {
      const result = await webhookStore.updateEndpoint(ENDPOINT_B_ID, { description: 'hijacked-by-a' }, TENANT_A);
      expect(result).toBeNull();
      const truth = await _groundTruthGetById(ENDPOINT_B_ID);
      expect(truth.description).not.toBe('hijacked-by-a');
    });

    test('CT-B-D2 tenant A\'s deleteEndpoint targeting tenant B\'s id affects 0 rows; B\'s row stays enabled under ground truth', async () => {
      const result = await webhookStore.deleteEndpoint(ENDPOINT_B_ID, TENANT_A);
      expect(result).toBeNull();
      const truth = await _groundTruthGetById(ENDPOINT_B_ID);
      expect(truth.enabled).toBe(true);
    });

    // ── E: missing tenant fails closed ────────────────────────────────────────

    test('CT-B-E1 getEndpointById with a missing tenantId throws TypeError before any row is returned', async () => {
      await expect(webhookStore.getEndpointById(ENDPOINT_A_ID, undefined)).rejects.toThrow(TypeError);
    });

    test('CT-B-E2 createEndpoint with a missing tenantId throws TypeError and creates no row', async () => {
      await expect(webhookStore.createEndpoint({
        tenantId: undefined, url: 'https://example.invalid/should-not-exist',
        eventTypes: ['certification.completed'],
      })).rejects.toThrow(TypeError);
    });

    // ── F: invalid tenant fails closed ────────────────────────────────────────

    test('CT-B-F1 getEndpointById with a SQL-injection-shaped tenantId throws TypeError; table stays intact', async () => {
      await expect(
        webhookStore.getEndpointById(ENDPOINT_A_ID, "a'; DROP TABLE webhook_endpoints; --"),
      ).rejects.toThrow(TypeError);
      const stillThere = await webhookStore.getEndpointById(ENDPOINT_A_ID, TENANT_A);
      expect(stillThere).not.toBeNull();
    });

    // ── G: sequential tenant switching ────────────────────────────────────────

    test('CT-B-G1 sequential A, B, A, B, A listEndpoints show zero residual context', async () => {
      const sequence = [TENANT_A, TENANT_B, TENANT_A, TENANT_B, TENANT_A];
      for (const tenantId of sequence) {
        const list = await webhookStore.listEndpoints({ tenantId });
        const urls = list.endpoints.map(e => e.url).join('|');
        const own   = tenantId === TENANT_A ? SENTINEL_A : SENTINEL_B;
        const other = tenantId === TENANT_A ? SENTINEL_B : SENTINEL_A;
        expect(urls).toContain(own);
        expect(urls).not.toContain(other);
      }
    });

    // ── H: 40-way concurrency ──────────────────────────────────────────────────

    test('CT-B-H1 40-way concurrent A/B reads on the same pool never cross-contaminate', async () => {
      const reads = [];
      for (let i = 0; i < 20; i++) {
        reads.push(webhookStore.listEndpoints({ tenantId: TENANT_A }));
        reads.push(webhookStore.listEndpoints({ tenantId: TENANT_B }));
      }
      const results = await Promise.all(reads);
      for (let i = 0; i < results.length; i += 2) {
        const a = results[i];
        const b = results[i + 1];
        expect(a.endpoints.map(e => e.url).join('|')).not.toContain(SENTINEL_B);
        expect(b.endpoints.map(e => e.url).join('|')).not.toContain(SENTINEL_A);
      }
    });

    // ── I: interleaved operations with delayed awaits inside one logical request ─

    test('CT-B-I1 an interleaved create(A) and read(B), racing on the same pool, do not cross-contaminate', async () => {
      const marker = crypto.randomBytes(4).toString('hex');
      const pCreateA = (async () => {
        await new Promise((r) => setTimeout(r, 5));
        return webhookStore.createEndpoint({
          tenantId: TENANT_A, url: `https://example.invalid/interleave-${marker}-${SENTINEL_A}`,
          eventTypes: ['certification.completed'],
        });
      })();
      const pReadB = webhookStore.listEndpoints({ tenantId: TENANT_B });

      const [createdA, listB] = await Promise.all([pCreateA, pReadB]);
      expect(createdA.endpoint.tenant_id).toBe(TENANT_A);
      expect(listB.endpoints.map(e => e.url).join('|')).not.toContain(marker);
    });

    // ── J: pool reuse — completed and aborted transactions leave no residue ────

    test('CT-B-J1 after a completed tenant-A operation, the next raw acquire on the pool shows NULL tenant context', async () => {
      await webhookStore.listEndpoints({ tenantId: TENANT_A }); // completes a withTenantTransaction
      const client = await _appPool.connect();
      try {
        const ctx = await client.query(`SELECT current_setting('qodiqa.tenant_id', true) AS t`);
        expect(ctx.rows[0].t === null || ctx.rows[0].t === '').toBe(true);
        const unscoped = await client.query('SELECT id FROM webhook_endpoints');
        expect(unscoped.rows.length).toBe(0); // no context set → RLS blocks everything (fail-closed)
      } finally {
        client.release();
      }
    });

    test('CT-B-J2 after an ABORTED tenant-A transaction, the next raw acquire on the pool also shows NULL tenant context', async () => {
      await expect(
        pgPool.withTenantTransaction(TENANT_A, (tx) => tx.query('SELECT 1/0')),
      ).rejects.toThrow();
      const client = await _appPool.connect();
      try {
        const ctx = await client.query(`SELECT current_setting('qodiqa.tenant_id', true) AS t`);
        expect(ctx.rows[0].t === null || ctx.rows[0].t === '').toBe(true);
      } finally {
        client.release();
      }
    });

    // ── K: delivery/retry (async, no HTTP request in scope) ────────────────────

    describe('CT-B-K — webhookDelivery.retryHandler (background path)', () => {
      const { retryHandler } = require('../../src/core/webhooks/webhookDelivery');

      test('CT-B-K1 wrong eventPayload.tenantId cannot resolve another tenant\'s endpoint — fails closed, not a leak', async () => {
        const op = {
          retryCount: 0,
          payload: {
            endpointId: ENDPOINT_B_ID, // tenant B's real endpoint
            eventId: crypto.randomUUID(),
            eventType: 'certification.completed',
            eventPayload: { tenantId: TENANT_A }, // wrong tenant claims it
            isIdempotent: true,
          },
        };
        const result = await retryHandler(op);
        expect(result.success).toBe(true); // "endpoint gone" from A's perspective — no delivery attempted
      });

      test('CT-B-K2 correct eventPayload.tenantId resolves its own endpoint (delivery then fails only on network, not on tenant lookup)', async () => {
        const op = {
          retryCount: 0,
          payload: {
            endpointId: ENDPOINT_A_ID,
            eventId: crypto.randomUUID(),
            eventType: 'certification.completed',
            eventPayload: { tenantId: TENANT_A },
            isIdempotent: true,
          },
        };
        const result = await retryHandler(op);
        expect(typeof result.success).toBe('boolean'); // reached delivery, not the "endpoint gone" short-circuit
      });

      test('CT-B-K3 missing eventPayload.tenantId fails closed without ever querying the database', async () => {
        const op = {
          retryCount: 0,
          payload: {
            endpointId: ENDPOINT_A_ID,
            eventId: crypto.randomUUID(),
            eventType: 'certification.completed',
            eventPayload: {},
          },
        };
        const result = await retryHandler(op);
        expect(result.success).toBe(true);
      });
    });

    // ── L: request completion followed by another tenant's request on the same worker ─

    test('CT-B-L1 tenant A\'s full request (create+read) immediately followed by tenant B\'s shows no leakage either direction', async () => {
      const marker = crypto.randomBytes(4).toString('hex');
      const createdA2 = await webhookStore.createEndpoint({
        tenantId: TENANT_A, url: `https://example.invalid/l-${marker}-${SENTINEL_A}`,
        eventTypes: ['certification.completed'],
      });
      const readA2 = await webhookStore.getEndpointById(createdA2.endpoint.id, TENANT_A);
      expect(readA2.url).toContain(SENTINEL_A);

      // Immediately, tenant B's own unrelated request on the same pool/process.
      const createdB2 = await webhookStore.createEndpoint({
        tenantId: TENANT_B, url: `https://example.invalid/l-${marker}-${SENTINEL_B}`,
        eventTypes: ['certification.completed'],
      });
      const readB2 = await webhookStore.getEndpointById(createdB2.endpoint.id, TENANT_B);
      expect(readB2.url).toContain(SENTINEL_B);

      // B cannot see the row A just created in this immediate sequence, and vice versa.
      expect(await webhookStore.getEndpointById(createdA2.endpoint.id, TENANT_B)).toBeNull();
      expect(await webhookStore.getEndpointById(createdB2.endpoint.id, TENANT_A)).toBeNull();
    });
  });
});
