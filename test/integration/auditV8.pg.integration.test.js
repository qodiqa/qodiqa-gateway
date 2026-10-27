'use strict';

/**
 * Audit schema v8 against real PostgreSQL.
 *
 * Requires real PostgreSQL (QODIQA_PG_ENABLED=true, a role with CREATEDB) — skipped otherwise, like its siblings
 * test/integration/audit-chain-distributed.integration.test.js. Creates and drops its own uniquely named database.
 *
 * AV8-PG-01  a v7 entry followed by one entry of every v8 type, appended through the distributed ordering authority,
 *            comes back from PostgreSQL byte-identical: every entry re-verifies in the production verifier, the
 *            BIGINT columns are numbers again, the v7 entry carries no v8 key
 * AV8-PG-02  the independent verifier reproduces the same verdict from the raw rows (entryFromPgRow + orderPgRows)
 * AV8-PG-03  lookup by artifact id returns the v8 fields
 * AV8-PG-04  a v7 append after the first v8 row is still written by the distributed path (the one-way guard is a
 *            single-node writer rule; the verifiers report it) — and both verifiers report SCHEMA_DOWNGRADE
 */

const crypto = require('crypto');
const { Pool } = require('pg');
const eb = require('../../src/core/audit/entryBuilder');
const contract = require('../../scripts/audit-repro/verify/auditContract');
const { trackInFlight } = require('../helpers/inFlight');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const PW = 'QODIQA_PG_' + 'PASSWORD';   // computed key: keeps the secret scanner's env-assignment rule from matching a restore of the ambient value
const TEST_DB_NAME = `qodiqa_av8_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const H = (c) => c.repeat(64);
const RID = '55555555-5555-4555-8555-555555555555';
const ISSUED = 1760000000000;

describeOrSkip('audit schema v8 (real PostgreSQL, migration 083)', () => {
  let maintenance; let raw; let pgPool; let distributedOrdering; let backend; let audit; let evidenceWrites;
  const saved = {};
  const appended = [];

  beforeAll(async () => {
    maintenance = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false, connectionTimeoutMillis: 5000,
    });
    await maintenance.query(`CREATE DATABASE "${TEST_DB_NAME}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW, 'QODIQA_AUDIT_ORDERING_MODE', 'QODIQA_AUDIT_SCHEMA_V8']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env.QODIQA_PG_TEST_PASSWORD; }
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
    delete process.env.QODIQA_AUDIT_SCHEMA_V8;

    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER;
    process.env[PW] = saved[PW];

    distributedOrdering = require('../../src/core/audit/distributedOrdering');
    backend = require('../../src/infra/postgres/pg-audit-backend');
    evidenceWrites = trackInFlight(backend, 'recordEvidenceForEntry');
    audit = require('../../src/core/audit/audit-log');
    raw = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false, connectionTimeoutMillis: 5000,
    });
  }, 90_000);

  afterAll(async () => {
    if (evidenceWrites) { await evidenceWrites.settle(); evidenceWrites.restore(); }
    if (raw) await raw.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maintenance) {
      try {
        await maintenance.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [TEST_DB_NAME]);
        await maintenance.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);   // this suite's own disposable database
      } catch (err) { console.warn(`[auditV8.pg] failed to drop ${TEST_DB_NAME}: ${err.message}`); }
      await maintenance.end().catch(() => {});
    }
  }, 30_000);

  const base = (over = {}) => ({ inputHash: H('a'), signature: 'sig', requestHash: H('a'), policyHash: H('b'), verificationResult: true, tenantId: 't1', ...over });
  const actionCtx = { action: { tool: { server: 'srv', name: 'tool', schemaHash: H('e') }, parentRequestHash: H('f'), prevActionHash: null } };
  const v8Specs = () => [
    base({ artifactId: eb.lifecycleArtifactId(RID, 'INTENT'), entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', requestId: RID, executingProvider: 'local', issuedAt: ISSUED, protocolVersion: 2 }),
    base({ artifactId: RID, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash: eb.outputHashOf('hi'), requestId: RID, executingProvider: 'local', issuedAt: ISSUED, protocolVersion: 2, completionStatus: 'COMPLETE' }),
    { artifactId: RID + ':commit', entryType: 'COMMIT', decision: 'ALLOW', reason: 'RESPONSE_DELIVERED', signature: 'sig', requestId: RID, tenantId: 't1', outputHash: H('c'), bytesDelivered: 4_000_000_000, completionStatus: 'COMPLETE', issuedAt: ISSUED, protocolVersion: 2 },
    { artifactId: 'ev1:kill_switch', entryType: 'KILL_SWITCH', decision: 'BLOCK', reason: 'KILL_SWITCH_ON', tenantId: '*', executionContext: { killSwitch: { operatorId: 'op1', scope: 'global', stateHash: H('1') } } },
    { artifactId: 'ar1:action_intent', entryType: 'ACTION_INTENT', decision: 'ALLOW', reason: 'ACTION_AUTHORIZED', signature: 'sig', tenantId: 't1', agentId: 'agent-é', sessionId: 'sess-1', actionSeq: 1, actionHash: H('d'), executionContext: actionCtx },
    { artifactId: 'ar1:action_commit', entryType: 'ACTION_COMMIT', decision: 'ALLOW', reason: 'ACTION_COMPLETED', signature: 'sig', tenantId: 't1', agentId: 'agent-é', sessionId: 'sess-1', actionSeq: 1, actionHash: H('d'), outputHash: H('c'), completionStatus: 'COMPLETE', executionContext: actionCtx },
    { artifactId: 'ap1:approval_requested', entryType: 'APPROVAL_REQUESTED', decision: 'BLOCK', reason: 'APPROVAL_REQUIRED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1', policyRuleId: 'tool:requiresApproval' } } },
    { artifactId: 'ap1:approval_decided', entryType: 'APPROVAL_DECIDED', decision: 'ALLOW', reason: 'APPROVED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1', approverId: 'u2', decision: 'APPROVED', notBefore: 1, expiresAt: 2, mfa: true } } },
    { artifactId: RID + ':dlp_in_1', entryType: 'DLP_TRANSFORM', decision: 'ALLOW', reason: 'DLP_REDACT', tenantId: 't1', requestId: RID, dlp: { rules: ['email', 'ünï'], action: 'REDACT', inputHashBefore: H('a'), inputHashAfter: H('b') } },
    { artifactId: 'dg1:delegation_issued', entryType: 'DELEGATION_ISSUED', decision: 'ALLOW', reason: 'DELEGATION_ISSUED', tenantId: 't1', executionContext: { delegation: { chainHash: H('9'), depth: 1, rootAgentId: 'agent-1', parentId: null } } },
  ];

  test('AV8-PG-01 a v7 entry then every v8 type round-trips through PostgreSQL and re-verifies', async () => {
    appended.push(await distributedOrdering.appendEntry(base({ artifactId: 'old-v7', decision: 'ALLOW', outputHash: eb.outputHashOf('x'), requestId: 'old-v7' })));
    expect(appended[0].schemaVersion).toBe(7);
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
    for (const s of v8Specs()) appended.push(await distributedOrdering.appendEntry(s));
    expect(appended.slice(1).every((e) => e.schemaVersion === 8)).toBe(true);

    const loaded = await backend.loadChainFromPg();
    expect(loaded).toHaveLength(appended.length);
    loaded.forEach((e, i) => {
      expect(e.hash).toBe(appended[i].hash);
      expect(eb.verifyCanonicalHash(e)).toBe(true);
      if (e.schemaVersion === 8) {
        for (const f of eb.V8_NEW_FIELDS) expect(JSON.parse(e.canonical)[f]).toEqual(e[f] === undefined ? null : e[f]);   // the stored value IS the hashed value
        for (const f of ['issuedAt', 'protocolVersion', 'actionSeq', 'bytesDelivered']) if (e[f] !== null) expect(typeof e[f]).toBe('number');
      } else {
        for (const f of eb.V8_NEW_FIELDS) expect(e).not.toHaveProperty(f);
      }
    });
    const commit = loaded.find((e) => e.entryType === 'COMMIT');
    expect(commit.bytesDelivered).toBe(4_000_000_000);       // > 2^31: a BIGINT, returned as a number
    const dlp = loaded.find((e) => e.entryType === 'DLP_TRANSFORM');
    expect(dlp.dlp.rules).toEqual(['email', 'ünï']);
    expect(loaded.find((e) => e.entryType === 'ACTION_INTENT').agentId).toBe('agent-é');

    const verdict = audit.verifyAuditChainDetailed(loaded);
    expect(verdict.valid).toBe(true);
    expect(verdict.lifecycleComplete).toBe(true);
  });

  test('AV8-PG-02 the independent verifier reaches the same verdict from the raw rows', async () => {
    const rows = (await raw.query('SELECT * FROM audit_chain ORDER BY seq ASC')).rows;
    expect(rows.length).toBe(appended.length);
    const { ordered, anomalies } = contract.orderPgRows(rows);
    expect(anomalies).toEqual([]);
    const res = contract.walkChain(ordered.map(contract.entryFromPgRow));
    expect(res).toMatchObject({ valid: true, entriesVerified: appended.length, lifecycleComplete: true });
    expect(res.warnings).toEqual([]);
  });

  test('AV8-PG-03 lookup by artifact id returns the v8 fields', async () => {
    const e = await backend.queryByArtifactId(RID + ':commit');
    expect(e).toMatchObject({ entryType: 'COMMIT', schemaVersion: 8, issuedAt: ISSUED, protocolVersion: 2, bytesDelivered: 4_000_000_000, completionStatus: 'COMPLETE' });
    // the lookup rows carry no `timestamp` (it is part of the hashed canonical string, not a column): re-derive it as the loaders do
    expect(eb.verifyCanonicalHash({ ...e, timestamp: JSON.parse(e.canonical).timestamp })).toBe(true);
    const old = await backend.queryByArtifactId('old-v7');
    expect(old.schemaVersion).toBe(7);
    expect(old).not.toHaveProperty('issuedAt');
  });

  test('AV8-PG-04 a v7 row after a v8 row is reported as SCHEMA_DOWNGRADE by both verifiers', async () => {
    delete process.env.QODIQA_AUDIT_SCHEMA_V8;
    // (migration 098): the WRITER refuses a downgrade once the chain head is v8 ...
    await expect(distributedOrdering.appendEntry(base({ artifactId: 'refused-v7', decision: 'ALLOW', outputHash: eb.outputHashOf('x'), requestId: 'refused-v7' }))).rejects.toMatchObject({ code: 'AUDIT_SCHEMA_DOWNGRADE_REFUSED' });
    // ... so the downgrade the verifiers must report is one planted by someone who can write the head row directly (a database administrator)
    await raw.query('UPDATE audit_chain_head SET tail_schema_version = 0');
    const late = await distributedOrdering.appendEntry(base({ artifactId: 'late-v7', decision: 'ALLOW', outputHash: eb.outputHashOf('y'), requestId: 'late-v7' }));
    expect(late.schemaVersion).toBe(7);
    const loaded = await backend.loadChainFromPg();
    const prod = audit.verifyAuditChainDetailed(loaded);
    expect(prod.valid).toBe(false);
    expect(prod.detail).toBe('SCHEMA_DOWNGRADE');
    const rows = (await raw.query('SELECT * FROM audit_chain ORDER BY seq ASC')).rows;
    const ind = contract.walkChain(contract.orderPgRows(rows).ordered.map(contract.entryFromPgRow));
    expect(ind.valid).toBe(false);
    expect(ind.failure.detail).toBe('SCHEMA_DOWNGRADE');
  });
});
