'use strict';

/**
 * step 6 — REAL PostgreSQL proof that aggregating the routine success events
 * leaves every consumer's COUNTS unchanged.
 *
 * One deterministic event stream (6 recent clock minutes × 3 tenants incl. NULL; the fourteen aggregated routine
 * types mixed with BLOCK decisions, WARN/ERROR/CRITICAL events and unlisted types) is ingested through the real
 * centralStore into two freshly migrated disposable databases: once with QODIQA_AUDIT_STORE_AGGREGATE=false (the
 * earlier per-row behaviour) and once with aggregation on. Then, against each database:
 *   AGG-01  stats(): every count field equal; the table holds far fewer rows with aggregation on
 *   AGG-02  search(): `total` equal for 14 filter sets (none, per aggregated type, tenant, category, severity,
 *           outcome, minute-aligned time range); non-aggregated listings (WARN, BLOCK) return the same events
 *   AGG-03  topEventTypes(): count and failure_count per type equal
 *   AGG-04  ingestionRate(): every per-minute bucket equal
 *   AGG-05  compliance evidenceCollector.collectAll(): every evidence type's count (and errorCount /
 *           blockCount / allowCount) equal, platform-wide and for one tenant, over a minute-aligned period
 * Documented, not asserted equal: an aggregated row's occurred_at is its minute's start, so stats().firstEvent /
 * lastEvent and mid-minute time filters are exact to the minute for the aggregated types (AGG-01 bounds it < 60 s).
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const SAFE = /^[a-z_][a-z0-9_]*$/;
const TAG = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const DB = { off: `qodiqa_w10agg_off_${TAG}`, on: `qodiqa_w10agg_on_${TAG}` };

// ── the deterministic stream ───────────────────────────────────────────────
function stream(nowMs) {
  let s = 0x2f6a1d;
  const rnd = (n) => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s % n; };
  const uuid = () => `${crypto.randomBytes(4).toString('hex')}-0000-4000-8000-${crypto.randomBytes(6).toString('hex')}`;
  const firstMinute = Math.floor(nowMs / 60_000) * 60_000 - 6 * 60_000;
  const ev = [];
  const ROUTINE = [['SIGN_AUTH_OK', {}], ['SIGN_DECISION', { decision: 'ALLOW' }], ['POLICY_HASH_BOUND', {}], ['POLICY_EXECUTE', {}],
    ['PROVIDER_REQUEST_VALIDATED', {}], ['PROVIDER_ROUTING_DECISION', {}], ['PROVIDER_EXECUTION_START', {}], ['PROVIDER_EXECUTION_COMPLETE', {}],
    ['AUDIT_EXECUTION_RECORDED', { decision: 'ALLOW' }], ['EVIDENCE_CHAIN_RECORD_CREATED', {}], ['TRANSPARENCY_ENTRY_CREATED', {}],
    ['TRANSPARENCY_ENTRY_REGISTERED', {}], ['TRANSPARENCY_ROOT_SIGNED', {}], ['ANOMALY_STATE_INCREMENTED', {}], ['ANOMALY_STATE_INCREMENTED', {}]];
  for (let m = 0; m < 6; m++) {
    const minute = firstMinute + m * 60_000;
    for (const tenantId of ['w10-t1', 'w10-t2', null]) {
      const requests = 3 + rnd(5);
      for (let r = 0; r < requests; r++) {
        const requestId = uuid(); const t = minute + rnd(59_000);
        for (const [type, extra] of ROUTINE) ev.push(['INFO', type, { timestamp: new Date(t + rnd(900)).toISOString(), requestId, ...(tenantId ? { tenantId } : {}), ...extra }]);
        if (rnd(3) === 0) ev.push(['INFO', 'SIGN_DECISION', { timestamp: new Date(t + 5).toISOString(), requestId, decision: 'BLOCK', ...(tenantId ? { tenantId } : {}) }]);
        if (rnd(3) === 0) ev.push(['INFO', 'AUDIT_BLOCK_RECORDED', { timestamp: new Date(t + 6).toISOString(), requestId, decision: 'BLOCK', ...(tenantId ? { tenantId } : {}) }]);
        if (rnd(4) === 0) ev.push(['WARN', 'RBAC_DENY', { timestamp: new Date(t + 7).toISOString(), requestId, ...(tenantId ? { tenantId } : {}) }]);
        if (rnd(5) === 0) ev.push(['WARN', 'POLICY_EXECUTE', { timestamp: new Date(t + 8).toISOString(), requestId, ...(tenantId ? { tenantId } : {}) }]);
        if (rnd(6) === 0) ev.push(['INFO', 'CONSENT_GRANTED', { timestamp: new Date(t + 9).toISOString(), requestId, ...(tenantId ? { tenantId } : {}) }]);
      }
      if (rnd(2) === 0) ev.push(['ERROR', 'PG_POOL_ERROR', { timestamp: new Date(minute + 30_000).toISOString(), error: 'x' }]);
      if (rnd(4) === 0) ev.push(['CRITICAL', 'EXECUTION_INVARIANT_VIOLATED', { timestamp: new Date(minute + 31_000).toISOString(), ...(tenantId ? { tenantId } : {}) }]);
      if (rnd(3) === 0) ev.push(['INFO', 'KEY_ROTATED', { timestamp: new Date(minute + 32_000).toISOString() }]);
    }
  }
  return { ev, firstMinute, lastMinuteEnd: firstMinute + 6 * 60_000 - 1 };
}

describeOrSkip('platform_audit_events aggregation leaves every consumer count unchanged (real PostgreSQL)', () => {
  let maint; const results = {}; let S;
  const saved = {};

  beforeAll(async () => {
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_AUDIT_STORE_AGGREGATE']) saved[k] = process.env[k];
    for (const d of Object.values(DB)) if (!SAFE.test(d)) throw new Error(`unsafe db name ${d}`);
    maint = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER, password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD });
    S = stream(Date.now());

    for (const mode of ['off', 'on']) {
      await maint.query(`CREATE DATABASE "${DB[mode]}"`);
      process.env.QODIQA_PG_DATABASE = DB[mode];
      if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD; }
      process.env.QODIQA_AUDIT_STORE_AGGREGATE = mode === 'on' ? 'true' : 'false';
      jest.resetModules();
      const pgPool = require('../../src/infra/postgres/pool');
      const rolePools = require('../../src/infra/postgres/rolePools');
      pgPool.initialize();
      await pgPool.runMigrations();
      const store = require('../../src/core/audit/centralStore');
      const collector = require('../../src/core/compliance/evidenceCollector');
      for (const [level, type, payload] of S.ev) await store.ingest(level, type, payload);
      await store.flush();

      const start = new Date(S.firstMinute).toISOString(); const end = new Date(S.lastMinuteEnd).toISOString();
      const mid = new Date(S.firstMinute + 2 * 60_000).toISOString(); const midEnd = new Date(S.firstMinute + 4 * 60_000 - 1).toISOString();
      const filters = { all: {}, signAuth: { eventType: 'SIGN_AUTH_OK' }, signDecision: { eventType: 'SIGN_DECISION' }, anomaly: { eventType: 'ANOMALY_STATE_INCREMENTED' },
        auditExec: { eventType: 'AUDIT_EXECUTION_RECORDED' }, policyExec: { eventType: 'POLICY_EXECUTE' }, t1: { tenantId: 'w10-t1' }, t2Provider: { tenantId: 'w10-t2', eventCategory: 'PROVIDER' },
        info: { severity: 'INFO' }, warn: { severity: 'WARN' }, allow: { outcome: 'ALLOW' }, block: { outcome: 'BLOCK' }, range: { startTime: mid, endTime: midEnd }, enforcement: { eventCategory: 'ENFORCEMENT' } };
      const search = {}; const listings = {};
      for (const [k, f] of Object.entries(filters)) {
        const r = await store.search({ ...f, pageSize: 500 });
        search[k] = r.total;
        if (k === 'warn' || k === 'block') listings[k] = r.events.map((e) => `${e.event_type}|${e.request_id}|${e.severity}|${e.outcome}`).sort();
      }
      const top = Object.fromEntries((await store.topEventTypes(24, 100)).map((r) => [r.event_type, `${r.count}/${r.failure_count}`]));
      const rate = Object.fromEntries((await store.ingestionRate(60)).map((r) => [new Date(r.bucket).toISOString(), `${r.event_count}/${r.security_count}/${r.failure_count}/${r.enforcement_count}`]));
      const collect = async (tenantId) => {
        const out = await collector.collectAll({ periodStart: start, periodEnd: end, tenantId });
        const items = out.evidence || out.items || out;
        return Object.fromEntries((Array.isArray(items) ? items : Object.values(items)).filter((e) => e && e.evidenceType)
          .map((e) => [e.evidenceType, { count: e.count, errorCount: e.errorCount, blockCount: e.blockCount, allowCount: e.allowCount }]));
      };
      const rowCount = Number((await pgPool.query('SELECT count(*)::bigint n FROM platform_audit_events')).rows[0].n);
      results[mode] = { stats: await store.stats(), search, listings, top, rate, compliance: await collect(null), complianceT1: await collect('w10-t1'), rowCount };

      if (mode === 'on') {
        // AGG-06: aggregated ENFORCEMENT counts keep indefinite retention. The REAL retention job
        // (qodiqa_retention) stamps, then every non-ENFORCEMENT row is forced past its expiry and the REAL expiry runs.
        const retentionPool = require('../../src/infra/postgres/retentionPool');
        const retention = require('../../src/core/audit/retention');
        retentionPool.initialize();
        const enf = async () => (await pgPool.query(`SELECT count(*)::int rows, COALESCE(sum(aggregate_count),0)::int events,
            count(*) FILTER (WHERE retain_until IS NOT NULL)::int stamped FROM platform_audit_events
            WHERE event_category = 'ENFORCEMENT' AND payload->>'aggregated' = 'true'`)).rows[0];
        const before = await enf();
        const stamp = await retention.stampRetentionDates();
        const afterStamp = await enf();
        const otherStamped = Number((await pgPool.query(`SELECT count(*) n FROM platform_audit_events WHERE event_category <> 'ENFORCEMENT' AND retain_until IS NOT NULL`)).rows[0].n);
        await pgPool.query(`UPDATE platform_audit_events SET retain_until = NOW() - interval '1 day' WHERE event_category <> 'ENFORCEMENT'`);
        const expire = await retention.expireEvents();
        const afterExpire = await enf();
        const othersLeft = Number((await pgPool.query(`SELECT count(*) n FROM platform_audit_events WHERE event_category <> 'ENFORCEMENT'`)).rows[0].n);
        results.retention = { before, afterStamp, afterExpire, stamp, otherStamped, expire, othersLeft };
        await retentionPool.shutdown().catch(() => {});
      }
      await pgPool.shutdown().catch(() => {});
      await rolePools.shutdownAll().catch(() => {});
    }
  }, 240_000);

  afterAll(async () => {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      for (const d of Object.values(DB)) {
        try { await maint.query(`DROP DATABASE IF EXISTS "${d}" WITH (FORCE)`); } catch (e) { console.warn(`[w10agg] could not drop ${d}: ${e.message}`); }
      }
      await maint.end();
    }
  }, 60_000);

  test('AGG-01 stats(): every count equal; far fewer rows; first/last event within the minute', () => {
    const { off, on } = results;
    const counts = (s) => Object.fromEntries(Object.entries(s).filter(([k]) => /Count$|^total$/.test(k)));
    expect(counts(on.stats)).toEqual(counts(off.stats));
    expect(off.stats.total).toBe(S.ev.length);
    expect(on.rowCount).toBeLessThan(off.rowCount / 3);
    expect(Math.abs(new Date(on.stats.firstEvent) - new Date(off.stats.firstEvent))).toBeLessThan(60_000);
    expect(Math.abs(new Date(on.stats.lastEvent) - new Date(off.stats.lastEvent))).toBeLessThan(60_000);
  });

  test('AGG-02 search(): totals equal for every filter set; non-aggregated listings identical', () => {
    expect(results.on.search).toEqual(results.off.search);
    expect(results.off.search.signAuth).toBeGreaterThan(0);
    expect(results.on.listings).toEqual(results.off.listings);
    expect(results.off.listings.block.length).toBeGreaterThan(0);
  });

  test('AGG-03 topEventTypes(): per-type count and failure_count equal', () => {
    expect(results.on.top).toEqual(results.off.top);
  });

  test('AGG-04 ingestionRate(): every per-minute bucket equal', () => {
    expect(Object.keys(results.off.rate).length).toBeGreaterThanOrEqual(6);
    expect(results.on.rate).toEqual(results.off.rate);
  });

  test('AGG-06 aggregated ENFORCEMENT counts are never stamped nor expired; other categories expire normally', () => {
    const r = results.retention;
    expect(r.before.rows).toBeGreaterThan(0);                       // AUDIT_EXECUTION_RECORDED aggregates exist
    expect(r.afterStamp.stamped).toBe(0);                           // no retain_until on them after the real stamp
    expect(r.otherStamped).toBeGreaterThan(0);                      // the stamp did run on other categories
    expect(r.afterExpire).toEqual({ ...r.before, stamped: 0 });     // same rows, same summed events after expiry
    expect(r.othersLeft).toBe(0);                                   // every forced-expired non-ENFORCEMENT row deleted
  });

  test('AGG-05 compliance evidence counts equal, platform-wide and per tenant', () => {
    expect(Object.keys(results.off.compliance).length).toBeGreaterThan(3);
    expect(results.on.compliance).toEqual(results.off.compliance);
    expect(results.on.complianceT1).toEqual(results.off.complianceT1);
    expect(results.off.compliance.anomaly_events.count).toBeGreaterThan(0);
    expect(results.off.compliance.enforcement_events.count).toBeGreaterThan(0);
  });
});
