'use strict';

/**
 * regression — AlertStore's dedup_key upsert contract.
 *
 * saveAlert()'s `ON CONFLICT (dedup_key) DO UPDATE` never once worked: the only
 * index covering dedup_key was non-unique AND multi-column, so PostgreSQL could
 * infer no arbiter and rejected every insert with 42P10. Every alert fell into
 * saveAlert()'s catch and was pushed to an in-process array instead — alerts
 * survived only until restart and were invisible to every PostgreSQL read path.
 * Verified before the fix: 0 rows in qodiqa_alerts on a database with six days
 * of real use.
 *
 * Migration 047 adds a PARTIAL unique index over the active statuses. Partial
 * means a resolved alert's dedup_key is freed, so a recurrence opens a new
 * alert rather than bumping a closed row's counter — the behavior a plain
 * UNIQUE (dedup_key) would have silently lost.
 *
 * These are pure/SQL-shape assertions; the two behavioral contracts (dedup
 * among active, fresh row after resolution) are exercised against a real
 * database by test/integration/alertStoreDedup.integration.test.js, which needs PG.
 */

const fs = require('fs');
const path = require('path');

const MIGRATION_PATH = path.resolve(
  __dirname, '..', '..', '..', 'infra', 'postgres', 'migrations',
  '047_alerts_dedup_key_unique_active.sql',
);
const ALERT_STORE_PATH = path.resolve(__dirname, '..', 'AlertStore.js');

const { ACTIVE_ALERT_STATUSES, buildDedupKey } = require(ALERT_STORE_PATH);
const MIGRATION_SQL = fs.readFileSync(MIGRATION_PATH, 'utf8');
const ALERT_STORE_SRC = fs.readFileSync(ALERT_STORE_PATH, 'utf8');

// Pulls the status list out of a `status IN ('A', 'B')` clause, normalised so
// ordering/whitespace differences never masquerade as drift.
function statusesFromInClause(sql) {
  const m = sql.match(/status\s+IN\s*\(([^)]*)\)/i);
  if (!m) return null;
  return m[1].split(',').map(s => s.trim().replace(/^'|'$/g, '')).sort();
}

describe('index predicate and ON CONFLICT predicate must not drift apart', () => {
  it('migration 047 creates a UNIQUE index on dedup_key', () => {
    expect(MIGRATION_SQL).toMatch(/CREATE UNIQUE INDEX[\s\S]*qodiqa_alerts_dedup_key_active_uq/i);
    expect(MIGRATION_SQL).toMatch(/ON qodiqa_alerts \(dedup_key\)/i);
  });

  it('the shipped index predicate matches ACTIVE_ALERT_STATUSES exactly', () => {
    // Everything after CREATE UNIQUE INDEX, so the guard block's own
    // `status IN (...)` earlier in the file cannot be what we match on.
    const createStmt = MIGRATION_SQL.slice(MIGRATION_SQL.search(/CREATE UNIQUE INDEX/i));
    expect(statusesFromInClause(createStmt)).toEqual([...ACTIVE_ALERT_STATUSES].sort());
  });

  it("saveAlert()'s ON CONFLICT carries the same predicate as the index", () => {
    const onConflict = ALERT_STORE_SRC.match(/ON CONFLICT \(dedup_key\)[^\n]*/i);
    expect(onConflict).not.toBeNull();
    // The clause is generated from ACTIVE_STATUS_SQL_LIST, so assert the
    // interpolation is actually present rather than a hardcoded list.
    expect(onConflict[0]).toMatch(/WHERE status IN \(\$\{ACTIVE_STATUS_SQL_LIST\}\)/);
  });

  it('ACTIVE_ALERT_STATUSES is exactly the set idx_alerts_status calls active', () => {
    // Migration 006 established this trio; 047 deliberately reuses it rather
    // than inventing a competing notion of activeness in the same schema.
    expect([...ACTIVE_ALERT_STATUSES].sort()).toEqual(['ACKNOWLEDGED', 'INVESTIGATING', 'OPEN']);
  });

  it('excludes every terminal status, so a resolved alert frees its dedup_key', () => {
    for (const terminal of ['RESOLVED', 'CLOSED', 'FALSE_POSITIVE', 'SUPPRESSED']) {
      expect(ACTIVE_ALERT_STATUSES).not.toContain(terminal);
    }
  });

  it('the migration guards against pre-existing duplicates among active rows', () => {
    expect(MIGRATION_SQL).toMatch(/RAISE EXCEPTION/);
    expect(MIGRATION_SQL).toMatch(/HAVING count\(\*\) > 1/);
  });
});

describe('buildDedupKey() is deterministic and never null', () => {
  // The pre-existing index carried `WHERE dedup_key IS NOT NULL`, which
  // excluded nothing: the key is a sha256 and is always produced. Recorded so
  // a future reader does not assume that predicate was doing real work.
  it('produces the same key for the same alert shape', () => {
    const alert = { type: 'T', subtype: 'S', tenantId: 't1', sourceEvent: 'E', publicKeyId: 'k1' };
    expect(buildDedupKey(alert)).toBe(buildDedupKey({ ...alert }));
  });

  it('produces a non-null 64-char key even when every optional field is absent', () => {
    const key = buildDedupKey({ type: 'T', subtype: 'S' });
    expect(typeof key).toBe('string');
    expect(key).toHaveLength(64);
  });

  it('separates alerts that differ in any keyed field', () => {
    const base = { type: 'T', subtype: 'S', tenantId: 't1', sourceEvent: 'E', publicKeyId: 'k1' };
    const keys = new Set([
      buildDedupKey(base),
      buildDedupKey({ ...base, type: 'T2' }),
      buildDedupKey({ ...base, subtype: 'S2' }),
      buildDedupKey({ ...base, tenantId: 't2' }),
      buildDedupKey({ ...base, sourceEvent: 'E2' }),
      buildDedupKey({ ...base, publicKeyId: 'k2' }),
    ]);
    expect(keys.size).toBe(6);
  });
});
