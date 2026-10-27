'use strict';

/**
 * remediation — backup coverage regression guard.
 *
 * This suite needs NO database connection (unlike
 * test/dr/postgresFullCoverage.integration.test.js), so it runs in every CI
 * job, including one with no Postgres service container. Its job is to make
 * the "future protection" requirement concrete: a build must FAIL if
 * a production table becomes silently unprotected by backup/restore.
 *
 * Two independent failure modes it guards against:
 *   1. Someone adds a new CREATE TABLE to a migration and it silently isn't
 *      backed up. This can no longer happen by construction — dumpPostgres()
 *      discovers tables LIVE from information_schema (scripts/dr/postgres.js)
 *      rather than consulting a hand-maintained allow-list — but this test
 *      still asserts that invariant holds so a future refactor can't
 *      quietly reintroduce an allow-list.
 *   2. Someone adds a table to EXCLUDED_TABLES (the only sanctioned way to
 *      opt a table OUT of backup coverage) without a real `reason` —
 *      turning an intentional, reviewed exclusion into an unexplained gap.
 */

const fs = require('fs');
const path = require('path');

const {
  EXPECTED_TABLES,
  EXCLUDED_TABLES,
  BACKED_UP_TABLES,
  parseExpectedTables,
  MIGRATIONS_DIR,
} = require('../../scripts/dr/table-registry');

describe('backup table coverage (offline, no DB required)', () => {
  test('the migration directory actually exists and has migration files', () => {
    expect(fs.existsSync(MIGRATIONS_DIR)).toBe(true);
    const files = fs.readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql'));
    expect(files.length).toBeGreaterThan(0);
  });

  test('parses a substantial, non-trivial table inventory from the migrations', () => {
    // Historical regression marker: was filed because backup covered
    // only ~8 of ~50 tables. This is not a hardcoded expectation of the
    // exact count (that would itself become a silent-drift risk) — it's a
    // sanity floor that catches the parser itself regressing to "finds
    // almost nothing", which would make every other assertion in this file
    // vacuously pass.
    expect(EXPECTED_TABLES.length).toBeGreaterThanOrEqual(50);
  });

  test('parseExpectedTables() is deterministic — same input, same output', () => {
    const first = parseExpectedTables();
    const second = parseExpectedTables();
    expect(second).toEqual(first);
  });

  test('every table QODIQA is known to need (consent, investigation, compliance, audit, security) is present', () => {
    // The exact tables called out by name as missing from backup.
    const mustBeCovered = [
      'consent_records',
      'consent_audit_log',
      'investigations',
      'investigation_artifacts',
      'investigation_audit_events',
      'compliance_reports',
      'compliance_control_assessments',
      'audit_chain',
      'platform_audit_events',
      'policies',
      'rbac_users',
      'signing_keys',
      'kms_provider_events',
      'qodiqa_alerts',
      'qodiqa_incidents',
      'organizations',
      'tenants',
    ];
    for (const table of mustBeCovered) {
      expect(EXPECTED_TABLES).toContain(table);
      expect(BACKED_UP_TABLES).toContain(table);
    }
  });

  test('every EXCLUDED_TABLES entry carries a non-empty justification', () => {
    // The only sanctioned way to opt a real table OUT of backup/restore
    // coverage is an entry here — and every entry must explain itself, so a
    // reviewer (or a future maintainer) can tell "intentional" from "someone
    // forgot".
    for (const [table, meta] of Object.entries(EXCLUDED_TABLES)) {
      expect(typeof meta === 'object' && meta !== null ? meta.reason : meta)
        .toEqual(expect.stringMatching(/\S/));
      // and the excluded table must be a real table, not a typo that
      // silently excludes nothing.
      expect(EXPECTED_TABLES).toContain(table);
    }
  });

  test('BACKED_UP_TABLES is EXACTLY "expected minus excluded" — no drift between the two lists', () => {
    const expectedBackedUp = EXPECTED_TABLES.filter(t => !EXCLUDED_TABLES[t]);
    expect(BACKED_UP_TABLES).toEqual(expectedBackedUp);
  });

  test('every expected table is covered except the reviewed exclusions (current state)', () => {
    // This test intentionally breaks the moment someone adds an exclusion —
    // forcing a conscious update here (and a `reason` in EXCLUDED_TABLES)
    // rather than a silent coverage regression.
    // S2: the one reviewed exclusion is the derived audit_chain_mirror_count (migration 073), which
    // restorePostgres() rebuilds from the restored audit_chain and proves equal to count(*).
    expect(Object.keys(EXCLUDED_TABLES).sort()).toEqual(['audit_chain_mirror_count']);
    expect(BACKED_UP_TABLES).toEqual(EXPECTED_TABLES.filter((t) => t !== 'audit_chain_mirror_count'));
  });

  test('scripts/dr/postgres.js no longer hardcodes a fixed table allow-list', () => {
    // Regression guard for the actual root cause: postgres.js used to
    // export a literal `TABLES` array of 8 names. Backup coverage must come
    // from LIVE discovery, not a list that can go stale as migrations grow.
    const postgresJsSource = fs.readFileSync(
      path.join(__dirname, '..', '..', 'scripts', 'dr', 'postgres.js'),
      'utf8',
    );
    expect(postgresJsSource).toMatch(/discoverTables/);
    expect(postgresJsSource).not.toMatch(/^const TABLES = Object\.freeze\(\[/m);

    const postgresModule = require('../../scripts/dr/postgres.js');
    expect(postgresModule.TABLES).toBeUndefined();
  });
});
