'use strict';

/**
 * PL13-09 — the DR JSON restore
 * order must be FK-safe when the dump runs as the SHIPPED backup identity (qodiqa_backup: SELECT-only, owns nothing).
 *
 * scripts/dr/table-registry.js getRestoreOrder() read the FK graph from information_schema.constraint_column_usage,
 * which only lists constraints on tables owned by a currently enabled role. As qodiqa_backup it saw ZERO foreign keys,
 * the order fell back to alphabetical, and restorePostgres() failed on consent_audit_log (sorted before its parent
 * consent_records) — reproduced on a real disposable cluster. CI never caught it because CI dumps as the superuser.
 *
 * Read-only: no DDL, no writes. Opt-in like every PostgreSQL suite and targets ONLY the explicit process env
 * (test/helpers/disposableTargets.js — never .env, never the local 5432):
 * bash npx jest test/dr/restoreOrderBackupRole.integration.test.js
 * Needs a migrated database (QODIQA_PG_DATABASE) and the backup role's password (QODIQA_PG_BACKUP_PASSWORD).
 */

const { Client } = require('pg');
const { pgTarget } = require('../helpers/disposableTargets');
const { getRestoreOrder, discoverTables } = require('../../scripts/dr/table-registry');

const T = pgTarget();
const DB = process.env.QODIQA_PG_DATABASE;
const BACKUP_USER = process.env.QODIQA_PG_BACKUP_USER || 'qodiqa_backup';
const BACKUP_PASSWORD = process.env.QODIQA_PG_BACKUP_PASSWORD;
const RUN = T.available && !!DB && !!BACKUP_PASSWORD && !!T.adminUser;

(RUN ? describe : describe.skip)('PL13-09 DR restore order as the backup role (real PostgreSQL)', () => {
  jest.setTimeout(60_000);
  let backup; let admin;

  beforeAll(async () => {
    backup = new Client({ host: T.host, port: T.port, database: DB, user: BACKUP_USER, password: BACKUP_PASSWORD });
    admin = new Client({ host: T.host, port: T.port, database: DB, user: T.adminUser, password: T.adminPassword });
    await backup.connect();
    await admin.connect();
  });
  afterAll(async () => { await backup?.end().catch(() => {}); await admin?.end().catch(() => {}); });

  test('RO-01 the dump identity owns no table (so this exercises the non-owner path production uses)', async () => {
    const { rows } = await backup.query(
      "SELECT count(*)::int AS n FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)");
    expect(rows[0].n).toBe(0);
  });

  test('RO-02 every foreign-key parent is ordered before its child, consent_records before consent_audit_log', async () => {
    const tables = await discoverTables(backup);
    const order = await getRestoreOrder(backup, tables);
    expect([...order].sort()).toEqual([...tables].sort());
    // ground truth from the catalog, read by the owner/admin identity
    const { rows: edges } = await admin.query(`
      SELECT ch.relname AS child, pa.relname AS parent FROM pg_constraint c
      JOIN pg_class ch ON ch.oid = c.conrelid JOIN pg_class pa ON pa.oid = c.confrelid
      WHERE c.contype = 'f' AND ch.relnamespace = 'public'::regnamespace AND pa.relnamespace = 'public'::regnamespace AND ch.oid <> pa.oid`);
    const pos = new Map(order.map((t, i) => [t, i]));
    const relevant = edges.filter((e) => pos.has(e.child) && pos.has(e.parent));
    expect(relevant.length).toBeGreaterThanOrEqual(10);
    const violations = relevant.filter((e) => pos.get(e.parent) > pos.get(e.child)).map((e) => `${e.parent} -> ${e.child}`);
    expect(violations).toEqual([]);
    expect(pos.get('consent_records')).toBeLessThan(pos.get('consent_audit_log'));
  });
});
