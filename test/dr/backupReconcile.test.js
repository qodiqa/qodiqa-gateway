'use strict';

// step 5 — the JSON DR backup can no longer be silently incomplete:
//   dumpPostgres refuses a role that Row-Level Security filters (before reading a row), fails on any table it cannot
//   dump completely, and records an independent snapshot count per table; dr:verify reconciles every one of those
//   facts (still without a database connection); restorePostgres reports the rows ON CONFLICT DO NOTHING skipped.
// No database: pg is replaced by a scripted fake. The real-PostgreSQL proof is and the
// suite (test/dr/distributedAuditRestore.integration.test.js), which now dumps as qodiqa_backup.

const fs = require('fs');
const os = require('os');
const path = require('path');

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w10-bk-')); }

// A scripted pg: `tables` = { name: { rows, count?, rls?, deny? } }, `role` = pg_roles row.
function fakePg({ tables, role, insertRowCounts = [] }) {
  const queries = [];
  let inserts = 0;
  const query = async (sql, params = []) => {
    queries.push(sql);
    if (/^(BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|ROLLBACK TO)/.test(sql)) return { rows: [] };
    if (sql.includes('information_schema.tables')) return { rows: Object.keys(tables).map((t) => ({ table_name: t })) };
    if (sql.includes('information_schema.table_constraints') || sql.includes('confrelid') || sql.includes('REFERENCES')) return { rows: [] };
    if (sql.includes("to_regclass('public.qodiqa_migrations')")) return { rows: [{ er16: false }] }; // a pre-079 fake schema
    if (sql.includes('pg_catalog.pg_roles')) return { rows: [role] };
    if (sql.includes('relrowsecurity')) return { rows: Object.entries(tables).filter(([, t]) => t.rls).map(([relname]) => ({ relname })) };
    if (sql.includes('information_schema.columns') && sql.includes('column_name = $2')) return { rows: [{ '?column?': 1 }] };
    if (sql.includes('information_schema.columns')) return { rows: [] };
    const m = sql.match(/FROM "([^"]+)"/);
    if (m && tables[m[1]] && tables[m[1]].deny) { const e = new Error(`permission denied for table ${m[1]}`); e.code = '42501'; throw e; }
    if (/SELECT count\(\*\)::bigint AS n FROM/.test(sql)) return { rows: [{ n: String(tables[m[1]].count ?? tables[m[1]].rows.length) }] };
    if (/^SELECT \* FROM/.test(sql)) return { rows: tables[m[1]].rows };
    if (/^INSERT INTO/.test(sql)) return { rowCount: insertRowCounts[inserts++] ?? 1 };
    return { rows: [] };
  };
  class Pool { constructor() {} async connect() { return { query, release() {} }; } query(sql, p) { return query(sql, p); } async end() {} }
  return { Pool, queries };
}

function loadWithPg(fake) {
  jest.resetModules();
  jest.doMock('pg', () => ({ Pool: fake.Pool }));
  jest.doMock('../../scripts/dr/table-registry', () => {
    const real = jest.requireActual('../../scripts/dr/table-registry');
    return { ...real, discoverTables: async (c) => (await c.query('SELECT table_name FROM information_schema.tables')).rows.map((r) => r.table_name),
      getRestoreOrder: async (_c, t) => t };
  });
  return require('../../scripts/dr/postgres');
}

// D-P: a correctly provisioned backup role is RLS-exempt AND a pg_read_all_data member.
const exemptRole = { name: 'qodiqa_backup', superuser: false, bypass_rls: true, read_all_data: true };
const exemptNoReadAll = { name: 'qodiqa_backup', superuser: false, bypass_rls: true, read_all_data: false };
const appRole = { name: 'qodiqa_app', superuser: false, bypass_rls: false, read_all_data: false };

afterEach(() => { jest.dontMock('pg'); jest.dontMock('../../scripts/dr/table-registry'); });

describe('dumpPostgres fails closed', () => {
  test('DP-01 a role Row-Level Security filters is refused before any row is read', async () => {
    const fake = fakePg({ role: appRole, tables: { audit_chain: { rls: true, rows: [{ id: 1 }] }, plain: { rows: [] } } });
    const { dumpPostgres } = loadWithPg(fake);
    const dir = tmp();
    await expect(dumpPostgres(dir, { connectionString: 'postgresql://x/y' })).rejects.toMatchObject({ code: 'BACKUP_ROLE_NOT_RLS_EXEMPT' });
    expect(fake.queries.some((q) => /^SELECT \* FROM/.test(q))).toBe(false);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  test('DP-01b D-P an RLS-exempt role WITHOUT pg_read_all_data is refused before any row is read; nothing is written', async () => {
    const fake = fakePg({ role: exemptNoReadAll, tables: { audit_chain: { rls: true, rows: [{ id: 1 }] }, plain: { rows: [] } } });
    const { dumpPostgres } = loadWithPg(fake);
    const dir = tmp();
    await expect(dumpPostgres(dir, { connectionString: 'postgresql://x/y' })).rejects.toMatchObject({ code: 'BACKUP_ROLE_READ_ALL_DATA_MISSING' });
    expect(fake.queries.some((q) => /^SELECT \* FROM/.test(q))).toBe(false);
    expect(fs.readdirSync(dir)).toEqual([]);
  });

  test('DP-02 an unreadable table fails the whole dump (was: present:false and success) and every failure is named', async () => {
    const fake = fakePg({ role: exemptRole, tables: { a: { rows: [{ id: 1 }] }, denied1: { deny: true, rows: [] }, denied2: { deny: true, rows: [] } } });
    const { dumpPostgres } = loadWithPg(fake);
    const err = await dumpPostgres(tmp(), { connectionString: 'postgresql://x/y' }).catch((e) => e);
    expect(err.code).toBe('BACKUP_INCOMPLETE');
    expect(err.message).toMatch(/denied1/);
    expect(err.message).toMatch(/denied2/);
    expect(err.partial.tables.filter((t) => !t.present).map((t) => t.table)).toEqual(['denied1', 'denied2']);
  });

  test('DP-03 a count that disagrees with the rows read fails the dump', async () => {
    const fake = fakePg({ role: exemptRole, tables: { a: { rows: [{ id: 1 }, { id: 2 }], count: 3 } } });
    const { dumpPostgres } = loadWithPg(fake);
    await expect(dumpPostgres(tmp(), { connectionString: 'postgresql://x/y' })).rejects.toMatchObject({ code: 'BACKUP_INCOMPLETE' });
  });

  test('DP-04 a complete dump records role, RLS exposure, snapshot and a per-table sourceRowCount', async () => {
    const fake = fakePg({ role: exemptRole, tables: { audit_chain: { rls: true, rows: [{ id: 1 }, { id: 2 }] } } });
    const { dumpPostgres } = loadWithPg(fake);
    const r = await dumpPostgres(tmp(), { connectionString: 'postgresql://x/y' });
    expect(r).toMatchObject({ rlsExempt: true, rlsTables: ['audit_chain'], snapshot: 'repeatable-read-read-only', role: { name: 'qodiqa_backup', bypassRls: true } });
    expect(r.tables[0]).toMatchObject({ table: 'audit_chain', present: true, rowCount: 2, sourceRowCount: 2 });
    expect(fake.queries[0]).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  });
});

describe('restorePostgres reports skipped rows', () => {
  test('RP-01 rows ON CONFLICT DO NOTHING skipped are counted, not reported as restored', async () => {
    const fake = fakePg({ role: exemptRole, tables: {}, insertRowCounts: [1, 0, 1, 0, 0] });
    const { restorePostgres } = loadWithPg(fake);
    const dir = tmp();
    fs.writeFileSync(path.join(dir, 'pg_t.json'), JSON.stringify([{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }, { id: 5 }]));
    const r = await restorePostgres(dir, { tables: [{ table: 't', present: true, archiveFile: 'pg_t.json', rowCount: 5 }] }, { connectionString: 'postgresql://x/y' });
    expect(r.tables[0]).toMatchObject({ table: 't', restored: 2, skipped: 3, expected: 5 });
    expect(r.skippedRows).toBe(3);
    expect(r.skippedByTable).toEqual([{ table: 't', skipped: 3 }]);
  });
});

describe('dr:verify reconciles (no database)', () => {
  const { buildManifest } = require('../../scripts/dr/manifest');
  const { verifyBackup } = require('../../scripts/dr/verify');
  function backup(pg, archives) {
    const dir = tmp();
    for (const [f, rows] of Object.entries(archives)) fs.writeFileSync(path.join(dir, f), JSON.stringify(rows));
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(buildManifest({ backupId: 'w10', createdAt: new Date().toISOString(),
      appVersion: 't', components: [], postgres: pg, redis: null, auditOrderingMode: 'single-node' })));
    return dir;
  }
  const full = [{ id: 1, tenant_id: 'a' }, { id: 2, tenant_id: null }, { id: 3, tenant_id: 'b' }];
  const good = () => ({ role: { name: 'qodiqa_backup', bypassRls: true }, rlsExempt: true, rlsTables: ['audit_chain'],
    tables: [{ table: 'audit_chain', present: true, rowCount: 3, sourceRowCount: 3, archiveFile: 'pg_audit_chain.json' }],
    coverage: { discoveredTableCount: 1, dumpedTableCount: 1 } });

  test('VR-01 a complete, reconciled backup passes', () => {
    const r = verifyBackup(backup(good(), { 'pg_audit_chain.json': full }));
    expect(r.errors).toEqual([]);
    expect(r.valid).toBe(true);
    expect(r.postgresTablesChecked).toBe(1);
  });

  test('VR-02 the shape — RLS-truncated archive WITH a matching rowCount, dumped as qodiqa_app — now fails', () => {
    const pg = good(); pg.role = { name: 'qodiqa_app', bypassRls: false }; pg.rlsExempt = false; pg.tables[0].rowCount = 1;
    const r = verifyBackup(backup(pg, { 'pg_audit_chain.json': full.filter((x) => x.tenant_id === null) }));
    expect(r.valid).toBe(false);
    expect(r.errors.join('\n')).toMatch(/POSTGRES_BACKUP_ROLE_NOT_RLS_EXEMPT/);
    expect(r.errors.join('\n')).toMatch(/POSTGRES_ROW_COUNT_UNRECONCILED: table "audit_chain" archive has 1 rows, the snapshot count at dump time was 3/);
  });

  test('VR-03 a table recorded as not dumped fails verify (it used to be skipped silently)', () => {
    const pg = good(); pg.tables.push({ table: 'evidence_chain_records', present: false, reason: 'permission denied' });
    pg.coverage = { discoveredTableCount: 2, dumpedTableCount: 1 };
    const r = verifyBackup(backup(pg, { 'pg_audit_chain.json': full }));
    expect(r.valid).toBe(false);
    expect(r.errors.join('\n')).toMatch(/POSTGRES_TABLE_NOT_DUMPED: table "evidence_chain_records"/);
    expect(r.errors.join('\n')).toMatch(/POSTGRES_TABLE_COVERAGE_MISMATCH: 1 of 2/);
  });

  test('VR-04 an earlier manifest cannot be proven complete', () => {
    const pg = good(); delete pg.rlsExempt; delete pg.rlsTables; delete pg.role; delete pg.tables[0].sourceRowCount;
    const r = verifyBackup(backup(pg, { 'pg_audit_chain.json': full }));
    expect(r.valid).toBe(false);
    expect(r.errors.join('\n')).toMatch(/POSTGRES_BACKUP_NOT_RECONCILABLE/);
  });
});
