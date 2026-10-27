'use strict';

/**
 * — the static table inventory parsed SQL COMMENTS as
 * statements: migration 055's header ("migration 001's own CREATE TABLE list") registered a table named "list", so
 * `pg-backup.sh verify` reported "Backup coverage gap — table(s) missing: list" on every database migrated past 055.
 *
 *   TR-01 comments never yield a table (line and block comments)
 *   TR-02 the real inventory contains no phantom: every entry is a table some migration really creates outside a
 *         comment, and "list" is not among them
 *   TR-03 control: real CREATE TABLE forms are still found (IF NOT EXISTS, quoted)
 */

const fs = require('fs');
const path = require('path');
const reg = require('../../scripts/dr/table-registry');

describe('table registry ignores SQL comments', () => {
  test('TR-01 comments never yield a table', () => {
    const sql = "-- migration 001's own CREATE TABLE list\n/* CREATE TABLE ghost (id int) */\nSELECT 1; -- CREATE TABLE trailing\n";
    expect([...reg._parseTableNamesFromSql(sql)]).toEqual([]);
  });

  test('TR-02 the shipped inventory has no phantom entry', () => {
    expect(reg.EXPECTED_TABLES).not.toContain('list');
    const all = fs.readdirSync(reg.MIGRATIONS_DIR).filter((f) => f.endsWith('.sql'))
      .map((f) => fs.readFileSync(path.join(reg.MIGRATIONS_DIR, f), 'utf8')).join('\n');
    const code = all.split(/\r?\n/).map((l) => l.replace(/--.*$/, '')).join('\n');
    for (const t of reg.EXPECTED_TABLES) {
      const created = new RegExp(String.raw`CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?"?` + t + String.raw`"?\b`, 'i').test(code);
      expect({ table: t, created }).toEqual({ table: t, created: true });
    }
  });

  test('TR-03 control: real CREATE TABLE forms are still found', () => {
    const sql = 'CREATE TABLE a (id int);\ncreate table if not exists "b" (id int);\nCREATE TABLE IF NOT EXISTS c(x int); -- trailing note';
    expect([...reg._parseTableNamesFromSql(sql)].sort()).toEqual(['a', 'b', 'c']);
  });
});
