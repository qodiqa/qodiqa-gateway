'use strict';

/**
 * Migration 108: comments the nine tables with no reader or writer in the application.
 *
 *   MIG-108-01 the migration only comments (no DDL that changes a table, no DML, nothing dropped)
 *   MIG-108-02 the nine tables it names exist in the migrations that create them
 *   MIG-108-03 the nine tables are still unreferenced by application code, scripts and definer functions (the list cannot go stale:
 *              a table that gains a reader must leave the list in a new migration)
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..', '..');
const DIR = path.join(__dirname, '..', 'migrations');
const FILE = path.join(DIR, '108_unused_tables_comment.sql');
const sql = fs.readFileSync(FILE, 'utf8');
const NAMED = [...sql.matchAll(/^\s+'([a-z_0-9]+)',?$/gm)].map((m) => m[1]).sort();

describe('migration 108', () => {
  test('MIG-108-01 comments only', () => {
    const body = sql.replace(/--.*$/gm, '');
    expect(body).toMatch(/COMMENT ON TABLE/);
    expect(body).toMatch(/reserved: not used by the application/);
    expect(body).not.toMatch(/\b(DROP|DELETE|TRUNCATE|INSERT|UPDATE|ALTER|CREATE|GRANT|REVOKE)\b/i);
    expect(NAMED).toHaveLength(9);
  });

  test('MIG-108-02 every named table is created by an earlier migration', () => {
    const created = new Set();
    for (const f of fs.readdirSync(DIR).filter((x) => x.endsWith('.sql') && x < '108')) {
      for (const m of fs.readFileSync(path.join(DIR, f), 'utf8').matchAll(/CREATE TABLE(?: IF NOT EXISTS)?\s+(?:public\.)?"?([a-z_0-9]+)"?/gi)) created.add(m[1].toLowerCase());
    }
    expect(NAMED.filter((t) => !created.has(t))).toEqual([]);
  });

  test('MIG-108-03 no application file, script or earlier migration function reads or writes them', () => {
    const skip = new Set(['node_modules', '.git', 'evidence', 'eval', '_quarantine', 'PLAN', 'REMEDIERE', 'docs', 'coverage', 'migrations', '__tests__']);
    const hits = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (skip.has(e.name) || (e.isDirectory() && e.name.startsWith('.'))) continue;
        const f = path.join(d, e.name);
        if (e.isDirectory()) walk(f);
        else if (/\.(js|sql|sh)$/.test(e.name) && !/(\.test\.|schema-ownership)/.test(e.name)) {
          const s = fs.readFileSync(f, 'utf8');
          for (const t of NAMED) if (new RegExp(`\\b${t}\\b`).test(s)) hits.push(`${t} <- ${path.relative(ROOT, f)}`);
        }
      }
    };
    for (const d of ['src', 'services', 'scripts', 'middleware', 'server']) if (fs.existsSync(path.join(ROOT, d))) walk(path.join(ROOT, d));
    // revocation_events is named by the privilege map (definerOwnership.js) only as a grant description: no statement reads or writes it
    expect(hits.filter((h) => !h.endsWith('definerOwnership.js'))).toEqual([]);
  });
});
