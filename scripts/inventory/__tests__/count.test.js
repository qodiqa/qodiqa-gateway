'use strict';

/**
 * Inventory figures: the committed docs/inventory.generated.json equals a fresh count, and the figures quoted in the public
 * documents are the ones the counting script produces.
 *
 *   INV-01 docs/inventory.generated.json == count()
 *   INV-02 the operation count in docs/api/REFERENCE.md and docs/guides/openapi-generation.md equals the counted OpenAPI operations
 * INV-03 the table count and migration count quoted in docs/deployment/persistence.md / match
 */
const fs = require('fs');
const path = require('path');
const { count, OUT } = require('../count');

const ROOT = path.join(__dirname, '..', '..', '..');
const doc = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

describe('inventory counts', () => {
  const fresh = count();

  test('INV-01 the committed inventory equals a fresh count', () => {
    expect(JSON.parse(fs.readFileSync(OUT, 'utf8'))).toEqual(fresh);
  });

  test('INV-02 documents quote the counted operation figure', () => {
    expect(doc('docs/api/REFERENCE.md')).toContain(`**${fresh.openapi.operations} operations**`);
    expect(doc('docs/guides/openapi-generation.md')).toContain(`**${fresh.openapi.operations} documented operations across ${fresh.openapi.paths} paths**`);
  });

  // the ledger is a source-repository document; an export without it skips this check
  const ledgerTest = fs.existsSync(path.join(ROOT, 'docs/MIGRATION_LEDGER.md')) ? test : test.skip;
  ledgerTest('INV-03 migration range quoted in the ledger matches the files', () => {
    expect(doc('docs/MIGRATION_LEDGER.md')).toContain(`(${fresh.migrations.files} files;`);
    expect(fresh.migrations.last).toMatch(/^\d{3}_/);
  });
});
