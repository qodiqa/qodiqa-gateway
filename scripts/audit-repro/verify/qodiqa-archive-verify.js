#!/usr/bin/env node
'use strict';

/**
 * qodiqa-archive-verify — verify sealed audit archive exports offline.
 *
 *   node scripts/audit-repro/verify/qodiqa-archive-verify.js --checkpoint-keys keys.json --archive <export dir>
 *   node scripts/audit-repro/verify/qodiqa-archive-verify.js --checkpoint-keys keys.json --index <archive root>
 *
 * keys.json = the body of /.well-known/qodiqa/checkpoint-keys (or the keys/checkpoint-keys.json of an anchors repository).
 * Prints a JSON verdict; exit 0 valid, 1 invalid, 2 usage / input error. Imports nothing from src/.
 */

const fs = require('fs');
const { keyResolver } = require('./checkpoint');
const { verifyExport, verifyIndex } = require('./archive');

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) if (argv[i].startsWith('--')) out[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
  return out;
}

function main(argv = process.argv.slice(2)) {
  const a = args(argv);
  if (typeof a['checkpoint-keys'] !== 'string' || (typeof a.archive !== 'string') === (typeof a.index !== 'string')) {
    process.stderr.write('usage: qodiqa-archive-verify --checkpoint-keys <file> (--archive <export dir> | --index <archive root>)\n'); return 2;
  }
  let resolve;
  try { resolve = keyResolver(JSON.parse(fs.readFileSync(a['checkpoint-keys'], 'utf8'))); } catch (e) { process.stderr.write(`cannot read the keys: ${e.message}\n`); return 2; }
  const report = typeof a.archive === 'string' ? verifyExport(a.archive, resolve) : verifyIndex(a.index, resolve);
  process.stdout.write(`${JSON.stringify(report)}\n`);
  return report.valid ? 0 : 1;
}

if (require.main === module) process.exit(main());
module.exports = { main };
