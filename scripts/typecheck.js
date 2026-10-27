'use strict';
/**
 * typecheck for the gateway with a regression budget.
 * Runs `tsc -p tsconfig.typecheck.json`, counts the errors per file and compares them with scripts/typecheck-baseline.json.
 * Fails when a file has MORE errors than the baseline or a new file with errors appears. `--update` rewrites the baseline
 * (allowed only when the total decreases). Existing errors are recorded explicitly in the baseline, not hidden.
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const baselinePath = path.join(__dirname, 'typecheck-baseline.json');
const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
const r = spawnSync(process.execPath, [tsc, '-p', 'tsconfig.typecheck.json', '--pretty', 'false'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
const counts = {};
for (const line of (r.stdout || '').split('\n')) {
  const m = /^(.+?)\(\d+,\d+\): error TS\d+/.exec(line);
  if (m) { const f = m[1].split(path.sep).join('/'); counts[f] = (counts[f] || 0) + 1; }
}
const total = Object.values(counts).reduce((a, b) => a + b, 0);
if (process.argv.includes('--update')) {
  let prev = Infinity;
  try { prev = Object.values(JSON.parse(fs.readFileSync(baselinePath, 'utf8')).files).reduce((a, b) => a + b, 0); } catch (_) {}
  if (total > prev) { console.error(`typecheck: refusing --update: the total increases (${prev} -> ${total})`); process.exit(1); }
  fs.writeFileSync(baselinePath, JSON.stringify({ generatedBy: 'scripts/typecheck.js --update', total, files: counts }, null, 2) + '\n');
  console.log(`typecheck: baseline written (${total} errors in ${Object.keys(counts).length} files)`); process.exit(0);
}
let base = { files: {} };
try { base = JSON.parse(fs.readFileSync(baselinePath, 'utf8')); } catch (_) { console.error('typecheck: the baseline is missing'); process.exit(1); }
const worse = Object.entries(counts).filter(([f, n]) => n > (base.files[f] || 0));
console.log(`typecheck: ${total} errors (baseline ${base.total}); regressions: ${worse.length}`);
if (worse.length) { for (const [f, n] of worse) console.error(`  ${f}: ${n} > baseline ${base.files[f] || 0}`); process.exit(1); }
console.log('typecheck: PASS (no regression against the baseline)');
