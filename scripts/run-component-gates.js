#!/usr/bin/env node
'use strict';

// run BOTH halves of the component gate, independently, every time.
//
// `npm run test:component` used to be `test:component:serial && test:component:parallel`,
// so any serial failure skipped the parallel half entirely and half the gate
// went unreported. This runner always runs serial first (catalog-touching
// suites, --runInBand — see package.json), then parallel, reports both, and
// exits non-zero if EITHER failed. Extra CLI args are forwarded to both halves
// (e.g. `npm run test:component -- --maxWorkers=2`); environment (e.g.
// QODIQA_ALLOW_PG_INTEGRATION_TESTS=true) is inherited unchanged.

const { spawnSync } = require('child_process');

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const extra = process.argv.slice(2);
const halves = ['test:component:serial', 'test:component:parallel'];
const results = [];

for (const script of halves) {
  const args = ['run', script, ...(extra.length ? ['--', ...extra] : [])];
  process.stdout.write(`\n[test:component] ── ${script} ──\n`);
  const started = Date.now();
  const r = spawnSync(npm, args, { stdio: 'inherit', env: process.env, shell: process.platform === 'win32' });
  const code = r.status === null ? 1 : r.status;
  results.push({ script, code, signal: r.signal, seconds: Math.round((Date.now() - started) / 1000) });
}

process.stdout.write('\n[test:component] summary\n');
for (const r of results) {
  process.stdout.write(`[test:component]   ${r.script.padEnd(24)} ${r.code === 0 ? 'PASS' : 'FAIL'} (exit ${r.code}${r.signal ? `, ${r.signal}` : ''}, ${r.seconds}s)\n`);
}
const failed = results.filter((r) => r.code !== 0);
process.stdout.write(`[test:component] ${failed.length ? `FAIL — ${failed.map((r) => r.script).join(', ')}` : 'PASS — both halves'}\n`);
process.exit(failed.length ? 1 : 0);
