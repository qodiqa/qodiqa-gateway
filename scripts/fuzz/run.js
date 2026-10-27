#!/usr/bin/env node
'use strict';

/**
 * run the coverage-guided fuzz targets (jazzer.js / libFuzzer) in fuzz/targets.
 *
 *   node scripts/fuzz/run.js [--seconds 30] [--only jcs,sortedJson] [--replay]
 *
 * Each target is fuzzed for --seconds (default 30) with its corpus in fuzz/corpus/<name>/ (seed inputs are committed, discovered inputs
 * stay untracked). A crash writes the reproducer to evidence/fuzz/crashes/<name>-<hash> and fails the run. --replay runs every stored
 * corpus/crash input once without mutating (fast, deterministic: the CI mode). Results are appended to.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const args = process.argv.slice(2);
const opt = (name, dflt) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : dflt; };
const seconds = Number(opt('seconds', 30));
const only = opt('only', null);
const replay = args.includes('--replay');

const targets = fs.readdirSync(path.join(REPO, 'fuzz', 'targets')).filter((f) => f.endsWith('.js')).map((f) => f.replace(/\.js$/, '')).sort()
  .filter((t) => !only || only.split(',').includes(t));
if (!targets.length) { console.error('no targets selected'); process.exit(2); }

const crashDir = path.join(REPO, 'evidence', 'fuzz', 'crashes');
fs.mkdirSync(crashDir, { recursive: true });
const rows = []; let failed = false;
for (const t of targets) {
  const corpus = path.join(REPO, 'fuzz', 'corpus', t);
  fs.mkdirSync(corpus, { recursive: true });
  const libfuzzer = replay ? ['-runs=0'] : [`-max_total_time=${seconds}`];
  const started = Date.now();
  const r = spawnSync(process.execPath, [path.join(REPO, 'node_modules', '@jazzer.js', 'core', 'dist', 'cli.js'), path.join('fuzz', 'targets', `${t}.js`), '--sync', corpus, '--', ...libfuzzer, `-artifact_prefix=${crashDir}${path.sep}${t}-`], { cwd: REPO, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  const runs = (/Done (\d+) runs in (\d+) second/.exec(out) || []);
  const ok = r.status === 0;
  if (!ok) failed = true;
  rows.push({ target: t, ok, runs: runs[1] || '?', secs: runs[2] || String(Math.round((Date.now() - started) / 1000)), detail: ok ? '' : (/(Error: [^\n]*|ERROR: [^\n]*)/.exec(out) || [`exit ${r.status}`])[0].slice(0, 160) });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${t}  ${runs[1] || '?'} runs${ok ? '' : `  ${rows[rows.length - 1].detail}`}`);
}
const stamp = new Date().toISOString();
const md = `\n## ${stamp} ${replay ? '(replay)' : `(${seconds}s per target)`}\n\n| target | result | runs | seconds | detail |\n|---|---|---|---|---|\n${rows.map((x) => `| ${x.target} | ${x.ok ? 'PASS' : 'FAIL'} | ${x.runs} | ${x.secs} | ${x.detail} |`).join('\n')}\n`;
fs.appendFileSync(path.join(REPO, 'evidence', 'fuzz', 'RUNS.md'), md);
process.exit(failed ? 1 : 0);
