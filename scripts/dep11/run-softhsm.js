#!/usr/bin/env node
'use strict';

/**
 *run src/infra/keys/providers/hsm.js against SoftHSM2 in the qodiqa-dep11-softhsm image.
 * Builds the image if missing; uses ONE named container (qodiqa-dep11-softhsm), created on first use and re-used —
 * never removed — with the repository bind-mounted read-only at /repo.
 *
 * Usage:  node scripts/dep11/run-softhsm.js [--out <file>]
 * Writes: (or --out).
 */

const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const IMAGE = 'qodiqa-dep11-softhsm:1';
const NAME = 'qodiqa-dep11-softhsm';
const outIdx = process.argv.indexOf('--out');
const OUT = outIdx > 0 ? path.resolve(process.argv[outIdx + 1]) : path.join(ROOT, 'kms-emulator-results', 'softhsm-run.json');

const docker = (args) => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

try { docker(['image', 'inspect', IMAGE]); } catch {
  execFileSync('docker', ['build', '-t', IMAGE, path.join(__dirname, 'hsm')], { stdio: 'inherit' });
}
let state = null;
try { state = docker(['inspect', '-f', '{{.State.Status}}', NAME]); } catch { /* not created yet */ }
if (state === null) {
  const mount = `${ROOT.replace(/\\/g, '/')}:/repo:ro`;
  docker(['create', '--name', NAME, '-v', mount, '--entrypoint', 'sleep', IMAGE, 'infinity']);
}
if (state !== 'running') docker(['start', NAME]);

// The test script points SoftHSM at a fresh per-run token directory itself (nothing is cleared or removed).
const r = spawnSync('docker', ['exec', '-e', 'NODE_PATH=/hsm/node_modules',
  NAME, 'node', '/repo/scripts/dep11/hsm/hsm-emulator-test.js'], { encoding: 'utf8' });
const line = (r.stdout || '').trim().split('\n').pop();
let res;
try { res = JSON.parse(line); } catch { res = { error: 'no result line', stdout: r.stdout, stderr: r.stderr }; }
res.exit = r.status;
res.ranAt = new Date().toISOString();
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(res, null, 2) + '\n');
docker(['stop', '-t', '1', NAME]);
console.log(`SoftHSM run: ${res.passed}/${res.total} passed (exit ${r.status}) -> ${path.relative(ROOT, OUT)}`);
for (const x of res.results || []) if (x.status !== 'passed') console.log(`  FAIL ${x.id}: ${x.error}`);
process.exit(r.status === 0 ? 0 : 1);
