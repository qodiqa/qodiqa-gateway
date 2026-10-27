'use strict';

/**
 *the built JS SDK (sdk/javascript/dist, untracked build output) for suites that test
 * the SDK as shipped. A clean checkout has no dist/, and a stale one would test old code, so it is (re)built whenever
 * it is missing or older than any file under sdk/javascript/src. Requires sdk/javascript's own dependencies
 * (`npm --prefix sdk/javascript ci`), as the SDK's own test job does.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const SDK = path.join(__dirname, '..', '..', 'sdk', 'javascript');
const DIST = path.join(SDK, 'dist', 'index.js');

const newest = (dir) => fs.readdirSync(dir, { withFileTypes: true })
  .reduce((m, e) => Math.max(m, e.isDirectory() ? newest(path.join(dir, e.name)) : fs.statSync(path.join(dir, e.name)).mtimeMs), 0);

function ensureJsSdkDist() {
  if (!fs.existsSync(DIST) || fs.statSync(DIST).mtimeMs < newest(path.join(SDK, 'src'))) {
    if (!fs.existsSync(path.join(SDK, 'node_modules'))) {
      throw new Error('sdk/javascript has no node_modules — run: npm --prefix sdk/javascript ci');
    }
    const b = spawnSync('npm', ['--prefix', SDK, 'run', 'build'], { encoding: 'utf8', shell: process.platform === 'win32' });
    if (b.status !== 0) throw new Error(`sdk/javascript build failed: ${(b.stderr || b.stdout || '').slice(-1500)}`);
  }
  return require(DIST);
}

module.exports = { ensureJsSdkDist, SDK_DIST: DIST };
