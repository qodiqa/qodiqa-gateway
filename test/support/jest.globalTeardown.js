'use strict';

// remove the per-test-file setup temp dirs this run created.
//
// test/support/jest.setup.js (key store, audit log, transparency keys) and
// test/support/jest.dataIsolation.js (file-backed stores) mkdtemp one directory each per
// test file; nothing ever removed them (234,200 of each test/support/jest.setup.js prefix
// had accumulated in %TEMP% by 2026-09-28). Workers record the directories
// they created in this run's list; this runs once in the parent process after
// every worker has finished, so no test can still be using them. Only a
// directory directly inside os.tmpdir() with one of the four setup prefixes is
// removed — anything else in the list is ignored. Directories from earlier
// runs are not touched here (that backlog is the hygiene sweep's, D1).

const fs = require('fs');
const os = require('os');
const path = require('path');

const SETUP_PREFIXES = ['qodiqa-test-ks-', 'qodiqa-test-audit-', 'qodiqa-test-ts-', 'qodiqa-test-stores-'];

module.exports = async function globalTeardown() {
  const list = process.env.QODIQA_W1_TMPDIR_LIST;
  const tmp = path.resolve(os.tmpdir());
  if (!list || path.dirname(path.resolve(list)) !== tmp || !path.basename(list).startsWith('qodiqa-jest-tmpdirs-')) return;
  let dirs = [];
  try { dirs = [...new Set(fs.readFileSync(list, 'utf8').split('\n').filter(Boolean))]; } catch { return; }
  for (const d of dirs) {
    // step 1: "M\t<dir>" = a directory a test created with mkdtemp directly in os.tmpdir() during THIS run
    // (test/support/jest.tmpdirTracker.js). Untagged lines are's per-file setup dirs, still limited to their four prefixes.
    const tracked = d.startsWith('M\t');
    const dir = path.resolve(tracked ? d.slice(2) : d);
    if (path.dirname(dir) !== tmp || path.basename(dir).startsWith('qodiqa-jest-tmpdirs-')) continue;
    if (!tracked && !SETUP_PREFIXES.some((p) => path.basename(dir).startsWith(p))) continue;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  try { fs.rmSync(list, { force: true }); } catch { /* best effort */ }
};
