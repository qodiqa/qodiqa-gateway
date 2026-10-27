'use strict';

// step 1 — the test suites' %TEMP% leak, fixed at its source.
//
// 71 test files mkdtemp directories in os.tmpdir() and most never remove them: every full gate round left 525
// qodiqa-* directories behind, over a million accumulated. Instead of hand-patching
// each file (and missing the next one), every directory a test process creates with mkdtemp DIRECTLY inside
// os.tmpdir() is recorded in this run's list, tagged
// "M\t". test/support/jest.globalTeardown.js removes exactly those, in the parent process, after every worker has finished — so
// no test can still be using them. Nothing that existed before the run, and nothing created by a spawned child
// process, is ever recorded here.

const fs = require('fs');
const os = require('os');
const path = require('path');

const LIST = process.env.QODIQA_W1_TMPDIR_LIST;
const TMP = path.resolve(os.tmpdir());
const SYM = Symbol.for('qodiqa.w10.tmpdirTracker');

if (LIST && !fs[SYM]) {
  Object.defineProperty(fs, SYM, { value: true, enumerable: false });
  const record = (dir) => {
    try {
      if (typeof dir === 'string' && path.dirname(path.resolve(dir)) === TMP) fs.appendFileSync(LIST, `M\t${path.resolve(dir)}\n`);
    } catch { /* recording must never fail a test */ }
  };
  const origSync = fs.mkdtempSync;
  fs.mkdtempSync = function trackedMkdtempSync(...args) { const d = origSync.apply(this, args); record(d); return d; };
  const origCb = fs.mkdtemp;
  fs.mkdtemp = function trackedMkdtemp(...args) {
    const cbIdx = args.findIndex((a) => typeof a === 'function');
    if (cbIdx < 0) return origCb.apply(this, args);
    const cb = args[cbIdx];
    args[cbIdx] = (err, d) => { if (!err) record(d); cb(err, d); };
    return origCb.apply(this, args);
  };
  if (fs.promises && typeof fs.promises.mkdtemp === 'function') {
    const origP = fs.promises.mkdtemp;
    fs.promises.mkdtemp = async function trackedMkdtempP(...args) { const d = await origP.apply(this, args); record(d); return d; };
  }
}
