'use strict';

// create this run's temp-dir list (see test/support/jest.globalTeardown.js).
// Runs once in the parent process before any worker starts; workers inherit
// QODIQA_W1_TMPDIR_LIST from process.env and append the per-file setup temp
// dirs they create (test/support/jest.dataIsolation.afterEnv.js).

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

module.exports = async function globalSetup() {
  const list = path.join(os.tmpdir(), `qodiqa-jest-tmpdirs-${process.pid}-${crypto.randomBytes(4).toString('hex')}.txt`);
  fs.writeFileSync(list, '');
  process.env.QODIQA_W1_TMPDIR_LIST = list;
};
