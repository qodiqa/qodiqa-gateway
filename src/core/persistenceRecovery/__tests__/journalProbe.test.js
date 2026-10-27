'use strict';

/** (D2/D6): journal.probeWritable() — creates the directory, writes + fsyncs + removes a probe file; false when the path cannot be written. */

const fs = require('fs');
const os = require('os');
const path = require('path');

function load(dir) {
  jest.resetModules();
  process.env.QODIQA_PRQ_JOURNAL_DIR = dir;
  return require('../journal');
}
afterAll(() => { delete process.env.QODIQA_PRQ_JOURNAL_DIR; });

test('JP-01 a writable (even not yet existing) directory probes true and leaves no probe file behind', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-jp-'));
  const dir = path.join(base, 'new', 'prq-journal');
  const j = load(dir);
  expect(await j.probeWritable()).toBe(true);
  expect(fs.existsSync(dir)).toBe(true);
  expect(fs.readdirSync(dir)).toEqual([]);
});

test('JP-02 a path that cannot be a directory probes false', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-jp-'));
  const file = path.join(base, 'afile');
  fs.writeFileSync(file, 'x');
  const j = load(path.join(file, 'prq-journal'));          // a directory "under" a regular file
  expect(await j.probeWritable()).toBe(false);
});
