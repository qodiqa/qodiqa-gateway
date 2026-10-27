'use strict';

// ── fail any test that attempted to write under data/ ────────────
// test/support/jest.dataIsolation.js refuses such writes and records them; this file turns
// every recorded refusal into a failure of the test (afterEach) or of the file
// (afterAll, for writes made at require time or in beforeAll/afterAll hooks),
// so a refusal swallowed by a try/catch in the code under test still fails.
// A test that deliberately probes the guard drains the record itself via
// global.__qodiqaDataWriteGuard.drain().

function failOnDataWrites(where) {
  const guard = global.__qodiqaDataWriteGuard;
  if (!guard) return;
  const hits = guard.drain();
  if (hits.length) {
    const list = hits.slice(0, 10).map((h) => `  ${h.op} → ${h.target}`).join('\n');
    throw new Error(`data/ write guard: ${hits.length} write(s) under data/ refused ${where}:\n${list}\n` +
      'Point the store at a temp path (see test/support/jest.dataIsolation.js) instead of the real data/ directory.');
  }
}

afterEach(() => failOnDataWrites('during this test'));
afterAll(() => failOnDataWrites('in this file (module load or beforeAll/afterAll)'));

// ── record this file's setup temp dirs for removal ──────────────
// test/support/jest.setup.js (key store, audit log, transparency keys) and
// test/support/jest.dataIsolation.js (stores) each mkdtemp a directory per test file. The
// paths are captured HERE, at file load, before any test can change the env,
// and appended to this run's list; test/support/jest.globalTeardown.js removes them in the
// parent process once every worker has finished. (A process 'exit' listener
// cannot do it: inside a test file `process` is Jest's per-environment copy,
// whose events the real worker process never emits — measured: +1,696 dirs.)
{
  const fs = require('fs');
  const path = require('path');
  const list = process.env.QODIQA_W1_TMPDIR_LIST;
  if (list) {
    const dirs = [process.env.QODIQA_KEYS_PATH, process.env.QODIQA_AUDIT_LOG,
      process.env.QODIQA_TRANSPARENCY_KEYS_PATH, process.env.ORG_STORE_PATH]
      .filter(Boolean).map((f) => path.dirname(path.resolve(f)));
    try { fs.appendFileSync(list, dirs.join('\n') + '\n'); } catch { /* best effort */ }
  }
}
