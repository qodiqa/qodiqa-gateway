'use strict';

/**
 * — audit-log.locateModernCursor(): the startup mirror check (and the runtime advancer) locate the
 * checkpoint entry by counting raw newlines from the start of audit.log instead of JSON-parsing the prefix. A candidate
 * only: it is accepted (mirrorConsistencyCheck._locateConfirmed) when the entry found there carries the expected hash,
 * otherwise the parse-based locate gives today's verdict. Real audit-log, file mode, 20-entry window.
 *
 *   LC-1  every position (inside and outside the window) yields the same entry as getModernEntryAt()
 *   LC-2  a blank line in the prefix shifts the raw count → the candidate is NOT confirmed (null), never trusted
 *   LC-3  with the shifted file the startup fast path still reaches today's verdict through the parse-based locate
 *   LC-4  with a regular file the startup fast path uses the newline locate and checks the same suffix
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const eb = require('../entryBuilder');

const N = 300;

function writeLog(file, { blankAfter = null } = {}) {
  const entries = []; let prev = 'GENESIS'; const lines = [];
  for (let i = 0; i < N; i++) {
    const e = eb.buildEntry(eb.normalizeFields({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: eb.EMPTY_OUTPUT_HASH,
      signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't' }), prev);
    entries.push(e); prev = e.hash; lines.push(JSON.stringify(e));
    if (blankAfter === i) lines.push('');
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
  return entries;
}

function load(file) {
  process.env.QODIQA_AUDIT_LOG = file;
  process.env.QODIQA_AUDIT_WINDOW_SIZE = '20';
  jest.resetModules();
  return { a: require('../audit-log'), mc: require('../mirrorConsistencyCheck') };
}

function fakePg(entries, cpLen) {
  const rows = entries.map((e, i) => ({ ...e, seq: i + 1 }));
  return {
    async getLatestAuditCheckpoint() { return { chainLength: cpLen, hash: entries[cpLen - 1].hash, seq: cpLen }; },
    async countChainRows() { return rows.length; },
    async fetchRowBySeq(seq) { return rows[seq - 1] ? rows[seq - 1].hash : null; },
    async fetchChainBatch(from, n) { return rows.slice(from, from + n); },
  };
}

describe('locateModernCursor', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut08f-lc-')); });
  afterEach(() => {
    delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
    jest.resetModules();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('LC-1 every position yields the same entry as getModernEntryAt()', async () => {
    const file = path.join(dir, 'audit.log');
    const entries = writeLog(file);
    const { a, mc } = load(file);
    expect(a.getChainStats().modernLength).toBe(N);
    for (const pos of [0, 1, 2, 57, 150, 279, 280, 281, N - 1]) {
      const c = a.locateModernCursor(pos);
      expect(c.m).toBe(pos);
      const page = await a.getModernChainPage({ cursor: c, limit: 1, durable: true });
      expect(page.entries[0].hash).toBe((await a.getModernEntryAt(pos)).hash);
      expect(page.entries[0].hash).toBe(entries[pos].hash);
      expect(await mc._locateConfirmed(a, pos, entries[pos].hash)).toMatchObject({ entry: { hash: entries[pos].hash } });
    }
    expect(a.locateModernCursor(N)).toBeNull();
    expect(a.locateModernCursor(-1)).toBeNull();
  });

  test('LC-2 a blank line in the prefix is never trusted (candidate not confirmed)', async () => {
    const file = path.join(dir, 'audit.log');
    const entries = writeLog(file, { blankAfter: 10 });
    const { a, mc } = load(file);
    expect(a.getChainStats().modernLength).toBe(N);                       // the loader skips the blank line
    expect(await mc._locateConfirmed(a, 5, entries[5].hash)).not.toBeNull(); // before the blank line: unaffected
    expect(await mc._locateConfirmed(a, 100, entries[100].hash)).toBeNull(); // after it: shifted → rejected
    expect((await a.getModernEntryAt(100)).hash).toBe(entries[100].hash);   // the parse-based locate is still right
  });

  test('LC-3 shifted file: the startup fast path reaches today\'s verdict through the parse-based locate', async () => {
    const file = path.join(dir, 'audit.log');
    const entries = writeLog(file, { blankAfter: 10 });
    const { a, mc } = load(file);
    const r = await mc._checkpointFastPath({ _auditLog: a, _pgAuditBackend: fakePg(entries, 200), fileCount: N, start: null });
    expect(r).toMatchObject({ ok: true, checkpointLength: 200, suffixChecked: N - 200, locate: 'parse' });
  });

  test('LC-4 regular file: the startup fast path uses the newline locate and checks the same suffix', async () => {
    const file = path.join(dir, 'audit.log');
    const entries = writeLog(file);
    const { a, mc } = load(file);
    const r = await mc._checkpointFastPath({ _auditLog: a, _pgAuditBackend: fakePg(entries, 200), fileCount: N, start: null });
    expect(r).toMatchObject({ ok: true, checkpointLength: 200, suffixChecked: N - 200, locate: 'newline' });
    const pg = fakePg(entries, 200);
    const rows = await pg.fetchChainBatch(0, N);
    rows[250] = { ...rows[250], canonical: rows[250].canonical.replace('"ALLOW"', '"BLOCK"') };
    const tampered = { ...pg, async fetchChainBatch(from, n) { return rows.slice(from, from + n); } };
    expect((await mc._checkpointFastPath({ _auditLog: a, _pgAuditBackend: tampered, fileCount: N, start: null })).ok).toBe(false);
  });
});
