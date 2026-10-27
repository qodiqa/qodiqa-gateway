'use strict';

/**
 * — the startup mirror-consistency fast path now STREAMS the suffix since the last checkpoint
 * (previously both whole suffixes were materialised; after a 1-h soak — 430k entries — that exhausted the heap at boot).
 * The security checks must be unchanged, including across PAGE BOUNDARIES, where a naive per-page verification would
 * lose cross-entry state. 12,000 valid chained entries (production entryBuilder), checkpoint at entry 1,000, pages of
 * 5,000 → the suffix spans three pages on both sides. Every case is also run through the previous materialising
 * implementation (_checkpointSuffixMaterialised) and must reach the same verdict.
 *
 *   FP-1  consistent mirror → ok, 11,000 suffix entries checked
 *   FP-2  one PG row's canonical body changed mid-suffix → rejected
 *   FP-3  the same artifactId on BOTH sides of a page boundary (validly re-hashed chain) → rejected (duplicate detection
 *         carried across pages)
 *   FP-4  a PG row whose prevHash breaks the link exactly at the first page boundary (re-hashed) → rejected
 *   FP-5  PG holds one row fewer than the file → rejected
 */

const crypto = require('crypto');
const auditLog = require('../audit-log');
const eb = require('../entryBuilder');
const mc = require('../mirrorConsistencyCheck');

const N = 12_000;
const CP = 1_000;

function buildChain({ duplicateAt = null } = {}) {
  const entries = []; let prev = 'GENESIS'; let dupId = null;
  for (let i = 0; i < N; i++) {
    let artifactId = crypto.randomUUID();
    if (duplicateAt && i === duplicateAt[0]) dupId = artifactId;
    if (duplicateAt && i === duplicateAt[1]) artifactId = dupId;
    const e = eb.buildEntry(eb.normalizeFields({ artifactId, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: eb.EMPTY_OUTPUT_HASH,
      signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't' }), prev);
    entries.push(e); prev = e.hash;
  }
  return entries;
}

function rehashFrom(entries, from, mutate) {
  // Re-chain from `from` after mutating entry `from` — a VALID chain on its own (an insider re-signing history).
  const out = entries.slice(0, from);
  let prev = from === 0 ? 'GENESIS' : out[from - 1].hash;
  for (let i = from; i < entries.length; i++) {
    const fields = JSON.parse(entries[i].canonical);
    const f = i === from ? mutate(fields) : fields;
    const e = eb.buildEntry(eb.normalizeFields({ artifactId: entries[i].artifactId, inputHash: f.inputHash ?? 'a'.repeat(64), decision: f.decision ?? 'ALLOW',
      outputHash: eb.EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
      tenantId: f.tenantId ?? 't' }), i === from && f.__prevHash ? f.__prevHash : prev);
    out.push(e); prev = e.hash;
  }
  return out;
}

function fakeAuditLog(fileEntries) {
  return {
    createChainWalker: auditLog.createChainWalker,
    verifyAuditChainDetailed: auditLog.verifyAuditChainDetailed,
    async getModernEntryAt(pos) { return fileEntries[pos] || null; },
    async getModernChainSlice(from) { return fileEntries.slice(from); },
    async getModernChainPage({ cursor, limit }) {
      const from = cursor && Number.isInteger(cursor.m) ? cursor.m : 0;
      const entries = fileEntries.slice(from, from + limit);
      const next = from + entries.length;
      return { entries, startPos: from, nextCursor: next < fileEntries.length ? { m: next } : null };
    },
  };
}

function fakePg(rows) { // rows: [{...entry, seq}] — seq = position + 1
  const cpRow = rows[CP - 1];
  return {
    async getLatestAuditCheckpoint() { return { chainLength: CP, hash: cpRow.hash, seq: cpRow.seq }; },
    async countChainRows() { return rows.length; },
    async fetchRowBySeq(seq) { const r = rows.find((x) => x.seq === seq); return r ? r.hash : null; },
    async fetchChainBatch(from, n) { const i = rows.findIndex((x) => x.seq > from); return i < 0 ? [] : rows.slice(i, i + n); },
  };
}
const asRows = (entries) => entries.map((e, i) => ({ ...e, seq: i + 1 }));

async function both(fileEntries, pgRows) {
  const _auditLog = fakeAuditLog(fileEntries); const _pgAuditBackend = fakePg(pgRows);
  const streamed = await mc._checkpointFastPath({ _auditLog, _pgAuditBackend, fileCount: fileEntries.length, start: null });
  const cp = await _pgAuditBackend.getLatestAuditCheckpoint();
  const pgTotal = await _pgAuditBackend.countChainRows();
  const materialised = pgTotal !== fileEntries.length ? { ok: false, reason: 'COUNT_MISMATCH' }
    : await mc._checkpointSuffixMaterialised({ _auditLog, _pgAuditBackend, cp, pgTotal });
  return { streamed, materialised };
}

describe('streaming mirror fast path', () => {
  const base = buildChain();

  test('FP-1 consistent mirror → ok, the whole suffix checked', async () => {
    const { streamed, materialised } = await both(base, asRows(base));
    expect(streamed).toMatchObject({ ok: true, checkpointLength: CP, suffixChecked: N - CP, tailSeq: N });
    expect(materialised).toMatchObject({ ok: true, suffixChecked: N - CP, tailSeq: N });
  });

  test('FP-2 a PG row with a changed body mid-suffix → rejected', async () => {
    const rows = asRows(base);
    rows[6000] = { ...rows[6000], canonical: rows[6000].canonical.replace('"ALLOW"', '"BLOCK"') };
    const { streamed, materialised } = await both(base, rows);
    expect(streamed.ok).toBe(false);
    expect(materialised.ok).toBe(false);
  });

  test('FP-3 the same artifactId across a page boundary (validly re-hashed) → rejected on both paths', async () => {
    const dup = buildChain({ duplicateAt: [CP + 4998, CP + 5002] }); // suffix positions 4998 and 5002: pages 1 and 2
    const { streamed, materialised } = await both(dup, asRows(dup));
    expect(streamed).toMatchObject({ ok: false, reason: 'PG_SUFFIX_INVALID' });
    expect(materialised.ok).toBe(false);
  });

  test('FP-4 a broken link exactly at the first page boundary (re-hashed PG history) → rejected', async () => {
    const forged = rehashFrom(base, CP + 5000, (f) => ({ ...f, __prevHash: 'f'.repeat(64) }));
    const { streamed, materialised } = await both(base, asRows(forged));
    expect(streamed.ok).toBe(false);
    expect(materialised.ok).toBe(false);
  });

  test('FP-5 PG one row short → rejected', async () => {
    const { streamed } = await both(base, asRows(base).slice(0, N - 1));
    expect(streamed).toMatchObject({ ok: false, reason: 'COUNT_MISMATCH' });
  });
});
