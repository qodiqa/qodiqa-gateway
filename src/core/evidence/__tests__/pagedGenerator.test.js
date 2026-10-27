'use strict';

/**
 * — the evidence generator walks the chain page by page instead of materialising it with
 * getAuditChain() per request. Invariants E-1..E-6:
 *
 *
 * Real audit-log in file mode, a 20-entry window (so the walk takes the durable, paged path), 2,500 valid chained
 * entries (production entryBuilder) with replays; pages of 1,000. Every result is compared with the PREVIOUS
 * computation — getAuditChain() + verifyAuditChainDetailed(chain) + chain.findIndex / chain.filter / chain.length — on
 * the same file ("oracle").
 *
 *   PG-1  package audit section, verification output and both exports equal the oracle (artifacts on, before and after
 *         page boundaries, inside and outside the window)
 *   PG-2  tampering: an entry's canonical changed without re-hashing at a page boundary → invalid + tamperingDetected,
 *         identical verdict to the oracle; verification overallStatus COMPROMISED
 *   PG-3  the same artifactId on both sides of a page boundary (validly re-hashed chain) → AUDIT_DUPLICATE_ENTRY, as the
 *         oracle
 *   PG-4  a broken prevHash link exactly at a page boundary → invalid, as the oracle
 *   PG-5  streamAuditChainExport writes exactly the oracle's entries (byte-identical JSON) with the same meta
 * PG-6 a read failure: every generator entry point rejects with AUDIT_HISTORY_UNAVAILABLE (design decision
 *         2026-10-11 — replaces the previous empty-chain result that was kept here for compatibility)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const eb = require('../../audit/entryBuilder');

const N = 2500;

function fields(i, artifactId, replayOf = null) {
  return eb.normalizeFields({ artifactId, inputHash: 'a'.repeat(64), decision: replayOf ? 'BLOCK' : 'ALLOW',
    outputHash: eb.EMPTY_OUTPUT_HASH, signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
    verificationResult: !replayOf, tenantId: `t-${i % 3}`,
    executionContext: replayOf ? { stage: 'ENFORCE', reason: 'REPLAY_DETECTED', replayOf } : { stage: 'ENFORCE', reason: 'ALL_CHECKS_PASSED' } });
}

// ids[i] = artifactId at position i. Replays of ids[REPLAYED] at positions in REPLAY_AT.
const REPLAYED = 998;
const REPLAY_AT = [1000, 1001, 2000];
function writeLog(file, { duplicateAt = null, breakLinkAt = null } = {}) {
  const ids = []; const lines = []; let prev = 'GENESIS';
  for (let i = 0; i < N; i++) {
    let id = crypto.randomUUID();
    if (duplicateAt && i === duplicateAt[1]) id = ids[duplicateAt[0]];
    ids.push(id);
    const replayOf = REPLAY_AT.includes(i) ? ids[REPLAYED] : null;
    const e = eb.buildEntry(fields(i, id, replayOf), i === breakLinkAt ? 'f'.repeat(64) : prev);
    lines.push(JSON.stringify(e)); prev = e.hash;
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
  return { ids, lines };
}

function load(file) {
  process.env.QODIQA_AUDIT_LOG = file;
  process.env.QODIQA_AUDIT_WINDOW_SIZE = '20';
  jest.resetModules();
  const a = require('../../audit/audit-log');
  const g = require('../generator');
  return { a, g };
}

async function oracle(a, artifactId) {
  const chain = await a.getAuditChain();
  const integrity = a.verifyAuditChainDetailed(chain);
  return { chain, integrity, index: chain.findIndex((e) => e.artifactId === artifactId),
    filtered: chain.filter((e) => e.artifactId === artifactId || e.executionContext?.replayOf === artifactId) };
}
const integrityView = (i) => ({ valid: i.valid, entriesVerified: i.entriesVerified, tamperingDetected: i.tamperingDetected, reason: i.reason ?? null, head: i.head ?? null, tail: i.tail ?? null });

describe('paged evidence generator', () => {
  let dir; let file;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut11-')); file = path.join(dir, 'audit.log'); });
  afterEach(() => {
    delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
    jest.resetModules();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('PG-1 package, verification and both exports equal the previous materialising computation', async () => {
    const { ids } = writeLog(file);
    const { a, g } = load(file);
    for (const pos of [0, 999, 1000, 1001, REPLAYED, 2499, 2490]) {
      const id = ids[pos];
      const o = await oracle(a, id);
      const pkg = (await g.generateEvidencePackage(id, [], null)).package;
      expect(pkg.sections.audit.chainIntegrity).toEqual(integrityView(o.integrity));
      expect(pkg.sections.audit.artifactPosition).toEqual({ index: o.index >= 0 ? o.index : null, totalInChain: o.chain.length, found: o.index >= 0 });
      expect(pkg.sections.audit.artifactPosition.index).toBe(pos);
      const v = await g.generateVerificationOutput(id, []);
      expect(v.verifications.chain).toMatchObject({ valid: o.integrity.valid, tamperingDetected: o.integrity.tamperingDetected, entriesVerified: o.integrity.entriesVerified });
      const ef = await g.exportAuditChain(id, true);
      expect(ef.entries).toEqual(o.filtered);
      expect(ef.meta).toMatchObject({ filtered: true, totalChain: N, exportedCount: o.filtered.length,
        chainIntegrity: { valid: true, tamperingDetected: false, entriesVerified: N } });
    }
    const replayed = await g.exportAuditChain(ids[REPLAYED], true);
    expect(replayed.entries).toHaveLength(1 + REPLAY_AT.length);   // the artifact and its replays across pages
    const eu = await g.exportAuditChain(ids[5], false);
    expect(eu.entries).toEqual((await oracle(a, ids[5])).chain);
    expect(eu.meta).toMatchObject({ filtered: false, totalChain: N, exportedCount: N });
  });

  test('PG-2 tampered canonical (no re-hash) at a page boundary → COMPROMISED, same verdict as before', async () => {
    const { ids, lines } = writeLog(file);
    const { a, g } = load(file);
    const t = JSON.parse(lines[1000]);                                   // the hashed body changed, the hash kept
    t.canonical = t.canonical.includes('"decision":"BLOCK"') ? t.canonical.replace('"decision":"BLOCK"', '"decision":"ALLOW"')
      : t.canonical.replace('"decision":"ALLOW"', '"decision":"BLOCK"');
    lines[1000] = JSON.stringify(t);                                     // after load: the paged walk reads it from disk
    fs.writeFileSync(file, lines.join('\n') + '\n');
    const o = await oracle(a, ids[5]);
    expect(o.integrity.valid).toBe(false);
    const pkg = (await g.generateEvidencePackage(ids[5], [], null)).package;
    expect(pkg.sections.audit.chainIntegrity).toEqual(integrityView(o.integrity));
    expect(pkg.sections.audit.chainIntegrity).toMatchObject({ valid: false, tamperingDetected: true, entriesVerified: 1000 });
    const v = await g.generateVerificationOutput(ids[5], []);
    expect(v.verifications.chain.status).toBe('INVALID');
    expect(v.overallStatus).toBe('COMPROMISED');
    expect((await g.exportAuditChain(ids[5], true)).meta.chainIntegrity.valid).toBe(false);
  });

  test('PG-3 duplicate artifactId across a page boundary → AUDIT_DUPLICATE_ENTRY, as before', async () => {
    const { ids } = writeLog(file, { duplicateAt: [999, 1001] });
    const { a, g } = load(file);
    const o = await oracle(a, ids[5]);
    expect(o.integrity.reason).toBe('AUDIT_DUPLICATE_ENTRY');
    const pkg = (await g.generateEvidencePackage(ids[5], [], null)).package;
    expect(pkg.sections.audit.chainIntegrity).toEqual(integrityView(o.integrity));
  });

  test('PG-4 a broken link exactly at a page boundary → invalid, as before', async () => {
    const { ids, lines } = writeLog(file);
    const { a, g } = load(file);
    const broken = writeLog(path.join(dir, 'b.log'), {}).lines;   // a different, valid chain …
    lines[2000] = broken[2000];                                     // … whose entry 2000 does not link here
    fs.writeFileSync(file, lines.join('\n') + '\n');
    const o = await oracle(a, ids[5]);
    expect(o.integrity.valid).toBe(false);
    const v = await g.generateVerificationOutput(ids[5], []);
    expect(v.verifications.chain).toMatchObject({ valid: false, entriesVerified: o.integrity.entriesVerified });
    expect((await g.generateEvidencePackage(ids[5], [], null)).package.sections.audit.chainIntegrity).toEqual(integrityView(o.integrity));
  });

  test('PG-5 the streamed unfiltered export writes byte-identical entries and the same meta', async () => {
    const { ids } = writeLog(file);
    const { a, g } = load(file);
    const chunks = [];
    const meta = await g.streamAuditChainExport(ids[7], async (c) => { chunks.push(c); });
    expect(chunks.length).toBeGreaterThanOrEqual(3);                 // one chunk per page
    const o = await oracle(a, ids[7]);
    expect(`[${chunks.join('')}]`).toBe(JSON.stringify(o.chain));
    const { exportedAt, ...rest } = meta;
    const { exportedAt: _x, ...expected } = (await g.exportAuditChain(ids[7], false)).meta;
    expect(rest).toEqual(expected);
    expect(typeof exportedAt).toBe('string');
  });

  test('PG-6 read failure: every entry point fails closed with AUDIT_HISTORY_UNAVAILABLE', async () => {
    const { ids } = writeLog(file);
    const { a, g } = load(file);
    const spy = jest.spyOn(a, 'forEachChainEntry').mockImplementation(async (visit) => { visit({ hash: 'x' }); throw new Error('disk gone'); });
    const closed = { code: 'AUDIT_HISTORY_UNAVAILABLE', read: 'chain walk' };
    await expect(g.generateEvidencePackage(ids[5], [], null)).rejects.toMatchObject(closed);
    await expect(g.generateVerificationOutput(ids[5], [])).rejects.toMatchObject(closed);
    await expect(g.exportAuditChain(ids[5], true)).rejects.toMatchObject(closed);
    await expect(g.exportAuditChain(ids[5], false)).rejects.toMatchObject(closed);
    await expect(g.streamAuditChainExport(ids[5], async () => {})).rejects.toMatchObject(closed);
    spy.mockRestore();
  });
});
