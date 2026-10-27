'use strict';

/**
 * ST23-03: GapScanner root authenticity.
 *
 * The production root audit verified only the root chain link, entry_count and root_hash. A hash-consistent but
 * forged root — the entries and roots rewritten consistently by anyone able to write the tables, but signed with a
 * key the instance does not trust — passed. The scanner now also verifies each root's Ed25519 signature under its
 * signer key from the transparency key store, accepting only keys with status active or deprecated, and reports any
 * other outcome as a CHECKPOINT_DIVERGENCE gap with details.check === 'ROOT_SIGNATURE'. An unknown key triggers ONE
 * reload of the transparency store per scan and one re-check.
 *
 * Roots are genuinely signed (log.computeRootSigningBuffer, as registrar.generateRoot does) with a key derived from
 *'s PUBLISHED test seed — never a deployment key. RA-15/16 use the REAL transparency key store in this file's own
 * jest temp directory (test/support/jest.setup.js), with ephemeral keys that are never printed or persisted.
 *
 *   RA-01  genuine root, active key → no gap
 *   RA-02  genuine root, deprecated key → no gap
 *   RA-03  hash-consistent FORGED root (consistent entries + root, signed by an untrusted key) → only a signature gap
 *   RA-04  a signature that belongs to a different root → root_signature_invalid
 *   RA-05  unknown key: ONE reload, ONE re-check, still unknown → root_key_unknown (never accepted)
 *   RA-06  unknown key that the reload brings in (stale replica) → verified, no gap
 *   RA-07  retry is bounded: two roots with unknown keys → reloadFromDisk called once per scan, both reported
 *   RA-08  revoked key → root_key_not_verifiable, no reload
 *   RA-09  key store unavailable (getKeyStatus throws) → root_key_store_unavailable
 *   RA-10  reload throws → still reported, scan completes
 *   RA-11  getPublicKey throws after a verifiable status → root_key_store_unavailable
 *   RA-12  missing signature / missing signer key id → reported
 *   RA-13  incremental scan: the boundary root is not re-verified; the resumed roots are
 *   RA-14  integrity and authenticity stay distinguishable: hash mismatch + bad signature → two gaps
 *   RA-15  real transparency key store, no injection: a root signed by the store's active key passes
 *   RA-16  real store: the same root after its key is revoked → root_key_not_verifiable
 */

jest.mock('../../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const { createGapScanner } = require('../GapScanner');
const log = require('../../log');

//'s PUBLISHED test seed.
const TEST_SEED = Buffer.from('7717'.repeat(16), 'hex');
const TEST_PRIV = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), TEST_SEED]), format: 'der', type: 'pkcs8' });
const TEST_PUB_DER = crypto.createPublicKey(TEST_PRIV).export({ format: 'der', type: 'spki' });
const OTHER_PRIV = crypto.generateKeyPairSync('ed25519').privateKey; // in-memory only: the "attacker" key
const KEY_ID = 'tr-test:key_v1';

// ── Builders ──────────────────────────────────────────────────────────────────

function makeEntry(id, prev, salt = '') {
  const row = {
    id, transparency_id: `tid-${id}${salt}`, entry_type: 'ARTIFACT', artifact_id: `art-${id}${salt}`,
    evidence_chain_id: null, verification_id: null, payload_hash: 'a'.repeat(64),
    previous_entry_hash: prev, signer_key_id: KEY_ID, signer_key_version: 1, signature: 'sig', registered_by: 'system', tenant_id: null,
  };
  row.entry_hash = log.computeEntryHash({
    transparencyId: row.transparency_id, entryType: row.entry_type, artifactId: row.artifact_id,
    evidenceChainId: null, verificationId: null, payloadHash: row.payload_hash, previousEntryHash: prev, signerKeyId: KEY_ID,
  });
  return row;
}

function makeChain(n, salt = '') {
  const out = []; let prev = null;
  for (let i = 1; i <= n; i++) { const e = makeEntry(i, prev, salt); out.push(e); prev = e.entry_hash; }
  return out;
}

function signRoot(root, priv = TEST_PRIV) {
  const buf = log.computeRootSigningBuffer({
    rootId: root.root_id, seqFrom: Number(root.seq_from), seqTo: Number(root.seq_to), entryCount: root.entry_count,
    rootHash: root.root_hash, previousRootHash: root.previous_root_hash,
  });
  return crypto.sign(null, buf, priv).toString('base64');
}

/** A root over entries[0..seqTo-1] (full tree, as registrar.generateRoot builds it), genuinely signed by `priv`. */
function makeRoot(entries, { id = 1, seqFrom = 1, seqTo = entries.length, prev = null, keyId = KEY_ID, priv = TEST_PRIV, rootId } = {}) {
  const root = {
    id, root_id: rootId || `root-${id}`, seq_from: String(seqFrom), seq_to: String(seqTo), entry_count: seqTo,
    root_hash: log.computeRootHash(entries.slice(0, seqTo).map((e) => e.entry_hash)), previous_root_hash: prev,
    signer_key_id: keyId, generated_at: new Date().toISOString(),
  };
  root.signature = priv ? signRoot(root, priv) : null;
  return root;
}

/** A fake transparency key store: { keyId: status }. reloadAdds is applied by reloadFromDisk(). */
function makeKeys(statuses, { reloadAdds = null, statusThrows = false, reloadThrows = false, publicThrows = false } = {}) {
  const map = { ...statuses };
  return {
    map,
    getKeyStatus: jest.fn((k) => { if (statusThrows) throw new Error('transparency key store bootstrap failed'); return map[k] ?? null; }),
    getPublicKey: jest.fn((k) => {
      if (publicThrows) throw new Error('decrypt failed');
      if (!map[k]) throw new Error(`unknown transparency keyId "${k}"`);
      if (map[k] === 'revoked') throw new Error(`transparency key "${k}" is revoked`);
      return { pubDer: TEST_PUB_DER, status: map[k], retiredAt: null };
    }),
    reloadFromDisk: jest.fn(() => {
      if (reloadThrows) throw new Error('reload exploded');
      if (reloadAdds) Object.assign(map, reloadAdds);
      return { reloaded: true };
    }),
  };
}

function harness({ entries, roots, keys, boundaryRoot = null, state = null, mode = 'FULL' }) {
  const handleGapCalls = [];
  const emitted = [];
  const query = async (sql, params) => {
    if (sql.includes('qodiqa_transparency_log_fetch_hashes_in_range')) {
      const from = Number(params[0]), to = Number(params[1]);
      return { rows: entries.filter((e) => e.id >= from && e.id <= to).map((e) => ({ id: e.id, entry_hash: e.entry_hash })) };
    }
    if (sql.includes('qodiqa_transparency_log_fetch_batch')) return { rows: entries.filter((e) => e.id >= Number(params[0])) };
    if (sql.includes('qodiqa_transparency_log_fetch_boundary')) return { rows: [] };
    if (sql.includes('FROM transparency_roots') && sql.includes('id < $1')) return { rows: boundaryRoot ? [boundaryRoot] : [] };
    if (sql.includes('FROM transparency_roots') && sql.includes('WHERE id >= $1')) return { rows: roots.filter((r) => r.id >= Number(params[0])) };
    return { rows: [] };
  };
  const pgPool = {
    isEnabled: () => true,
    withTransaction: async (fn) => fn({ query: async (sql, params) => (sql.includes('pg_try_advisory_xact_lock') ? { rows: [{ acquired: true }] } : query(sql, params)) }),
  };
  const metrics = new Proxy({}, { get: (t, k) => (t[k] ||= { inc: jest.fn(), set: jest.fn(), observe: jest.fn() }) });
  const scanner = createGapScanner({
    config: { mode, maxBatchSize: 100, verifyEntryHashes: false, verifyRoots: true },
    _pgPool: pgPool,
    _definerQuery: query,
    _gapFramework: {
      handleGap: jest.fn(async (gapType, context) => { handleGapCalls.push({ gapType, context }); return { gap: { gapId: `g${handleGapCalls.length}` }, blocked: false }; }),
      autoResolveGap: jest.fn(() => false),
    },
    _emit: (level, event, data) => emitted.push({ level, event, data }),
    _metrics: metrics,
    _scannerState: { load: jest.fn(async () => state), save: jest.fn(async () => {}) },
    ...(keys !== undefined ? { _transparencyKeys: keys } : {}),
  });
  const sigGaps = () => handleGapCalls.filter((c) => c.gapType === 'CHECKPOINT_DIVERGENCE' && c.context.details.check === 'ROOT_SIGNATURE').map((c) => c.context.details);
  const integrityGaps = () => handleGapCalls.filter((c) => c.context.details.check !== 'ROOT_SIGNATURE').map((c) => c.context.details);
  return { scanner, handleGapCalls, emitted, sigGaps, integrityGaps };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GapScanner root authenticity (ST23-03)', () => {
  test('RA-01 a genuine root signed by an active key reports no gap', async () => {
    const entries = makeChain(2);
    const keys = makeKeys({ [KEY_ID]: 'active' });
    const h = harness({ entries, roots: [makeRoot(entries)], keys });
    const result = await h.scanner.scan('FULL');
    expect(result.success).toBe(true);
    expect(h.handleGapCalls).toEqual([]);
    expect(keys.reloadFromDisk).not.toHaveBeenCalled();
  });

  test('RA-02 a genuine root signed by a deprecated key reports no gap (historical roots stay verifiable)', async () => {
    const entries = makeChain(1);
    const h = harness({ entries, roots: [makeRoot(entries)], keys: makeKeys({ [KEY_ID]: 'deprecated' }) });
    await h.scanner.scan('FULL');
    expect(h.handleGapCalls).toEqual([]);
  });

  test('RA-03 a hash-consistent FORGED root (rewritten entries + root, untrusted signer) is reported; integrity checks pass', async () => {
    // The forger rewrites every entry and recomputes a consistent root (chain link, entry_count, root_hash all hold),
    // naming the trusted key id but signing with a key they control.
    const forgedEntries = makeChain(3, '-forged');
    const forged = makeRoot(forgedEntries, { priv: OTHER_PRIV });
    const h = harness({ entries: forgedEntries, roots: [forged], keys: makeKeys({ [KEY_ID]: 'active' }) });
    const result = await h.scanner.scan('FULL');
    expect(h.integrityGaps()).toEqual([]);                       // hash consistency alone would have passed it
    expect(h.sigGaps()).toEqual([expect.objectContaining({ check: 'ROOT_SIGNATURE', context: 'root_signature_invalid', rootId: 'root-1', signerKeyId: KEY_ID, keyStatus: 'active' })]);
    expect(result.gapsDetected).toBe(1);
  });

  test('RA-04 a genuine signature copied from a different root is root_signature_invalid', async () => {
    const entries = makeChain(2);
    const r1 = makeRoot(entries, { id: 1, seqTo: 1 });
    const r2 = makeRoot(entries, { id: 2, seqFrom: 2, seqTo: 2, prev: r1.root_hash });
    r2.signature = r1.signature;
    const h = harness({ entries, roots: [r1, r2], keys: makeKeys({ [KEY_ID]: 'active' }) });
    await h.scanner.scan('FULL');
    expect(h.integrityGaps()).toEqual([]);
    expect(h.sigGaps()).toEqual([expect.objectContaining({ context: 'root_signature_invalid', rootId: 'root-2' })]);
  });

  test('RA-05 an unknown key triggers ONE reload and ONE re-check, then is reported as root_key_unknown', async () => {
    const entries = makeChain(1);
    const keys = makeKeys({});
    const h = harness({ entries, roots: [makeRoot(entries)], keys });
    await h.scanner.scan('FULL');
    expect(keys.reloadFromDisk).toHaveBeenCalledTimes(1);
    expect(keys.getKeyStatus).toHaveBeenCalledTimes(2);          // check + one re-check
    expect(keys.getPublicKey).not.toHaveBeenCalled();
    expect(h.sigGaps()).toEqual([expect.objectContaining({ context: 'root_key_unknown', signerKeyId: KEY_ID })]);
    expect(h.emitted.find((e) => e.event === 'TRANSPARENCY_SCANNER_KEY_RELOAD')).toEqual(expect.objectContaining({ level: 'INFO', data: expect.objectContaining({ keyId: KEY_ID, reloaded: true }) }));
  });

  test('RA-06 a key rotated in on another instance (stale replica) is found by the reload and the root verifies', async () => {
    const entries = makeChain(1);
    const keys = makeKeys({}, { reloadAdds: { [KEY_ID]: 'active' } });
    const h = harness({ entries, roots: [makeRoot(entries)], keys });
    await h.scanner.scan('FULL');
    expect(keys.reloadFromDisk).toHaveBeenCalledTimes(1);
    expect(h.handleGapCalls).toEqual([]);
  });

  test('RA-07 the retry is bounded: two roots with unknown keys cause ONE reload per scan; both are reported', async () => {
    const entries = makeChain(2);
    const r1 = makeRoot(entries, { id: 1, seqTo: 1, keyId: 'tr-a:key_v1' });
    const r2 = makeRoot(entries, { id: 2, seqFrom: 2, seqTo: 2, prev: r1.root_hash, keyId: 'tr-b:key_v1' });
    const keys = makeKeys({});
    const h = harness({ entries, roots: [r1, r2], keys });
    await h.scanner.scan('FULL');
    expect(keys.reloadFromDisk).toHaveBeenCalledTimes(1);
    expect(h.sigGaps().map((g) => [g.rootId, g.context])).toEqual([['root-1', 'root_key_unknown'], ['root-2', 'root_key_unknown']]);
    // A second scan pass gets its own single reload.
    await h.scanner.scan('FULL');
    expect(keys.reloadFromDisk).toHaveBeenCalledTimes(2);
  });

  test('RA-08 a revoked key is root_key_not_verifiable, without a reload', async () => {
    const entries = makeChain(1);
    const keys = makeKeys({ [KEY_ID]: 'revoked' });
    const h = harness({ entries, roots: [makeRoot(entries)], keys });
    await h.scanner.scan('FULL');
    expect(keys.reloadFromDisk).not.toHaveBeenCalled();
    expect(h.sigGaps()).toEqual([expect.objectContaining({ context: 'root_key_not_verifiable', keyStatus: 'revoked' })]);
  });

  test('RA-09 an unavailable key store (getKeyStatus throws) is reported as root_key_store_unavailable, never a pass', async () => {
    const entries = makeChain(1);
    const h = harness({ entries, roots: [makeRoot(entries)], keys: makeKeys({ [KEY_ID]: 'active' }, { statusThrows: true }) });
    const result = await h.scanner.scan('FULL');
    expect(result.success).toBe(true);
    expect(h.sigGaps()).toEqual([expect.objectContaining({ context: 'root_key_store_unavailable', reason: expect.stringContaining('bootstrap failed') })]);
  });

  test('RA-10 a reload that throws leaves the key unknown; the root is reported and the scan completes', async () => {
    const entries = makeChain(1);
    const keys = makeKeys({}, { reloadThrows: true });
    const h = harness({ entries, roots: [makeRoot(entries)], keys });
    const result = await h.scanner.scan('FULL');
    expect(result.success).toBe(true);
    expect(h.sigGaps()).toEqual([expect.objectContaining({ context: 'root_key_unknown' })]);
    expect(h.emitted.find((e) => e.event === 'TRANSPARENCY_SCANNER_KEY_RELOAD').data).toEqual(expect.objectContaining({ reloaded: false, error: 'reload exploded' }));
  });

  test('RA-11 getPublicKey throwing after a verifiable status is root_key_store_unavailable', async () => {
    const entries = makeChain(1);
    const h = harness({ entries, roots: [makeRoot(entries)], keys: makeKeys({ [KEY_ID]: 'active' }, { publicThrows: true }) });
    await h.scanner.scan('FULL');
    expect(h.sigGaps()).toEqual([expect.objectContaining({ context: 'root_key_store_unavailable', keyStatus: 'active', reason: 'decrypt failed' })]);
  });

  test('RA-12 a root with no signature, or no signer key id, is reported', async () => {
    const entries = makeChain(2);
    const r1 = makeRoot(entries, { id: 1, seqTo: 1 });
    const r2 = makeRoot(entries, { id: 2, seqFrom: 2, seqTo: 2, prev: r1.root_hash });
    r1.signature = null;
    r2.signer_key_id = null;
    const keys = makeKeys({ [KEY_ID]: 'active' });
    const h = harness({ entries, roots: [r1, r2], keys });
    await h.scanner.scan('FULL');
    expect(h.sigGaps().map((g) => [g.rootId, g.context])).toEqual([['root-1', 'root_signature_missing'], ['root-2', 'root_signer_key_missing']]);
    expect(keys.getKeyStatus).not.toHaveBeenCalled();
  });

  test('RA-13 incremental scan: the boundary root is only chain-linked, the resumed roots are authenticated', async () => {
    const entries = makeChain(3);
    const r1 = makeRoot(entries, { id: 1, seqTo: 1 });
    r1.signature = 'not-a-valid-signature';                     // boundary root: read for its hash only
    const r2 = makeRoot(entries, { id: 2, seqFrom: 2, seqTo: 2, prev: r1.root_hash });
    const r3 = makeRoot(entries, { id: 3, seqFrom: 3, seqTo: 3, prev: r2.root_hash, priv: OTHER_PRIV });
    const keys = makeKeys({ [KEY_ID]: 'active' });
    const h = harness({
      entries, roots: [r1, r2, r3], keys, mode: 'INCREMENTAL',
      boundaryRoot: { id: 1, root_hash: r1.root_hash }, state: { last_scanned_id: 3, last_completed_root_id: 1 },
    });
    const result = await h.scanner.scan('INCREMENTAL');
    expect(h.integrityGaps()).toEqual([]);                       // r2 chains to the boundary root
    expect(h.sigGaps().map((g) => [g.rootId, g.context])).toEqual([['root-3', 'root_signature_invalid']]);
    expect(result.lastCompletedRootId).toBe(3);
  });

  test('RA-14 integrity and authenticity outcomes stay distinguishable (hash mismatch + bad signature → two gaps)', async () => {
    const entries = makeChain(1);
    const root = makeRoot(entries);
    root.root_hash = 'f'.repeat(64);                            // tampered after signing: both checks fail
    const h = harness({ entries, roots: [root], keys: makeKeys({ [KEY_ID]: 'active' }) });
    const result = await h.scanner.scan('FULL');
    expect(h.integrityGaps()).toEqual([expect.objectContaining({ context: 'root_hash_mismatch' })]);
    expect(h.integrityGaps()[0].check).toBeUndefined();
    expect(h.sigGaps()).toEqual([expect.objectContaining({ check: 'ROOT_SIGNATURE', context: 'root_signature_invalid' })]);
    expect(result.gapsDetected).toBe(2);
  });
});

describe('GapScanner root authenticity — real transparency key store (ST23-03)', () => {
  // test/support/jest.setup.js gives this file its own temp QODIQA_TRANSPARENCY_KEYS_PATH and test KEK; the store bootstraps
  // there with ephemeral keys. The scanner gets NO _transparencyKeys injection: this is the production default path.
  const tKeyStore = require('../../transparencyKeyStore');
  let entries;
  let root;

  beforeAll(() => {
    const active = tKeyStore.getActiveKey();
    const priv = crypto.createPrivateKey({ key: active.privDer, format: 'der', type: 'pkcs8' });
    entries = makeChain(2);
    root = makeRoot(entries, { keyId: active.keyId, priv });
  });

  test('RA-15 a root signed by the store\'s active key passes the audit (default key store, no injection)', async () => {
    const h = harness({ entries, roots: [root] });
    await h.scanner.scan('FULL');
    expect(h.handleGapCalls).toEqual([]);
  });

  test('RA-16 the same root after its key is revoked is root_key_not_verifiable', async () => {
    tKeyStore.rotateKeyGracefully();                             // the signer becomes deprecated (still verifies)
    let h = harness({ entries, roots: [root] });
    await h.scanner.scan('FULL');
    expect(h.handleGapCalls).toEqual([]);
    tKeyStore.revokeKey(root.signer_key_id);
    h = harness({ entries, roots: [root] });
    await h.scanner.scan('FULL');
    expect(h.sigGaps()).toEqual([expect.objectContaining({ context: 'root_key_not_verifiable', keyStatus: 'revoked', signerKeyId: root.signer_key_id })]);
  });
});
