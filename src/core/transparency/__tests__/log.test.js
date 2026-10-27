'use strict';

/**
 * Transparency Log Tests — Component #22
 *
 * TL-01 … TL-20   Pure logic: hash computation (log.js)
 * TL-21 … TL-40   Chain integrity and continuity (log.js)
 * TL-41 … TL-55   Signature verification (log.js, with real keys from test/support/jest.setup.js)
 * TL-56 … TL-70   Inclusion proof generation and verification (log.js)
 * TL-71 … TL-90   PG store: PG-disabled path (logStore.js)
 * TL-91 … TL-110  PG store: PG-enabled path (logStore.js, mocked pool)
 * TL-111 … TL-125 Registrar: entry registration and root generation (registrar.js, mocked pool)
 * TL-126 … TL-140 Tampering and corruption detection (log.js)
 * TL-141 … TL-150 RBAC permissions matrix
 */

const { createHash, randomUUID } = require('crypto');

// ── Mock pgPool (disabled by default) ─────────────────────────────────────────

const mockPool = {
  _enabled:   false,
  lastTxOpts: null,
  isEnabled: function () { return this._enabled; },
  query:     jest.fn(),
  // Simulate withTransaction: run fn immediately with a tx that delegates to mockPool.query.
  // This lets existing mockPool.query mock setups work unchanged for transaction-based paths.
  withTransaction: async function (fn, opts) {
    if (!this._enabled) throw new Error('PG pool not initialized');
    mockPool.lastTxOpts = opts;
    // generateRoot() now also probes for the first new entry and
    // reads the Merkle block checkpoints (merkleCheckpoints.js). With the 1-5
    // entries these tests use, no block is ever complete, so the faithful
    // answers are fixed: no stored blocks, the probe (limit 1) finds the first
    // new entry at seqFrom, and the block-completion read finds no full block.
    // Answered here so each test's queued mocks still map 1:1 to the
    // statements they document (locks, range read, appendRoot, head update).
    const tx = { query: (sql, params) => {
      if (/transparency_merkle_checkpoints/.test(sql)) return Promise.resolve({ rows: [] });
      // the probe/batch read is now hash-only (qodiqa_transparency_public_hashes_from_id).
      if (/qodiqa_transparency_log_fetch_batch|qodiqa_transparency_public_hashes_from_id/.test(sql)) {
        return Promise.resolve({ rows: Number(params[1]) === 1 ? [{ id: Number(params[0]) }] : [] });
      }
      return mockPool.query(sql, params);
    } };
    return fn(tx);
  },
};

// cross-tenant DEFINER reads now go through rolePools (qodiqa_system / qodiqa_reporting);
// the forwarder sends them to the same mocked pool and records which pool served each call.
jest.mock('../../../infra/postgres/rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../../../infra/postgres/pool')));
jest.mock('../../../infra/postgres/pool', () => mockPool);

// ── Mock logger ────────────────────────────────────────────────────────────────

jest.mock('../../../../services/logger', () => ({
  emit:                jest.fn(),
  allowed:             jest.fn(),
  blocked:             jest.fn(),
  eventBus:            { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

// ── Mock transparencyGap (prevents AlertStore from consuming mock query values) ─

jest.mock('../../transparencyGap', () => ({
  detectSequenceBreak:               jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectPartialAppend:               jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectMissingEntry:                jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectHashChainBreak:              jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectArtifactWithoutTransparency: jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectTransparencyWithoutArtifact: jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectMissingVerificationEvidence: jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  detectCheckpointDivergence:        jest.fn().mockResolvedValue({ gap: {}, blocked: false }),
  GAP_TYPE: {},
  GapError: class GapError extends Error {},
  MODE: {},
}));

// ── Load modules ───────────────────────────────────────────────────────────────

const log         = require('../log');
const stableStringify = require('../../../utils/stableStringify'); // TL-71/TL-72
const logStore    = require('../logStore');
const registrar   = require('../registrar');
const keyManager  = require('../../../../services/artifact/keyManager');
const ed25519     = require('../../../infra/crypto/ed25519');
const { getTransparencySigner } = require('../transparencySigner');
const { PERMISSIONS } = require('../../rbac/roles');

// ── Helpers ────────────────────────────────────────────────────────────────────

function makeEntry(overrides = {}) {
  const transparencyId = randomUUID();
  const payload        = { event: 'test', value: 42 };
  const payloadHash    = log.computePayloadHash(payload);
  const signerKeyId    = 'default:key_v1';

  const base = {
    transparencyId,
    entryType:         'ARTIFACT',
    artifactId:        'art-001',
    evidenceChainId:   null,
    verificationId:    null,
    payloadHash,
    previousEntryHash: null,
    signerKeyId,
    ...overrides,
  };

  const entryHash = log.computeEntryHash(base);
  return { ...base, entryHash, payload, signature: 'MOCK_SIG' };
}

function makeDbRow(camelRecord, id = 1) {
  return {
    id,
    transparency_id:    camelRecord.transparencyId,
    entry_type:         camelRecord.entryType,
    artifact_id:        camelRecord.artifactId        ?? null,
    evidence_chain_id:  camelRecord.evidenceChainId   ?? null,
    verification_id:    camelRecord.verificationId    ?? null,
    payload:            camelRecord.payload            ?? {},
    payload_hash:       camelRecord.payloadHash,
    previous_entry_hash: camelRecord.previousEntryHash ?? null,
    entry_hash:         camelRecord.entryHash,
    signer_key_id:      camelRecord.signerKeyId,
    signer_key_version: null,
    signature:          camelRecord.signature,
    registered_by:      'system',
    tenant_id:          null,
    created_at:         new Date().toISOString(),
  };
}

// ── TL-01 … TL-20: Hash computation ───────────────────────────────────────────

describe('TL-01 … TL-20: Hash computation (log.js)', () => {
  test('TL-01 computePayloadHash returns 64-char hex string', () => {
    const h = log.computePayloadHash({ foo: 'bar' });
    expect(typeof h).toBe('string');
    expect(h).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(h)).toBe(true);
  });

  test('TL-02 computePayloadHash is deterministic', () => {
    const h1 = log.computePayloadHash({ a: 1, b: 2 });
    const h2 = log.computePayloadHash({ b: 2, a: 1 });
    expect(h1).toBe(h2);
  });

  test('TL-03 computePayloadHash differs for different payloads', () => {
    expect(log.computePayloadHash({ a: 1 })).not.toBe(log.computePayloadHash({ a: 2 }));
  });

  test('TL-04 computePayloadHash accepts null/undefined (treated as {})', () => {
    const h1 = log.computePayloadHash(null);
    const h2 = log.computePayloadHash(undefined);
    const h3 = log.computePayloadHash({});
    expect(h1).toBe(h3);
    expect(h2).toBe(h3);
  });

  test('TL-05 computeEntryHash returns 64-char hex string', () => {
    const entry = makeEntry();
    const h     = log.computeEntryHash(entry);
    expect(h).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(h)).toBe(true);
  });

  test('TL-06 computeEntryHash is deterministic', () => {
    const entry = makeEntry();
    expect(log.computeEntryHash(entry)).toBe(log.computeEntryHash(entry));
  });

  test('TL-07 computeEntryHash changes when transparencyId changes', () => {
    const e1 = makeEntry({ transparencyId: randomUUID() });
    const e2 = makeEntry({ transparencyId: randomUUID() });
    expect(log.computeEntryHash(e1)).not.toBe(log.computeEntryHash(e2));
  });

  test('TL-08 computeEntryHash changes when entryType changes', () => {
    const e1 = makeEntry({ entryType: 'ARTIFACT' });
    const e2 = makeEntry({ ...e1, entryType: 'EVIDENCE' });
    expect(log.computeEntryHash(e1)).not.toBe(log.computeEntryHash(e2));
  });

  test('TL-09 computeEntryHash changes when payloadHash changes', () => {
    const e1 = makeEntry({ payloadHash: 'a'.repeat(64) });
    const e2 = makeEntry({ ...e1, payloadHash: 'b'.repeat(64) });
    expect(log.computeEntryHash(e1)).not.toBe(log.computeEntryHash(e2));
  });

  test('TL-10 computeEntryHash changes when previousEntryHash changes', () => {
    const e1 = makeEntry({ previousEntryHash: null });
    const e2 = makeEntry({ ...e1, previousEntryHash: 'a'.repeat(64) });
    expect(log.computeEntryHash(e1)).not.toBe(log.computeEntryHash(e2));
  });

  test('TL-11 computeEntryHash changes when signerKeyId changes', () => {
    const e1 = makeEntry({ signerKeyId: 'default:key_v1' });
    const e2 = makeEntry({ ...e1, signerKeyId: 'default:key_v2' });
    expect(log.computeEntryHash(e1)).not.toBe(log.computeEntryHash(e2));
  });

  test('TL-12 computeEntrySigningBuffer returns 32-byte Buffer', () => {
    const entry = makeEntry();
    const buf   = log.computeEntrySigningBuffer(entry);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBe(32);
  });

  test('TL-13 computeEntrySigningBuffer matches computeEntryHash hex', () => {
    const entry = makeEntry();
    const hex   = log.computeEntryHash(entry);
    const buf   = log.computeEntrySigningBuffer(entry);
    expect(buf.toString('hex')).toBe(hex);
  });

  test('TL-14 computeRootHash returns 64-char hex', () => {
    const hashes = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)];
    const root   = log.computeRootHash(hashes);
    expect(root).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(root)).toBe(true);
  });

  test('TL-15 computeRootHash is deterministic and order-dependent', () => {
    const h1 = log.computeRootHash(['aa'.repeat(32), 'bb'.repeat(32)]);
    const h2 = log.computeRootHash(['aa'.repeat(32), 'bb'.repeat(32)]);
    const h3 = log.computeRootHash(['bb'.repeat(32), 'aa'.repeat(32)]);
    expect(h1).toBe(h2);
    expect(h1).not.toBe(h3);
  });

  test('TL-16 computeRootHash throws for empty array', () => {
    expect(() => log.computeRootHash([])).toThrow(RangeError);
  });

  test('TL-17 computeRootSigningBuffer returns 32-byte Buffer', () => {
    const rootRecord = {
      rootId:           randomUUID(),
      seqFrom:          1,
      seqTo:            10,
      entryCount:       10,
      rootHash:         'a'.repeat(64),
      previousRootHash: null,
    };
    const buf = log.computeRootSigningBuffer(rootRecord);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBe(32);
  });

  test('TL-18 computeRootSigningBuffer changes when rootHash changes', () => {
    const base = { rootId: randomUUID(), seqFrom: 1, seqTo: 5, entryCount: 5,
                   rootHash: 'a'.repeat(64), previousRootHash: null };
    const b1 = log.computeRootSigningBuffer(base);
    const b2 = log.computeRootSigningBuffer({ ...base, rootHash: 'b'.repeat(64) });
    expect(b1.toString('hex')).not.toBe(b2.toString('hex'));
  });

  test('TL-19 domain separator ENTRY_DOMAIN is unique', () => {
    expect(log.ENTRY_DOMAIN).toBe('QODIQA::TRANSPARENCY::V1');
    expect(log.ROOT_DOMAIN).toBe('QODIQA::TRANSPARENCY_ROOT::V1');
    expect(log.ENTRY_DOMAIN).not.toBe(log.ROOT_DOMAIN);
  });

  test('TL-20 CANONICAL_ENTRY_FIELDS contains all required fields', () => {
    const required = [
      'transparencyId', 'entryType', 'artifactId', 'evidenceChainId',
      'verificationId', 'payloadHash', 'previousEntryHash', 'signerKeyId',
    ];
    for (const f of required) {
      expect(log.CANONICAL_ENTRY_FIELDS).toContain(f);
    }
  });
});

// ── TL-21 … TL-40: Chain integrity and continuity ─────────────────────────────

describe('TL-21 … TL-40: Chain integrity and continuity (log.js)', () => {
  function buildChain(length) {
    const records = [];
    let prevHash  = null;

    for (let i = 0; i < length; i++) {
      const transparencyId = randomUUID();
      const payload        = { seq: i };
      const payloadHash    = log.computePayloadHash(payload);
      const signerKeyId    = 'default:key_v1';

      const entryBase = {
        transparencyId,
        entryType:         'SYSTEM',
        artifactId:        null,
        evidenceChainId:   null,
        verificationId:    null,
        payloadHash,
        previousEntryHash: prevHash,
        signerKeyId,
      };
      const entryHash = log.computeEntryHash(entryBase);
      const dbRow     = makeDbRow({ ...entryBase, entryHash, payload, signature: 'SIG' }, i + 1);
      records.push(dbRow);
      prevHash = entryHash;
    }

    return records;
  }

  test('TL-21 verifyEntryIntegrity passes for a valid genesis entry', () => {
    const entry  = makeEntry({ previousEntryHash: null });
    const dbRow  = makeDbRow(entry, 1);
    const result = log.verifyEntryIntegrity(dbRow, null);
    expect(result.valid).toBe(true);
    expect(result.failedCheck).toBeNull();
  });

  test('TL-22 verifyEntryIntegrity detects corrupted payload hash', () => {
    const entry  = makeEntry();
    const dbRow  = { ...makeDbRow(entry, 1), payload_hash: 'bad'.padEnd(64, '0') };
    const result = log.verifyEntryIntegrity(dbRow, null);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('PAYLOAD_HASH');
  });

  test('TL-23 verifyEntryIntegrity detects corrupted entry hash', () => {
    const entry  = makeEntry();
    const dbRow  = { ...makeDbRow(entry, 1), entry_hash: 'bad'.padEnd(64, '0') };
    const result = log.verifyEntryIntegrity(dbRow, null);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('ENTRY_HASH');
  });

  test('TL-24 verifyEntryIntegrity detects broken chain link', () => {
    const chain = buildChain(2);
    const entry = chain[1];

    // Tamper the prior record's entry_hash
    const tampered = { ...chain[0], entry_hash: 'tampered'.padEnd(64, '0') };
    const result   = log.verifyEntryIntegrity(entry, tampered);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('CHAIN_LINK');
  });

  test('TL-25 verifyEntryIntegrity fails chain_link when a claimed prior is unresolved', () => {
    const chain = buildChain(2);
    // Second entry's record claims a previousEntryHash, but the caller could
    // not resolve a matching prior (e.g. it was deleted/spliced from the
    // log). A claimed-but-unresolved prior is the signature of a chain
    // splice, so this must FAIL — silently SKIPping it was the original bug.
    const result = log.verifyEntryIntegrity(chain[1], null);
    const chainLinkCheck = result.checks.find(c => c.check === 'CHAIN_LINK');
    expect(chainLinkCheck.result).toBe('FAIL');
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('CHAIN_LINK');
  });

  test('TL-26 verifyEntryIntegrity passes chain link for valid chain', () => {
    const chain = buildChain(3);
    const result = log.verifyEntryIntegrity(chain[2], chain[1]);
    expect(result.valid).toBe(true);
    const chainLinkCheck = result.checks.find(c => c.check === 'CHAIN_LINK');
    expect(chainLinkCheck.result).toBe('PASS');
  });

  test('TL-27 validateChainContinuity passes for empty array', () => {
    const result = log.validateChainContinuity([]);
    expect(result.valid).toBe(true);
    expect(result.checkedCount).toBe(0);
  });

  test('TL-28 validateChainContinuity passes for single entry', () => {
    const chain  = buildChain(1);
    const result = log.validateChainContinuity(chain);
    expect(result.valid).toBe(true);
    expect(result.checkedCount).toBe(1);
  });

  test('TL-29 validateChainContinuity passes for valid 10-entry chain', () => {
    const chain  = buildChain(10);
    const result = log.validateChainContinuity(chain);
    expect(result.valid).toBe(true);
    expect(result.checkedCount).toBe(10);
    expect(result.failureId).toBeNull();
  });

  test('TL-30 validateChainContinuity detects ID gap', () => {
    const chain = buildChain(5);
    // Remove the third entry to create a gap (ids: 1,2,4,5)
    const gapped = [chain[0], chain[1], chain[3], chain[4]];
    const result = log.validateChainContinuity(gapped);
    expect(result.valid).toBe(false);
    expect(result.failureDetail).toMatch(/ID gap/);
  });

  test('TL-31 validateChainContinuity detects chain break', () => {
    const chain = buildChain(5);
    // Tamper with entry_hash of the third entry to break the link from the fourth
    const tampered = chain.map((r, i) => {
      if (i === 2) return { ...r, entry_hash: 'tampered'.padEnd(64, '0') };
      return r;
    });
    const result = log.validateChainContinuity(tampered);
    expect(result.valid).toBe(false);
  });

  test('TL-32 validateChainContinuity detects entry hash tampering', () => {
    const chain = buildChain(3);
    // Tamper entry_hash of the second entry (recompute would not match)
    const tampered = [...chain];
    tampered[1] = { ...chain[1], entry_hash: 'ffff'.padEnd(64, 'f') };
    const result = log.validateChainContinuity(tampered);
    expect(result.valid).toBe(false);
    expect(result.checkedCount).toBe(1);  // fails at second entry
  });

  test('TL-33 validateChainContinuity detects payload hash tampering', () => {
    const chain = buildChain(3);
    const tampered = [...chain];
    tampered[0] = { ...chain[0], payload_hash: 'bad'.padEnd(64, '0') };
    const result = log.validateChainContinuity(tampered);
    expect(result.valid).toBe(false);
    expect(result.failureDetail).toMatch(/Payload hash mismatch/);
  });

  test('TL-34 validateChainContinuity reports correct failureId', () => {
    const chain = buildChain(5);
    const tampered = [...chain];
    tampered[3] = { ...chain[3], entry_hash: 'bad'.padEnd(64, '0') };
    const result = log.validateChainContinuity(tampered);
    expect(result.valid).toBe(false);
    expect(result.failureId).toBe(4);   // 4th entry (id=4)
  });

  test('TL-35 validateChainContinuity passes 50-entry chain', () => {
    const chain  = buildChain(50);
    const result = log.validateChainContinuity(chain);
    expect(result.valid).toBe(true);
    expect(result.checkedCount).toBe(50);
  });

  test('TL-36 _toCanonicalCase converts snake_case DB row to camelCase', () => {
    const row = {
      transparency_id:    randomUUID(),
      entry_type:         'EVIDENCE',
      artifact_id:        'art-1',
      evidence_chain_id:  randomUUID(),
      verification_id:    null,
      payload_hash:       'a'.repeat(64),
      previous_entry_hash: null,
      signer_key_id:      'k1',
      signature:          'sig',
      entry_hash:         'b'.repeat(64),
    };
    const camel = log._toCanonicalCase(row);
    expect(camel.transparencyId).toBe(row.transparency_id);
    expect(camel.entryType).toBe('EVIDENCE');
    expect(camel.artifactId).toBe('art-1');
    expect(camel.payloadHash).toBe(row.payload_hash);
    expect(camel.signerKeyId).toBe('k1');
  });

  test('TL-37 _toRootCanonicalCase converts snake_case root row to camelCase', () => {
    const row = {
      root_id:          randomUUID(),
      seq_from:         1,
      seq_to:           100,
      entry_count:      100,
      root_hash:        'a'.repeat(64),
      previous_root_hash: null,
      signature:        'sig',
      signer_key_id:    'k1',
    };
    const camel = log._toRootCanonicalCase(row);
    expect(camel.rootId).toBe(row.root_id);
    expect(camel.seqFrom).toBe(1);
    expect(camel.seqTo).toBe(100);
    expect(camel.rootHash).toBe(row.root_hash);
  });

  test('TL-38 verifyEntryIntegrity returns all 3 checks', () => {
    const chain  = buildChain(2);
    const result = log.verifyEntryIntegrity(chain[1], chain[0]);
    expect(result.checks).toHaveLength(3);
    const checkNames = result.checks.map(c => c.check);
    expect(checkNames).toContain('PAYLOAD_HASH');
    expect(checkNames).toContain('ENTRY_HASH');
    expect(checkNames).toContain('CHAIN_LINK');
  });

  test('TL-39 computeRootHash single entry differs from multi-entry', () => {
    const h1 = log.computeRootHash(['aa'.repeat(32)]);
    const h2 = log.computeRootHash(['aa'.repeat(32), 'bb'.repeat(32)]);
    expect(h1).not.toBe(h2);
  });

  test('TL-40 verifyEntryIntegrity returns valid=false when both hash checks fail', () => {
    const entry  = makeEntry();
    const dbRow  = {
      ...makeDbRow(entry, 1),
      payload_hash: 'bad'.padEnd(64, '0'),
      entry_hash:   'bad'.padEnd(64, '0'),
    };
    const result = log.verifyEntryIntegrity(dbRow, null);
    expect(result.valid).toBe(false);
    const failedChecks = result.checks.filter(c => c.result === 'FAIL');
    expect(failedChecks.length).toBeGreaterThanOrEqual(1);
  });
});

// ── TL-41 … TL-55: Signature verification ─────────────────────────────────────

describe('TL-41 … TL-55: Signature verification (real Ed25519 keys)', () => {
  let keyMeta;

  beforeAll(() => {
    // test/support/jest.setup.js provisions the 'default' client — use it here
    keyMeta = keyManager.getSigningKey('default');
  });

  test('TL-41 real Ed25519 key material is available in test environment', () => {
    expect(keyMeta).toBeDefined();
    expect(keyMeta.keyId).toBeDefined();
    expect(Buffer.isBuffer(keyMeta.privDer)).toBe(true);
    expect(Buffer.isBuffer(keyMeta.pubDer)).toBe(true);
  });

  test('TL-42 sign + verify round-trip succeeds', () => {
    const entry = makeEntry({ signerKeyId: keyMeta.keyId });
    const buf   = log.computeEntrySigningBuffer(entry);
    const sig   = ed25519.sign(buf, keyMeta.privDer);
    expect(ed25519.verify(buf, sig, keyMeta.pubDer)).toBe(true);
  });

  test('TL-43 verifyEntrySignature returns true for valid signature', () => {
    const entry = makeEntry({ signerKeyId: keyMeta.keyId });
    const buf   = log.computeEntrySigningBuffer(entry);
    const sig   = ed25519.sign(buf, keyMeta.privDer);
    const dbRow = makeDbRow({ ...entry, signature: sig }, 1);
    expect(log.verifyEntrySignature(dbRow, keyMeta.pubDer)).toBe(true);
  });

  test('TL-44 verifyEntrySignature returns false for wrong public key', () => {
    const entry    = makeEntry({ signerKeyId: keyMeta.keyId });
    const buf      = log.computeEntrySigningBuffer(entry);
    const sig      = ed25519.sign(buf, keyMeta.privDer);
    const dbRow    = makeDbRow({ ...entry, signature: sig }, 1);
    // Use a different key
    keyManager.rotate('default', { mode: 'emergency' });
    const newMeta  = keyManager.getActivePublicKey('default');
    expect(log.verifyEntrySignature(dbRow, newMeta.pubDer)).toBe(false);
  });

  test('TL-45 verifyEntrySignature returns false for tampered signature', () => {
    // TL-44 rotated the 'default' client's key — zeroizes the outgoing
    // key's private buffer on rotation, so `keyMeta` (captured in beforeAll,
    // before TL-44 ran) is no longer usable. Re-fetch the live signing key,
    // matching the same fresh-fetch pattern TL-49 below already uses.
    const freshKey = keyManager.getSigningKey('default');
    const entry = makeEntry({ signerKeyId: freshKey.keyId });
    const buf   = log.computeEntrySigningBuffer(entry);
    const sig   = ed25519.sign(buf, freshKey.privDer);
    const tampered = Buffer.from(sig, 'base64');
    tampered[0] ^= 0xff;
    const dbRow = makeDbRow({ ...entry, signature: tampered.toString('base64') }, 1);
    expect(log.verifyEntrySignature(dbRow, freshKey.pubDer)).toBe(false);
  });

  test('TL-46 verifyEntrySignature returns false if entry hash field changed after signing', () => {
    // See TL-45 comment — must re-fetch the live key post-TL-44-rotation.
    const freshKey = keyManager.getSigningKey('default');
    const entry = makeEntry({ signerKeyId: freshKey.keyId });
    const buf   = log.computeEntrySigningBuffer(entry);
    const sig   = ed25519.sign(buf, freshKey.privDer);
    // Tamper with the entryType after signing
    const dbRow = makeDbRow({ ...entry, entryType: 'POLICY', signature: sig }, 1);
    expect(log.verifyEntrySignature(dbRow, freshKey.pubDer)).toBe(false);
  });

  test('TL-47 verifyEntrySignature returns false when pubDer is null', () => {
    const entry = makeEntry();
    const dbRow = makeDbRow(entry, 1);
    expect(log.verifyEntrySignature(dbRow, null)).toBe(false);
  });

  test('TL-48 verifyEntrySignature never throws', () => {
    const entry = makeEntry();
    const dbRow = makeDbRow(entry, 1);
    expect(() => log.verifyEntrySignature(dbRow, Buffer.alloc(0))).not.toThrow();
    expect(() => log.verifyEntrySignature(null, null)).not.toThrow();
  });

  test('TL-49 verifyRootSignature returns true for valid root signature', () => {
    const rootMeta = keyManager.getActivePublicKey('default');
    const freshKey = keyManager.getSigningKey('default');

    const rootRecord = {
      rootId:           randomUUID(),
      seqFrom:          1,
      seqTo:            50,
      entryCount:       50,
      rootHash:         'a'.repeat(64),
      previousRootHash: null,
    };
    const sigBuf = log.computeRootSigningBuffer(rootRecord);
    const sig    = ed25519.sign(sigBuf, freshKey.privDer);

    const dbRoot = {
      root_id:           rootRecord.rootId,
      seq_from:          rootRecord.seqFrom,
      seq_to:            rootRecord.seqTo,
      entry_count:       rootRecord.entryCount,
      root_hash:         rootRecord.rootHash,
      previous_root_hash: null,
      signature:         sig,
      signer_key_id:     freshKey.keyId,
    };

    expect(log.verifyRootSignature(dbRoot, rootMeta.pubDer)).toBe(true);
  });

  test('TL-50 verifyRootSignature returns false for tampered root_hash', () => {
    const freshKey = keyManager.getSigningKey('default');
    const rootMeta = keyManager.getActivePublicKey('default');

    const rootRecord = {
      rootId:           randomUUID(),
      seqFrom:          1,
      seqTo:            10,
      entryCount:       10,
      rootHash:         'a'.repeat(64),
      previousRootHash: null,
    };
    const sigBuf = log.computeRootSigningBuffer(rootRecord);
    const sig    = ed25519.sign(sigBuf, freshKey.privDer);

    const dbRoot = {
      root_id:           rootRecord.rootId,
      seq_from:          rootRecord.seqFrom,
      seq_to:            rootRecord.seqTo,
      entry_count:       rootRecord.entryCount,
      root_hash:         'b'.repeat(64),   // tampered
      previous_root_hash: null,
      signature:         sig,
      signer_key_id:     freshKey.keyId,
    };

    expect(log.verifyRootSignature(dbRoot, rootMeta.pubDer)).toBe(false);
  });

  test('TL-51 verifyRootSignature never throws', () => {
    expect(() => log.verifyRootSignature(null, null)).not.toThrow();
    expect(() => log.verifyRootSignature({}, Buffer.alloc(0))).not.toThrow();
  });

  test('TL-52 computeEntryHash includes all CANONICAL_ENTRY_FIELDS', () => {
    // Verify that each canonical field affects the hash output
    const base = makeEntry();
    for (const field of log.CANONICAL_ENTRY_FIELDS) {
      const modified = { ...base, [field]: randomUUID() };
      expect(log.computeEntryHash(base)).not.toBe(log.computeEntryHash(modified));
    }
  });

  test('TL-53 computeEntryHash is independent of non-canonical fields', () => {
    const e1 = makeEntry();
    // The payload and signature fields are NOT in CANONICAL_ENTRY_FIELDS
    const e2 = { ...e1, payload: { different: true }, signature: 'DIFFERENT' };
    expect(log.computeEntryHash(e1)).toBe(log.computeEntryHash(e2));
  });

  test('TL-54 signatures are base64-encoded 64-byte values', () => {
    const freshKey = keyManager.getSigningKey('default');
    const entry    = makeEntry({ signerKeyId: freshKey.keyId });
    const buf      = log.computeEntrySigningBuffer(entry);
    const sig      = ed25519.sign(buf, freshKey.privDer);
    const decoded  = Buffer.from(sig, 'base64');
    expect(decoded.length).toBe(64);
  });

  test('TL-55 root signing buffer is 32 bytes', () => {
    const rootRecord = {
      rootId: randomUUID(), seqFrom: 1, seqTo: 100,
      entryCount: 100, rootHash: 'a'.repeat(64), previousRootHash: null,
    };
    const buf = log.computeRootSigningBuffer(rootRecord);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBe(32);
  });
});

// ── TL-56 … TL-70: Inclusion proof (Merkle, proofVersion '2') ────────────────

describe('TL-56 … TL-70: Inclusion proof generation and verification (log.js)', () => {
  function buildProof(chainLength, entryIndex) {
    const entries = [];
    let prevHash = null;

    for (let i = 0; i < chainLength; i++) {
      const tid    = randomUUID();
      const ph     = log.computePayloadHash({ i });
      const base   = {
        transparencyId: tid, entryType: 'SYSTEM', artifactId: null,
        evidenceChainId: null, verificationId: null,
        payloadHash: ph, previousEntryHash: prevHash, signerKeyId: 'k1',
      };
      const eh = log.computeEntryHash(base);
      entries.push({ ...makeDbRow({ ...base, entryHash: eh, payload: { i }, signature: 'SIG' }, i + 1) });
      prevHash = eh;
    }

    const hashes   = entries.map(e => e.entry_hash);
    const rootHash = log.computeRootHash(hashes);
    const rootRecord = {
      id:                1,
      root_id:           randomUUID(),
      seq_from:          1,
      seq_to:            chainLength,
      entry_count:       chainLength,
      root_hash:         rootHash,
      previous_root_hash: null,
      signature:         'SIG',
      signer_key_id:     'k1',
      generated_at:      new Date().toISOString(),
    };

    return { entries, hashes, rootRecord, targetEntry: entries[entryIndex] };
  }

  test('TL-56 generateInclusionProof returns proofVersion "2" and Merkle structure', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 2);
    const proof = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    expect(proof.proofType).toBe('TRANSPARENCY_INCLUSION');
    expect(proof.proofVersion).toBe('2');
    expect(proof.entry).toBeDefined();
    expect(proof.root).toBeDefined();
    expect(proof.proof).toBeDefined();
    expect(proof.verifiable).toBe(true);
  });

  test('TL-57 proof.proof.leafIndex identifies the correct entry position', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 3);
    const proof = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    expect(proof.proof.leafIndex).toBe(3);
    // The merklePath has O(log n) elements, not all n entry hashes
    expect(proof.proof.merklePath).toBeDefined();
    expect(Array.isArray(proof.proof.merklePath)).toBe(true);
    expect(proof.proof.merklePath.length).toBeLessThan(5);
  });

  test('TL-58 verifyInclusionProof passes for a valid Merkle proof', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 1);
    const proof  = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    const result = log.verifyInclusionProof(proof);
    expect(result.valid).toBe(true);
    expect(result.failedCheck).toBeNull();
  });

  // the proof object's claimed position and tree size are verified, not just carried.
  test('TL-CRY16-01 a valid proof whose leafIndex is relabelled fails MERKLE_PATH', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(7, 4);
    const proof = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    expect(log.verifyInclusionProof(proof).valid).toBe(true);
    for (const li of [0, 3, 5, 6]) {
      const r = log.verifyInclusionProof({ ...proof, proof: { ...proof.proof, leafIndex: li } });
      expect(r.valid).toBe(false);
      expect(r.failedCheck).toBe('MERKLE_PATH');
    }
  });

  test('TL-CRY16-02 a proof whose treeSize is not the signed root entryCount fails TREE_SIZE_MATCH', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(7, 4);
    const proof = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    expect(proof.proof.treeSize).toBe(proof.root.entryCount);
    const r = log.verifyInclusionProof({ ...proof, proof: { ...proof.proof, treeSize: 8 } });
    expect(r.valid).toBe(false);
    expect(r.failedCheck).toBe('TREE_SIZE_MATCH');
    const r2 = log.verifyInclusionProof({ ...proof, root: { ...proof.root, entryCount: 9 } });
    expect(r2.checks.find((c) => c.check === 'TREE_SIZE_MATCH').result).toBe('FAIL');
  });

  test('TL-59 verifyInclusionProof fails when entry.entryHash tampered', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 2);
    const proof   = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    const tampered = { ...proof, entry: { ...proof.entry, entryHash: 'tampered'.padEnd(64, '0') } };
    const result  = log.verifyInclusionProof(tampered);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('MERKLE_PATH');
  });

  test('TL-60 verifyInclusionProof fails when root.rootHash tampered', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 0);
    const proof  = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    proof.root.rootHash = 'tampered'.padEnd(64, '0');
    const result = log.verifyInclusionProof(proof);
    expect(result.valid).toBe(false);
    // Both MERKLE_PATH and ROOT_HASH_MATCH will fail
    expect(result.checks.some(c => c.result === 'FAIL')).toBe(true);
  });

  test('TL-61 verifyInclusionProof fails when merklePath tampered', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(8, 4);
    const proof  = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    // Tamper the first path element
    if (proof.proof.merklePath.length > 0) {
      proof.proof.merklePath[0] = { ...proof.proof.merklePath[0], hash: 'bad'.padEnd(64, '0') };
    }
    const result = log.verifyInclusionProof(proof);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('MERKLE_PATH');
  });

  test('TL-62 verifyInclusionProof LEAF_INDEX_RANGE check catches invalid index', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 2);
    const proof  = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    proof.proof.leafIndex = -1;
    const result = log.verifyInclusionProof(proof);
    expect(result.checks.find(c => c.check === 'LEAF_INDEX_RANGE').result).toBe('FAIL');
  });

  test('TL-63 generateInclusionProof sets verifiable=false when entry not in hashes', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 2);
    // Use a different entry hash list that doesn't contain the target entry
    const wrongHashes = hashes.map(() => randomUUID().replace(/-/g, '').padEnd(64, '0').slice(0, 64));
    const proof = log.generateInclusionProof(targetEntry, wrongHashes, rootRecord);
    expect(proof.verifiable).toBe(false);
    expect(proof.proof.leafIndex).toBe(-1);
  });

  test('TL-64 verifyInclusionProof returns structured checks array', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(3, 1);
    const proof  = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    const result = log.verifyInclusionProof(proof);
    expect(Array.isArray(result.checks)).toBe(true);
    expect(result.checks.length).toBeGreaterThan(0);
    const checkNames = result.checks.map(c => c.check);
    expect(checkNames).toContain('LEAF_INDEX_RANGE');
    expect(checkNames).toContain('MERKLE_PATH');
    expect(checkNames).toContain('ROOT_HASH_MATCH');
  });

  test('TL-65 verifyInclusionProof handles null proof gracefully', () => {
    const result = log.verifyInclusionProof(null);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('PROOF_STRUCTURE');
  });

  test('TL-66 proof includes all required root fields', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(3, 0);
    const proof = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    expect(proof.root.rootId).toBeDefined();
    expect(proof.root.seqFrom).toBe(1);
    expect(proof.root.seqTo).toBe(3);
    expect(proof.root.entryCount).toBe(3);
    expect(proof.root.rootHash).toBeDefined();
  });

  test('TL-67 proof includes all required entry fields', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(3, 1);
    const proof = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    expect(proof.entry.transparencyId).toBeDefined();
    expect(proof.entry.entryHash).toBeDefined();
    expect(proof.entry.entryType).toBe('SYSTEM');
    expect(proof.entry.signerKeyId).toBe('k1');
  });

  test('TL-68 verifyInclusionProof passes for first entry in chain', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(10, 0);
    const proof  = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    const result = log.verifyInclusionProof(proof);
    expect(result.valid).toBe(true);
  });

  test('TL-69 verifyInclusionProof passes for last entry in chain', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(10, 9);
    const proof  = log.generateInclusionProof(targetEntry, hashes, rootRecord);
    const result = log.verifyInclusionProof(proof);
    expect(result.valid).toBe(true);
  });

  // ── TL-71 / TL-72 — regression ──────────────────────────────────────
  //
  // node-postgres returns a `timestamptz` column as a JavaScript Date. Every
  // OTHER field this function lifts off a DB row is explicitly coerced
  // (Number(...)) or is already a string, but `entry.createdAt` and
  // `root.generatedAt` were passed through raw. That is invisible while the
  // proof only ever reaches res.json() -- which serializes a Date to exactly
  // the same ISO string -- and fatal the moment the proof is CANONICALIZED:
  // stableStringify rejects every non-plain-object exotic value by design, so
  // generateEvidenceBundle() threw CanonicalizationError and
  // GET /evidence/package/:artifactId/bundle returned HTTP 500 for every
  // artifact once a covering Merkle root existed.
  //
  // These fixtures deliberately pass Date objects, because the pre-existing
  // fixtures in this file all use `new Date().toISOString()` -- strings -- and
  // that is precisely why no unit test ever reproduced the live failure.
  test('TL-71 generateInclusionProof emits ISO strings for both timestamps when the DB row supplies Date objects (pg timestamptz shape)', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 2);
    const pgEntry = { ...targetEntry, created_at: new Date('2026-09-14T12:00:00.000Z') };
    const pgRoot  = { ...rootRecord,  generated_at: new Date('2026-09-14T12:00:01.000Z') };

    const proof = log.generateInclusionProof(pgEntry, hashes, pgRoot);

    expect(typeof proof.entry.createdAt).toBe('string');
    expect(proof.entry.createdAt).toBe('2026-09-14T12:00:00.000Z');
    expect(typeof proof.root.generatedAt).toBe('string');
    expect(proof.root.generatedAt).toBe('2026-09-14T12:00:01.000Z');
  });

  test('TL-72 a proof built from pg Date rows is canonicalizable, and the proof still verifies', () => {
    const { hashes, rootRecord, targetEntry } = buildProof(5, 2);
    const pgEntry = { ...targetEntry, created_at: new Date('2026-09-14T12:00:00.000Z') };
    const pgRoot  = { ...rootRecord,  generated_at: new Date('2026-09-14T12:00:01.000Z') };

    const proof = log.generateInclusionProof(pgEntry, hashes, pgRoot);

    // The exact operation generateEvidenceBundle() performs, which used to throw.
    expect(() => stableStringify(proof)).not.toThrow();

    // Coercion must not disturb the cryptographic content of the proof.
    expect(log.verifyInclusionProof(proof).valid).toBe(true);

    // Idempotent: a row that already carries ISO strings is unchanged, and
    // produces a byte-identical canonicalization.
    const strEntry = { ...targetEntry, created_at: '2026-09-14T12:00:00.000Z' };
    const strRoot  = { ...rootRecord,  generated_at: '2026-09-14T12:00:01.000Z' };
    const strProof = log.generateInclusionProof(strEntry, hashes, strRoot);
    expect(stableStringify({ ...strProof, generatedAt: 'X' }))
      .toBe(stableStringify({ ...proof, generatedAt: 'X' }));
  });

  test('TL-70 assembleVerificationReport returns correct overall result', () => {
    const entry  = makeEntry();
    const dbRow  = makeDbRow(entry, 1);
    const checks = [
      { check: 'PAYLOAD_HASH', result: 'PASS' },
      { check: 'ENTRY_HASH',   result: 'PASS' },
      { check: 'CHAIN_LINK',   result: 'PASS' },
    ];
    const report = log.assembleVerificationReport(dbRow, checks, {
      verifiedBy:    'test',
      signatureValid: true,
    });
    expect(report.overallResult).toBe('VALID');
    expect(report.summary.passed).toBe(3);
    expect(report.summary.failed).toBe(0);
    expect(report.signatureValid).toBe(true);
  });
});

// ── TL-71 … TL-90: PG store — PG disabled ─────────────────────────────────────

describe('TL-71 … TL-90: PG store — PG disabled (logStore.js)', () => {
  beforeEach(() => {
    mockPool._enabled = false;
    mockPool.query.mockClear();
  });

  test('TL-71 appendEntry returns null when PG disabled', async () => {
    expect(await logStore.appendEntry({})).toBeNull();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('TL-72 appendRoot returns null when PG disabled', async () => {
    expect(await logStore.appendRoot({})).toBeNull();
  });

  test('TL-73 recordVerification is a no-op when PG disabled', async () => {
    await expect(logStore.recordVerification({})).resolves.toBeUndefined();
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('TL-74 getByTransparencyId returns null when PG disabled', async () => {
    expect(await logStore.getByTransparencyId(randomUUID())).toBeNull();
  });

  test('TL-75 getByArtifactId returns empty array when PG disabled', async () => {
    expect(await logStore.getByArtifactId('art-1')).toEqual([]);
  });

  test('TL-76 getByEvidenceChainId returns empty array when PG disabled', async () => {
    expect(await logStore.getByEvidenceChainId(randomUUID())).toEqual([]);
  });

  test('TL-77 listEntries returns empty result when PG disabled', async () => {
    const result = await logStore.listEntries({ page: 1, pageSize: 50 });
    expect(result).toEqual({ entries: [], total: 0, page: 1, pageSize: 50 });
  });

  test('TL-78 getLatestEntry returns null when PG disabled', async () => {
    expect(await logStore.getLatestEntry()).toBeNull();
  });

  test('TL-79 getEntriesInRange returns empty array when PG disabled', async () => {
    expect(await logStore.getEntriesInRange(1, 100)).toEqual([]);
  });

  test('TL-80 getLatestRoot returns null when PG disabled', async () => {
    expect(await logStore.getLatestRoot()).toBeNull();
  });

  test('TL-81 getRootById returns null when PG disabled', async () => {
    expect(await logStore.getRootById(randomUUID())).toBeNull();
  });

  test('TL-82 getRootCoveringEntry returns null when PG disabled', async () => {
    expect(await logStore.getRootCoveringEntry(5)).toBeNull();
  });

  test('TL-83 listRoots returns empty result when PG disabled', async () => {
    const result = await logStore.listRoots({ page: 1 });
    expect(result).toEqual({ roots: [], total: 0, page: 1, pageSize: 20 });
  });

  test('TL-84 getVerifications returns empty array when PG disabled', async () => {
    expect(await logStore.getVerifications(randomUUID())).toEqual([]);
  });

  test('TL-85 aggregateStats returns null when PG disabled', async () => {
    expect(await logStore.aggregateStats()).toBeNull();
  });
});

// ── TL-91 … TL-110: PG store — PG enabled ─────────────────────────────────────

describe('TL-91 … TL-110: PG store — PG enabled (logStore.js, mocked pool)', () => {
  beforeEach(() => {
    mockPool._enabled = true;
    mockPool.query.mockClear();
  });
  afterEach(() => { mockPool._enabled = false; });

  const sampleEntry = {
    id:                  1,
    transparency_id:     randomUUID(),
    entry_type:          'ARTIFACT',
    artifact_id:         'art-001',
    evidence_chain_id:   null,
    verification_id:     null,
    payload:             { x: 1 },
    payload_hash:        'a'.repeat(64),
    previous_entry_hash: null,
    entry_hash:          'b'.repeat(64),
    signer_key_id:       'k1',
    signer_key_version:  null,
    signature:           'sig',
    registered_by:       'test',
    tenant_id:           null,
    created_at:          new Date().toISOString(),
  };

  test('TL-91 appendEntry issues INSERT and returns row', async () => {
    mockPool.query.mockResolvedValue({
      rows: [{ id: 1, transparency_id: sampleEntry.transparency_id, created_at: new Date() }],
    });
    const result = await logStore.appendEntry({
      transparencyId: sampleEntry.transparency_id,
      entryType:      'ARTIFACT',
      payloadHash:    'a'.repeat(64),
      entryHash:      'b'.repeat(64),
      signerKeyId:    'k1',
      signature:      'sig',
      payload:        {},
    });
    expect(mockPool.query).toHaveBeenCalledTimes(1);
    expect(result).not.toBeNull();
    expect(result.id).toBe(1);
  });

  test('TL-92 appendEntry returns null and logs error on DB failure', async () => {
    mockPool.query.mockRejectedValue(new Error('DB error'));
    const result = await logStore.appendEntry({
      transparencyId: randomUUID(), entryType: 'SYSTEM',
      payloadHash: 'a'.repeat(64), entryHash: 'b'.repeat(64),
      signerKeyId: 'k1', signature: 'sig', payload: {},
    });
    expect(result).toBeNull();
  });

  test('TL-93 getByTransparencyId returns entry when found', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleEntry] });
    const result = await logStore.getByTransparencyId(sampleEntry.transparency_id);
    expect(result).toEqual(sampleEntry);
    // the public lookup is the minimized function (verification fields only).
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining('qodiqa_transparency_public_entry('),
      [sampleEntry.transparency_id],
      'transparency_by_id',
    );
  });


  test('TL-94 getByTransparencyId returns null when not found', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    expect(await logStore.getByTransparencyId(randomUUID())).toBeNull();
  });

  test('TL-95 getByArtifactId returns array of entries', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleEntry] });
    const result = await logStore.getByArtifactId('art-001');
    expect(Array.isArray(result)).toBe(true);
    expect(result[0]).toEqual(sampleEntry);
  });

  test('TL-96 listEntries returns paginated result', async () => {
    // one call to qodiqa_transparency_public_list(); the total
    // rides on each row as a window count and is stripped from the entries.
    mockPool.query.mockResolvedValueOnce({ rows: [{ ...sampleEntry, total_count: '42' }] });

    const result = await logStore.listEntries({ page: 1, pageSize: 50 });
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]).not.toHaveProperty('total_count');
    expect(result.total).toBe(42);
    expect(result.page).toBe(1);
    expect(result.pageSize).toBe(50);
  });

  test('TL-96b listEntries ignores a public tenantId filter', async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [] });
    await logStore.listEntries({ tenantId: 'tenant-victim', page: 1, pageSize: 10 });
    const [sql, params] = mockPool.query.mock.calls[0];
    expect(sql).not.toMatch(/tenant/i);
    expect(params).not.toContain('tenant-victim');
  });

  test('TL-96c a page past the end still reports the true total (probe)', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total_count: '7' }] });
    const result = await logStore.listEntries({ page: 5, pageSize: 10 });
    expect(result.entries).toEqual([]);
    expect(result.total).toBe(7);
    expect(mockPool.query.mock.calls[1][0]).toContain('qodiqa_transparency_public_list');
  });


  test('TL-97 listEntries caps pageSize at 500', async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [] });

    const result = await logStore.listEntries({ page: 1, pageSize: 99999 });
    // p_limit (6th argument) is capped at 500 before it reaches SQL, which caps it again.
    const params = mockPool.query.mock.calls[0][1];
    expect(params[5]).toBe(500);
    expect(result.pageSize).toBe(500);
  });


  test('TL-98 getLatestEntry queries for max id entry', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleEntry] });
    const result = await logStore.getLatestEntry();
    expect(result).toEqual(sampleEntry);
    const sql = mockPool.query.mock.calls[0][0];
    // routed through a SECURITY DEFINER function (migration 050) --
    // the ORDER BY id DESC now lives inside qodiqa_transparency_log_latest_entry()
    // itself, not in the calling SQL text.
    expect(sql).toContain('qodiqa_transparency_log_latest_entry');
  });

  test('TL-99 getEntriesInRange passes correct params', async () => {
    mockPool.query.mockResolvedValue({ rows: [sampleEntry] });
    await logStore.getEntriesInRange(5, 20);
    // routed through a SECURITY DEFINER function (migration 050) -- the
    // id >= $1 AND id <= $2 predicate now lives inside
    // qodiqa_transparency_log_fetch_range_full() itself.
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining('qodiqa_transparency_log_fetch_range_full'),
      [5, 20],
      'transparency_entries_in_range',
    );
  });

  test('TL-100 appendRoot inserts root and returns row', async () => {
    mockPool.query.mockResolvedValue({
      rows: [{ id: 1, root_id: randomUUID(), generated_at: new Date() }],
    });
    const result = await logStore.appendRoot({
      rootId:       randomUUID(),
      seqFrom:      1,
      seqTo:        100,
      entryCount:   100,
      rootHash:     'a'.repeat(64),
      signature:    'sig',
      signerKeyId:  'k1',
    });
    expect(result).not.toBeNull();
    expect(mockPool.query).toHaveBeenCalledTimes(1);
  });

  test('TL-101 getLatestRoot returns the most recent root', async () => {
    const sampleRoot = { id: 5, root_id: randomUUID(), root_hash: 'a'.repeat(64) };
    mockPool.query.mockResolvedValue({ rows: [sampleRoot] });
    const result = await logStore.getLatestRoot();
    expect(result).toEqual(sampleRoot);
  });

  test('TL-102 getRootCoveringEntry queries by seq range', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    await logStore.getRootCoveringEntry(42);
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining('seq_from <= $1 AND seq_to >= $1'),
      [42],
      'transparency_root_covering_entry',
    );
  });

  test('TL-103 listRoots returns paginated roots', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ id: 1 }] })
      .mockResolvedValueOnce({ rows: [{ total: '5' }] });
    const result = await logStore.listRoots({ page: 1, pageSize: 20 });
    expect(result.roots).toHaveLength(1);
    expect(result.total).toBe(5);
  });

  test('TL-104 recordVerification fires and forgets', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    await logStore.recordVerification({
      transparencyId:    randomUUID(),
      verificationType:  'ENTRY',
      verificationResult: 'VALID',
      checksPerformed:   [],
      verifiedBy:        'test',
    });
    // query is called async — just verify no throw
    await new Promise(r => setTimeout(r, 10));
  });

  test('TL-105 aggregateStats returns structured stats object', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ total_entries: '100', artifact_count: '50', evidence_count: '20',
        verification_count: '15', policy_count: '10', audit_count: '4', system_count: '1',
        distinct_signers: '2', first_entry: '2025-01-01', last_entry: '2025-06-01' }] })
      .mockResolvedValueOnce({ rows: [{ total_roots: '5', first_root: '2025-01-01', last_root: '2025-06-01' }] })
      .mockResolvedValueOnce({ rows: [{ total_verifications: '30', valid_count: '25',
        invalid_count: '3', partial_count: '1', error_count: '1' }] });

    const stats = await logStore.aggregateStats();
    expect(stats.entries.total).toBe(100);
    expect(stats.entries.byType.ARTIFACT).toBe(50);
    expect(stats.roots.total).toBe(5);
    expect(stats.verifications.valid).toBe(25);
    expect(stats.verifications.invalid).toBe(3);
  });

  test('TL-106 getVerifications returns verification history', async () => {
    const sample = { id: 1, transparency_id: randomUUID(), verification_result: 'VALID' };
    mockPool.query.mockResolvedValue({ rows: [sample] });
    const result = await logStore.getVerifications(sample.transparency_id, { limit: 10 });
    expect(result).toHaveLength(1);
    expect(result[0].verification_result).toBe('VALID');
  });

  test('TL-107 getVerifications caps limit at 500', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    await logStore.getVerifications(randomUUID(), { limit: 99999 });
    const sql = mockPool.query.mock.calls[0][0];
    expect(sql).toContain('500');
  });

  test('TL-108 listEntries applies entryType filter', async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [] });
    await logStore.listEntries({ entryType: 'EVIDENCE' });
    const [sql, params] = mockPool.query.mock.calls[0];
    expect(sql).toContain('qodiqa_transparency_public_list');
    expect(params[0]).toBe('EVIDENCE');
  });


  test('TL-109 listEntries applies date range filters', async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [] });
    await logStore.listEntries({ startTime: '2025-01-01', endTime: '2025-12-31' });
    const params = mockPool.query.mock.calls[0][1];
    expect(params[3]).toEqual(new Date('2025-01-01'));
    expect(params[4]).toEqual(new Date('2025-12-31'));
  });


  test('TL-110 appendRoot returns null and logs error on DB failure', async () => {
    mockPool.query.mockRejectedValue(new Error('insert error'));
    const result = await logStore.appendRoot({
      rootId: randomUUID(), seqFrom: 1, seqTo: 10, entryCount: 10,
      rootHash: 'a'.repeat(64), signature: 'sig', signerKeyId: 'k1',
    });
    expect(result).toBeNull();
  });
});

// ── TL-111 … TL-125: Registrar ────────────────────────────────────────────────

describe('TL-111 … TL-125: Registrar — entry registration and root generation', () => {
  let _savedClientId;
  beforeEach(() => {
    _savedClientId = process.env.QODIQA_CLIENT_ID;
    process.env.QODIQA_CLIENT_ID = 'default';
    mockPool._enabled = true;
    mockPool.query.mockClear();
  });
  afterEach(() => {
    if (_savedClientId === undefined) delete process.env.QODIQA_CLIENT_ID;
    else process.env.QODIQA_CLIENT_ID = _savedClientId;
    mockPool._enabled = false;
  });

  test('TL-111 register() creates a signed entry with real Ed25519 key', async () => {
    // lockTransparencyLogHead → genesis (tail_hash null)
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })  // lockTransparencyLogHead
      .mockResolvedValueOnce({               // appendEntry RETURNING
        rows: [{ id: 1, transparency_id: randomUUID(), created_at: new Date() }],
      })
      .mockResolvedValueOnce({ rows: [] });  // UPDATE transparency_log_head

    const result = await registrar.register({
      entryType:   'SYSTEM',
      payload:     { test: true },
      registeredBy: 'test-runner',
    });

    expect(result.transparencyId).toBeDefined();
    expect(typeof result.entryHash).toBe('string');
    expect(result.entryHash).toHaveLength(64);
    expect(typeof result.signature).toBe('string');
    // Verify the signature with the active transparency public key (Component #30)
    const tPubDer = getTransparencySigner().getActiveKeyInfo().pubDer;
    const hashBuf = Buffer.from(result.entryHash, 'hex');
    expect(ed25519.verify(hashBuf, result.signature, tPubDer)).toBe(true);
  });

  test('TL-112 register() sets previousEntryHash from the latest DB entry', async () => {
    const prevHash = 'c'.repeat(64);
    // lockTransparencyLogHead → returns the pointer row with tail_hash
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: prevHash, tail_id: '1' }] })  // lockTransparencyLogHead
      .mockResolvedValueOnce({ rows: [{ id: 2, transparency_id: randomUUID(), created_at: new Date() }] })  // appendEntry
      .mockResolvedValueOnce({ rows: [] });  // UPDATE transparency_log_head

    const result = await registrar.register({
      entryType:    'ARTIFACT',
      artifactId:   'art-001',
      payload:      {},
      registeredBy: 'test',
    });

    // The entry hash should have been computed with previousEntryHash = prevHash
    // We can verify by recomputing the entry hash (Component #30: uses transparency key)
    const tKeyInfo = getTransparencySigner().getActiveKeyInfo();
    const hashBuf = Buffer.from(result.entryHash, 'hex');
    // Signature must verify
    expect(ed25519.verify(hashBuf, result.signature, tKeyInfo.pubDer)).toBe(true);
    // The entry hash must encode the previous hash
    const expected = log.computeEntryHash({
      transparencyId:    result.transparencyId,
      entryType:         'ARTIFACT',
      artifactId:        'art-001',
      evidenceChainId:   null,
      verificationId:    null,
      payloadHash:       log.computePayloadHash({}),
      previousEntryHash: prevHash,
      signerKeyId:       tKeyInfo.keyId,
    });
    expect(result.entryHash).toBe(expected);
  });

  test('TL-113 register() throws for unknown entryType', async () => {
    await expect(registrar.register({ entryType: 'UNKNOWN' }))
      .rejects.toThrow('Unknown entryType');
  });

  test('TL-114 register() throws if entryType is missing', async () => {
    await expect(registrar.register({})).rejects.toThrow('entryType is required');
  });

  test('TL-115 register() succeeds for all valid entryTypes', async () => {
    const types = ['ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM'];
    for (const entryType of types) {
      mockPool.query
        .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })   // lockTransparencyLogHead
        .mockResolvedValueOnce({ rows: [{ id: 1, transparency_id: randomUUID(), created_at: new Date() }] })  // appendEntry
        .mockResolvedValueOnce({ rows: [] });  // UPDATE transparency_log_head

      const result = await registrar.register({ entryType, payload: {} });
      expect(result.transparencyId).toBeDefined();
      expect(result.entryHash).toHaveLength(64);
    }
  });

  // (D3): inverted. This used to pin "proceeds without prev hash" — i.e. a
  // leaf written with previousEntryHash=null into an existing chain (a fork,
  // visible here because this double does not abort the transaction the way
  // PostgreSQL does). register() now rethrows the ORIGINAL lookup error, so it
  // is classified on its own merits (retryable → recovery queue) and nothing
  // is inserted.
  test('TL-116 register() rethrows the head-lookup error and inserts nothing', async () => {
    const lookupErr = Object.assign(new Error('canceling statement due to statement timeout'), { code: '57014' });
    mockPool.query.mockRejectedValueOnce(lookupErr); // lockTransparencyLogHead fails

    await expect(registrar.register({ entryType: 'SYSTEM' })).rejects.toBe(lookupErr);
    expect(mockPool.query.mock.calls.some(([sql]) => /INSERT INTO transparency_log_entries/.test(sql))).toBe(false);
  });

  test('TL-117 generateRoot() computes valid root hash from entries', async () => {
    // Build a 3-entry chain
    const entries = [];
    let prevHash = null;
    for (let i = 0; i < 3; i++) {
      const tid = randomUUID();
      const ph  = log.computePayloadHash({ i });
      const base = { transparencyId: tid, entryType: 'SYSTEM', artifactId: null,
                     evidenceChainId: null, verificationId: null, payloadHash: ph,
                     previousEntryHash: prevHash, signerKeyId: 'k1' };
      const eh = log.computeEntryHash(base);
      entries.push({ id: i + 1, entry_hash: eh, previous_entry_hash: prevHash });
      prevHash = eh;
    }
    const expectedRootHash = log.computeRootHash(entries.map(e => e.entry_hash));

    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })                          // lockTransparencyRootsHead (no prior root)
      .mockResolvedValueOnce({ rows: [{ tail_hash: entries[2].entry_hash, tail_id: '3' }] })         // lockTransparencyLogHead
      .mockResolvedValueOnce({ rows: entries })                                                       // getEntriesInRange
      .mockResolvedValueOnce({ rows: [{ id: 1, root_id: randomUUID(), generated_at: new Date() }] })  // appendRoot
      .mockResolvedValueOnce({ rows: [] });                                                            // UPDATE transparency_roots_head

    const result = await registrar.generateRoot({ generatedBy: 'test' });
    expect(result.rootHash).toBe(expectedRootHash);
    expect(result.entryCount).toBe(3);
    expect(result.seqFrom).toBe(1);
    expect(result.seqTo).toBe(3);
  });

  test('TL-118 generateRoot() throws when no entries exist', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })  // lockTransparencyRootsHead
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] }); // lockTransparencyLogHead (no entries)

    await expect(registrar.generateRoot()).rejects.toThrow('no transparency log entries');
  });

  test('TL-119 generateRoot() throws when no new entries since last root', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: 'a'.repeat(64), tail_id: '1' }] })   // lockTransparencyRootsHead
      .mockResolvedValueOnce({ rows: [{ tail_hash: 'z'.repeat(64), tail_id: '10' }] })  // lockTransparencyLogHead
      .mockResolvedValueOnce({ rows: [{ seq_to: 10 }] });  // SELECT seq_to FROM transparency_roots WHERE root_hash = $1

    await expect(registrar.generateRoot()).rejects.toThrow('no new entries');
  });

  test('TL-120 generateRoot() signature is verifiable with active public key', async () => {
    const entries = [1, 2].map(i => ({
      id:         i,
      entry_hash: 'a'.repeat(63) + i.toString(),
      previous_entry_hash: i === 1 ? null : 'a'.repeat(64),
    }));

    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })
      .mockResolvedValueOnce({ rows: [{ tail_hash: entries[1].entry_hash, tail_id: '2' }] })
      .mockResolvedValueOnce({ rows: entries })
      .mockResolvedValueOnce({ rows: [{ id: 1, root_id: randomUUID(), generated_at: new Date() }] })
      .mockResolvedValueOnce({ rows: [] });

    const result = await registrar.generateRoot({ generatedBy: 'test' });
    // Component #30: root is signed with transparency key, not artifact key
    const tPubDer = getTransparencySigner().getActiveKeyInfo().pubDer;

    const rootForSign = {
      rootId:           result.rootId,
      seqFrom:          result.seqFrom,
      seqTo:            result.seqTo,
      entryCount:       result.entryCount,
      rootHash:         result.rootHash,
      previousRootHash: result.previousRootHash,
    };
    const sigBuf = log.computeRootSigningBuffer(rootForSign);
    expect(ed25519.verify(sigBuf, result.signature, tPubDer)).toBe(true);
  });

  test('TL-121 _signingClientId falls back to QODIQA_CLIENT_ID when QODIQA_TRANSPARENCY_SIGNING_CLIENT is unset', () => {
    const savedTransp  = process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT;
    const savedClient  = process.env.QODIQA_CLIENT_ID;
    delete process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT;
    process.env.QODIQA_CLIENT_ID = 'my-prod-client';
    expect(registrar._signingClientId()).toBe('my-prod-client');
    if (savedTransp !== undefined) process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT = savedTransp;
    else delete process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT;
    if (savedClient !== undefined) process.env.QODIQA_CLIENT_ID = savedClient;
    else delete process.env.QODIQA_CLIENT_ID;
  });

  test('TL-122 _signingClientId reads from env', () => {
    const saved = process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT;
    process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT = 'custom-client';
    expect(registrar._signingClientId()).toBe('custom-client');
    if (saved !== undefined) process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT = saved;
    else delete process.env.QODIQA_TRANSPARENCY_SIGNING_CLIENT;
  });

  test('TL-123 register() sets persisted=true when DB returns a row', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })
      .mockResolvedValueOnce({ rows: [{ id: 5, transparency_id: randomUUID(), created_at: new Date() }] })
      .mockResolvedValueOnce({ rows: [] });

    const result = await registrar.register({ entryType: 'SYSTEM' });
    expect(result.persisted).toBe(true);
    expect(result.row).not.toBeNull();
  });

  test('TL-124 register() sets persisted=false when DB returns no row (conflict)', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })
      .mockResolvedValueOnce({ rows: [] });  // ON CONFLICT DO NOTHING — no pointer UPDATE follows

    const result = await registrar.register({ entryType: 'SYSTEM' });
    expect(result.persisted).toBe(false);
    expect(result.row).toBeNull();
    expect(mockPool.query).toHaveBeenCalledTimes(2);
  });

  test('TL-125 register() includes correct fields in the persisted record', async () => {
    const capturedArgs = [];
    mockPool.query.mockImplementation((sql, args) => {
      capturedArgs.push({ sql, args });
      if (sql.includes('FROM transparency_log_head')) return { rows: [{ tail_hash: null, tail_id: '0' }] };
      if (sql.includes('INSERT INTO transparency_log_entries')) return { rows: [{ id: 1, transparency_id: randomUUID(), created_at: new Date() }] };
      return { rows: [] };  // UPDATE transparency_log_head
    });

    await registrar.register({
      entryType:      'EVIDENCE',
      artifactId:     'art-xyz',
      evidenceChainId: randomUUID(),
      payload:        { key: 'value' },
      registeredBy:   'test-actor',
    });

    // Second call is the INSERT
    const insertCall = capturedArgs.find(c => c.sql.includes('INSERT INTO transparency_log_entries'));
    expect(insertCall).toBeDefined();
    expect(insertCall.args[1]).toBe('EVIDENCE');  // entryType
    expect(insertCall.args[2]).toBe('art-xyz');   // artifact_id
  });

  // (D3): enforcementBridge.js pre-assigns the id so a queued replay of the
  // same registration is idempotent (transparency_id is UNIQUE).
  test('TL-125b register() uses a pre-assigned transparencyId, and it enters the entry hash', async () => {
    const captured = [];
    mockPool.query.mockImplementation((sql, args) => {
      captured.push({ sql, args });
      if (sql.includes('FROM transparency_log_head')) return { rows: [{ tail_hash: null, tail_id: '0' }] };
      if (sql.includes('INSERT INTO transparency_log_entries')) return { rows: [{ id: 1, transparency_id: args[0], created_at: new Date() }] };
      return { rows: [] };
    });
    const tid = randomUUID();
    const r = await registrar.register({ entryType: 'AUDIT', payload: { a: 1 }, transparencyId: tid });
    expect(r.transparencyId).toBe(tid);
    const insert = captured.find(c => c.sql.includes('INSERT INTO transparency_log_entries'));
    expect(insert.args[0]).toBe(tid);
    expect(r.entryHash).toBe(log.computeEntryHash({
      transparencyId: tid, entryType: 'AUDIT', artifactId: null, evidenceChainId: null, verificationId: null,
      payloadHash: log.computePayloadHash({ a: 1 }), previousEntryHash: null, signerKeyId: r.keyId,
    }));
  });

  test('TL-125c register() rejects a malformed pre-assigned transparencyId before any DB work', async () => {
    await expect(registrar.register({ entryType: 'AUDIT', transparencyId: 'not-a-uuid' })).rejects.toThrow(TypeError);
    await expect(registrar.register({ entryType: 'AUDIT', transparencyId: 42 })).rejects.toThrow(TypeError);
    expect(mockPool.query).not.toHaveBeenCalled();
  });
});

// ── TL-126 … TL-140: Tampering and corruption detection ───────────────────────

describe('TL-126 … TL-140: Tampering and corruption detection', () => {
  function buildValidChain(length) {
    const records = [];
    let prevHash = null;
    for (let i = 0; i < length; i++) {
      const tid = randomUUID();
      const pl  = { idx: i };
      const ph  = log.computePayloadHash(pl);
      const base = { transparencyId: tid, entryType: 'AUDIT', artifactId: null,
                     evidenceChainId: null, verificationId: null, payloadHash: ph,
                     previousEntryHash: prevHash, signerKeyId: 'k' };
      const eh = log.computeEntryHash(base);
      records.push({ id: i + 1, transparency_id: tid, entry_type: 'AUDIT',
                     artifact_id: null, evidence_chain_id: null, verification_id: null,
                     payload: pl, payload_hash: ph, previous_entry_hash: prevHash,
                     entry_hash: eh, signer_key_id: 'k', signature: 'S',
                     registered_by: 'test', tenant_id: null, created_at: new Date().toISOString() });
      prevHash = eh;
    }
    return records;
  }

  test('TL-126 chain of 20 entries validates successfully', () => {
    const chain = buildValidChain(20);
    expect(log.validateChainContinuity(chain).valid).toBe(true);
  });

  test('TL-127 inserting a record in the middle breaks chain validation', () => {
    const chain = buildValidChain(5);
    // Insert a fake record between index 2 and 3
    const fake = { ...chain[2], id: 3, transparency_id: randomUUID(),
                   entry_hash: 'ffff'.padEnd(64, 'f') };
    const corrupted = [chain[0], chain[1], fake, { ...chain[2], id: 4 }, { ...chain[3], id: 5 }];
    expect(log.validateChainContinuity(corrupted).valid).toBe(false);
  });

  test('TL-128 deleting a record from the middle is detectable via ID gap', () => {
    const chain   = buildValidChain(5);
    const deleted = [chain[0], chain[1], chain[3], chain[4]];  // id=3 removed
    const result  = log.validateChainContinuity(deleted);
    expect(result.valid).toBe(false);
    expect(result.failureDetail).toMatch(/ID gap/);
  });

  test('TL-129 modifying payload content is detectable', () => {
    const chain    = buildValidChain(3);
    const modified = [...chain];
    modified[1]    = { ...chain[1], payload: { idx: 999 } };  // wrong payload
    // payload_hash won't match
    const result = log.validateChainContinuity(modified);
    expect(result.valid).toBe(false);
    expect(result.failureDetail).toMatch(/Payload hash mismatch/);
  });

  test('TL-130 reordering two entries breaks chain validation', () => {
    const chain    = buildValidChain(4);
    const reordered = [chain[0], chain[2], chain[1], chain[3]];
    expect(log.validateChainContinuity(reordered).valid).toBe(false);
  });

  test('TL-131 modifying artifact_id without updating entry_hash is detectable', () => {
    const chain    = buildValidChain(3);
    const modified = [...chain];
    modified[1]    = { ...chain[1], artifact_id: 'attacker-art' };
    const result   = log.validateChainContinuity(modified);
    // The entry_hash was computed with artifact_id=null so changing it breaks hash
    expect(result.valid).toBe(false);
  });

  test('TL-132 inclusion proof detects root hash tampering (MERKLE_PATH fails)', () => {
    const chain  = buildValidChain(5);
    const hashes = chain.map(e => e.entry_hash);
    const rootHash = log.computeRootHash(hashes);
    const root   = { root_id: randomUUID(), seq_from: 1, seq_to: 5, entry_count: 5,
                     root_hash: rootHash, previous_root_hash: null,
                     signature: 'SIG', signer_key_id: 'k', generated_at: new Date().toISOString() };

    const proof  = log.generateInclusionProof(chain[2], hashes, root);
    // Tamper root hash in the proof — MERKLE_PATH reconstruction fails to match tampered root
    proof.root.rootHash = 'tampered'.padEnd(64, '0');
    const result = log.verifyInclusionProof(proof);
    expect(result.valid).toBe(false);
    // With Merkle proofs, tampering root.rootHash causes MERKLE_PATH to fail first
    expect(result.checks.some(c => c.result === 'FAIL')).toBe(true);
  });

  test('TL-133 inclusion proof detects tampered merklePath entry', () => {
    const chain  = buildValidChain(8);
    const hashes = chain.map(e => e.entry_hash);
    const rootHash = log.computeRootHash(hashes);
    const root   = { root_id: randomUUID(), seq_from: 1, seq_to: 8, entry_count: 8,
                     root_hash: rootHash, previous_root_hash: null,
                     signature: 'SIG', signer_key_id: 'k', generated_at: new Date().toISOString() };

    const proof = log.generateInclusionProof(chain[3], hashes, root);
    // Tamper a Merkle path element — reconstruction will yield wrong root
    if (proof.proof.merklePath.length > 0) {
      proof.proof.merklePath[0] = { ...proof.proof.merklePath[0], hash: 'injected'.padEnd(64, '0') };
    }
    const result = log.verifyInclusionProof(proof);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('MERKLE_PATH');
  });

  test('TL-134 chain validation reports exact failure ID', () => {
    const chain = buildValidChain(10);
    const corrupted = [...chain];
    corrupted[6] = { ...chain[6], entry_hash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' };
    const result = log.validateChainContinuity(corrupted);
    expect(result.valid).toBe(false);
    expect(result.failureId).toBe(7);
  });

  test('TL-135 entry hash covers signerKeyId — key substitution is detectable', () => {
    const entry1 = makeEntry({ signerKeyId: 'key-A' });
    const entry2 = makeEntry({ ...entry1, signerKeyId: 'key-B' });
    expect(log.computeEntryHash(entry1)).not.toBe(log.computeEntryHash(entry2));
  });

  test('TL-136 previousEntryHash null for genesis vs non-null for chain produce different hashes', () => {
    const e1 = makeEntry({ previousEntryHash: null });
    const e2 = makeEntry({ ...e1, previousEntryHash: 'a'.repeat(64) });
    expect(log.computeEntryHash(e1)).not.toBe(log.computeEntryHash(e2));
  });

  test('TL-137 root hash covers previousRootHash — root chain tampering is detectable', () => {
    const hashes = ['a'.repeat(64), 'b'.repeat(64)];
    const rh = log.computeRootHash(hashes);
    const base = { rootId: randomUUID(), seqFrom: 1, seqTo: 2, entryCount: 2,
                   rootHash: rh, previousRootHash: null };
    const b1 = log.computeRootSigningBuffer(base);
    const b2 = log.computeRootSigningBuffer({ ...base, previousRootHash: 'c'.repeat(64) });
    expect(b1.toString('hex')).not.toBe(b2.toString('hex'));
  });

  test('TL-138 verifyEntryIntegrity detects modification of evidenceChainId', () => {
    const entry  = makeEntry({ evidenceChainId: randomUUID() });
    const dbRow  = makeDbRow(entry, 1);
    // Tamper the entry_hash stored — it no longer matches fields
    const tampered = { ...dbRow, evidence_chain_id: randomUUID() };
    const result   = log.verifyEntryIntegrity(tampered, null);
    expect(result.valid).toBe(false);
    expect(result.failedCheck).toBe('ENTRY_HASH');
  });

  test('TL-139 computePayloadHash is sensitive to nested structure changes', () => {
    const h1 = log.computePayloadHash({ a: { b: 1 } });
    const h2 = log.computePayloadHash({ a: { b: 2 } });
    expect(h1).not.toBe(h2);
  });

  test('TL-140 100-entry chain validates in under 500ms', () => {
    const chain = [];
    let prevHash = null;
    for (let i = 0; i < 100; i++) {
      const tid = randomUUID();
      const ph  = log.computePayloadHash({ i });
      const base = { transparencyId: tid, entryType: 'SYSTEM', artifactId: null,
                     evidenceChainId: null, verificationId: null, payloadHash: ph,
                     previousEntryHash: prevHash, signerKeyId: 'k' };
      const eh = log.computeEntryHash(base);
      chain.push({ id: i + 1, transparency_id: tid, entry_type: 'SYSTEM',
                   artifact_id: null, evidence_chain_id: null, verification_id: null,
                   payload: { i }, payload_hash: ph, previous_entry_hash: prevHash,
                   entry_hash: eh, signer_key_id: 'k', signature: 'S',
                   registered_by: 'test', tenant_id: null, created_at: new Date().toISOString() });
      prevHash = eh;
    }
    const start  = Date.now();
    const result = log.validateChainContinuity(chain);
    const elapsed = Date.now() - start;
    expect(result.valid).toBe(true);
    expect(elapsed).toBeLessThan(500);
  });
});

// ── TL-141 … TL-150: RBAC permissions ─────────────────────────────────────────

describe('TL-141 … TL-150: RBAC permissions matrix', () => {
  test('TL-141 READ_TRANSPARENCY_LOG permission exists', () => {
    expect(PERMISSIONS.READ_TRANSPARENCY_LOG).toBeDefined();
  });

  test('TL-142 MANAGE_TRANSPARENCY_LOG permission exists', () => {
    expect(PERMISSIONS.MANAGE_TRANSPARENCY_LOG).toBeDefined();
  });

  test('TL-143 READ_TRANSPARENCY_LOG grants admin access', () => {
    expect(PERMISSIONS.READ_TRANSPARENCY_LOG).toContain('admin');
  });

  test('TL-144 READ_TRANSPARENCY_LOG grants auditor access', () => {
    expect(PERMISSIONS.READ_TRANSPARENCY_LOG).toContain('auditor');
  });

  test('TL-145 READ_TRANSPARENCY_LOG grants compliance access', () => {
    expect(PERMISSIONS.READ_TRANSPARENCY_LOG).toContain('compliance');
  });

  test('TL-146 MANAGE_TRANSPARENCY_LOG grants admin access', () => {
    expect(PERMISSIONS.MANAGE_TRANSPARENCY_LOG).toContain('admin');
  });

  test('TL-147 MANAGE_TRANSPARENCY_LOG does not grant viewer access', () => {
    expect(PERMISSIONS.MANAGE_TRANSPARENCY_LOG).not.toContain('viewer');
  });

  test('TL-148 MANAGE_TRANSPARENCY_LOG does not grant operator access', () => {
    expect(PERMISSIONS.MANAGE_TRANSPARENCY_LOG).not.toContain('operator');
  });

  test('TL-149 READ_TRANSPARENCY_LOG does not grant viewer access', () => {
    expect(PERMISSIONS.READ_TRANSPARENCY_LOG).not.toContain('viewer');
  });

  test('TL-150 READ_TRANSPARENCY_LOG does not grant operator access', () => {
    expect(PERMISSIONS.READ_TRANSPARENCY_LOG).not.toContain('operator');
  });
});

// ── TL-151 … TL-154: Transaction isolation and concurrency ────────────────────

describe('TL-151 … TL-154: Registrar transaction isolation and concurrency', () => {
  let _savedClientId;

  beforeEach(() => {
    _savedClientId = process.env.QODIQA_CLIENT_ID;
    process.env.QODIQA_CLIENT_ID = 'default';
    mockPool._enabled = true;
    mockPool.query.mockClear();
  });

  afterEach(() => {
    if (_savedClientId === undefined) delete process.env.QODIQA_CLIENT_ID;
    else process.env.QODIQA_CLIENT_ID = _savedClientId;
    mockPool._enabled = false;
  });

  test('TL-151 register() propagates DB error from appendEntry INSERT', async () => {
    // getLatestEntry succeeds; the appendEntry INSERT throws.
    // withTransaction should rethrow, making register() reject.
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockRejectedValueOnce(new Error('INSERT constraint violation'));

    await expect(
      registrar.register({ entryType: 'SYSTEM' })
    ).rejects.toThrow('INSERT constraint violation');
  });

  test('TL-152 generateRoot() propagates DB error from appendRoot INSERT', async () => {
    const entry = { id: 1, entry_hash: 'a'.repeat(64) };

    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })                  // lockTransparencyRootsHead
      .mockResolvedValueOnce({ rows: [{ tail_hash: entry.entry_hash, tail_id: '1' }] })      // lockTransparencyLogHead
      .mockResolvedValueOnce({ rows: [entry] })                                               // getEntriesInRange
      .mockRejectedValueOnce(new Error('root INSERT failed'));

    await expect(registrar.generateRoot()).rejects.toThrow('root INSERT failed');
  });

  test('TL-153 sequential register() calls chain correctly via previousEntryHash', async () => {
    const entry1Hash = 'b'.repeat(64);
    const entry1Row  = { id: 1, entry_hash: entry1Hash, transparency_id: randomUUID(), created_at: new Date() };

    // First call: no previous entry (genesis)
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: null, tail_id: '0' }] })
      .mockResolvedValueOnce({ rows: [entry1Row] })
      .mockResolvedValueOnce({ rows: [] });

    const result1 = await registrar.register({ entryType: 'SYSTEM', payload: {} });

    // Second call: lockTransparencyLogHead returns the row from the first call
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ tail_hash: entry1Hash, tail_id: '1' }] })
      .mockResolvedValueOnce({ rows: [{ id: 2, transparency_id: randomUUID(), created_at: new Date() }] })
      .mockResolvedValueOnce({ rows: [] });

    const result2 = await registrar.register({ entryType: 'SYSTEM', payload: {} });

    // result2's entry hash must encode entry1Hash as its previousEntryHash
    // Component #30: signerKeyId is the transparency key ID, not the artifact key ID
    const activeTranspKeyId = getTransparencySigner().getActiveKeyInfo().keyId;
    const expected2  = log.computeEntryHash({
      transparencyId:   result2.transparencyId,
      entryType:        'SYSTEM',
      artifactId:       null,
      evidenceChainId:  null,
      verificationId:   null,
      payloadHash:      log.computePayloadHash({}),
      previousEntryHash: entry1Hash,
      signerKeyId:      activeTranspKeyId,
    });

    expect(result2.entryHash).toBe(expected2);
    expect(result1.entryHash).not.toBe(result2.entryHash);
  });

  test('TL-154 register() locks transparency_log_head (FOR UPDATE) inside the transaction, under READ COMMITTED', async () => {
    const capturedSqls = [];
    mockPool.query.mockImplementation((sql) => {
      capturedSqls.push(sql);
      if (sql.includes('FROM transparency_log_head')) return { rows: [{ tail_hash: null, tail_id: '0' }] };
      if (sql.includes('INSERT INTO transparency_log_entries')) return { rows: [{ id: 1, transparency_id: randomUUID(), created_at: new Date() }] };
      return { rows: [] };
    });

    await registrar.register({ entryType: 'SYSTEM' });

    const lockSql = capturedSqls.find(s => s.includes('transparency_log_head') && s.includes('FOR UPDATE'));
    expect(lockSql).toBeDefined();
    expect(capturedSqls.some(s => s.includes('transparency_log_entries') && s.includes('FOR UPDATE'))).toBe(false);
    expect(mockPool.lastTxOpts).toEqual({ isolationLevel: 'READ COMMITTED' });
  });
});
