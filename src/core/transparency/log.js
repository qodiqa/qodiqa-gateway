'use strict';

/**
 * QODIQA Transparency Log Engine — Component #22
 *
 * Pure-logic module: no I/O, no side effects.  All functions are synchronous
 * and deterministic except where explicitly noted.
 *
 * Responsibilities:
 *   • Canonical JSON for deterministic hashing
 *   • Entry hash computation (domain-separated SHA-256)
 *   • Payload hash computation
 *   • Root hash computation over a range of entry hashes
 *   • Root signing digest computation
 *   • Ed25519 signature verification for entries and roots
 *   • Hash chain link verification (entry ↔ prior entry)
 *   • Chain continuity validation over an ordered sequence
 *   • Inclusion proof generation and offline verification
 *   • Structured report assembly
 */

const { createHash, randomUUID } = require('crypto');
const stableStringify             = require('../../utils/stableStringify');
const merkle                      = require('./merkle');

// ── Domain separators ─────────────────────────────────────────────────────────
// Unique per artifact class — prevents cross-protocol signature reuse.

const ENTRY_DOMAIN = 'QODIQA::TRANSPARENCY::V1';
const ROOT_DOMAIN  = 'QODIQA::TRANSPARENCY_ROOT::V1';

function _sha256Hex(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

function _sha256Buffer(str) {
  return createHash('sha256').update(str, 'utf8').digest();
}

// ── Canonical entry fields ────────────────────────────────────────────────────
//
// These fields are hashed to produce entry_hash.  Changing any of them
// produces a different hash, revealing any tampering with the entry.
// Operational metadata (created_at, registered_by, tenant_id) is excluded.

const CANONICAL_ENTRY_FIELDS = Object.freeze([
  'transparencyId',
  'entryType',
  'artifactId',
  'evidenceChainId',
  'verificationId',
  'payloadHash',
  'previousEntryHash',
  'signerKeyId',
]);

// Canonical root fields hashed to produce the root signing digest.
const CANONICAL_ROOT_FIELDS = Object.freeze([
  'rootId',
  'seqFrom',
  'seqTo',
  'entryCount',
  'rootHash',
  'previousRootHash',
]);

// ── Hash computation ──────────────────────────────────────────────────────────

/**
 * Compute SHA-256 of the canonical JSON of the entry payload.
 *
 * @param {object} payload — arbitrary JSON object
 * @returns {string} 64-char hex SHA-256
 */
function computePayloadHash(payload) {
  return _sha256Hex(stableStringify(payload ?? {}));
}

/**
 * Compute the domain-separated entry hash.
 *
 * entry_hash = SHA-256(ENTRY_DOMAIN || canonicalJson(canonical_fields))
 *
 * Only CANONICAL_ENTRY_FIELDS are included so that metadata fields
 * (created_at, registered_by, tenant_id) do not affect the hash.
 *
 * @param {object} record — must contain all CANONICAL_ENTRY_FIELDS (camelCase)
 * @returns {string} 64-char hex SHA-256
 */
function computeEntryHash(record) {
  const canonical = {};
  for (const f of CANONICAL_ENTRY_FIELDS) {
    canonical[f] = record[f] ?? null;
  }
  return createHash('sha256')
    .update(ENTRY_DOMAIN,           'utf8')
    .update(stableStringify(canonical), 'utf8')
    .digest('hex');
}

/**
 * Compute the 32-byte Buffer used as input to the Ed25519 signing operation
 * for an entry.  This is the domain-separated SHA-256 hash buffer.
 *
 * @param {object} record — same fields as computeEntryHash
 * @returns {Buffer} 32-byte SHA-256 digest
 */
function computeEntrySigningBuffer(record) {
  return Buffer.from(computeEntryHash(record), 'hex');
}

/**
 * Compute the Merkle root hash from an ordered list of entry hashes.
 *
 * Uses RFC6962-compatible Merkle tree construction:
 *   leaf_hash(e) = SHA-256(0x00 || bytes(e))
 *   node_hash(l, r) = SHA-256(0x01 || l || r)
 *
 * Reproducible by any party with access to the ordered entry list and merkle.js.
 *
 * @param {string[]} entryHashes — hex entry hashes in ascending id order
 * @returns {string} 64-char hex Merkle root
 */
function computeRootHash(entryHashes) {
  if (!Array.isArray(entryHashes) || entryHashes.length === 0) {
    throw new RangeError('computeRootHash: entryHashes must be a non-empty array');
  }
  return merkle.merkleRoot(entryHashes);
}

/**
 * Compute the 32-byte signing buffer for a root record.
 * Covers all root metadata so any field modification is detectable.
 *
 * @param {object} rootRecord — must contain all CANONICAL_ROOT_FIELDS (camelCase)
 * @returns {Buffer} 32-byte SHA-256 digest
 */
function computeRootSigningBuffer(rootRecord) {
  const canonical = {};
  for (const f of CANONICAL_ROOT_FIELDS) {
    canonical[f] = rootRecord[f] ?? null;
  }
  return createHash('sha256')
    .update(ROOT_DOMAIN,               'utf8')
    .update(stableStringify(canonical), 'utf8')
    .digest();
}

// ── Signature verification ────────────────────────────────────────────────────

/**
 * Verify the Ed25519 signature on a transparency log entry.
 *
 * Returns false (never throws) when the signature is invalid or pubDer is
 * unavailable — consistent with the existing QODIQA ed25519.verify() contract.
 *
 * @param {object} entryRecord — DB row (snake_case) or camelCase record
 * @param {Buffer} pubDer      — SPKI DER-encoded Ed25519 public key
 * @returns {boolean}
 */
function verifyEntrySignature(entryRecord, pubDer) {
  try {
    if (!pubDer || !Buffer.isBuffer(pubDer)) return false;

    const camelRecord = _toCanonicalCase(entryRecord);
    const hashBuffer  = computeEntrySigningBuffer(camelRecord);

    const { verify } = require('../../infra/crypto/ed25519');
    const sig = camelRecord.signature ?? entryRecord.signature;
    return verify(hashBuffer, sig, pubDer);
  } catch {
    return false;
  }
}

/**
 * Verify the Ed25519 signature on a transparency root.
 *
 * @param {object} rootRecord — DB row (snake_case) or camelCase record
 * @param {Buffer} pubDer
 * @returns {boolean}
 */
function verifyRootSignature(rootRecord, pubDer) {
  try {
    if (!pubDer || !Buffer.isBuffer(pubDer)) return false;

    const camelRoot = _toRootCanonicalCase(rootRecord);
    const hashBuffer = computeRootSigningBuffer(camelRoot);

    const { verify } = require('../../infra/crypto/ed25519');
    const sig = camelRoot.signature ?? rootRecord.signature;
    return verify(hashBuffer, sig, pubDer);
  } catch {
    return false;
  }
}

// ── Field name normalisation ──────────────────────────────────────────────────
// DB rows use snake_case; pure-logic functions expect camelCase.

function _toCanonicalCase(r) {
  return {
    transparencyId:   r.transparencyId   ?? r.transparency_id,
    entryType:        r.entryType         ?? r.entry_type,
    artifactId:       r.artifactId        ?? r.artifact_id        ?? null,
    evidenceChainId:  r.evidenceChainId   ?? r.evidence_chain_id  ?? null,
    verificationId:   r.verificationId    ?? r.verification_id    ?? null,
    payloadHash:      r.payloadHash       ?? r.payload_hash,
    previousEntryHash: r.previousEntryHash ?? r.previous_entry_hash ?? null,
    signerKeyId:      r.signerKeyId       ?? r.signer_key_id,
    signature:        r.signature,
    entryHash:        r.entryHash         ?? r.entry_hash,
  };
}

function _toRootCanonicalCase(r) {
  // seqFrom/seqTo are BIGINT columns — node-postgres returns BIGINT as a JS
  // string (to avoid precision loss beyond Number.MAX_SAFE_INTEGER), but
  // registrar.js signs them as JS numbers (Number(latestRoot.seq_to) + 1,
  // Number(latestEntry.id)). Without this coercion, re-verifying a root
  // freshly fetched from Postgres recomputes the signing buffer over the
  // string form and never matches a genuine signature (confirmed via the
  // acceptance test framework, AT-079).
  const seqFrom = r.seqFrom ?? r.seq_from;
  const seqTo   = r.seqTo   ?? r.seq_to;
  return {
    rootId:           r.rootId            ?? r.root_id,
    seqFrom:          seqFrom !== undefined && seqFrom !== null ? Number(seqFrom) : null,
    seqTo:            seqTo   !== undefined && seqTo   !== null ? Number(seqTo)   : null,
    entryCount:       r.entryCount        ?? r.entry_count,
    rootHash:         r.rootHash          ?? r.root_hash,
    previousRootHash: r.previousRootHash  ?? r.previous_root_hash ?? null,
    signature:        r.signature,
    signerKeyId:      r.signerKeyId       ?? r.signer_key_id,
  };
}

// ── Entry integrity verification ──────────────────────────────────────────────

/**
 * Verify the integrity of a single entry record without signature validation.
 * Checks: payload hash correctness, entry hash correctness, chain link.
 *
 * @param {object}      entryRecord — DB row or camelCase record
 * @param {object|null} priorRecord — the entry matching entryRecord's previousEntryHash,
 *   resolved by the caller (e.g. via logStore.getByEntryHash), or null if none was found.
 *   A record that itself carries no previousEntryHash (genesis) always passes regardless
 *   of priorRecord. A record that DOES carry a previousEntryHash but priorRecord is null
 *   is treated as a verification failure, not a skip — the record claims a prior entry
 *   the caller could not resolve, which is the signature of a spliced/deleted prior.
 * @returns {{ valid: boolean, checks: object[], failedCheck: string|null, failureReason: string|null }}
 */
function verifyEntryIntegrity(entryRecord, priorRecord) {
  const rec    = _toCanonicalCase(entryRecord);
  const checks = [];

  function pass(name)         { checks.push({ check: name, result: 'PASS' }); }
  function fail(name, reason) { checks.push({ check: name, result: 'FAIL', reason }); }

  // ── Check 1: PAYLOAD_HASH ──────────────────────────────────────────────────
  const payload = entryRecord.payload ?? {};
  const computedPayloadHash = computePayloadHash(payload);
  if (rec.payloadHash === computedPayloadHash) {
    pass('PAYLOAD_HASH');
  } else {
    fail('PAYLOAD_HASH',
      `Stored payload_hash ${rec.payloadHash} ≠ recomputed ${computedPayloadHash}`);
  }

  // ── Check 2: ENTRY_HASH ────────────────────────────────────────────────────
  const computedEntryHash = computeEntryHash(rec);
  if (rec.entryHash === computedEntryHash) {
    pass('ENTRY_HASH');
  } else {
    fail('ENTRY_HASH',
      `Stored entry_hash ${rec.entryHash} ≠ recomputed ${computedEntryHash}`);
  }

  // ── Check 3: CHAIN_LINK ────────────────────────────────────────────────────
  if (!rec.previousEntryHash) {
    pass('CHAIN_LINK');   // genesis entry — no prior claimed
  } else if (!priorRecord) {
    fail('CHAIN_LINK',
      `previous_entry_hash ${rec.previousEntryHash} claims a prior entry, but none was resolved`);
  } else {
    const priorHash = priorRecord.entry_hash ?? priorRecord.entryHash;
    if (rec.previousEntryHash === priorHash) {
      pass('CHAIN_LINK');
    } else {
      fail('CHAIN_LINK',
        `previous_entry_hash ${rec.previousEntryHash} ≠ prior entry_hash ${priorHash}`);
    }
  }

  const firstFail = checks.find(c => c.result === 'FAIL');
  return {
    valid:         !firstFail,
    checks,
    failedCheck:   firstFail?.check  ?? null,
    failureReason: firstFail?.reason ?? null,
  };
}

// ── Chain continuity validation ───────────────────────────────────────────────

/**
 * Validate continuity over an ordered array of entry records (id ASC).
 *
 * Checks per record:
 *   - Payload hash correctness
 *   - Entry hash correctness (recomputed from fields)
 *   - Hash chain link (previousEntryHash === prior entry_hash)
 *   - No id gaps (sequential IDs)
 *
 * @param {object[]} records — ordered ASC by id
 * @returns {{ valid: boolean, checkedCount: number, failureId: number|null, failureDetail: string|null }}
 */
function validateChainContinuity(records) {
  if (!Array.isArray(records) || records.length === 0) {
    return { valid: true, checkedCount: 0, failureId: null, failureDetail: null };
  }

  let prevEntryHash = null;
  let prevId        = null;
  let checkedCount  = 0;

  for (const rec of records) {
    const r         = _toCanonicalCase(rec);
    const currentId = Number(rec.id);

    // ID gap check
    if (prevId !== null && Number.isFinite(prevId) && Number.isFinite(currentId)) {
      if (currentId !== prevId + 1) {
        return {
          valid:         false,
          checkedCount,
          failureId:     currentId,
          failureDetail: `ID gap: expected ${prevId + 1}, found ${currentId}`,
        };
      }
    }

    // Payload hash check — only when the caller actually provided a payload.
    // logStore.getEntriesInRange() (the caller behind GET /admin/chain/
    // validate) deliberately omits the payload column for size reasons, so
    // rec.payload is undefined for every record from that path; treating
    // "not provided" as "{}" would recompute SHA-256("{}") and always
    // mismatch the real stored hash for any non-trivial payload — a false
    // positive on every genuine, untampered entry. Skipping (not failing)
    // this specific check when payload is absent mirrors the same
    // "data not provided → SKIP" handling verifyEntryIntegrity() already
    // uses for a missing prior record, just above.
    if (rec.payload !== undefined) {
      const computedPayloadHash = computePayloadHash(rec.payload);
      if (r.payloadHash !== computedPayloadHash) {
        return {
          valid:         false,
          checkedCount,
          failureId:     currentId,
          failureDetail: `Payload hash mismatch at id=${currentId}: stored=${r.payloadHash}, recomputed=${computedPayloadHash}`,
        };
      }
    }

    // Entry hash check
    const computedEntryHash = computeEntryHash(r);
    if (r.entryHash !== computedEntryHash) {
      return {
        valid:         false,
        checkedCount,
        failureId:     currentId,
        failureDetail: `Entry hash mismatch at id=${currentId}: stored=${r.entryHash}, recomputed=${computedEntryHash}`,
      };
    }

    // Chain link check
    if (checkedCount === 0) {
      if (r.previousEntryHash !== null && r.previousEntryHash !== undefined) {
        // First record in the provided window may have a legitimate prev hash
        // (it's not the genesis entry). We skip this check.
      }
    } else if (r.previousEntryHash !== prevEntryHash) {
      return {
        valid:         false,
        checkedCount,
        failureId:     currentId,
        failureDetail: `Chain break at id=${currentId}: expected prev_hash=${prevEntryHash}, stored=${r.previousEntryHash}`,
      };
    }

    prevEntryHash = r.entryHash;
    prevId        = currentId;
    checkedCount++;
  }

  return { valid: true, checkedCount, failureId: null, failureDetail: null };
}

// ── Inclusion proof ───────────────────────────────────────────────────────────

/**
 * Generate a Merkle inclusion proof for a transparency log entry.
 *
 * Returns an O(log n) proof — the entry's position and a sibling path from
 * leaf to root — sufficient for offline cryptographic verification without
 * access to any other entries.
 *
 * A verifier with no system access can:
 *   1. Recompute leafHash = SHA-256(0x00 || bytes(entryHash))
 *   2. Walk the merklePath, combining with siblings at each level
 *   3. Confirm the recomputed root matches proof.root.rootHash
 *   4. Verify the root and entry signatures with the public key
 *
 * @param {object}   entryRecord  — the DB row being proved
 * @param {string[]} entryHashes  — all entry_hashes in root's [seqFrom, seqTo] range (id ASC)
 * @param {object}   rootRecord   — the transparency_roots DB row covering this entry
 * @returns {object} proof object
 */
/**
 * Coerce a timestamp field to a canonical ISO-8601 UTC string.
 *
 * node-postgres returns a `timestamptz` column as a JavaScript `Date`, and a
 * proof's two timestamp fields (`entry.createdAt`, `root.generatedAt`) are
 * read straight off DB rows — unlike every neighbouring field, which is
 * explicitly coerced with `Number(...)` or is already a string. A `Date` is
 * harmless while the proof is only ever handed to `res.json()` (which
 * serializes it to exactly this ISO string), but it is fatal the moment the
 * proof is CANONICALIZED: `stableStringify` rejects every non-plain-object
 * exotic value by design, so `generateEvidenceBundle()` threw
 * `CanonicalizationError` and `GET /evidence/package/:artifactId/bundle`
 * returned HTTP 500 — deterministically, for every artifact, but only once a
 * covering Merkle root existed (before that the proof is null and the bundle
 * reports `available: false`, which is why no test or prior run ever reached
 * it). Found live, 2026-09-14.
 *
 * Idempotent: a string passes through untouched, so file-mode records and
 * already-serialized rows are unaffected. The emitted value is byte-identical
 * to what `JSON.stringify` produced for the `Date` before, so no HTTP
 * response body and no proof hash changes.
 */
function _isoTimestamp(value) {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return value;
}

function generateInclusionProof(entryRecord, entryHashes, rootRecord) {
  const rec  = _toCanonicalCase(entryRecord);

  const leafIndex  = entryHashes.indexOf(rec.entryHash);
  const treeSize   = entryHashes.length;
  const merklePath = leafIndex >= 0
    ? merkle.inclusionPath(entryHashes, leafIndex)
    : [];
  const merkleRoot  = leafIndex >= 0
    ? computeRootHash(entryHashes)
    : null;

  return buildInclusionProof(entryRecord, { leafIndex, treeSize, merklePath, merkleRoot }, rootRecord);
}

/**
 * the proof object from already-computed parts — used by
 * generateInclusionProof() above (full leaf list) and by proofLookup.js's
 * checkpoint path (merkleCheckpoints.js). One object shape, one place.
 * leafIndex < 0 means the entry is not in the tree (proof not verifiable).
 */
function buildInclusionProof(entryRecord, { leafIndex, treeSize, merklePath, merkleRoot }, rootRecord) {
  const rec  = _toCanonicalCase(entryRecord);
  const root = _toRootCanonicalCase(rootRecord);

  return {
    proofVersion: '2',
    proofType:    'TRANSPARENCY_INCLUSION',
    generatedAt:  new Date().toISOString(),
    entry: {
      transparencyId:    rec.transparencyId,
      id:                Number(entryRecord.id),
      entryType:         rec.entryType,
      artifactId:        rec.artifactId,
      evidenceChainId:   rec.evidenceChainId,
      verificationId:    rec.verificationId,
      payloadHash:       rec.payloadHash,
      previousEntryHash: rec.previousEntryHash,
      entryHash:         rec.entryHash,
      signerKeyId:       rec.signerKeyId,
      signature:         rec.signature,
      createdAt:         _isoTimestamp(entryRecord.created_at ?? entryRecord.createdAt),
    },
    root: {
      rootId:           root.rootId,
      seqFrom:          Number(root.seqFrom),
      seqTo:            Number(root.seqTo),
      entryCount:       Number(root.entryCount),
      rootHash:         root.rootHash,
      previousRootHash: root.previousRootHash,
      signerKeyId:      root.signerKeyId,
      signature:        root.signature,
      generatedAt:      _isoTimestamp(rootRecord.generated_at ?? rootRecord.generatedAt),
    },
    proof: {
      leafIndex,
      treeSize,
      merklePath,    // O(log n) sibling hashes — NOT the full entry list
      merkleRoot,
    },
    verifiable: leafIndex >= 0,
  };
}

/**
 * Verify a Merkle inclusion proof offline (no DB access required).
 *
 * Checks:
 *   1. PROOF_STRUCTURE  — required fields present
 *   2. LEAF_INDEX_RANGE — leafIndex within [0, treeSize)
 * 3. TREE_SIZE_MATCH — proof.treeSize equals the signed root's entryCount (the tree the root commits to)
 * 4. MERKLE_PATH — the path is exactly the RFC6962 path for (leafIndex, treeSize) — position-bound —
 *                         and its reconstruction yields the Merkle root
 *   5. ROOT_HASH_MATCH  — reconstructed root matches proof.root.rootHash
 *
 * Signature verification requires the public key and is performed by the caller
 * using verifyEntrySignature() and verifyRootSignature().
 *
 * @param {object} proof — from generateInclusionProof() (proofVersion '2')
 * @returns {{ valid: boolean, checks: object[], failedCheck: string|null, failureReason: string|null }}
 */
function verifyInclusionProof(proof) {
  const checks = [];

  function pass(name)         { checks.push({ check: name, result: 'PASS' }); }
  function fail(name, reason) { checks.push({ check: name, result: 'FAIL', reason }); }

  if (!proof || !proof.entry || !proof.root || !proof.proof) {
    return {
      valid:         false,
      checks:        [{ check: 'PROOF_STRUCTURE', result: 'FAIL', reason: 'Proof is missing required fields' }],
      failedCheck:   'PROOF_STRUCTURE',
      failureReason: 'Proof is missing required fields',
    };
  }

  const { entry, root, proof: proofData } = proof;

  // ── Check 1: LEAF_INDEX_RANGE ──────────────────────────────────────────────
  const leafIndex = Number(proofData.leafIndex);
  const treeSize  = Number(proofData.treeSize);
  if (leafIndex >= 0 && leafIndex < treeSize) {
    pass('LEAF_INDEX_RANGE');
  } else {
    fail('LEAF_INDEX_RANGE',
      `leafIndex ${leafIndex} out of range [0, ${treeSize - 1}]`
    );
  }

  // ── Check 2: TREE_SIZE_MATCH — the claimed tree is the one the signed root covers ────────────────
  if (Number.isSafeInteger(treeSize) && treeSize === Number(root.entryCount)) {
    pass('TREE_SIZE_MATCH');
  } else {
    fail('TREE_SIZE_MATCH', `proof.treeSize ${proofData.treeSize} is not the signed root's entryCount ${root.entryCount}`);
  }

  // ── Check 3: MERKLE_PATH — the path for exactly (leafIndex, treeSize), rebuilt to the root ───────────────
  try {
    const valid = merkle.verifyInclusionPath(
      entry.entryHash,
      proofData.merklePath,
      root.rootHash,
      leafIndex,
      treeSize,
    );
    if (valid) {
      pass('MERKLE_PATH');
    } else {
      fail('MERKLE_PATH',
        `Merkle path is not the path of leaf ${leafIndex} in a ${treeSize}-leaf tree, or does not rebuild proof.root.rootHash ${root.rootHash}`
      );
    }
  } catch (e) {
    fail('MERKLE_PATH', `Merkle path verification failed: ${e.message}`);
  }

  // ── Check 3: ROOT_HASH_MATCH ───────────────────────────────────────────────
  if (proofData.merkleRoot !== null && proofData.merkleRoot !== undefined) {
    if (proofData.merkleRoot === root.rootHash) {
      pass('ROOT_HASH_MATCH');
    } else {
      fail('ROOT_HASH_MATCH',
        `proof.merkleRoot ${proofData.merkleRoot} ≠ proof.root.rootHash ${root.rootHash}`
      );
    }
  } else {
    fail('ROOT_HASH_MATCH', 'proof.merkleRoot is missing');
  }

  const firstFail = checks.find(c => c.result === 'FAIL');
  return {
    valid:         !firstFail,
    checks,
    failedCheck:   firstFail?.check  ?? null,
    failureReason: firstFail?.reason ?? null,
  };
}

// ── Consistency proof ─────────────────────────────────────────────────────────

/**
 * Generate an RFC6962 Merkle consistency proof between two roots.
 *
 * Proves that the tree covered by oldRootRecord is a cryptographic prefix of
 * the tree covered by newRootRecord.  The proof has O(log n) elements.
 *
 * @param {object}   oldRootRecord      — older transparency_roots DB row
 * @param {object}   newRootRecord      — newer transparency_roots DB row
 * @param {string[]} allEntryHashes     — all entry_hashes in [1, newRoot.seqTo] (id ASC)
 * @returns {object} consistency proof object
 */
function generateConsistencyProof(oldRootRecord, newRootRecord, allEntryHashes) {
  const oldRoot = _toRootCanonicalCase(oldRootRecord);
  const newRoot = _toRootCanonicalCase(newRootRecord);

  const oldSize = Number(oldRoot.entryCount);
  const newSize = Number(newRoot.entryCount);

  if (allEntryHashes.length < newSize) {
    throw new RangeError(
      `generateConsistencyProof: need ${newSize} entry hashes, got ${allEntryHashes.length}`,
    );
  }

  const proofHashes = merkle.consistencyProof(
    oldSize,
    newSize,
    allEntryHashes.slice(0, newSize),
  );

  return {
    proofVersion: '2',
    proofType:    'TRANSPARENCY_CONSISTENCY',
    generatedAt:  new Date().toISOString(),
    oldTree: {
      rootId:     oldRoot.rootId,
      seqFrom:    Number(oldRoot.seqFrom),
      seqTo:      Number(oldRoot.seqTo),
      entryCount: oldSize,
      rootHash:   oldRoot.rootHash,
      signature:  oldRoot.signature,
      signerKeyId: oldRoot.signerKeyId,
    },
    newTree: {
      rootId:     newRoot.rootId,
      seqFrom:    Number(newRoot.seqFrom),
      seqTo:      Number(newRoot.seqTo),
      entryCount: newSize,
      rootHash:   newRoot.rootHash,
      signature:  newRoot.signature,
      signerKeyId: newRoot.signerKeyId,
    },
    proof: {
      proofHashes,
      proofLength: proofHashes.length,
    },
    verifiable: true,
  };
}

/**
 * Verify a consistency proof offline.
 *
 * @param {object} consistencyProofObj — from generateConsistencyProof()
 * @returns {{ valid: boolean, checks: object[], failedCheck: string|null, failureReason: string|null }}
 */
function verifyConsistencyProof(consistencyProofObj) {
  const checks = [];

  function pass(name)         { checks.push({ check: name, result: 'PASS' }); }
  function fail(name, reason) { checks.push({ check: name, result: 'FAIL', reason }); }

  if (!consistencyProofObj?.oldTree || !consistencyProofObj?.newTree || !consistencyProofObj?.proof) {
    return {
      valid:         false,
      checks:        [{ check: 'PROOF_STRUCTURE', result: 'FAIL', reason: 'Proof is missing required fields' }],
      failedCheck:   'PROOF_STRUCTURE',
      failureReason: 'Proof is missing required fields',
    };
  }

  const { oldTree, newTree, proof: proofData } = consistencyProofObj;

  try {
    const valid = merkle.verifyConsistencyProof(
      oldTree.rootHash,
      newTree.rootHash,
      oldTree.entryCount,
      newTree.entryCount,
      proofData.proofHashes,
    );
    if (valid) {
      pass('CONSISTENCY_PROOF');
    } else {
      fail('CONSISTENCY_PROOF',
        `Consistency proof failed: tree(${oldTree.entryCount}) is not a prefix of tree(${newTree.entryCount})`
      );
    }
  } catch (e) {
    fail('CONSISTENCY_PROOF', `Consistency proof verification failed: ${e.message}`);
  }

  const firstFail = checks.find(c => c.result === 'FAIL');
  return {
    valid:         !firstFail,
    checks,
    failedCheck:   firstFail?.check  ?? null,
    failureReason: firstFail?.reason ?? null,
  };
}

// ── Report assembly ───────────────────────────────────────────────────────────

/**
 * Assemble a structured verification report for an entry.
 *
 * @param {object}   entryRecord
 * @param {object[]} checks       — from verifyEntryIntegrity() checks array
 * @param {object}   [opts]
 * @param {string}   [opts.verifiedBy]
 * @param {boolean}  [opts.signatureValid]  — from verifyEntrySignature()
 * @param {string}   [opts.signerKeyStatus] — 'active', 'revoked', null
 * @returns {object}
 */
function assembleVerificationReport(entryRecord, checks, opts) {
  const { verifiedBy = 'system', signatureValid = null, signerKeyStatus = null } = opts || {};
  const rec = _toCanonicalCase(entryRecord);

  const checksFailed  = checks.filter(c => c.result === 'FAIL');
  const checksSkipped = checks.filter(c => c.result === 'SKIP');
  const checksPassed  = checks.filter(c => c.result === 'PASS');

  let overallResult;
  if (checksFailed.length > 0)            overallResult = 'INVALID';
  else if (checksSkipped.length > 0)      overallResult = 'PARTIAL';
  else if (checksPassed.length > 0)       overallResult = 'VALID';
  else                                     overallResult = 'ERROR';

  return {
    reportType:    'TRANSPARENCY_VERIFICATION',
    generatedAt:   new Date().toISOString(),
    verifiedBy,
    entry: {
      transparencyId: rec.transparencyId,
      entryType:      rec.entryType,
      entryHash:      rec.entryHash,
      signerKeyId:    rec.signerKeyId,
      createdAt:      entryRecord.created_at ?? entryRecord.createdAt,
    },
    overallResult,
    integrityChecks:  checks,
    signatureValid:   signatureValid,
    signerKeyStatus:  signerKeyStatus,
    summary: {
      passed:  checksPassed.length,
      failed:  checksFailed.length,
      skipped: checksSkipped.length,
      total:   checks.length,
    },
    firstFailure: checksFailed[0] ?? null,
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  // Hash computation
  computePayloadHash,
  computeEntryHash,
  computeEntrySigningBuffer,
  computeRootHash,
  computeRootSigningBuffer,
  // Signature verification
  verifyEntrySignature,
  verifyRootSignature,
  // Integrity verification
  verifyEntryIntegrity,
  validateChainContinuity,
  // Inclusion proofs (Merkle path, O(log n))
  generateInclusionProof,
  buildInclusionProof,
  verifyInclusionProof,
  // Consistency proofs (RFC6962 §2.1.2)
  generateConsistencyProof,
  verifyConsistencyProof,
  // Reporting
  assembleVerificationReport,
  // Internal field normalisation (exported for tests)
  _toCanonicalCase,
  _toRootCanonicalCase,
  // Constants
  ENTRY_DOMAIN,
  ROOT_DOMAIN,
  CANONICAL_ENTRY_FIELDS,
  CANONICAL_ROOT_FIELDS,
};
