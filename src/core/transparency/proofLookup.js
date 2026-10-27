'use strict';

/**
 * Shared Merkle inclusion-proof lookup.
 *
 * Extracted from src/api/routes/transparencyLog.js's GET /proof/:transparencyId
 * handler so the same entry -> covering-root -> inclusion-proof sequence has
 * exactly one implementation, used by both that route and the offline
 * evidence bundle generator (src/core/evidence/generator.js
 * generateEvidenceBundle()) — a second, independently-maintained copy of
 * this lookup would be a drift risk for a security-relevant computation.
 */

const logStore = require('./logStore');
const log      = require('./log');
const merkleCheckpoints = require('./merkleCheckpoints');

/**
 * Look up the Merkle inclusion proof for an already-fetched transparency log
 * entry row.
 *
 * @param {object|null} entry — a transparency_log_entries row (or null)
 * @returns {Promise<{ proof: object|null, proofVerification: object|null, message: string|null }>}
 */
async function getInclusionProofForEntry(entry) {
  if (!entry) {
    return { proof: null, proofVerification: null, message: 'Transparency log entry not found.' };
  }

  const root = await logStore.getRootCoveringEntry(Number(entry.id));
  if (!root) {
    return {
      proof: null,
      proofVerification: null,
      message: 'No root has been generated covering this entry yet. '
             + 'Generate a root first with POST /transparency/admin/roots/generate',
    };
  }

  // The tree MUST be rebuilt over entries 1..seq_to, NOT seq_from..seq_to.
  //
  // registrar.generateRoot() computes root_hash (and entry_count) over the
  // FULL log from id 1 to seq_to — its own comment says so explicitly, and
  // records that computing from only the incremental range "produced a root
  // that shared no leaves at all with any prior root ... every root after the
  // first was cryptographically unrelated to the ones before it" (fixed there
  // under AT-078). seq_from/seq_to survive only as a record of which range
  // that particular generation call newly covered; they are NOT the tree.
  //
  // This lookup was never updated to match, so it rebuilt the tree from the
  // incremental range and recomputed a root that could not equal the stored
  // one. Invisible for the FIRST root, where seq_from === 1 makes the two
  // ranges identical — and wrong for every root after it, making every
  // inclusion proof for any entry covered by a second or later root fail
  // MERKLE_PATH and ROOT_HASH_MATCH. Found live, 2026-09-14, the
  // first time root generation ever ran on real data with more than one root
  //.
  //
  // The same stale assumption existed in GapScanner._scanRoots(); both are
  // corrected to match the registrar, which is the authority here — the
  // RFC6962 consistency proof between two roots only verifies under this
  // full-tree interpretation, and it does verify.
  //
  // still the FULL tree 1..seq_to (the interpretation above), but
  // computed from the Merkle block checkpoints (migration 059,
  // merkleCheckpoints.js): stored hashes of complete aligned blocks + the
  // leaves of the entry's own block and of the final incomplete block — no
  // longer every entry from 1. Byte-identical path/root (property-tested in
  // merkleBlocks.test.js against merkle.inclusionPath/merkleRoot).
  const tree = await merkleCheckpoints.treeFor({ seqTo: Number(root.seq_to), targetId: Number(entry.id) });
  const parts = tree.leafIndex === null
    ? { leafIndex: -1, treeSize: tree.treeSize, merklePath: [], merkleRoot: null }
    : { leafIndex: tree.leafIndex, treeSize: tree.treeSize, merklePath: tree.inclusionPath(tree.leafIndex), merkleRoot: tree.root() };

  const proof             = log.buildInclusionProof(entry, parts, root);
  const proofVerification = log.verifyInclusionProof(proof);

  return { proof, proofVerification, message: null };
}

/**
 * Look up the Merkle inclusion proof for the transparency log entry
 * registered for a given artifactId. If more than one entry was registered
 * for the same artifactId (uncommon — one enforcement decision normally
 * registers exactly one leaf), the earliest (first-registered) entry is used.
 *
 * @param {string} artifactId
 * @returns {Promise<{ proof: object|null, proofVerification: object|null, message: string|null }>}
 */
async function getInclusionProofForArtifact(artifactId) {
  const entries = await logStore.getByArtifactId(artifactId);
  const entry   = entries[0] ?? null;
  if (!entry) {
    return { proof: null, proofVerification: null, message: `No transparency log entry found for artifact ${artifactId}.` };
  }
  return getInclusionProofForEntry(entry);
}

module.exports = { getInclusionProofForEntry, getInclusionProofForArtifact };
