'use strict';

/**
 * Transparency Gap Detector — Component #14
 *
 * Builds structured gap records for all 8 gap types.
 * Detectors never throw and never classify — they only construct raw gap data.
 * Classification (severity) is delegated to classifier.js.
 *
 * GAP_TYPE catalogue:
 *   MISSING_TRANSPARENCY_ENTRY    — Expected entry not found
 *   SEQUENCE_BREAK                — Sequence number continuity broken
 *   HASH_CHAIN_BREAK              — previousEntryHash chain link broken
 *   PARTIAL_APPEND                — Entry signed but not persisted
 *   ARTIFACT_WITHOUT_TRANSPARENCY — Artifact exists, no transparency record
 *   TRANSPARENCY_WITHOUT_ARTIFACT — Transparency record exists, artifact does not
 *   MISSING_VERIFICATION_EVIDENCE — Verification references missing transparency
 *   CHECKPOINT_DIVERGENCE         — Checkpoint cannot be reconciled
 */

const { randomUUID } = require('crypto');

// ── Gap type catalogue ────────────────────────────────────────────────────────

const GAP_TYPE = Object.freeze({
  MISSING_TRANSPARENCY_ENTRY:    'MISSING_TRANSPARENCY_ENTRY',
  SEQUENCE_BREAK:                'SEQUENCE_BREAK',
  HASH_CHAIN_BREAK:              'HASH_CHAIN_BREAK',
  PARTIAL_APPEND:                'PARTIAL_APPEND',
  ARTIFACT_WITHOUT_TRANSPARENCY: 'ARTIFACT_WITHOUT_TRANSPARENCY',
  TRANSPARENCY_WITHOUT_ARTIFACT: 'TRANSPARENCY_WITHOUT_ARTIFACT',
  MISSING_VERIFICATION_EVIDENCE: 'MISSING_VERIFICATION_EVIDENCE',
  CHECKPOINT_DIVERGENCE:         'CHECKPOINT_DIVERGENCE',
});

// ── Internal builder ──────────────────────────────────────────────────────────

function _buildGap(gapType, context = {}) {
  return {
    gapId:      randomUUID(),
    gapType,
    service:    context.service    ?? 'transparency',
    artifactId: context.artifactId ?? null,
    detectedAt: new Date().toISOString(),
    details:    context.details    ?? {},
  };
}

// ── Public detectors ──────────────────────────────────────────────────────────

/**
 * Expected transparency entry is missing.
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {string} [ctx.artifactId]
 * @param {string} [ctx.expectedTransparencyId]
 * @param {boolean} [ctx.details.temporaryLag]   — true when likely replication lag
 * @returns {object}  gap record
 */
function detectMissingEntry(ctx) {
  return _buildGap(GAP_TYPE.MISSING_TRANSPARENCY_ENTRY, ctx);
}

/**
 * Sequence number continuity is broken (gap in sequential IDs).
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {string} [ctx.artifactId]
 * @param {object} ctx.details  — should include: expectedId, foundId, failureDetail
 * @returns {object}
 */
function detectSequenceBreak(ctx) {
  return _buildGap(GAP_TYPE.SEQUENCE_BREAK, ctx);
}

/**
 * Hash chain continuity is broken (previousEntryHash does not match).
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {string} [ctx.artifactId]
 * @param {object} ctx.details  — should include: failureId, failureDetail, checkedCount
 * @returns {object}
 */
function detectHashChainBreak(ctx) {
  return _buildGap(GAP_TYPE.HASH_CHAIN_BREAK, ctx);
}

/**
 * Transparency append succeeded partially — entry signed but not persisted.
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {string} [ctx.artifactId]
 * @param {string} [ctx.details.transparencyId]   — the signed-but-missing ID
 * @param {boolean} [ctx.details.recentlyQueued]  — true when persistence queue holds it
 * @returns {object}
 */
function detectPartialAppend(ctx) {
  return _buildGap(GAP_TYPE.PARTIAL_APPEND, ctx);
}

/**
 * Artifact exists but has no corresponding transparency record.
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {string} ctx.artifactId
 * @returns {object}
 */
function detectArtifactWithoutTransparency(ctx) {
  return _buildGap(GAP_TYPE.ARTIFACT_WITHOUT_TRANSPARENCY, ctx);
}

/**
 * Transparency record references an artifact that no longer exists.
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {string} [ctx.artifactId]
 * @param {string} [ctx.details.transparencyId]
 * @returns {object}
 */
function detectTransparencyWithoutArtifact(ctx) {
  return _buildGap(GAP_TYPE.TRANSPARENCY_WITHOUT_ARTIFACT, ctx);
}

/**
 * Verification result references transparency evidence that is missing.
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {string} [ctx.artifactId]
 * @param {string} [ctx.details.verificationId]
 * @param {string} [ctx.details.transparencyId]
 * @returns {object}
 */
function detectMissingVerificationEvidence(ctx) {
  return _buildGap(GAP_TYPE.MISSING_VERIFICATION_EVIDENCE, ctx);
}

/**
 * Transparency checkpoint cannot be reconciled with known state.
 *
 * @param {object} ctx
 * @param {string} ctx.service
 * @param {object} ctx.details  — should include: checkpointA, checkpointB
 * @returns {object}
 */
function detectCheckpointDivergence(ctx) {
  return _buildGap(GAP_TYPE.CHECKPOINT_DIVERGENCE, ctx);
}

/**
 * Generic builder — used by index.js when dispatching by type string.
 *
 * @param {string} gapType  — one of GAP_TYPE values
 * @param {object} context
 * @returns {object}
 */
function buildGap(gapType, context) {
  if (!Object.values(GAP_TYPE).includes(gapType)) {
    throw new Error(`detector.buildGap: unknown gapType "${gapType}"`);
  }
  return _buildGap(gapType, context);
}

module.exports = {
  GAP_TYPE,
  buildGap,
  detectMissingEntry,
  detectSequenceBreak,
  detectHashChainBreak,
  detectPartialAppend,
  detectArtifactWithoutTransparency,
  detectTransparencyWithoutArtifact,
  detectMissingVerificationEvidence,
  detectCheckpointDivergence,
};
