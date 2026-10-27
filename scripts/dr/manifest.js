'use strict';

/**
 * Backup manifest — build and verify.
 *
 * The manifest is the single, self-describing record of what a backup
 * contains: every component's presence, source path, checksum, and size,
 * plus timestamp/app/protocol version metadata (Requirement 1: "backup
 * metadata / timestamp / version / protocol version / application version").
 *
 * manifestChecksum seals the manifest itself (via the project's own
 * canonical-JSON serializer, src/utils/stableStringify.js — the same
 * serializer used for audit/evidence/policy hashing, so manifest sealing
 * uses no new, unaudited serialization logic) so that restore can detect a
 * tampered or corrupted manifest before trusting ANY per-file checksum in it.
 */

const crypto          = require('crypto');
const stableStringify  = require('../../src/utils/stableStringify');

const MANIFEST_VERSION  = 1;
// QODIQA-PROTOCOL-SPEC.md §19.1 — "`v1`: Current."
const PROTOCOL_VERSION  = 'v1';

function computeManifestChecksum(manifestWithoutChecksum) {
  return crypto.createHash('sha256')
    .update(stableStringify(manifestWithoutChecksum), 'utf8')
    .digest('hex');
}

/**
 * @param {object} opts
 * @param {string} opts.backupId
 * @param {string} opts.createdAt        ISO-8601
 * @param {string} opts.appVersion       from package.json
 * @param {object[]} opts.components
 * @param {object|null} [opts.postgres]
 * @param {object|null} [opts.redis]
 * @param {string} [opts.auditOrderingMode] — 'single-node' or 'distributed'
 *the audit-chain ordering mode THIS BACKUP was taken under, per
 *   src/infra/config/deploymentMode.js's getResolvedDeploymentConfig() at
 *   backup time — the ground truth for which source (the local auditLog
 *   file, or PostgreSQL's audit_chain table) is authoritative for
 *   THIS backup's audit evidence. Recorded here, at backup time, rather than
 *   re-derived from whatever environment happens to run restore later
 *   (which may be a different host/process entirely) — restore must trust
 *   what the backup actually was, not guess it. Defaults to 'single-node'
 *   only for full backward compatibility with manifests produced before
 *   this field existed; every backup taken by the current backup.js always
 *   sets it explicitly.
 * @param {object|null} [opts.encryption] — archiveCrypto.encryptionManifestField() for an encrypted backup
 * @returns {object} sealed manifest (includes manifestChecksum)
 */
// controlPlaneBackend — 'pg' or 'memory', resolved at backup time like auditOrderingMode; decides
// whether the legacy JSON seed files are required and whether policies are validated in PostgreSQL. Recorded only when
// set, so manifests built without it keep their previous shape (restore reads absence as 'memory').
function buildManifest({ backupId, createdAt, appVersion, components, postgres, redis, auditOrderingMode, encryption, controlPlaneBackend }) {
  const base = {
    manifestVersion: MANIFEST_VERSION,
    protocolVersion: PROTOCOL_VERSION,
    backupId,
    createdAt,
    appVersion,
    nodeVersion: process.version,
    components,
    postgres: postgres || null,
    redis:    redis    || null,
    auditOrderingMode: auditOrderingMode === 'distributed' ? 'distributed' : 'single-node',
  };
  // present only for an encrypted backup (scheme + seal description, never key material) — a plaintext
  // backup's manifest keeps exactly its previous shape.
  if (encryption) base.encryption = encryption;
  if (controlPlaneBackend) base.controlPlaneBackend = controlPlaneBackend === 'pg' ? 'pg' : 'memory';
  return { ...base, manifestChecksum: computeManifestChecksum(base) };
}

/**
 * @param {object} manifest
 * @returns {boolean} true iff the stored manifestChecksum matches a fresh recomputation
 */
function verifyManifestChecksum(manifest) {
  if (!manifest || typeof manifest !== 'object') return false;
  const { manifestChecksum, ...rest } = manifest;
  if (typeof manifestChecksum !== 'string' || manifestChecksum.length !== 64) return false;
  return computeManifestChecksum(rest) === manifestChecksum;
}

module.exports = {
  buildManifest,
  verifyManifestChecksum,
  computeManifestChecksum,
  MANIFEST_VERSION,
  PROTOCOL_VERSION,
};
