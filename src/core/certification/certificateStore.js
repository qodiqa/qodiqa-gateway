'use strict';

/**
 * Certificate Artifact Store — Component #29
 *
 * PostgreSQL persistence for signed certificate artifacts.
 *
 * WRITE PATH: storeCertificate(bundle)
 *   INSERT with ON CONFLICT DO NOTHING — idempotent, never overwrites.
 *   The UNIQUE constraint on certification_id ensures one certificate per
 *   certification decision.
 *
 * READ PATH:  getByCertificateId(), getByCertificationId()
 *
 * All reads return null when PG is disabled.
 * Certificates are immutable — no UPDATE or DELETE is ever issued.
 */

const pgPool  = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');

// ── Write path ────────────────────────────────────────────────────────────────

/**
 * Persist a signed certificate bundle.
 *
 * ON CONFLICT DO NOTHING: if a certificate was already stored for this
 * certificationId (e.g. from a prior attempt), the re-insert is a no-op.
 * Returns the stored row, or null if PG is disabled.
 *
 * @param {object} bundle  Full signed bundle from issueCertificateArtifact()
 * @returns {Promise<object|null>}
 */
async function storeCertificate(bundle) {
  if (!pgPool.isEnabled()) return null;

  const { certificate, keyId } = bundle;
  const { certificateId, certificationId, artifactVersion } = certificate;

  try {
    const result = await pgPool.query(
      `INSERT INTO certificate_artifacts
         (certificate_id, certification_id, bundle, key_id, artifact_version)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (certification_id) DO NOTHING
       RETURNING *`,
      [
        certificateId,
        certificationId,
        JSON.stringify(bundle),
        keyId,
        artifactVersion,
      ],
    );

    const row = result.rows[0] ?? null;

    emit('INFO', 'CERTIFICATE_ARTIFACT_STORED', {
      certificateId,
      certificationId,
      keyId,
      stored: row !== null,
    });

    return row;
  } catch (err) {
    emit('ERROR', 'CERTIFICATE_ARTIFACT_STORE_FAILED', {
      certificateId,
      certificationId,
      error: err.message,
    });
    throw err;
  }
}

// ── Read paths ────────────────────────────────────────────────────────────────

/**
 * Retrieve a certificate artifact by its own certificate_id.
 *
 * @param {string} certificateId  UUID
 * @returns {Promise<object|null>}
 */
async function getByCertificateId(certificateId) {
  if (!pgPool.isEnabled()) return null;
  const result = await pgPool.query(
    `SELECT * FROM certificate_artifacts WHERE certificate_id = $1 LIMIT 1`,
    [certificateId],
  );
  return result.rows[0] ?? null;
}

/**
 * Retrieve a certificate artifact by its associated certification_id.
 *
 * @param {string} certificationId  UUID
 * @returns {Promise<object|null>}
 */
async function getByCertificationId(certificationId) {
  if (!pgPool.isEnabled()) return null;
  const result = await pgPool.query(
    `SELECT * FROM certificate_artifacts WHERE certification_id = $1 LIMIT 1`,
    [certificationId],
  );
  return result.rows[0] ?? null;
}

module.exports = {
  storeCertificate,
  getByCertificateId,
  getByCertificationId,
};
