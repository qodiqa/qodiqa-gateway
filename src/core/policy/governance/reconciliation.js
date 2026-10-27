'use strict';

/**
 * Governance Publish Reconciliation —
 *
 * ROOT CAUSE (see docs/guides/policy-governance.md's documented known
 * limitation, and PolicyGovernanceService.js's own header): the file-based
 * live policy store (policies.json, src/core/policy/store.js) is written by
 * publish()/RollbackGovernanceService/EmergencyPolicyService AFTER their
 * Postgres governance-workflow transaction has already committed — the file
 * write is not, and structurally cannot be, transactional with that commit.
 * A file write that fails, or a file hand-edited outside the governance
 * workflow, therefore leaves the file and the Postgres governance ledger
 * (policy_change_requests/policy_publications) silently diverged, with
 * nothing detecting it.
 *
 * WHAT THIS MODULE DOES: compares the live file-based policy repository
 * against policy_change_requests/policy_publications (and, for full-content
 * hash comparison, policy_provenance_versions — see "WHY
 * policy_provenance_versions" below) once at startup, classifies any
 * divergence found, and emits a structured event for each one plus one
 * summary event. It is STRICTLY a verification/alerting mechanism:
 *   - It NEVER writes to policies.json, policy_change_requests,
 *     policy_publications, or any other table — every query here is a
 *     read-only SELECT.
 *   - It NEVER blocks startup or calls process.exit() — unlike
 *     mirrorConsistencyCheck.js (the audit-chain equivalent this module is
 *     structurally modeled on), a governance divergence is drift requiring
 *     operator attention, not evidence the platform is unsafe to serve
 *     traffic. Findings are emitted through the normal services/logger
 *     emit() path (not the raw-stderr FATAL path multiInstanceGuard-style
 * checks use) precisely so they reach the alerting pipeline
 *     (src/alerting) and get paged like any other CRITICAL/HIGH finding.
 *   - It is deterministic: the same file/database state always produces the
 *     same findings.
 *
 * WHY policy_provenance_versions FOR HASH COMPARISON, NOT
 * policy_publications.policy_hash DIRECTLY:
 *   policy_publications.policy_hash is governanceEvents.hashPayload(payload)
 *   — a hash of the SUBMITTED CHANGE-REQUEST PAYLOAD (the delta, e.g. just
 *   `{config: {...}}` for an UPDATE, or `{toVersion}` for a ROLLBACK), using
 *   a distinct hash domain (ARTIFACT_DOMAINS.POLICY_GOVERNANCE). It is not a
 *   hash of the resulting full policy object, so it cannot be compared
 *   directly against the current file content.
 *   policy_provenance_versions.policy_hash (migration 009), by contrast, is
 *   `SHA-256(canonical JSON of policy_content)` — policy_content there IS the
 *   full resulting policy snapshot at that version, written by every publish
 *   path (publish()/RollbackGovernanceService/EmergencyPolicyService) via
 *   provenanceBridge.js's fire-and-forget recordPolicyProvenance() call at
 *   the same publish event. Recomputing provenance.computePolicyHash() over
 *   the file's current snapshot and comparing it to this table's value is
 *   therefore a genuine apples-to-apples full-content comparison.
 *
 * DIVERGENCE TAXONOMY (DIVERGENCE_TYPE below) matches's required set
 * exactly: MISSING_PUBLICATION, MISSING_FILE, HASH_MISMATCH,
 * VERSION_MISMATCH, PUBLICATION_STATE_INCONSISTENT.
 */

const pool        = require('../../../infra/postgres/pool');
const policyStore = require('../store');
const provenance  = require('../provenance');
const { emit }    = require('../../../../services/logger');

const DIVERGENCE_TYPE = Object.freeze({
  MISSING_PUBLICATION:            'MISSING_PUBLICATION',
  MISSING_FILE:                   'MISSING_FILE',
  HASH_MISMATCH:                  'HASH_MISMATCH',
  VERSION_MISMATCH:               'VERSION_MISMATCH',
  PUBLICATION_STATE_INCONSISTENT: 'PUBLICATION_STATE_INCONSISTENT',
});

// Finds, per policy_id, the most recently PUBLISHED change request and its
// publication row (if any — a NULL publication_id here is itself the
// MISSING_PUBLICATION case). LEFT JOIN so a published change request with no
// matching publication row is still returned, not silently dropped.
const _LATEST_PUBLISHED_PER_POLICY_SQL = `
  SELECT DISTINCT ON (cr.policy_id)
    cr.id                        AS change_request_id,
    cr.policy_id                 AS policy_id,
    pp.id                        AS publication_id,
    pp.resulting_policy_version  AS pub_resulting_version,
    pp.policy_hash               AS pub_policy_hash,
    pp.published_at              AS published_at
  FROM policy_change_requests cr
  LEFT JOIN policy_publications pp ON pp.change_request_id = cr.id
  WHERE cr.status = 'PUBLISHED'
  ORDER BY cr.policy_id, pp.published_at DESC NULLS LAST
`;

// Publication rows whose change request is not (or no longer) PUBLISHED —
// a structural inconsistency; publish() writes both inside one transaction,
// so this should never happen absent data corruption or manual tampering.
const _ORPHANED_PUBLICATIONS_SQL = `
  SELECT pp.id AS publication_id, pp.change_request_id, pp.policy_id, cr.status AS cr_status
  FROM policy_publications pp
  JOIN policy_change_requests cr ON cr.id = pp.change_request_id
  WHERE cr.status != 'PUBLISHED'
`;

// More than one publication row for the same change request — the FK
// relationship allows this (no UNIQUE constraint on change_request_id), but
// the workflow should produce exactly one publication per change request.
const _DUPLICATE_PUBLICATIONS_SQL = `
  SELECT change_request_id, count(*) AS publication_count
  FROM policy_publications
  GROUP BY change_request_id
  HAVING count(*) > 1
`;

function _findVersionSnapshot(fileRecord, versionNumber) {
  return (fileRecord.versions || []).find(v => v.v === versionNumber) ?? null;
}

/**
 * Compares the file-based policy repository against the Postgres governance
 * ledger. Read-only; never mutates anything. Must be called after
 * pgPool.initialize() and after policies.json has been loaded.
 *
 * All dependencies are injectable for testing.
 *
 * @param {object}   [opts]
 * @param {object}   [opts._pool]         PG pool module (default: src/infra/postgres/pool.js)
 * @param {object}   [opts._policyStore]  policy store module (default: src/core/policy/store.js)
 * @param {object}   [opts._provenance]   provenance module (default: src/core/policy/provenance.js)
 * @param {function} [opts._emit]         Logger emit function (default: services/logger emit)
 * @param {function} [opts._now]          Clock function returning ms since epoch (default: Date.now)
 * @returns {Promise<{ outcome: string, mismatches: number, policiesScanned: number, publicationsScanned: number }>}
 */
async function reconcile({
  _pool        = pool,
  _policyStore = policyStore,
  _provenance  = provenance,
  _emit        = emit,
  _now         = () => Date.now(),
} = {}) {
  if (!_pool.isEnabled()) {
    _emit('INFO', 'GOVERNANCE_RECONCILIATION_SKIPPED', {
      reason: 'QODIQA_PG_ENABLED is not "true" — no governance ledger to reconcile the file store against.',
    });
    return { outcome: 'SKIPPED', mismatches: 0, policiesScanned: 0, publicationsScanned: 0 };
  }

  const startedAt = _now();
  const findings = [];

  try {
    const [latestPublished, orphanedPublications, duplicatePublications, publicationCountRes] = await Promise.all([
      _pool.query(_LATEST_PUBLISHED_PER_POLICY_SQL, [], 'governance_reconcile_latest_published'),
      _pool.query(_ORPHANED_PUBLICATIONS_SQL, [], 'governance_reconcile_orphaned_publications'),
      _pool.query(_DUPLICATE_PUBLICATIONS_SQL, [], 'governance_reconcile_duplicate_publications'),
      _pool.query('SELECT count(*) AS total FROM policy_publications', [], 'governance_reconcile_publication_count'),
    ]);

    for (const row of orphanedPublications.rows) {
      findings.push({
        divergenceType: DIVERGENCE_TYPE.PUBLICATION_STATE_INCONSISTENT,
        policyId:       row.policy_id,
        publicationId:  row.publication_id,
        version:        null,
        expectedHash:   null,
        actualHash:     null,
        detail:         `publication ${row.publication_id} references change request ${row.change_request_id} in status ${row.cr_status}, not PUBLISHED`,
      });
    }

    for (const row of duplicatePublications.rows) {
      findings.push({
        divergenceType: DIVERGENCE_TYPE.PUBLICATION_STATE_INCONSISTENT,
        policyId:       null,
        publicationId:  null,
        version:        null,
        expectedHash:   null,
        actualHash:     null,
        detail:         `change request ${row.change_request_id} has ${row.publication_count} publication rows, expected at most 1`,
      });
    }

    for (const row of latestPublished.rows) {
      const fileRecord = _policyStore.getPolicy(row.policy_id);

      if (!fileRecord) {
        findings.push({
          divergenceType: DIVERGENCE_TYPE.MISSING_FILE,
          policyId:       row.policy_id,
          publicationId:  row.publication_id,
          version:        row.pub_resulting_version,
          expectedHash:   row.pub_policy_hash,
          actualHash:     null,
          detail:         `policy_id ${row.policy_id} is PUBLISHED in the governance ledger but absent from policies.json`,
        });
        continue;
      }

      if (row.publication_id === null) {
        findings.push({
          divergenceType: DIVERGENCE_TYPE.MISSING_PUBLICATION,
          policyId:       row.policy_id,
          publicationId:  null,
          version:        fileRecord.currentVersion,
          expectedHash:   null,
          actualHash:     null,
          detail:         `change request ${row.change_request_id} is PUBLISHED but has no matching policy_publications row`,
        });
        continue;
      }

      if (fileRecord.currentVersion !== row.pub_resulting_version) {
        findings.push({
          divergenceType: DIVERGENCE_TYPE.VERSION_MISMATCH,
          policyId:       row.policy_id,
          publicationId:  row.publication_id,
          version:        row.pub_resulting_version,
          expectedHash:   null,
          actualHash:     null,
          detail:         `file currentVersion=${fileRecord.currentVersion}, latest publication resulting_policy_version=${row.pub_resulting_version}`,
        });
      }

      const provenanceRes = await _pool.query(
        `SELECT policy_hash FROM policy_provenance_versions WHERE policy_id = $1 AND version_number = $2`,
        [row.policy_id, row.pub_resulting_version],
        'governance_reconcile_provenance_lookup',
      );

      if (provenanceRes.rows.length === 0) {
        findings.push({
          divergenceType: DIVERGENCE_TYPE.PUBLICATION_STATE_INCONSISTENT,
          policyId:       row.policy_id,
          publicationId:  row.publication_id,
          version:        row.pub_resulting_version,
          expectedHash:   null,
          actualHash:     null,
          detail:         `no policy_provenance_versions row for policy_id=${row.policy_id} version=${row.pub_resulting_version} — provenanceBridge write may have failed`,
        });
        continue;
      }

      const snapshot = _findVersionSnapshot(fileRecord, fileRecord.currentVersion);
      if (snapshot) {
        const fileHash = _provenance.computePolicyHash(snapshot.snapshot ?? snapshot);
        const expectedHash = provenanceRes.rows[0].policy_hash;
        if (fileHash !== expectedHash) {
          findings.push({
            divergenceType: DIVERGENCE_TYPE.HASH_MISMATCH,
            policyId:       row.policy_id,
            publicationId:  row.publication_id,
            version:        row.pub_resulting_version,
            expectedHash,
            actualHash:     fileHash,
            detail:         `SHA-256(file snapshot at version ${fileRecord.currentVersion}) does not match policy_provenance_versions.policy_hash`,
          });
        }
      }
    }

    for (const finding of findings) {
      _emit('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED', {
        ...finding,
        timestamp: new Date(_now()).toISOString(),
        reconciliationResult: 'DIVERGENCE_DETECTED',
      });
    }

    const durationMs = _now() - startedAt;
    const summary = {
      policiesScanned:      latestPublished.rows.length,
      publicationsScanned:  Number(publicationCountRes.rows[0]?.total ?? 0),
      mismatches:           findings.length,
      durationMs,
      outcome:              findings.length === 0 ? 'CLEAN' : 'DIVERGENCE_DETECTED',
    };
    _emit('INFO', 'GOVERNANCE_RECONCILIATION_COMPLETE', summary);

    return summary;
  } catch (err) {
    _emit('ERROR', 'GOVERNANCE_RECONCILIATION_FAILED', {
      error:     err.message,
      durationMs: _now() - startedAt,
    });
    return { outcome: 'FAILED', mismatches: 0, policiesScanned: 0, publicationsScanned: 0, error: err.message };
  }
}

module.exports = { reconcile, DIVERGENCE_TYPE };
