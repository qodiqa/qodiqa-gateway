'use strict';

/**
 * QODIQA Disaster Recovery — seed a live-like data set for cycle validation.
 *
 * Used by CI (and available to operators for local drills) to produce a
 * realistic set of persistent state — an active signing key, several audit
 * chain entries, and a stored policy — so that `dr:cycle` has something
 * substantive to back up, restore, and validate. When a Postgres connection
 * is available it inserts one representative audit_chain row (it does NOT run migrations — the target database must already be
 * migrated; audit 2026-10-20), so the postgres.js dump -> restore -> row-count path is
 * exercised with real content rather than empty tables.
 *
 * This writes to the file locations resolved by scripts/dr/components.js
 * (i.e. honours QODIQA_AUDIT_LOG / QODIQA_KEYS_PATH / QODIQA_POLICY_STORE
 * etc.), so CI points those env vars at a scratch directory and never touches
 * a real deployment's data.
 *
 * IMPORTANT: src/core/policy/store.js's createPolicy() also persists to
 * POLICY_FILE (a separate, legacy-format mirror of the same policy data,
 * unrelated to scripts/dr/components.js's own resolution). CI/drill
 * invocations MUST also set POLICY_FILE to a scratch path, or the seeded
 * policy below is written into the real repository-root policies.json.
 */

const crypto = require('crypto');

async function seed() {
  const auditLog     = require('../../src/core/audit/audit-log.js');
  // INJ-3/#283: policy/policyStore.js was dead code (zero production
  // callers) — src/core/policy/store.js is the module actually mounted in
  // the request path, so DR seeding now exercises the same one production
  // traffic does.
  const policyStore  = require('../../src/core/policy/store.js');
  const keyStore      = require('../../services/artifact/keyStore.js');

  // Active signing key (encrypted at rest with the test/CI KEK).
  keyStore.rotateKey('default');

  // Audit chain entries — real appends through the production module, so the
  // hash chain + WAL + checksum companion files are all produced authentically.
  const appended = [];
  for (let i = 0; i < 5; i++) {
    const entry = await auditLog.append({
      artifactId: crypto.randomUUID(),
      inputHash:  crypto.randomBytes(32).toString('hex'),
      decision:   i % 2 === 0 ? 'ALLOW' : 'BLOCK',
      signature:  i % 2 === 0 ? crypto.randomBytes(64).toString('base64') : 'UNAVAILABLE',
      requestHash: crypto.randomBytes(32).toString('hex'),
      policyHash:  crypto.randomBytes(32).toString('hex'),
      verificationResult: i % 2 === 0,
      // v7 (R-5): a v7 ALLOW must state its delivered-output hash; these synthetic entries deliver nothing.
      outputHash: require('../../src/core/audit/entryBuilder').EMPTY_OUTPUT_HASH,
    });
    appended.push(entry);
  }

  // Stored policy — REQUIRE_CONSENT is the one mandatory policy type every
  // real policy set must include (src/core/policy/store.js's own schema),
  // so this doubles as a realistic minimum-viable seed.
  await policyStore.createPolicy({
    id:       'dr-seed-policy',
    type:     'REQUIRE_CONSENT',
    priority: 10,
    config:   { requireValidArtifact: true },
    actor:    'dr-seed',
    comment:  'DR cycle seed policy',
  });
  // the policy store no longer writes a file at runtime. The DR
  // cycle's file component is the dev/test seed file, so hand the seeded
  // state to it explicitly (memory mode only; PostgreSQL mode is covered by
  // the PostgreSQL backup).
  if (!require('../../src/core/controlPlane').isPg()) policyStore.exportSeedFixture();

  const result = {
    keyId: keyStore.getActiveKey('default').keyId,
    auditEntries: auditLog.getChainLength(),
    policies: policyStore.listPolicies({ status: 'ACTIVE', pageSize: Number.MAX_SAFE_INTEGER }).total,
    postgres: null,
  };

  // Optional Postgres seed. Beyond the audit_chain row (kept for backward
  // compatibility with existing checks), this also seeds one representative
  // row in each of the data categories called out by name as excluded
  // from backup coverage — consent, investigations, compliance reports — so
  // the pg dump/restore path is exercised against real content in exactly
  // those categories, not just audit_chain.
  if (process.env.QODIQA_PG_URL || process.env.DATABASE_URL) {
    const crypto = require('crypto');
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: process.env.QODIQA_PG_URL || process.env.DATABASE_URL });
    try {
      const e = appended[0];
      // (design §9/§11): per-field columns through the reversible projection P, marker 1 — as insertMirrorRow()
      const m = require('../../src/infra/postgres/mirrorProjection').projectEntryForMirror(e);
      // every column pg-audit-backend.js insertMirrorRow() writes.
      // This used to insert 12 — no schema_version, so the column DEFAULT 1 applied and the
      // seeded (v6) row could never re-verify (it was checked under the 9-field v1 set).
      await pool.query(
        `INSERT INTO audit_chain
           (hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time,
            input_hash, signature, request_hash, policy_hash, verification_result,
            nonce, tenant_id, execution_context, public_key_id, schema_version,
            consent_provenance, policy_decision, caller_context, provider, model,
            stage, reason, semantic, token_usage, response_id,
            entry_type, output_hash, request_id, organization_id, executing_provider, mirror_encoding)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)
         ON CONFLICT (hash) DO NOTHING`,
        [
          e.hash, e.prevHash, e.canonical, m.artifactId, m.decision,
          e.timestamp, m.highResTime, m.inputHash, m.signature,
          m.requestHash, m.policyHash, e.verificationResult,
          m.nonce ?? null, m.tenantId ?? null, m.executionContext ? JSON.stringify(m.executionContext) : null,
          m.publicKeyId ?? null, e.schemaVersion ?? 1,
          m.consentProvenance != null ? JSON.stringify(m.consentProvenance) : null,
          m.policyDecision != null ? JSON.stringify(m.policyDecision) : null,
          m.callerContext != null ? JSON.stringify(m.callerContext) : null,
          m.provider ?? null, m.model ?? null, m.stage ?? null, m.reason ?? null,
          m.semantic != null ? JSON.stringify(m.semantic) : null,
          m.tokenUsage != null ? JSON.stringify(m.tokenUsage) : null,
          m.responseId ?? null,
          // audit schema v7 (migration 075) — the seeded entry is v7
          m.entryType ?? null, m.outputHash ?? null, m.requestId ?? null, m.organizationId ?? null, m.executingProvider ?? null,
          1,   // (R-F2): mirror_encoding — projected row
        ],
      );
      const { rows } = await pool.query('SELECT COUNT(*)::int AS c FROM audit_chain');

      const suffix = crypto.randomBytes(4).toString('hex');

      const consent = await pool.query(
        `INSERT INTO consent_records (actor_id, action, state, granted_by)
         VALUES ($1, 'inference', 'ACTIVE', 'dr-seed')
         RETURNING id`,
        [`actor-dr-seed-${suffix}`],
      );
      await pool.query(
        `INSERT INTO consent_audit_log (consent_id, event_type, actor, actor_id, action, verification_result)
         VALUES ($1, 'GRANTED', 'dr-seed', $2, 'inference', 'VERIFIED')`,
        [consent.rows[0].id, `actor-dr-seed-${suffix}`],
      );

      const investigationId = 'INV-' + crypto.randomBytes(8).toString('hex').toUpperCase();
      await pool.query(
        `INSERT INTO investigations (id, title, investigator) VALUES ($1, $2, 'dr-seed')`,
        [investigationId, 'DR seed investigation'],
      );
      await pool.query(
        `INSERT INTO investigation_artifacts (investigation_id, artifact_id) VALUES ($1, $2)`,
        [investigationId, `artifact-dr-seed-${suffix}`],
      );

      const report = await pool.query(
        `INSERT INTO compliance_reports
           (report_ref, framework_id, framework_name, title, period_start, period_end, generated_by, status)
         VALUES ($1, 'GDPR', 'General Data Protection Regulation', 'DR seed compliance report',
                 NOW() - interval '30 days', NOW(), 'dr-seed', 'COMPLETE')
         RETURNING id`,
        [`RPT-DR-SEED-${suffix}`],
      );

      result.postgres = {
        auditChainRows: rows[0].c,
        consentId: consent.rows[0].id,
        investigationId,
        complianceReportId: report.rows[0].id,
      };
    } finally {
      await pool.end();
    }
  }

  return result;
}

module.exports = { seed };

if (require.main === module) {
  seed()
    .then(r => console.log(JSON.stringify({ event: 'DR_SEED_COMPLETE', ...r }, null, 2)))
    .catch(err => { console.error(JSON.stringify({ event: 'DR_SEED_FAILED', error: err.message })); process.exitCode = 1; });
}
