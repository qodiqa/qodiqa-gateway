-- Migration 010: Immutable Evidence Chain (Component #21)
--
-- Establishes the cryptographic evidence chain that binds every artifact to the
-- exact policy, signing key, and audit record that governed its execution.
--
-- Every row in evidence_chain_records is generated automatically when an audit
-- chain entry is persisted.  No row is ever manually inserted, updated, or deleted.
--
-- Hash chain design:
--   evidence_hash = SHA-256(canonical JSON of { evidenceId, artifactId, artifactHash,
--                            policyId, policyHash, keyId, keyFingerprint,
--                            auditRecordId, auditRecordHash, previousEvidenceHash })
--   Chain: v(n).previousEvidenceHash === v(n-1).evidence_hash
--
-- Immutability enforcement:
--   • No UPDATE or DELETE policies created (RLS INSERT-only).
--   • UNIQUE constraint on evidence_hash prevents collision reuse.
--   • UNIQUE constraint on artifact_id enforces one record per artifact.
--
-- Integrates with: audit_chain, policies, signing_keys, policy_provenance_versions.
-- RLS: FORCE on all tables; qodiqa_app INSERT + SELECT; qodiqa_read SELECT only.

BEGIN;

-- ── Evidence Chain Records ─────────────────────────────────────────────────────
--
-- Immutable append-only ledger. One row per executed artifact.
-- INSERT-only. No UPDATE or DELETE.

CREATE TABLE IF NOT EXISTS evidence_chain_records (
  id                      BIGSERIAL      PRIMARY KEY,

  -- Unique evidence identifier (used as external stable reference)
  evidence_id             UUID           NOT NULL DEFAULT gen_random_uuid(),

  -- Artifact link
  artifact_id             VARCHAR(128)   NOT NULL,
  artifact_hash           VARCHAR(128)   NOT NULL,   -- entry.inputHash; 'UNAVAILABLE' for early BLOCKs

  -- Policy link (full policy set hash from audit entry)
  policy_id               VARCHAR(256)   NOT NULL DEFAULT 'POLICY_SET',
  policy_version          INTEGER        NULL,        -- populated via provenance lookup when available
  policy_hash             VARCHAR(128)   NOT NULL,   -- entry.policyHash; 'UNAVAILABLE' if unknown

  -- Signing key link
  key_id                  VARCHAR(128)   NULL,        -- entry.executionContext.publicKeyId
  key_version             INTEGER        NULL,
  key_fingerprint         VARCHAR(128)   NULL,        -- SHA-256 of public key DER

  -- Audit chain link
  audit_record_id         VARCHAR(64)    NOT NULL,   -- audit_chain.hash (the SHA-256 chain hash)
  audit_record_hash       CHAR(64)       NOT NULL,   -- SHA-256 of the full serialised audit entry

  -- Evidence chain links
  previous_evidence_hash  VARCHAR(64)    NULL,        -- NULL for the first record in the chain
  evidence_hash           CHAR(64)       NOT NULL,   -- SHA-256 of the canonical evidence record

  -- Metadata
  decision                VARCHAR(8)     NOT NULL,   -- ALLOW or BLOCK (from audit entry)
  tenant_id               VARCHAR(128)   NULL,
  created_at              TIMESTAMPTZ    NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT ecr_evidence_id_unique    UNIQUE (evidence_id),
  CONSTRAINT ecr_artifact_id_unique    UNIQUE (artifact_id),
  CONSTRAINT ecr_evidence_hash_unique  UNIQUE (evidence_hash),
  CONSTRAINT ecr_audit_id_unique       UNIQUE (audit_record_id),
  CONSTRAINT ecr_decision_check        CHECK  (decision IN ('ALLOW', 'BLOCK')),
  CONSTRAINT ecr_audit_hash_length     CHECK  (LENGTH(audit_record_hash) = 64),
  CONSTRAINT ecr_evidence_hash_length  CHECK  (LENGTH(evidence_hash) = 64)
);

COMMENT ON TABLE evidence_chain_records IS
  'Immutable cryptographic evidence chain. One row per executed artifact. '
  'Binds artifact → policy → signing key → audit record. '
  'No UPDATE or DELETE permitted at any layer. '
  'evidence_hash chain enables end-to-end tamper detection.';

COMMENT ON COLUMN evidence_chain_records.artifact_hash IS
  'SHA-256 of the artifact content at execution time (entry.inputHash from audit chain). '
  '''UNAVAILABLE'' for early-stage BLOCKs before artifact parsing.';

COMMENT ON COLUMN evidence_chain_records.key_fingerprint IS
  'SHA-256 of the raw public key DER bytes. Enables key substitution detection.';

COMMENT ON COLUMN evidence_chain_records.audit_record_id IS
  'The SHA-256 chain hash from audit_chain.hash. Used as the unique audit record identifier.';

COMMENT ON COLUMN evidence_chain_records.audit_record_hash IS
  'SHA-256 of the complete serialised audit entry. '
  'Detects any modification to any field in the audit record.';

COMMENT ON COLUMN evidence_chain_records.evidence_hash IS
  'SHA-256 of the canonical evidence record fields. '
  'Chain: evidence_n.previous_evidence_hash === evidence_{n-1}.evidence_hash.';

-- ── Indexes ────────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_ecr_artifact_id
  ON evidence_chain_records (artifact_id);

CREATE INDEX IF NOT EXISTS idx_ecr_policy_hash
  ON evidence_chain_records (policy_hash, created_at DESC)
  WHERE policy_hash != 'UNAVAILABLE';

CREATE INDEX IF NOT EXISTS idx_ecr_key_id
  ON evidence_chain_records (key_id, created_at DESC)
  WHERE key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ecr_audit_record_id
  ON evidence_chain_records (audit_record_id);

CREATE INDEX IF NOT EXISTS idx_ecr_created_at
  ON evidence_chain_records (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ecr_decision
  ON evidence_chain_records (decision, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ecr_tenant
  ON evidence_chain_records (tenant_id, created_at DESC)
  WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ecr_prev_hash
  ON evidence_chain_records (previous_evidence_hash)
  WHERE previous_evidence_hash IS NOT NULL;

-- ── Evidence Chain Verification Runs ──────────────────────────────────────────
--
-- Stores every verification run result.
-- Immutable — INSERT-only.

CREATE TABLE IF NOT EXISTS evidence_chain_verifications (
  id                   BIGSERIAL     PRIMARY KEY,
  evidence_id          UUID          NOT NULL,
  verification_time    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  verification_result  VARCHAR(16)   NOT NULL,   -- VALID, INVALID, PARTIAL, ERROR
  failed_step          VARCHAR(64)   NULL,
  failure_reason       TEXT          NULL,
  verified_by          VARCHAR(128)  NOT NULL DEFAULT 'system',
  steps_passed         JSONB         NOT NULL DEFAULT '[]',
  steps_failed         JSONB         NOT NULL DEFAULT '[]',
  duration_ms          INTEGER       NULL,

  CONSTRAINT ecv_result_check CHECK (verification_result IN ('VALID', 'INVALID', 'PARTIAL', 'ERROR'))
);

CREATE INDEX IF NOT EXISTS idx_ecv_evidence_id
  ON evidence_chain_verifications (evidence_id, verification_time DESC);

CREATE INDEX IF NOT EXISTS idx_ecv_result
  ON evidence_chain_verifications (verification_result, verification_time DESC);

CREATE INDEX IF NOT EXISTS idx_ecv_time
  ON evidence_chain_verifications (verification_time DESC);

COMMENT ON TABLE evidence_chain_verifications IS
  'Immutable log of every evidence chain verification run. '
  'INSERT-only: verification history must never be modified or deleted.';

-- ── Row Level Security ─────────────────────────────────────────────────────────

ALTER TABLE evidence_chain_records      ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_chain_verifications ENABLE ROW LEVEL SECURITY;

ALTER TABLE evidence_chain_records      FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_chain_verifications FORCE ROW LEVEL SECURITY;

-- SELECT: all authenticated roles
CREATE POLICY ecr_select
  ON evidence_chain_records
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

CREATE POLICY ecv_select
  ON evidence_chain_verifications
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

-- INSERT-only (no UPDATE, no DELETE)
CREATE POLICY ecr_insert
  ON evidence_chain_records
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

CREATE POLICY ecv_insert
  ON evidence_chain_verifications
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT ON evidence_chain_records       TO qodiqa_app;
GRANT SELECT         ON evidence_chain_records       TO qodiqa_read;
GRANT SELECT, INSERT ON evidence_chain_verifications TO qodiqa_app;
GRANT SELECT         ON evidence_chain_verifications TO qodiqa_read;

GRANT USAGE, SELECT ON SEQUENCE evidence_chain_records_id_seq       TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE evidence_chain_verifications_id_seq TO qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (10, 'evidence_chain', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
