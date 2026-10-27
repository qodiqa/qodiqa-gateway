-- Migration 012: Public Verification Portal (Component #23)
--
-- Establishes the portal_verifications table that persists every artifact
-- verification run submitted to the Public Verification Portal.  Each row
-- records the full check suite result so verification history is queryable
-- for compliance, audit, and replay-detection purposes.
--
-- Architecture:
--   portal_verifications — immutable log of verification runs
--
-- Fingerprint chain:
--   artifact_fingerprint = SHA-256(stableStringify(artifact))
--   Used for replay detection within the portal: if the same fingerprint
--   appears more than once, the second submission returns VERIFIED_WITH_WARNINGS.
--
-- Immutability enforcement:
--   • No UPDATE or DELETE policies (RLS INSERT-only for qodiqa_app).
--   • UNIQUE constraint on verification_id.
--
-- Integrates with: transparency_log_entries, evidence_chain_records.
-- RLS: FORCE on all tables; qodiqa_app INSERT + SELECT; qodiqa_read SELECT only.

BEGIN;

-- ── Portal Verifications ──────────────────────────────────────────────────────
--
-- Immutable append-only log of every portal verification run.
-- INSERT-only. No UPDATE or DELETE.

CREATE TABLE IF NOT EXISTS portal_verifications (
  id                      BIGSERIAL     PRIMARY KEY,

  -- Stable external identifier
  verification_id         UUID          NOT NULL DEFAULT gen_random_uuid(),

  -- Artifact fingerprint for replay detection (SHA-256 of canonical artifact JSON)
  artifact_fingerprint    CHAR(64)      NOT NULL,

  -- Extracted artifact fields for indexing and querying
  artifact_public_key_id  VARCHAR(128)  NULL,
  artifact_timestamp_ms   BIGINT        NULL,
  artifact_expiry_ms      BIGINT        NULL,
  artifact_id             VARCHAR(128)  NULL,    -- payload.artifactId if present

  -- Verification outcome
  overall_result          VARCHAR(32)   NOT NULL,  -- VERIFIED, VERIFIED_WITH_WARNINGS, FAILED

  -- Individual check results (ordered JSON array: [{check, result, reason?}])
  checks_performed        JSONB         NOT NULL DEFAULT '[]',

  -- First failure (for quick query and indexing)
  failed_check            VARCHAR(64)   NULL,
  failure_reason          TEXT          NULL,

  -- Warnings (JSON array: [{check, reason}])
  warnings                JSONB         NOT NULL DEFAULT '[]',

  -- Link to transparency log entry for this verification run
  transparency_id         UUID          NULL,

  -- Submission metadata
  submitted_by            VARCHAR(128)  NOT NULL DEFAULT 'public',
  submission_ip           VARCHAR(64)   NULL,
  duration_ms             INTEGER       NULL,
  verified_at             TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT pv_verification_id_unique UNIQUE (verification_id),
  CONSTRAINT pv_fingerprint_length     CHECK (LENGTH(artifact_fingerprint) = 64),
  CONSTRAINT pv_result_check           CHECK (overall_result IN (
    'VERIFIED', 'VERIFIED_WITH_WARNINGS', 'FAILED'
  ))
);

COMMENT ON TABLE portal_verifications IS
  'Immutable log of every Public Verification Portal submission. '
  'INSERT-only: verification history must never be modified or deleted. '
  'artifact_fingerprint enables replay detection across submissions.';

COMMENT ON COLUMN portal_verifications.artifact_fingerprint IS
  'SHA-256 of stableStringify(artifact). '
  'If the same fingerprint appears more than once, the result is VERIFIED_WITH_WARNINGS.';

COMMENT ON COLUMN portal_verifications.overall_result IS
  'VERIFIED: all checks passed with no warnings. '
  'VERIFIED_WITH_WARNINGS: crypto checks passed but advisory warnings raised. '
  'FAILED: one or more core validation checks failed.';

COMMENT ON COLUMN portal_verifications.transparency_id IS
  'UUID of the transparency_log_entries row registered for this verification run.';

-- ── Indexes ───────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_pv_verification_id
  ON portal_verifications (verification_id);

CREATE INDEX IF NOT EXISTS idx_pv_fingerprint
  ON portal_verifications (artifact_fingerprint, verified_at DESC);

CREATE INDEX IF NOT EXISTS idx_pv_overall_result
  ON portal_verifications (overall_result, verified_at DESC);

CREATE INDEX IF NOT EXISTS idx_pv_verified_at
  ON portal_verifications (verified_at DESC);

CREATE INDEX IF NOT EXISTS idx_pv_artifact_id
  ON portal_verifications (artifact_id, verified_at DESC)
  WHERE artifact_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pv_public_key_id
  ON portal_verifications (artifact_public_key_id, verified_at DESC)
  WHERE artifact_public_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pv_failed_check
  ON portal_verifications (failed_check, verified_at DESC)
  WHERE failed_check IS NOT NULL;

-- ── Row Level Security ────────────────────────────────────────────────────────

ALTER TABLE portal_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_verifications FORCE ROW LEVEL SECURITY;

-- SELECT: all authenticated roles
CREATE POLICY pv_select
  ON portal_verifications
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

-- INSERT-only (no UPDATE, no DELETE)
CREATE POLICY pv_insert
  ON portal_verifications
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT ON portal_verifications TO qodiqa_app;
GRANT SELECT         ON portal_verifications TO qodiqa_read;
GRANT USAGE, SELECT  ON SEQUENCE portal_verifications_id_seq TO qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (12, 'verification_portal', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
