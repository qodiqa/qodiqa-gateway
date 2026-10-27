-- Migration 013: Attestation API (Component #24)
--
-- Establishes the attestations table that persists every attestation generated
-- by the Attestation API.  Each row records the full attestation result so
-- attestation history is queryable for compliance, audit, regulatory review,
-- and independent verification purposes.
--
-- Attestation types:
--   ARTIFACT_VERIFICATION  — from POST /v1/attestation/verify
--   EVIDENCE_VERIFICATION  — from POST /v1/attestation/evidence/verify
--   CHAIN_VERIFICATION     — from POST /v1/attestation/chain/verify
--
-- Attestation decisions:
--   ATTESTED               — all core checks pass, no advisory warnings
--   ATTESTED_WITH_WARNINGS — core checks pass, advisory warnings raised
--   NOT_ATTESTED           — one or more core checks failed
--
-- Architecture:
--   attestations — immutable log of attestation generations
--
-- Immutability enforcement:
--   • No UPDATE or DELETE policies (RLS INSERT-only for qodiqa_app).
--   • UNIQUE constraint on attestation_id.
--
-- Integrates with:
--   portal_verifications, evidence_chain_records, transparency_log_entries.
-- RLS: FORCE on all tables; qodiqa_app INSERT + SELECT; qodiqa_read SELECT only.

BEGIN;

-- ── Attestations ──────────────────────────────────────────────────────────────
--
-- Immutable append-only log of every attestation generated.
-- INSERT-only. No UPDATE or DELETE.

CREATE TABLE IF NOT EXISTS attestations (
  id                      BIGSERIAL     PRIMARY KEY,

  -- Stable external identifier
  attestation_id          UUID          NOT NULL DEFAULT gen_random_uuid(),

  -- Attestation type and version
  attestation_type        VARCHAR(50)   NOT NULL DEFAULT 'ARTIFACT_VERIFICATION',
  version                 VARCHAR(10)   NOT NULL DEFAULT '1.0',

  -- Artifact identification (for ARTIFACT_VERIFICATION)
  artifact_fingerprint    CHAR(64)      NULL,
  artifact_public_key_id  VARCHAR(128)  NULL,
  artifact_timestamp_ms   BIGINT        NULL,
  artifact_expiry_ms      BIGINT        NULL,
  artifact_id             VARCHAR(128)  NULL,

  -- Attestation decision
  attestation_decision    VARCHAR(30)   NOT NULL,

  -- Full result payloads (JSONB for rich querying)
  verification_result     JSONB         NOT NULL DEFAULT '{}',
  cryptographic_result    JSONB         NOT NULL DEFAULT '{}',
  compliance_result       JSONB         NOT NULL DEFAULT '{}',
  chain_result            JSONB         NOT NULL DEFAULT '{}',

  -- Individual check details (for ARTIFACT_VERIFICATION)
  checks_performed        JSONB         NOT NULL DEFAULT '[]',
  warnings                JSONB         NOT NULL DEFAULT '[]',
  failed_check            VARCHAR(64)   NULL,
  failure_reason          TEXT          NULL,

  -- Cryptographic anchoring
  transparency_id         UUID          NULL,      -- link to transparency_log_entries
  evidence_package_hash   CHAR(64)      NULL,      -- SHA-256 of evidence package content

  -- Request metadata
  requested_by            VARCHAR(128)  NOT NULL DEFAULT 'external',
  request_ip              VARCHAR(64)   NULL,
  duration_ms             INTEGER       NULL,
  generated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT at_attestation_id_unique UNIQUE (attestation_id),
  CONSTRAINT at_fingerprint_length    CHECK (artifact_fingerprint IS NULL OR LENGTH(artifact_fingerprint) = 64),
  CONSTRAINT at_evpkg_hash_length     CHECK (evidence_package_hash IS NULL OR LENGTH(evidence_package_hash) = 64),
  CONSTRAINT at_decision_check        CHECK (attestation_decision IN (
    'ATTESTED', 'ATTESTED_WITH_WARNINGS', 'NOT_ATTESTED'
  )),
  CONSTRAINT at_type_check            CHECK (attestation_type IN (
    'ARTIFACT_VERIFICATION', 'EVIDENCE_VERIFICATION', 'CHAIN_VERIFICATION'
  ))
);

COMMENT ON TABLE attestations IS
  'Immutable log of every QODIQA attestation generated. '
  'INSERT-only: attestation history must never be modified or deleted. '
  'Each row records the full attestation result for external verification.';

COMMENT ON COLUMN attestations.attestation_decision IS
  'ATTESTED: all core checks passed with no advisory warnings. '
  'ATTESTED_WITH_WARNINGS: crypto checks passed but advisory warnings raised. '
  'NOT_ATTESTED: one or more core validation checks failed.';

COMMENT ON COLUMN attestations.transparency_id IS
  'UUID of the transparency_log_entries row registered for this attestation.';

COMMENT ON COLUMN attestations.evidence_package_hash IS
  'SHA-256 of the stableStringify(content) of the evidence package generated '
  'for this attestation run — enables offline integrity verification.';

-- ── Indexes ───────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_at_attestation_id
  ON attestations (attestation_id);

CREATE INDEX IF NOT EXISTS idx_at_fingerprint
  ON attestations (artifact_fingerprint, generated_at DESC)
  WHERE artifact_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_at_decision
  ON attestations (attestation_decision, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_at_generated_at
  ON attestations (generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_at_artifact_id
  ON attestations (artifact_id, generated_at DESC)
  WHERE artifact_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_at_public_key_id
  ON attestations (artifact_public_key_id, generated_at DESC)
  WHERE artifact_public_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_at_transparency_id
  ON attestations (transparency_id)
  WHERE transparency_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_at_type
  ON attestations (attestation_type, generated_at DESC);

-- ── Row Level Security ────────────────────────────────────────────────────────

ALTER TABLE attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestations FORCE ROW LEVEL SECURITY;

-- SELECT: all authenticated roles
CREATE POLICY at_select
  ON attestations
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

-- INSERT-only (no UPDATE, no DELETE)
CREATE POLICY at_insert
  ON attestations
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT ON attestations TO qodiqa_app;
GRANT SELECT         ON attestations TO qodiqa_read;
GRANT USAGE, SELECT  ON SEQUENCE attestations_id_seq TO qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (13, 'attestation_api', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
