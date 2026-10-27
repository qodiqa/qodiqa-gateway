-- Migration 017: Certificate Artifacts — Component #29
--
-- Persistent storage for QODIQA Signed Certificate Artifacts.
--
-- A certificate artifact is a cryptographically signed, self-contained JSON
-- bundle issued for every successful CERTIFIED decision.  It is the canonical
-- evidence artifact proving that a certification was completed.
--
-- Design properties:
--   • One certificate per certification (UNIQUE on certification_id).
--   • Immutable after issuance — no UPDATE or DELETE on certificate_artifacts.
--   • Full signed bundle stored as JSONB for queryability and download.
--   • key_id records which key was used — required for post-rotation verification.
--   • RLS: qodiqa_app INSERT + SELECT; qodiqa_read SELECT; no UPDATE, no DELETE.

BEGIN;

-- ── Certificate Artifacts ─────────────────────────────────────────────────────
--
-- Each row is the complete signed certificate bundle for one certification.
-- INSERT-only: certificates are immutable evidence artifacts.

CREATE TABLE IF NOT EXISTS certificate_artifacts (
  id                BIGSERIAL     PRIMARY KEY,

  -- Stable external identifiers
  certificate_id    UUID          NOT NULL DEFAULT gen_random_uuid(),
  certification_id  UUID          NOT NULL,

  -- Signed bundle (full JSON: certificate payload + signature metadata)
  bundle            JSONB         NOT NULL,

  -- Indexed signing metadata (also present inside bundle, duplicated for queries)
  key_id            VARCHAR(128)  NOT NULL,
  artifact_version  SMALLINT      NOT NULL DEFAULT 1,
  issued_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  CONSTRAINT ca_cert_id_unique    UNIQUE (certificate_id),
  CONSTRAINT ca_certif_id_unique  UNIQUE (certification_id),
  CONSTRAINT ca_key_id_nonempty   CHECK (key_id <> ''),
  CONSTRAINT ca_version_positive  CHECK (artifact_version > 0)
);

COMMENT ON TABLE certificate_artifacts IS
  'Immutable log of signed QODIQA Certificate Artifacts. '
  'INSERT-only: one certificate per certification decision. '
  'Full signed bundle stored for download and offline verification.';

COMMENT ON COLUMN certificate_artifacts.bundle IS
  'Complete signed certificate bundle: { version, certificate, signature, keyId, '
  'signingAlgorithm, signedAt, domain }.  Self-contained for offline verification.';

COMMENT ON COLUMN certificate_artifacts.certification_id IS
  'Foreign reference to the certifications.certification_id. '
  'UNIQUE ensures exactly one certificate is issued per certification.';

-- ── Indexes ───────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_ca_certificate_id
  ON certificate_artifacts (certificate_id);

CREATE INDEX IF NOT EXISTS idx_ca_certification_id
  ON certificate_artifacts (certification_id);

CREATE INDEX IF NOT EXISTS idx_ca_key_id
  ON certificate_artifacts (key_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_ca_issued_at
  ON certificate_artifacts (issued_at DESC);

-- ── Row Level Security ────────────────────────────────────────────────────────

ALTER TABLE certificate_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_artifacts FORCE ROW LEVEL SECURITY;

-- INSERT-only for qodiqa_app (no UPDATE, no DELETE)
CREATE POLICY ca_select ON certificate_artifacts
  FOR SELECT TO qodiqa_app, qodiqa_read USING (true);

CREATE POLICY ca_insert ON certificate_artifacts
  FOR INSERT TO qodiqa_app WITH CHECK (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT ON certificate_artifacts TO qodiqa_app;
GRANT SELECT         ON certificate_artifacts TO qodiqa_read;
GRANT USAGE, SELECT  ON SEQUENCE certificate_artifacts_id_seq TO qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (17, 'certificate_artifacts', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
