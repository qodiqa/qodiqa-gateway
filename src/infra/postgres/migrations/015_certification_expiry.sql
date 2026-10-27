-- Migration 015: Certification Expiry (Component #21)
--
-- Adds expires_at and renewal lifecycle fields to the certifications table.
--
-- expires_at: UTC timestamp when the certification expires.
--   NULL for NOT_CERTIFIED decisions and for records predating this migration.
--   Set at issuance to generated_at + CERTIFICATION_VALIDITY_DAYS.
--
-- renewal: renewal eligibility recorded at the time of issuance.
--   ELIGIBLE       — certified decision; renewal permitted within the validity window.
--   NOT_APPLICABLE — NOT_CERTIFIED decision; no validity window applies.
--   NULL           — historical records predating this migration.
--
-- Backward compatibility:
--   Existing rows receive NULL for both columns.
--   The application layer handles NULL gracefully (see certificationStore.js).
--   No backfill is performed — historical records have unknown expiry.

BEGIN;

ALTER TABLE certifications
  ADD COLUMN IF NOT EXISTS expires_at  TIMESTAMPTZ  NULL,
  ADD COLUMN IF NOT EXISTS renewal     VARCHAR(20)  NULL;

ALTER TABLE certifications
  ADD CONSTRAINT cert_renewal_check CHECK (
    renewal IS NULL OR renewal IN ('ELIGIBLE', 'NOT_APPLICABLE')
  );

CREATE INDEX IF NOT EXISTS idx_cert_expires_at
  ON certifications (expires_at)
  WHERE expires_at IS NOT NULL;

COMMENT ON COLUMN certifications.expires_at IS
  'UTC timestamp when this certification expires. '
  'NULL for NOT_CERTIFIED decisions and records predating migration 015. '
  'Computed at issuance as generated_at + CERTIFICATION_VALIDITY_DAYS.';

COMMENT ON COLUMN certifications.renewal IS
  'Renewal eligibility recorded at the time of issuance. '
  'ELIGIBLE: certified decision, renewal is permitted within the validity window. '
  'NOT_APPLICABLE: NOT_CERTIFIED decision, no validity window applies. '
  'NULL: historical record predating migration 015.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (15, 'certification_expiry', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
