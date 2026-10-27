-- QODIQA PostgreSQL Migration 064
-- lawful basis and purpose on consent.
--
-- Before: no consent table, schema, route or SDK carried a purpose or a lawful
-- basis. After, on consent_records:
--   lawful_basis                one of the six GDPR Art. 6(1) bases
--   purpose                     1–500 characters
--   purpose_code                optional machine grouping, ^[a-z0-9_.-]{1,64}$
--   special_category_condition  the GDPR Art. 9(2)(a)–(j) condition, as art9_2_a … art9_2_j;
--                               the API requires it when the grant's scope is special-category
--   lawful_basis_status         SPECIFIED | LEGACY_UNSPECIFIED
--
-- Existing rows become LEGACY_UNSPECIFIED with lawful_basis NULL — never
-- auto-labelled 'consent'. POST /consent requires basis + purpose from now on;
-- store-level grants that supply none (dev bootstrap, internal callers) are
-- recorded honestly as LEGACY_UNSPECIFIED. A CHECK keeps status and fields
-- consistent. None of these columns is in record_hash (unchanged).
--
-- consent_scopes gains special_category (Art. 9(1)); the two seeded scopes that
-- ARE Art. 9(1) categories by definition — biometric (biometric data for unique
-- identification) and medical (data concerning health) — are marked.
--
-- IDENTITY: table owner (qodiqa_mig (055); qodiqa_test on disposable DBs).

BEGIN;

ALTER TABLE consent_records
  ADD COLUMN IF NOT EXISTS lawful_basis               VARCHAR(32),
  ADD COLUMN IF NOT EXISTS purpose                    VARCHAR(500),
  ADD COLUMN IF NOT EXISTS purpose_code               VARCHAR(64),
  ADD COLUMN IF NOT EXISTS special_category_condition VARCHAR(16),
  ADD COLUMN IF NOT EXISTS lawful_basis_status        VARCHAR(32) NOT NULL DEFAULT 'LEGACY_UNSPECIFIED';

ALTER TABLE consent_records DROP CONSTRAINT IF EXISTS consent_records_lawful_basis_check;
ALTER TABLE consent_records ADD CONSTRAINT consent_records_lawful_basis_check CHECK (
  lawful_basis IS NULL OR lawful_basis IN
    ('consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests'));

ALTER TABLE consent_records DROP CONSTRAINT IF EXISTS consent_records_purpose_check;
ALTER TABLE consent_records ADD CONSTRAINT consent_records_purpose_check CHECK (
  purpose IS NULL OR char_length(btrim(purpose)) BETWEEN 1 AND 500);

ALTER TABLE consent_records DROP CONSTRAINT IF EXISTS consent_records_purpose_code_check;
ALTER TABLE consent_records ADD CONSTRAINT consent_records_purpose_code_check CHECK (
  purpose_code IS NULL OR purpose_code ~ '^[a-z0-9_.-]{1,64}$');

ALTER TABLE consent_records DROP CONSTRAINT IF EXISTS consent_records_special_category_condition_check;
ALTER TABLE consent_records ADD CONSTRAINT consent_records_special_category_condition_check CHECK (
  special_category_condition IS NULL OR special_category_condition IN
    ('art9_2_a', 'art9_2_b', 'art9_2_c', 'art9_2_d', 'art9_2_e',
     'art9_2_f', 'art9_2_g', 'art9_2_h', 'art9_2_i', 'art9_2_j'));

ALTER TABLE consent_records DROP CONSTRAINT IF EXISTS consent_records_lawful_basis_status_check;
ALTER TABLE consent_records ADD CONSTRAINT consent_records_lawful_basis_status_check CHECK (
     (lawful_basis_status = 'SPECIFIED'          AND lawful_basis IS NOT NULL AND purpose IS NOT NULL)
  OR (lawful_basis_status = 'LEGACY_UNSPECIFIED' AND lawful_basis IS NULL));

COMMENT ON COLUMN consent_records.lawful_basis IS 'GDPR Art. 6(1) lawful basis. NULL only for LEGACY_UNSPECIFIED rows.';
COMMENT ON COLUMN consent_records.special_category_condition IS 'GDPR Art. 9(2) condition art9_2_a … art9_2_j; required by the API for special-category scopes.';
COMMENT ON COLUMN consent_records.lawful_basis_status IS 'SPECIFIED, or LEGACY_UNSPECIFIED for rows created / without a stated basis — never auto-labelled.';

ALTER TABLE consent_scopes ADD COLUMN IF NOT EXISTS special_category BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE consent_scopes SET special_category = TRUE WHERE scope_name IN ('biometric', 'medical');
COMMENT ON COLUMN consent_scopes.special_category IS 'GDPR Art. 9(1) special category of personal data: a grant needs special_category_condition.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (64, 'w5_consent_lawful_basis', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
