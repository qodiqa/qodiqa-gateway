-- QODIQA PostgreSQL Migration 045
-- BLOCK-02 sub-item (c): templates migration 038's hardcoded
-- `GRANT CONNECT ON DATABASE qodiqa TO qodiqa_retention` so this migration
-- set is portable to any database name, not just the literal "qodiqa" one.
--
-- ROOT CAUSE: 038_retention_dedicated_role.sql:72 hardcodes the literal
-- database name "qodiqa". Every CI workflow in .github/workflows/ pins
-- POSTGRES_DB: qodiqa, so this never surfaced there — but any locally
-- provisioned disposable/uniquely-named database (e.g. scripts/lib/
-- devConsent.js's qodiqa_dev_<hex>, or the qodiqa_wp019_*/qodiqa_acv_test_*
-- pattern documented in this repo's own dev-infra notes) that runs the full
-- migration set against a fresh cluster with no literal "qodiqa" database
-- present would fail this GRANT outright ("database qodiqa does not
-- exist"); on a cluster that happens to ALSO have the real "qodiqa"
-- database (e.g. this dev machine), the GRANT instead silently succeeds
-- against the WRONG database, granting qodiqa_retention nothing on the
-- actual target.
--
-- 038 is already applied everywhere it matters and, per
-- docs/operations/database-role-management.md's own rule, an applied
-- migration's checksummed content is never edited after the fact — the fix
-- is this new, additive migration, using dynamic SQL against
-- current_database() instead of a literal name. On the existing "qodiqa"
-- database this is a harmless idempotent no-op (the grant already exists);
-- on any future disposable database it makes the grant correct for
-- whichever database this migration set is actually applied to.
--
-- Scope note: 002_security_hardening.sql has the identical hardcoded-name
-- pattern for qodiqa_app/qodiqa_read/qodiqa_mig (lines 39, 68, 76) — out of
-- scope here (not named in this item), logged separately as a new finding
-- rather than fixed silently alongside this one.
--
-- IDEMPOTENT: re-granting an already-held privilege is a no-op, consistent
-- with every other grants-fix migration (022, 024, 027, 041).

BEGIN;

DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_retention', current_database());
END
$$;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (45, 'retention_grant_connect_templated', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
