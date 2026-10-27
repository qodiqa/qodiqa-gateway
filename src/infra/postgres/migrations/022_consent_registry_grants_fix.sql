-- QODIQA PostgreSQL Migration 022
-- Fixes a gap in migration 007 (consent_registry): it created RLS bypass
-- policies for qodiqa_app on consent_records/consent_audit_log/
-- consent_scopes (see migration 007's "consent_app_bypass" policies), but
-- never granted the underlying table-level privileges those policies
-- depend on. RLS policies only restrict WHICH rows a role already holding
-- base privileges can see/write — without the GRANT below, every
-- POST /consent call fails at the database layer with
-- "permission denied for table consent_records", regardless of any RLS
-- policy. Confirmed via the acceptance test framework (AT-005) against a
-- fresh, fully-migrated Postgres instance.
--
-- IDEMPOTENT: GRANT is itself idempotent (re-granting an already-held
-- privilege is a no-op), consistent with every other migration's grants.

BEGIN;

GRANT SELECT, INSERT, UPDATE ON consent_records TO qodiqa_app;
GRANT SELECT                 ON consent_records TO qodiqa_read;

GRANT SELECT, INSERT ON consent_audit_log TO qodiqa_app;
GRANT SELECT          ON consent_audit_log TO qodiqa_read;
GRANT USAGE, SELECT ON SEQUENCE consent_audit_log_id_seq TO qodiqa_app;

GRANT SELECT ON consent_scopes TO qodiqa_app, qodiqa_read;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (22, 'consent_registry_grants_fix', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
