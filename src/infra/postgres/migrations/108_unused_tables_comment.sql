-- QODIQA PostgreSQL Schema -- Migration 108
-- Marks nine tables that no application code, script or SECURITY DEFINER function reads or writes as reserved.
-- COMMENT ON TABLE only: no table, column, grant, policy or row changes, and nothing is dropped.
-- Idempotent: COMMENT ON replaces the previous comment. A table that is absent, or one the migration role does not own, is skipped with a NOTICE
-- (a comment must never be the reason the migration chain stops).
-- The list is pinned by src/infra/postgres/__tests__/migration108.test.js.

BEGIN;

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'compliance_frameworks',
    'compliance_report_exports',
    'evidence_packages',
    'kms_encrypted_data_keys',
    'kms_provider_events',
    'kms_wrapping_key_rotations',
    'qodiqa_alert_stats',
    'qodiqa_anomaly_baselines',
    'revocation_events'
  ] LOOP
    IF to_regclass('public.' || t) IS NULL THEN
      RAISE NOTICE 'migration 108: table % not present, skipped', t;
      CONTINUE;
    END IF;
    BEGIN
      EXECUTE format('COMMENT ON TABLE public.%I IS %L', t, 'reserved: not used by the application');
    EXCEPTION WHEN insufficient_privilege THEN
      RAISE NOTICE 'migration 108: not the owner of %, comment skipped', t;
    END;
  END LOOP;
END
$$;

COMMIT;
