-- 082: narrow qodiqa_definer's table-wide UPDATE on audit_chain.
--
-- Migration 079 granted `UPDATE ON TABLE audit_chain TO qodiqa_definer` for ONE reason: qodiqa_audit_chain_mirror_count_rebuild() takes
-- `LOCK TABLE audit_chain IN SHARE ROW EXCLUSIVE MODE`, and on PostgreSQL < 17 that lock mode requires UPDATE/DELETE/TRUNCATE on the table.
-- The grant therefore gave the definer owner a data-modifying privilege on the audit chain that it never uses (the append-only trigger
-- from 076 is all that held it back). PostgreSQL 17 added the MAINTAIN privilege, which authorises LOCK TABLE in every mode without
-- authorising any row modification. On PostgreSQL >= 17 this migration swaps the grant:
--     GRANT MAINTAIN, REVOKE UPDATE.
-- On PostgreSQL < 17 there is no narrower privilege that allows that lock, so the grant stays (documented limit; the 076 trigger still
-- blocks UPDATE) and this migration is a no-op. Additive and idempotent.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_definer') THEN
    RAISE NOTICE '082: role qodiqa_definer does not exist; nothing to narrow';
  ELSIF current_setting('server_version_num')::int >= 170000 THEN
    EXECUTE 'GRANT MAINTAIN ON TABLE audit_chain TO qodiqa_definer';
    EXECUTE 'REVOKE UPDATE ON TABLE audit_chain FROM qodiqa_definer';
  ELSE
    RAISE NOTICE '082: PostgreSQL % < 17 has no MAINTAIN privilege; qodiqa_definer keeps UPDATE on audit_chain (append-only trigger 076 still applies)',
      current_setting('server_version');
  END IF;
END
$$;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (82, 'audit_definer_audit_chain_lock_privilege', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;
