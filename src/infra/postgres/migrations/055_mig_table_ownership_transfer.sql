-- QODIQA PostgreSQL Migration 055
-- transfer ownership of the 12 tables created by migration 001
-- (initial_schema, run before qodiqa_mig exists) to qodiqa_mig.
--
-- ROOT CAUSE (live-reproduced twice on
-- independently-created disposable databases via the exact documented
-- "Fresh-container bootstrap sequencing" procedure, not assumed): migration
-- 002's own GRANT ALL ON ALL TABLES IN SCHEMA public TO qodiqa_mig gives
-- qodiqa_mig full DML privilege (SELECT/INSERT/UPDATE/DELETE/TRUNCATE/
-- REFERENCES/TRIGGER) on the 12 tables migration 001 creates -- confirmed
-- live, qodiqa_mig CAN read/write every one of them via that grant. What the
-- grant does NOT confer is table OWNERSHIP, which PostgreSQL requires
-- independently of any GRANT for structural DDL (ALTER TABLE ADD COLUMN/
-- ADD INDEX/etc.) -- a distinct privilege layer from ordinary DML. Migration
-- 001 necessarily runs before qodiqa_mig exists (created by 002), so its 12
-- tables are owned by whatever bootstrap identity ran migration 001 (varies
-- by deployment -- qodiqa_test locally, a cluster superuser elsewhere, per
-- docs/operations/database-role-management.md's own documented pattern) --
-- never qodiqa_mig, and no later migration has ever transferred that
-- ownership. Two later migrations already in this chain need to ALTER one
-- of these 12 tables' structure and FAIL when run as qodiqa_mig specifically
-- because of this: migration 021 (audit_chain_index_optimization) and
-- migration 039 (audit_chain_provider_model), both against audit_chain --
-- reproduced live: "Migration FAILED: must be owner of table audit_chain"
-- when those two files are run under the documented, intended qodiqa_mig
-- identity, in an otherwise-correct staged bootstrap sequence.
--
-- THE 12 TABLES (migration 001's own CREATE TABLE list, exhaustive):
--   qodiqa_migrations, rbac_users, signing_keys, signing_key_legacy_map,
--   policies, policy_versions, policy_history, audit_chain, investigations,
--   investigation_artifacts, investigation_audit_events, evidence_packages
--
-- WHY THIS MIGRATION NEEDS AN ELEVATED BOOTSTRAP IDENTITY TOO (same class as
-- 002/018/038, not a new problem): ALTER TABLE ... OWNER TO requires the
-- CURRENT connecting role to already own the table (or be a superuser) AND
-- be a member of the target role. qodiqa_mig itself cannot run this
-- migration (it does not yet own these tables -- that is the exact gap
-- being closed). It must run as whatever identity currently owns them --
-- typically the same identity that already had to run migrations 001/002/
-- 018/038 for the identical structural reason. migrate.js's own
-- _wrapRolePrivilegeError() now recognizes this statement shape too (see
-- that function's own updated ROLE_DDL_PATTERN) and gives the same guided
-- "re-run with QODIQA_PG_MIG_USER set to a superuser" diagnostic on failure,
-- instead of a raw, unexplained PostgreSQL error.
--
-- IDEMPOTENT AND SAFE ON EVERY DEPLOYMENT SHAPE:
--   - A deployment where these 12 tables are ALREADY owned by qodiqa_mig
--     (e.g. this machine's own shared `qodiqa` database, where an operator
--     bootstrap step already reassigned ownership outside any migration
--     file -- object ownership is not covered by the migrations-only ROLE
--     policy in docs/operations/database-role-management.md, only role
--     ATTRIBUTES/MEMBERSHIP are) -- ALTER TABLE ... OWNER TO the role it is
--     already owned by is a documented no-op in PostgreSQL, so this
--     migration is safe to apply there too.
--   - A deployment following the exact staged bootstrap sequence for the
--     first time -- this migration is what makes migrations 021/039 (and
--     any future migration that needs to ALTER one of these 12 tables)
--     succeed under the documented qodiqa_mig identity going forward.
--
-- NOT a grant of anything new: no GRANT statement in this file. Ownership
-- transfer does not touch RLS (RLS policies are independent of ownership --
-- FORCE ROW LEVEL SECURITY already applies to audit_chain's owner
-- specifically because it forces RLS even for the owner, migration 002),
-- does not touch BYPASSRLS, does not touch any other role's privileges.

BEGIN;

ALTER TABLE qodiqa_migrations         OWNER TO qodiqa_mig;
ALTER TABLE rbac_users                OWNER TO qodiqa_mig;
ALTER TABLE signing_keys              OWNER TO qodiqa_mig;
ALTER TABLE signing_key_legacy_map    OWNER TO qodiqa_mig;
ALTER TABLE policies                  OWNER TO qodiqa_mig;
ALTER TABLE policy_versions           OWNER TO qodiqa_mig;
ALTER TABLE policy_history            OWNER TO qodiqa_mig;
ALTER TABLE audit_chain               OWNER TO qodiqa_mig;
ALTER TABLE investigations            OWNER TO qodiqa_mig;
ALTER TABLE investigation_artifacts   OWNER TO qodiqa_mig;
ALTER TABLE investigation_audit_events OWNER TO qodiqa_mig;
ALTER TABLE evidence_packages         OWNER TO qodiqa_mig;

COMMENT ON TABLE audit_chain IS
  'Cryptographic audit chain ledger. FORCE ROW LEVEL SECURITY applies even to the table owner. '
  ': ownership transferred to qodiqa_mig -- migration 001 (which creates this '
  'table) necessarily runs before qodiqa_mig exists (created by migration 002), so ownership defaulted '
  'to that bootstrap identity; later migrations (021, 039) that ALTER this table''s structure require '
  'true ownership, not merely the DML grant migration 002 already provides.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (55, 'rem063_mig_table_ownership_transfer', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
