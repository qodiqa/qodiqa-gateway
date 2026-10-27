-- QODIQA PostgreSQL Migration 076
-- DB-05: append-only guards for the audit-adjacent tables.
--
-- Before this migration:
--   policy_history, investigation_audit_events  qodiqa_app held SELECT, INSERT, UPDATE, DELETE (migration 002) and
--                                               no trigger guarded them — an app-role compromise could rewrite or
--                                               erase policy and investigation history silently.
--   audit_chain                                  append-only for qodiqa_app by GRANT only (SELECT, INSERT); every
--                                               role with table privileges or BYPASSRLS (owner, maintenance roles)
--                                               could UPDATE / DELETE / TRUNCATE it with no barrier at all.
--
-- After:
--   1. The app role loses UPDATE / DELETE / TRUNCATE on policy_history and investigation_audit_events (no application
--      code path updates or deletes either table — verified by repository search, 2026-10-04).
--   2. A guard trigger on all three tables refuses UPDATE, DELETE and TRUNCATE for EVERY role, the owner and BYPASSRLS
--      roles included (no role exemption, unlike migration 062's guard) unless the session or transaction states an
--      explicit, allowed maintenance intent:
--          SET LOCAL qodiqa.audit_maintenance = '<intent>';
--      audit_chain prune scripts/audit/prune.js
--                                    rebuild   scripts/audit-mirror-rebuild.js (seq re-numbering)
--                                    fixture   disposable test databases only (tamper simulation, fixture reset)
--      policy_history,
--      investigation_audit_events    erasure   an operator-run data-subject erasure (neither table is an erasure
--                                              target today: no actor_id / subject_id column, migration 063)
--                                    fixture   disposable test databases only
--   Every permitted mutation is raised as a WARNING (server log) naming the table, operation, role and intent.
--
-- What this is and is not: it turns a silent rewrite by a privileged role into one that must be declared (and is
-- logged), and it makes an accidental one impossible. It is NOT a boundary against the table owner, who can disable
-- the trigger (a logged DDL statement). Operator-independent tamper EVIDENCE remains the witness-co-signed checkpoint
-- anchors, which detect any rewrite of audit_chain covered by a checkpoint, guard or no guard.
--
-- Additive only. LIVE `qodiqa` is held at 057 by design decision; this migration is applied only where the chain is
-- applied (disposable/test databases) until 058+ is approved.

BEGIN;

CREATE OR REPLACE FUNCTION qodiqa_audit_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  intent text := NULLIF(current_setting('qodiqa.audit_maintenance', true), '');
BEGIN
  -- TG_ARGV: the maintenance intents this table accepts.
  IF intent IS NOT NULL AND intent = ANY (TG_ARGV) THEN
    RETURN COALESCE(NEW, OLD); -- permitted; logged once per statement by qodiqa_audit_maintenance_log()
  END IF;
  RAISE EXCEPTION '% is append-only: % refused for role % (DB-05; a maintenance operation must SET LOCAL qodiqa.audit_maintenance to one of %)',
    TG_TABLE_NAME, TG_OP, current_user, TG_ARGV USING ERRCODE = '42501';
END
$$;

-- One WARNING per permitted maintenance statement (UPDATE / DELETE / TRUNCATE), after the row guard allowed it.
CREATE OR REPLACE FUNCTION qodiqa_audit_maintenance_log()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE WARNING 'DB-05 audit maintenance: % on % by role % (intent %, txid %)',
    TG_OP, TG_TABLE_NAME, current_user, current_setting('qodiqa.audit_maintenance', true), pg_current_xact_id();
  RETURN NULL;
END
$$;

-- ── 1. app role: append-only by grant ──────────────────────────────────────────
REVOKE UPDATE, DELETE, TRUNCATE ON policy_history FROM qodiqa_app;
REVOKE UPDATE, DELETE, TRUNCATE ON investigation_audit_events FROM qodiqa_app;

-- ── 2. guards: every role ─────────────────────────────────────────────────────
DROP TRIGGER IF EXISTS audit_chain_append_only_guard ON audit_chain;
CREATE TRIGGER audit_chain_append_only_guard
  BEFORE UPDATE OR DELETE ON audit_chain
  FOR EACH ROW EXECUTE FUNCTION qodiqa_audit_append_only_guard('prune', 'rebuild', 'fixture');
DROP TRIGGER IF EXISTS audit_chain_no_truncate ON audit_chain;
CREATE TRIGGER audit_chain_no_truncate
  BEFORE TRUNCATE ON audit_chain
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_append_only_guard('prune', 'rebuild', 'fixture');
DROP TRIGGER IF EXISTS audit_chain_maintenance_log ON audit_chain;
CREATE TRIGGER audit_chain_maintenance_log
  AFTER UPDATE OR DELETE OR TRUNCATE ON audit_chain
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_maintenance_log();

DROP TRIGGER IF EXISTS policy_history_append_only_guard ON policy_history;
CREATE TRIGGER policy_history_append_only_guard
  BEFORE UPDATE OR DELETE ON policy_history
  FOR EACH ROW EXECUTE FUNCTION qodiqa_audit_append_only_guard('erasure', 'fixture');
DROP TRIGGER IF EXISTS policy_history_no_truncate ON policy_history;
CREATE TRIGGER policy_history_no_truncate
  BEFORE TRUNCATE ON policy_history
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_append_only_guard('erasure', 'fixture');
DROP TRIGGER IF EXISTS policy_history_maintenance_log ON policy_history;
CREATE TRIGGER policy_history_maintenance_log
  AFTER UPDATE OR DELETE OR TRUNCATE ON policy_history
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_maintenance_log();

DROP TRIGGER IF EXISTS investigation_audit_events_append_only_guard ON investigation_audit_events;
CREATE TRIGGER investigation_audit_events_append_only_guard
  BEFORE UPDATE OR DELETE ON investigation_audit_events
  FOR EACH ROW EXECUTE FUNCTION qodiqa_audit_append_only_guard('erasure', 'fixture');
DROP TRIGGER IF EXISTS investigation_audit_events_no_truncate ON investigation_audit_events;
CREATE TRIGGER investigation_audit_events_no_truncate
  BEFORE TRUNCATE ON investigation_audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_append_only_guard('erasure', 'fixture');
DROP TRIGGER IF EXISTS investigation_audit_events_maintenance_log ON investigation_audit_events;
CREATE TRIGGER investigation_audit_events_maintenance_log
  AFTER UPDATE OR DELETE OR TRUNCATE ON investigation_audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_maintenance_log();

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (76, 'db05_append_only_guards', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
