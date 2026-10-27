-- QODIQA PostgreSQL Migration 041
-- Grants qodiqa_app the least-privilege access it actually needs on the
-- alerting subsystem's 6 tables, closing a superuser-masked privilege gap
-- discovered while diagnosing a move away from running the main app pool
-- as the Postgres superuser.
--
-- ROOT CAUSE:
-- Migration 006 created qodiqa_alerts, qodiqa_alert_history, qodiqa_incidents,
-- qodiqa_escalation_records, qodiqa_notification_deliveries, and
-- qodiqa_suppression_rules with ROW LEVEL SECURITY enabled, and migration 018
-- later added FORCE ROW LEVEL SECURITY plus correctly-scoped, per-command RLS
-- policies for qodiqa_app on every one of them (qa_tenant_select,
-- qa_system_insert, qa_tenant_update, etc.). Neither migration — nor any
-- migration since — ever issued the underlying base GRANT (INSERT/SELECT/
-- UPDATE) on these tables to qodiqa_app. PostgreSQL requires BOTH a base
-- privilege AND a passing RLS policy for the same command; the RLS half was
-- ready, the GRANT half never arrived. This was invisible because the main
-- app pool (src/infra/postgres/pool.js) has been running as the Postgres
-- superuser in every environment that hit this table set, which bypasses
-- privilege checks entirely — src/alerting/storage/AlertStore.js (the only
-- application code touching these tables) has been silently relying on
-- superuser access for every alert/escalation/notification write.
--
-- LEAST PRIVILEGE — grants below are scoped to exactly the commands
-- AlertStore.js actually issues today (grepped directly from source), not
-- the broader set the pre-existing RLS policies would technically permit:
--
--   qodiqa_alerts                  INSERT, SELECT, UPDATE
--     (created, read, and mutated in place — status/incident_id updates)
--   qodiqa_alert_history           INSERT, SELECT
--   qodiqa_incidents               INSERT
--     (a qi_tenant_select/qi_tenant_update policy already exists for
--      possible future use, but nothing in current code reads or updates
--      this table — not granted, since nothing needs it yet)
--   qodiqa_escalation_records      INSERT
--   qodiqa_notification_deliveries INSERT
--   qodiqa_suppression_rules       SELECT, UPDATE
--     (rules are read and their suppressed_count incremented; nothing in
--      current code creates or removes a rule via the app pool, despite an
--      INSERT/DELETE policy already existing for both — not granted)
--
-- No mismatch between "code issues UPDATE" and "table should be append-only"
-- was found: qodiqa_alerts/qodiqa_suppression_rules are intentionally
-- mutable state tables, not logs, and the four INSERT-only tables show zero
-- UPDATE/DELETE anywhere in application code, consistent with their
-- append-only design.
--
-- SEQUENCES:
-- qodiqa_alert_history, qodiqa_notification_deliveries, and
-- qodiqa_escalation_records use BIGSERIAL primary keys (qodiqa_alerts,
-- qodiqa_incidents, and qodiqa_suppression_rules use UUID PKs and need no
-- sequence grant). INSERT into a BIGSERIAL column requires USAGE on its
-- backing sequence or the insert fails at the DEFAULT nextval() step even
-- with table-level INSERT granted.
--
-- IDEMPOTENT: GRANT is naturally re-runnable (re-granting an already-held
-- privilege is a no-op), consistent with every other grants-fix migration
-- (022, 024, 027).

BEGIN;

GRANT INSERT, SELECT, UPDATE ON qodiqa_alerts                  TO qodiqa_app;
GRANT INSERT, SELECT         ON qodiqa_alert_history            TO qodiqa_app;
GRANT INSERT                 ON qodiqa_incidents                TO qodiqa_app;
GRANT INSERT                 ON qodiqa_escalation_records       TO qodiqa_app;
GRANT INSERT                 ON qodiqa_notification_deliveries  TO qodiqa_app;
GRANT SELECT, UPDATE         ON qodiqa_suppression_rules        TO qodiqa_app;

GRANT USAGE ON SEQUENCE qodiqa_alert_history_id_seq           TO qodiqa_app;
GRANT USAGE ON SEQUENCE qodiqa_notification_deliveries_id_seq TO qodiqa_app;
GRANT USAGE ON SEQUENCE qodiqa_escalation_records_id_seq      TO qodiqa_app;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (41, 'alerting_qodiqa_app_grants', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
