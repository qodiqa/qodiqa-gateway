-- QODIQA PostgreSQL Migration 077
-- DB-05 correction pass: the maintenance intent is self-declared.
--
-- Migration 076's guard honours `qodiqa.audit_maintenance` whatever role sets it — and any role can set a custom
-- setting (SET / SET LOCAL / PGOPTIONS). That was harmless for the roles the application connects as only because
-- they hold no UPDATE / DELETE / TRUNCATE grant on the guarded tables: the GRANT, not the trigger, was the control.
-- A single mistaken GRANT to an application-facing role would have turned the declared intent into a bypass.
--
-- After this migration the guard NEVER honours an intent declared by an application-facing role:
--   qodiqa_app        the request path (INSERT-only on these tables by grant, 002 / 076)
--   qodiqa_read       read-only access
--   qodiqa_reporting  reporting access
-- Their UPDATE / DELETE / TRUNCATE is refused by the trigger even if a privilege is ever granted to them by mistake.
--
-- Legitimate maintenance is unchanged: the table owner / qodiqa_mig, the operator-designated prune role
-- (scripts/audit/prune.js, QODIQA_PG_PRUNE_URL), the BYPASSRLS rebuild role (scripts/audit-mirror-rebuild.js) and
-- disposable test fixtures still declare their intent exactly as before (076's TG_ARGV per table).
--
-- What this still is not (stated in SECURITY.md / docs/security/audit-anchoring.md): the table owner can disable the
-- trigger (a logged DDL statement) and any role that legitimately holds the privilege can declare an intent. The guard
-- makes a privileged rewrite declared and logged and an accidental one impossible; operator-independent tamper
-- EVIDENCE remains the witness-co-signed checkpoint anchors.
--
-- Additive only (CREATE OR REPLACE of the 076 function; the 076 triggers keep pointing at it). LIVE `qodiqa` is held at
-- 057 by design decision; this migration is applied only where the chain is applied until 058+ is approved.

BEGIN;

CREATE OR REPLACE FUNCTION qodiqa_audit_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  intent text := NULLIF(current_setting('qodiqa.audit_maintenance', true), '');
BEGIN
  -- 077: application-facing roles can never use a maintenance intent, whatever they declare.
  IF current_user IN ('qodiqa_app', 'qodiqa_read', 'qodiqa_reporting') THEN
    RAISE EXCEPTION '% is append-only: % refused for application role % (DB-05; a maintenance intent is not honoured for application roles)',
      TG_TABLE_NAME, TG_OP, current_user USING ERRCODE = '42501';
  END IF;
  -- TG_ARGV: the maintenance intents this table accepts.
  IF intent IS NOT NULL AND intent = ANY (TG_ARGV) THEN
    RETURN COALESCE(NEW, OLD); -- permitted; logged once per statement by qodiqa_audit_maintenance_log()
  END IF;
  RAISE EXCEPTION '% is append-only: % refused for role % (DB-05; a maintenance operation must SET LOCAL qodiqa.audit_maintenance to one of %)',
    TG_TABLE_NAME, TG_OP, current_user, TG_ARGV USING ERRCODE = '42501';
END
$$;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (77, 'db05_intent_not_for_app_roles', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
