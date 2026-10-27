-- QODIQA PostgreSQL Schema — Migration 002
-- Purpose: Service account creation, row-level privileges, and security hardening.
--
-- This migration runs as a superuser (DBA role).
-- The QODIQA application connects as a restricted service account.
--
-- THREE service accounts follow the principle of least privilege:
--   qodiqa_app    — INSERT + SELECT on most tables; NO UPDATE/DELETE on audit_chain
--   qodiqa_read   — SELECT only (for read replicas, dashboards, Grafana)
--   qodiqa_mig    — DDL rights for running future migrations (not used by app at runtime)
--
-- NOTE: Replace '<STRONG_PASSWORD_HERE>' with vault-generated secrets in deployment.
--       Never commit actual passwords to source control.
--
-- the three GRANT CONNECT statements below used to
-- hardcode the literal database name "qodiqa" instead of current_database().
-- Confirmed live via a genuine fresh-clone docs/guides/quickstart.md validation: on a
-- cluster with no database literally named "qodiqa" (e.g. `npm run dev`
-- Path A's own advertised isolated, uniquely-named per-boot database —
-- scripts/lib/devConsent.js's generatedDevDbName), the first GRANT CONNECT
-- throws "database qodiqa does not exist", and because this entire migration
-- is one BEGIN/COMMIT transaction, the failure rolls back the CREATE ROLE
-- statements above too — the migration cannot partially apply, and no later
-- migration (see migration 045's own now-superseded attempt to patch the
-- identical bug in migration 038 this same way) can ever run to compensate,
-- since migrate.js aborts the whole run on the first failing migration.
-- Fixed here directly, an exception to this repo's normal "never edit an
-- applied migration" rule — see docs/operations/database-role-management.md
-- for
-- the full justification (checksum drift-detection already a no-op; edit is
-- behavior-identical for every deployment where the database is already
-- named "qodiqa", which is every real deployment today).

BEGIN;

-- ── Create roles (idempotent) ─────────────────────────────────────────────────

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_app') THEN
        CREATE ROLE qodiqa_app LOGIN PASSWORD 'REPLACE_WITH_VAULT_SECRET_APP';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_read') THEN
        CREATE ROLE qodiqa_read LOGIN PASSWORD 'REPLACE_WITH_VAULT_SECRET_READ';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'qodiqa_mig') THEN
        CREATE ROLE qodiqa_mig LOGIN PASSWORD 'REPLACE_WITH_VAULT_SECRET_MIG';
    END IF;
END
$$;

-- ── qodiqa_app permissions ────────────────────────────────────────────────────
-- Application service account: INSERT + SELECT everywhere except:
--   - audit_chain: INSERT + SELECT only (no UPDATE/DELETE ever)
--   - signing_keys: SELECT only for key lookup; INSERT for provisioning;
--                   UPDATE allowed for rotation/revocation (status field only)

DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_app', current_database()); END $$;
GRANT USAGE ON SCHEMA public TO qodiqa_app;

-- Tables where the app needs full CRUD
GRANT SELECT, INSERT, UPDATE, DELETE ON rbac_users          TO qodiqa_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON policies            TO qodiqa_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON policy_versions     TO qodiqa_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON policy_history      TO qodiqa_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON investigations      TO qodiqa_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON investigation_artifacts TO qodiqa_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON investigation_audit_events TO qodiqa_app;
GRANT SELECT, INSERT                 ON evidence_packages    TO qodiqa_app;
GRANT SELECT, INSERT                 ON qodiqa_migrations    TO qodiqa_app;
GRANT SELECT, INSERT                 ON signing_key_legacy_map TO qodiqa_app;

-- Signing keys: INSERT for provisioning, UPDATE for rotation/revocation only
-- Private key material is purged (set to NULL) on revocation via UPDATE
GRANT SELECT, INSERT, UPDATE ON signing_keys TO qodiqa_app;

-- CRITICAL: audit_chain is append-only — application can INSERT and SELECT only
-- UPDATE and DELETE are explicitly NOT granted
GRANT SELECT, INSERT ON audit_chain TO qodiqa_app;

-- Sequences
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO qodiqa_app;

-- ── qodiqa_read permissions ───────────────────────────────────────────────────
-- Read-only account for dashboards, Grafana, read replicas, on-call queries

DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_read', current_database()); END $$;
GRANT USAGE ON SCHEMA public TO qodiqa_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO qodiqa_read;

-- ── qodiqa_mig permissions ────────────────────────────────────────────────────
-- Migration account: DDL rights for schema changes only
-- Used by CI/CD pipeline, NOT by the running application

DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO qodiqa_mig', current_database()); END $$;
GRANT CREATE, USAGE ON SCHEMA public TO qodiqa_mig;
GRANT ALL ON ALL TABLES IN SCHEMA public TO qodiqa_mig;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO qodiqa_mig;

-- ── Row-level security on audit_chain ────────────────────────────────────────
-- Belt-and-suspenders: even if a role is misconfigured, RLS prevents modification

ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain FORCE ROW LEVEL SECURITY;

-- Policy: any role can SELECT
CREATE POLICY audit_chain_select ON audit_chain FOR SELECT USING (TRUE);

-- Policy: only qodiqa_app can INSERT
CREATE POLICY audit_chain_insert ON audit_chain FOR INSERT
    WITH CHECK (current_user = 'qodiqa_app');

-- No UPDATE or DELETE policies defined → those operations are implicitly forbidden

-- ── Revoke dangerous defaults ─────────────────────────────────────────────────
-- Revoke PUBLIC schema CREATE privilege (PostgreSQL 14 default grants this)

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- ── Record migration ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (2, 'security_hardening', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
