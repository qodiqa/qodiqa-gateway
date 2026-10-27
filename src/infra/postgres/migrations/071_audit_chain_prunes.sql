-- QODIQA PostgreSQL Migration 071
-- step 6, design decisions M3/M4: the record of every retention prune.
--
--   audit_chain_prunes   one APPEND-ONLY row per prune performed by the operator command (scripts/audit/prune.js — the
--                        only path that removes audit history; nothing schedules it, no running service writes here):
--                        the signed checkpoint the prune stopped at, the removed range, the rows deleted per table,
--                        the SHA-256 of the verified archive's manifest, and the full base record written next to
--                        audit.log (<audit.log>.base.json: the signed checkpoint + prefix statistics).
--                        Owner M3: the base record must be in BOTH backup paths — the DR JSON path copies the file;
--                        pg_dump (pg-backup.sh) carries it through this table (with the signed checkpoint in
--                        audit_signed_checkpoints, migration 070).
--
-- Writes: the table owner only (the operator command's connection). qodiqa_read, qodiqa_app, qodiqa_reporting:
-- SELECT. qodiqa_backup: SELECT
-- (migration 067's default privileges). UPDATE / DELETE / TRUNCATE refused by the guard for every role that does not
-- bypass RLS.

BEGIN;

CREATE TABLE IF NOT EXISTS audit_chain_prunes (
  prune_id                   UUID          PRIMARY KEY,
  checkpoint_id              UUID          NOT NULL REFERENCES audit_signed_checkpoints (checkpoint_id),
  from_count                 BIGINT        NOT NULL CHECK (from_count >= 0),
  to_count                   BIGINT        NOT NULL CHECK (to_count > from_count),
  audit_rows_deleted         BIGINT        NOT NULL DEFAULT 0,
  evidence_rows_deleted      BIGINT        NOT NULL DEFAULT 0,
  transparency_rows_deleted  BIGINT        NOT NULL DEFAULT 0,
  archive_manifest_sha256    CHAR(64)      NOT NULL,
  archive_location           TEXT,
  base_record                JSONB         NOT NULL,
  pruned_at                  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  pruned_by                  VARCHAR(64)   NOT NULL
);

GRANT SELECT ON audit_chain_prunes TO qodiqa_read;
-- the evidence verifiers read the latest prune's base (where the kept evidence chain
-- starts) — qodiqa_app (chainStore, evidenceCollector) and qodiqa_reporting (the evidence full-read path). Read only.
GRANT SELECT ON audit_chain_prunes TO qodiqa_app, qodiqa_reporting;

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_prunes_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolbypassrls OR rolsuper)) THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  RAISE EXCEPTION 'audit_chain_prunes is append-only (% refused for %)', TG_OP, current_user USING ERRCODE = '42501';
END
$$;

DROP TRIGGER IF EXISTS audit_chain_prunes_append_only_guard ON audit_chain_prunes;
CREATE TRIGGER audit_chain_prunes_append_only_guard
  BEFORE UPDATE OR DELETE ON audit_chain_prunes
  FOR EACH ROW EXECUTE FUNCTION qodiqa_audit_chain_prunes_append_only_guard();
DROP TRIGGER IF EXISTS audit_chain_prunes_no_truncate ON audit_chain_prunes;
CREATE TRIGGER audit_chain_prunes_no_truncate
  BEFORE TRUNCATE ON audit_chain_prunes
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_chain_prunes_append_only_guard();

COMMENT ON TABLE audit_chain_prunes IS
  'one append-only row per operator-run retention prune — signed checkpoint, removed range, rows deleted, archive manifest SHA-256 and the base record (so pg_dump carries it). Written only by scripts/audit/prune.js as the table owner.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (71, 'w10_audit_chain_prunes', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
