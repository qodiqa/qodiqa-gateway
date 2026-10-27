-- QODIQA PostgreSQL Migration 074
-- S3: persisted progress of the
-- layered file ↔ PG divergence verifier, which replaces the 15-minute full-chain comparison.
--
--   audit_chain_verification_progress   one row per kind:
--     'incremental'  the 60 s new-row layer's position — the next file position to compare (pos + its byte offset in
--                    audit.log) and the last verified entry (prev_hash) / PG row (pg_seq)
--     'sweep'        the rolling re-verification cursor over the verified prefix (20,000 rows per 15 min), same shape,
--                    plus its cycle counters
--   base_checkpoint_id = the signed prune base the position belongs to (NULL = unpruned chain); a different base
--   invalidates the position.
--
-- Derived, verifier-owned state — never an audit record and never trusted blindly: the verifier re-validates every
-- position against BOTH the file and audit_chain before using it, and on any mismatch discards it (reset to the chain
-- base) and runs the full verifier instead. It is written only after the range it describes has been verified, inside a
-- transaction holding the existing verifier advisory lock (one writer across processes). A stale or restored row can
-- therefore only cause a reset, never a skipped range.
--
-- Separate from audit_chain_verifier_state (migration 031: file-mode / PG-authoritative watermarks), whose semantics
-- differ. Privileges mirror that table: qodiqa_app SELECT/INSERT/UPDATE (the verifier's own pool), qodiqa_read SELECT;
-- qodiqa_backup SELECT via migration 067's default privileges. No DELETE for any runtime role. No RLS (no tenant data).
-- Additive; reversible by DROP TABLE (design decision — destructive DDL).

BEGIN;

CREATE TABLE IF NOT EXISTS audit_chain_verification_progress (
  kind               VARCHAR(16)  PRIMARY KEY CHECK (kind IN ('incremental', 'sweep')),
  base_checkpoint_id VARCHAR(64),
  pos                BIGINT       NOT NULL CHECK (pos >= 0),
  byte_offset        BIGINT       CHECK (byte_offset IS NULL OR byte_offset >= 0),
  prev_hash          VARCHAR(64)  NOT NULL,
  pg_seq             BIGINT       NOT NULL CHECK (pg_seq >= 0),
  cycle_started_at   TIMESTAMPTZ,
  cycles_completed   BIGINT       NOT NULL DEFAULT 0,
  last_cycle_ms      BIGINT,
  updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE audit_chain_verification_progress IS
  'S3 (migration 074): positions of the layered audit-chain divergence verifier (incremental 60 s layer; rolling 20k/15 min sweep). Derived, re-validated before every use, written only after the range is verified and only under the verifier advisory lock.';

REVOKE ALL ON TABLE audit_chain_verification_progress FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON audit_chain_verification_progress TO qodiqa_app;
GRANT SELECT                 ON audit_chain_verification_progress TO qodiqa_read;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (74, 'w11_audit_chain_verification_progress', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
