-- QODIQA PostgreSQL Migration 070
-- step 6, design decisions M1/M2: signed audit-chain checkpoints, anchored in the transparency log.
--
--   audit_signed_checkpoints   one row per signed checkpoint (src/core/audit/checkpoint/checkpoint.js): the canonical
--                              payload, its payloadHash and the Ed25519 signature by the dedicated checkpoint key
--                              (checkpointKeyStore.js, published at /.well-known/qodiqa/checkpoint-keys). Checkpoints
--                              chain through previous_checkpoint_hash. APPEND-ONLY: the request-serving role may
--                              INSERT and SELECT; UPDATE / DELETE / TRUNCATE are refused by a guard trigger for every
--                              role that does not bypass RLS (the owner / migrator only — M4's operator command never
--                              deletes checkpoints; they are what later verification starts from).
--
--   A separate table, not new columns on audit_chain_checkpoints: signing an existing unsigned row
--   would need UPDATE for the app role on a checkpoint table. audit_chain_checkpoints keeps its meaning (unsigned
--   "file == PG mirror up to here" positions for the startup mirror check); its "Unsigned until" comment is
--   corrected below.
--
--   transparency_log_entries   entry_type gains 'AUDIT_CHECKPOINT' (M2): each signed checkpoint is also registered as
--                              a transparency leaf { checkpointId, checkpointPayloadHash, chainLength, headHash }, so
--                              it is committed to by the next signed Merkle root.

BEGIN;

CREATE TABLE IF NOT EXISTS audit_signed_checkpoints (
  checkpoint_id            UUID          PRIMARY KEY,
  chain_length             BIGINT        NOT NULL UNIQUE CHECK (chain_length > 0),
  head_hash                CHAR(64)      NOT NULL,
  pg_seq                   BIGINT,
  payload                  JSONB         NOT NULL,
  payload_hash             CHAR(64)      NOT NULL UNIQUE,
  signature                TEXT          NOT NULL,
  key_id                   VARCHAR(128)  NOT NULL,
  key_version              INTEGER       NOT NULL,
  previous_checkpoint_hash CHAR(64),
  created_at               TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  created_by               VARCHAR(64)   NOT NULL
);

GRANT SELECT, INSERT ON audit_signed_checkpoints TO qodiqa_app;
GRANT SELECT ON audit_signed_checkpoints TO qodiqa_read;

CREATE OR REPLACE FUNCTION qodiqa_audit_signed_checkpoints_append_only_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolbypassrls OR rolsuper)) THEN
    RETURN COALESCE(NEW, OLD);
  END IF;
  RAISE EXCEPTION 'audit_signed_checkpoints is append-only (% refused for %)', TG_OP, current_user USING ERRCODE = '42501';
END
$$;

DROP TRIGGER IF EXISTS audit_signed_checkpoints_append_only_guard ON audit_signed_checkpoints;
CREATE TRIGGER audit_signed_checkpoints_append_only_guard
  BEFORE UPDATE OR DELETE ON audit_signed_checkpoints
  FOR EACH ROW EXECUTE FUNCTION qodiqa_audit_signed_checkpoints_append_only_guard();
DROP TRIGGER IF EXISTS audit_signed_checkpoints_no_truncate ON audit_signed_checkpoints;
CREATE TRIGGER audit_signed_checkpoints_no_truncate
  BEFORE TRUNCATE ON audit_signed_checkpoints
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_signed_checkpoints_append_only_guard();

COMMENT ON TABLE audit_signed_checkpoints IS
  'signed audit-chain checkpoints (Ed25519, dedicated checkpoint key), chained by previous_checkpoint_hash and anchored as AUDIT_CHECKPOINT transparency leaves. Append-only.';

COMMENT ON TABLE audit_chain_checkpoints IS
  'verified positions of the single-node audit chain (file == PG mirror up to chain_length, ending at hash/seq). The startup mirror check verifies only the suffix after the latest checkpoint. Unsigned by design; signed checkpoints are in audit_signed_checkpoints.';

ALTER TABLE transparency_log_entries DROP CONSTRAINT IF EXISTS tle_entry_type_valid;
ALTER TABLE transparency_log_entries ADD CONSTRAINT tle_entry_type_valid CHECK (entry_type IN (
  'ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM', 'AUDIT_CHECKPOINT'
));

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (70, 'w10_signed_checkpoints', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
