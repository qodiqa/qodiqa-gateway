-- QODIQA PostgreSQL Schema — Migration 099
-- Finding: (external anchoring of signed audit checkpoints)
-- Purpose: one row per (signed checkpoint, anchor kind) tracking where the checkpoint's anchor statement went outside the gateway's trust
--          domain: a signed commit in an anchors git repository (`git`), an OpenTimestamps stamp (`ots`), an RFC 3161 timestamp token
--          (`rfc3161`). Publication is asynchronous and never blocks a request or a checkpoint: a row starts `pending`, becomes `confirmed`
--          with its receipt, or stays `pending`/`failed` with the last error and an attempt count (alerted, retried).
--
-- Additive: one new table. Platform-wide (no tenant data: a checkpoint position, hashes and receipts). Row-level security like the other audit
-- tables: the application role reads, inserts and updates its rows; the read role only reads. Never deleted by the application.
-- Idempotent: IF NOT EXISTS / DROP POLICY IF EXISTS.

BEGIN;

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE IF NOT EXISTS external_anchors (
  id               BIGSERIAL    PRIMARY KEY,
  checkpoint_id    TEXT         NOT NULL,
  payload_hash     CHAR(64)     NOT NULL,
  chain_length     BIGINT       NOT NULL CHECK (chain_length >= 1),
  head_hash        CHAR(64)     NOT NULL,
  checkpoint_created_at TEXT    NOT NULL,
  kind             TEXT         NOT NULL CHECK (kind IN ('git', 'ots', 'rfc3161')),
  status           TEXT         NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'failed')),
  receipt          TEXT,
  receipt_ref      TEXT,
  attempts         INTEGER      NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error       TEXT,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
  confirmed_at     TIMESTAMPTZ,
  CONSTRAINT external_anchors_unique_per_kind UNIQUE (payload_hash, kind)
);

CREATE INDEX IF NOT EXISTS idx_external_anchors_pending ON external_anchors (status, created_at) WHERE status <> 'confirmed';
CREATE INDEX IF NOT EXISTS idx_external_anchors_chain_length ON external_anchors (chain_length);

COMMENT ON TABLE external_anchors IS
  'where each signed audit checkpoint was anchored outside the gateway (git signed commit, OpenTimestamps, RFC 3161). Asynchronous, never blocks; receipts are verified offline by the independent verifier.';

ALTER TABLE external_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_anchors FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS external_anchors_select ON external_anchors;
CREATE POLICY external_anchors_select ON external_anchors FOR SELECT USING (TRUE);
DROP POLICY IF EXISTS external_anchors_insert ON external_anchors;
CREATE POLICY external_anchors_insert ON external_anchors FOR INSERT WITH CHECK (current_user = 'qodiqa_app');
DROP POLICY IF EXISTS external_anchors_update ON external_anchors;
CREATE POLICY external_anchors_update ON external_anchors FOR UPDATE USING (current_user = 'qodiqa_app') WITH CHECK (current_user = 'qodiqa_app');

GRANT SELECT, INSERT, UPDATE ON external_anchors TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE external_anchors_id_seq TO qodiqa_app;
GRANT SELECT ON external_anchors TO qodiqa_read;

-- (migration 081): objects created after the schema-owner role belong to it, and the backup role reads every table
-- (081's default privileges only apply to objects CREATED by qodiqa_owner). The table is also listed in post_081_tables of scripts/dr/schema-ownership.sql.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_owner') THEN
    ALTER TABLE external_anchors OWNER TO qodiqa_owner;
    ALTER SEQUENCE external_anchors_id_seq OWNER TO qodiqa_owner;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_backup') THEN
    GRANT SELECT ON external_anchors TO qodiqa_backup;
    GRANT SELECT ON SEQUENCE external_anchors_id_seq TO qodiqa_backup;
  END IF;
END
$$;

COMMIT;
