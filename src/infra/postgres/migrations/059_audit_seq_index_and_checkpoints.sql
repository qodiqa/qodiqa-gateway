-- Migration 059: audit_chain.seq index + audit/transparency checkpoints
--
-- ROOT CAUSE:
--   * audit_chain has no index on seq. The verifier's batch read
--     (qodiqa_audit_chain_fetch_batch: WHERE seq > $1 ORDER BY seq LIMIT n) and
--     distributed hydration run as Seq Scan + Sort per batch, so a full walk is
--     O(n^2 / batch).
--   * every single-node boot loads the ENTIRE PG mirror into memory for the
--     startup mirror consistency check.
--   * every transparency inclusion proof (and every root) rebuilds the Merkle
--     tree from entry 1.
--
-- This migration adds:
--   1. idx_audit_chain_seq — plain (non-unique) btree on audit_chain(seq).
--      Non-unique on purpose: uniqueness of seq is a verifier finding
--      (DUPLICATE_SEQUENCE), not a constraint a historical database may be
--      forced to satisfy by a migration.
--   2. audit_chain_checkpoints — "the mirror was verified consistent with the
--      file chain up to chain_length entries, ending at hash, at seq". Written
--      by the startup mirror check after a successful check; the next boot
--      verifies only the suffix after the latest checkpoint (falls back to the
--      full check on any doubt). Append-only for qodiqa_app. UNSIGNED for now;
-- signs checkpoints.
--   3. transparency_merkle_checkpoints — RFC 6962 subtree hash of each
--      complete, aligned block of block_size leaves (first_id..last_id in id
--      order; ids may have gaps, positions do not). A proof/root then needs
--      the block hashes + the leaves of at most two blocks instead of the
--      whole log. Tamper-evident without a signature: a wrong block hash yields
--      a root/path that does not match the SIGNED root. Append-only for
--      qodiqa_app.
--
-- Neither checkpoint table holds tenant data (hashes, ids, counts only), so no
-- RLS policy is needed; qodiqa_app may SELECT and INSERT only (no UPDATE or
-- DELETE). Natural primary keys, no sequences. Additive only.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_audit_chain_seq ON audit_chain (seq);

COMMENT ON INDEX idx_audit_chain_seq IS
  'seq-ordered batch reads (verifier, distributed hydration) use an index scan instead of Seq Scan + Sort per batch. Non-unique by design (duplicate seq is a verifier finding).';

CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
  chain_length  BIGINT       PRIMARY KEY CHECK (chain_length > 0),
  hash          CHAR(64)     NOT NULL,
  seq           BIGINT       NOT NULL,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  created_by    VARCHAR(64)  NOT NULL
);

COMMENT ON TABLE audit_chain_checkpoints IS
  'verified positions of the single-node audit chain (file == PG mirror up to chain_length, ending at hash/seq). The startup mirror check verifies only the suffix after the latest checkpoint. Unsigned until.';

CREATE TABLE IF NOT EXISTS transparency_merkle_checkpoints (
  block_size    INT          NOT NULL CHECK (block_size >= 2),
  block_index   BIGINT       NOT NULL CHECK (block_index >= 0),
  first_id      BIGINT       NOT NULL,
  last_id       BIGINT       NOT NULL,
  subtree_hash  CHAR(64)     NOT NULL,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
  PRIMARY KEY (block_size, block_index),
  CHECK (last_id >= first_id)
);

COMMENT ON TABLE transparency_merkle_checkpoints IS
  'RFC 6962 subtree hash of each complete aligned block of block_size leaves of transparency_log_entries (id order, first_id..last_id). Proofs and roots combine these with at most two blocks of leaves instead of loading the whole log.';

GRANT SELECT, INSERT ON audit_chain_checkpoints         TO qodiqa_app;
GRANT SELECT         ON audit_chain_checkpoints         TO qodiqa_read;
GRANT SELECT, INSERT ON transparency_merkle_checkpoints TO qodiqa_app;
GRANT SELECT         ON transparency_merkle_checkpoints TO qodiqa_read;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (59, 'audit_seq_index_and_checkpoints', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
