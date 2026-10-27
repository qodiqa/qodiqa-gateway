-- Migration 036: Audit Checksum Anchor Isolation
--
-- The audit checksum anchor (audit.log.sum, src/core/audit/audit-log.js)
-- has always lived on the same filesystem/directory as audit.log itself —
-- the exact file it exists to tamper-evidence. A fault or attacker capable
-- of corrupting or truncating the log directory can trivially corrupt or
-- roll back the anchor in lockstep, giving it no independent tamper-evidence
-- value. This is a distinct problem from migration 026's audit_chain_head,
-- which is the ORDERING authority for QODIQA_AUDIT_ORDERING_MODE=distributed
-- deployments only — single-node mode (the default) has no PG-backed anchor
-- at all today.
--
-- audit_checksum_anchor is therefore a NEW, single-node-scoped table,
-- deliberately NOT the same table as audit_chain_head — reusing that table
-- would couple this WP's tamper-evidence isolation goal to the distributed
-- ordering feature's invariants (a different concern, owned by a different
-- mode). This table is dual-written alongside the existing file-based
-- checksum anchor (never replacing it — see checksumAnchor.js) whenever
-- QODIQA_PG_ENABLED=true, giving operators a second, independent-failure-
-- domain signal to detect log-directory corruption/truncation/tampering
-- even when the file anchor itself has been compromised.
--
-- Idempotent: safe to re-run.

BEGIN;

CREATE TABLE IF NOT EXISTS audit_checksum_anchor (
  id         BOOLEAN   PRIMARY KEY DEFAULT TRUE,
  count      BIGINT    NOT NULL,
  tail_hash  CHAR(64),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT audit_checksum_anchor_singleton CHECK (id = TRUE)
);

COMMENT ON TABLE audit_checksum_anchor IS
  'Single-node-mode checksum anchor, isolated from the audit.log filesystem — #2. Dual-written alongside the co-located audit.log.sum file, never a replacement for it. See src/core/audit/checksumAnchor.js.';

-- ── Row-level security ────────────────────────────────────────────────────────
-- Mirrors audit_chain_head's shape (migration 026): UPDATE is granted since,
-- like that table, this one-row anchor is meant to be mutated in place.

ALTER TABLE audit_checksum_anchor ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checksum_anchor FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_checksum_anchor_select ON audit_checksum_anchor;
CREATE POLICY audit_checksum_anchor_select ON audit_checksum_anchor FOR SELECT USING (TRUE);

DROP POLICY IF EXISTS audit_checksum_anchor_insert ON audit_checksum_anchor;
CREATE POLICY audit_checksum_anchor_insert ON audit_checksum_anchor FOR INSERT
  WITH CHECK (current_user = 'qodiqa_app');

DROP POLICY IF EXISTS audit_checksum_anchor_update ON audit_checksum_anchor;
CREATE POLICY audit_checksum_anchor_update ON audit_checksum_anchor FOR UPDATE
  USING (current_user = 'qodiqa_app')
  WITH CHECK (current_user = 'qodiqa_app');

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE ON audit_checksum_anchor TO qodiqa_app;
GRANT SELECT                  ON audit_checksum_anchor TO qodiqa_read;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (36, 'audit_checksum_anchor', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
