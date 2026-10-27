-- Migration 031: Audit Chain Verifier State (CHAIN-2 remediation)
--
-- Persisted watermark/cursor for the Live Audit Chain Integrity Verifier
-- (src/core/audit/verifier/)
-- "Decision Update: Live Audit Chain Integrity Verifier (CHAIN-2)".
--
-- Single mutable row, same shape as audit_chain_head (migration 026) and
-- gap_scanner_state (migration 019): tracks how far the verifier has already
-- confirmed the chain to be internally consistent, so a periodic incremental
-- scan only needs to walk the delta since the last run (O(delta), not O(n)),
-- and so a process restart can seed its starting watermark from durable
-- state instead of forcing a full rescan every boot.
--
-- This table is intentionally separate from audit_chain itself and does NOT
-- change audit_chain's existing append-only grants (migration 002: qodiqa_app
-- gets INSERT+SELECT only, never UPDATE/DELETE). audit_chain_verifier_state
-- is a mutable pointer table, not part of the immutable log.
--
-- Idempotent: safe to re-run.

BEGIN;

CREATE TABLE IF NOT EXISTS audit_chain_verifier_state (
  id                             INTEGER      PRIMARY KEY DEFAULT 1,

  -- Own-chain hash-walk cursor (PG-authoritative / distributed mode, and the
  -- PG side of dual-write mode).
  last_verified_seq              BIGINT,
  last_verified_hash             CHAR(64),

  -- Dual-write divergence cursor (single-node + PG mirror mode) — the last
  -- seq position confirmed to match between the file chain and the PG mirror.
  last_pg_divergence_seq         BIGINT,

  -- Scan metadata.
  last_scan_mode                 VARCHAR(16),   -- 'FULL' | 'INCREMENTAL'
  last_scan_trigger              VARCHAR(16),   -- 'STARTUP' | 'SCHEDULED' | 'MANUAL'
  last_scan_at                   TIMESTAMPTZ,
  last_full_scan_at              TIMESTAMPTZ,
  last_scan_duration_ms          BIGINT,

  -- Scan results.
  last_scan_violations_detected  INTEGER      NOT NULL DEFAULT 0,
  last_scan_entries_checked      BIGINT       NOT NULL DEFAULT 0,

  updated_at                     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

  CONSTRAINT audit_chain_verifier_state_singleton CHECK (id = 1)
);

COMMENT ON TABLE audit_chain_verifier_state IS
  'Single-row watermark/cursor for the live audit chain integrity verifier (CHAIN-2). Never a source of truth about chain contents — only where the verifier last confirmed consistency up to. Mutable by design, unlike audit_chain itself.';

INSERT INTO audit_chain_verifier_state (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

-- ── Row-level security ────────────────────────────────────────────────────────
-- Mirrors audit_chain_head's RLS shape (migration 026) — a mutable pointer
-- table, UPDATE is granted (unlike audit_chain itself).

ALTER TABLE audit_chain_verifier_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_verifier_state FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_chain_verifier_state_select ON audit_chain_verifier_state;
CREATE POLICY audit_chain_verifier_state_select ON audit_chain_verifier_state FOR SELECT USING (TRUE);

DROP POLICY IF EXISTS audit_chain_verifier_state_insert ON audit_chain_verifier_state;
CREATE POLICY audit_chain_verifier_state_insert ON audit_chain_verifier_state FOR INSERT
  WITH CHECK (current_user = 'qodiqa_app');

DROP POLICY IF EXISTS audit_chain_verifier_state_update ON audit_chain_verifier_state;
CREATE POLICY audit_chain_verifier_state_update ON audit_chain_verifier_state FOR UPDATE
  USING (current_user = 'qodiqa_app')
  WITH CHECK (current_user = 'qodiqa_app');

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE ON audit_chain_verifier_state TO qodiqa_app;
GRANT SELECT                  ON audit_chain_verifier_state TO qodiqa_read;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (31, 'audit_chain_verifier_state', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
