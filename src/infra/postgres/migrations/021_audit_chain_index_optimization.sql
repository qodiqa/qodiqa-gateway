-- Migration 021: Audit Chain Index Optimization
--
-- Adds missing PostgreSQL indexes on audit_chain to ensure every runtime
-- lookup pattern has O(1) database support at the PostgreSQL layer.
--
-- Background:
-- (current): in-memory chain is authoritative; PostgreSQL is the
--   durable complement. will promote PostgreSQL to primary. These
--   indexes ensure promotion requires zero additional schema work and
--   that existing PostgreSQL-backed queries (pg-audit-backend.js) are already
--   optimal.
--
-- Indexes added:
--   idx_audit_chain_nonce — O(1) nonce replay detection+
--   idx_audit_chain_request_hash — O(1) lookup of entries by request hash
--   idx_audit_chain_input_hash   — O(1) lookup by artifact input hash
--   idx_audit_chain_policy_hash  — O(1) lookup by policy hash (forensics)
--   idx_audit_chain_hash         — already PRIMARY KEY; documented here for clarity
--
-- Existing indexes (from 001_initial_schema.sql) that remain valid:
--   PRIMARY KEY (hash)                     — O(1) hash lookup
--   UNIQUE idx_audit_chain_artifact_id     — O(1) artifact_id lookup
--   idx_audit_chain_tenant                 — O(1) tenant-scoped queries
--   idx_audit_chain_decision               — decision + time queries
--   idx_audit_chain_recorded_at            — time-range queries
--   idx_audit_chain_replay_of              — replayOf JSONB extraction
--   idx_audit_chain_prev_hash              — forward chain traversal
--
-- Idempotent: all DDL uses IF NOT EXISTS.

BEGIN;

-- ── Nonce replay detection ────────────────────────────────────────────────────
-- Enables O(1) nonce uniqueness check+ (PG-primary) without
-- scanning the full table.  Partial index: most entries have no nonce.

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_nonce
  ON audit_chain (nonce)
  WHERE nonce IS NOT NULL;

COMMENT ON INDEX idx_audit_chain_nonce IS
  'Unique nonce index for O(1) replay detection. Partial: nonce IS NOT NULL.';

-- ── Request hash lookup ───────────────────────────────────────────────────────
-- Supports "find all audit entries sharing the same request" without scanning.
-- Partial index: excludes sentinel ''UNAVAILABLE'' values (BLOCK entries that
-- did not reach the request-hash computation stage).

CREATE INDEX IF NOT EXISTS idx_audit_chain_request_hash
  ON audit_chain (request_hash, recorded_at DESC)
  WHERE request_hash IS NOT NULL AND request_hash <> 'UNAVAILABLE';

COMMENT ON INDEX idx_audit_chain_request_hash IS
  'Request hash index for O(1) correlated-request lookup. Excludes UNAVAILABLE sentinels.';

-- ── Input hash lookup ─────────────────────────────────────────────────────────
-- Supports forensic lookup of an artifact by its input hash when the artifact_id
-- is not known.  Partial index: excludes UNAVAILABLE.

CREATE INDEX IF NOT EXISTS idx_audit_chain_input_hash
  ON audit_chain (input_hash)
  WHERE input_hash IS NOT NULL AND input_hash <> 'UNAVAILABLE';

COMMENT ON INDEX idx_audit_chain_input_hash IS
  'Input hash index for O(1) forensic lookup by artifact input hash.';

-- ── Policy hash lookup ────────────────────────────────────────────────────────
-- Supports forensic queries like "all enforcement decisions under policy hash X".
-- Partial index: excludes UNAVAILABLE.

CREATE INDEX IF NOT EXISTS idx_audit_chain_policy_hash
  ON audit_chain (policy_hash, recorded_at DESC)
  WHERE policy_hash IS NOT NULL AND policy_hash <> 'UNAVAILABLE';

COMMENT ON INDEX idx_audit_chain_policy_hash IS
  'Policy hash index for O(1) policy-scoped forensic lookup.';

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (21, 'audit_chain_index_optimization', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
