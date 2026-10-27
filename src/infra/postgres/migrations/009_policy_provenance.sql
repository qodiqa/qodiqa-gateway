-- Migration 009: Policy Provenance Framework (Component #20)
--
-- Establishes the immutable provenance ledger for every policy version:
--   who changed it, when, what changed, why it changed, and a cryptographic
--   hash chain that detects any tampering.
--
-- Integrates with: policies, policy_versions, policy_history,
--                  rbac_users, platform_audit_events.
--
-- RLS: FORCE on all tables; qodiqa_app INSERT + SELECT; qodiqa_read SELECT only.
-- Immutability: NO UPDATE or DELETE policies are created on the provenance table.
--               Application layer also enforces append-only writes.
--
-- Design invariants:
--   1. One row per policy version, ever. Never rewritten, never deleted.
--   2. actor_id, actor_username, actor_role, source_ip are all mandatory.
--      The application layer rejects any mutation without full attribution.
--   3. change_reason is mandatory. The application rejects empty strings.
--   4. policy_hash = SHA-256(canonical JSON of policy_content).
--   5. previous_policy_hash = policy_hash of the preceding version (NULL for v1).
--      This forms the tamper-evident hash chain.
--   6. diff_structured is generated automatically at write time and never modified.

BEGIN;

-- ── Policy Provenance Versions ─────────────────────────────────────────────────
--
-- Immutable append-only ledger.  One row is inserted for every policy mutation
-- (creation, update, enable/disable, rollback, deprecation).
-- Rows are never updated or deleted.

CREATE TABLE IF NOT EXISTS policy_provenance_versions (
  id                     BIGSERIAL      PRIMARY KEY,

  -- Policy identity
  policy_id              VARCHAR(128)   NOT NULL,
  version_number         INTEGER        NOT NULL,
  parent_version         INTEGER        NULL,
  root_version           INTEGER        NOT NULL DEFAULT 1,

  -- Event classification
  event_type             VARCHAR(64)    NOT NULL,

  -- When this version was created
  occurred_at            TIMESTAMPTZ    NOT NULL DEFAULT NOW(),

  -- Attribution — all four fields are mandatory
  -- The application layer rejects any write with a missing or blank value.
  actor_id               VARCHAR(128)   NOT NULL,
  actor_username         VARCHAR(128)   NOT NULL,
  actor_role             VARCHAR(64)    NOT NULL,
  source_ip              VARCHAR(64)    NOT NULL,

  -- Change justification — mandatory, non-empty
  change_reason          VARCHAR(512)   NOT NULL,
  change_notes           TEXT           NOT NULL DEFAULT '',

  -- Full policy state snapshot at this version (for forensic reconstruction)
  policy_content         JSONB          NOT NULL,

  -- Cryptographic integrity
  policy_hash            CHAR(64)       NOT NULL,   -- SHA-256(canonical JSON of policy_content)
  previous_policy_hash   VARCHAR(64)    NULL,       -- policy_hash of preceding version; NULL for v1

  -- Diff (generated automatically, stored immutably)
  diff_structured        JSONB          NOT NULL DEFAULT '[]',
  diff_human_readable    TEXT           NOT NULL DEFAULT '',

  -- Rollback reference — populated when event_type = 'POLICY_ROLLED_BACK'
  rolled_back_to_version INTEGER        NULL,

  -- Constraints
  CONSTRAINT ppv_unique_version   UNIQUE (policy_id, version_number),
  CONSTRAINT ppv_version_positive CHECK  (version_number > 0),
  CONSTRAINT ppv_root_positive    CHECK  (root_version > 0),
  CONSTRAINT ppv_hash_length      CHECK  (LENGTH(policy_hash) = 64),
  CONSTRAINT ppv_parent_chain     CHECK  (
    (version_number = 1 AND parent_version IS NULL)
    OR
    (version_number > 1 AND parent_version IS NOT NULL AND parent_version < version_number)
  ),
  CONSTRAINT ppv_event_type_valid CHECK  (event_type IN (
    'POLICY_CREATED',
    'POLICY_UPDATED',
    'POLICY_ENABLED',
    'POLICY_DISABLED',
    'POLICY_ROLLED_BACK',
    'POLICY_RESTORED',
    'POLICY_DEPRECATED',
    'POLICY_IMPORTED',
    'POLICY_VERSION_CREATED'
  ))
);

COMMENT ON TABLE policy_provenance_versions IS
  'Immutable provenance ledger. One row per policy version. '
  'No UPDATE or DELETE permitted at any layer. '
  'Hash chain (policy_hash → previous_policy_hash) enables tamper detection.';

COMMENT ON COLUMN policy_provenance_versions.policy_hash IS
  'SHA-256 of the canonical JSON representation of policy_content. '
  'Canonical = keys sorted recursively, no extra whitespace.';

COMMENT ON COLUMN policy_provenance_versions.previous_policy_hash IS
  'policy_hash of the preceding version. NULL for version 1. '
  'Chain: v2.previous_policy_hash === v1.policy_hash, etc.';

COMMENT ON COLUMN policy_provenance_versions.diff_structured IS
  'JSON array of { path, op, from, to } change descriptors generated at write time.';

COMMENT ON COLUMN policy_provenance_versions.change_reason IS
  'Mandatory human-readable justification. Empty strings rejected by the application layer.';

-- ── Indexes — optimised for investigation and reporting query patterns ──────────

-- History for a single policy (most common query)
CREATE INDEX IF NOT EXISTS idx_ppv_policy_history
  ON policy_provenance_versions (policy_id, occurred_at DESC, version_number DESC);

-- Lookup specific version of a policy (O(1) via unique constraint index)
-- (covered by the UNIQUE constraint index on (policy_id, version_number))

-- Time-range queries across all policies (cross-policy investigation)
CREATE INDEX IF NOT EXISTS idx_ppv_occurred_at
  ON policy_provenance_versions (occurred_at DESC);

-- Actor activity queries (who did what, when)
CREATE INDEX IF NOT EXISTS idx_ppv_actor_id
  ON policy_provenance_versions (actor_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_ppv_actor_username
  ON policy_provenance_versions (actor_username, occurred_at DESC);

-- Event type filtering (how many rollbacks? all POLICY_CREATED events?)
CREATE INDEX IF NOT EXISTS idx_ppv_event_type
  ON policy_provenance_versions (event_type, occurred_at DESC);

-- Source IP for security investigations
CREATE INDEX IF NOT EXISTS idx_ppv_source_ip
  ON policy_provenance_versions (source_ip, occurred_at DESC);

-- Hash lookup (tamper detection — find a specific hash, verify chain)
CREATE INDEX IF NOT EXISTS idx_ppv_policy_hash
  ON policy_provenance_versions (policy_hash);

-- Previous hash lookup (forward chain walk)
CREATE INDEX IF NOT EXISTS idx_ppv_previous_hash
  ON policy_provenance_versions (previous_policy_hash)
  WHERE previous_policy_hash IS NOT NULL;

-- Rollback queries
CREATE INDEX IF NOT EXISTS idx_ppv_rollback
  ON policy_provenance_versions (policy_id, rolled_back_to_version)
  WHERE rolled_back_to_version IS NOT NULL;

-- ── Policy Provenance Integrity Runs ──────────────────────────────────────────
--
-- Records the results of hash-chain integrity validation runs.
-- A chain_valid = FALSE row indicates detected tampering or corruption.

CREATE TABLE IF NOT EXISTS policy_provenance_integrity_runs (
  id               BIGSERIAL    PRIMARY KEY,
  policy_id        VARCHAR(128) NOT NULL,
  checked_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  versions_checked INTEGER      NOT NULL DEFAULT 0,
  chain_valid      BOOLEAN      NOT NULL,
  failure_version  INTEGER      NULL,   -- first version where chain breaks
  failure_detail   TEXT         NULL,
  checked_by       VARCHAR(128) NOT NULL DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS idx_ppir_policy
  ON policy_provenance_integrity_runs (policy_id, checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_ppir_invalid
  ON policy_provenance_integrity_runs (chain_valid, checked_at DESC)
  WHERE chain_valid = FALSE;

CREATE INDEX IF NOT EXISTS idx_ppir_time
  ON policy_provenance_integrity_runs (checked_at DESC);

COMMENT ON TABLE policy_provenance_integrity_runs IS
  'Records of hash-chain integrity validation runs. '
  'A chain_valid=FALSE row is a security incident requiring investigation.';

-- ── Row Level Security ─────────────────────────────────────────────────────────

ALTER TABLE policy_provenance_versions         ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_provenance_integrity_runs   ENABLE ROW LEVEL SECURITY;

ALTER TABLE policy_provenance_versions         FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_provenance_integrity_runs   FORCE ROW LEVEL SECURITY;

-- SELECT: both app and read roles may query provenance
CREATE POLICY ppv_select
  ON policy_provenance_versions
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

CREATE POLICY ppir_select
  ON policy_provenance_integrity_runs
  FOR SELECT TO qodiqa_app, qodiqa_read
  USING (true);

-- INSERT-only: no UPDATE or DELETE policies are created (immutability enforcement)
CREATE POLICY ppv_insert
  ON policy_provenance_versions
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

CREATE POLICY ppir_insert
  ON policy_provenance_integrity_runs
  FOR INSERT TO qodiqa_app
  WITH CHECK (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT ON policy_provenance_versions       TO qodiqa_app;
GRANT SELECT         ON policy_provenance_versions       TO qodiqa_read;
GRANT SELECT, INSERT ON policy_provenance_integrity_runs TO qodiqa_app;
GRANT SELECT         ON policy_provenance_integrity_runs TO qodiqa_read;

GRANT USAGE, SELECT ON SEQUENCE policy_provenance_versions_id_seq       TO qodiqa_app;
GRANT USAGE, SELECT ON SEQUENCE policy_provenance_integrity_runs_id_seq TO qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (9, 'policy_provenance', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
