-- Migration 032: Persistence Recovery Queue — durable Postgres backing (CHAIN-3 remediation)
--
-- Prior to this migration, the Persistence Recovery Queue (Component #13,
-- src/core/persistenceRecovery/queue.js) stored every pending retry, its
-- retry/error history, and the Dead Letter Queue exclusively in Redis (a
-- ZSET + per-item HASH). If Redis was unavailable at the moment a PostgreSQL
-- dual-write or Evidence Chain write failed, recoveryManager.enqueue()
-- logged RECOVERY_QUEUE_UNAVAILABLE and returned — the failed write was
-- never durably recorded anywhere and was permanently lost. Redis was an
-- undisclosed single point of failure for a mechanism whose entire purpose
-- is guaranteeing writes are "not lost".
--
-- This table makes PostgreSQL — already the platform's primary durable
-- store, and already the destination every queued operation is retried
-- against — the sole authoritative store for pending recovery work. Redis
-- is removed from this durability path entirely; queue.js no longer opens
-- a Redis connection at all.,
-- "Decision Update: Durable Postgres-Backed Persistence Recovery Queue
-- (CHAIN-3)" for the full design rationale.
--
-- Claim semantics mirror the previous Redis Lua CLAIM_SCRIPT exactly: a
-- claim does not move rows to a separate "processing" table or set a
-- separate lock column — it advances eligible_at forward by the claim
-- timeout, in the same UPDATE that performs the claim. If the worker
-- crashes mid-processing, eligible_at naturally elapses and another worker
-- (or the same one, after restart) claims the row again — no separate
-- expiry sweep is needed. `FOR UPDATE SKIP LOCKED` (the same idiom already
-- used by src/core/audit/retention.js) makes concurrent claims by multiple
-- worker processes mutually exclusive without any Redis-based locking.
--
-- Status values: 'PENDING' (in the active retry cycle), 'DLQ' (exhausted
-- MAX_RETRIES, awaiting operator replay/archive), 'ARCHIVED' (soft-deleted
-- by an operator, retained for audit — never physically removed). There is
-- no 'COMPLETE' status: a successfully processed operation is DELETEd
-- outright (markComplete), exactly as the Redis version deleted the hash
-- and removed the ZSET member on success.
--
-- Idempotent: safe to re-run.

BEGIN;

CREATE TABLE IF NOT EXISTS persistence_recovery_queue (
  operation_id     TEXT         PRIMARY KEY,
  operation_type   TEXT         NOT NULL,
  service          TEXT         NOT NULL,
  payload          JSONB        NOT NULL,

  status           TEXT         NOT NULL DEFAULT 'PENDING'
                                 CHECK (status IN ('PENDING', 'DLQ', 'ARCHIVED')),

  -- Scheduling / crash-safe claim: the next time this row is eligible to be
  -- claimed. On claim, a worker advances this forward by CLAIM_TIMEOUT_MS —
  -- if the worker dies before finishing, the row becomes claimable again
  -- once that window elapses, exactly as the prior ZSET-score design worked.
  eligible_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

  retry_count      INTEGER      NOT NULL DEFAULT 0,
  replay_count     INTEGER      NOT NULL DEFAULT 0,
  last_error       TEXT,
  error_history    JSONB        NOT NULL DEFAULT '[]'::jsonb,

  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  dlq_at           TIMESTAMPTZ,
  replayed_at      TIMESTAMPTZ,
  archived_at      TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

  CONSTRAINT prq_operation_id_nonempty   CHECK (operation_id   <> ''),
  CONSTRAINT prq_operation_type_nonempty CHECK (operation_type <> ''),
  CONSTRAINT prq_retry_count_nonneg      CHECK (retry_count  >= 0),
  CONSTRAINT prq_replay_count_nonneg     CHECK (replay_count >= 0)
);

COMMENT ON TABLE persistence_recovery_queue IS
  'Durable Postgres-backed Persistence Recovery Queue (CHAIN-3 remediation). '
  'Authoritative store for pending/DLQ/archived retry work — replaces the '
  'previous Redis-only ZSET+HASH design. Redis is no longer read from or '
  'written to anywhere in this path.';

COMMENT ON COLUMN persistence_recovery_queue.eligible_at IS
  'Next eligible claim/retry time. Claiming a PENDING row advances this by '
  'the claim timeout instead of moving the row — a crashed worker''s claim '
  'simply expires and the row becomes claimable again.';

COMMENT ON COLUMN persistence_recovery_queue.status IS
  'PENDING = active retry cycle. DLQ = exhausted MAX_RETRIES, awaiting '
  'operator action. ARCHIVED = soft-deleted by an operator, retained for '
  'audit. Successful completion DELETEs the row outright (no COMPLETE state).';

-- ── Indexes ───────────────────────────────────────────────────────────────────

-- Claim query: WHERE status = 'PENDING' AND eligible_at <= now() ORDER BY
-- eligible_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED. Partial index keeps this
-- cheap regardless of how large the DLQ/archived sets grow.
CREATE INDEX IF NOT EXISTS idx_prq_claim
  ON persistence_recovery_queue (eligible_at)
  WHERE status = 'PENDING';

-- DLQ listing/filtering, ordered oldest-or-newest first.
CREATE INDEX IF NOT EXISTS idx_prq_dlq
  ON persistence_recovery_queue (dlq_at)
  WHERE status = 'DLQ';

-- Archived listing, newest first.
CREATE INDEX IF NOT EXISTS idx_prq_archived
  ON persistence_recovery_queue (archived_at)
  WHERE status = 'ARCHIVED';

-- DLQ filtering by operationType/service (admin API query params).
CREATE INDEX IF NOT EXISTS idx_prq_dlq_type_service
  ON persistence_recovery_queue (operation_type, service)
  WHERE status = 'DLQ';

-- ── Row-level security ────────────────────────────────────────────────────────
-- Platform-level operational table (attestations, certifications, portal
-- verifications, webhook deliveries, audit/evidence chain retries) — none of
-- the current operation types carry a tenant_id at the queue-row level (see
-- src/core/persistenceRecovery/dlqManager.js header comment), so this mirrors
-- the permissive "global tables" pattern already established for
-- qodiqa_alert_stats and similar platform-scoped tables (migration 018,
-- RLS-114/115), not the tenant-scoped IS NULL OR pattern.

ALTER TABLE persistence_recovery_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE persistence_recovery_queue FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS prq_select ON persistence_recovery_queue;
CREATE POLICY prq_select ON persistence_recovery_queue
  FOR SELECT TO qodiqa_app, qodiqa_read USING (true);

DROP POLICY IF EXISTS prq_insert ON persistence_recovery_queue;
CREATE POLICY prq_insert ON persistence_recovery_queue
  FOR INSERT TO qodiqa_app WITH CHECK (true);

DROP POLICY IF EXISTS prq_update ON persistence_recovery_queue;
CREATE POLICY prq_update ON persistence_recovery_queue
  FOR UPDATE TO qodiqa_app USING (true) WITH CHECK (true);

-- DELETE is required: a successfully processed operation is removed
-- outright (markComplete), exactly as the Redis version deleted its hash.
DROP POLICY IF EXISTS prq_delete ON persistence_recovery_queue;
CREATE POLICY prq_delete ON persistence_recovery_queue
  FOR DELETE TO qodiqa_app USING (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE, DELETE ON persistence_recovery_queue TO qodiqa_app;
GRANT SELECT                          ON persistence_recovery_queue TO qodiqa_read;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (32, 'persistence_recovery_queue', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
