-- QODIQA PostgreSQL Migration 068
-- step 6, decision 1: aggregate the routine per-request success events.
--
-- platform_audit_events received ~15 rows per /ai/chat request (16,810 of 31,052 PG bytes per request,
--). Fourteen routine INFO success event types, 15 rows/request (src/core/audit/centralStore.js
-- AGGREGATED_EVENT_TYPES) are now written as ONE row per (clock minute, event type, tenant, category, severity,
-- component, outcome), carrying how many events it stands for in aggregate_count. Every other event — every WARN or
-- higher, every BLOCK/FAILURE/WARNING outcome, every type not on the list — is still one row with aggregate_count 1.
--
-- Every count over this table now sums aggregate_count (centralStore stats/search total/ingestionRate/topEventTypes,
-- compliance evidenceCollector), so all counts are unchanged; rows written before this migration default to 1.
-- Additive only; qodiqa_platform_audit_events_full_read() (053) returns SETOF platform_audit_events and therefore
-- carries the new column.

BEGIN;

ALTER TABLE platform_audit_events
  ADD COLUMN IF NOT EXISTS aggregate_count INTEGER NOT NULL DEFAULT 1;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'platform_audit_events_aggregate_count_chk') THEN
    ALTER TABLE platform_audit_events
      ADD CONSTRAINT platform_audit_events_aggregate_count_chk CHECK (aggregate_count >= 1);
  END IF;
END
$$;

COMMENT ON COLUMN platform_audit_events.aggregate_count IS
  'number of events this row stands for. 1 for every individually persisted event; N for a per-minute aggregate of a routine success event type (payload.aggregated = true). Every count must SUM this column.';

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (68, 'w10_platform_events_aggregate_count', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
