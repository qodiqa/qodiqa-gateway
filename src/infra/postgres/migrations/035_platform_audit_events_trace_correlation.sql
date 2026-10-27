-- QODIQA PostgreSQL Migration 035
-- adds W3C trace/span correlation columns to platform_audit_events —
-- the canonical cross-subsystem correlation store (migration 003) — so a SOC
-- analyst can join an operational/security log event to its OpenTelemetry-style
-- trace (activated) using the same identifiers the log stream itself
-- now carries (services/logger.js emit(), remediation).
--
-- Nullable and unindexed-by-default-population: tracing is opt-in
-- (QODIQA_OTEL_ENABLED), so most rows will have trace_id/span_id = NULL,
-- exactly like the existing partial indexes on request_id/tenant_id/actor_id
-- above already handle for optional correlation columns.
--
-- Does NOT touch audit_chain / audit.log or their PostgreSQL dual-write
-- (pg-audit-backend.js) — those are the separate, cryptographically
-- hash-chained evidence record described in QODIQA-PROTOCOL-SPEC.md §11.3,
-- out of scope for this migration. See SIEM-3-REMEDIATION-REPORT.md for the
-- full root-cause analysis of why these are two different systems.

BEGIN;

ALTER TABLE platform_audit_events
  ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32),
  ADD COLUMN IF NOT EXISTS span_id  VARCHAR(16);

COMMENT ON COLUMN platform_audit_events.trace_id IS
  'W3C trace-id (32 lowercase hex chars) of the OTel-style span active when '
  'this event was emitted (src/observability/tracing/context.js), when '
  'tracing is enabled. NULL when tracing is disabled or the event occurred '
  'outside any traced request.';

COMMENT ON COLUMN platform_audit_events.span_id IS
  'W3C span-id (16 lowercase hex chars) of the active span at emit time. '
  'NULL under the same conditions as trace_id.';

-- Trace correlation: "every event within a single distributed trace"
CREATE INDEX IF NOT EXISTS idx_pae_trace_id
  ON platform_audit_events (trace_id, occurred_at DESC)
  WHERE trace_id IS NOT NULL;

COMMIT;
