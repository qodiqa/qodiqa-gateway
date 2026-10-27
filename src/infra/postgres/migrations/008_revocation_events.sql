-- 008_revocation_events.sql
-- Durable revocation event log for Component #19 — Instant Consent Revocation.
--
-- Purpose:
--   1. Persistent deduplication: supplements the in-memory LRU Set so that
--      events are not re-processed after a subscriber restart.
--   2. Audit trail: full record of every revocation event published and processed.
--   3. Replay / recovery: operators can replay recent events to a new subscriber
--      after an outage by querying revocation_events ORDER BY received_at.
--
-- This table is append-only and is never updated.  Retention is handled by the
-- same audit retention policy as consent_audit_log (see 007_consent_registry.sql).

BEGIN;

CREATE TABLE IF NOT EXISTS revocation_events (
  id                      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Deduplication key — matches RevocationEvent.eventId (UUID v4)
  event_id                UUID          NOT NULL,

  -- Protocol version — matches RevocationEvent.EVENT_VERSION
  version                 TEXT          NOT NULL DEFAULT '1',

  -- Affected consent record (NULL for actor-level revocations with no single record)
  consent_id              UUID          REFERENCES consent_records(id) ON DELETE SET NULL,

  -- Actor whose consent was revoked
  subject_id              TEXT          NOT NULL,

  -- Specific action revoked (NULL for actor-level revocations)
  action                  TEXT,

  -- Tenant scope (NULL = cross-tenant / global)
  tenant_id               TEXT,

  -- Identity that triggered the revocation
  revoked_by              TEXT,

  -- Human-readable reason
  revocation_reason       TEXT,

  -- When the revocation was initiated (from the event envelope)
  revocation_timestamp    TIMESTAMPTZ   NOT NULL,

  -- Audit correlation
  correlation_id          TEXT,

  -- Source system that published the event
  source_system           TEXT          NOT NULL DEFAULT 'qodiqa-consent-registry',

  -- When this node received and stored the event
  received_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),

  -- When cache invalidation completed on this node (NULL = not yet processed)
  processed_at            TIMESTAMPTZ,

  -- Latency from received_at to processed_at in milliseconds
  processing_latency_ms   INTEGER,

  -- Hostname / instance ID of the receiving node (for multi-node audit)
  node_id                 TEXT,

  -- HMAC-SHA256 signature from the event envelope (hex; NULL if event unsigned)
  event_signature         TEXT,

  -- Original JSON payload for replay capability
  raw_payload             TEXT          NOT NULL
);

-- Deduplication: fast existence check by event_id
CREATE UNIQUE INDEX IF NOT EXISTS uidx_revocation_events_event_id
  ON revocation_events (event_id);

-- Audit queries: all events for a given actor, newest first
CREATE INDEX IF NOT EXISTS idx_revocation_events_subject_id
  ON revocation_events (subject_id, revocation_timestamp DESC);

-- Audit queries: all events for a specific consent record
CREATE INDEX IF NOT EXISTS idx_revocation_events_consent_id
  ON revocation_events (consent_id, revocation_timestamp DESC)
  WHERE consent_id IS NOT NULL;

-- Replay window: recent events ordered by receipt time
CREATE INDEX IF NOT EXISTS idx_revocation_events_received_at
  ON revocation_events (received_at DESC);

COMMENT ON TABLE revocation_events IS
  'Append-only durable log of consent revocation propagation events (Component #19). '
  'Used for deduplication after subscriber restart, audit, and replay/recovery.';

COMMENT ON COLUMN revocation_events.event_id IS
  'UUID v4 assigned by the publisher; globally unique deduplication key.';
COMMENT ON COLUMN revocation_events.raw_payload IS
  'Original JSON string received from the Redis pub/sub channel. '
  'Retained verbatim for replay and forensic analysis.';

COMMIT;
