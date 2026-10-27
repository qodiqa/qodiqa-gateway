-- Migration 016: Webhooks — Component #28
--
-- Establishes persistent storage for webhook endpoint subscriptions and
-- delivery history.  Enables external systems to receive signed notifications
-- when long-running operations (certifications, attestations) complete.
--
-- Tables:
--   webhook_endpoints    — per-tenant endpoint subscriptions (mutable)
--   webhook_delivery_log — immutable append-only delivery attempt log
--
-- Secret storage:
--   Webhook signing secrets are stored AES-256-GCM encrypted (3-column pattern:
--   secret_enc, secret_iv, secret_tag).  The KEK is QODIQA_KEY_ENCRYPTION_KEY.
--   Plaintext secrets are never stored in PG and are returned only once at
--   endpoint creation.
--
-- RLS: FORCE on all tables.
--   webhook_endpoints    — qodiqa_app SELECT + INSERT + UPDATE; qodiqa_read SELECT.
--   webhook_delivery_log — qodiqa_app SELECT + INSERT;          qodiqa_read SELECT.
--   No DELETE or UPDATE on delivery log (immutable audit trail).

BEGIN;

-- ── Webhook Endpoints ─────────────────────────────────────────────────────────
--
-- Mutable registry of per-tenant webhook endpoint subscriptions.
-- UPDATE allowed (enabled toggle, eventTypes changes).
-- DELETE not permitted via application role (ops-only DDL).

CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     VARCHAR(128)  NOT NULL,
  url           TEXT          NOT NULL,
  enabled       BOOLEAN       NOT NULL DEFAULT TRUE,
  event_types   TEXT[]        NOT NULL DEFAULT '{}',

  -- AES-256-GCM encrypted signing secret
  -- secret_enc: base64 ciphertext of the plaintext secret
  -- secret_iv:  base64 of 12-byte random IV
  -- secret_tag: base64 of 16-byte GCM authentication tag
  secret_enc    TEXT          NOT NULL,
  secret_iv     TEXT          NOT NULL,
  secret_tag    TEXT          NOT NULL,

  description   VARCHAR(255)  NULL,
  created_by    VARCHAR(128)  NOT NULL DEFAULT 'external',
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  CONSTRAINT webhook_url_nonempty    CHECK (url       <> ''),
  CONSTRAINT webhook_tenant_nonempty CHECK (tenant_id <> '')
);

COMMENT ON TABLE webhook_endpoints IS
  'Per-tenant webhook endpoint subscriptions. '
  'Secrets are stored AES-256-GCM encrypted — never in plaintext. '
  'Plaintext is returned once at creation only.';

COMMENT ON COLUMN webhook_endpoints.secret_enc IS
  'AES-256-GCM ciphertext of the plaintext webhook signing secret (base64).';

COMMENT ON COLUMN webhook_endpoints.secret_iv IS
  'AES-256-GCM 12-byte initialization vector for the secret (base64).';

COMMENT ON COLUMN webhook_endpoints.secret_tag IS
  'AES-256-GCM 16-byte authentication tag for the secret (base64).';

-- ── Webhook Delivery Log ──────────────────────────────────────────────────────
--
-- Immutable append-only log of every delivery attempt.
-- One row per attempt (retries produce additional rows with higher attempt numbers).
-- INSERT-only: no UPDATE, no DELETE.

CREATE TABLE IF NOT EXISTS webhook_delivery_log (
  id           BIGSERIAL     PRIMARY KEY,

  -- Stable delivery attempt identifier
  delivery_id  UUID          NOT NULL DEFAULT gen_random_uuid(),

  endpoint_id  UUID          NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  event_id     UUID          NOT NULL,
  event_type   VARCHAR(100)  NOT NULL,

  attempt      SMALLINT      NOT NULL DEFAULT 1,
  delivered_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  http_status  SMALLINT      NULL,
  duration_ms  INTEGER       NULL,
  success      BOOLEAN       NOT NULL DEFAULT FALSE,
  error_msg    TEXT          NULL,

  CONSTRAINT wdl_attempt_positive CHECK (attempt > 0)
);

COMMENT ON TABLE webhook_delivery_log IS
  'Immutable log of every webhook delivery attempt. '
  'INSERT-only: one row per attempt; retries append new rows. '
  'Retained indefinitely for audit and debugging.';

COMMENT ON COLUMN webhook_delivery_log.delivery_id IS
  'Stable UUID for this delivery attempt. Used to correlate log entries.';

COMMENT ON COLUMN webhook_delivery_log.attempt IS
  'Delivery attempt number (1 = first try, 2+ = retries).';

-- ── Indexes ───────────────────────────────────────────────────────────────────

-- Endpoint lookups: by tenant and event type (fan-out query on every event)
CREATE INDEX IF NOT EXISTS idx_we_tenant_enabled
  ON webhook_endpoints (tenant_id, enabled, created_at DESC);

-- GIN index on event_types array for fast containment queries
CREATE INDEX IF NOT EXISTS idx_we_event_types
  ON webhook_endpoints USING GIN (event_types);

-- Delivery log: most recent attempts per endpoint
CREATE INDEX IF NOT EXISTS idx_wdl_endpoint_id
  ON webhook_delivery_log (endpoint_id, delivered_at DESC);

-- Delivery log: lookup by event_id (all attempts for a given event)
CREATE INDEX IF NOT EXISTS idx_wdl_event_id
  ON webhook_delivery_log (event_id, attempt);

-- Delivery log: lookup by delivery_id
CREATE INDEX IF NOT EXISTS idx_wdl_delivery_id
  ON webhook_delivery_log (delivery_id);

-- Failed deliveries for operational monitoring
CREATE INDEX IF NOT EXISTS idx_wdl_failed
  ON webhook_delivery_log (success, delivered_at DESC)
  WHERE success = FALSE;

-- ── Row Level Security ────────────────────────────────────────────────────────

ALTER TABLE webhook_endpoints    ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints    FORCE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery_log FORCE ROW LEVEL SECURITY;

-- webhook_endpoints: SELECT + INSERT + UPDATE for app; SELECT for read role
CREATE POLICY we_select ON webhook_endpoints
  FOR SELECT TO qodiqa_app, qodiqa_read USING (true);

CREATE POLICY we_insert ON webhook_endpoints
  FOR INSERT TO qodiqa_app WITH CHECK (true);

CREATE POLICY we_update ON webhook_endpoints
  FOR UPDATE TO qodiqa_app USING (true) WITH CHECK (true);

-- webhook_delivery_log: INSERT-only for app; SELECT for read role
CREATE POLICY wdl_select ON webhook_delivery_log
  FOR SELECT TO qodiqa_app, qodiqa_read USING (true);

CREATE POLICY wdl_insert ON webhook_delivery_log
  FOR INSERT TO qodiqa_app WITH CHECK (true);

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE ON webhook_endpoints    TO qodiqa_app;
GRANT SELECT                  ON webhook_endpoints    TO qodiqa_read;

GRANT SELECT, INSERT          ON webhook_delivery_log TO qodiqa_app;
GRANT SELECT                  ON webhook_delivery_log TO qodiqa_read;
GRANT USAGE, SELECT           ON SEQUENCE webhook_delivery_log_id_seq TO qodiqa_app;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (16, 'webhooks', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
