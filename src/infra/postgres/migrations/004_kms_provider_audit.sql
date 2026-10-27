-- Migration 004: KMS Provider Audit Tables
-- Records key provider lifecycle events for compliance, forensics, and rotation auditing.
-- All sensitive fields (key material) are excluded; only metadata is persisted.

-- ── KMS Provider Event Log ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS kms_provider_events (
  id             BIGSERIAL     PRIMARY KEY,
  occurred_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  provider_name  TEXT          NOT NULL,
  event_type     TEXT          NOT NULL,
  key_name       TEXT,
  client_id      TEXT,
  actor          TEXT,
  outcome        TEXT          NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'WARNING')),
  detail         JSONB         NOT NULL DEFAULT '{}',
  error_message  TEXT
);

COMMENT ON TABLE  kms_provider_events IS 'Immutable log of KMS provider lifecycle events: initialization, key generation, rotation, revocation, health checks.';
COMMENT ON COLUMN kms_provider_events.provider_name  IS 'Provider name string, e.g. vault:transit:transit or aws:kms:arn:aws:kms:...';
COMMENT ON COLUMN kms_provider_events.event_type     IS 'Structured event identifier, e.g. KMS_PROVIDER_INIT_COMPLETE, KMS_KEY_ROTATED.';
COMMENT ON COLUMN kms_provider_events.key_name       IS 'Provider-scoped key identifier (never contains private key bytes).';

CREATE INDEX idx_kpe_provider     ON kms_provider_events (provider_name, occurred_at DESC);
CREATE INDEX idx_kpe_event_type   ON kms_provider_events (event_type, occurred_at DESC);
CREATE INDEX idx_kpe_client_id    ON kms_provider_events (client_id)   WHERE client_id IS NOT NULL;
CREATE INDEX idx_kpe_outcome_fail ON kms_provider_events (occurred_at DESC) WHERE outcome = 'FAILURE';

-- ── Encrypted Data Key Registry ────────────────────────────────────────────────
-- Tracks wrapped/encrypted data keys (EDKs) per provider and tenant.
-- EDK ciphertext is stored here as a reference; the actual blobs live in files
-- (kek.edk, kek.wk, kek.gcp) to keep DB writes off the critical path.

CREATE TABLE IF NOT EXISTS kms_encrypted_data_keys (
  id              BIGSERIAL     PRIMARY KEY,
  created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  rotated_at      TIMESTAMPTZ,
  provider_name   TEXT          NOT NULL,
  tenant_id       TEXT,
  key_purpose     TEXT          NOT NULL DEFAULT 'kek',
  edk_file_path   TEXT          NOT NULL,
  provider_key_id TEXT          NOT NULL,
  algorithm       TEXT          NOT NULL,
  active          BOOLEAN       NOT NULL DEFAULT TRUE,
  metadata        JSONB         NOT NULL DEFAULT '{}'
);

COMMENT ON TABLE  kms_encrypted_data_keys IS 'Registry of encrypted data key blobs; the EDK files are the authoritative store.';
COMMENT ON COLUMN kms_encrypted_data_keys.edk_file_path   IS 'Absolute path to the EDK file on the QODIQA host.';
COMMENT ON COLUMN kms_encrypted_data_keys.provider_key_id IS 'CMK/KEK identifier in the external KMS (ARN, Vault path, etc.).';

CREATE UNIQUE INDEX idx_kms_edk_active ON kms_encrypted_data_keys (provider_name, tenant_id, key_purpose)
  WHERE active = TRUE;

-- ── Wrapping Key Rotation History ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS kms_wrapping_key_rotations (
  id             BIGSERIAL    PRIMARY KEY,
  rotated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  provider_name  TEXT         NOT NULL,
  old_version    TEXT,
  new_version    TEXT,
  initiated_by   TEXT,
  tenant_ids_affected TEXT[], -- tenant IDs whose key material was re-wrapped
  duration_ms    INTEGER,
  status         TEXT         NOT NULL CHECK (status IN ('COMPLETE', 'FAILED', 'PARTIAL'))
);

CREATE INDEX idx_kwkr_provider ON kms_wrapping_key_rotations (provider_name, rotated_at DESC);

-- ── RLS ────────────────────────────────────────────────────────────────────────

ALTER TABLE kms_provider_events         ENABLE ROW LEVEL SECURITY;
ALTER TABLE kms_encrypted_data_keys     ENABLE ROW LEVEL SECURITY;
ALTER TABLE kms_wrapping_key_rotations  ENABLE ROW LEVEL SECURITY;

ALTER TABLE kms_provider_events         FORCE ROW LEVEL SECURITY;
ALTER TABLE kms_encrypted_data_keys     FORCE ROW LEVEL SECURITY;
ALTER TABLE kms_wrapping_key_rotations  FORCE ROW LEVEL SECURITY;

-- App role: append-only on events; read-only on EDK registry.
CREATE POLICY kpe_insert ON kms_provider_events
  FOR INSERT TO qodiqa_app WITH CHECK (true);
CREATE POLICY kpe_select ON kms_provider_events
  AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);

CREATE POLICY kedk_select ON kms_encrypted_data_keys
  AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY kedk_insert ON kms_encrypted_data_keys
  FOR INSERT TO qodiqa_app WITH CHECK (true);

CREATE POLICY kwkr_select ON kms_wrapping_key_rotations
  AS PERMISSIVE FOR SELECT TO qodiqa_app, qodiqa_read USING (true);
CREATE POLICY kwkr_insert ON kms_wrapping_key_rotations
  FOR INSERT TO qodiqa_app WITH CHECK (true);

GRANT SELECT, INSERT ON kms_provider_events         TO qodiqa_app;
GRANT SELECT, INSERT ON kms_encrypted_data_keys     TO qodiqa_app;
GRANT SELECT, INSERT ON kms_wrapping_key_rotations  TO qodiqa_app;
GRANT SELECT          ON kms_provider_events         TO qodiqa_read;
GRANT SELECT          ON kms_encrypted_data_keys     TO qodiqa_read;
GRANT SELECT          ON kms_wrapping_key_rotations  TO qodiqa_read;
GRANT USAGE, SELECT   ON SEQUENCE kms_provider_events_id_seq        TO qodiqa_app;
GRANT USAGE, SELECT   ON SEQUENCE kms_encrypted_data_keys_id_seq    TO qodiqa_app;
GRANT USAGE, SELECT   ON SEQUENCE kms_wrapping_key_rotations_id_seq TO qodiqa_app;
