-- Migration 019: Transparency Gap Scanner State (Component #34)
--
-- Single-row state table that persists scan progress across restarts.
-- The scanner uses pg_try_advisory_xact_lock to ensure only one scanner
-- runs at a time across all replicas (Kubernetes / Docker Swarm safe).
--
-- Design:
--   • id=1 is the only valid row (enforced by CHECK constraint).
--   • All columns are nullable; NULL means "never scanned".
--   • The scanner UPSERTs after each successful scan so state is always current.
--   • INCREMENTAL mode resumes from last_scanned_id; FULL mode starts at id=1.
--
-- Advisory lock key:
--   hashtext('qodiqa_gap_scanner')::bigint — stable int derived from string.
--   Acquired via pg_try_advisory_xact_lock inside the scan transaction so it
--   auto-releases on transaction commit, rollback, or connection loss.

BEGIN;

CREATE TABLE IF NOT EXISTS gap_scanner_state (
  id                         INTEGER       PRIMARY KEY DEFAULT 1,

  -- Incremental scan resumption
  last_scanned_id            BIGINT        NULL,     -- id of last entry fully verified
  last_completed_root_id     BIGINT        NULL,     -- id of last root fully verified

  -- Scan metadata
  last_scan_mode             VARCHAR(16)   NULL,     -- 'FULL' | 'INCREMENTAL'
  last_scan_at               TIMESTAMPTZ   NULL,     -- when the last scan completed
  last_full_scan_at          TIMESTAMPTZ   NULL,     -- when the last FULL scan completed
  last_scan_duration_ms      BIGINT        NULL,     -- duration of the last scan

  -- Scan results
  last_scan_gaps_detected    INTEGER       NOT NULL DEFAULT 0,
  last_scan_entries_checked  BIGINT        NOT NULL DEFAULT 0,

  -- Internal
  updated_at                 TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

  CONSTRAINT gss_single_row CHECK (id = 1)
);

COMMENT ON TABLE gap_scanner_state IS
  'Single-row state record for the Transparency Gap Scanner (Component #34). '
  'Persists scan progress across process restarts. id=1 is the only valid row. '
  'Scanner resumes from last_scanned_id in INCREMENTAL mode. '
  'Advisory lock key: hashtext(''qodiqa_gap_scanner'')::bigint.';

COMMENT ON COLUMN gap_scanner_state.last_scanned_id IS
  'id (BIGSERIAL PK) of the last transparency_log_entries row fully verified. '
  'INCREMENTAL scan resumes from this position + 1. '
  'NULL means no scan has completed yet.';

COMMENT ON COLUMN gap_scanner_state.last_completed_root_id IS
  'id (BIGSERIAL PK) of the last transparency_roots row fully verified. '
  'Root scanner resumes from this position + 1. '
  'NULL means no root scan has completed yet.';

-- Ensure the single-row exists immediately after migration.
INSERT INTO gap_scanner_state (id) VALUES (1) ON CONFLICT DO NOTHING;

-- ── Grants ────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, UPDATE ON gap_scanner_state TO qodiqa_app;
GRANT SELECT                  ON gap_scanner_state TO qodiqa_read;

-- ── Migration record ──────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (19, 'gap_scanner', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
