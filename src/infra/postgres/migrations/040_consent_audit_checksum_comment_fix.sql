-- QODIQA PostgreSQL Schema — Migration 040
-- Finding: TRACE-3 — Consent audit checksum is write-only, and its
--          documented field coverage is inaccurate
-- Purpose: Correct the column comment on consent_audit_log.checksum.
--          Migration 007's original comment claimed the checksum covers
--          "(id, event_type, event_ts, detail)" — this was never accurate:
--          `id` and `event_ts` are DB-assigned (BIGSERIAL/DEFAULT NOW()),
--          only known AFTER insertion, and cannot be part of a checksum
--          computed BEFORE the INSERT runs (see
--          src/core/consent/ConsentStore.js's original _appendAudit()).
--          The actual formula has always been consent_id|event_type|actor|
--          detail — this migration only fixes the misleading comment; it
--          does not change the column type, data, or (as of the TRACE-3
--          remediation) the checksum formula itself.
--
-- Historical migration files are checksummed by migrate.js and must never
-- be edited after being applied (doing so trips the "Migration integrity
-- violation: checksum changed after application" guard for any database
-- that already ran migration 007) — a new, additive `COMMENT ON COLUMN`
-- migration is the correct way to fix documentation on an existing column.
--
-- Idempotent: COMMENT ON COLUMN is safe to re-run.

BEGIN;

COMMENT ON COLUMN consent_audit_log.checksum IS
    'TRACE-3: SHA-256 of consent_id|event_type|actor|detail (detail '
    'serialized via stableStringify — lexicographic key sort at every '
    'depth, so the checksum survives a JSONB storage round-trip regardless '
    'of PostgreSQL''s own internal key reordering). See '
    'src/core/consent/ConsentStore.js _auditChecksum()/verifyAuditChecksum(). '
    'Does NOT cover from_state, to_state, actor_id, action, tenant_id, '
    'verification_result, denial_reason, or request_id, even though those '
    'are also columns on this row Section 2.1. '
    'Verified on read as of TRACE-3 (previously write-only); surfaced '
    'through the live audit chain verifier''s FULL scan on mismatch.';

COMMIT;
