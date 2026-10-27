-- Migration 050: logStore.js transparency_log_entries RLS-bypass functions
--
--
-- fixed GapScanner.js's own three RLS-blind query shapes against
-- transparency_log_entries. This migration closes the identical defect
-- class across logStore.js's own read surface, following the same
-- SECURITY DEFINER-per-shape idiom (migrations 043/044/048/049) — a
-- read-only audit traced every real
-- production caller of every transparency_log_entries query in logStore.js
-- before writing anything here; only confirmed-defective, confirmed-global
-- call sites are covered below.
--
-- appendEntry() (the one WRITE call site) was audited and found CORRECT —
-- registrar.js already calls tenantContext.js's setLocal() before it when
-- a tenant_id is present (registrar.js:177-178) — not touched here.
--
-- All read call sites are legitimately global by design, not tenant-scoped:
-- five back the transparency log's own PUBLIC, UNAUTHENTICATED verification
-- router (createTransparencyPublicRouter() in transparencyLog.js — no
-- tenant identity exists on these requests at all, by design, matching a
-- Certificate-Transparency-style public log), the rest back genuinely
-- global admin/internal chain-integrity operations (root generation,
-- chain-continuity validation, root-generation scheduling, platform-wide
-- stats). None of them should be tenant-restricted; withTenantTransaction()
-- would be actively wrong for any of them (same reasoning already
-- established for their own global-scan call sites).
--
-- SECURITY DEFINER, STABLE, LANGUAGE sql, SET search_path = pg_catalog,
-- public — identical idiom to 043/044/048/049: a narrow, deliberate,
-- auditable exception per query shape, never a blanket bypass grant on the
-- table itself. EXECUTE granted to qodiqa_app and qodiqa_read, REVOKEd
-- from PUBLIC.

BEGIN;

-- ── getByTransparencyId()'s indexed point lookup ───────────────────────────
-- Backs the public /entry/:id, /verify/:id, /proof/:id routes — unauthenticated,
-- must find any entry regardless of tenant.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_by_transparency_id(target_id UUID)
RETURNS SETOF transparency_log_entries
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM transparency_log_entries WHERE transparency_id = target_id LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_by_transparency_id(UUID) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for the public, unauthenticated transparency verification routes. remediation. Used by logStore.js''s getByTransparencyId().';

-- ── getByEntryHash()'s indexed point lookup ────────────────────────────────
-- Backs public /verify/:id's chain-link check — must find the true prior
-- entry regardless of tenant to correctly verify the hash chain.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_by_entry_hash(target_hash CHAR(64))
RETURNS SETOF transparency_log_entries
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM transparency_log_entries WHERE entry_hash = target_hash LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_by_entry_hash(CHAR(64)) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for the public /verify/:id chain-link check. remediation. Used by logStore.js''s getByEntryHash().';

-- ── getByArtifactId()'s indexed lookup ─────────────────────────────────────
-- Backs evidence-bundle generation's inclusion-proof lookup (proofLookup.js
-- -> generator.js) — must find the entry for a known artifact regardless of
-- tenant to prove public inclusion.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_by_artifact_id(target_artifact_id VARCHAR)
RETURNS SETOF transparency_log_entries
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM transparency_log_entries WHERE artifact_id = target_artifact_id ORDER BY id ASC
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_by_artifact_id(VARCHAR) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for evidence-bundle generation''s inclusion-proof lookup. remediation. Used by logStore.js''s getByArtifactId().';

-- ── getByEvidenceChainId()'s indexed lookup ────────────────────────────────
-- No real production caller as of this migration (precedent: fixed
-- pre-emptively anyway so a future caller does not inherit the same gap).

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_by_evidence_chain_id(target_evidence_chain_id UUID)
RETURNS SETOF transparency_log_entries
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM transparency_log_entries WHERE evidence_chain_id = target_evidence_chain_id ORDER BY id ASC
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_by_evidence_chain_id(UUID) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS. No real caller as remediation — fixed pre-emptively, same precedent as migration 048''s queryByArtifactId/queryReplayLineage. Used by logStore.js''s getByEvidenceChainId().';

-- ── getLatestEntry()'s tail lookup ──────────────────────────────────────────
-- Backs rootScheduler.js's decision of when to trigger root generation —
-- needs the TRUE latest id across the whole table; RLS-blind here can
-- silently under-trigger root generation whenever recent entries are
-- tenant-owned.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_latest_entry()
RETURNS SETOF transparency_log_entries
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM transparency_log_entries ORDER BY id DESC LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_latest_entry() IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for rootScheduler.js''s root-generation trigger decision. remediation. Used by logStore.js''s getLatestEntry().';

-- ── getEntriesInRange()'s id-range read ─────────────────────────────────────
-- HIGHEST SEVERITY of this migration's fixes: backs registrar.js's
-- generateRoot(), which uses the result to compute the ACTUAL SIGNED ROOT
-- HASH. RLS-blind here does not just cause a false detector alert (as
-- GapScanner's own defect did) — it silently excludes tenant-owned entries
-- from the Merkle tree at the moment the root is cryptographically
-- committed and signed, corrupting the root itself, not just a later read
-- of it. Also backs proofLookup.js's inclusion-proof computation and both
-- the public /consistency and admin /chain/validate routes.
--
-- Explicit column list (excluding `payload`) mirrors logStore.js's own
-- current SELECT exactly — deliberately omitted there "for size reasons"
-- (see src/core/transparency/log.js's own comment on this), preserved here
-- via RETURNS TABLE rather than RETURNS SETOF transparency_log_entries so
-- that optimization is not silently lost.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_fetch_range_full(from_id BIGINT, to_id BIGINT)
RETURNS TABLE (
  id                  BIGINT,
  transparency_id     UUID,
  entry_type          VARCHAR(64),
  artifact_id         VARCHAR(128),
  evidence_chain_id   UUID,
  verification_id     BIGINT,
  payload_hash        CHAR(64),
  previous_entry_hash VARCHAR(64),
  entry_hash          CHAR(64),
  signer_key_id       VARCHAR(128),
  signer_key_version  INTEGER,
  signature           TEXT,
  registered_by       VARCHAR(128),
  tenant_id           VARCHAR(128),
  created_at          TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT
    id, transparency_id, entry_type,
    artifact_id, evidence_chain_id, verification_id,
    payload_hash, previous_entry_hash, entry_hash,
    signer_key_id, signer_key_version, signature,
    registered_by, tenant_id, created_at
  FROM transparency_log_entries
  WHERE id >= from_id AND id <= to_id
  ORDER BY id ASC
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_fetch_range_full(BIGINT, BIGINT) IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for registrar.js''s generateRoot() (the actual signed-root-hash computation), proofLookup.js''s inclusion-proof computation, and the public /consistency + admin /chain/validate routes. remediation, highest severity in this migration. Used by logStore.js''s getEntriesInRange().';

-- ── Generic full-table bypass for listEntries()/aggregateStats() ──────────
-- Mirrors migration 044's qodiqa_audit_chain_full_read() precedent exactly:
-- listEntries() has multiple OPTIONAL filter dimensions (entry_type,
-- artifact_id, signer_key_id, tenant_id, startTime, endTime) with no single
-- dominant index regardless of which combination is active, and
-- aggregateStats() is an unconditional full-table aggregate — neither
-- benefits from a narrower, parameter-pushed-down function the way
-- fetch_by_transparency_id's indexed point lookup does. The existing
-- dynamic WHERE/ORDER BY/LIMIT/OFFSET logic in logStore.js stays exactly as
-- written; only the FROM-table reference changes.

CREATE OR REPLACE FUNCTION qodiqa_transparency_log_read_all()
RETURNS SETOF transparency_log_entries
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM transparency_log_entries
$$;

COMMENT ON FUNCTION qodiqa_transparency_log_read_all() IS
  'SECURITY DEFINER: bypasses transparency_log_entries'' per-tenant RLS for logStore.js''s listEntries() (public /entries, with its own optional filters applied by the caller''s outer SQL) and aggregateStats() (admin /admin/stats dashboard). remediation, same full-table-bypass precedent as migration 044''s qodiqa_audit_chain_full_read().';

-- ── Grants ──────────────────────────────────────────────────────────────────

REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_by_transparency_id(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_by_entry_hash(CHAR(64)) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_by_artifact_id(VARCHAR) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_by_evidence_chain_id(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_latest_entry() FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_fetch_range_full(BIGINT, BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_transparency_log_read_all() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_by_transparency_id(UUID)          TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_by_entry_hash(CHAR(64))            TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_by_artifact_id(VARCHAR)            TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_by_evidence_chain_id(UUID)         TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_latest_entry()                          TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_fetch_range_full(BIGINT, BIGINT)         TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_transparency_log_read_all()                              TO qodiqa_app, qodiqa_read;

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (50, 'transparency_logstore_rls_bypass', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
