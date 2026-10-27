-- Migration 048: Audit-chain verifier RLS-bypass functions
--
-- Same defect class as migrations 043 (qodiqa_audit_chain_last_row) and 044
-- (qodiqa_audit_chain_full_read): a plain SELECT against audit_chain as
-- qodiqa_app is subject to ac_tenant_select (migration 018), so any global,
-- cross-tenant integrity check that queries audit_chain directly only ever
-- sees the calling session's own tenant (or NULL-tenant) rows, not the true
-- chain. Migration 044 closed this for pg-audit-backend.js's loadChainFromPg()
-- alone; found
-- the identical defect, unfixed, in seven more pg-audit-backend.js functions
-- that back the live audit chain verifier's PG-authoritative (distributed
-- mode) scan and the verifier's own startup continuity gate
-- (verifierStartupGate.js) -- live-reproduced: a false ORPHAN_RECORD from
-- validateChainLinks() with real evidence a genuinely-present row was simply
-- invisible to the RLS-scoped connection.
--
-- Three of the seven (validateChainLinks, detectDuplicateSequences,
-- countGenesisRows) are already unconditional full-table checks with no
-- parameters -- these are rewired in src/ to select FROM
-- qodiqa_audit_chain_full_read() (migration 044's existing SECURITY DEFINER
-- function) instead of FROM audit_chain directly. No new SQL function is
-- needed for these three; nothing here defines one.
--
-- The remaining four (fetchChainBatch, detectSequenceAnomalies,
-- fetchRowBySeq, getMaxSeq) plus two currently-unused-but-exported functions
-- of the identical shape (queryByArtifactId, queryReplayLineage) are
-- genuinely parameterized/indexed/bounded queries (seq-range pagination, a
-- single indexed point lookup, a bounded window-function gap scan). Routing
-- these through qodiqa_audit_chain_full_read() instead would force a full,
-- unbounded table materialization on every call -- fetchChainBatch's own doc
-- comment is explicit that this is exactly what its pagination exists to
-- avoid ("a FULL scan never loads the entire table into memory at once").
-- Each of the six below is therefore its own dedicated SECURITY DEFINER
-- function, mirroring its caller's existing SQL exactly (same predicates,
-- same LIMIT/ORDER BY), so the query planner can still push the seq
-- range/index lookup down inside the bypassed read -- no query-plan
-- regression versus the pre-fix, RLS-scoped version, only the RLS bypass
-- itself changes.
--
-- queryByTenant() is deliberately NOT touched here -- it is the one function
-- in this group that is correctly tenant-scoped by design (its own name and
-- signature), not a global/cross-tenant integrity check; RLS is the CORRECT
-- behavior for it, provided its (currently zero) real callers set the
-- session tenant context via tenantContext.js's setLocal() before calling,
-- exactly as persistEntry()'s write path already does.
--
-- SECURITY DEFINER, STABLE, LANGUAGE sql, SET search_path = pg_catalog,
-- public -- identical idiom to 043/044: a narrow, deliberate, auditable
-- exception per query shape, never a blanket bypass grant on the table
-- itself. EXECUTE granted to qodiqa_app and qodiqa_read (matching 044's own
-- DEC-3 grant breadth, since these serve the same verifier subsystem
-- loadChainFromPg() does), REVOKEd from PUBLIC.

BEGIN;

-- ── fetchChainBatch()'s paginated seq-range read ───────────────────────────
-- Mirrors pg-audit-backend.js:433-456 exactly (WHERE seq > $1 ORDER BY seq
-- ASC LIMIT $2); RETURNS SETOF audit_chain per 044's own reasoning (a strict
-- superset of the caller's SELECT column list, always correct by
-- construction, no hand-typed column list to keep in sync across migrations
-- 025/033/034/037/039).

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_fetch_batch(from_seq BIGINT, batch_size INT)
RETURNS SETOF audit_chain
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM audit_chain WHERE seq > from_seq ORDER BY seq ASC LIMIT batch_size
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_fetch_batch(BIGINT, INT) IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS (ac_tenant_select) for the live audit chain verifier''s paginated seq-range batch read. remediation -- see migration 044''s header. Used by pg-audit-backend.js''s fetchChainBatch().';

-- ── detectSequenceAnomalies()'s bounded gap scan ───────────────────────────
-- Mirrors pg-audit-backend.js:507-526 exactly, including the boundary-row
-- technique for an off-by-one at the batch's own starting edge.

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_detect_sequence_gaps(from_seq BIGINT, batch_size INT)
RETURNS TABLE (previous_seq BIGINT, actual_seq BIGINT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  WITH boundary AS (
    SELECT seq FROM audit_chain WHERE seq <= from_seq ORDER BY seq DESC LIMIT 1
  ),
  scoped AS (
    SELECT seq FROM audit_chain WHERE seq > from_seq ORDER BY seq ASC LIMIT batch_size
  ),
  combined AS (
    SELECT seq FROM boundary
    UNION ALL
    SELECT seq FROM scoped
  ),
  windowed AS (
    SELECT seq, LAG(seq) OVER (ORDER BY seq) AS prev_seq FROM combined
  )
  SELECT prev_seq AS previous_seq, seq AS actual_seq
  FROM windowed
  WHERE seq > from_seq AND prev_seq IS NOT NULL AND seq <> prev_seq + 1
  ORDER BY seq ASC
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_detect_sequence_gaps(BIGINT, INT) IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS for the live audit chain verifier''s bounded sequence-gap scan. remediation. Used by pg-audit-backend.js''s detectSequenceAnomalies().';

-- ── fetchRowBySeq()'s indexed point lookup ─────────────────────────────────
-- Backs the verifier's startup watermark-continuity gate
-- (verifierStartupGate.js), which is FATAL (process.exit(1)) on a mismatch
-- in distributed mode -- the same false-positive/false-FATAL exposure class
-- already confirmed for mirrorConsistencyCheck.js's own startup gate.

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_fetch_row_by_seq(target_seq BIGINT)
RETURNS CHAR(64)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT hash FROM audit_chain WHERE seq = target_seq LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_fetch_row_by_seq(BIGINT) IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS for the live audit chain verifier''s startup watermark-continuity gate (verifierStartupGate.js, FATAL on mismatch in distributed mode). remediation. Used by pg-audit-backend.js''s fetchRowBySeq().';

-- ── getMaxSeq()'s table-wide max ───────────────────────────────────────────
-- Also backs verifierStartupGate.js -- an RLS-undercounted max(seq) could
-- mask real truncation (fewer visible rows look like a shorter, but still
-- internally consistent, chain) as easily as it could false-positive one.

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_max_seq()
RETURNS BIGINT
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT max(seq) FROM audit_chain
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_max_seq() IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS for the live audit chain verifier''s startup watermark-continuity gate (verifierStartupGate.js). remediation. Used by pg-audit-backend.js''s getMaxSeq().';

-- ── queryByArtifactId()'s indexed point lookup ─────────────────────────────
-- Currently unused (zero real callers in src/ as of this migration) but
-- exported as public module interface with clearly global intent (lookup a
-- specific artifact regardless of which tenant wrote it) -- fixed now so a
-- future caller does not inherit the same silent RLS-visibility gap.

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_fetch_by_artifact_id(target_artifact_id VARCHAR)
RETURNS SETOF audit_chain
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM audit_chain WHERE artifact_id = target_artifact_id LIMIT 1
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_fetch_by_artifact_id(VARCHAR) IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS for a global, tenant-independent artifact lookup. remediation (closing the same defect class pre-emptively on a currently-unused-but-exported function). Used by pg-audit-backend.js''s queryByArtifactId().';

-- ── queryReplayLineage()'s indexed filtered scan ───────────────────────────
-- Same currently-unused status and same rationale as queryByArtifactId()
-- above -- also global-intent by design (replay detection must see every
-- entry referencing an artifactId regardless of tenant).

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_fetch_replay_lineage(target_artifact_id VARCHAR)
RETURNS SETOF audit_chain
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT * FROM audit_chain WHERE execution_context->>'replayOf' = target_artifact_id ORDER BY seq ASC
$$;

COMMENT ON FUNCTION qodiqa_audit_chain_fetch_replay_lineage(VARCHAR) IS
  'SECURITY DEFINER: bypasses audit_chain''s per-tenant RLS for a global, tenant-independent replay-lineage scan. remediation (closing the same defect class pre-emptively on a currently-unused-but-exported function). Used by pg-audit-backend.js''s queryReplayLineage().';

-- ── Grants ──────────────────────────────────────────────────────────────────

REVOKE ALL ON FUNCTION qodiqa_audit_chain_fetch_batch(BIGINT, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_detect_sequence_gaps(BIGINT, INT) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_fetch_row_by_seq(BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_max_seq() FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_fetch_by_artifact_id(VARCHAR) FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_fetch_replay_lineage(VARCHAR) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_fetch_batch(BIGINT, INT)          TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_detect_sequence_gaps(BIGINT, INT) TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_fetch_row_by_seq(BIGINT)          TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_max_seq()                        TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_fetch_by_artifact_id(VARCHAR)     TO qodiqa_app, qodiqa_read;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_fetch_replay_lineage(VARCHAR)     TO qodiqa_app, qodiqa_read;

-- ── Migration record ─────────────────────────────────────────────────────────

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (48, 'audit_chain_verifier_rls_bypass', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
