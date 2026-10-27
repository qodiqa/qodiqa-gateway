-- 047_alerts_dedup_key_unique_active.sql
--
-- AlertStore.saveAlert()'s `ON CONFLICT (dedup_key) DO UPDATE` has never
-- once worked. The only index covering dedup_key is
-- idx_alerts_dedup_key -- btree (dedup_key, detected_at DESC)
-- WHERE dedup_key IS NOT NULL -- which is neither UNIQUE nor a single-column
-- index, so PostgreSQL cannot infer an arbiter from it and rejects every
-- insert outright with SQLSTATE 42P10, "there is no unique or exclusion
-- constraint matching the ON CONFLICT specification". Every alert therefore
-- fell into saveAlert()'s catch, which emits ALERT_STORE_SAVE_FAILED and
-- pushes to an in-process array (_memAlerts) -- so alerts existed only until
-- the next restart and were invisible to every query path that reads
-- PostgreSQL. Verified empirically before this migration: qodiqa_alerts held
-- 0 rows on the shared `qodiqa` database after six days of real use,
-- including the detection events that's own serialization failures
-- triggered.
--
-- ── Why the index is PARTIAL, on active statuses only ────────────────────────
-- A plain UNIQUE (dedup_key) would fix persistence but introduce a subtler
-- detection gap: one row per alert shape for all time, so an alert resolved
-- last month and recurring today would merely bump deduplicated_count on the
-- closed row and never re-surface to an operator. Scoping uniqueness to the
-- active statuses means a row LEAVES the index the moment it is resolved,
-- freeing its dedup_key so a recurrence opens a genuinely new alert -- while
-- repeated firings of a still-open alert continue to collapse onto the one
-- row, which is what the upsert was written for.
--
-- The predicate deliberately reuses the exact status set migration 006's own
-- idx_alerts_status already established as "active"
-- (OPEN, ACKNOWLEDGED, INVESTIGATING), rather than inventing a second,
-- competing notion of activeness in the same schema.
--
-- SUPPRESSED is deliberately NOT in the set, and that is not an oversight:
-- suppression is enforced upstream and independently of row status, by
-- AlertStore.isSuppressed() reading qodiqa_suppression_rules, which
-- AlertEngine consults BEFORE saveAlert() is ever called
-- (src/alerting/engine/AlertEngine.js:95). An operator who wants a recurring
-- alert silenced adds a suppression rule; the SUPPRESSED status on a row is a
-- record of a past action on that row, not a standing instruction about
-- future ones.
--
-- ── ON CONFLICT inference against a partial index ────────────────────────────
-- Inferring an arbiter from a partial index requires the statement's own
-- ON CONFLICT ... WHERE clause to match this predicate. AlertStore.saveAlert()
-- is updated in the same change to carry exactly that predicate, and
-- src/alerting/storage/__tests__/AlertStore.dedupKeyContract.test.js fails if
-- the two ever drift apart -- the brittleness of partial-index inference was
-- the one argument raised against this approach, so it is pinned by a test
-- rather than by a comment.
--
-- Guard: refuses to run if duplicate dedup_key groups already exist among
-- active rows, which would make the unique index creation fail with a much
-- less actionable error. Same posture as migration 046's guard. Verified
-- 0 such groups locally before authoring this, but another environment's
-- table is not this one's.

BEGIN;

DO $$
DECLARE
  dup_count integer;
BEGIN
  SELECT count(*) INTO dup_count FROM (
    SELECT dedup_key
      FROM qodiqa_alerts
     WHERE dedup_key IS NOT NULL
       AND status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING')
     GROUP BY dedup_key
    HAVING count(*) > 1
  ) dups;

  IF dup_count > 0 THEN
    RAISE EXCEPTION
      'migration 047 aborted: % duplicate dedup_key group(s) already exist among active qodiqa_alerts rows. Resolve manually before re-running -- diagnostic query: SELECT dedup_key, count(*), array_agg(id) FROM qodiqa_alerts WHERE dedup_key IS NOT NULL AND status IN (''OPEN'',''ACKNOWLEDGED'',''INVESTIGATING'') GROUP BY dedup_key HAVING count(*) > 1;',
      dup_count;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS qodiqa_alerts_dedup_key_active_uq
    ON qodiqa_alerts (dedup_key)
 WHERE status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING');

COMMENT ON INDEX qodiqa_alerts_dedup_key_active_uq IS
    'the arbiter AlertStore.saveAlert()''s ON CONFLICT (dedup_key) infers. Partial on the active statuses (matching idx_alerts_status''s own definition of active) so a resolved alert''s dedup_key is freed and a recurrence opens a new alert instead of silently bumping a closed row''s counter. The pre-existing idx_alerts_dedup_key is non-unique and multi-column, so it could never serve as an arbiter -- every alert insert failed with 42P10 and fell back to in-process memory.';

COMMIT;
