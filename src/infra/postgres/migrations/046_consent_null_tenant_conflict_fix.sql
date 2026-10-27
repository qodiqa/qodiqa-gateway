-- 046_consent_null_tenant_conflict_fix.sql
--
-- consent_records' UNIQUE (actor_id, action, tenant_id) constraint
-- never fires ON CONFLICT for a NULL tenant_id -- standard SQL
-- NULL-distinctness means two NULLs are never considered equal for
-- uniqueness purposes, so every platform-level (tenant_id IS NULL) consent
-- grant for an (actor_id, action) pair that already has a row falls through
-- to a plain INSERT instead of the intended `ON CONFLICT (...) DO UPDATE`
-- upsert. Consequence: duplicate rows accumulate, and
-- ConsentStore.create()'s terminal-state reactivation guard (which only
-- ever runs when ON CONFLICT actually fires) never engages. Bounded
-- MODERATE / admin-path-only: real enforcement traffic always supplies a
-- real tenant_id derived from the signing key ("tenantId:key_vN"), never
-- NULL -, Case #9 (filed as).
--
-- Fix: replace the plain UNIQUE constraint with a UNIQUE index over
-- (actor_id, action, COALESCE(tenant_id, '')), treating a NULL tenant_id as
-- the concrete, self-equal value '' -- which is otherwise unreachable
-- (zodTenantId rejects an empty string with .min(1), so a real tenant_id
-- can never collide with the sentinel). ConsentStore.create()'s own SQL is
-- updated in the same change to target this exact expression as its
-- ON CONFLICT clause, so platform-level grants now upsert onto the same row
-- exactly like tenant-scoped grants already do -- matching migration 007's
-- own original design comment, "One row per (actor_id, action, tenant_id)
-- triple."
--
-- Guard: this migration refuses to run if any duplicate
-- (actor_id, action, tenant_id) group already exists -- creating the unique
-- index would otherwise fail with a much less actionable "could not create
-- unique index" error. Resolving pre-existing duplicates (deciding which
-- row is canonical, and whether the losing rows' audit trail needs
-- reconciling first) is a deliberate operator decision this migration does
-- not make silently -- see the RAISE EXCEPTION message below for the
-- diagnostic query.

DO $$
DECLARE
  dup_count integer;
BEGIN
  SELECT count(*) INTO dup_count FROM (
    SELECT actor_id, action, tenant_id
      FROM consent_records
     GROUP BY actor_id, action, tenant_id
    HAVING count(*) > 1
  ) dups;

  IF dup_count > 0 THEN
    RAISE EXCEPTION
      'migration 046 aborted: % duplicate (actor_id, action, tenant_id) group(s) already exist in consent_records. Resolve manually before re-running -- diagnostic query: SELECT actor_id, action, tenant_id, count(*), array_agg(id) FROM consent_records GROUP BY actor_id, action, tenant_id HAVING count(*) > 1;',
      dup_count;
  END IF;
END $$;

ALTER TABLE consent_records
  DROP CONSTRAINT consent_records_actor_id_action_tenant_id_key;

CREATE UNIQUE INDEX consent_records_actor_action_tenant_coalesced_key
    ON consent_records (actor_id, action, COALESCE(tenant_id, ''));

COMMENT ON INDEX consent_records_actor_action_tenant_coalesced_key IS
    'replaces the old plain UNIQUE(actor_id,action,tenant_id) constraint, which never fired ON CONFLICT for a NULL tenant_id due to standard SQL NULL-distinctness. COALESCE(tenant_id, '''') treats NULL as the concrete value '''' (unreachable as a real tenant_id -- zodTenantId requires min length 1), so platform-level (tenant_id IS NULL) consents now collide correctly on repeat grants, matching migration 007''s original "one row per (actor_id,action,tenant_id) triple" design intent.';
