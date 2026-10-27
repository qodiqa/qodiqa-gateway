-- QODIQA PostgreSQL Migration 073
-- S2 (design decisions 2026-10-01: counter scope = cardinality ONLY,
-- the lag monitor reads it by default, DR rebuilds it from the restored audit_chain, no automatic drift healing).
--
-- The 60 s audit PG lag monitor counted the mirror with SELECT count(*) FROM qodiqa_audit_chain_full_read(): a
-- SECURITY DEFINER SETOF function, so every row of audit_chain was produced and spilled to temp just to be counted
--.
--
-- audit_chain_mirror_count holds ONE row whose row_count is the exact number of live audit_chain rows:
--
--     INVARIANT  row_count = (SELECT count(*) FROM audit_chain)   in every committed state
--
-- maintained IN THE SAME TRANSACTION as every statement that changes that number, by statement-level triggers:
--   AFTER INSERT   (transition table NEW: only rows actually inserted — ON CONFLICT DO NOTHING no-ops are not in it)
--   AFTER DELETE   (transition table OLD: the rows actually deleted — the operator prune is one DELETE statement)
--   AFTER TRUNCATE (row_count := 0)
-- An UPDATE never changes the number of rows (scripts/audit-mirror-rebuild.js only re-sequences seq), so there is no
-- UPDATE trigger. A rolled-back statement or transaction rolls the counter back with it.
--
-- The counter is DERIVED state: never a source of truth for any audit decision. qodiqa_audit_chain_mirror_count_check()
-- keeps the exact count as the authoritative cross-check (it reports drift; it never repairs). The ONLY writer outside
-- the triggers is qodiqa_audit_chain_mirror_count_rebuild() (owner-only EXECUTE), used by the DR restore after
-- audit_chain has been restored. A guard trigger refuses every other write, so the DR restore cannot overwrite it with
-- a dumped row (the table is also excluded from DR row data: scripts/dr/table-registry.js).
--
-- Seeding (existing databases): audit_chain is locked IN SHARE ROW EXCLUSIVE MODE for the rest of this transaction
-- (writers wait, readers do not), counted once, and the triggers are created under the same lock — no row can be
-- inserted or deleted between the count and the triggers. One O(n) count, once, at migration time (migrations run
-- before the server serves; measured 56 ms at 117k rows, 170 ms at 360k).
--
-- Privileges: no runtime role gets any privilege on the table. Trigger and read functions are SECURITY DEFINER
-- (search_path pinned) so writers (qodiqa_app, the prune identity, the DR restore identity) need no write privilege on
-- it. EXECUTE: count + check → qodiqa_system; rebuild → owner only; trigger functions → nobody (triggers fire anyway).

BEGIN;

LOCK TABLE audit_chain IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE IF NOT EXISTS audit_chain_mirror_count (
  id          BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (id),
  row_count   BIGINT      NOT NULL CHECK (row_count >= 0),
  seeded_at   TIMESTAMPTZ NOT NULL,
  rebuilt_at  TIMESTAMPTZ,
  updated_at  TIMESTAMPTZ NOT NULL
) WITH (fillfactor = 10);

COMMENT ON TABLE audit_chain_mirror_count IS
  'S2 (migration 073): derived singleton — row_count = count(*) of audit_chain in every committed state, maintained by statement-level triggers on audit_chain in the same transaction. Read by the 60 s PG lag monitor. Never restored as DR row data (rebuilt from the restored audit_chain). Written only by the triggers and qodiqa_audit_chain_mirror_count_rebuild().';

REVOKE ALL ON TABLE audit_chain_mirror_count FROM PUBLIC;

-- Idempotent without ON CONFLICT: on a re-run the row already exists, NO row is proposed, so the write guard created
-- below (a BEFORE INSERT row trigger, which would fire even for a conflicting row) is never reached.
INSERT INTO audit_chain_mirror_count (id, row_count, seeded_at, updated_at)
SELECT TRUE, (SELECT count(*) FROM audit_chain), now(), now()
WHERE NOT EXISTS (SELECT 1 FROM audit_chain_mirror_count);

-- ── maintenance triggers on audit_chain ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION qodiqa_audit_chain_mirror_count_on_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_n BIGINT;
BEGIN
  SELECT count(*) INTO v_n FROM w11_inserted_rows;
  IF v_n > 0 THEN
    UPDATE audit_chain_mirror_count SET row_count = row_count + v_n, updated_at = now() WHERE id;
  END IF;
  RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_mirror_count_on_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_n BIGINT;
BEGIN
  SELECT count(*) INTO v_n FROM w11_deleted_rows;
  IF v_n > 0 THEN
    -- row_count >= 0 is a CHECK: a decrement below zero (a counter already out of step) fails the DELETE loudly.
    UPDATE audit_chain_mirror_count SET row_count = row_count - v_n, updated_at = now() WHERE id;
  END IF;
  RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION qodiqa_audit_chain_mirror_count_on_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  UPDATE audit_chain_mirror_count SET row_count = 0, updated_at = now() WHERE id;
  RETURN NULL;
END
$$;

REVOKE ALL ON FUNCTION qodiqa_audit_chain_mirror_count_on_insert()   FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_mirror_count_on_delete()   FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_mirror_count_on_truncate() FROM PUBLIC;

CREATE OR REPLACE TRIGGER audit_chain_mirror_count_insert
  AFTER INSERT ON audit_chain REFERENCING NEW TABLE AS w11_inserted_rows
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_chain_mirror_count_on_insert();
CREATE OR REPLACE TRIGGER audit_chain_mirror_count_delete
  AFTER DELETE ON audit_chain REFERENCING OLD TABLE AS w11_deleted_rows
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_chain_mirror_count_on_delete();
CREATE OR REPLACE TRIGGER audit_chain_mirror_count_truncate
  AFTER TRUNCATE ON audit_chain
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_chain_mirror_count_on_truncate();

-- ── write guard on the counter itself ───────────────────────────────────────────────────────────────────────────────
-- Allowed: a write issued from inside a trigger (the audit_chain triggers above: depth > 1), or from the rebuild
-- function (transaction-local flag it sets and clears). Everything else — a manual UPDATE, a DR row restore — fails.
CREATE OR REPLACE FUNCTION qodiqa_audit_chain_mirror_count_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF pg_trigger_depth() > 1 OR current_setting('qodiqa.audit_chain_mirror_count_rebuild', true) = 'on' THEN
    IF TG_LEVEL = 'STATEMENT' THEN RETURN NULL; END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'audit_chain_mirror_count is derived state: % refused (maintained only by the audit_chain triggers and qodiqa_audit_chain_mirror_count_rebuild(); migration 073)', TG_OP;
END
$$;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_mirror_count_guard() FROM PUBLIC;

CREATE OR REPLACE TRIGGER audit_chain_mirror_count_guard
  BEFORE INSERT OR UPDATE OR DELETE ON audit_chain_mirror_count
  FOR EACH ROW EXECUTE FUNCTION qodiqa_audit_chain_mirror_count_guard();
CREATE OR REPLACE TRIGGER audit_chain_mirror_count_no_truncate
  BEFORE TRUNCATE ON audit_chain_mirror_count
  FOR EACH STATEMENT EXECUTE FUNCTION qodiqa_audit_chain_mirror_count_guard();

-- ── readers ─────────────────────────────────────────────────────────────────────────────────────────────────────────
-- O(1): the stored row_count (NULL if the row is missing — the lag monitor reports that, it never guesses).
CREATE OR REPLACE FUNCTION qodiqa_audit_chain_mirror_count()
RETURNS BIGINT
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT row_count FROM audit_chain_mirror_count WHERE id
$$;

-- The authoritative cross-check: stored vs exact count(*), both in ONE statement snapshot. O(n), on demand only;
-- reports drift, never repairs it.
CREATE OR REPLACE FUNCTION qodiqa_audit_chain_mirror_count_check()
RETURNS TABLE(stored BIGINT, exact BIGINT, in_sync BOOLEAN)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
STABLE
AS $$
  SELECT s.row_count, e.n, s.row_count IS NOT DISTINCT FROM e.n
    FROM (SELECT count(*) AS n FROM audit_chain) e
    LEFT JOIN audit_chain_mirror_count s ON s.id
$$;

-- DR only (owner EXECUTE): rebuild the counter from the audit_chain just restored. Writers are blocked while it
-- counts; returns the value it replaced (NULL if the row was missing) and the rebuilt value.
CREATE OR REPLACE FUNCTION qodiqa_audit_chain_mirror_count_rebuild()
RETURNS TABLE(previous BIGINT, rebuilt BIGINT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE v_prev BIGINT; v_n BIGINT;
BEGIN
  LOCK TABLE audit_chain IN SHARE ROW EXCLUSIVE MODE;
  SELECT row_count INTO v_prev FROM audit_chain_mirror_count WHERE id;
  SELECT count(*) INTO v_n FROM audit_chain;
  PERFORM set_config('qodiqa.audit_chain_mirror_count_rebuild', 'on', true);
  INSERT INTO audit_chain_mirror_count (id, row_count, seeded_at, rebuilt_at, updated_at)
  VALUES (TRUE, v_n, now(), now(), now())
  ON CONFLICT (id) DO UPDATE SET row_count = EXCLUDED.row_count, rebuilt_at = now(), updated_at = now();
  PERFORM set_config('qodiqa.audit_chain_mirror_count_rebuild', 'off', true);
  previous := v_prev; rebuilt := v_n;
  RETURN NEXT;
END
$$;

REVOKE ALL ON FUNCTION qodiqa_audit_chain_mirror_count()         FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_mirror_count_check()   FROM PUBLIC;
REVOKE ALL ON FUNCTION qodiqa_audit_chain_mirror_count_rebuild() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_mirror_count()       TO qodiqa_system;
GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_mirror_count_check() TO qodiqa_system;

INSERT INTO qodiqa_migrations (version, name, checksum, applied_by)
VALUES (73, 'w11_audit_chain_mirror_count', 'PLACEHOLDER_CHECKSUM', current_user)
ON CONFLICT (version) DO NOTHING;

COMMIT;
