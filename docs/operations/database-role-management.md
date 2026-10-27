# PostgreSQL Role Management — Migrations-Only Policy

| Field | Value |
|-------|-------|
| Owner | Platform Engineering / SRE |
| Status | Active policy |
| Last Updated | 2026-08-06 |

## The rule

**All PostgreSQL role attribute changes — `CREATE ROLE`, `ALTER ROLE`
(privilege/attribute flags such as `CREATEDB`/`CREATEROLE`/`BYPASSRLS`,
role-membership grants like `GRANT <role> TO <role>`), and `DROP ROLE` —
must land as a migration file under `src/infra/postgres/migrations/`, never
as a manual `psql`/admin-tool statement run directly against any database
that matters** (local dev included, not just staging/production).

**The only permitted exception is documented operator bootstrap actions**
(see below) — a narrow, explicitly-approved, one-time action to get a fresh
cluster from "PostgreSQL just installed" to "the roles this repo's
migrations assume already exist" state, never a substitute for an ordinary
schema/privilege change.

Password rotation (`ALTER ROLE <role> PASSWORD '<new>'`) is the one
role-attribute action that legitimately happens outside a migration file —
credential rotation is inherently an environment-specific, secret-bearing
operation that must never be committed as SQL text — but it is still an
**operator action taken deliberately and disclosed**, not a silent manual
edit. See "Password rotation" below.

## Why

Migration files are QODIQA's single source of truth for schema *and* role
state: `migrate.js` checksums every applied migration and refuses to start
if a file's content no longer matches what was recorded as applied — the
same integrity guarantee this repo relies on for schema correctness also
implicitly assumes role state was established the same, trackable way. A
role attribute set via a one-off manual `ALTER ROLE` breaks that assumption
silently: nothing checksums it, nothing diffs it, and nothing in the repo
records that it happened. The role's *effective* privileges then diverge
from what the migration files, read in isolation, would lead an engineer to
believe — exactly the class of drift this rule closes.

This was not a hypothetical risk — see "Known historical exceptions" below
for two real, confirmed incidents this exact gap produced.

## What this means in practice

- Need a new role?
  Create it `NOLOGIN` with **no** password literal in a new migration file
  (`CREATE ROLE <role> NOLOGIN ...`), and let the operator enable it with a real
  secret (`scripts/db/role-credentials.js --rotate`, then `ALTER ROLE <role> LOGIN`).
  Migrations 002–067 used `CREATE ROLE ... LOGIN PASSWORD 'REPLACE_WITH_VAULT_SECRET_<ROLE>'`;
  those files are applied history and stay as they are, but a published password
  is a public password, and a test (`roleCredentials.test.js`) now refuses any new
  literal role password after migration 075.
- Need to grant a role a new attribute (`CREATEDB`, `CREATEROLE`,
  `BYPASSRLS`, `SUPERUSER`, etc.) or a new role membership (`GRANT <role> TO
  <role>`)? Add an `ALTER ROLE` / `GRANT` statement to a new migration file
  — same pattern as `018_rls_tenant_isolation.sql:90`
  (`ALTER ROLE qodiqa_mig BYPASSRLS;`), which is the only in-repo precedent
  and is itself the correct way to do this.
- **Never** hand-run `ALTER ROLE`/`GRANT`/`CREATE ROLE` against a database
  this repo's migrations track, even "just for now," even in local dev, even
  to unblock yourself quickly. If a role needs elevated privileges to
  unblock a real, immediate need, add the migration — it takes the same
  couple of minutes as the manual statement and leaves a durable, checksummed
  record instead of silent drift.
- Migration files with applied checksums must never be edited after the
  fact (see any migration file's own header, or `migrate.js`'s integrity
  guard) — a role-attribute fix always lands as a **new**, additive
  migration, never an edit to an already-applied one.

### Password rotation

Rotating a role's password via `ALTER ROLE <role> PASSWORD '<new>'` does
not belong in a migration file (migration files are committed source; a
real password must never be committed, even as a rotation target) and is
therefore not covered by the "migrations only" rule above. It remains a
manual, operator-run action — but it must be:

1. **Deliberate and disclosed** — requested explicitly, run by the operator
   (not automated tooling acting on its own judgement), and followed by a
   verification pass confirming the new credential works end-to-end and the
   old value has zero remaining references in the tracked repo (see
 for
   the template this should follow).
2. **Recorded in `.env`** (git-ignored, never committed) under the
   variable the connecting code actually reads — see
   `docs/security/secrets-management.md` / `docs/configuration/reference.md` for the
   `QODIQA_PG_PASSWORD` / `QODIQA_PG_MIG_PASSWORD` /
   `QODIQA_PG_RETENTION_PASSWORD` split.
3. **Never** bundled with an attribute change in the same manual statement
   — rotating a password and escalating a privilege are different classes
   of action with different rules; conflating them in one ad hoc `ALTER
   ROLE` is exactly how the qodiqa_mig incident below went undetected for
   as long as it did.

## Documented operator bootstrap exception

The **only** standing exception to "role attributes come from migrations":
provisioning `qodiqa_test` (`CREATEDB CREATEROLE BYPASSRLS LOGIN`) on a
fresh local/CI Postgres cluster so integration test suites that need to
create their own scratch databases and run the full migration set
(including `018_rls_tenant_isolation.sql`'s `ALTER ROLE qodiqa_mig
BYPASSRLS`, which itself requires `CREATEROLE`+`BYPASSRLS` on the
connecting role) have somewhere to connect from. This is a one-time,
explicitly-decided bootstrap step for a role that migrations do not and
should not create (it exists only for test infrastructure, never for
production traffic) — see §1–2
for the full design decision and the follow-up `GRANT qodiqa_mig TO
qodiqa_test WITH ADMIN OPTION` operator grant it required (PostgreSQL 16+
restricts a `CREATEROLE` role to administering only roles it created or was
explicitly granted admin-option membership on).
`qodiqa_test` also serves as the documented migration identity for role-management migrations (002, 018, 038, 060,
065, 067) on existing clusters, including LIVE; it never serves request
traffic.

** ADMIN OPTION alone is not enough on a fresh PostgreSQL 16+ cluster.** Migration 055
(`rem063_mig_table_ownership_transfer`) runs `SET ROLE qodiqa_mig`, and PostgreSQL 16+ allows that only through a
membership with the **SET** option; the ownership changes also need **INHERIT**. With only
`GRANT qodiqa_mig TO qodiqa_test WITH ADMIN OPTION`, a fresh chain stops at 055 with
`must be able to SET ROLE "qodiqa_mig"` (reproduced on PostgreSQL 18:
). The operator grant is therefore:

```sql
GRANT qodiqa_mig TO qodiqa_test WITH ADMIN OPTION, INHERIT TRUE, SET TRUE;
```

This matches the shared local cluster, whose `qodiqa_test` holds an extra `INHERIT TRUE` membership in `qodiqa_mig`
(SET defaults to true). Before this note it was recorded only.

Any other manual role action needs the same level of explicit, documented,
one-time justification to qualify as a bootstrap exception rather than
prohibited drift — the default is migrations-only.

### `pg_signal_backend` grant

A second standing exception on the same `qodiqa_test` bootstrap role, owner-
approved for this local development cluster: `GRANT pg_signal_backend TO
qodiqa_test`. `qodiqa_test`'s `CREATEROLE` privilege is not sufficient to
grant this predefined role — PostgreSQL rejects it with `permission denied
to grant role "pg_signal_backend"` — so the grant was applied by the
cluster superuser (`postgres`), one time, on this machine's local dev
cluster only.

**Why:**'s acceptance-suite housekeeping (`startBootstrapped()` in
`test/harness/server.js`, see the CLAUDE.md environment-floor
notes) drops each `qodiqa_dev_%` scratch database it creates when the
acceptance case tears down. `qodiqa_test` owns every database it creates
and can already `DROP DATABASE ... WITH (FORCE)` most of them, but
`WITH (FORCE)` needs to terminate any backend still attached to that
database, and terminating another role's backend
(`pg_terminate_backend`/`pg_cancel_backend`, which `FORCE` uses internally)
requires the `pg_signal_backend` predefined role — which `qodiqa_test`
did not hold. In the rare timing window where a `qodiqa_app` backend was
still attached at drop time, the drop failed and logged a non-fatal
`[acceptance] WARNING`, leaving a small residual of undropped
`qodiqa_dev_%` databases per full run (measured 2–17 out of ~90 PG-enabled
cases). This grant closes that residual by letting `qodiqa_test` terminate
a lingering `qodiqa_app` backend itself.

**Explicitly a dev/test-role privilege, not a production one.** No
production role (`qodiqa_app`, `qodiqa_mig`, `qodiqa_retention`) holds or
needs `pg_signal_backend` — the ability to signal arbitrary backends has no
role in request-serving, migration, or retention code paths, and granting
it there would be a real privilege-escalation surface. It exists on
`qodiqa_test` only because that role's whole purpose (per the bootstrap
exception above) is test-infrastructure database lifecycle management on a
local/CI cluster, never production traffic. Do not carry this grant into
any migration file, any production role, or any non-development cluster.

`qodiqa_test` carries `pg_signal_backend` alongside its existing `qodiqa_app`/`qodiqa_mig`/
`qodiqa_read`/`qodiqa_retention` memberships (check `pg_auth_members`). With it, a full
acceptance run (`npm run acceptance`) leaves no `qodiqa_dev_%` residual databases.

## Exception: migrations 002 and 038 hardcoded-database-name fix

The second, narrower standing exception to this document's own "migration
files with applied checksums must never be edited after the fact" rule
(above): `002_security_hardening.sql` and `038_retention_dedicated_role.sql`
were edited directly on 2026-08-13 to replace three hardcoded
`GRANT CONNECT ON DATABASE qodiqa TO <role>;` statements (002 lines 39/68/76)
and one more in 038 with a dynamic-SQL equivalent —
`EXECUTE format('GRANT CONNECT ON DATABASE %I TO <role>', current_database())`
— rather than shipping as a new, additive migration (the normal remedy this
document prescribes everywhere else).

**Why the normal additive-migration remedy does not work here.** Both
migrations wrap their entire body — role creation *and* the hardcoded
grant — in one `BEGIN`/`COMMIT`. On a cluster with no database literally
named `qodiqa` (e.g. `npm run dev`'s own Path A, whose whole point is a
fresh, isolated, uniquely-named per-boot database — see
`scripts/lib/devConsent.js`'s `generatedDevDbName` — docs/guides/quickstart.md's
documented, recommended path), the first `GRANT CONNECT` throws `database
qodiqa does not exist`, and the transaction rolls back everything before
it too, including `CREATE ROLE`. `migrate.js` aborts the entire run on the
first failing migration, so no later, additive migration — including
migration 045, which already attempted exactly this remedy for 038's copy
of the bug — is ever reached to compensate. The bug is *in* the first
application of 002/038, not something a later migration can patch around.
Confirmed live via a genuine fresh-clone docs/guides/quickstart.md validation run
 findings register,.

**Why editing in place is safe here specifically** (this is a narrow
exception, not a reopening of the general rule):
> **CORRECTION: the claim in point 1 below is FALSE for the current runner.** `migrate.js` now records the real
> SHA-256 of each migration (`migrate.js:279-283`) and verifies it; on LIVE all 57 applied rows hold real, matching checksums.
> Editing an already-applied migration (002/038) WILL trip the guard on any database migrated by this runner. Never edit applied
> migrations — add a new one. The text below is kept as history of the 2026-08 reasoning.

1. **The checksum integrity guard this rule exists to protect is already a
   no-op**, independent of this change. `migrate.js`'s comparison —
   `existing.checksum !== 'PLACEHOLDER_CHECKSUM' && existing.checksum !==
   file.checksum` — never fires, because every migration in this repo's own
   history, 001 through 048, records the literal string `'PLACEHOLDER_CHECKSUM'`
   as its own applied checksum (verified by grepping every migration's own
   `INSERT INTO qodiqa_migrations` statement), never a real SHA-256. The
   first operand is therefore always `false` and the `&&` short-circuits.
   Editing 002/038 does not disable a real drift-detection mechanism,
   because in this codebase's current form there isn't one to disable.
2. **The edit is behavior-identical for every deployment where it matters.**
   `current_database()` evaluates to the literal string `'qodiqa'` on every
   real deployment today — the shared production/dev database this whole
   policy is written to protect. The resulting `GRANT` is byte-identical to
   the one the old hardcoded statement produced there. The only behavior
   change is that the grant now *also* succeeds against a database with any
   other name — exactly, and only, the isolated per-boot databases this
   fix exists for.
3. **The alternative (leaving 002/038 broken, demoting Path A) was
   presented and explicitly declined** — it keeps migration history
   append-only but leaves docs/guides/quickstart.md's own recommended onboarding path
   permanently broken for a first-time user's genuinely fresh cluster, and
   was judged the worse trade.

Migration 045 (the earlier, structurally-nonfunctional attempt to patch
038's copy of this bug additively) is left in place rather than deleted —
it is itself already an applied migration on every real deployment, and its
own `GRANT CONNECT ... current_database()` statement is a harmless,
idempotent no-op once 038 grants the same thing correctly on first
application. No file this document's checksum guard protects for a real,
already-migrated deployment changes effective privileges as a result of
this exception.

## Fresh-container bootstrap sequencing (the qodiqa_mig chicken-and-egg)

`migrate.js` connects using `QODIQA_PG_MIG_USER` (default `'qodiqa_mig'`) —
but `qodiqa_mig` itself does not exist until `002_security_hardening.sql`
creates it, and `qodiqa_migrations` (the tracking table the integrity guard
above depends on) does not exist until `001_initial_schema.sql` creates it.
On a brand-new database, there is no `qodiqa_mig` to connect as yet — the
very first migration has nothing to authenticate as under `migrate.js`'s own
default. **This means migrations 001 and 002 must be applied by a superuser
(or another role that already exists and holds sufficient privileges) on any
fresh container/database; `migrate.js`'s `QODIQA_PG_MIG_USER` default only
becomes usable starting with migration 003 onward.** This is a structural
property of the bootstrap sequence, not a bug to fix in `migrate.js` — every
role-creation migration in this repo (002, 038) necessarily runs before the
role it creates can run anything itself.

> **Note:** the `applied_by` split described here is the AIO-era history. On the current machine LIVE shows
> `qodiqa_test` ×50 and `qodiqa_mig` ×7, and after the 2026-10-20 remediation run 81/81 via `qodiqa_test`.

Live `qodiqa`'s own `qodiqa_migrations.applied_by` history is **codified as
documented-intentional** confirmation of this (design decision, Findings
Group A, 2026-08-04 — see "Known historical exceptions" item 3 below):
versions 1-17 (and 22-25) show `applied_by=qodiqa_mig`; versions 18-21 and
26-44 show `applied_by=postgres`. The switch at version 18 reflects an
operator applying the remaining chain as the cluster superuser rather than
provisioning a distinct `qodiqa_mig` credential for ongoing use — an
accepted operational pattern in this environment, not drift to revert.
`.github/workflows/load-test.yml` independently documents this same gap and
points its own migration job at the container's superuser for the same
reason; `test.yml` has the same gap and is deliberately left unaddressed
(tracked as separate, already-acknowledged post-push debt, out of this
scope).

## Known historical exceptions (untracked drift, now on record)

Four confirmed incidents of exactly the drift this policy exists to
prevent, discovered after the fact rather than performed under this policy —
except item 3, which is an intentional, approved operational pattern
(covered above), included here only for completeness of the applied_by
record. Items 1 and 4 are now resolved — kept on
record rather than removed, since the point of this section is a durable
history of drift, not just a list of currently-open problems.

1. **`qodiqa_mig` privilege escalation.**
   `qodiqa_mig` was found holding live `CREATEDB`+`CREATEROLE` attributes —
   well beyond what `002_security_hardening.sql` (the only migration that
   creates the role) grants it (`CREATE, USAGE ON SCHEMA public` only).
   No migration file in the repo's 41-migration set contains a matching
   `ALTER ROLE qodiqa_mig` statement. See
 for the
   original investigation.
   **Origin, upgraded 2026-08-06:**'s own
   §9.4 one-time local setup instructions (lines 305-306, pre-fix) told an
   operator to run `CREATE ROLE qodiqa_mig LOGIN CREATEDB CREATEROLE
   PASSWORD '<generate one>'; ALTER ROLE qodiqa_mig BYPASSRLS;` — the only
   place in the repository where a `CREATE ROLE qodiqa_mig` statement
   carries `CREATEDB`/`CREATEROLE`, and it matches the observed live
   attribute set exactly. Migration 002's `CREATE ROLE ... IF NOT EXISTS`
   guard means that if this command ran first against a database, 002
   would silently skip role creation forever after, baking the extra
   attributes in with no migration ever touching them. No downstream code
   was found to use either attribute on `qodiqa_mig` (`helpers/postgres.js`
   never does `CREATE`/`DROP DATABASE`; `migrate.js` has no maintenance-
   database logic; no script issues `CREATE ROLE`/role grants as
   `qodiqa_mig`) — most plausibly a copy-paste from `qodiqa_test`'s
   legitimately-broader definition. **Epistemic caveat, unchanged:** no
   execution log or timestamp proves this exact command is what ran
   against this specific database — this is the best-supported hypothesis
   given available evidence, not a certainty, upgrading the prior "unknown
   `ALTER ROLE`, unknown reason" characterization.
   **Resolved 2026-08-06:** design decision was to revoke both attributes.
   `ALTER ROLE qodiqa_mig NOCREATEDB NOCREATEROLE;` executed via `qodiqa_test`
   (holds `CREATEROLE` + `ADMIN OPTION` on `qodiqa_mig`, per the bootstrap
   exception below). Confirmed via `pg_roles`: `qodiqa_mig` now holds
   exactly `LOGIN BYPASSRLS`, matching migrations 002+018 with nothing left
   over. corrected to stop instructing
   the extra attributes, closing the reintroduction path.
4. **`qodiqa_mig` role-membership drift (discovered 2026-08-06, BLOCK-02;
   RESOLVED same day).** During the above investigation, `qodiqa_mig` was
   also found to be a member of both `qodiqa_app` and `qodiqa_read`, in
   both cases **with `ADMIN OPTION`** (`pg_auth_members`) — not previously
   recorded in this document or in
/. No migration or script anywhere in the repo
   grants `qodiqa_mig` membership in either role (`grep` for `GRANT
   qodiqa_app`/`GRANT qodiqa_read` across the full tree: zero matches).
   **Origin: unknown** — `pg_auth_members.grantor` identifies `postgres`
   (the cluster superuser) as the grantor of both, which only narrows *who*
   could have run it, not *when* or *why*; no further evidence was found
   and none is invented here. **Resolved 2026-08-06:** design decision was
   to revoke both memberships. Because the grantor was `postgres` and
   PostgreSQL only permits the original grantor (or another superuser) to
   revoke a role-membership grant — `ADMIN OPTION` on the target role does
   not override this — this specifically required the owner to run
   `REVOKE qodiqa_app FROM qodiqa_mig; REVOKE qodiqa_read FROM qodiqa_mig;`
   as `postgres` directly (attempted first via `qodiqa_mig` and `qodiqa_test`,
   both correctly rejected by PostgreSQL's grantor-matching rule). Confirmed
   via `pg_auth_members`: zero rows for `qodiqa_mig` as member of anything,
   post-revocation.
2. **Dev PostgreSQL credential rotations via `ALTER ROLE`.**
   The dev Postgres password was rotated directly by the operator
   (`ALTER ROLE ... PASSWORD ...` + matching `.env` update) on more than
   one occasion that session (the primary dev role, and separately
   `qodiqa_app`'s password during the least-privilege role switch) — see
.
   Each rotation was deliberate, disclosed, and verified end-to-end per the
   "Password rotation" checklist above, so these are **compliant** examples
   of the password-rotation exception, not drift — recorded here as the
   precedent that exception's checklist above was written to match.
3. **`qodiqa_mig`→`postgres` applied_by switch at migration 18 (approved
   2026-08-04, Findings Group A).** Not drift — see "Fresh-container
   bootstrap sequencing" above. Included here so the full `applied_by`
   history (1-17/22-25 as `qodiqa_mig`, 18-21/26-44 as `postgres`) has one
   place documenting why it looks like an exception but is a deliberately
   accepted pattern, approved rather than reverted.

## control role

Migration 065 creates `qodiqa_control`: LOGIN, NOBYPASSRLS, NOSUPERUSER, NOCREATEROLE, NOCREATEDB, with no memberships. Its placeholder password (`REPLACE_WITH_VAULT_SECRET_CONTROL`) must be rotated before use (see *Password rotation* above) and provided as `QODIQA_PG_CONTROL_PASSWORD`.

Like 002/038/060, the migration creates a role, so it needs a CREATEROLE identity (`qodiqa_test` locally, the bootstrap identity elsewhere). Migration 066 grants the role SELECT/INSERT/UPDATE on `control_plane_records` only, never DELETE, and nothing else anywhere. `qodiqa_app` has no privilege on the control plane.

The canonical matrix, including the role and table, is, held to the live catalog by `test/integration/privilegeRls.integration.test.js` PM-01. Operations: `docs/operations/control-plane.md`.

## backup role

Migration 067 creates `qodiqa_backup`, the identity for **both** backup paths: `scripts/pg-backup.sh` (pg_dump) and the DR JSON dump (`scripts/dr/postgres.js`).
- **Attributes:** LOGIN, **BYPASSRLS**, NOSUPERUSER, NOCREATEROLE, NOCREATEDB.
- **Privileges:** SELECT on every table and sequence in `public`, plus default privileges for tables and sequences created later by the migrating identity and by `qodiqa_mig`. It has no write privilege anywhere.
- **Password:** the placeholder (`REPLACE_WITH_VAULT_SECRET_BACKUP`) must be rotated. It goes only to the backup jobs: Kubernetes secret key `postgres-backup-password`, systemd `PGPASSWORD` in `backup.env`, and `QODIQA_PG_BACKUP_PASSWORD` in the local `.env`.

**Why a dedicated role.** Both paths used to run as `qodiqa_app`:
- Under the per-tenant RLS policies, the JSON dump silently kept only NULL-tenant rows, and `dr:verify` passed.
- pg_dump failed every full backup with `permission denied … LOCK TABLE`.

Since the JSON dump refuses (`BACKUP_ROLE_NOT_RLS_EXEMPT`) to run as any role that RLS filters, and fails on any table it cannot dump completely. `dr:verify` reconciles the recorded role, RLS exposure and per-table snapshot counts.

**One-time superuser grants.** These are optional and not applied on this machine; they are an design decision:
- `GRANT pg_read_all_data TO qodiqa_backup`
  - Covers any table the explicit and default grants miss, e.g. one created by an identity other than the migrator or `qodiqa_mig`.
  - Migration 067 attempts it and continues with a NOTICE when the migrating identity may not grant it. `qodiqa_test` may not, as with `pg_signal_backend` above.
  - Without it, coverage rests on the explicit and default grants. A missed table fails the backup loudly; it is never silently incomplete.
- `ALTER ROLE qodiqa_backup REPLICATION`
  - Only if `pg-backup.sh incremental` (`pg_basebackup`) is used.
  - That path needs the REPLICATION attribute, which `qodiqa_app` never had either, so the incremental CronJob could not have worked.

**[D-P, batch 2026-10-12] `pg_read_all_data` is now REQUIRED, not optional.** Every backup path
(`scripts/pg-backup.sh full`, `scripts/dr/pgDump.js`, `scripts/dr/postgres.js`) refuses to start, writing nothing,
unless the dumping role is RLS-exempt **and** a `pg_read_all_data` member (`BACKUP_ROLE_READ_ALL_DATA_MISSING`). A
cluster migrated by a superuser already has the grant (migration 067); a cluster migrated by a non-superuser bootstrap
role needs the one-time, reviewed provisioning step, run by a superuser before the first backup:

```bash
psql -X -v ON_ERROR_STOP=1 -U <superuser> -d postgres -f scripts/db/provision-backup-role.superuser.sql
```

The LIVE cluster needs an explicit approval for this step (roles are cluster-wide).

## SECURITY DEFINER owner role —

Migration 079 creates `qodiqa_definer` and makes it the owner of all 47 SECURITY DEFINER functions:
- **Attributes:** NOLOGIN (no credential exists), NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, **BYPASSRLS**
  (required: every table the definers touch has FORCE ROW LEVEL SECURITY with no policy for this role, and the
  platform_audit_events append-only guard admits the erasure update only for a BYPASSRLS role).
- **Privileges:** exactly what the 47 bodies use (`src/infra/postgres/definerOwnership.js`, pinned by
  `test/integration/definerOwnership.integration.test.js`): SELECT on 23 tables, column-scoped UPDATE for the erasure targets,
  INSERT/DELETE for the erasure finalize, the mirror-counter writes, and UPDATE on `audit_chain` solely for the
  rebuild's `LOCK TABLE … SHARE ROW EXCLUSIVE`. No CREATE anywhere.
- **Membership:** it is a member of nothing. No runtime role and not `qodiqa_mig` may be a member of it (migration 079
  refuses). A **non-superuser** migrating identity (`qodiqa_test`) is made a member, because `ALTER FUNCTION … OWNER TO`
  needs `SET ROLE qodiqa_definer` and future migrations that replace a definer need the same; it already owned every
  one of these functions before 079. A superuser migrator (compose bootstrap, CI) needs no membership.
- **Why:** before 079 the owner was whoever ran the chain — on a compose deployment the cluster bootstrap
  **superuser**, so every definer executed with superuser rights.

**Before running 079 as `qodiqa_test` on a cluster where `qodiqa_definer` was created by a different identity**
(PostgreSQL 16+), that identity must first `GRANT qodiqa_definer TO qodiqa_test WITH INHERIT TRUE, SET TRUE`;
otherwise 079 stops with `permission denied to grant role` and changes nothing.

### Narrowing the definer's `audit_chain` grant — migration 082

Migration 079 gave `qodiqa_definer` a table-wide `UPDATE` on `audit_chain` only because `qodiqa_audit_chain_mirror_count_rebuild()` takes
`LOCK TABLE audit_chain IN SHARE ROW EXCLUSIVE MODE`, which needs `UPDATE`/`DELETE`/`TRUNCATE` before PostgreSQL 17. On PostgreSQL >= 17
migration 082 replaces it with `MAINTAIN` (authorises `LOCK TABLE` in every mode, authorises no row change). On PostgreSQL < 17 (the
shipped compose stack is PostgreSQL 16) there is no narrower privilege: 082 is a recorded no-op, the grant stays and the append-only
trigger from migration 076 is the control. Pinned in `test/integration/definerOwnership.integration.test.js` (DO-04, DO-18) through
`definerOwnership.tablePrivilegesFor()`.

### Schema owner role — closure

Migration 081 creates `qodiqa_owner` and makes it the owner of every table (84), their sequences and indexes, the 15
non-definer functions and the `audit_category` type in `public`:
- **Attributes:** NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION, **NOBYPASSRLS**; member of nothing;
  USAGE + CREATE on `public` (so a migration can create objects as it). FORCE RLS still applies to it as owner.
- **Who can assume it:** a superuser, or the non-superuser bootstrap identity (`qodiqa_test`), which 081 grants
  INHERIT/SET membership. No runtime role, not `qodiqa_mig` and not `qodiqa_definer` may be a member (081 refuses).
- **`qodiqa_mig`** no longer owns anything. It keeps the table privileges it held as owner of the 11 other
  migration-001 tables, but on `audit_chain` only SELECT and INSERT — it can no longer disable or replace the audit
  chain's guard triggers, update, delete or truncate it. Schema-altering migrations therefore run as the bootstrap
  identity (compose: the bootstrap superuser; local: `qodiqa_test`), as the role-management migrations already did.
- **Default privileges** exist only `FOR ROLE qodiqa_owner` (backup SELECT on tables and sequences). Dumps therefore
  no longer name the deployment's bootstrap role, which removes the PL13-10 restore stop.
- **Convention for later migrations:** create objects as `qodiqa_owner` (`SET LOCAL ROLE qodiqa_owner`), or end with
  `ALTER … OWNER TO qodiqa_owner`; `test/integration/definerOwnership.integration.test.js` DO-14..16 fail otherwise.
- **Restore identity (D-R):** the bootstrap identity, **without** the superuser override. After
  `pg_restore --no-owner`, `scripts/dr/schema-ownership.sql` then `scripts/dr/definer-ownership.sql` hand the objects
  back and verify ownership, backup coverage and default privileges (both restore paths run them automatically).
  Preconditions on the target cluster: the roles exist (run the migration chain once on that cluster), and the restoring
  identity is a superuser or can `SET ROLE` both `qodiqa_owner` and `qodiqa_definer`.
- **Rollback:** `deploy/sql/rollback-schema-owner.sql` (re-opens the superuser-only restore and
  `qodiqa_mig`'s control of `audit_chain`) — prefer forward recovery.

**Restore:** `scripts/pg-backup.sh restore` re-establishes the ownership after `pg_restore --no-owner`
(`scripts/dr/definer-ownership.sql`); the DR restore paths verify it. **Rollback:** `deploy/sql/rollback-definer-ownership.sql`
(re-opens prefer forward recovery).

## Placeholder credentials —

Migrations 002/038/060/065/067 create eight LOGIN roles whose passwords are the
literal placeholders `REPLACE_WITH_VAULT_SECRET_*`. Those literals are in the
repository, so until an operator changes them they are **public passwords** —
including `qodiqa_read` (SELECT on every table, EXECUTE on cross-tenant SECURITY
DEFINER functions) and `qodiqa_backup` (BYPASSRLS).

| Role | Migration | Consumer | Secret variable | Operator action |
|---|---|---|---|---|
| `qodiqa_app` | 002 | gateway request pool | `QODIQA_PG_PASSWORD` | rotate |
| `qodiqa_read` | 002 | **none** (legacy dashboards role) | — | **`NOLOGIN`** (`--harden-unused`) unless you deliberately use it |
| `qodiqa_mig` | 002 | migrations | `QODIQA_PG_MIG_PASSWORD` | rotate |
| `qodiqa_retention` | 038 | retention pool | `QODIQA_PG_RETENTION_PASSWORD` | rotate |
| `qodiqa_system` | 060 | system role pool | `QODIQA_PG_SYSTEM_PASSWORD` | rotate |
| `qodiqa_reporting` | 060 | reporting role pool | `QODIQA_PG_REPORTING_PASSWORD` | rotate |
| `qodiqa_control` | 065 | control plane pool | `QODIQA_PG_CONTROL_PASSWORD` | rotate |
| `qodiqa_backup` | 067 | backup jobs only (pg_dump, DR dump) | `QODIQA_PG_BACKUP_PASSWORD` | rotate |

**Enforcement.** A production boot (`NODE_ENV=production`) now *proves* that no
role in this table accepts its placeholder: `server/startup.js` (gate -2.45,
`src/infra/postgres/roleCredentials.js`) attempts a login as each role with its
published placeholder and refuses to start (`FATAL PG_ROLE_PLACEHOLDER_CREDENTIAL`)
if any login succeeds. A role that is `NOLOGIN`, or whose password was changed,
passes. Roles that cannot be probed from the gateway host (pg_hba, network) are
reported `PG_ROLE_CREDENTIAL_UNPROVEN` and must be checked from a host that can
reach them. The gate is controlled by `QODIQA_PG_ROLE_CREDENTIAL_GATE`
(`enforce` default in production — production refuses any other value; `off`
default elsewhere, `warn`/`enforce` opt-in). The gate only observes; it never
changes a role.

**Operator tool** (`scripts/db/role-credentials.js`, never run automatically —
roles are **cluster-wide**, so these actions affect every database on the cluster):

```bash
node scripts/db/role-credentials.js --check
```
Exit 0 means proven safe, 1 means a role accepts its placeholder, and 2 means unproven from this host.

```bash
QODIQA_PG_ADMIN_USER=<admin> QODIQA_PG_ADMIN_PASSWORD=<…> node scripts/db/role-credentials.js --harden-unused --confirm
```
This sets `qodiqa_read` to `NOLOGIN`.

```bash
NEW_PW=<secret from your vault> QODIQA_PG_ADMIN_USER=<admin> QODIQA_PG_ADMIN_PASSWORD=<…> node scripts/db/role-credentials.js --rotate qodiqa_backup --password-env NEW_PW --confirm
```
`--rotate` sends a client-computed SCRAM-SHA-256 verifier, never the plaintext,
so the secret cannot appear in the PostgreSQL statement log. It refuses
passwords shorter than 24 characters or placeholder-like values. After rotating,
update the consumer's secret store (Kubernetes secret / `backup.env` / `.env`).

**State of the developer cluster on 2026-10-04** (read-only `--check`,
): seven roles REJECTED their
placeholder; **`qodiqa_read` ACCEPTED it**. Because roles are cluster-wide, that
role is shared with the LIVE `qodiqa` database, so hardening it is an owner
action (OA-IND01), not something any test or session does automatically.

** COMPLETE:** `qodiqa_read` is NOLOGIN on this cluster (authorized,
`role-credentials.js --harden-unused --confirm` as `qodiqa_test`); `--check` exits 0
.

## References

- `src/infra/postgres/migrate.js` — the checksum/integrity guard this
  policy exists to keep meaningful.
- `src/infra/postgres/migrations/002_security_hardening.sql`,
  `018_rls_tenant_isolation.sql`, `038_retention_dedicated_role.sql` — the
  only role-creation/role-attribute precedents in the repo.
- —
  `qodiqa_test` bootstrap exception, full design rationale.
- — `qodiqa_mig`
  escalation finding.
-
  password-rotation verification template.
- `docs/security/secrets-management.md`, `docs/configuration/reference.md` — where
  rotated credentials get recorded (`.env` variable names).
