# Control plane

The control plane is the state that decides **who may do what**: signing identities (and their API keys), operator users and custom roles, tenants, organizations, tenant-portal users, the global policy state (what is enforced), and the status timeline of every signing key. it lived in per-process JSON files: a revocation on one replica never reached another, and a stale replica's next write could put a revoked key back (audit F-S02).

## How it works

| | |
|---|---|
| Authority | PostgreSQL: table `control_plane_records` (migration 066), reachable only as role `qodiqa_control` (migration 065). |
| Per replica | A full snapshot of the rows. The replica pulls changes every 1 s (`QODIQA_CONTROL_PLANE_SYNC_INTERVAL_MS`, 50–2500), and immediately when a **signed** change notification arrives on `qodiqa:control-plane`. |
| Guarantee | A snapshot older than **5 s** is never used. Every read then fails with `CONTROL_PLANE_STALE` (HTTP 503): `/sign`, operator auth, artifact validation (tenant/org), RBAC checks. So a change committed at *t* is in force on every replica by *t* + 5 s, or that replica refuses. Notifications are only an optimisation (measured: 4–274 ms with them, ≈ 1 s without). |
| Writes | Row-level and versioned: a write names the version it read, and a stale replica's write matches no row (`CONTROL_PLANE_VERSION_CONFLICT`, HTTP 409). Deletes are tombstones that can never be un-deleted. Signing-key status only moves forward. All of this is enforced by trigger `control_plane_records_guard`, not just by the application. |
| `/sign` | No file write at all. `lastUsedAt` is coalesced to at most one single-column update per identity per minute, which never moves the record's version. |
| Enforced policy | Every replica derives its enforced set from the policy store and recomputes it whenever a change is pulled. `POLICY_FILE` is the **import source** only; `SIGHUP` no longer reloads it. |
| Signing keys | The key **material** stays in the keystore. Its status timeline is control-plane state: verification uses the more advanced of the local and control-plane view, and signing refuses (after a keystore reload) a key the cluster has retired. |

## Configuration

| Variable | Production | Meaning |
|---|---|---|
| `QODIQA_PG_CONTROL_PASSWORD` | **required** (boot rule `control_plane`) | password of `qodiqa_control`, rotated from the migration placeholder; never reuse another role's |
| `QODIQA_PG_CONTROL_USER` | optional | default `qodiqa_control` |
| `QODIQA_CONTROL_PLANE_BACKEND` | ignored (always `pg`); `memory` is refused | outside production: `pg` opts in, anything else is the dev/test **memory mode** (seeded once from the legacy JSON files, never persisted — boot warns `CONTROL_PLANE_MEMORY_MODE`) |
| `QODIQA_CONTROL_PLANE_MAX_STALENESS_MS` | optional | can only **tighten** the 5 s bound (clamped to [200, 5000]) |
| `QODIQA_CONTROL_PLANE_SYNC_INTERVAL_MS` | optional | pull interval, default 1000 |

Multiple replicas on one PostgreSQL also require `QODIQA_DEPLOYMENT_MODE=distributed` (audit-chain ordering; unchanged).

## Moving an existing deployment to the control plane (operator action; LIVE is never changed autonomously)

1. Apply migrations 065 (creates the role; needs a CREATEROLE identity) and 066 (the table; `qodiqa_mig`).
2. `ALTER ROLE qodiqa_control PASSWORD '<new random>'`, and store it as `QODIQA_PG_CONTROL_PASSWORD` in the deployment's secret store.
3. Import the legacy files once:
   `node scripts/controlPlane/import.js --database <db> --report <path> [--live-approved]`
   The import is create-only and idempotent. It verifies every store by checksum (source set = rows read back) and exits 2, without overwriting, if a row already exists with different data. The shared `qodiqa` database is refused without `--live-approved`.
4. Start the replicas. From then on the JSON files are never written. Keep them only as the import record.

## Failure modes

| Symptom | Meaning | Action |
|---|---|---|
| `CONTROL_PLANE_UNAVAILABLE` FATAL at boot | first pull failed | check PG connectivity, the control password, migrations 065/066 |
| `CONTROL_PLANE_STALE_REFUSED` events / 503s | this replica could not pull for > 5 s | check PG; the replica recovers on its own at the next successful pull |
| `CONTROL_PLANE_SYNC_FAILED` | one pull failed | transient unless it persists past 5 s (above) |
| HTTP 409 `CONTROL_PLANE_VERSION_CONFLICT` on an admin write | another replica changed the record first | re-read and retry — by design |
| `CONTROL_PLANE_NOTIFICATION_REJECTED` | a notification failed MAC verification | investigate Redis access; correctness is unaffected (notifications carry no state) |
